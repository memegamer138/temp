#include "crypto_store.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <algorithm>
#include <memory>
#include <stdexcept>

namespace crypto_store {
namespace {

constexpr unsigned char filesystem_master_key[dek_size] = {
    0x0f, 0xcf, 0x79, 0x65, 0x8c, 0x12, 0x27, 0x6d, 0xbf, 0x5d, 0x45, 0x14, 0x80, 0xe0, 0xed, 0xf6,
    0x41, 0x4e, 0xc0, 0xd0, 0x66, 0xd5, 0xf1, 0x2b, 0xa2, 0x98, 0xdf, 0x76, 0x18, 0xe5, 0x5a, 0x52};

constexpr char index_type = 'I';
constexpr char blob_type = 'B';
constexpr char registry_type = 'R';
constexpr unsigned char format_version = 0x01;
constexpr char object_magic[] = {'B', 'I', 'B', 'I', 'F', 'I'};
constexpr char index_info[] = "bibifi/fs/index/v1";
constexpr char blob_info[] = "bibifi/fs/blob/v1";
constexpr char registry_info[] = "bibifi/accounts/v3";
constexpr char hex_digits[] = "0123456789abcdef";

using Cipher = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using Kdf = std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)>;
using KdfContext = std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>;
using KeyHandle = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using KeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

struct DerivedKey {
    unsigned char bytes[dek_size]{};
    ~DerivedKey() { secure_zero(bytes, sizeof bytes); }
};

void random_bytes(unsigned char* data, int size) {
    if (RAND_bytes(data, size) != 1) {
        throw std::runtime_error("Could not generate secure random bytes");
    }
}

std::string hex_of(const unsigned char* data, std::size_t size) {
    std::string text;
    text.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        text.push_back(hex_digits[data[i] >> 4]);
        text.push_back(hex_digits[data[i] & 0x0f]);
    }
    return text;
}

bool derive_key(const unsigned char* ikm, std::size_t ikm_size, const unsigned char* salt,
                const char* info, DerivedKey& key) {
    Kdf kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr), EVP_KDF_free);
    KdfContext context(kdf ? EVP_KDF_CTX_new(kdf.get()) : nullptr, EVP_KDF_CTX_free);
    char digest_name[] = "SHA256";
    char* info_bytes = const_cast<char*>(info);
    auto* salt_bytes = const_cast<unsigned char*>(salt);
    auto* ikm_bytes = const_cast<unsigned char*>(ikm);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest_name, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm_bytes, ikm_size),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt_bytes, salt_size),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info_bytes, std::char_traits<char>::length(info)),
        OSSL_PARAM_construct_end()};
    return context && EVP_KDF_derive(context.get(), key.bytes, sizeof key.bytes, params) == 1;
}

Bytes blob_aad(const BlobBinding& binding) {
    Bytes aad;
    const char label[] = "FILESYSTEM_BLOB_V1";
    aad.insert(aad.end(), label, label + sizeof(label) - 1);
    const schema::ObjectId* ids[] = {&binding.blob_id, &binding.owner_id, &binding.file_id};
    for (const schema::ObjectId* id : ids) {
        aad.push_back(0);
        aad.insert(aad.end(), id->begin(), id->end());
    }
    aad.push_back(0);
    aad.push_back(static_cast<unsigned char>((binding.blob_version >> 24) & 0xff));
    aad.push_back(static_cast<unsigned char>((binding.blob_version >> 16) & 0xff));
    aad.push_back(static_cast<unsigned char>((binding.blob_version >> 8) & 0xff));
    aad.push_back(static_cast<unsigned char>(binding.blob_version & 0xff));
    return aad;
}

Bytes seal_object(char type, const unsigned char* ikm, std::size_t ikm_size, const char* info,
                  const Bytes& aad, const std::string& plaintext, std::size_t max_plaintext) {
    if (plaintext.size() > max_plaintext) {
        throw std::runtime_error("Object is too large");
    }
    Bytes object(object_overhead + plaintext.size());
    std::copy(object_magic, object_magic + sizeof object_magic, object.begin());
    object[sizeof object_magic] = static_cast<unsigned char>(type);
    object[sizeof object_magic + 1] = format_version;
    random_bytes(object.data() + header_size, static_cast<int>(salt_size + nonce_size));

    DerivedKey key;
    if (!derive_key(ikm, ikm_size, object.data() + header_size, info, key)) {
        throw std::runtime_error("Could not derive an object key");
    }
    Cipher cipher(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    int written = 0;
    int final_size = 0;
    const auto ok =
        cipher &&
        EVP_EncryptInit_ex(cipher.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce_size), nullptr) == 1 &&
        EVP_EncryptInit_ex(cipher.get(), nullptr, nullptr, key.bytes, object.data() + header_size + salt_size) == 1 &&
        EVP_EncryptUpdate(cipher.get(), nullptr, &written, aad.data(), static_cast<int>(aad.size())) == 1 &&
        EVP_EncryptUpdate(cipher.get(), object.data() + object_overhead, &written,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) == 1 &&
        EVP_EncryptFinal_ex(cipher.get(), object.data() + object_overhead + written, &final_size) == 1 &&
        written + final_size == static_cast<int>(plaintext.size()) &&
        EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag_size),
                            object.data() + header_size + salt_size + nonce_size) == 1;
    if (!ok) {
        secure_zero(object.data(), object.size());
        throw std::runtime_error("Could not encrypt object");
    }
    return object;
}

std::optional<std::string> open_object(char type, const unsigned char* ikm, std::size_t ikm_size,
                                       const char* info, const Bytes& aad, const Bytes& object,
                                       std::size_t max_plaintext) {
    if (object.size() < object_overhead || object.size() - object_overhead > max_plaintext) {
        return std::nullopt;
    }
    if (!std::equal(object_magic, object_magic + sizeof object_magic, object.begin()) ||
        object[sizeof object_magic] != static_cast<unsigned char>(type) ||
        object[sizeof object_magic + 1] != format_version) {
        return std::nullopt;
    }
    DerivedKey key;
    if (!derive_key(ikm, ikm_size, object.data() + header_size, info, key)) {
        return std::nullopt;
    }
    const auto ciphertext_size = object.size() - object_overhead;
    std::string plaintext(ciphertext_size, '\0');
    Cipher cipher(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    int written = 0;
    int final_size = 0;
    auto* tag = const_cast<unsigned char*>(object.data() + header_size + salt_size + nonce_size);
    const auto ok =
        cipher &&
        EVP_DecryptInit_ex(cipher.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce_size), nullptr) == 1 &&
        EVP_DecryptInit_ex(cipher.get(), nullptr, nullptr, key.bytes, object.data() + header_size + salt_size) == 1 &&
        EVP_DecryptUpdate(cipher.get(), nullptr, &written, aad.data(), static_cast<int>(aad.size())) == 1 &&
        EVP_DecryptUpdate(cipher.get(), reinterpret_cast<unsigned char*>(plaintext.data()), &written,
                          object.data() + object_overhead, static_cast<int>(ciphertext_size)) == 1 &&
        EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag_size), tag) == 1 &&
        EVP_DecryptFinal_ex(cipher.get(), reinterpret_cast<unsigned char*>(plaintext.data()) + written,
                            &final_size) == 1;
    if (!ok || written + final_size != static_cast<int>(ciphertext_size)) {
        secure_zero(plaintext.data(), plaintext.size());
        return std::nullopt;
    }
    plaintext.resize(static_cast<std::size_t>(written + final_size));
    return plaintext;
}

}  // namespace

void secure_zero(void* data, std::size_t size) {
    if (data != nullptr && size != 0) {
        OPENSSL_cleanse(data, size);
    }
}

schema::ObjectId new_object_id() {
    unsigned char bytes[schema::id_hex_size / 2];
    random_bytes(bytes, static_cast<int>(sizeof bytes));
    return hex_of(bytes, sizeof bytes);
}

Dek generate_dek() {
    Dek dek;
    random_bytes(dek.bytes.data(), static_cast<int>(dek.bytes.size()));
    return dek;
}

std::string sha256_hex(const Bytes& data) {
    unsigned char digest[32];
    if (EVP_Digest(data.data(), data.size(), digest, nullptr, EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("Could not hash object bytes");
    }
    return hex_of(digest, sizeof digest);
}

Bytes seal_index(const InstallationId& installation, const std::string& install_path,
                  const std::string& plaintext) {
    return seal_object(index_type, filesystem_master_key, sizeof filesystem_master_key, index_info,
                       index_aad(installation, install_path), plaintext, schema::max_index_plaintext);
}

std::optional<std::string> open_index(const InstallationId& installation, const std::string& install_path,
                                      const Bytes& object) {
    return open_object(index_type, filesystem_master_key, sizeof filesystem_master_key, index_info,
                       index_aad(installation, install_path), object, schema::max_index_plaintext);
}

Bytes seal_registry(const std::string& installation_name, const std::string& plaintext) {
    return seal_object(registry_type, filesystem_master_key, sizeof filesystem_master_key, registry_info,
                       Bytes(installation_name.begin(), installation_name.end()), plaintext, max_registry_plaintext);
}

std::optional<std::string> open_registry(const std::string& installation_name, const Bytes& object) {
    return open_object(registry_type, filesystem_master_key, sizeof filesystem_master_key, registry_info,
                       Bytes(installation_name.begin(), installation_name.end()), object, max_registry_plaintext);
}

Bytes seal_blob(const Dek& dek, const BlobBinding& binding, const std::string& plaintext) {
    return seal_object(blob_type, dek.bytes.data(), dek.bytes.size(), blob_info, blob_aad(binding),
                       plaintext, max_blob_plaintext);
}

std::optional<std::string> open_blob(const Dek& dek, const BlobBinding& binding, const Bytes& object) {
    return open_object(blob_type, dek.bytes.data(), dek.bytes.size(), blob_info, blob_aad(binding),
                       object, max_blob_plaintext);
}

namespace {

constexpr char wrap_label[] = "bibifi/fs/dek-wrap/v1";
constexpr std::size_t wrap_version_size = 1;
constexpr std::size_t wrap_ephemeral_offset = wrap_version_size;
constexpr std::size_t wrap_nonce_offset = wrap_ephemeral_offset + public_key_size;
constexpr std::size_t wrap_tag_offset = wrap_nonce_offset + nonce_size;
constexpr std::size_t wrap_ciphertext_offset = wrap_tag_offset + tag_size;
constexpr unsigned char wrap_version = 0x01;

static_assert(wrap_ciphertext_offset + dek_size == schema::wrapped_dek_size);

struct SharedSecret {
    unsigned char bytes[dek_size]{};
    ~SharedSecret() { secure_zero(bytes, sizeof bytes); }
};

struct EphemeralPrivate {
    unsigned char bytes[dek_size]{};
    ~EphemeralPrivate() { secure_zero(bytes, sizeof bytes); }
};

bool grant_byte(schema::GrantKind kind, unsigned char& out) {
    switch (kind) {
    case schema::GrantKind::owner:
        out = 0;
        return true;
    case schema::GrantKind::admin:
        out = 1;
        return true;
    case schema::GrantKind::recipient:
        out = 2;
        return true;
    }
    return false;
}

bool wrap_context_ok(const WrapContext& context, unsigned char& kind) {
    return schema::is_valid_id(context.file_id) && schema::is_valid_id(context.recipient_id) &&
           grant_byte(context.kind, kind);
}

Bytes wrap_info(const PublicKey& recipient, const unsigned char* ephemeral_public, const WrapContext& context) {
    Bytes info;
    info.insert(info.end(), wrap_label, wrap_label + sizeof(wrap_label) - 1);
    info.insert(info.end(), recipient.begin(), recipient.end());
    info.insert(info.end(), ephemeral_public, ephemeral_public + public_key_size);
    info.insert(info.end(), context.file_id.begin(), context.file_id.end());
    info.insert(info.end(), context.recipient_id.begin(), context.recipient_id.end());
    return info;
}

Bytes wrap_aad(const WrapContext& context, unsigned char kind) {
    Bytes aad;
    aad.insert(aad.end(), context.file_id.begin(), context.file_id.end());
    aad.insert(aad.end(), context.recipient_id.begin(), context.recipient_id.end());
    aad.push_back(kind);
    return aad;
}

bool derive_wrap_key(const unsigned char* shared, std::size_t shared_size, const Bytes& info, DerivedKey& key) {
    // No salt parameter: HKDF uses the standard all-zero salt of hash length.
    Kdf kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr), EVP_KDF_free);
    KdfContext context(kdf ? EVP_KDF_CTX_new(kdf.get()) : nullptr, EVP_KDF_CTX_free);
    char digest_name[] = "SHA256";
    auto* ikm = const_cast<unsigned char*>(shared);
    auto* info_bytes = const_cast<unsigned char*>(info.data());
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest_name, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, shared_size),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info_bytes, info.size()),
        OSSL_PARAM_construct_end()};
    return context && EVP_KDF_derive(context.get(), key.bytes, sizeof key.bytes, params) == 1;
}

bool agree(EVP_PKEY* local, EVP_PKEY* peer, SharedSecret& secret) {
    KeyContext context(EVP_PKEY_CTX_new(local, nullptr), EVP_PKEY_CTX_free);
    std::size_t length = sizeof secret.bytes;
    return context && EVP_PKEY_derive_init(context.get()) == 1 &&
           EVP_PKEY_derive_set_peer(context.get(), peer) == 1 &&
           EVP_PKEY_derive(context.get(), secret.bytes, &length) == 1 && length == sizeof secret.bytes;
}

// RFC 7748 X25519 low-order public keys (little-endian). Agreement with any of
// these yields a predictable shared secret.
constexpr unsigned char x25519_low_order[][public_key_size] = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
     0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
    {0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
     0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xdd, 0xf4, 0x53, 0x00},
    {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
    {0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
    {0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
    {0xcd, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
     0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x80},
};

bool is_low_order_public(const unsigned char* bytes) {
    int matched = 0;
    for (const auto& point : x25519_low_order) {
        matched |= CRYPTO_memcmp(bytes, point, public_key_size) == 0;
    }
    return matched != 0;
}

bool is_zero_shared(const SharedSecret& secret) {
    unsigned char zero[dek_size]{};
    return CRYPTO_memcmp(secret.bytes, zero, sizeof secret.bytes) == 0;
}

KeyHandle public_x25519(const unsigned char* bytes) {
    return KeyHandle(EVP_PKEY_new_raw_public_key_ex(nullptr, "X25519", nullptr, bytes, public_key_size),
                     EVP_PKEY_free);
}

KeyHandle private_x25519(const unsigned char* bytes) {
    return KeyHandle(EVP_PKEY_new_raw_private_key_ex(nullptr, "X25519", nullptr, bytes, dek_size),
                     EVP_PKEY_free);
}

}  // namespace

schema::WrappedDek wrap_key(const Dek& dek, const WrapContext& context, const PublicKey& recipient_encryption_key) {
    unsigned char kind = 0;
    if (!wrap_context_ok(context, kind)) {
        throw std::runtime_error("Invalid wrap context");
    }
    if (is_low_order_public(recipient_encryption_key.data())) {
        throw std::runtime_error("Could not wrap the file key");
    }
    EphemeralPrivate ephemeral_private;
    random_bytes(ephemeral_private.bytes, static_cast<int>(sizeof ephemeral_private.bytes));
    KeyHandle ephemeral = private_x25519(ephemeral_private.bytes);
    KeyHandle recipient = public_x25519(recipient_encryption_key.data());
    unsigned char ephemeral_public[public_key_size];
    std::size_t public_length = sizeof ephemeral_public;
    if (!ephemeral || !recipient ||
        EVP_PKEY_get_raw_public_key(ephemeral.get(), ephemeral_public, &public_length) != 1 ||
        public_length != sizeof ephemeral_public) {
        throw std::runtime_error("Could not generate a wrap key");
    }
    SharedSecret shared;
    if (!agree(ephemeral.get(), recipient.get(), shared) || is_zero_shared(shared)) {
        throw std::runtime_error("Could not agree on a wrap key");
    }
    const Bytes info = wrap_info(recipient_encryption_key, ephemeral_public, context);
    const Bytes aad = wrap_aad(context, kind);
    DerivedKey key;
    if (!derive_wrap_key(shared.bytes, sizeof shared.bytes, info, key)) {
        throw std::runtime_error("Could not derive a wrap key");
    }

    schema::WrappedDek wrapped;
    wrapped.envelope.assign(schema::wrapped_dek_size, 0);
    wrapped.envelope[0] = wrap_version;
    std::copy(ephemeral_public, ephemeral_public + sizeof ephemeral_public,
              wrapped.envelope.begin() + static_cast<std::ptrdiff_t>(wrap_ephemeral_offset));
    random_bytes(wrapped.envelope.data() + wrap_nonce_offset, static_cast<int>(nonce_size));
    Cipher cipher(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    int written = 0;
    int final_size = 0;
    const auto ok =
        cipher &&
        EVP_EncryptInit_ex(cipher.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce_size), nullptr) == 1 &&
        EVP_EncryptInit_ex(cipher.get(), nullptr, nullptr, key.bytes, wrapped.envelope.data() + wrap_nonce_offset) == 1 &&
        EVP_EncryptUpdate(cipher.get(), nullptr, &written, aad.data(), static_cast<int>(aad.size())) == 1 &&
        EVP_EncryptUpdate(cipher.get(), wrapped.envelope.data() + wrap_ciphertext_offset, &written, dek.bytes.data(),
                          static_cast<int>(dek.bytes.size())) == 1 &&
        EVP_EncryptFinal_ex(cipher.get(), wrapped.envelope.data() + wrap_ciphertext_offset + written, &final_size) == 1 &&
        written + final_size == static_cast<int>(dek.bytes.size()) &&
        EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag_size),
                            wrapped.envelope.data() + wrap_tag_offset) == 1;
    if (!ok) {
        secure_zero(wrapped.envelope.data(), wrapped.envelope.size());
        throw std::runtime_error("Could not wrap the file key");
    }
    return wrapped;
}

std::optional<Dek> unwrap_key(const accounts::Session& session, const WrapContext& context,
                              const schema::WrappedDek& wrapped) {
    unsigned char kind = 0;
    if (!session.encryption_key || wrapped.envelope.size() != schema::wrapped_dek_size ||
        wrapped.envelope[0] != wrap_version || !wrap_context_ok(context, kind)) {
        return std::nullopt;
    }
    if (is_low_order_public(wrapped.envelope.data() + wrap_ephemeral_offset)) {
        return std::nullopt;
    }
    KeyHandle ephemeral = public_x25519(wrapped.envelope.data() + wrap_ephemeral_offset);
    SharedSecret shared;
    if (!ephemeral || !agree(session.encryption_key.get(), ephemeral.get(), shared) ||
        is_zero_shared(shared)) {
        return std::nullopt;
    }
    PublicKey recipient{};
    std::size_t recipient_length = recipient.size();
    if (EVP_PKEY_get_raw_public_key(session.encryption_key.get(), recipient.data(), &recipient_length) != 1 ||
        recipient_length != recipient.size()) {
        return std::nullopt;
    }
    const Bytes info = wrap_info(recipient, wrapped.envelope.data() + wrap_ephemeral_offset, context);
    const Bytes aad = wrap_aad(context, kind);
    DerivedKey key;
    if (!derive_wrap_key(shared.bytes, sizeof shared.bytes, info, key)) {
        return std::nullopt;
    }
    Dek opened;
    Cipher cipher(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    int written = 0;
    int final_size = 0;
    auto* tag = const_cast<unsigned char*>(wrapped.envelope.data() + wrap_tag_offset);
    const auto ok =
        cipher &&
        EVP_DecryptInit_ex(cipher.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce_size), nullptr) == 1 &&
        EVP_DecryptInit_ex(cipher.get(), nullptr, nullptr, key.bytes,
                           wrapped.envelope.data() + wrap_nonce_offset) == 1 &&
        EVP_DecryptUpdate(cipher.get(), nullptr, &written, aad.data(), static_cast<int>(aad.size())) == 1 &&
        EVP_DecryptUpdate(cipher.get(), opened.bytes.data(), &written, wrapped.envelope.data() + wrap_ciphertext_offset,
                          static_cast<int>(dek_size)) == 1 &&
        EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag_size), tag) == 1 &&
        EVP_DecryptFinal_ex(cipher.get(), opened.bytes.data() + written, &final_size) == 1 &&
        written + final_size == static_cast<int>(dek_size);
    if (!ok) {
        return std::nullopt;
    }
    return opened;
}

}  // namespace crypto_store
