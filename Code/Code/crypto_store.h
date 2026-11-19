#pragma once

// Filesystem cryptography interface (issues #2, #3, #4). See SCHEMA.md
// sections 3, 4, and 7. Owner: KG.
//
// Everything uses OpenSSL EVP (AES-256-GCM, HKDF-SHA256, X25519, SHA-256,
// RAND_bytes). No primitive is implemented here. The functions are declared by
// issue #2 and defined in issue #3 (index and blob objects) and issue #4
// (wrap_key and unwrap_key). The FMK is a constant inside crypto_store.cpp and is
// never exposed through any header.
//
// Conventions:
//   seal_*  and wrap_key  throw std::runtime_error when OpenSSL or the CSPRNG
//                         fails (matching accounts.cpp). wrap_key also throws
//                         for a low-order peer public key or an all-zero
//                         shared secret.
//   open_*  and unwrap_key return std::nullopt for ANY failure (bad header, wrong
//                         length, wrong key, wrong context, tag mismatch,
//                         low-order ephemeral public key, or all-zero shared
//                         secret) and never release unauthenticated plaintext
//                         or details.

#include "accounts.h"
#include "fs_schema.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace crypto_store {

using Bytes = schema::Bytes;

constexpr std::size_t header_size = 8;
constexpr std::size_t salt_size = 32;
constexpr std::size_t nonce_size = 12;
constexpr std::size_t tag_size = 16;
// Bytes added around the ciphertext of each encrypted object.
constexpr std::size_t object_overhead = header_size + salt_size + nonce_size + tag_size;  // 68
constexpr std::size_t dek_size = 32;
constexpr std::size_t public_key_size = 32;
// Upper bound for one file's contents. Provisional until ngh2 and Mike confirm
// the limit (SCHEMA.md section 10), but storage never accepts more.
constexpr std::size_t max_blob_plaintext = 1024 * 1024;
constexpr std::size_t max_registry_plaintext = 16 * 1024 * 1024 - object_overhead;

using PublicKey = std::array<unsigned char, public_key_size>;

// Identifies one installation. Drawn once from the CSPRNG and stored in the
// per-install state file, never inside index.enc and never derived from a
// username, path, or public key. See SCHEMA.md sections 4 and 8.
constexpr std::size_t installation_id_size = 32;
using InstallationId = std::array<unsigned char, installation_id_size>;

// Overwrites memory in a way the optimizer cannot remove (OPENSSL_cleanse).
void secure_zero(void* data, std::size_t size);

// A 256-bit data-encryption key. Clears itself when destroyed. Move-only.
class Dek {
public:
    Dek() = default;
    Dek(const Dek&) = delete;
    Dek& operator=(const Dek&) = delete;
    Dek(Dek&& other) noexcept : bytes(other.bytes) { secure_zero(other.bytes.data(), other.bytes.size()); }
    Dek& operator=(Dek&& other) noexcept {
        if (this != &other) {
            bytes = other.bytes;
            secure_zero(other.bytes.data(), other.bytes.size());
        }
        return *this;
    }
    ~Dek() { secure_zero(bytes.data(), bytes.size()); }

    std::array<unsigned char, dek_size> bytes{};
};

// What an encrypted blob is bound to. All four values enter the AEAD
// associated data, so a blob copied to another name, owner, file, or version
// fails authentication.
struct BlobBinding {
    schema::BlobId blob_id;
    schema::AccountId owner_id;
    schema::FileId file_id;
    std::uint32_t blob_version = 1;
};

// What a wrapped DEK is bound to.
struct WrapContext {
    schema::FileId file_id;
    schema::AccountId recipient_id;
    schema::GrantKind kind = schema::GrantKind::owner;
};

// ---- Random material (issue #3) ---------------------------------------------

// 32 lowercase hexadecimal characters from RAND_bytes.
schema::ObjectId new_object_id();

// 256 random bits from RAND_bytes.
Dek generate_dek();

// Lowercase hexadecimal SHA-256 of the bytes (64 characters).
std::string sha256_hex(const Bytes& data);

// ---- Index object (issue #3) --------------------------------------------------

// Index associated data: "FILESYSTEM_INDEX_V1", its terminating NUL, the 32
// raw installation-id bytes, then the absolute install path. Both values are
// arguments. Neither is read from the plaintext or the ciphertext. The path
// is binding context, not a key.
inline Bytes index_aad(const InstallationId& installation, const std::string& install_path) {
    constexpr char label[] = "FILESYSTEM_INDEX_V1";
    Bytes aad(label, label + sizeof(label));
    aad.insert(aad.end(), installation.begin(), installation.end());
    aad.insert(aad.end(), install_path.begin(), install_path.end());
    return aad;
}

// Fresh salt and nonce on every call. Key = HKDF-SHA256(FMK, salt,
// "bibifi/fs/index/v1"). AAD = index_aad(installation, install_path).
Bytes seal_index(const InstallationId& installation, const std::string& install_path,
                 const std::string& plaintext);
std::optional<std::string> open_index(const InstallationId& installation, const std::string& install_path,
                                      const Bytes& object);

// The registry uses its own FMK derivation label and authenticates the
// installation name, which is derived from the working directory.
Bytes seal_registry(const std::string& installation_name, const std::string& plaintext);
std::optional<std::string> open_registry(const std::string& installation_name, const Bytes& object);

// ---- Blob object (issue #3) ---------------------------------------------------

// Fresh salt and nonce on every call. Key = HKDF-SHA256(DEK, salt,
// "bibifi/fs/blob/v1"). AAD is the canonical BlobBinding record (SCHEMA.md
// section 4). plaintext must not exceed max_blob_plaintext.
Bytes seal_blob(const Dek& dek, const BlobBinding& binding, const std::string& plaintext);
std::optional<std::string> open_blob(const Dek& dek, const BlobBinding& binding, const Bytes& object);

// ---- DEK wrapping (issue #4) ----------------------------------------------------

// Wraps the DEK for one account using an ephemeral X25519 key and the account's
// registered encryption public key (fetched from the account registry through
// storage::AccountDirectory, never from the index). The result is exactly
// schema::wrapped_dek_size bytes.
schema::WrappedDek wrap_key(const Dek& dek, const WrapContext& context,
                            const PublicKey& recipient_encryption_key);

// Unwraps with the private X25519 key held by the authenticated session. Fails
// for the wrong account, a malformed envelope, or any modified byte.
std::optional<Dek> unwrap_key(const accounts::Session& session, const WrapContext& context,
                              const schema::WrappedDek& wrapped);

}  // namespace crypto_store
