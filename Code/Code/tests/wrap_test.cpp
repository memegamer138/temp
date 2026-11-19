#include "crypto_store.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void check(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

struct Identity {
    accounts::Session session;
    crypto_store::PublicKey public_key{};
};

Identity make_identity() {
    unsigned char seed[crypto_store::dek_size];
    check(RAND_bytes(seed, static_cast<int>(sizeof seed)) == 1, "seed");
    Identity identity;
    identity.session.encryption_key.reset(
        EVP_PKEY_new_raw_private_key_ex(nullptr, "X25519", nullptr, seed, sizeof seed), EVP_PKEY_free);
    OPENSSL_cleanse(seed, sizeof seed);
    check(static_cast<bool>(identity.session.encryption_key), "private key");
    std::size_t length = identity.public_key.size();
    check(EVP_PKEY_get_raw_public_key(identity.session.encryption_key.get(), identity.public_key.data(), &length) == 1 &&
              length == identity.public_key.size(),
          "public key");
    return identity;
}

crypto_store::WrapContext context_for(const std::string& recipient) {
    crypto_store::WrapContext context;
    context.file_id = std::string(schema::id_hex_size, 'a');
    context.recipient_id = recipient;
    context.kind = schema::GrantKind::owner;
    return context;
}

bool same_dek(const crypto_store::Dek& left, const crypto_store::Dek& right) {
    return CRYPTO_memcmp(left.bytes.data(), right.bytes.data(), left.bytes.size()) == 0;
}

void test_wrap_round_trip() {
    const Identity owner = make_identity();
    const Identity other = make_identity();
    const auto context = context_for(std::string(schema::id_hex_size, 'b'));
    const crypto_store::Dek dek = crypto_store::generate_dek();
    const schema::WrappedDek wrapped = crypto_store::wrap_key(dek, context, owner.public_key);
    check(wrapped.envelope.size() == schema::wrapped_dek_size, "envelope size");
    check(wrapped.envelope[0] == 0x01, "version");

    const auto opened = crypto_store::unwrap_key(owner.session, context, wrapped);
    check(opened && same_dek(*opened, dek), "round trip");

    check(!crypto_store::unwrap_key(other.session, context, wrapped), "wrong recipient");

    schema::WrappedDek flipped = wrapped;
    flipped.envelope.back() ^= 0x01;
    check(!crypto_store::unwrap_key(owner.session, context, flipped), "modified envelope");

    schema::WrappedDek truncated = wrapped;
    truncated.envelope.pop_back();
    check(!crypto_store::unwrap_key(owner.session, context, truncated), "truncated envelope");

    schema::WrappedDek bad_version = wrapped;
    bad_version.envelope[0] = 0x02;
    check(!crypto_store::unwrap_key(owner.session, context, bad_version), "bad version");

    accounts::Session missing = owner.session;
    missing.encryption_key.reset();
    check(!crypto_store::unwrap_key(missing, context, wrapped), "missing session key");

    crypto_store::WrapContext other_file = context;
    other_file.file_id = std::string(schema::id_hex_size, 'c');
    check(!crypto_store::unwrap_key(owner.session, other_file, wrapped), "file binding");

    crypto_store::WrapContext other_kind = context;
    other_kind.kind = schema::GrantKind::recipient;
    check(!crypto_store::unwrap_key(owner.session, other_kind, wrapped), "grant binding");

    crypto_store::WrapContext other_recipient = context;
    other_recipient.recipient_id = std::string(schema::id_hex_size, 'd');
    check(!crypto_store::unwrap_key(owner.session, other_recipient, wrapped), "recipient binding");

    schema::WrappedDek zero_ephemeral = wrapped;
    std::fill(zero_ephemeral.envelope.begin() + 1,
              zero_ephemeral.envelope.begin() + 1 + static_cast<std::ptrdiff_t>(crypto_store::public_key_size),
              static_cast<unsigned char>(0));
    check(!crypto_store::unwrap_key(owner.session, context, zero_ephemeral), "zero ephemeral");
}

void test_reject_low_order() {
    const auto context = context_for(std::string(schema::id_hex_size, 'b'));
    const crypto_store::Dek dek = crypto_store::generate_dek();
    crypto_store::PublicKey zero{};
    bool threw_zero = false;
    try {
        crypto_store::wrap_key(dek, context, zero);
    } catch (const std::runtime_error&) {
        threw_zero = true;
    }
    check(threw_zero, "zero public key");

    // Another RFC 7748 low-order point (not the all-zero key).
    crypto_store::PublicKey low_order = {
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
        0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00};
    bool threw_low = false;
    try {
        crypto_store::wrap_key(dek, context, low_order);
    } catch (const std::runtime_error&) {
        threw_low = true;
    }
    check(threw_low, "low-order public key");
}

}  // namespace

int main() {
    try {
        test_wrap_round_trip();
        test_reject_low_order();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
