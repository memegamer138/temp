#pragma once

// Shared filesystem records (issue #2). See SCHEMA.md for the full contract.
//
// Ownership:
//   KG      Account/File/Grant/WrappedDek/FsIndex records, ID rules, limits,
//           serialization, and invariants. Frozen.
//   ngh2    Directory/Entry semantics (names, collisions, traversal).
//           BOOTSTRAP ONLY: the shapes below let storage work proceed, but
//           ngh2 must review and own them before issue #2 closes.
//
// This header has no OpenSSL or JSON dependency. serialize_index() and
// parse_index() are implemented in issue #3 with nlohmann/json.

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace schema {

using Bytes = std::vector<unsigned char>;

// An object ID is 128 random bits written as 32 lowercase hexadecimal
// characters. Accounts, directories, files, and blobs all use this form. A
// creator that draws an ID already in use must draw again and never overwrite.
using ObjectId = std::string;
using AccountId = ObjectId;
using DirectoryId = ObjectId;
using FileId = ObjectId;
using BlobId = ObjectId;

constexpr std::size_t id_hex_size = 32;
constexpr std::uint32_t index_format_version = 1;
// A decrypted index larger than this is rejected before parsing.
constexpr std::size_t max_index_plaintext = 16 * 1024 * 1024;
constexpr std::size_t sha256_hex_size = 64;
// Fixed size of a wrapped DEK envelope. See SCHEMA.md section 4.
constexpr std::size_t wrapped_dek_size = 93;

// Reserved names that a username may never take (the admin root lists users
// next to the admin's own "personal" and "shared").
inline bool is_reserved_username(const std::string& name) {
    return name == "personal" || name == "shared" || name == "admin";
}

inline bool is_valid_id(const std::string& id) {
    if (id.size() != id_hex_size) {
        return false;
    }
    for (char c : id) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

enum class Role { user, admin };

// The kinds of directory entry. shared_file is the shared reference: it lives
// in a recipient's "shared" directory and points at a file somebody else owns.
enum class EntryKind { directory, file, shared_file };

// Why an account holds a wrapped DEK. recipient is a share. There is no write
// grant: a share is read-only by construction.
enum class GrantKind { owner, admin, recipient };

// ---- Account (KG) ---------------------------------------------------------

// A filesystem identity. Public keys are NOT stored here. They come from the
// authenticated account registry (issue #1) and are joined by username.
struct AccountEntry {
    std::string username;
    Role role = Role::user;
    DirectoryId personal_dir_id;
    DirectoryId shared_dir_id;
};

// ---- Tree (VFS) -------------------------------------------

// Name rules, collision behavior, and traversal are implemented by vfs.cpp;
// see SCHEMA.md section 10.
struct Entry {
    EntryKind kind = EntryKind::file;
    // DirectoryId for directory, FileId for file and shared_file.
    ObjectId target_id;
};

struct Directory {
    AccountId owner_id;
    // Entry names are unique within a directory (std::map enforces it).
    std::map<std::string, Entry> entries;
};

// ---- File, grant, wrapped DEK (KG) -----------------------------------------

// The DEK wrapped for one account. Opaque outside crypto_store (issue #4).
struct WrappedDek {
    Bytes envelope;  // exactly wrapped_dek_size bytes
};

// One account's right to read one file. At most one per file and account.
struct Grant {
    AccountId account_id;
    GrantKind kind = GrantKind::owner;
    WrappedDek wrapped_dek;
};

// The file ID is stable for the life of the file. An overwrite keeps file_id
// and the DEK, draws a new blob_id, and increments blob_version. Every grant,
// including every share, therefore sees the new contents.
struct FileRecord {
    AccountId owner_id;
    BlobId blob_id;
    std::uint32_t blob_version = 1;
    std::uint64_t size = 0;      // plaintext length in bytes
    std::string blob_sha256;     // 64 hex characters over the whole blob file
    std::vector<Grant> grants;
};

// ---- Index (KG) -------------------------------------------------------------

// The decrypted plaintext of filesystem/index.enc. Every table is keyed by the
// object's ID, so the records above carry no id field of their own.
struct FsIndex {
    std::uint32_t format = index_format_version;
    // Increases by one on every commit. Used for rollback detection.
    std::uint64_t generation = 0;
    std::map<AccountId, AccountEntry> accounts;
    std::map<DirectoryId, Directory> directories;
    std::map<FileId, FileRecord> files;
};

// A first-run index. validate_index (issue #3) accepts this and only this as an
// empty index. Any other empty or partial index is corrupt.
inline bool is_bootstrap_index(const FsIndex& index) {
    return index.format == index_format_version && index.generation >= 1 &&
           index.accounts.empty() && index.directories.empty() && index.files.empty();
}

// Checks every invariant in SCHEMA.md section 5. A bootstrap index is valid.
// Every other index must contain exactly one admin and satisfy the remaining
// invariants. Returns an empty string when the index is consistent, otherwise
// a short reason for logs and tests (never printed to a user). Implemented in
// issue #3.
std::string validate_index(const FsIndex& index);

// Deterministic JSON text for the index. Implemented in issue #3.
std::string serialize_index(const FsIndex& index);

// Parses and validates. Returns nullopt for any malformed, oversized, unknown
// field, duplicate key, wrong type, or invariant failure. Never throws.
std::optional<FsIndex> parse_index(const std::string& text);

}  // namespace schema
