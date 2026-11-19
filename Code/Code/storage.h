#pragma once

// Encrypted object storage interface (issues #2, #3). See SCHEMA.md sections 2,
// 8, and 9. Owner: KG. Declared by issue #2, defined by issue #3.
//
// Every function that touches filesystem/ requires an InstallationLock. A
// filesystem command takes the lock once, then loads, checks permissions,
// mutates, commits, and releases. The shell does not hold the lock while it
// waits for input. Reads lock too, so a writer cannot delete a blob mid-read.
//
// Results never carry text meant for users. The shell prints the existing
// "Could not complete command" for every Error except where a caller maps an
// outcome itself (shell::Status::storage_error).

#include "crypto_store.h"
#include "fs_schema.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace storage {

enum class Error {
    none,
    missing_index,         // registry exists but filesystem/index.enc does not
    not_authentic,         // header, length, or AEAD tag check failed
    corrupt,               // authentic but violates a schema invariant
    rolled_back,           // generation is older than the pinned generation
    generation_conflict,   // expected_generation no longer matches
    too_large,             // index or blob over its limit
    blob_missing,          // a referenced blob is absent
    blob_mismatch,         // blob SHA-256 differs from the index
    already_exists,        // initialize_empty on an existing index
    io                     // read, write, fsync, or rename failed
};

struct Result {
    Error error = Error::none;
    // Meaningful for commit_mutation. False until the index.enc rename
    // succeeds, then true even if a later fsync, pin update, or retired-blob
    // deletion fails. Other calls leave it false. ok() does not consult it.
    bool committed = false;
    bool ok() const { return error == Error::none; }
};

// RAII exclusive installation lock (flock). Movable, not copyable. Throws
// std::runtime_error from acquire() if the lock cannot be taken.
//
// accounts.cpp and VFS use this same lock. A second flock on another descriptor
// of the same file would block the process forever.
class InstallationLock {
public:
    static InstallationLock acquire();
    InstallationLock(InstallationLock&& other) noexcept;
    InstallationLock& operator=(InstallationLock&& other) noexcept;
    InstallationLock(const InstallationLock&) = delete;
    InstallationLock& operator=(const InstallationLock&) = delete;
    ~InstallationLock();

private:
    InstallationLock() = default;
    int fd_ = -1;
};

// Read access to the authenticated account registry (issue #1). The filesystem
// index never stores public keys, so wrapping and enrollment checks go through
// this interface. accounts::directory_snapshot supplies it under the same lock.
class AccountDirectory {
public:
    virtual ~AccountDirectory() = default;
    // The registered X25519 key, or nullopt if the name is not enrolled.
    virtual std::optional<crypto_store::PublicKey> encryption_key(const std::string& username) const = 0;
    virtual bool is_enrolled(const std::string& username) const = 0;
    // Enrolled usernames only (used for the admin root listing).
    virtual std::vector<std::string> usernames() const = 0;
};

// A blob already encrypted by crypto_store::seal_blob.
struct StagedBlob {
    schema::BlobId blob_id;
    crypto_store::Bytes object;
};

// One atomic change: a new index plus the blobs it needs and the blobs it
// retires. Used by directory creation, file replacement, sharing, and
// enrollment alike.
struct Mutation {
    // The generation the caller loaded. commit_mutation fails with
    // generation_conflict if the stored generation differs.
    std::uint64_t expected_generation = 0;
    // Its generation field is overwritten with expected_generation + 1.
    schema::FsIndex next_index;
    std::vector<StagedBlob> new_blobs;
    std::vector<schema::BlobId> retired_blobs;
};

// First run only: creates blobs/, draws a 32-byte installation id into the
// per-install state file, and writes a bootstrap index at generation 1 (no
// accounts). Fails with already_exists if index.enc exists. Does not enroll
// admin. ensure_user_roots does that on the next commit.
Result initialize_empty(const InstallationLock& lock);

// Reads the installation id from the per-install state file (never from
// index.enc) and passes it to open_index. Then parses, validates invariants,
// checks the generation pin, and removes staging files and unreferenced blobs
// left by an interrupted commit. A missing installation id when an index
// exists fails closed. If the loaded generation is higher than the pin, the
// pin is raised to that generation. A lower generation returns rolled_back.
Result load_metadata(const InstallationLock& lock, schema::FsIndex& out);

// Stages blobs, renames index.enc into place (the commit point), updates the
// generation pin, then deletes retired blobs. The installation id used to seal
// the index is read from the state file, not from the candidate index. On any
// failure before the index rename, committed is false and the previous state
// stays current. After the rename, committed is true even when a later step
// returns io. Callers must reload and must not retry the old expected_generation.
Result commit_mutation(const InstallationLock& lock, Mutation& mutation);

// Reads blobs/<blob_id>.enc and checks its SHA-256 against the file record.
// Decryption stays with crypto_store::open_blob.
Result read_blob(const InstallationLock& lock, const schema::FileRecord& file,
                 crypto_store::Bytes& object_out);

// The enrollment boundary (SCHEMA.md section 9). Idempotent. On first launch
// the loaded index is the bootstrap index from initialize_empty, and this call
// adds admin and both roots. Otherwise it adds an AccountEntry with fresh
// personal and shared directories, or adopts an existing entry with this
// username, and commits one new generation. adduser calls this BEFORE
// publishing the account in the registry, so a user is never loginable
// without roots, and a failure leaves only an inert entry.
Result ensure_user_roots(const InstallationLock& lock, const std::string& username,
                         schema::Role role, schema::AccountId& account_id_out);

}  // namespace storage
