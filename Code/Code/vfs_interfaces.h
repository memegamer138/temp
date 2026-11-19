#pragma once

// Virtual tree, permissions, filesystem commands, and read-only sharing (#5-#8).
// Paths never map to host filenames. See SCHEMA.md for the persisted format.

#include "accounts.h"
#include "command_shell.h"
#include "fs_schema.h"
#include "storage.h"

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace vfs {

// Entry creation rules (SCHEMA.md section 10).
constexpr std::size_t max_name_length = 64;

inline bool is_valid_entry_name(const std::string& name) {
    if (name.empty() || name.size() > max_name_length || name == "." || name == "..") {
        return false;
    }
    for (char c : name) {
        const bool allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!allowed) {
            return false;
        }
    }
    return true;
}

// Where a resolved target lives in the synthesized tree.
//   root       "/" (synthesized: personal and shared; for admin also users)
//   user_root  "/<username>" (admin view only, synthesized)
//   personal   inside a user's personal tree
//   shared     inside a user's shared tree (always read-only)
enum class Zone { root, user_root, personal, shared };

enum class NodeKind { directory, file };

// The result of walking a virtual path. Carries what traversal learned so that
// permission checks and command bodies never walk the tree again.
struct Resolution {
    std::vector<std::string> path;  // normalized virtual components, empty for "/"
    Zone zone = Zone::root;
    NodeKind kind = NodeKind::directory;
    schema::AccountId owner_id;           // empty for root
    schema::DirectoryId directory_id;     // set for real directories
    schema::FileId file_id;               // set for file targets
    bool is_shared_reference = false;     // file reached through a shared_file entry
};

enum class ResolveError { none, not_found, not_a_directory, invalid_path, forbidden };

struct ResolveResult {
    std::optional<Resolution> value;
    // Success carries a value and error == none; failures have no value.
    ResolveError error = ResolveError::not_found;
};

// Resolves absolute and relative paths component by component. Handles ".",
// "..", and multiple segments, clamps ".." at the virtual root, and fails on the
// first missing component (so "missing/../personal" fails). A host path, symlink,
// or ID typed by the user never becomes a storage path. Index accounts that the
// registry does not list are treated as nonexistent.
ResolveResult resolve_path(const schema::FsIndex& index, const storage::AccountDirectory& accounts,
                           const accounts::Session& session, const std::string& path);

// Resolves everything but the last component and returns it in final_name, for
// mkdir and mkfile. The parent must be a directory.
ResolveResult resolve_parent(const schema::FsIndex& index, const storage::AccountDirectory& accounts,
                             const accounts::Session& session, const std::string& path,
                             std::string& final_name);

// ---- Permissions (Mike) -----------------------------------------------------

enum class Access { read, create_entry, replace_file, share };
enum class Decision { allow, forbidden };

// Called by traversal and again immediately before each operation. Policy
// (SCHEMA.md section 1): everyone reads their own tree and /shared; owners write
// only below their own /personal (admin included); admin reads every user's tree
// and writes nowhere else; /shared is read-only; only the owner shares.
Decision check_access(const accounts::Session& session, const schema::FsIndex& index,
                      Access access, const Resolution& target);

// ---- Sharing (Mike) -----------------------------------------------------------

// Adds a recipient grant (wrapping the DEK for the recipient from the registry's
// encryption key) and a shared_file entry under the recipient's /shared in ONE
// storage::Mutation. Idempotent for the same file and recipient. Display-name
// collisions follow SCHEMA.md section 10.
shell::Result share_file(accounts::Session& session, const storage::InstallationLock& lock,
                         const storage::AccountDirectory& accounts, const std::string& filename,
                         const std::string& recipient);

// ---- Command entry point (ngh2, Mike, wired by issue #10) -----------------------

// The shell::FilesystemHandler. Takes the installation lock, loads metadata,
// dispatches cd, pwd, ls, cat, mkdir, mkfile, and share, and returns a
// shell::Result for the shell to format. Updates session.current_directory only
// after a complete successful cd.
// Injectable registry under an already-held lock, also used by integration tests.
shell::Result execute(accounts::Session& session, const shell::Command& command,
                      const storage::AccountDirectory& registry, const storage::InstallationLock& lock);
shell::Result execute(accounts::Session& session, const shell::Command& command);

}  // namespace vfs
