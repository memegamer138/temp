#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <openssl/types.h>

namespace storage { class AccountDirectory; class InstallationLock; }

namespace accounts {

struct Session {
    std::string username;
    std::filesystem::path key_directory;
    // OpenSSL owns the private encryption key and frees it when the last
    // session reference is released. The filesystem uses it to unwrap file keys.
    std::shared_ptr<EVP_PKEY> encryption_key;
    // An empty sequence represents the virtual root. Entries are virtual names.
    std::vector<std::string> current_directory;

    bool is_admin() const { return username == "admin"; }
};

Session login(const std::filesystem::path& keyfile);
// Valid registry/command name, including the bootstrapped admin account.
// personal/shared are never account names. add_user preserves duplicate-admin
// handling rather than treating an existing admin as an invalid command.
bool valid_username(const std::string& username);
// Reads enrolled keys under the caller's installation lock; never public_keys/.
std::unique_ptr<storage::AccountDirectory> directory_snapshot(const storage::InstallationLock& lock);

bool add_user(const Session& admin, const std::string& username);

}  // namespace accounts
