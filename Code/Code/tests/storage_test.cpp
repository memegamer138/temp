#include "crypto_store.h"
#include "storage.h"

#include <openssl/evp.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <pwd.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;

void check(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::string installation_name_for(const std::string& cwd) {
    unsigned char digest[32];
    check(EVP_Digest(cwd.data(), cwd.size(), digest, nullptr, EVP_sha256(), nullptr) == 1, "digest");
    constexpr char digits[] = "0123456789abcdef";
    std::string text = "openssl-";
    for (unsigned char byte : digest) {
        text.push_back(digits[byte >> 4]);
        text.push_back(digits[byte & 0x0f]);
    }
    return text;
}

fs::path state_directory() {
    const auto close_passwd = [](std::FILE* file) { std::fclose(file); };
    const std::unique_ptr<std::FILE, decltype(close_passwd)> passwd(std::fopen("/etc/passwd", "r"), close_passwd);
    const char* home_path = std::getenv("HOME");
    if (passwd) {
        while (const auto* user = fgetpwent(passwd.get())) {
            if (user->pw_uid == geteuid()) {
                home_path = user->pw_dir;
                break;
            }
        }
    }
    check(home_path != nullptr && home_path[0] == '/', "home");
    return fs::path(home_path) / ".bibifi-state";
}

void remove_state(const std::string& cwd) {
    const auto name = installation_name_for(cwd);
    const auto directory = state_directory();
    std::error_code error;
    for (fs::directory_iterator entry(directory, error), end; !error && entry != end; entry.increment(error)) {
        const auto filename = entry->path().filename().string();
        if (filename.rfind(name, 0) == 0) {
            fs::remove(entry->path(), error);
        }
    }
}

class Workspace {
public:
    Workspace() {
        char pattern[] = "/tmp/bibifi-storage-XXXXXX";
        check(mkdtemp(pattern) != nullptr, "temp directory");
        root = pattern;
    }
    Workspace(const Workspace&) = delete;
    Workspace& operator=(const Workspace&) = delete;
    ~Workspace() {
        if (inside) {
            leave();
        }
        std::error_code error;
        fs::remove_all(root, error);
    }

    void enter() {
        previous = fs::current_path();
        fs::current_path(root);
        cwd_used = fs::current_path().string();
        inside = true;
    }
    void leave() {
        if (!inside) {
            return;
        }
        fs::current_path(previous);
        remove_state(cwd_used);
        inside = false;
    }

    fs::path root;

private:
    fs::path previous;
    std::string cwd_used;
    bool inside = false;
};

class ModeGuard {
public:
    ModeGuard(fs::path path, mode_t mode) : path_(std::move(path)) {
        struct stat status{};
        check(stat(path_.c_str(), &status) == 0, "stat");
        saved_ = status.st_mode & 0777;
        check(chmod(path_.c_str(), mode) == 0, "chmod");
    }
    ~ModeGuard() { chmod(path_.c_str(), saved_); }

private:
    fs::path path_;
    mode_t saved_ = 0;
};

storage::InstallationLock locked() { return storage::InstallationLock::acquire(); }

schema::FsIndex initialized() {
    auto lock = locked();
    check(storage::initialize_empty(lock).ok(), "initialize");
    schema::FsIndex index;
    check(storage::load_metadata(lock, index).ok(), "load bootstrap");
    check(schema::is_bootstrap_index(index), "bootstrap shape");
    return index;
}

std::vector<unsigned char> read_bytes(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(input), {});
}

void write_bytes(const fs::path& path, const std::vector<unsigned char>& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    check(static_cast<bool>(output), "write");
}

crypto_store::InstallationId read_installation_id() {
    const auto path = state_directory() / (installation_name_for(fs::current_path().string()) + ".fs");
    const auto bytes = read_bytes(path);
    check(bytes.size() == 8 + crypto_store::installation_id_size + 8, "state size");
    crypto_store::InstallationId id{};
    std::copy(bytes.begin() + 8, bytes.begin() + 8 + static_cast<std::ptrdiff_t>(id.size()), id.begin());
    return id;
}

storage::Result commit_same(storage::InstallationLock& lock, const schema::FsIndex& current) {
    storage::Mutation mutation;
    mutation.expected_generation = current.generation;
    mutation.next_index = current;
    return storage::commit_mutation(lock, mutation);
}

void test_admin_roots() {
    Workspace workspace;
    workspace.enter();
    auto lock = locked();
    check(storage::initialize_empty(lock).ok(), "initialize");
    schema::FsIndex bootstrap;
    check(storage::load_metadata(lock, bootstrap).ok(), "load");
    check(schema::is_bootstrap_index(bootstrap), "bootstrap before admin");
    schema::AccountId admin_id;
    const auto enrolled = storage::ensure_user_roots(lock, "admin", schema::Role::admin, admin_id);
    check(enrolled.ok() && enrolled.committed, "enroll admin");
    schema::FsIndex index;
    check(storage::load_metadata(lock, index).ok(), "load admin");
    check(index.generation == 2, "generation");
    check(index.accounts.size() == 1 && index.directories.size() == 2 && index.files.empty(), "shape");
    check(index.accounts.count(admin_id) == 1, "admin id");
    check(index.accounts[admin_id].username == "admin" && index.accounts[admin_id].role == schema::Role::admin,
          "admin record");
    schema::AccountId again;
    const auto adopted = storage::ensure_user_roots(lock, "admin", schema::Role::admin, again);
    check(adopted.ok() && !adopted.committed && again == admin_id, "adopt admin");
    schema::FsIndex after;
    check(storage::load_metadata(lock, after).ok() && after.generation == 2, "generation unchanged");
}

void test_tamper_and_blob() {
    Workspace workspace;
    workspace.enter();
    auto lock = locked();
    schema::AccountId admin_id;
    check(storage::initialize_empty(lock).ok(), "initialize");
    check(storage::ensure_user_roots(lock, "admin", schema::Role::admin, admin_id).ok(), "admin");
    schema::FsIndex index;
    check(storage::load_metadata(lock, index).ok(), "load");

    const auto dek = crypto_store::generate_dek();
    const std::string plaintext = "hello";
    schema::FileRecord file;
    file.owner_id = admin_id;
    file.blob_id = crypto_store::new_object_id();
    file.blob_version = 1;
    file.size = plaintext.size();
    crypto_store::BlobBinding binding{file.blob_id, admin_id, crypto_store::new_object_id(), 1};
    const auto sealed = crypto_store::seal_blob(dek, binding, plaintext);
    const auto opened = crypto_store::open_blob(dek, binding, sealed);
    check(opened && *opened == plaintext, "blob round trip");
    file.blob_sha256 = crypto_store::sha256_hex(sealed);
    schema::Grant grant;
    grant.account_id = admin_id;
    grant.kind = schema::GrantKind::owner;
    grant.wrapped_dek.envelope.assign(schema::wrapped_dek_size, 0);
    file.grants.push_back(grant);
    const schema::FileId file_id = binding.file_id;
    index.files.emplace(file_id, file);
    schema::Entry entry;
    entry.kind = schema::EntryKind::file;
    entry.target_id = file_id;
    index.directories[index.accounts[admin_id].personal_dir_id].entries["notes.txt"] = entry;

    storage::Mutation mutation;
    mutation.expected_generation = index.generation;
    mutation.next_index = index;
    mutation.new_blobs.push_back(storage::StagedBlob{file.blob_id, sealed});
    const auto committed = storage::commit_mutation(lock, mutation);
    check(committed.ok() && committed.committed, "commit blob");
    crypto_store::Bytes stored;
    check(storage::read_blob(lock, file, stored).ok() && stored == sealed, "read blob");

    auto on_disk = read_bytes(fs::path("filesystem/blobs") / (file.blob_id + ".enc"));
    on_disk.back() ^= 0x01;
    write_bytes(fs::path("filesystem/blobs") / (file.blob_id + ".enc"), on_disk);
    crypto_store::Bytes mismatched;
    check(storage::read_blob(lock, file, mismatched).error == storage::Error::blob_mismatch, "blob tamper");
    fs::remove(fs::path("filesystem/blobs") / (file.blob_id + ".enc"));
    check(storage::read_blob(lock, file, mismatched).error == storage::Error::blob_missing, "blob missing");

    auto index_bytes = read_bytes("filesystem/index.enc");
    index_bytes.back() ^= 0x01;
    write_bytes("filesystem/index.enc", index_bytes);
    schema::FsIndex ignored;
    check(storage::load_metadata(lock, ignored).error == storage::Error::not_authentic, "index tamper");
}

void test_cross_install_copy() {
    Workspace source;
    Workspace destination;
    source.enter();
    {
        auto lock = locked();
        check(storage::initialize_empty(lock).ok(), "source init");
    }
    const auto source_id = read_installation_id();
    const auto source_path = fs::current_path().string();
    const auto source_index = read_bytes("filesystem/index.enc");
    check(crypto_store::open_index(source_id, source_path, source_index).has_value(), "source opens");
    source.leave();

    destination.enter();
    {
        auto lock = locked();
        check(storage::initialize_empty(lock).ok(), "destination init");
    }
    const auto destination_id = read_installation_id();
    write_bytes("filesystem/index.enc", source_index);
    check(!crypto_store::open_index(destination_id, fs::current_path().string(), source_index), "copied index rejected");
    auto lock = locked();
    schema::FsIndex ignored;
    check(storage::load_metadata(lock, ignored).error == storage::Error::not_authentic, "load rejects copy");
}

void test_rollback_and_cleanup() {
    Workspace workspace;
    workspace.enter();
    auto index = initialized();
    const auto original = read_bytes("filesystem/index.enc");
    auto lock = locked();
    const auto committed = commit_same(lock, index);
    check(committed.ok() && committed.committed, "second generation");
    write_bytes("filesystem/index.enc", original);
    schema::FsIndex ignored;
    check(storage::load_metadata(lock, ignored).error == storage::Error::rolled_back, "rollback");
}

void test_cleanup_after_good_load() {
    Workspace workspace;
    workspace.enter();
    check(initialized().generation == 1, "generation 1");
    auto lock = locked();
    const std::string blob_name(std::string(schema::id_hex_size, 'a') + ".enc");
    const std::string blob_tmp(std::string(schema::id_hex_size, 'b') + ".tmp");
    const std::string index_tmp("index." + std::string(schema::id_hex_size, 'c') + ".tmp");
    write_bytes("filesystem/blobs/" + blob_name, {1, 2, 3});
    write_bytes("filesystem/blobs/" + blob_tmp, {4});
    write_bytes("filesystem/blobs/outside.enc", {9});
    write_bytes("filesystem/" + index_tmp, {5});
    schema::FsIndex index;
    check(storage::load_metadata(lock, index).ok(), "load cleans");
    check(!fs::exists("filesystem/blobs/" + blob_name), "unreferenced blob");
    check(!fs::exists("filesystem/blobs/" + blob_tmp), "blob tmp");
    check(!fs::exists("filesystem/" + std::string("index.") + std::string(schema::id_hex_size, 'c') + ".tmp"), "index tmp");
    check(fs::exists("filesystem/blobs/outside.enc"), "unrelated name kept");
    check(fs::exists("filesystem/index.enc"), "index kept");
}

void test_generation_conflict() {
    Workspace workspace;
    workspace.enter();
    schema::FsIndex index;
    {
        auto lock = locked();
        check(storage::initialize_empty(lock).ok(), "initialize");
        check(storage::load_metadata(lock, index).ok(), "load");
    }
    auto child = [&index]() {
        try {
            auto lock = locked();
            const auto result = commit_same(lock, index);
            if (result.ok()) {
                _exit(0);
            }
            _exit(result.error == storage::Error::generation_conflict ? 2 : 1);
        } catch (...) {
            _exit(1);
        }
    };
    const pid_t first = fork();
    check(first >= 0, "fork");
    if (first == 0) {
        child();
    }
    const pid_t second = fork();
    check(second >= 0, "fork");
    if (second == 0) {
        child();
    }
    int first_status = 0;
    int second_status = 0;
    check(waitpid(first, &first_status, 0) == first && waitpid(second, &second_status, 0) == second, "wait");
    const int first_code = WEXITSTATUS(first_status);
    const int second_code = WEXITSTATUS(second_status);
    check((first_code == 0 && second_code == 2) || (first_code == 2 && second_code == 0), "one conflict");
}

struct LiveBlob {
    schema::FileRecord file;
    crypto_store::Bytes bytes;
};

LiveBlob commit_live_blob(storage::InstallationLock& lock) {
    schema::AccountId admin_id;
    check(storage::ensure_user_roots(lock, "admin", schema::Role::admin, admin_id).ok(), "admin");
    schema::FsIndex index;
    check(storage::load_metadata(lock, index).ok(), "load for blob");
    const auto dek = crypto_store::generate_dek();
    schema::FileRecord file;
    file.owner_id = admin_id;
    file.blob_id = crypto_store::new_object_id();
    file.blob_version = 1;
    file.size = 5;
    crypto_store::BlobBinding binding{file.blob_id, admin_id, crypto_store::new_object_id(), 1};
    const auto sealed = crypto_store::seal_blob(dek, binding, "hello");
    file.blob_sha256 = crypto_store::sha256_hex(sealed);
    schema::Grant grant;
    grant.account_id = admin_id;
    grant.kind = schema::GrantKind::owner;
    grant.wrapped_dek.envelope.assign(schema::wrapped_dek_size, 0);
    file.grants.push_back(grant);
    index.files.emplace(binding.file_id, file);
    schema::Entry entry;
    entry.kind = schema::EntryKind::file;
    entry.target_id = binding.file_id;
    index.directories[index.accounts[admin_id].personal_dir_id].entries["notes.txt"] = entry;
    storage::Mutation mutation;
    mutation.expected_generation = index.generation;
    mutation.next_index = std::move(index);
    mutation.new_blobs.push_back(storage::StagedBlob{file.blob_id, sealed});
    check(storage::commit_mutation(lock, mutation).ok(), "commit live blob");
    return {file, sealed};
}

void test_filesystem_symlink_is_not_followed() {
    Workspace workspace;
    workspace.enter();
    {
        auto lock = locked();
        check(storage::initialize_empty(lock).ok(), "initialize");
    }
    fs::rename("filesystem", "real-filesystem");
    fs::create_directory_symlink("real-filesystem", "filesystem");
    write_bytes("real-filesystem/blobs/outside.enc", {9, 9, 9});
    auto lock = locked();
    schema::FsIndex ignored;
    check(!storage::load_metadata(lock, ignored).ok(), "symlink rejected");
    check(fs::exists("real-filesystem/blobs/outside.enc"), "outside blob kept");
}

void test_aborted_commit_keeps_live_blob() {
    Workspace workspace;
    workspace.enter();
    auto lock = locked();
    check(storage::initialize_empty(lock).ok(), "initialize");
    const LiveBlob live = commit_live_blob(lock);
    schema::FsIndex index;
    check(storage::load_metadata(lock, index).ok(), "reload");
    storage::Mutation mutation;
    mutation.expected_generation = index.generation;
    mutation.next_index = index;
    mutation.new_blobs.push_back(storage::StagedBlob{live.file.blob_id, {1, 2, 3, 4}});
    mutation.new_blobs.push_back(storage::StagedBlob{"not-valid", {5}});
    const auto blocked = storage::commit_mutation(lock, mutation);
    check(blocked.error == storage::Error::corrupt && !blocked.committed, "aborted commit");
    check(read_bytes(fs::path("filesystem/blobs") / (live.file.blob_id + ".enc")) == live.bytes, "live bytes unchanged");
}

void test_copied_index_and_state_rejected() {
    Workspace source;
    Workspace destination;
    source.enter();
    {
        auto lock = locked();
        check(storage::initialize_empty(lock).ok(), "source init");
    }
    const auto source_index = read_bytes("filesystem/index.enc");
    const auto source_state = read_bytes(state_directory() / (installation_name_for(fs::current_path().string()) + ".fs"));
    source.leave();

    destination.enter();
    auto lock = locked();
    check(storage::initialize_empty(lock).ok(), "destination init");
    const LiveBlob live = commit_live_blob(lock);
    write_bytes("filesystem/index.enc", source_index);
    write_bytes(state_directory() / (installation_name_for(fs::current_path().string()) + ".fs"), source_state);
    schema::FsIndex ignored;
    check(storage::load_metadata(lock, ignored).error == storage::Error::not_authentic, "copied pair rejected");
    check(fs::exists(fs::path("filesystem/blobs") / (live.file.blob_id + ".enc")), "destination blob kept");
}

void test_commit_failures() {
    Workspace workspace;
    workspace.enter();
    auto index = initialized();
    auto lock = locked();
    {
        ModeGuard unwritable("filesystem/blobs", 0555);
        storage::Mutation mutation;
        mutation.expected_generation = index.generation;
        mutation.next_index = index;
        mutation.new_blobs.push_back(storage::StagedBlob{crypto_store::new_object_id(), {1, 2, 3, 4}});
        const auto blocked = storage::commit_mutation(lock, mutation);
        check(blocked.error == storage::Error::io && !blocked.committed, "unwritable before rename");
    }
    schema::FsIndex still;
    check(storage::load_metadata(lock, still).ok() && still.generation == 1, "unchanged");

    check(setenv("BIBIFI_FAIL_AFTER_RENAME", "1", 1) == 0, "setenv");
    const auto visible = commit_same(lock, still);
    unsetenv("BIBIFI_FAIL_AFTER_RENAME");
    check(visible.error == storage::Error::io && visible.committed, "failure after rename");
    schema::FsIndex recovered;
    check(storage::load_metadata(lock, recovered).ok() && recovered.generation == 2, "reload catches up");
}

}  // namespace

int main() {
    try {
        test_admin_roots();
        test_tamper_and_blob();
        test_cross_install_copy();
        test_rollback_and_cleanup();
        test_cleanup_after_good_load();
        test_generation_conflict();
        test_commit_failures();
        test_filesystem_symlink_is_not_followed();
        test_aborted_commit_keeps_live_blob();
        test_copied_index_and_state_rejected();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
