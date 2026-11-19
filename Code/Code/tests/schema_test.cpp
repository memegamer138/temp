// Unit tests for the issue #2 schema freeze helpers that already have
// implementations (inline in the headers). Storage and crypto bodies land in
// #3 and #4, so those APIs are not exercised here. The installation-id AAD,
// the bootstrap predicate, and Result::committed are contract rules and are
// checked below.
//
// Build and run from the Code directory:
//   g++ -std=c++17 -Wall -Wextra -pedantic -I. tests/schema_test.cpp -o /tmp/schema_test
//   /tmp/schema_test

#include "crypto_store.h"
#include "fs_schema.h"
#include "storage.h"
#include "vfs_interfaces.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>

namespace {

void test_object_ids() {
    assert(schema::id_hex_size == 32);
    assert(schema::is_valid_id("0123456789abcdef0123456789abcdef"));
    assert(schema::is_valid_id(std::string(32, '0')));
    assert(schema::is_valid_id(std::string(32, 'f')));

    assert(!schema::is_valid_id(""));
    assert(!schema::is_valid_id("0123456789abcdef0123456789abcde"));   // 31
    assert(!schema::is_valid_id("0123456789abcdef0123456789abcdef0"));  // 33
    assert(!schema::is_valid_id("0123456789ABCDEF0123456789abcdef"));  // uppercase
    assert(!schema::is_valid_id("0123456789abcdef0123456789abcdeg"));  // non-hex
    assert(!schema::is_valid_id("0123456789abcdef 123456789abcdef"));  // space
}

void test_reserved_usernames() {
    assert(schema::is_reserved_username("personal"));
    assert(schema::is_reserved_username("shared"));
    assert(schema::is_reserved_username("admin"));

    assert(!schema::is_reserved_username("alice"));
    assert(!schema::is_reserved_username("Personal"));
    assert(!schema::is_reserved_username("admin_"));
    assert(!schema::is_reserved_username(""));
}

void test_entry_names() {
    assert(vfs::max_name_length == 64);
    assert(vfs::is_valid_entry_name("notes.txt"));
    assert(vfs::is_valid_entry_name("a"));
    assert(vfs::is_valid_entry_name("A-Z_0-9."));
    assert(vfs::is_valid_entry_name(std::string(64, 'x')));

    assert(!vfs::is_valid_entry_name(""));
    assert(!vfs::is_valid_entry_name("."));
    assert(!vfs::is_valid_entry_name(".."));
    assert(!vfs::is_valid_entry_name("a/b"));
    assert(!vfs::is_valid_entry_name("a b"));
    assert(!vfs::is_valid_entry_name("x@y"));  // reserved for share collisions
    assert(!vfs::is_valid_entry_name(std::string("a\0b", 3)));
    assert(!vfs::is_valid_entry_name(std::string(65, 'x')));
}

void test_format_constants() {
    // Object envelope: header(8) + salt(32) + nonce(12) + tag(16) = 68.
    assert(crypto_store::object_overhead == 68);
    assert(crypto_store::object_overhead == crypto_store::header_size + crypto_store::salt_size +
               crypto_store::nonce_size + crypto_store::tag_size);

    // Wrapped DEK: version(1) + ephemeral pub(32) + nonce(12) + tag(16) + DEK(32).
    assert(schema::wrapped_dek_size == 93);
    assert(schema::wrapped_dek_size == 1 + crypto_store::public_key_size + crypto_store::nonce_size +
               crypto_store::tag_size + crypto_store::dek_size);

    assert(schema::sha256_hex_size == 64);
    assert(schema::index_format_version == 1);
    assert(schema::max_index_plaintext == 16 * 1024 * 1024);
    assert(crypto_store::max_blob_plaintext == 1024 * 1024);
    assert(crypto_store::dek_size == 32);
}

void test_record_defaults_and_shapes() {
    schema::FsIndex index;
    assert(index.format == schema::index_format_version);
    assert(index.generation == 0);
    assert(index.accounts.empty());
    assert(index.directories.empty());
    assert(index.files.empty());

    schema::AccountEntry account;
    account.username = "alice";
    account.role = schema::Role::user;
    account.personal_dir_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    account.shared_dir_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    assert(schema::is_valid_id(account.personal_dir_id));
    assert(schema::is_valid_id(account.shared_dir_id));

    schema::Directory dir;
    dir.owner_id = "cccccccccccccccccccccccccccccccc";
    schema::Entry file_entry;
    file_entry.kind = schema::EntryKind::file;
    file_entry.target_id = "dddddddddddddddddddddddddddddddd";
    dir.entries["notes.txt"] = file_entry;
    assert(dir.entries.size() == 1);
    assert(dir.entries.count("notes.txt") == 1);

    // Duplicate names collapse through std::map: last write wins, still one entry.
    schema::Entry shared;
    shared.kind = schema::EntryKind::shared_file;
    shared.target_id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    dir.entries["notes.txt"] = shared;
    assert(dir.entries.size() == 1);
    assert(dir.entries["notes.txt"].kind == schema::EntryKind::shared_file);

    schema::FileRecord file;
    file.owner_id = dir.owner_id;
    file.blob_id = "ffffffffffffffffffffffffffffffff";
    file.blob_version = 1;
    file.size = 0;
    file.blob_sha256 = std::string(schema::sha256_hex_size, '0');
    assert(file.blob_sha256.size() == schema::sha256_hex_size);

    schema::Grant owner_grant;
    owner_grant.account_id = file.owner_id;
    owner_grant.kind = schema::GrantKind::owner;
    owner_grant.wrapped_dek.envelope.assign(schema::wrapped_dek_size, 0);
    assert(owner_grant.wrapped_dek.envelope.size() == schema::wrapped_dek_size);
    file.grants.push_back(owner_grant);

    index.accounts[account.personal_dir_id] = account;  // keyed by account id in real use
    index.directories[account.personal_dir_id] = dir;
    index.files[file_entry.target_id] = file;
    assert(index.accounts.size() == 1);
    assert(index.directories.size() == 1);
    assert(index.files.size() == 1);

    // Overwrite keeps the file id and bumps the blob version (schema contract).
    const schema::FileId stable_id = file_entry.target_id;
    index.files[stable_id].blob_id = "11111111111111111111111111111111";
    index.files[stable_id].blob_version = 2;
    assert(index.files.count(stable_id) == 1);
    assert(index.files[stable_id].blob_version == 2);
}

void test_index_aad() {
    crypto_store::InstallationId first{};
    crypto_store::InstallationId second{};
    second[0] = 1;

    const std::string path = "/tmp/bibifi-install-a";
    const auto first_aad = crypto_store::index_aad(first, path);
    const auto second_aad = crypto_store::index_aad(second, path);
    const std::string label = "FILESYSTEM_INDEX_V1";

    assert(first_aad.size() == label.size() + 1 + crypto_store::installation_id_size + path.size());
    assert(std::string(first_aad.begin(), first_aad.begin() + static_cast<std::ptrdiff_t>(label.size())) == label);
    assert(first_aad[label.size()] == 0);
    for (std::size_t i = 0; i < crypto_store::installation_id_size; ++i) {
        assert(first_aad[label.size() + 1 + i] == first[i]);
    }
    assert(std::string(first_aad.end() - static_cast<std::ptrdiff_t>(path.size()), first_aad.end()) == path);
    assert(first_aad != second_aad);
    assert(first_aad != crypto_store::index_aad(first, "/tmp/bibifi-install-b"));
}

void test_bootstrap_index() {
    schema::FsIndex index;
    index.generation = 1;
    assert(schema::is_bootstrap_index(index));

    index.generation = 0;
    assert(!schema::is_bootstrap_index(index));

    index.generation = 1;
    schema::AccountEntry account;
    account.username = "admin";
    account.role = schema::Role::admin;
    index.accounts["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] = account;
    assert(!schema::is_bootstrap_index(index));

    index.accounts.clear();
    index.files["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"] = schema::FileRecord{};
    assert(!schema::is_bootstrap_index(index));
}

void test_commit_result() {
    storage::Result aborted;
    aborted.error = storage::Error::io;
    assert(!aborted.ok());
    assert(!aborted.committed);

    storage::Result visible;
    visible.error = storage::Error::io;
    visible.committed = true;
    assert(!visible.ok());
    assert(visible.committed);
}

schema::FsIndex directory_fixture() {
    schema::FsIndex index;
    index.generation = 1;
    const std::string admin(32, 'a'), alice(32, 'b');
    index.accounts[admin] = {"admin", schema::Role::admin, std::string(32, 'c'), std::string(32, 'd')};
    index.accounts[alice] = {"alice", schema::Role::user, std::string(32, 'e'), std::string(32, 'f')};
    for (const auto& account : index.accounts) {
        index.directories[account.second.personal_dir_id] = {account.first, {}};
        index.directories[account.second.shared_dir_id] = {account.first, {}};
    }
    index.directories[std::string(32, '1')] = {alice, {}};
    index.directories[std::string(32, 'e')].entries["child"] =
        {schema::EntryKind::directory, std::string(32, '1')};
    return index;
}

void test_child_directory_owner() {
    auto index = directory_fixture();
    assert(schema::validate_index(index).empty());
    index.directories.at(std::string(32, '1')).owner_id = std::string(32, 'a');
    assert(!schema::validate_index(index).empty());
}

void test_resolution_result_status() {
    class Directory final : public storage::AccountDirectory {
        std::optional<crypto_store::PublicKey> encryption_key(const std::string&) const override {
            return std::nullopt;
        }
        bool is_enrolled(const std::string& name) const override {
            return name == "admin" || name == "alice";
        }
        std::vector<std::string> usernames() const override { return {"admin", "alice"}; }
    } registry;
    const auto index = directory_fixture();
    accounts::Session alice{"alice", {}, {}, {}};
    for (const std::string path : {"/", "/personal", "/personal/child", "/personal/child/.."}) {
        const auto result = vfs::resolve_path(index, registry, alice, path);
        assert(result.value && result.error == vfs::ResolveError::none);
    }
    std::string name;
    const auto parent = vfs::resolve_parent(index, registry, alice, "/personal/child/file", name);
    assert(parent.value && parent.error == vfs::ResolveError::none && name == "file");
    const auto missing = vfs::resolve_path(index, registry, alice, "/personal/missing");
    assert(!missing.value && missing.error == vfs::ResolveError::not_found);
    const auto invalid = vfs::resolve_path(index, registry, alice, "");
    assert(!invalid.value && invalid.error == vfs::ResolveError::invalid_path);
}

}  // namespace

int main() {
    test_object_ids();
    test_reserved_usernames();
    test_entry_names();
    test_format_constants();
    test_record_defaults_and_shapes();
    test_index_aad();
    test_bootstrap_index();
    test_commit_result();
    test_child_directory_owner();
    test_resolution_result_status();
    return 0;
}
