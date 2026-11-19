#include "vfs_interfaces.h"
#include "crypto_store.h"

#include <fstream>
#include <stdexcept>

namespace {
void check(bool condition, const char* reason) {
    if (!condition) throw std::runtime_error(reason);
}

void write_blob(const schema::FileRecord& file, const crypto_store::Bytes& object) {
    std::ofstream out("filesystem/blobs/" + file.blob_id + ".enc", std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(object.data()), static_cast<std::streamsize>(object.size()));
    check(out.good(), "write blob");
}
}

// Invoked inside an isolated integration fixture containing alice's /personal/f
// shared with bob. A reader can create a valid AEAD tag with its unwrapped DEK;
// only the separately authenticated index authorizes the current ciphertext.
int main() {
    auto bob = accounts::login("bob_keyfile");
    const auto lock = storage::InstallationLock::acquire();
    auto registry = accounts::directory_snapshot(lock);
    schema::FsIndex index;
    check(storage::load_metadata(lock, index).ok(), "load");
    auto source = vfs::resolve_path(index, *registry, bob, "/shared/f");
    check(source.value.has_value(), "resolve share");
    const auto& node = *source.value;
    const auto& file = index.files.at(node.file_id);
    check(vfs::check_access(bob, index, vfs::Access::read, node) == vfs::Decision::allow, "recipient read");
    check(vfs::check_access(bob, index, vfs::Access::replace_file, node) == vfs::Decision::forbidden, "recipient write");
    check(vfs::check_access(bob, index, vfs::Access::share, node) == vfs::Decision::forbidden, "recipient reshare");
    std::optional<crypto_store::Dek> dek;
    for (const auto& grant : file.grants) {
        if (grant.kind == schema::GrantKind::recipient)
            dek = crypto_store::unwrap_key(bob, {node.file_id, grant.account_id, grant.kind}, grant.wrapped_dek);
    }
    check(dek.has_value(), "unwrap recipient");
    const crypto_store::BlobBinding binding{file.blob_id, file.owner_id, node.file_id, file.blob_version};
    auto forged = crypto_store::seal_blob(*dek, binding, "forged!");
    check(crypto_store::open_blob(*dek, binding, forged) == std::optional<std::string>("forged!"), "valid reader tag");
    crypto_store::Bytes original;
    check(storage::read_blob(lock, file, original).ok(), "read original");
    write_blob(file, forged);
    const auto command = *shell::parse_command("cat /shared/f");
    const auto result = vfs::execute(bob, command, *registry, lock);
    write_blob(file, original);
    check(result.status == shell::Status::storage_error && result.output.empty(), "reject recipient ciphertext");
    check(vfs::execute(bob, command, *registry, lock).output == "private", "restored owner ciphertext");

    // Failed enrollment can leave an inert index entry. Never expose it to a
    // regular user or through admin listings/traversal.
    schema::AccountId inert;
    check(storage::ensure_user_roots(lock, "inert", schema::Role::user, inert).ok(), "inert roots");
    check(storage::load_metadata(lock, index).ok(), "reload");
    auto admin = bob;
    admin.username = "admin";
    check(!vfs::resolve_path(index, *registry, admin, "/inert/personal").value, "hide inert enrollment");
    check(vfs::execute(admin, *shell::parse_command("ls"), *registry, lock).output.find("inert") == std::string::npos,
          "hide inert listing");
    // An unknown session name cannot obtain even traversal access.
    auto unknown = bob;
    unknown.username = "unknown";
    check(!vfs::resolve_path(index, *registry, unknown, "/personal").value, "unknown session");
}
