#include "vfs_interfaces.h"
#include "crypto_store.h"

#include <algorithm>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace vfs {
namespace {
using schema::AccountId;
using schema::FsIndex;
using shell::Status;

AccountId account_id(const FsIndex& index, const std::string& username) {
    for (const auto& item : index.accounts) {
        if (item.second.username == username) return item.first;
    }
    return {};
}

std::string virtual_path(const std::vector<std::string>& components) {
    std::string result;
    for (const auto& component : components) result += "/" + component;
    return result.empty() ? "/" : result;
}

// Walk normalized prefixes again after '..'. No lexical normalization may skip
// a missing component or a file: missing/../personal and file/.. must fail.
ResolveResult child(const FsIndex& index, const storage::AccountDirectory& registry,
                    const accounts::Session& session, Resolution node, const std::string& name) {
    if (node.kind != NodeKind::directory) return {{}, ResolveError::not_a_directory};
    if (node.zone == Zone::root || node.zone == Zone::user_root) {
        const std::string username = node.zone == Zone::root ? session.username :
            index.accounts.at(node.owner_id).username;
        if (name == "personal" || name == "shared") {
            node.owner_id = account_id(index, username);
            if (node.owner_id.empty() || !registry.is_enrolled(username)) return {};
            const auto& owner = index.accounts.at(node.owner_id);
            node.zone = name == "personal" ? Zone::personal : Zone::shared;
            node.directory_id = name == "personal" ? owner.personal_dir_id : owner.shared_dir_id;
        } else if (node.zone == Zone::root && session.is_admin() && registry.is_enrolled(name)) {
            node.owner_id = account_id(index, name);
            if (node.owner_id.empty()) return {};
            node.zone = Zone::user_root;
        } else return {};
    } else {
        const auto directory = index.directories.find(node.directory_id);
        if (directory == index.directories.end()) return {};
        const auto entry = directory->second.entries.find(name);
        if (entry == directory->second.entries.end()) return {};
        if (entry->second.kind == schema::EntryKind::directory) {
            node.directory_id = entry->second.target_id;
        } else {
            node.kind = NodeKind::file;
            node.file_id = entry->second.target_id;
            node.directory_id.clear();
            node.is_shared_reference = entry->second.kind == schema::EntryKind::shared_file;
        }
    }
    node.path.push_back(name);
    if (check_access(session, index, Access::read, node) != Decision::allow)
        return {{}, ResolveError::forbidden};
    return {node, ResolveError::none};
}

shell::Result failed_resolution(const ResolveResult& resolved) {
    return {resolved.error == ResolveError::forbidden ? Status::forbidden : Status::missing_file, {}};
}

std::optional<crypto_store::Dek> file_key(const FsIndex& index, const accounts::Session& session,
                                         const schema::FileId& id) {
    const auto who = account_id(index, session.username);
    const auto& file = index.files.at(id);
    for (const auto& grant : file.grants) {
        if (grant.account_id == who)
            return crypto_store::unwrap_key(session, {id, who, grant.kind}, grant.wrapped_dek);
    }
    return std::nullopt;
}

std::optional<std::string> read_file(const storage::InstallationLock& lock, const FsIndex& index,
                                    const accounts::Session& session, const schema::FileId& id) {
    const auto& file = index.files.at(id);
    auto dek = file_key(index, session, id);
    crypto_store::Bytes object;
    // read_blob verifies the SHA-256 in the separately authenticated index.
    // A recipient knowing the DEK cannot authorize replacement ciphertext.
    if (!dek || !storage::read_blob(lock, file, object).ok()) return std::nullopt;
    auto contents = crypto_store::open_blob(*dek, {file.blob_id, file.owner_id, id, file.blob_version}, object);
    if (!contents || contents->size() != file.size) return std::nullopt;
    return contents;
}

schema::ObjectId fresh_id(const FsIndex& index) {
    for (;;) {
        auto id = crypto_store::new_object_id();
        if (index.accounts.count(id) || index.directories.count(id) || index.files.count(id)) continue;
        if (std::any_of(index.files.begin(), index.files.end(), [&](const auto& f) {
                return f.second.blob_id == id;
            })) continue;
        return id;
    }
}

shell::Result save(const storage::InstallationLock& lock, storage::Mutation& mutation) {
    // Even a post-rename error must be returned. Never retry this generation;
    // every subsequent command reloads metadata while holding the lock.
    return {storage::commit_mutation(lock, mutation).ok() ? Status::ok : Status::storage_error, {}};
}

}  // namespace

Decision check_access(const accounts::Session& session, const FsIndex& index,
                      Access access, const Resolution& target) {
    const auto who = account_id(index, session.username);
    if (who.empty()) return Decision::forbidden;
    const bool admin = session.is_admin() && index.accounts.at(who).role == schema::Role::admin;
    if (access == Access::read) {
        if (target.zone == Zone::root) return Decision::allow;
        if (target.owner_id.empty() || (!admin && target.owner_id != who)) return Decision::forbidden;
        if (target.kind == NodeKind::file) {
            const auto file = index.files.find(target.file_id);
            if (file == index.files.end()) return Decision::forbidden;
            for (const auto& grant : file->second.grants) {
                if (grant.account_id == who &&
                    ((file->second.owner_id == who && grant.kind == schema::GrantKind::owner) ||
                     (admin && grant.kind == schema::GrantKind::admin) ||
                     (target.zone == Zone::shared && target.is_shared_reference &&
                      grant.kind == schema::GrantKind::recipient))) return Decision::allow;
            }
            return Decision::forbidden;
        }
        return Decision::allow;
    }
    if (target.zone != Zone::personal || target.owner_id != who || target.is_shared_reference)
        return Decision::forbidden;
    if (access == Access::create_entry)
        return target.kind == NodeKind::directory ? Decision::allow : Decision::forbidden;
    const auto file = index.files.find(target.file_id);
    return target.kind == NodeKind::file && file != index.files.end() && file->second.owner_id == who ?
        Decision::allow : Decision::forbidden;
}

ResolveResult resolve_path(const FsIndex& index, const storage::AccountDirectory& registry,
                           const accounts::Session& session, const std::string& path) {
    if (path.empty() || path.find('\0') != std::string::npos ||
        !registry.is_enrolled(session.username) || account_id(index, session.username).empty())
        return {{}, ResolveError::invalid_path};
    std::vector<Resolution> stack(1);
    if (path.front() != '/') {
        for (const auto& component : session.current_directory) {
            auto next = child(index, registry, session, stack.back(), component);
            if (!next.value) return next;
            stack.push_back(*next.value);
        }
    }
    std::istringstream components(path);
    for (std::string component; std::getline(components, component, '/');) {
        if (component.empty()) continue;
        if (stack.back().kind != NodeKind::directory) return {{}, ResolveError::not_a_directory};
        if (component == ".") continue;
        if (component == "..") {
            if (stack.size() > 1) stack.pop_back();
            continue;
        }
        auto next = child(index, registry, session, stack.back(), component);
        if (!next.value) return next;
        stack.push_back(*next.value);
    }
    if (path.back() == '/' && stack.back().kind != NodeKind::directory)
        return {{}, ResolveError::not_a_directory};
    return {stack.back(), ResolveError::none};
}

ResolveResult resolve_parent(const FsIndex& index, const storage::AccountDirectory& registry,
                             const accounts::Session& session, const std::string& path,
                             std::string& final_name) {
    const auto slash = path.find_last_of('/');
    final_name = slash == std::string::npos ? path : path.substr(slash + 1);
    if (!is_valid_entry_name(final_name)) return {{}, ResolveError::invalid_path};
    auto parent = resolve_path(index, registry, session,
                              slash == std::string::npos ? "." : (slash == 0 ? "/" : path.substr(0, slash)));
    if (parent.value && parent.value->kind != NodeKind::directory)
        return {{}, ResolveError::not_a_directory};
    return parent;
}

shell::Result share_file(accounts::Session& session, const storage::InstallationLock& lock,
                         const storage::AccountDirectory& registry, const std::string& filename,
                         const std::string& recipient) {
    FsIndex index;
    if (!storage::load_metadata(lock, index).ok()) return {Status::storage_error, {}};
    const auto source = resolve_path(index, registry, session, filename);
    if (!source.value) return failed_resolution(source);
    if (source.value->kind != NodeKind::file) return {Status::missing_file, {}};
    if (check_access(session, index, Access::share, *source.value) != Decision::allow)
        return {Status::forbidden, {}};
    if (!registry.is_enrolled(recipient)) return {Status::missing_user, {}};
    const auto recipient_id = account_id(index, recipient);
    if (recipient_id.empty()) return {Status::storage_error, {}};
    const auto& file_id = source.value->file_id;
    auto& file = index.files.at(file_id);
    if (recipient_id == file.owner_id) return {Status::forbidden, {}};
    auto& entries = index.directories.at(index.accounts.at(recipient_id).shared_dir_id).entries;
    for (const auto& entry : entries) {
        if (entry.second.kind == schema::EntryKind::shared_file && entry.second.target_id == file_id) return {};
    }
    const auto key = registry.encryption_key(recipient);
    auto dek = file_key(index, session, file_id);
    // Also authenticate the current object before sharing it.
    if (!key || !dek || !read_file(lock, index, session, file_id)) return {Status::storage_error, {}};
    std::string display = source.value->path.back();
    if (entries.count(display)) {
        display += "@" + session.username;
        if (entries.count(display)) {
            display += "-" + file_id.substr(0, 8);
            if (entries.count(display)) display += "-" + file_id;
            if (entries.count(display)) return {Status::storage_error, {}};
        }
    }
    // Admin already has a global read grant; do not duplicate it.
    const bool granted = std::any_of(file.grants.begin(), file.grants.end(), [&](const auto& grant) {
        return grant.account_id == recipient_id;
    });
    if (!granted) file.grants.push_back({recipient_id, schema::GrantKind::recipient,
        crypto_store::wrap_key(*dek, {file_id, recipient_id, schema::GrantKind::recipient}, *key)});
    entries.emplace(display, schema::Entry{schema::EntryKind::shared_file, file_id});
    storage::Mutation mutation{index.generation, std::move(index), {}, {}};
    return save(lock, mutation);
}

shell::Result execute(accounts::Session& session, const shell::Command& command,
                      const storage::AccountDirectory& registry, const storage::InstallationLock& lock) {
    if (command.operation == shell::Operation::share)
        return share_file(session, lock, registry, command.name, command.target);
    FsIndex index;
    if (!storage::load_metadata(lock, index).ok()) return {Status::storage_error, {}};
    using shell::Operation;
    if (command.operation == Operation::mkdir || command.operation == Operation::mkfile) {
        std::string name;
        const auto parent = resolve_parent(index, registry, session, command.name, name);
        if (!parent.value) return parent.error == ResolveError::invalid_path ?
            shell::Result{Status::forbidden, {}} : failed_resolution(parent);
        if (check_access(session, index, Access::create_entry, *parent.value) != Decision::allow)
            return {Status::forbidden, {}};
        auto& entries = index.directories.at(parent.value->directory_id).entries;
        const auto existing = entries.find(name);
        if (command.operation == Operation::mkdir) {
            if (existing != entries.end()) return {Status::directory_exists, {}};
            const auto id = fresh_id(index);
            index.directories.emplace(id, schema::Directory{parent.value->owner_id, {}});
            entries.emplace(name, schema::Entry{schema::EntryKind::directory, id});
            storage::Mutation mutation{index.generation, std::move(index), {}, {}};
            return save(lock, mutation);
        }
        if (command.contents.size() > crypto_store::max_blob_plaintext ||
            !std::all_of(command.contents.begin(), command.contents.end(), [](unsigned char c) {
                return c >= 32 && c <= 126;
            })) return {Status::forbidden, {}};
        schema::FileId id;
        schema::FileRecord file;
        std::optional<crypto_store::Dek> dek;
        std::vector<schema::BlobId> retired;
        if (existing != entries.end()) {
            const auto target = resolve_path(index, registry, session, command.name);
            if (!target.value || check_access(session, index, Access::replace_file, *target.value) != Decision::allow)
                return {Status::forbidden, {}};
            id = target.value->file_id;
            file = index.files.at(id);
            if (file.blob_version == std::numeric_limits<std::uint32_t>::max()) return {Status::storage_error, {}};
            dek = file_key(index, session, id);
            if (!dek || !read_file(lock, index, session, id)) return {Status::storage_error, {}};
            retired.push_back(file.blob_id);
            ++file.blob_version;
        } else {
            id = fresh_id(index);
            file.owner_id = parent.value->owner_id;
            dek = crypto_store::generate_dek();
            for (const auto& account : index.accounts) {
                if (account.first != file.owner_id && account.second.role != schema::Role::admin) continue;
                const auto key = registry.encryption_key(account.second.username);
                if (!key) return {Status::storage_error, {}};
                const auto kind = account.first == file.owner_id ? schema::GrantKind::owner : schema::GrantKind::admin;
                file.grants.push_back({account.first, kind, crypto_store::wrap_key(*dek, {id, account.first, kind}, *key)});
            }
            entries.emplace(name, schema::Entry{schema::EntryKind::file, id});
        }
        do {
            file.blob_id = fresh_id(index);
        } while (file.blob_id == id);
        auto object = crypto_store::seal_blob(*dek, {file.blob_id, file.owner_id, id, file.blob_version}, command.contents);
        file.size = command.contents.size();
        file.blob_sha256 = crypto_store::sha256_hex(object);
        index.files[id] = file;
        storage::Mutation mutation{index.generation, std::move(index), {{file.blob_id, std::move(object)}}, std::move(retired)};
        return save(lock, mutation);
    }
    const auto target = resolve_path(index, registry, session,
                                    command.operation == Operation::cd || command.operation == Operation::cat ? command.name : ".");
    if (!target.value) return failed_resolution(target);
    if (check_access(session, index, Access::read, *target.value) != Decision::allow) return {Status::forbidden, {}};
    const auto& node = *target.value;
    switch (command.operation) {
    case Operation::cd:
        if (node.kind != NodeKind::directory) return {Status::missing_file, {}};
        session.current_directory = node.path;
        return {};
    case Operation::pwd: return {Status::ok, virtual_path(node.path)};
    case Operation::cat: {
        if (node.kind != NodeKind::file) return {Status::missing_file, {}};
        auto contents = read_file(lock, index, session, node.file_id);
        return contents ? shell::Result{Status::ok, contents->empty() ? "\n" : *contents} :
            shell::Result{Status::storage_error, {}};
    }
    case Operation::ls: {
        std::string output = "d -> .\nd -> ..\n";
        if (node.zone == Zone::root || node.zone == Zone::user_root) {
            output += "d -> personal\nd -> shared\n";
            if (node.zone == Zone::root && session.is_admin()) {
                for (const auto& name : registry.usernames()) {
                    if (!account_id(index, name).empty()) output += "d -> " + name + "\n";
                }
            }
        } else {
            for (const auto& entry : index.directories.at(node.directory_id).entries)
                output += std::string(entry.second.kind == schema::EntryKind::directory ? "d -> " : "f -> ") + entry.first + "\n";
        }
        return {Status::ok, output};
    }
    default: return {Status::forbidden, {}};
    }
}

shell::Result execute(accounts::Session& session, const shell::Command& command) {
    const auto lock = storage::InstallationLock::acquire();
    const auto registry = accounts::directory_snapshot(lock);
    return execute(session, command, *registry, lock);
}

}  // namespace vfs
