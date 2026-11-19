#include "fs_schema.h"

#include <nlohmann/json.hpp>

#include <charconv>
#include <initializer_list>
#include <set>
#include <utility>

namespace schema {
namespace {

using json = nlohmann::json;

class DuplicateKeySax : public json::json_sax_t {
public:
    bool null() override { return true; }
    bool boolean(bool) override { return true; }
    bool number_integer(number_integer_t) override { return true; }
    bool number_unsigned(number_unsigned_t) override { return true; }
    bool number_float(number_float_t, const string_t&) override { return true; }
    bool string(string_t&) override { return true; }
    bool binary(binary_t&) override { return true; }
    bool start_object(std::size_t) override {
        keys_.emplace_back();
        return true;
    }
    bool key(string_t& value) override {
        if (keys_.empty() || !keys_.back().insert(value).second) {
            return false;
        }
        return true;
    }
    bool end_object() override {
        if (keys_.empty()) {
            return false;
        }
        keys_.pop_back();
        return true;
    }
    bool start_array(std::size_t) override { return true; }
    bool end_array() override { return true; }
    bool parse_error(std::size_t, const std::string&, const nlohmann::detail::exception&) override {
        return false;
    }

private:
    std::vector<std::set<std::string>> keys_;
};

bool hex_text(const std::string& text, std::size_t size) {
    if (text.size() != size) {
        return false;
    }
    for (char character : text) {
        if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f'))) {
            return false;
        }
    }
    return true;
}

bool decode_hex(const std::string& text, Bytes& out) {
    if (text.size() % 2 != 0) {
        return false;
    }
    out.resize(text.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        unsigned int value = 0;
        const char* first = text.data() + 2 * i;
        const auto parsed = std::from_chars(first, first + 2, value, 16);
        if (parsed.ec != std::errc{} || parsed.ptr != first + 2 || value > 255) {
            return false;
        }
        out[i] = static_cast<unsigned char>(value);
    }
    return hex_text(text, text.size());
}

const char* role_name(Role role) {
    return role == Role::admin ? "admin" : "user";
}

const char* entry_name(EntryKind kind) {
    switch (kind) {
    case EntryKind::directory:
        return "directory";
    case EntryKind::file:
        return "file";
    case EntryKind::shared_file:
        return "shared_file";
    }
    return "";
}

const char* grant_name(GrantKind kind) {
    switch (kind) {
    case GrantKind::owner:
        return "owner";
    case GrantKind::admin:
        return "admin";
    case GrantKind::recipient:
        return "recipient";
    }
    return "";
}

bool parse_role(const json& value, Role& role) {
    if (!value.is_string()) {
        return false;
    }
    if (value == "user") {
        role = Role::user;
        return true;
    }
    if (value == "admin") {
        role = Role::admin;
        return true;
    }
    return false;
}

bool parse_entry_kind(const json& value, EntryKind& kind) {
    if (!value.is_string()) {
        return false;
    }
    if (value == "directory") {
        kind = EntryKind::directory;
        return true;
    }
    if (value == "file") {
        kind = EntryKind::file;
        return true;
    }
    if (value == "shared_file") {
        kind = EntryKind::shared_file;
        return true;
    }
    return false;
}

bool parse_grant_kind(const json& value, GrantKind& kind) {
    if (!value.is_string()) {
        return false;
    }
    if (value == "owner") {
        kind = GrantKind::owner;
        return true;
    }
    if (value == "admin") {
        kind = GrantKind::admin;
        return true;
    }
    if (value == "recipient") {
        kind = GrantKind::recipient;
        return true;
    }
    return false;
}

bool exact_keys(const json& object, std::initializer_list<const char*> keys) {
    if (!object.is_object() || object.size() != keys.size()) {
        return false;
    }
    for (const char* key : keys) {
        if (!object.contains(key)) {
            return false;
        }
    }
    return true;
}

bool unsigned_in_range(const json& value, std::uint64_t max, std::uint64_t& out) {
    if (!value.is_number_unsigned()) {
        return false;
    }
    out = value.get<std::uint64_t>();
    return out <= max;
}

std::string fail(const char* reason) { return reason; }

bool grant_for(const FileRecord& file, const AccountId& account, GrantKind kind) {
    for (const Grant& grant : file.grants) {
        if (grant.account_id == account && grant.kind == kind) {
            return true;
        }
    }
    return false;
}

}  // namespace

std::string validate_index(const FsIndex& index) {
    if (is_bootstrap_index(index)) {
        return "";
    }
    if (index.format != index_format_version || index.generation < 1) {
        return fail("generation");
    }
    for (const auto& item : index.accounts) {
        if (!is_valid_id(item.first)) {
            return fail("account id");
        }
    }
    for (const auto& item : index.directories) {
        if (!is_valid_id(item.first)) {
            return fail("directory id");
        }
    }
    for (const auto& item : index.files) {
        if (!is_valid_id(item.first)) {
            return fail("file id");
        }
    }

    std::set<std::string> usernames;
    AccountId admin_id;
    int admins = 0;
    for (const auto& item : index.accounts) {
        const AccountEntry& account = item.second;
        if (!usernames.insert(account.username).second) {
            return fail("username");
        }
        if (account.role == Role::admin) {
            if (account.username != "admin") {
                return fail("admin username");
            }
            ++admins;
            admin_id = item.first;
        } else if (account.username == "admin") {
            return fail("admin role");
        }
        if (account.personal_dir_id == account.shared_dir_id || !is_valid_id(account.personal_dir_id) ||
            !is_valid_id(account.shared_dir_id)) {
            return fail("roots");
        }
        const auto personal = index.directories.find(account.personal_dir_id);
        const auto shared = index.directories.find(account.shared_dir_id);
        if (personal == index.directories.end() || shared == index.directories.end() ||
            personal->second.owner_id != item.first || shared->second.owner_id != item.first) {
            return fail("roots");
        }
    }
    if (admins != 1) {
        return fail("admin count");
    }

    std::map<DirectoryId, int> references;
    for (const auto& item : index.directories) {
        if (index.accounts.find(item.second.owner_id) == index.accounts.end()) {
            return fail("directory owner");
        }
        for (const auto& entry : item.second.entries) {
            if (!is_valid_id(entry.second.target_id)) {
                return fail("entry id");
            }
            if (entry.second.kind == EntryKind::directory) {
                const auto child = index.directories.find(entry.second.target_id);
                if (child == index.directories.end() || child->second.owner_id != item.second.owner_id) {
                    return fail("directory entry");
                }
                ++references[entry.second.target_id];
            } else if (entry.second.kind == EntryKind::file) {
                const auto file = index.files.find(entry.second.target_id);
                if (file == index.files.end() || file->second.owner_id != item.second.owner_id) {
                    return fail("file entry");
                }
            } else {
                const auto owner = index.accounts.find(item.second.owner_id);
                const auto file = index.files.find(entry.second.target_id);
                if (owner == index.accounts.end() || item.first != owner->second.shared_dir_id ||
                    file == index.files.end() ||
                    (!grant_for(file->second, item.second.owner_id, GrantKind::recipient) &&
                     !(owner->second.role == Role::admin &&
                       grant_for(file->second, item.second.owner_id, GrantKind::admin)))) {
                    return fail("shared entry");
                }
            }
        }
    }
    for (const auto& item : references) {
        if (item.second > 1) {
            return fail("directory link");
        }
    }
    for (const auto& item : index.accounts) {
        if (references[item.second.personal_dir_id] != 0 || references[item.second.shared_dir_id] != 0) {
            return fail("root link");
        }
    }

    for (const auto& item : index.files) {
        const FileRecord& file = item.second;
        if (index.accounts.find(file.owner_id) == index.accounts.end() || !is_valid_id(file.blob_id) ||
            file.blob_version < 1 || !hex_text(file.blob_sha256, sha256_hex_size)) {
            return fail("file record");
        }
        std::set<AccountId> holders;
        int owners = 0;
        int admin_grants = 0;
        for (const Grant& grant : file.grants) {
            if (!holders.insert(grant.account_id).second ||
                index.accounts.find(grant.account_id) == index.accounts.end() ||
                grant.wrapped_dek.envelope.size() != wrapped_dek_size) {
                return fail("grant");
            }
            if (grant.kind == GrantKind::owner) {
                if (grant.account_id != file.owner_id) {
                    return fail("owner grant");
                }
                ++owners;
            } else if (grant.kind == GrantKind::admin) {
                if (grant.account_id != admin_id) {
                    return fail("admin grant");
                }
                ++admin_grants;
            }
        }
        const bool owned_by_admin = file.owner_id == admin_id;
        if (owners != 1 || admin_grants != (owned_by_admin ? 0 : 1)) {
            return fail("grant count");
        }
    }
    return "";
}

std::string serialize_index(const FsIndex& index) {
    json accounts = json::object();
    for (const auto& item : index.accounts) {
        accounts[item.first] = json{{"username", item.second.username},
                                    {"role", role_name(item.second.role)},
                                    {"personal", item.second.personal_dir_id},
                                    {"shared", item.second.shared_dir_id}};
    }
    json directories = json::object();
    for (const auto& item : index.directories) {
        json entries = json::object();
        for (const auto& entry : item.second.entries) {
            entries[entry.first] = json{{"kind", entry_name(entry.second.kind)}, {"id", entry.second.target_id}};
        }
        directories[item.first] = json{{"owner", item.second.owner_id}, {"entries", std::move(entries)}};
    }
    json files = json::object();
    for (const auto& item : index.files) {
        json grants = json::array();
        for (const Grant& grant : item.second.grants) {
            std::string wrapped;
            wrapped.reserve(grant.wrapped_dek.envelope.size() * 2);
            constexpr char digits[] = "0123456789abcdef";
            for (unsigned char byte : grant.wrapped_dek.envelope) {
                wrapped.push_back(digits[byte >> 4]);
                wrapped.push_back(digits[byte & 0x0f]);
            }
            grants.push_back(json{{"account", grant.account_id},
                                  {"kind", grant_name(grant.kind)},
                                  {"wrapped", std::move(wrapped)}});
        }
        files[item.first] = json{{"owner", item.second.owner_id},
                                 {"blob", item.second.blob_id},
                                 {"version", item.second.blob_version},
                                 {"size", item.second.size},
                                 {"blob_sha256", item.second.blob_sha256},
                                 {"grants", std::move(grants)}};
    }
    json document = json{{"format", index.format},
                         {"generation", index.generation},
                         {"accounts", std::move(accounts)},
                         {"directories", std::move(directories)},
                         {"files", std::move(files)}};
    return document.dump();
}

std::optional<FsIndex> parse_index(const std::string& text) {
    if (text.size() > max_index_plaintext) {
        return std::nullopt;
    }
    DuplicateKeySax sax;
    if (!json::sax_parse(text, &sax)) {
        return std::nullopt;
    }
    json document;
    try {
        document = json::parse(text);
    } catch (const json::exception&) {
        return std::nullopt;
    }
    if (!exact_keys(document, {"format", "generation", "accounts", "directories", "files"})) {
        return std::nullopt;
    }
    FsIndex index;
    std::uint64_t format = 0;
    std::uint64_t generation = 0;
    if (!unsigned_in_range(document["format"], index_format_version, format) || format != index_format_version ||
        !unsigned_in_range(document["generation"], UINT64_MAX, generation)) {
        return std::nullopt;
    }
    index.format = static_cast<std::uint32_t>(format);
    index.generation = generation;
    if (!document["accounts"].is_object() || !document["directories"].is_object() || !document["files"].is_object()) {
        return std::nullopt;
    }
    try {
        for (auto item = document["accounts"].begin(); item != document["accounts"].end(); ++item) {
            if (!exact_keys(*item, {"username", "role", "personal", "shared"}) || !(*item)["username"].is_string() ||
                !(*item)["personal"].is_string() || !(*item)["shared"].is_string()) {
                return std::nullopt;
            }
            AccountEntry account;
            account.username = (*item)["username"].get<std::string>();
            account.personal_dir_id = (*item)["personal"].get<std::string>();
            account.shared_dir_id = (*item)["shared"].get<std::string>();
            if (!parse_role((*item)["role"], account.role)) {
                return std::nullopt;
            }
            index.accounts.emplace(item.key(), std::move(account));
        }
        for (auto item = document["directories"].begin(); item != document["directories"].end(); ++item) {
            if (!exact_keys(*item, {"owner", "entries"}) || !(*item)["owner"].is_string() ||
                !(*item)["entries"].is_object()) {
                return std::nullopt;
            }
            Directory directory;
            directory.owner_id = (*item)["owner"].get<std::string>();
            for (auto entry = (*item)["entries"].begin(); entry != (*item)["entries"].end(); ++entry) {
                if (!exact_keys(*entry, {"kind", "id"}) || !(*entry)["id"].is_string()) {
                    return std::nullopt;
                }
                Entry value;
                value.target_id = (*entry)["id"].get<std::string>();
                if (!parse_entry_kind((*entry)["kind"], value.kind)) {
                    return std::nullopt;
                }
                directory.entries.emplace(entry.key(), std::move(value));
            }
            index.directories.emplace(item.key(), std::move(directory));
        }
        for (auto item = document["files"].begin(); item != document["files"].end(); ++item) {
            if (!exact_keys(*item, {"owner", "blob", "version", "size", "blob_sha256", "grants"}) ||
                !(*item)["owner"].is_string() || !(*item)["blob"].is_string() ||
                !(*item)["blob_sha256"].is_string() || !(*item)["grants"].is_array()) {
                return std::nullopt;
            }
            FileRecord file;
            file.owner_id = (*item)["owner"].get<std::string>();
            file.blob_id = (*item)["blob"].get<std::string>();
            file.blob_sha256 = (*item)["blob_sha256"].get<std::string>();
            std::uint64_t version = 0;
            std::uint64_t size = 0;
            if (!unsigned_in_range((*item)["version"], UINT32_MAX, version) ||
                !unsigned_in_range((*item)["size"], UINT64_MAX, size)) {
                return std::nullopt;
            }
            file.blob_version = static_cast<std::uint32_t>(version);
            file.size = size;
            for (const json& grant_json : (*item)["grants"]) {
                if (!exact_keys(grant_json, {"account", "kind", "wrapped"}) || !grant_json["account"].is_string() ||
                    !grant_json["wrapped"].is_string()) {
                    return std::nullopt;
                }
                Grant grant;
                grant.account_id = grant_json["account"].get<std::string>();
                if (!parse_grant_kind(grant_json["kind"], grant.kind) ||
                    !decode_hex(grant_json["wrapped"].get<std::string>(), grant.wrapped_dek.envelope)) {
                    return std::nullopt;
                }
                file.grants.push_back(std::move(grant));
            }
            index.files.emplace(item.key(), std::move(file));
        }
    } catch (const json::exception&) {
        return std::nullopt;
    }
    if (!validate_index(index).empty()) {
        return std::nullopt;
    }
    return index;
}

}  // namespace schema
