#include "storage.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1
#endif
extern "C" int renameat2(int olddirfd, const char* oldpath, int newdirfd, const char* newpath, unsigned int flags);

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <functional>
#include <memory>
#include <set>
#include <vector>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace storage {
namespace {

namespace fs = std::filesystem;

constexpr char filesystem_name[] = "filesystem";
constexpr char blobs_name[] = "blobs";
constexpr char index_name[] = "index.enc";
constexpr unsigned char state_header[] = {'B', 'I', 'B', 'I', 'F', 'I', 'P', 1};
constexpr std::size_t pin_size = 8;
constexpr std::size_t state_size = sizeof state_header + crypto_store::installation_id_size + pin_size;
constexpr char fail_after_rename[] = "BIBIFI_FAIL_AFTER_RENAME";

struct FsState {
    crypto_store::InstallationId id{};
    std::uint64_t pin = 0;
};

enum class StateFile { missing, ok, unusable };

Result failure(Error error) {
    Result result;
    result.error = error;
    return result;
}

Result committed_failure() {
    Result result;
    result.error = Error::io;
    result.committed = true;
    return result;
}

std::string hex_digits(const unsigned char* data, std::size_t size) {
    constexpr char digits[] = "0123456789abcdef";
    std::string text;
    text.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        text.push_back(digits[data[i] >> 4]);
        text.push_back(digits[data[i] & 0x0f]);
    }
    return text;
}

std::string installation_name() {
    const auto cwd = fs::current_path().string();
    unsigned char digest[32];
    if (EVP_Digest(cwd.data(), cwd.size(), digest, nullptr, EVP_sha256(), nullptr) != 1) {
        return "";
    }
    return "openssl-" + hex_digits(digest, sizeof digest);
}

std::optional<fs::path> state_directory() {
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
    if (home_path == nullptr || home_path[0] != '/') {
        return std::nullopt;
    }
    struct stat home{};
    if (lstat(home_path, &home) != 0 || !S_ISDIR(home.st_mode) || home.st_uid != geteuid() ||
        (home.st_mode & 0022) != 0) {
        return std::nullopt;
    }
    const fs::path directory = fs::path(home_path) / ".bibifi-state";
    if (mkdir(directory.c_str(), 0700) != 0 && errno != EEXIST) {
        return std::nullopt;
    }
    struct stat status{};
    if (lstat(directory.c_str(), &status) != 0 || !S_ISDIR(status.st_mode) || status.st_uid != geteuid() ||
        (status.st_mode & 0077) != 0) {
        return std::nullopt;
    }
    return directory;
}

std::string install_path() { return fs::current_path().string(); }

bool fsync_directory(const fs::path& path) {
    const int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    const int synced = fsync(fd);
    const int saved = errno;
    close(fd);
    errno = saved;
    return synced == 0;
}

bool fsync_fd(int fd) { return fd >= 0 && fsync(fd) == 0; }

struct StoreDirs {
    int filesystem = -1;
    int blobs = -1;
    StoreDirs() = default;
    StoreDirs(const StoreDirs&) = delete;
    StoreDirs& operator=(const StoreDirs&) = delete;
    StoreDirs(StoreDirs&& other) noexcept : filesystem(other.filesystem), blobs(other.blobs) {
        other.filesystem = -1;
        other.blobs = -1;
    }
    StoreDirs& operator=(StoreDirs&& other) noexcept {
        if (this != &other) {
            if (blobs >= 0) {
                close(blobs);
            }
            if (filesystem >= 0) {
                close(filesystem);
            }
            filesystem = other.filesystem;
            blobs = other.blobs;
            other.filesystem = -1;
            other.blobs = -1;
        }
        return *this;
    }
    ~StoreDirs() {
        if (blobs >= 0) {
            close(blobs);
        }
        if (filesystem >= 0) {
            close(filesystem);
        }
    }
};

enum class OpenStore { ok, missing, rejected };

OpenStore open_store(StoreDirs& dirs) {
    dirs.filesystem = open(filesystem_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dirs.filesystem < 0) {
        return errno == ENOENT ? OpenStore::missing : OpenStore::rejected;
    }
    dirs.blobs = openat(dirs.filesystem, blobs_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dirs.blobs < 0) {
        return errno == ENOENT ? OpenStore::missing : OpenStore::rejected;
    }
    return OpenStore::ok;
}

bool entry_status(int dirfd, const char* name, struct stat& status) {
    return fstatat(dirfd, name, &status, AT_SYMLINK_NOFOLLOW) == 0;
}

bool regular_file_exists(int dirfd, const char* name) {
    struct stat status{};
    return entry_status(dirfd, name, status) && S_ISREG(status.st_mode);
}

bool index_staging_name(const std::string& name) {
    constexpr std::size_t prefix = 6;
    constexpr std::size_t suffix = 4;
    return name.size() == prefix + schema::id_hex_size + suffix && name.compare(0, prefix, "index.") == 0 &&
           name.compare(name.size() - suffix, suffix, ".tmp") == 0 &&
           schema::is_valid_id(name.substr(prefix, schema::id_hex_size));
}

bool blob_storage_name(const std::string& name, std::string& id, bool& temporary) {
    constexpr std::size_t suffix = 4;
    if (name.size() != schema::id_hex_size + suffix) {
        return false;
    }
    id = name.substr(0, schema::id_hex_size);
    if (!schema::is_valid_id(id)) {
        return false;
    }
    if (name.compare(schema::id_hex_size, suffix, ".tmp") == 0) {
        temporary = true;
        return true;
    }
    if (name.compare(schema::id_hex_size, suffix, ".enc") == 0) {
        temporary = false;
        return true;
    }
    return false;
}

bool each_name(int dirfd, const std::function<bool(const std::string&)>& visit) {
    const int copy = dup(dirfd);
    if (copy < 0) {
        return false;
    }
    DIR* directory = fdopendir(copy);
    if (directory == nullptr) {
        close(copy);
        return false;
    }
    bool ok = true;
    while (ok) {
        errno = 0;
        const dirent* entry = readdir(directory);
        if (entry == nullptr) {
            ok = errno == 0;
            break;
        }
        const std::string name = entry->d_name;
        if (name != "." && name != ".." && !visit(name)) {
            ok = false;
        }
    }
    closedir(directory);
    return ok;
}

bool write_all(int fd, const unsigned char* data, std::size_t size) {
    while (size != 0) {
        const auto count = write(fd, data, size);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        data += count;
        size -= static_cast<std::size_t>(count);
    }
    return fsync(fd) == 0;
}

bool read_all(int fd, unsigned char* data, std::size_t size) {
    while (size != 0) {
        const auto count = read(fd, data, size);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        data += count;
        size -= static_cast<std::size_t>(count);
    }
    return true;
}

std::optional<crypto_store::Bytes> read_at(int dirfd, const char* name, std::size_t max_size) {
    const int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        return std::nullopt;
    }
    struct stat status{};
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) || status.st_size < 0 ||
        static_cast<std::uint64_t>(status.st_size) > max_size) {
        close(fd);
        return std::nullopt;
    }
    crypto_store::Bytes bytes(static_cast<std::size_t>(status.st_size));
    const bool ok = read_all(fd, bytes.data(), bytes.size());
    close(fd);
    if (!ok) {
        return std::nullopt;
    }
    return bytes;
}

bool create_private_file(const fs::path& path, const unsigned char* data, std::size_t size) {
    const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        return false;
    }
    struct stat status{};
    const bool ok = fstat(fd, &status) == 0 && status.st_uid == geteuid() && (status.st_mode & 0077) == 0 &&
                    S_ISREG(status.st_mode) && write_all(fd, data, size);
    close(fd);
    if (!ok) {
        unlink(path.c_str());
    }
    return ok;
}

void encode_state(const FsState& state, unsigned char* bytes) {
    std::copy(state_header, state_header + sizeof state_header, bytes);
    std::copy(state.id.begin(), state.id.end(), bytes + sizeof state_header);
    for (std::size_t i = 0; i < pin_size; ++i) {
        bytes[sizeof state_header + crypto_store::installation_id_size + i] =
            static_cast<unsigned char>((state.pin >> (8 * (pin_size - 1 - i))) & 0xff);
    }
}

StateFile read_state(const fs::path& path, FsState& state) {
    struct stat status{};
    if (lstat(path.c_str(), &status) != 0) {
        return errno == ENOENT ? StateFile::missing : StateFile::unusable;
    }
    if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() || (status.st_mode & 0077) != 0 ||
        status.st_size != static_cast<off_t>(state_size)) {
        return StateFile::unusable;
    }
    const int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return StateFile::unusable;
    }
    unsigned char bytes[state_size];
    const bool ok = read_all(fd, bytes, state_size);
    close(fd);
    if (!ok || !std::equal(state_header, state_header + sizeof state_header, bytes)) {
        return StateFile::unusable;
    }
    std::copy(bytes + sizeof state_header, bytes + sizeof state_header + state.id.size(), state.id.begin());
    state.pin = 0;
    for (std::size_t i = 0; i < pin_size; ++i) {
        state.pin = (state.pin << 8) | bytes[sizeof state_header + state.id.size() + i];
    }
    return StateFile::ok;
}

bool write_state(const fs::path& directory, const std::string& name, const FsState& state) {
    unsigned char bytes[state_size];
    encode_state(state, bytes);
    const fs::path final_path = directory / name;
    const fs::path temporary = directory / (name + "." + crypto_store::new_object_id() + ".tmp");
    if (!create_private_file(temporary, bytes, state_size)) {
        return false;
    }
    if (rename(temporary.c_str(), final_path.c_str()) != 0) {
        unlink(temporary.c_str());
        return false;
    }
    return fsync_directory(directory);
}

std::set<schema::BlobId> referenced_blobs(const schema::FsIndex& index) {
    std::set<schema::BlobId> ids;
    for (const auto& file : index.files) {
        ids.insert(file.second.blob_id);
    }
    return ids;
}

bool unlink_name(int dirfd, const std::string& name) { return unlinkat(dirfd, name.c_str(), 0) == 0; }

bool cleanup_unreferenced(const StoreDirs& dirs, const schema::FsIndex& index) {
    const auto referenced = referenced_blobs(index);
    std::vector<std::string> index_names;
    if (!each_name(dirs.filesystem, [&index_names](const std::string& name) {
            if (index_staging_name(name)) {
                index_names.push_back(name);
            }
            return true;
        })) {
        return false;
    }
    for (const std::string& name : index_names) {
        if (!unlink_name(dirs.filesystem, name)) {
            return false;
        }
    }
    std::vector<std::string> blob_names;
    if (!each_name(dirs.blobs, [&blob_names, &referenced](const std::string& name) {
            std::string id;
            bool temporary = false;
            if (blob_storage_name(name, id, temporary) && (temporary || referenced.count(id) == 0)) {
                blob_names.push_back(name);
            }
            return true;
        })) {
        return false;
    }
    for (const std::string& name : blob_names) {
        if (!unlink_name(dirs.blobs, name)) {
            return false;
        }
    }
    return true;
}

Result open_current(schema::FsIndex& out, FsState& state) {
    StoreDirs dirs;
    const OpenStore opened = open_store(dirs);
    if (opened == OpenStore::missing) {
        return failure(Error::missing_index);
    }
    if (opened != OpenStore::ok) {
        return failure(Error::not_authentic);
    }
    struct stat index_status{};
    if (!entry_status(dirs.filesystem, index_name, index_status)) {
        return failure(errno == ENOENT ? Error::missing_index : Error::not_authentic);
    }
    if (!S_ISREG(index_status.st_mode)) {
        return failure(Error::not_authentic);
    }
    const auto directory = state_directory();
    const auto name = installation_name();
    if (!directory || name.empty()) {
        return failure(Error::io);
    }
    const StateFile stored = read_state(*directory / (name + ".fs"), state);
    if (stored != StateFile::ok) {
        return failure(Error::not_authentic);
    }
    const auto object = read_at(dirs.filesystem, index_name, schema::max_index_plaintext + crypto_store::object_overhead);
    if (!object) {
        return failure(Error::not_authentic);
    }
    const auto plaintext = crypto_store::open_index(state.id, install_path(), *object);
    if (!plaintext) {
        return failure(Error::not_authentic);
    }
    const auto parsed = schema::parse_index(*plaintext);
    if (!parsed) {
        return failure(Error::corrupt);
    }
    if (parsed->generation < state.pin) {
        return failure(Error::rolled_back);
    }
    out = *parsed;
    return {};
}

bool stage_blob(int blobs, const StagedBlob& blob) {
    const std::string temporary_name = blob.blob_id + ".tmp";
    const std::string final_name = blob.blob_id + ".enc";
    if (regular_file_exists(blobs, final_name.c_str())) {
        return false;
    }
    const int fd = openat(blobs, temporary_name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0 || !write_all(fd, blob.object.data(), blob.object.size())) {
        if (fd >= 0) {
            close(fd);
        }
        unlinkat(blobs, temporary_name.c_str(), 0);
        return false;
    }
    close(fd);
    if (renameat2(blobs, temporary_name.c_str(), blobs, final_name.c_str(), RENAME_NOREPLACE) != 0) {
        unlinkat(blobs, temporary_name.c_str(), 0);
        return false;
    }
    return fsync_fd(blobs);
}

schema::ObjectId fresh_id(const schema::FsIndex& index) {
    for (;;) {
        auto id = crypto_store::new_object_id();
        if (index.accounts.count(id) == 0 && index.directories.count(id) == 0 && index.files.count(id) == 0) {
            return id;
        }
    }
}

}  // namespace

InstallationLock InstallationLock::acquire() {
    const auto directory = state_directory();
    const auto name = installation_name();
    if (!directory || name.empty()) {
        throw std::runtime_error("Could not lock the installation");
    }
    const int fd = open((*directory / (name + ".lock")).c_str(),
                        O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
    if (fd < 0) {
        throw std::runtime_error("Could not lock the installation");
    }
    struct stat status{};
    if (fstat(fd, &status) != 0 || status.st_uid != geteuid() || (status.st_mode & 0077) != 0 ||
        !S_ISREG(status.st_mode)) {
        close(fd);
        throw std::runtime_error("Invalid installation lock");
    }
    while (flock(fd, LOCK_EX) < 0) {
        if (errno != EINTR) {
            close(fd);
            throw std::runtime_error("Could not lock the installation");
        }
    }
    InstallationLock lock;
    lock.fd_ = fd;
    return lock;
}

InstallationLock::InstallationLock(InstallationLock&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }

InstallationLock& InstallationLock::operator=(InstallationLock&& other) noexcept {
    if (this != &other) {
        if (fd_ >= 0) {
            close(fd_);
        }
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

InstallationLock::~InstallationLock() {
    if (fd_ >= 0) {
        close(fd_);
    }
}

Result initialize_empty(const InstallationLock&) {
    if (mkdir(filesystem_name, 0755) != 0 && errno != EEXIST) {
        return failure(Error::io);
    }
    const int filesystem = open(filesystem_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (filesystem < 0) {
        return failure(Error::io);
    }
    if (mkdirat(filesystem, blobs_name, 0755) != 0 && errno != EEXIST) {
        close(filesystem);
        return failure(Error::io);
    }
    const int blobs = openat(filesystem, blobs_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (blobs < 0) {
        close(filesystem);
        return failure(Error::io);
    }
    if (regular_file_exists(filesystem, index_name)) {
        close(blobs);
        close(filesystem);
        return failure(Error::already_exists);
    }
    const auto directory = state_directory();
    const auto name = installation_name();
    if (!directory || name.empty()) {
        close(blobs);
        close(filesystem);
        return failure(Error::io);
    }
    FsState state;
    const StateFile existing = read_state(*directory / (name + ".fs"), state);
    if (existing != StateFile::ok) {
        if (RAND_bytes(state.id.data(), static_cast<int>(state.id.size())) != 1) {
            close(blobs);
            close(filesystem);
            return failure(Error::io);
        }
    }
    state.pin = 1;
    if (!write_state(*directory, name + ".fs", state)) {
        close(blobs);
        close(filesystem);
        return failure(Error::io);
    }
    schema::FsIndex index;
    index.generation = 1;
    if (!schema::validate_index(index).empty()) {
        close(blobs);
        close(filesystem);
        return failure(Error::corrupt);
    }
    crypto_store::Bytes sealed;
    try {
        sealed = crypto_store::seal_index(state.id, install_path(), schema::serialize_index(index));
    } catch (const std::exception&) {
        close(blobs);
        close(filesystem);
        return failure(Error::io);
    }
    const std::string temporary_name = "index." + crypto_store::new_object_id() + ".tmp";
    const int fd = openat(filesystem, temporary_name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0 || !write_all(fd, sealed.data(), sealed.size())) {
        if (fd >= 0) {
            close(fd);
        }
        unlinkat(filesystem, temporary_name.c_str(), 0);
        close(blobs);
        close(filesystem);
        return failure(Error::io);
    }
    close(fd);
    if (renameat(filesystem, temporary_name.c_str(), filesystem, index_name) != 0) {
        unlinkat(filesystem, temporary_name.c_str(), 0);
        close(blobs);
        close(filesystem);
        return failure(Error::io);
    }
    const bool synced = fsync_fd(filesystem);
    close(blobs);
    close(filesystem);
    if (!synced) {
        return failure(Error::io);
    }
    return {};
}

Result load_metadata(const InstallationLock&, schema::FsIndex& out) {
    FsState state;
    const Result opened = open_current(out, state);
    if (!opened.ok()) {
        return opened;
    }
    if (out.generation > state.pin) {
        state.pin = out.generation;
        const auto directory = state_directory();
        const auto name = installation_name();
        if (!directory || name.empty() || !write_state(*directory, name + ".fs", state)) {
            return failure(Error::io);
        }
    }
    StoreDirs dirs;
    if (open_store(dirs) != OpenStore::ok || !cleanup_unreferenced(dirs, out)) {
        return failure(Error::io);
    }
    return {};
}

Result commit_mutation(const InstallationLock&, Mutation& mutation) {
    schema::FsIndex current;
    FsState state;
    const Result opened = open_current(current, state);
    if (!opened.ok()) {
        return opened;
    }
    if (current.generation != mutation.expected_generation || mutation.expected_generation == UINT64_MAX) {
        return failure(current.generation == mutation.expected_generation ? Error::io : Error::generation_conflict);
    }
    mutation.next_index.generation = mutation.expected_generation + 1;
    if (!schema::validate_index(mutation.next_index).empty()) {
        return failure(Error::corrupt);
    }
    const auto plaintext = schema::serialize_index(mutation.next_index);
    if (plaintext.size() > schema::max_index_plaintext) {
        return failure(Error::too_large);
    }
    const auto current_blobs = referenced_blobs(current);
    const auto next_blobs = referenced_blobs(mutation.next_index);
    std::set<schema::BlobId> expected_retired;
    for (const schema::BlobId& id : current_blobs) {
        if (next_blobs.count(id) == 0) {
            expected_retired.insert(id);
        }
    }
    if (std::set<schema::BlobId>(mutation.retired_blobs.begin(), mutation.retired_blobs.end()) != expected_retired) {
        return failure(Error::corrupt);
    }
    StoreDirs dirs;
    if (open_store(dirs) != OpenStore::ok) {
        return failure(Error::io);
    }
    for (const StagedBlob& blob : mutation.new_blobs) {
        if (!schema::is_valid_id(blob.blob_id) || current_blobs.count(blob.blob_id) != 0 ||
            regular_file_exists(dirs.blobs, (blob.blob_id + ".enc").c_str())) {
            return failure(Error::corrupt);
        }
        if (blob.object.size() > crypto_store::object_overhead + crypto_store::max_blob_plaintext) {
            return failure(Error::too_large);
        }
    }
    for (const StagedBlob& blob : mutation.new_blobs) {
        if (!stage_blob(dirs.blobs, blob)) {
            return failure(Error::io);
        }
    }
    crypto_store::Bytes sealed;
    try {
        sealed = crypto_store::seal_index(state.id, install_path(), plaintext);
    } catch (const std::exception&) {
        return failure(Error::io);
    }
    const std::string temporary_name = "index." + crypto_store::new_object_id() + ".tmp";
    const int fd = openat(dirs.filesystem, temporary_name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0 || !write_all(fd, sealed.data(), sealed.size())) {
        if (fd >= 0) {
            close(fd);
        }
        unlinkat(dirs.filesystem, temporary_name.c_str(), 0);
        return failure(Error::io);
    }
    close(fd);
    if (renameat(dirs.filesystem, temporary_name.c_str(), dirs.filesystem, index_name) != 0) {
        unlinkat(dirs.filesystem, temporary_name.c_str(), 0);
        return failure(Error::io);
    }

    const char* fail = std::getenv(fail_after_rename);
    if (fail != nullptr && std::strcmp(fail, "1") == 0) {
        return committed_failure();
    }
    if (!fsync_fd(dirs.filesystem)) {
        return committed_failure();
    }
    state.pin = mutation.next_index.generation;
    const auto directory = state_directory();
    const auto name = installation_name();
    if (!directory || name.empty() || !write_state(*directory, name + ".fs", state)) {
        return committed_failure();
    }
    for (const schema::BlobId& retired : expected_retired) {
        if (!unlink_name(dirs.blobs, retired + ".enc")) {
            return committed_failure();
        }
    }
    Result result;
    result.committed = true;
    return result;
}

Result read_blob(const InstallationLock&, const schema::FileRecord& file, crypto_store::Bytes& object_out) {
    StoreDirs dirs;
    if (open_store(dirs) != OpenStore::ok) {
        return failure(Error::io);
    }
    const std::string name = file.blob_id + ".enc";
    const auto object = read_at(dirs.blobs, name.c_str(), crypto_store::object_overhead + crypto_store::max_blob_plaintext);
    if (!object) {
        return failure(regular_file_exists(dirs.blobs, name.c_str()) ? Error::io : Error::blob_missing);
    }
    try {
        if (crypto_store::sha256_hex(*object) != file.blob_sha256) {
            return failure(Error::blob_mismatch);
        }
    } catch (const std::exception&) {
        return failure(Error::io);
    }
    object_out = *object;
    return {};
}

Result ensure_user_roots(const InstallationLock& lock, const std::string& username, schema::Role role,
                         schema::AccountId& account_id_out) {
    schema::FsIndex index;
    const Result loaded = load_metadata(lock, index);
    if (!loaded.ok()) {
        return loaded;
    }
    for (const auto& item : index.accounts) {
        if (item.second.username == username) {
            account_id_out = item.first;
            return {};
        }
    }
    const schema::AccountId account_id = fresh_id(index);
    schema::DirectoryId personal_id;
    schema::DirectoryId shared_id;
    do {
        personal_id = fresh_id(index);
    } while (personal_id == account_id);
    do {
        shared_id = fresh_id(index);
    } while (shared_id == account_id || shared_id == personal_id);

    schema::AccountEntry account;
    account.username = username;
    account.role = role;
    account.personal_dir_id = personal_id;
    account.shared_dir_id = shared_id;
    index.accounts.emplace(account_id, account);
    index.directories.emplace(personal_id, schema::Directory{account_id, {}});
    index.directories.emplace(shared_id, schema::Directory{account_id, {}});
    if (!schema::validate_index(index).empty()) {
        return failure(Error::corrupt);
    }
    Mutation mutation;
    mutation.expected_generation = index.generation;
    mutation.next_index = std::move(index);
    const Result committed = commit_mutation(lock, mutation);
    if (!committed.ok()) {
        return committed;
    }
    account_id_out = account_id;
    return committed;
}

}  // namespace storage
