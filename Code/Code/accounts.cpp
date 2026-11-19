#include "accounts.h"
#include "storage.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

// This file sets up the first admin, checks a keyfile at login, and enrolls
// new users. Start with login() and add_user() near the bottom for the main flow.
namespace accounts {
// An unnamed namespace makes these helpers available only in this source file.
namespace {

namespace fs = std::filesystem;
using Byte = unsigned char;

constexpr char filesystem_name[] = "filesystem";
constexpr char public_keys_name[] = "public_keys";
// A keyfile starts with a format marker and version, followed by two random
// seeds. Each seed recreates one keypair when the keyfile is loaded.
constexpr std::array<Byte, 8> credential_header{'B', 'I', 'B', 'I', 'F', 'I', 'K', 1};
constexpr std::array<Byte, 8> state_header{'B', 'I', 'B', 'I', 'F', 'I', 'S', 3};
constexpr std::size_t seed_size = 32;
constexpr std::size_t public_key_size = 32;
constexpr std::size_t credential_size = credential_header.size() +
    2 * seed_size;
constexpr std::size_t object_nonce_offset = crypto_store::header_size + crypto_store::salt_size;
using PublicKeys = std::array<Byte, 2 * public_key_size>;
using PrivateKey = std::shared_ptr<EVP_PKEY>;
using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

// A template lets us use this wrapper for different fixed sizes. The destructor
// clears the secret bytes when the object leaves scope, including after an error.
template<std::size_t Size>
struct Secret {
    std::array<Byte, Size> bytes{};

    Secret() = default;
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    ~Secret() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};

using Credential = Secret<credential_size>;
// State stores the format header and the nonce that selects the current registry.
using RegistryState = std::array<Byte, state_header.size() + crypto_store::nonce_size>;

void random_bytes(Byte* data, int size) {
    if (RAND_bytes(data, size) != 1) {
        throw std::runtime_error("Could not generate secure random bytes");
    }
}

struct Account {
    std::string name;
    PublicKeys keys;
};

struct KeyPairs {
    PublicKeys public_keys{};
    PrivateKey signing;
    PrivateKey encryption;
};

// A file descriptor is Linux's integer handle for an open file or directory.
// This wrapper closes the handle automatically. Moving it transfers ownership,
// and copying is disabled so two objects can't close the same handle.
class File {
public:
    explicit File(int fd) : fd_(fd) {
        if (fd_ < 0) {
            throw std::runtime_error("Could not open authentication storage");
        }
    }
    File(const File&) = delete;
    File& operator=(const File&) = delete;
    File(File&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
    ~File() {
        if (fd_ >= 0) {
            close(fd_);
        }
    }
    int fd() const { return fd_; }

private:
    int fd_;
};

File open_directory(const fs::path& path) {
    return File(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
}

File open_directory_at(const File& parent, const char* name) {
    // openat resolves the name inside an already-open directory. O_NOFOLLOW
    // rejects a symbolic link at the final path component.
    return File(openat(parent.fd(), name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
}

File ensure_directory(const File& parent, const char* name, mode_t mode) {
    if (mkdirat(parent.fd(), name, mode) < 0 && errno != EEXIST) {
        throw std::runtime_error("Could not create authentication directory");
    }
    return open_directory_at(parent, name);
}

struct stat file_status(const File& file) {
    struct stat status{};
    if (fstat(file.fd(), &status) < 0) {
        throw std::runtime_error("Could not inspect authentication storage");
    }
    return status;
}

void require_private(const struct stat& status) {
    // 0077 is an octal mask covering all group and other permission bits.
    if (status.st_uid != geteuid() || (status.st_mode & 0077) != 0) {
        throw std::runtime_error("Private authentication storage requires owner-only access");
    }
}

bool exists(const File& directory, const std::string& name) {
    struct stat status{};
    if (fstatat(directory.fd(), name.c_str(), &status, AT_SYMLINK_NOFOLLOW) == 0) {
        return true;
    }
    if (errno != ENOENT) {
        throw std::runtime_error("Could not inspect authentication path");
    }
    return false;
}

void read_bytes(const File& file, Byte* data, std::size_t size) {
    // One read can return fewer bytes than requested. Advance through the
    // buffer until it is full and retry if a signal interrupted the read.
    while (size != 0) {
        const auto count = read(file.fd(), data, size);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            throw std::runtime_error("Could not read authentication data");
        }
        data += count;
        size -= count;
    }
}

void read_private(const File& directory, const std::string& name, Byte* data, std::size_t size) {
    // O_NONBLOCK keeps a named pipe from blocking the open before we can
    // check that the entry is a regular file of the expected size.
    const File file(openat(directory.fd(), name.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
    const auto status = file_status(file);
    require_private(status);
    if (!S_ISREG(status.st_mode) || status.st_size != static_cast<off_t>(size)) {
        throw std::runtime_error("Invalid private file format");
    }
    read_bytes(file, data, size);
}

// Create a file without overwriting an existing name. The file is removed
// when this object leaves scope unless keep() marks the operation complete.
class NewFile {
public:
    NewFile(const File& directory, std::string name, const Byte* data, std::size_t size, mode_t mode)
        : directory_(directory), name_(std::move(name)) {
        const File file(openat(directory_.fd(), name_.c_str(),
                               O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode));
        try {
            if (mode == 0600) {
                require_private(file_status(file));
            }
            while (size != 0) {
                const auto count = write(file.fd(), data, size);
                if (count < 0 && errno == EINTR) {
                    continue;
                }
                if (count <= 0) {
                    throw std::runtime_error("Could not write authentication data");
                }
                data += count;
                size -= count;
            }
            if (fsync(file.fd()) < 0) {
                throw std::runtime_error("Could not save authentication data");
            }
        } catch (...) {
            // A constructor that throws never reaches this object's destructor.
            unlinkat(directory_.fd(), name_.c_str(), 0);
            throw;
        }
    }
    NewFile(const NewFile&) = delete;
    NewFile& operator=(const NewFile&) = delete;
    ~NewFile() {
        if (!kept_) {
            unlinkat(directory_.fd(), name_.c_str(), 0);
        }
    }
    void keep() { kept_ = true; }

private:
    const File& directory_;
    const std::string name_;
    bool kept_ = false;
};

template<std::size_t Size>
std::string hex(const std::array<Byte, Size>& bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(2 * Size);
    for (Byte byte : bytes) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}

PublicKeys parse_public_keys(const std::string& text) {
    PublicKeys result{};
    if (text.size() != 2 * result.size()) {
        throw std::runtime_error("Invalid public key encoding");
    }
    for (std::size_t i = 0; i < result.size(); ++i) {
        unsigned int value = 0;
        const char* first = text.data() + 2 * i;
        const auto parsed = std::from_chars(first, first + 2, value, 16);
        if (parsed.ec != std::errc{} || parsed.ptr != first + 2 || value > 255) {
            throw std::runtime_error("Invalid public key encoding");
        }
        result[i] = static_cast<Byte>(value);
    }
    return result;
}

File open_trusted_directory() {
    // Keep the registry version under the Linux user's home directory. Reading
    // /etc/passwd directly avoids getpwuid's optional shared lookup libraries
    // in the static build. HOME is the fallback for a non-local account.
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
        throw std::runtime_error("Could not locate the Linux account home");
    }
    const auto home = open_directory(home_path);
    const auto status = file_status(home);
    if (status.st_uid != geteuid() || (status.st_mode & 0022) != 0) {
        throw std::runtime_error("Authentication state requires an owner-controlled Linux home");
    }
    return ensure_directory(home, ".bibifi-state", 0700);
}

std::string installation_name() {
    // Hash the working path into a fixed-length filename so multiple
    // installations can keep separate registry state under the same home.
    const auto cwd = fs::current_path().string();
    std::array<Byte, 32> digest{};
    if (EVP_Digest(cwd.data(), cwd.size(), digest.data(), nullptr, EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("Could not identify the installation");
    }
    return "openssl-" + hex(digest);
}

struct Installation {
    const File working = open_directory(".");
    const File trusted = open_trusted_directory();
    const std::string name = installation_name();
    const storage::InstallationLock lock = storage::InstallationLock::acquire();
};

File public_directory() {
    // Linux exposes the running executable through /proc/self/exe. The public
    // keys go beside that executable, even when launched from another directory.
    const auto executable = fs::read_symlink("/proc/self/exe");
    const auto directory = open_directory(executable.parent_path());
    return ensure_directory(directory, public_keys_name, 0755);
}

PrivateKey private_key(const char* algorithm, const Byte* data) {
    PrivateKey key(EVP_PKEY_new_raw_private_key_ex(nullptr, algorithm, nullptr, data, seed_size),
                   EVP_PKEY_free);
    if (!key) {
        throw std::runtime_error("Could not load the private key");
    }
    return key;
}

KeyPairs derive_keys(const Credential& credential) {
    // Ed25519 accepts the saved seed directly. The encryption seed is expanded
    // with SHA-512, and its first 32 bytes form the raw X25519 private key.
    KeyPairs keys;
    const Byte* seed = credential.bytes.data() + credential_header.size();
    keys.signing = private_key("ED25519", seed);
    Secret<64> encryption_digest;
    if (EVP_Digest(seed + seed_size, seed_size, encryption_digest.bytes.data(), nullptr,
                    EVP_sha512(), nullptr) != 1) {
        throw std::runtime_error("Could not derive the account keys");
    }
    keys.encryption = private_key("X25519", encryption_digest.bytes.data());
    std::size_t size = public_key_size;
    if (EVP_PKEY_get_raw_public_key(keys.signing.get(), keys.public_keys.data(), &size) != 1 ||
        size != public_key_size) {
        throw std::runtime_error("Could not derive the signing public key");
    }
    size = public_key_size;
    if (EVP_PKEY_get_raw_public_key(keys.encryption.get(), keys.public_keys.data() + public_key_size,
                                    &size) != 1 || size != public_key_size) {
        throw std::runtime_error("Could not derive the encryption public key");
    }
    return keys;
}

Account generate_account(const std::string& name, Credential& credential) {
    std::copy(credential_header.begin(), credential_header.end(), credential.bytes.begin());
    random_bytes(credential.bytes.data() + credential_header.size(), 2 * seed_size);
    return {name, derive_keys(credential).public_keys};
}

bool verify_login(const PublicKeys& enrolled, const PrivateKey& signing_key) {
    // Sign a fresh random challenge with the keyfile's private signing key.
    // The enrolled public signing key must verify the signature.
    std::array<Byte, 32> challenge{};
    std::array<Byte, 64> signature{};
    random_bytes(challenge.data(), challenge.size());
    DigestContext signer(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    DigestContext verifier(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    const PrivateKey public_key(EVP_PKEY_new_raw_public_key_ex(
        nullptr, "ED25519", nullptr, enrolled.data(), public_key_size), EVP_PKEY_free);
    std::size_t signature_size = signature.size();
    return signer && verifier && public_key &&
        EVP_DigestSignInit(signer.get(), nullptr, nullptr, nullptr, signing_key.get()) == 1 &&
        EVP_DigestSign(signer.get(), signature.data(), &signature_size,
                        challenge.data(), challenge.size()) == 1 &&
        EVP_DigestVerifyInit(verifier.get(), nullptr, nullptr, nullptr, public_key.get()) == 1 &&
        EVP_DigestVerify(verifier.get(), signature.data(), signature_size,
                          challenge.data(), challenge.size()) == 1;
}

RegistryState read_registry_state(const File& directory, const std::string& name) {
    RegistryState state{};
    read_private(directory, name, state.data(), state.size());
    if (!std::equal(state_header.begin(), state_header.end(), state.begin())) {
        throw std::runtime_error("Invalid registry state format");
    }
    return state;
}

std::string registry_filename(const RegistryState& state) {
    std::array<Byte, crypto_store::nonce_size> nonce{};
    std::copy(state.begin() + state_header.size(), state.end(), nonce.begin());
    return "accounts." + hex(nonce);
}

std::vector<Account> load_registry(const File& directory, const std::string& installation_name,
                                   const RegistryState& state) {
    const auto name = registry_filename(state);
    const File file(openat(directory.fd(), name.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
    const auto status = file_status(file);
    if (!S_ISREG(status.st_mode) || status.st_size < static_cast<off_t>(crypto_store::object_overhead) ||
        status.st_size > static_cast<off_t>(crypto_store::object_overhead + crypto_store::max_registry_plaintext)) {
        throw std::runtime_error("Invalid account registry");
    }
    crypto_store::Bytes encrypted(status.st_size);
    read_bytes(file, encrypted.data(), encrypted.size());

    // The saved nonce pins the committed version. Only the crypto store can
    // authenticate and release the plaintext for that version.
    if (!std::equal(state.begin() + state_header.size(), state.end(), encrypted.begin() + object_nonce_offset)) {
        throw std::runtime_error("Unexpected account registry version");
    }
    const auto plaintext = crypto_store::open_registry(installation_name, encrypted);
    if (!plaintext) {
        throw std::runtime_error("Account registry authentication failed");
    }

    // Each decrypted record holds a username and both public keys in hex.
    std::vector<Account> accounts;
    std::set<std::string> names;
    std::set<PublicKeys> enrolled_keys;
    std::istringstream input(*plaintext);
    for (Account account; input >> account.name;) {
        std::string keys;
        if (!valid_username(account.name) || !(input >> keys)) {
            throw std::runtime_error("Invalid account record");
        }
        account.keys = parse_public_keys(keys);
        if (!names.insert(account.name).second || !enrolled_keys.insert(account.keys).second) {
            throw std::runtime_error("Duplicate account record");
        }
        accounts.push_back(account);
    }
    if (names.count("admin") == 0) {
        throw std::runtime_error("Missing admin account");
    }
    return accounts;
}

void save_registry(const Installation& installation, const File& directory,
                   const std::vector<Account>& accounts) {
    std::string plaintext;
    for (const auto& account : accounts) {
        plaintext += account.name + ' ' + hex(account.keys) + '\n';
    }
    const auto encrypted = crypto_store::seal_registry(installation.name, plaintext);
    RegistryState state{};
    std::copy(state_header.begin(), state_header.end(), state.begin());
    std::copy_n(encrypted.begin() + object_nonce_offset, crypto_store::nonce_size,
                state.begin() + state_header.size());

    // Publish the encrypted record first. The protected state selects one
    // version and commits it with a single atomic rename.
    const auto name = registry_filename(state);
    NewFile registry(directory, name, encrypted.data(), encrypted.size(), 0644);
    const NewFile pending(installation.trusted, name, state.data(), state.size(), 0600);
    if (renameat(installation.trusted.fd(), name.c_str(),
                 installation.trusted.fd(), installation.name.c_str()) < 0) {
        throw std::runtime_error("Could not commit account registry");
    }
    registry.keep();
}

std::string public_filename(const PublicKeys& keys) {
    std::array<Byte, public_key_size> signing_key{};
    std::copy_n(keys.begin(), signing_key.size(), signing_key.begin());
    return hex(signing_key) + ".pub";
}

void initialize(const Installation& installation, const File& keys, const std::string& key_name) {
    // Bootstrap requires the admin filename and a fresh filesystem directory.
    // An existing keyfile or storage directory is preserved.
    if (key_name != "admin_keyfile" || exists(keys, key_name) ||
        mkdirat(installation.working.fd(), filesystem_name, 0755) < 0) {
        throw std::runtime_error("Cannot initialize the filesystem");
    }
    std::optional<File> directory;
    try {
        directory.emplace(open_directory_at(installation.working, filesystem_name));
        const auto public_keys = public_directory();
        Credential credential;
        const auto admin = generate_account("admin", credential);
        NewFile private_file(keys, key_name, credential.bytes.data(), credential.bytes.size(), 0600);
        NewFile public_file(public_keys, public_filename(admin.keys), admin.keys.data(), admin.keys.size(), 0644);

        if (!storage::initialize_empty(installation.lock).ok()) {
            throw std::runtime_error("Could not initialize filesystem index");
        }
        schema::AccountId root_id;
        if (!storage::ensure_user_roots(installation.lock, "admin", schema::Role::admin, root_id).ok()) {
            throw std::runtime_error("Could not create admin roots");
        }
        save_registry(installation, *directory, {admin});
        private_file.keep();
        public_file.keep();
    } catch (...) {
        // This call created filesystem/. Before the registry is published,
        // its index and empty blobs directory are disposable setup state.
        // Keep the descriptor open during rollback and remove only known
        // entries. rmdir preserves a directory containing unexpected files.
        if (directory) {
            unlinkat(directory->fd(), "index.enc", 0);
            unlinkat(directory->fd(), "blobs", AT_REMOVEDIR);
        }
        if (unlinkat(installation.working.fd(), filesystem_name, AT_REMOVEDIR) == 0) {
            const auto index_state = installation.name + ".fs";
            unlinkat(installation.trusted.fd(), index_state.c_str(), 0);
        }
        throw;
    }
}

}  // namespace

bool valid_username(const std::string& name) {
    // Usernames become part of keyfile names. Restricting them to these
    // characters keeps path separators and whitespace out of those names.
    return name != "personal" && name != "shared" && !name.empty() && name.size() <= 64 &&
        std::all_of(name.begin(), name.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-';
    });
}

Session login(const fs::path& keyfile) {
    if (OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr) != 1) {
        throw std::runtime_error("Could not initialize OpenSSL");
    }
    const auto path = fs::absolute(keyfile);
    const auto key_name = path.filename().string();
    const auto keys = open_directory(path.parent_path());
    // Keeping this object in scope holds the installation lock through setup
    // and credential verification. It is released before the shell starts.
    const Installation installation;
    if (!exists(installation.trusted, installation.name)) {
        initialize(installation, keys, key_name);
    }

    Credential credential;
    read_private(keys, key_name, credential.bytes.data(), credential.bytes.size());
    if (!std::equal(credential_header.begin(), credential_header.end(), credential.bytes.begin())) {
        throw std::runtime_error("Invalid keyfile header");
    }

    const auto state = read_registry_state(installation.trusted, installation.name);
    const auto directory = open_directory_at(installation.working, filesystem_name);
    const auto registry = load_registry(directory, installation.name, state);
    auto keys_for_session = derive_keys(credential);
    // The encrypted registry binds the actual keypair to a username. The
    // keyfile's name and the public copies in public_keys/ can change.
    const auto account = std::find_if(registry.begin(), registry.end(), [&](const Account& candidate) {
        return candidate.keys == keys_for_session.public_keys;
    });
    if (account == registry.end() || !verify_login(account->keys, keys_for_session.signing)) {
        throw std::runtime_error("Keyfile is not enrolled");
    }
    return {account->name, path.parent_path(), std::move(keys_for_session.encryption), {}};
}

namespace {
class DirectorySnapshot final : public storage::AccountDirectory {
public:
    explicit DirectorySnapshot(std::vector<Account> entries) : entries_(std::move(entries)) {}
    std::optional<crypto_store::PublicKey> encryption_key(const std::string& username) const override {
        for (const auto& account : entries_) {
            if (account.name == username) {
                crypto_store::PublicKey key{};
                std::copy(account.keys.begin() + public_key_size, account.keys.end(), key.begin());
                return key;
            }
        }
        return std::nullopt;
    }
    bool is_enrolled(const std::string& username) const override {
        return std::any_of(entries_.begin(), entries_.end(), [&](const auto& a) { return a.name == username; });
    }
    std::vector<std::string> usernames() const override {
        std::vector<std::string> names;
        for (const auto& a : entries_) names.push_back(a.name);
        std::sort(names.begin(), names.end());
        return names;
    }
private:
    std::vector<Account> entries_;
};
}  // namespace

std::unique_ptr<storage::AccountDirectory> directory_snapshot(const storage::InstallationLock&) {
    const auto trusted = open_trusted_directory();
    const auto name = installation_name();
    const auto state = read_registry_state(trusted, name);
    const auto working = open_directory(".");
    const auto directory = open_directory_at(working, filesystem_name);
    return std::make_unique<DirectorySnapshot>(load_registry(directory, name, state));
}

bool add_user(const Session& admin, const std::string& username) {
    if (!admin.is_admin() || !valid_username(username)) {
        throw std::runtime_error("Invalid account creation request");
    }
    const Installation installation;
    const auto state = read_registry_state(installation.trusted, installation.name);
    const auto directory = open_directory_at(installation.working, filesystem_name);
    auto registry = load_registry(directory, installation.name, state);
    const auto previous_registry = registry_filename(state);
    if (std::any_of(registry.begin(), registry.end(), [&](const Account& account) {
        return account.name == username;
    })) {
        return false;
    }

    // Put the new private key beside the admin's keyfile. Publish the new
    // registry before keeping either key file, so a failed save cleans them up.
    const auto keys = open_directory(admin.key_directory);
    const auto public_keys = public_directory();
    Credential credential;
    registry.push_back(generate_account(username, credential));
    const auto& account = registry.back();
    NewFile private_file(keys, username + "_keyfile", credential.bytes.data(), credential.bytes.size(), 0600);
    NewFile public_file(public_keys, public_filename(account.keys), account.keys.data(), account.keys.size(), 0644);
    schema::AccountId root_id;
    if (!storage::ensure_user_roots(installation.lock, username, schema::Role::user, root_id).ok()) {
        throw std::runtime_error("Could not create user roots");
    }
    save_registry(installation, directory, registry);
    private_file.keep();
    public_file.keep();
    unlinkat(directory.fd(), previous_registry.c_str(), 0);
    return true;
}

}  // namespace accounts
