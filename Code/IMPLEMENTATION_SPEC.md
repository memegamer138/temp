BIBIFI implementation spec and work allocation
=============================================

Prepared for Shahruj, Nishant, Kevin Gonzalez Castro (KG), and Mike on 6 November 2026.

This draft translates the supplied team discussion into implementation tasks. Shahruj confirmed OpenSSL with AES-256-GCM and a single synchronous process on 6 November 2026. Teaching-team Piazza clarifications of 19 October 2026 ([post 25](https://piazza.com/class/mtv3ou33v53wh/post/25)) settle approved libraries, master-key / internal-secret rules, and admin dual-role permissions. A follow-up TA reply on that thread also confirms that password/keyfile reissue and share revocation are out of scope. Remaining choices are listed for team confirmation. Work assignments are proposed based on the discussion and Shahruj's existing authentication implementation.

**Confirmed decisions and remaining handoffs**

| ID | Decision | Proposals in the notes | Proposed direction and consequence | Decision owners |
| --- | --- | --- | --- | --- |
| D1 | Confirmed crypto choice | OpenSSL, Ed25519 signatures, separate X25519 encryption keys, and AES-256-GCM for encrypted storage. | Shahruj implements authentication and encrypted account storage. KG owns file-key wrapping and the filesystem encrypted-object format. Do not implement cryptographic primitives yourselves. | Shahruj + KG |
| D2 | Confirmed admin policy | Admin is also a regular user and can read every other user's tree. | Admin has its own `/personal` and `/shared` and full regular-user features there, including `mkdir`, `mkfile`, and `share` of its own files. Admin may also `cd`, `pwd`, `ls`, and `cat` under every user's directories. Admin must not create, modify, or share inside any other user's directories; refuse those with `Forbidden`. Only the file owner may share, so recipients cannot re-share. | Nishant + Mike |
| D3 | Confirmed process structure | One synchronous `fileserver` executable containing the shell, authentication, and filesystem modules. | Components communicate through C++ interfaces within that process. The submission must be a standalone static executable that links statically on the lab Ubuntu image. | Team |
| D4 | Confirmed metadata serialization | KG proposes `nlohmann::json`. | Use `nlohmann::json` for JSON parsing and serialization. Teaching-team Piazza [post 25](https://piazza.com/class/mtv3ou33v53wh/post/25) (19 October 2026) approved it without a further request. Agree the schema first. Serialization belongs to KG's storage module. | KG |
| D5 | Confirmed key custody and threat model | A filesystem master key copied into every keyfile, or a protected internal metadata key with file keys wrapped for authorized users. | A key compiled into the binary counts as an internal secret; extracting it from source or the binary is not a Break-it finding. A key stored on disk, placed in user keyfiles, or derived from public information (usernames, public keys, paths) is not an internal secret; recovering it is a valid weak-cryptography finding. Prefer a compiled-in filesystem master key (and/or per-user envelope keys) rather than putting a global key in keyfiles. Store recipient-wrapped file keys in metadata. Single master key and per-user key designs are both acceptable; explain the choice in the design report. | Shahruj + KG |
| D6 | Sharing collisions and denied re-sharing | Flat shared names, with several possible collision and permission error behaviors. | The VFS adopts idempotent sharing, stable owner/ID suffixes on collision, and `Forbidden` for denied re-sharing. Exact rules are in `Code/SCHEMA.md` section 10. | Mike + Shahruj |
| D7 | Name rules, limits, and unspecified errors | KG proposes a 64-character whitelist and single-name operands for file commands. Some notes also reject dots while permitting extensions. | The VFS adopts the creation-name and content limits in `Code/SCHEMA.md` section 10 and `Code/vfs_interfaces.h`, supports absolute and relative operands, and preserves printable ASCII spaces. Extensions such as `notes.txt` are allowed; exact `.` and `..`, separators within an entry name, and embedded NUL are rejected. | Nishant + Shahruj |
| D8 | Confirmed account and filesystem metadata layout | Separate encrypted account registry and index. | The registry and `filesystem/index.enc` are joined by username. Under one installation lock, `storage::ensure_user_roots` commits the roots before the registry publishes the account. The registry derives its AES key from the compiled-in master key. See `Code/SCHEMA.md` for formats and interfaces. | KG + Shahruj |

**Approved external libraries (teaching-team Piazza [post 25](https://piazza.com/class/mtv3ou33v53wh/post/25), 19 October 2026)**

The following may be used for the listed functionality without asking again:

| Library | Approved use |
| --- | --- |
| C++17 standard library, including `std::filesystem` | Anything |
| OpenSSL | Cryptography |
| libsodium | Cryptography (encryption, signatures, hashing / key derivation, secure random numbers, secure-memory helpers) |
| nlohmann/json | JSON parsing and serialization |

For any other dependency, make a private Piazza post first with a link to the code and the needed functionality. Do not implement cryptographic primitives yourselves. The submission must remain a standalone static executable, so libraries must link statically on the lab Ubuntu image.

**Locked precedence calls (older FAQ vs Piazza post 25)**

The default order is the instructions, then the FAQ, then Piazza, then this spec. For the four conflicts below the team accepted the Piazza answer over the older FAQ answer. `Code/SCHEMA.md` section 1 repeats them for the code.

| Topic | Rejected (older FAQ) | Accepted (Piazza and instructions) |
| --- | --- | --- |
| Admin | FAQ #4: read-only | Dual role: full user features in admin's own `/personal`, read-only elsewhere, `Forbidden` for writes outside it |
| Master key | FAQ #11: store anything in the keyfile | Compiled-in master key; never in a keyfile or on disk; never derived from public data |
| Host layout | FAQ #7: host `mkdir` allowed | Encrypted index plus flat opaque blobs; no host names that reflect virtual names, owners, or shares |
| Libraries | STL only | C++17, `std::filesystem`, OpenSSL, libsodium, nlohmann/json without a further request |

**Out of scope (TA follow-up on [post 25](https://piazza.com/class/mtv3ou33v53wh/post/25))**

Neither password/keyfile rotation nor share revocation is part of the course spec, so do not implement them:

| Topic | Teaching-team guidance |
| --- | --- |
| Password / keyfile changes | There are no passwords. Users log in with their keyfile, and there is no command to change or reissue it. |
| Revoking shared access | There is no `unshare` command. Once a file is shared it stays shared. |
| Shared-file updates | The only update that must be supported is `mkfile` on a shared file: the recipient must see the new contents. |

Do not add extra commands for these cases. Keep the architecture simple; every extra feature is more attack surface in Break-it. If the design would make password/keyfile reissue or unshare hard to add later, note that as a limitation in the design report.

Shahruj's implemented handoff includes OpenSSL authentication, a session containing an owned X25519 key and virtual current directory, and the complete command parser with structured filesystem results. The production CLI now also connects VFS execution and creates personal/shared roots before account publication. The parser accepts empty file contents and the shell uses `Invalid Command` for non-admin `adduser` requests.

**Required behavior and acceptance checks**

All implementation is C++17. The executable is called `fileserver`, starts with `./fileserver <keyfile>`, and prints a newline after every output line. The target environment is the course-supported Ubuntu image, currently represented locally by Ubuntu 24.04. The final executable must be statically linked.

| Feature | Required behavior | Minimum acceptance check | Owner |
| --- | --- | --- | --- |
| First run | Initialize `filesystem/` in the launch directory and create the admin keyfile and registered public keys. Preserve existing credentials and initialized data on subsequent runs. | Fresh start succeeds, second login retains the admin identity, and a failed initialization preserves existing files. | Shahruj + KG |
| Login | Verify the supplied private credential against authenticated account enrollment. Print `Invalid keyfile` and exit on failure. Print `Logged in as <username>` on success and list available commands. Start the virtual working directory at `/`. | Valid, renamed, corrupted, unknown, missing, and public-only keyfiles. A public-key replacement cannot grant another identity. | Shahruj |
| `cd <directory>` | Resolve absolute and relative paths component by component, including `.`, `..`, and multiple segments. `/` returns to the user's virtual root. Failed resolution preserves the previous working directory. | `cd /`, `cd ../../personal/x`, traversal above root, missing intermediate directory, and a file used as an intermediate directory. | Nishant |
| `pwd` | Print the normalized virtual working path. | First login prints `/`. Navigation produces the expected virtual path. | Nishant |
| `ls` | Print `d -> .`, `d -> ..`, and one line per entry using `d -> <name>` or `f -> <name>`. Admin's `/` lists user directories. | An empty personal directory, a mixed directory, a regular user's root, the admin root, and a shared file. | Nishant |
| `cat <filename>` | Check read access and display decrypted contents. A missing file prints `<filename> doesn't exist`. | Owner, recipient, admin, unrelated user, empty file, and tampered ciphertext. | Nishant + Mike |
| `mkdir <directory_name>` | Create a virtual directory in an authorized writable location (owner `/personal`, including admin's own). An existing directory prints `Directory already exists`. Writes in `/`, `/shared`, or another user's tree print `Forbidden`. | Nested personal directories, admin own-tree create, admin foreign-tree `Forbidden`, duplicate directory, root write, shared write, and file/directory name collision. | Nishant + Mike |
| `mkfile <filename> <contents>` | Create or replace file contents in an authorized writable location (owner `/personal`, including admin's own). Preserve printable ASCII contents, including spaces. An overwrite retains the stable file ID and updates every existing share so recipients see the new contents. There is no password change, keyfile reissue, or `unshare`. | New, empty-content policy, overwrite, multiword contents, admin own-tree write, admin foreign-tree `Forbidden`, persistence after restart, and shared update visible to recipient. | Nishant + KG |
| `share <filename> <username>` | Check the file first. A missing file prints `File <filename> doesn't exist`. Then check the recipient, printing `User <username> doesn't exist` when absent. Create a read-only reference under the recipient's `/shared`. Only the owner may share; recipients and admin-outside-own-tree must be refused. | Both arguments missing, valid share, admin own-file share, repeated share, collision, unauthorized share, denied re-share, and owner update visible to recipient. | Mike |
| `adduser <username>` | Admin enrolls the account, creates `<username>_keyfile` on the host, and creates that user's personal/shared roots. Duplicate enrollment prints `User <username> already exists`. | Two distinct users, duplicate name, failure during commit, simultaneous enrollment, and non-admin request. Confirm the non-admin error text at D7. | Shahruj + KG |
| `exit` and malformed commands | End the shell on `exit`. Invalid commands print `Invalid Command`. | Unknown command, missing arguments, excess arguments, empty line, and end of input. Preserve all text after the filename for `mkfile`. | Shahruj |

Admin starts at `/`. It is also a regular user: its own `/personal` and `/shared` support the full user feature set, including `mkdir`, `mkfile`, and `share` of admin-owned files. Admin may also traverse and read every other user through `/<username>/personal` and `/<username>/shared` with `cd`, `pwd`, `ls`, and `cat`. Creating, modifying, or sharing inside any other user's directories returns `Forbidden`. Every regular user's virtual root has exactly `/personal` and `/shared`. Directory operations inside `/shared` inherit its read-only behavior. Only the owner of a personal file may share it; a recipient must not re-share. The shell returns `Invalid Command` for a non-admin `adduser`, following KG's proposed command policy.

**Representation and storage contract**

Use a tree of directory entries in memory. A directory maps entry names to child directories or stable file IDs. Each user has personal and shared roots. A shared entry references an existing file ID and records the recipient's read grant. The global file table owns the file's storage version and access information, which keeps owner and recipient views consistent.

| Record | Fields to agree in the shared schema | Constraint |
| --- | --- | --- |
| Account | Stable account ID, username, role, registered signing public key, registered encryption public key, root references | Role and key bindings come from authenticated enrollment. |
| Directory | Stable directory ID, owner ID, named child entries | Every entry name is unique inside its directory. |
| File | Stable file ID, owner ID, current blob version, content authenticator, grants, wrapped DEKs | Overwriting changes the blob version while keeping the file ID. |
| Share | Recipient ID, display name, source file ID, read permission | One grant per file/recipient pair. |
| Session | Authenticated identity, role, virtual current directory, access to the user's private encryption operation | Secret key material has clear ownership and gets cleared after use. |
| Commit state | Index `generation` inside the authenticated index, plus a generation pin (a counter, no key material) in the owner-only state directory. The metadata key is derived from the compiled-in master key and a per-object salt, never stored. | An older valid metadata snapshot is rejected when its generation is below the pin (best effort; see `Code/SCHEMA.md` section 8). |

Use random 128-bit IDs encoded as 32 hexadecimal characters for new objects, and handle the unlikely creation collision without overwriting an existing object. Filesystem operations use those validated IDs when calling storage.

The logical host layout has `filesystem/` in the launch directory, `public_keys/` beside the executable, and private `<username>_keyfile` credentials on the host. Within `filesystem/`, keep encrypted metadata and a flat `blobs/` object directory. Virtual `mkdir` changes encrypted metadata. Opaque blob names conceal the virtual names and directory structure. Confidentiality covers more than file contents: someone browsing `filesystem/` must not learn file or directory names, who owns what, or who shared what with whom. Anyone can modify, copy, or move host files, so use authenticated encryption and bind each ciphertext to its owner and location so copied or edited files and metadata cannot grant access. File counts, ciphertext lengths, and host timestamps may still be observable; the design report must describe that residual leakage.

A proposed security refinement is to name public-key files with opaque account IDs or public-key fingerprints, as the current implementation does. KG's proposed `<username>.pub` names would reveal usernames. Keep username bindings in authenticated encrypted metadata and private credentials.

`index.enc` is the filesystem index. It is replaced by one atomic rename, which is the commit point, and carries a generation counter for rollback detection (`Code/SCHEMA.md` sections 4 and 8). The existing `filesystem/accounts.<version>` registry stays a separate object (D8).

**Authentication and encryption contract**

Use `accounts::login()` and `accounts::add_user()` as the authentication entry points while extending the authenticated session for filesystem access. Keyfiles hold a format header and two seeds. OpenSSL derives the account's signing and encryption keypairs from those seeds.

Keep signing and encryption keypairs separate. Retrieve a recipient's encryption public key from authenticated enrollment when wrapping a DEK. The readable public-key copies support publication, while the enrolled record establishes identity. Keep the global metadata / filesystem master key as an internal secret compiled into the binary (or use per-user envelope encryption where a keyfile only unlocks keys that user is authorized to access). Never store that global key on disk, never place it in user keyfiles, and never derive it from usernames, paths, or public keys. The design report must explain the chosen master-key versus per-user-key approach. The current local implementation runs logical users under one Linux account.

Give every file a random 256-bit DEK. Wrap it separately for its owner, the admin, and each shared recipient. Persist the wrapped copies. Plain DEKs can exist in controlled memory while an operation runs. Every encryption write uses the selected library's authenticated encryption API with a nonce that is unique for its key.

Use OpenSSL EVP for Ed25519 signatures, X25519 private/public key operations, and AES-256-GCM authenticated encryption. KG must specify the complete file-key wrapping construction, including key derivation and identity binding. Ed25519 supplies signatures and X25519 supplies key agreement. [OpenSSL Ed25519 documentation](https://docs.openssl.org/3.0/man7/EVP_SIGNATURE-ED25519/), [OpenSSL X25519 documentation](https://docs.openssl.org/3.0/man7/EVP_PKEY-X25519/), [OpenSSL AES documentation](https://docs.openssl.org/3.0/man7/EVP_CIPHER-AES/)

The authentication registry uses version 3 state containing an 8-byte header and the current 12-byte nonce. Each registry save derives its AES key with HKDF-SHA256 using the compiled-in master key, a fresh salt, and `bibifi/accounts/v3`. The object includes the salt, nonce, tag, and ciphertext. The tag binds the registry to the installation name, and the selected nonce rejects replacing the object alone with an older snapshot. See `Code/SCHEMA.md` sections 3 and 4.

Bind encrypted data to its object ID, format version, and current authorized version through authenticated metadata or authenticated associated data. Because a reader with a DEK can generate ciphertext and authentication tags, a separate protected manifest must identify the owner-authorized current ciphertext. Mike defines this verification requirement and KG implements it.

**Permissions and path contract**

Mike owns a shared permission policy that Nishant invokes during traversal and immediately before each operation. Regular owners may read, write, and share their own personal files. Recipients may read their shared references but must not re-share them. Admin may read all files, enroll users, and use full regular-user write/share powers inside admin's own `/personal` tree. Admin `mkdir`, `mkfile`, and `share` outside that tree return `Forbidden`. Regular-user root and shared directory writes also return `Forbidden`. Confirm recipient re-sharing errors through D6.

Resolve every path within the session's virtual tree. Process `.` and `..` in order, clamping navigation at the virtual root. Commit a new current directory only after the entire `cd` succeeds. A path such as `missing/../personal` fails when `missing` is encountered. A host path, symbolic link, or file ID supplied by a command must never become an unrestricted storage path.

Parse command words while preserving the remainder of a `mkfile` command as contents. The command shell owns the exact course-required output strings. Filesystem, permission, crypto, and storage functions return structured success or error information for that shell to format.

**Mutation and recovery contract**

KG owns one mutation protocol used by account creation, directory creation, file replacement, and sharing. Hold the installation lock across loading the current version, checking permissions, changing state, and committing. Each concurrent shell must reload the current state under that lock before a mutation.

Prepare new encrypted objects and metadata under fresh names, flush completed writes, then atomically publish one protected commit record selecting the new state. For file replacement, prepare a new blob version while keeping the old version available until the metadata commit succeeds. Account enrollment and its personal/shared roots become visible together. A share reference, its grant, and its wrapped DEK become visible together. Remove superseded objects after a successful commit.

Replacing a single file through a temporary file and rename provides only that file's atomic replacement. The storage protocol also needs an explicit recovery rule for interruptions between multiple file writes, along with directory synchronization where crash durability requires it. Test interrupted writes, out-of-space errors, stale metadata, and concurrent commands. Recovery selects a complete committed version and identifies abandoned prepared files for safe cleanup.

**Component handoffs**

The following contracts define responsibilities. Agree the exact C++ signatures at the schema handoff before parallel implementation.

| Operation or boundary | Input and result | Owner |
| --- | --- | --- |
| `login(keyfile)` | Host credential path to authenticated session, or login failure | Shahruj |
| `add_user(session, username)` | Admin identity and name to committed enrollment plus user roots | Shahruj, using KG's transaction boundary |
| `shell::parse_command(line)` and `shell::run(session, input, output, handler)` | Parse every course command, preserve `mkfile` contents, enforce shell-level admin policy, and dispatch filesystem requests through `shell::FilesystemHandler`. A handler returns `shell::Result` for the shell to format. | Shahruj |
| `resolve_path(session, path)` | Virtual path to authorized directory or entry reference, or an error | Nishant, calling Mike's traversal policy |
| `pwd`, `ls`, `cat`, `mkdir`, `mkfile` | Session and parsed operands to virtual filesystem results | Nishant |
| `check_access(session, operation, target)` | Authenticated session and resolved target to a permission decision | Mike |
| `share_file(session, file, recipient)` | Valid source and recipient to an atomic grant and reference | Mike |
| `load_metadata`, `commit_mutation`, `ensure_user_roots` | Installation lock to the validated index, or a prepared index and blob changes to a new committed generation. Declared in `Code/storage.h`. | KG |
| `encrypt`, `decrypt`, `wrap_key`, `unwrap_key` | Validated bytes, key context, and identity binding to authenticated crypto results | KG |
| Object reads and writes | Validated opaque IDs and encrypted bytes to storage results | KG |

**Proposed work allocation**

| Person | Main deliverables | Suggested owned files | Completion evidence |
| --- | --- | --- | --- |
| Shahruj | Extend existing auth and session handling. Implement command parsing, required messages, and available-command listing. Integrate account creation with user-root creation. Coordinate the static build and final CLI walkthrough. | Existing `accounts.h`, `accounts.cpp`, and `main.cpp`, plus a command-shell module when extracted | Valid and invalid login, role enforcement, duplicate enrollment, parser tests, existing keyfile compatibility, and a reproducible static build command. |
| Nishant | Define the shared tree model with input from all owners. Implement the virtual working directory, path traversal, `pwd`, `ls`, `cat`, `mkdir`, and `mkfile`. Call Mike's policy and KG's storage boundary. | Shared model header, virtual-filesystem module, and path-resolver module | Command acceptance cases, failed `cd` preservation, traversal confinement, file/directory collisions, and persistence through KG's interface. |
| KG | Implement OpenSSL AES-256-GCM for filesystem data, metadata serialization, encrypted object format, recipient wrapping, storage limits, locking, and crash-consistent commits. Integrate with Shahruj's authentication boundary. | Crypto-store module and format/serialization definitions | Encryption round trips, wrong-key and tamper rejection, nonce handling, wrapped-key tests, rollback tests, interrupted-save recovery, and static dependency verification. |
| Mike | Define and implement permission checks and sharing. Cover recipient read access, owner-only mutation and share, denied re-sharing, admin dual-role (own-tree writes vs other-user read-only), duplicate shares, collisions, and recipient-visible updates. Coordinate security integration checks. | Permission-policy module, sharing module, and its verification cases | Cross-user access denied, writes through `/shared` denied, admin own-tree mutations allowed, admin foreign-tree mutations `Forbidden`, valid admin reads, key-substitution rejection, same-file update visibility, and duplicate/collision tests. |

Nishant owns the virtual-filesystem entry points and calls Mike's permission and sharing helpers. Mike implements those helpers in separate files. KG owns serialization and storage formats. Shahruj owns the command grammar and user-visible messages. Each owner writes their component's verification cases and a short explanation of its attack defenses for the final report.

Pair reviews are Shahruj with KG for authentication and key custody, and Nishant with Mike for traversal and permissions. All four review the combined sharing update flow.

**Implementation order and integration gates**

| Gate | Work that must be agreed or demonstrated | Lead | Work unlocked |
| --- | --- | --- | --- |
| 0 | Apply confirmed D1-D5 (libraries, admin dual role, master-key / internal-secret rules), resolve remaining D6-D7 (D8 is confirmed by the schema freeze), freeze shared record fields and interface signatures (`Code/fs_schema.h`, `Code/storage.h`, `Code/crypto_store.h`, with `Code/vfs_interfaces.h` awaiting Nishant and Mike), and verify existing-data compatibility. Any library outside the Piazza allowlist still needs a private teaching-team post. | All four | Shared headers and real persistence formats. Owners can draft isolated algorithm tests while decisions are pending. |
| 1 | Auth returns the agreed session, the model can represent user roots, and crypto/storage can save and reload an encrypted empty instance. | Shahruj + Nishant + KG | Basic filesystem command integration. |
| 2 | An ordinary user can navigate, create directories/files, read them, restart, and see the same state. Denied writes and invalid paths produce the defined outcomes. | Nishant + Mike | Full sharing and admin traversal integration. |
| 3 | Sharing wraps the DEK for the recipient, prevents mutation through shared entries and re-sharing, and reflects owner updates. Admin can read each user and can mutate only inside admin's own `/personal` tree. | Mike + KG | Combined security and recovery walkthrough. |
| 4 | Concurrent mutations, corrupted objects, stale snapshots, failed saves, and existing credential compatibility pass their cases. | KG + Shahruj | Release packaging. |
| 5 | A fresh Ubuntu environment builds the static binary, initializes a new instance, and passes the complete command walkthrough. Each owner contributes design-defense notes. | Shahruj, reviewed by all four | Final submission. |

Package the final deliverables as `BIBIFI_Buildit_Group_N/Code/` and `BIBIFI_Buildit_Group_N/Report/BIBIFI_Buildit_Group_N.pdf`, then create `BIBIFI_Buildit_Group_N.zip`. Keep generated private credentials and test runtime data outside the submitted source history. The team also needs its weekly progress record and the required teaching-team repository access.
