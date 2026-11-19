# BIBIFI shared schema and interface freeze (issue #2)

Status: **KG half frozen, tree/session half bootstrap only.** This file is the source of truth for the on-disk format and the KG-owned C++ interfaces. The matching headers are:

| Header | Content | Owner | Status |
| --- | --- | --- | --- |
| `fs_schema.h` | Record types, ID rules, index limits, invariants | KG (records), ngh2 (tree semantics) | Frozen for KG records; tree records are bootstrap |
| `crypto_store.h` | Object envelopes, AAD, DEK, key wrapping signatures | KG | Frozen (bodies arrive in #3 and #4) |
| `storage.h` | Lock, load, commit, blob I/O, enrollment boundary | KG | Frozen (bodies arrive in #3) |
| `vfs_interfaces.h` | `resolve_path`, name rules, command execution, permission and share hooks | ngh2 (VFS), Mike (permissions, share) | **Stubs, not frozen** |

Nothing here changes the behavior of `./fileserver` yet.

Precedence used: `BIBIFI_instructions.md`, then `CMPT 785 BIBIFI FAQs.pdf`, then `piazza_post.txt`, then `IMPLEMENTATION_SPEC.md` and `resolution_conflicting_instructions.md`. Four documented exceptions follow.

## 1. Policy decisions (FAQ vs Piazza)

Piazza post 25 (19 October 2026) is the current-semester clarification. Where an older FAQ answer contradicts it, Piazza wins. The team accepted these four calls.

| Topic | Older FAQ | Decision (Piazza and instructions) | Security difference |
| --- | --- | --- | --- |
| Admin | FAQ #4: admin is read-only | Admin is also a regular user. Full user features inside admin's own `/personal`. Read-only (`cd`, `ls`, `cat`, `pwd`) on every other user. `mkdir`, `mkfile`, `share` outside admin's own `/personal` print `Forbidden`. | Small |
| Master key | FAQ #11: store anything in the keyfile | The filesystem master key (FMK) is compiled into the binary. It is never in a keyfile, never on disk outside the binary, and never derived from usernames, paths, or public keys. A keyfile holds only that account's own seeds. | Large |
| Host layout | FAQ #7: host `mkdir` is allowed | One encrypted index plus flat, randomly named encrypted blobs. No host directory or file name reflects a virtual name, owner, depth, or share. | Large |
| Libraries | Instructions: STL only | C++17 standard library (including `std::filesystem`), OpenSSL, libsodium, and nlohmann/json need no further approval. Static link. No home-made crypto primitives. | Process only |

Also locked: no passwords, no keyfile reissue, no `unshare`, no `rm`/`rmdir`/`mv`. The only update that must propagate to a recipient is `mkfile` on a shared file. Only the owner can share, so a recipient cannot re-share.

## 2. Host layout

```text
<launch directory>/
  admin_keyfile, <username>_keyfile      private credentials (existing, issue #1)
  filesystem/
    accounts.<hex>                       existing encrypted account registry (issue #1)
    index.enc                            encrypted metadata index (new)
    blobs/<blob_id>.enc                  encrypted file contents, flat (new)
    index.<random>.tmp, blobs/<id>.tmp   staging files, never trusted
<directory of the fileserver binary>/
  public_keys/<hex of signing key>.pub   existing public keys (issue #1)
```

- `blob_id` is 32 lowercase hexadecimal characters from a CSPRNG. Names reveal nothing about contents, owners, or structure. Counts, sizes, and timestamps remain observable (see section 11).
- Virtual `mkdir` never calls host `mkdir`. The virtual tree lives only inside `index.enc`.
- Writes use a staging file, `fsync`, then `std::filesystem::rename` (or `renameat`). `index.enc` is replaced by a single atomic rename, which is the commit point.

### Separate account registry and filesystem index (decision D8)

The account registry and the filesystem index are separate encrypted objects joined by **username**.

- The registry (issue #1) is authoritative for identity and public keys. Login never depends on the index.
- The index holds the filesystem identity of each account: a stable `account_id`, role, and the two root directories.
- The index never stores public keys. Wrapping asks the registry for a recipient's X25519 key through `storage::AccountDirectory`, so a replaced index cannot substitute a key.

## 3. Secrets and keys

| Key | Where it lives | Purpose |
| --- | --- | --- |
| FMK (32 bytes) | Compiled into `crypto_store.cpp`. Never exposed through a header. | Root for index and registry encryption keys |
| Index key | Derived per write: `HKDF-SHA256(ikm = FMK, salt = random 32 bytes in the object, info = "bibifi/fs/index/v1")` | AES-256-GCM key for one index version |
| Registry key | Derived per write: `HKDF-SHA256(ikm = FMK, salt = random 32 bytes in the object, info = "bibifi/accounts/v3")` | AES-256-GCM key for one registry version |
| DEK (32 bytes) | Random per file. Persisted only wrapped, once per authorized account. | Root for blob keys of that file |
| Blob key | Derived per write: `HKDF-SHA256(ikm = DEK, salt = random 32 bytes in the object, info = "bibifi/fs/blob/v1")` | AES-256-GCM key for one blob version |
| Account X25519 and Ed25519 keys | Derived from the account's keyfile seeds (issue #1) | Unwrap DEKs, log in |

Why two layers: an attacker who extracts the FMK from the binary can read the index (names, tree, owners, shares) but still cannot read file contents without an account's private key. File contents depend only on the wrapped DEKs, and a DEK is wrapped only for the owner, the admin, and recipients.

Every encrypted object uses a fresh derived key and a fresh random 12-byte nonce, so no (key, nonce) pair repeats even when a DEK encrypts many versions.

### Registry version state (#9)

`~/.bibifi-state/openssl-<cwd-sha256>` holds the 8-byte marker `BIBIFIS` + `0x03` followed by the 12-byte nonce selecting the current `filesystem/accounts.<nonce-hex>` object. The registry's salt lives in the object. Its derived AES key lives in memory. The fileserver saves the new object before atomically replacing the version selector. A registry-only rollback fails the nonce check. Restoring both a genuine earlier object and its selector at the same location can replay that version. Legacy v2 installations fail closed and retain their original files.

The installation id is 32 random bytes drawn once by `initialize_empty`. It is not the FMK, it is not stored in `index.enc`, and it is not derived from a username, a path, or a public key. The existing cwd hash only selects which state file is used.

## 4. Object formats

Registry, index, and blob objects use the same envelope layout.

```text
offset  size  field
0       8     header: 'B' 'I' 'B' 'I' 'F' 'I' <type> 0x01   (type 'I' index, 'B' blob, 'R' registry)
8       32    salt            (random, input to HKDF)
40      12    nonce           (random)
52      16    tag             (AES-GCM)
68      n     ciphertext
```

`open_*` checks the header, the minimum length of 68 bytes, and the per-type size limit before decrypting, and it releases plaintext only after the tag verifies. Any failure returns "not authentic" without detail.

### Associated data (AAD)

- Index: the bytes `FILESYSTEM_INDEX_V1`, then one NUL, then the 32 raw installation-id bytes, then the absolute install path (`crypto_store::index_aad`). `seal_index` and `open_index` take the id and the path as arguments. Neither is stored in the index plaintext or the `.fs` file, and neither is recovered from the ciphertext. The path is authenticated data, not a key.
- Blob: `FILESYSTEM_BLOB_V1`, then for each of `blob_id`, `owner_id`, `file_id` a NUL byte followed by the 32 hexadecimal characters, then a NUL byte and the 4-byte big-endian `blob_version`. All IDs have a fixed width, so the encoding is unambiguous.
- Registry: `openssl-` followed by the lowercase SHA-256 hex digest of the absolute launch directory. A registry copied with its selector to a different launch directory fails authentication.

Binding the index to the installation id and the absolute install path means copying `index.enc` alone, or copying it together with the `.fs` file, fails the tag check. The id is read from the per-install state file (section 8). The path is the process's current directory and does not travel in either file. Replacing every writable file inside one install can still roll that install back.

Binding the blob to `{blob_id, owner_id, file_id, blob_version}` means copying a blob over another blob name, to another owner, or to another version fails the tag check. `owner_id` is the owner's stable account ID, which is one-to-one with the owner username in the index.

### Content authenticator

A reader with a DEK can mint valid ciphertext, so the index also records the `blob_sha256` of the complete blob file. The index itself is protected by the FMK key, so a recipient cannot change it. `read_blob` rejects a blob whose SHA-256 differs from the index.

### Wrapped DEK envelope (details finalized and implemented in issue #4)

Frozen layout (93 bytes): `version 0x01 | ephemeral X25519 public key (32) | nonce (12) | tag (16) | wrapped DEK (32)`. Construction: ephemeral X25519 agreement with the recipient's registered encryption key, HKDF-SHA256 over the shared secret with `info = "bibifi/fs/dek-wrap/v1" | recipient public key | ephemeral public key | file_id | recipient_id`, then AES-256-GCM over the DEK with AAD `file_id | recipient_id | grant kind`. A low-order peer public key (RFC 7748) or an all-zero shared secret makes `wrap_key` throw and `unwrap_key` return `std::nullopt`. Issue #4 may refine the KDF inputs but must keep the envelope size and the `wrap_key` / `unwrap_key` signatures.

## 5. Records

Defined in `fs_schema.h`. IDs are 128-bit random values encoded as 32 lowercase hexadecimal characters. Creation never overwrites: on a collision the creator draws a new ID. Each table in `FsIndex` is keyed by ID, so a record's `id` is its table key and is not repeated inside the record.

| Record | Fields | Notes |
| --- | --- | --- |
| Account (`AccountEntry`) | `id`, `username`, `role`, `personal_dir_id`, `shared_dir_id` | No keys. Username is the join key to the registry. |
| Directory (`Directory`) | `id`, `owner_id`, `entries` (name to `Entry`) | Entry names unique per directory. Bootstrap, ngh2 owns semantics. |
| Entry (`Entry`) | `kind` (`directory`, `file`, `shared_file`), `target_id` | `shared_file` is the **shared reference**: it points at a file owned by someone else. |
| File (`FileRecord`) | `id`, `owner_id`, `blob_id`, `blob_version`, `size`, `blob_sha256`, `grants` | `id` is stable. `blob_id` and `blob_version` change on every overwrite. |
| Grant (`Grant`) | `account_id`, `kind` (`owner`, `admin`, `recipient`), `wrapped_dek` | One per file and account. A recipient grant is a share. Read-only is implicit: the schema has no write grant. |
| Wrapped DEK (`WrappedDek`) | `envelope` (93 bytes) | Opaque to everyone except `crypto_store`. |
| Index (`FsIndex`) | `format`, `generation`, `accounts`, `directories`, `files` | The decrypted plaintext of `index.enc`. |

### Invariants (checked by `validate_index` before any decrypted index is used)

1. Every ID is 32 lowercase hexadecimal characters and unique within its table.
2. Either the index is a bootstrap index, or it is operational. A bootstrap index has the current format version, `generation >= 1`, and empty `accounts`, `directories`, and `files` (`schema::is_bootstrap_index`). It is the only empty index that is valid. An operational index has unique usernames and exactly one account with role `admin` and username `admin`. Invariants 3 through 7 apply to an operational index. A bootstrap index has no records for them to check.
3. Every account's `personal_dir_id` and `shared_dir_id` exist, are owned by that account, and are not referenced from any other directory.
4. A directory owned by account A is referenced by at most one entry.
5. A `file` entry points at a file whose owner is the directory owner. A `shared_file` entry lives only in a `shared` directory and points at a file with a `recipient` grant for that directory's owner.
6. Each file has exactly one `owner` grant. It has one `admin` grant unless the owner is the admin. It has at most one grant per account.
7. `blob_version` starts at 1 and only increases. `blob_sha256` is 64 hex characters.
8. The serialized index is at most 16 MiB. `generation` only increases.

`validate_index` accepts a bootstrap index. Every other index that fails an invariant is corrupt (`Error::corrupt`), including a generation of 0, an empty index that still holds a file or directory, and an index with accounts but no admin. The caller fails closed and never repairs it silently. The function itself is implemented in issue #3.

### Serialization

`nlohmann::json` serializes `FsIndex` before encryption. Maps are keyed by ID, so output order is deterministic.

```json
{
  "format": 1,
  "generation": 7,
  "accounts": {
    "<account_id>": {"username": "alice", "role": "user",
                      "personal": "<dir_id>", "shared": "<dir_id>"}
  },
  "directories": {
    "<dir_id>": {"owner": "<account_id>",
                  "entries": {"notes": {"kind": "file", "id": "<file_id>"}}}
  },
  "files": {
    "<file_id>": {"owner": "<account_id>", "blob": "<blob_id>", "version": 3,
                   "size": 42, "blob_sha256": "<64 hex>",
                   "grants": [{"account": "<account_id>", "kind": "owner",
                                "wrapped": "<hex of 93 bytes>"}]}
  }
}
```

JSON parsing rejects unknown top-level fields, duplicate keys, and wrong types. `parse_index` returns `std::nullopt` instead of throwing out of the storage layer.

## 6. Virtual tree model

- A regular user's root `/` is **synthesized**, never stored. It lists exactly `personal` and `shared`. Nothing can be created in `/`.
- The admin's root `/` is synthesized as `personal`, `shared`, and one directory `<username>` per **enrolled** user. `/<username>` lists that user's `personal` and `shared`. `adduser` must reject the usernames `personal`, `shared`, and `admin`, so a username never collides with an admin root entry (change in `accounts::valid_username` or `add_user`, owned by Shahruj in issue #9).
- `/shared` and everything below it is read-only for everyone. Only `adduser` and `share` populate it, through the storage mutation protocol.
- Admin write permission applies only below admin's own `/personal`.
- The current directory stays `accounts::Session::current_directory` (a vector of virtual names). `Session` is **not changed** by issue #2.

## 7. Cryptographic operations (all approved)

| Need | Operation | Library call |
| --- | --- | --- |
| Authenticated encryption | AES-256-GCM, 12-byte random nonce, 16-byte tag | OpenSSL `EVP_aes_256_gcm` |
| Key derivation | HKDF-SHA256 | OpenSSL `EVP_KDF` ("HKDF") |
| Key agreement | X25519 | OpenSSL `EVP_PKEY_derive` |
| Hash | SHA-256 | OpenSSL `EVP_Digest` |
| Random | IDs, DEKs, salts, nonces | OpenSSL `RAND_bytes` |
| Authentication | Ed25519 | OpenSSL `EVP_DigestSign` (issue #1, unchanged) |
| JSON | Index plaintext | nlohmann/json |
| Files | Rename, directory handling | `std::filesystem` and POSIX calls |

libsodium is approved but unused, to keep one crypto library in the static link.

## 8. Storage protocol (implemented in issue #3)

1. **Lock.** Every filesystem command takes the installation lock (an exclusive `flock`) for its whole duration: load, check, mutate, commit, release. Reads lock too, so a writer cannot delete a blob mid-read. The shell does not hold the lock while it waits for input.
2. **Load.** `load_metadata` reads the installation id from the per-install state file (never from `index.enc`) and passes it to `open_index`. It then parses, runs `validate_index`, and compares `generation` with the pin. A missing installation id when an index exists fails closed. If the loaded generation is higher than the pin, the pin is raised to that generation before the call returns. A lower generation returns `rolled_back`.
3. **Commit.** `commit_mutation` receives the next index, the new encrypted blobs, and the blob IDs to retire. Under the lock it re-checks that the stored generation equals `expected_generation`, reads the installation id from the state file, and seals the next index with that id. It writes each new blob to `blobs/<id>.tmp`, `fsync`s, renames it to `blobs/<id>.enc`, `fsync`s `blobs/`, writes `index.<random>.tmp` with `generation + 1`, and `fsync`s. The rename over `index.enc` is the commit point. `Result::committed` stays false until that rename succeeds, and any failure before it leaves the previous index current so the caller may retry. After the rename, `committed` is true even if the directory `fsync`, the pin update, or retired-blob deletion fails. That failure returns `error == io` and is not `ok()`. The caller must reload and must not retry with the old `expected_generation`. A fully successful commit returns `error == none` with `committed` true.
4. **Overwrite.** `mkfile` on an existing file keeps `file_id` and the DEK, picks a new `blob_id`, increments `blob_version`, and replaces the index entry. The old blob stays until the commit succeeds. Recipients read the same `file_id`, so they see the new contents with no re-wrapping.
5. **Recovery.** A crash before the index rename leaves unreferenced `blobs/*.enc` and `*.tmp` files. The next locked `load_metadata` deletes staging files and blobs that the loaded index does not reference. A crash after the rename leaves only retired blobs, removed the same way. A pin that is behind the loaded generation is caught up during that load (item 2). The rename is not rolled back.
6. **Missing or bad index.** First run calls `initialize_empty` before the registry commit, so the bootstrap index exists before the registry does. If the registry exists but `index.enc` does not, or the index fails authentication, loading returns `missing_index`, `not_authentic`, or `corrupt`. The server fails closed. It never silently re-creates the index.
7. **Rollback pin and installation id.** Both live in `~/.bibifi-state/openssl-<cwd-sha256>.fs` (mode 0600), beside the account-registry file that issue #1 owns. Issue #3 does not write that registry file. The VFS integration replaces `accounts.cpp`'s private lock with `storage::InstallationLock` on `openssl-<cwd-sha256>.lock` and calls `initialize_empty` before the registry commit. The pin is the generation of the last committed index. It holds a counter, not a key. The installation id is 32 random bytes drawn once by `initialize_empty`. It is not derived from a username, a path, or a public key. The cwd hash only selects these file names. `load_metadata` rejects an index whose generation is lower than the pin, and raises the pin when the loaded generation is higher. This is best-effort: an attacker who can alter both the index and the state file can still roll back, or transplant an index by copying the state file with it, because the threat model gives no trusted storage. Document this limitation in the design report.

Concurrent shells serialize on the lock and always reload the current index before checking permissions.

Issue #3 implements this protocol and these tests. They are not part of issue #2.

- Copy `index.enc` from one install of this binary onto another, without copying the state file, and show that `open_index` rejects it.
- First launch: `initialize_empty`, then `ensure_user_roots` for `admin`, then a successful admin login. The bootstrap index must pass `validate_index` before admin is added.
- Inject a failure after the index rename and show `committed == true` with `error == io`. Recovery is a reload, not a retry of the old `expected_generation`.

## 9. Atomic enrollment boundary (`adduser`)

Goal: a user is never loginable without personal and shared roots, and a failure leaves nothing exposed.

Order, all under one `storage::InstallationLock`:

1. `accounts` generates the new keys in memory (nothing written yet).
2. `storage::ensure_user_roots(lock, username, role)` loads the index (a bootstrap index on first launch, otherwise an operational one), adds an `AccountEntry` with fresh personal and shared directories (or **adopts** an existing entry with that username and no registry enrollment), and commits one new index generation.
3. `accounts` writes the keyfile and public key and commits the registry. This is the moment the user becomes visible (login works, the admin root lists them). Login does not read the index.
4. If step 3 fails, the index entry is **inert**: the registry does not list the user, so login fails, every command treats the name as unknown, and the admin root omits it. A repeated `adduser` adopts the leftover entry.

First launch, under the same lock, is `initialize_empty` and then this sequence for `admin`. `initialize_empty` draws the installation id and writes a bootstrap index at generation 1 with no accounts. `ensure_user_roots` loads that index, adds the admin account and both roots, and commits the next generation. The registry commit is still the moment login works.

`ensure_user_roots` is idempotent. If a registry already exists and `index.enc` does not, loading returns `missing_index` and does not recreate the index.

`accounts.cpp` and VFS now share `storage::InstallationLock`. Taking a second `flock` on another descriptor of the same file would deadlock the process, so registry snapshots require the caller's existing lock.

## 10. VFS rules (#5–#8)

The VFS implementation adopts the rules below. The current implementation spec's admin dual-role policy takes precedence over older issue descriptions.

| Topic | Proposal |
| --- | --- |
| Entry names (`mkdir`, `mkfile`) | 1 to 64 characters from `A-Z a-z 0-9 . _ -`. `.` and `..` are rejected as new names. No separators, spaces, or NUL. Extensions such as `notes.txt` are allowed. |
| Usernames | `accounts::valid_username` rejects `personal` and `shared`. `admin` is reserved for the bootstrapped administrator, is valid when loading the registry, and cannot be enrolled a second time. `adduser admin` returns `User admin already exists`, as required for duplicate enrollment. Other names follow the existing syntax rules. |
| File contents | Printable ASCII, 0 to 1 MiB. Empty contents are allowed. |
| Name collision on `mkdir` | `Directory already exists` when the name is a directory. A name already used by a file is also rejected with the same message (no other message is specified). |
| `mkfile` over a directory | `Forbidden`. |
| `mkfile` on a shared reference | `Forbidden` (read-only). |
| Shared display name | The file's own name. If taken in the recipient's `/shared`, use `<name>@<owner username>`. If that is taken too, use `<name>@<owner username>-<first 8 hex of file_id>`. If the eight-character prefix also collides, append `-<full file_id>`. `@` is outside the user name whitelist, so a generated name can never collide with a user-created name. |
| Repeated share (same file, same recipient) | Idempotent success, no second grant. |
| Re-share by a recipient, share by non-owner, admin share outside admin's own tree | `Forbidden`. |
| `share` of a directory | `File <name> doesn't exist` (only files are shareable). |
| `share` to oneself | `Forbidden`. |
| Missing file before missing user | As in the instructions: check the file first. |
| Storage failure | The shell prints its existing `Could not complete command` text for `storage_error`. |

## 11. Residual leakage and limitations (for the design report)

- Observable on the host: number of blobs, ciphertext sizes (contents length plus 68 bytes), the index size, and file timestamps. No padding is added.
- An attacker who extracts the compiled-in FMK can read all metadata but not file contents.
- Rollback to an older authentic index is detected only through the pin (section 8).
- Copying `index.enc` alone onto another install of this binary fails the tag check, because the installation id in the AAD is not inside the index. Copying the state file as well can still transplant an index. That is the same limitation as the generation pin.
- Password or keyfile reissue and share revocation are out of scope (Piazza follow-up). The schema would need a new grant lifecycle and re-wrapping to add them later.

## 12. Out of scope for issue #2

AES blob I/O and index persistence (issue #3, including the three tests in section 8), the wrapping implementation (issue #4), path resolution (issue #5), permissions (issue #6), command bodies (issue #7), share flow (issue #8), account integration (issue #9), shell wiring (issue #10).

## VFS integration (#5–#8)

`Code/vfs.cpp` implements path traversal, the shared permission policy, filesystem
commands, and sharing. `main.cpp` connects the handler. `accounts.cpp` exposes an
authenticated registry snapshot under the caller's storage lock and creates user
roots before publishing enrollment.
Admin writes are authorized by the VFS for admin's own personal tree. A share to
admin reuses its existing admin grant; shared-entry validation accepts that grant
as well as a recipient grant. No duplicate envelope is needed.
