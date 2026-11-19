# BIBIFI

The [implementation spec and proposed work allocation](IMPLEMENTATION_SPEC.md) records the team requirements, confirmed OpenSSL/admin/process decisions, component handoffs, and acceptance checks. The [shared schema and interface freeze](Code/SCHEMA.md) defines the on-disk format and the storage and crypto interfaces.

## Open Ubuntu

Run this in PowerShell to open Ubuntu 24.04 in the project directory.

```powershell
wsl -d Ubuntu-24.04 --cd /mnt/c/Users/amsha/Documents/Repo/bibifi
```

## Build the fileserver

Install the OpenSSL development package in Ubuntu 24.04, then build from the repo root.

```bash
sudo apt-get install libssl-dev
make
```

The executable uses OpenSSL for Ed25519 login signatures, X25519 account keys, and AES-256-GCM account-registry encryption.

## Create and use keyfiles

Run the first command from the repo root. It creates the admin account on a fresh installation and opens the admin shell. Use a Linux home directory for private keyfiles because the checkout lives on a Windows drive.

```bash
install -d -m 700 ~/.bibifi-keys
./fileserver ~/.bibifi-keys/admin_keyfile
```

In the admin shell, create Alice's account and exit.

```text
adduser alice
exit
```

Back in Ubuntu, log in using Alice's keyfile.

```bash
./fileserver ~/.bibifi-keys/alice_keyfile
```

`adduser` writes new private keyfiles beside the admin keyfile. On a native Linux filesystem, `./fileserver admin_keyfile` also works and puts the keyfiles in the current directory.

The working directory holds `filesystem/` and its encrypted account registry. The executable's directory holds `public_keys/` with the Ed25519 and X25519 public keys. The owner-only `~/.bibifi-state/` directory holds the registry version selector in an `openssl-<path-hash>` file. OpenSSL derives the registry encryption key in memory from the compiled-in master key and the salt in the registry object. This layer uses one Linux account to run the local instance. Keep that state directory and use the same working path to reopen an existing instance.

## Virtual filesystem

The shell supports `cd`, `pwd`, `ls`, `cat`, `mkdir`, `mkfile`, and `share`.
Every account starts at `/` with `/personal` and `/shared`. Create directories
and files under your own `/personal`; shared entries are read-only references.
An owner's `mkfile` overwrite preserves the file ID and updates existing shares.
Only an owner may share. Admin has the same features in its own `/personal`,
and can browse other enrolled users through `/<username>/personal` and
`/<username>/shared`, with read access only outside its own personal tree.

Paths resolve component by component, including `.`, `..`, repeated separators,
and absolute/relative paths. A failed `cd` preserves the working directory.
Entry creation accepts 1–64 characters from letters, digits, `.`, `_`, and `-`,
except exact `.` and `..`. File contents are printable ASCII, including spaces
and empty contents, up to 1 MiB. A shared-name collision uses `name@owner`, then
`name@owner-<first eight file-ID hex characters>`, with the full ID appended if
that prefix also collides. Repeating a share is idempotent. Sharing to oneself
and re-sharing a received file return `Forbidden`.

Filesystem commands hold one installation lock through authenticated account
lookup, metadata load, permission checks, and commit. Enrollment creates roots
before publishing an account; incomplete enrollments remain invisible. Reads
verify the current blob hash in the separately authenticated index before
AEAD decryption. Public-key files are publication copies, never key authority.

The current binary requires a v3 account registry. To try it with a legacy v2
installation present, leave that installation in place. Start the current binary
from a fresh working directory and give it a new `admin_keyfile` path.

## Verify

```bash
make test
```

This runs schema, storage, wrapping, authentication, and VFS tests in temporary
installations. It builds static executables and checks that the fileserver has
no dynamic library dependencies. Tests cover permissions, admin browsing,
sharing collisions and live updates, recipient-generated ciphertext,
public-key substitution, and failures before and after the index commit point.
