# BIBIFI Group 7

This directory contains the static Ubuntu executable, source, build rules, and test evidence.

## Run

Extract the submission on Ubuntu 24.04 x86-64. Run from this directory or copy the executable into a fresh Linux directory.

```bash
chmod +x fileserver
./fileserver admin_keyfile
```

First launch creates the admin credential and encrypted storage. Use a native Linux directory for credentials when working under WSL. Keep the same launch directory and its state in `~/.bibifi-state/` for subsequent sessions.

Inside the admin shell, create users and exit.

```text
adduser alice
adduser bob
exit
```

Then log in as Alice.

```bash
./fileserver alice_keyfile
```

## Build and test

The source retains its original `Code/` subdirectory so the supplied Makefile and tests use their existing paths. Run these commands from this directory.

```bash
sudo apt-get install build-essential libssl-dev python3 binutils
make -j2
make test
readelf -d fileserver
```

Run the seven additional stress cases and collect a new evidence folder.

```bash
python3 Code/tests/stress_test.py --evidence-dir TestEvidence/new-run --commit 5707694f035c36a0046b2dee945a21123c19a35b
```

The package includes source commit `5707694f035c36a0046b2dee945a21123c19a35b` and the test runner from `e5e3892e57a32a2e579b1847c4543672191a3815`. The report identifies the tested executable by SHA-256. Test evidence is under `TestEvidence/`.

## Storage and limits

Registry format v3 derives its key from the compiled-in master secret. Legacy v2 storage is preserved and rejected. Start with a fresh launch directory and new admin keyfile path when testing v3 alongside an older instance.

Accepted file contents are printable ASCII up to 1 MiB. Creation names contain 1 to 64 letters, digits, dots, underscores, or hyphens, excluding exact `.` and `..`. The encrypted metadata index is limited to 16 MiB. Each account has `/personal` and `/shared`. Shared files are read-only references.

OpenSSL supplies cryptography and the bundled nlohmann/json header supplies JSON parsing. OpenSSL license information is in `THIRD_PARTY_NOTICES.txt`, and the JSON license is included in `Code/third_party/nlohmann/json.hpp`. The teaching-team clarifications are recorded in `piazza_posts.md`.
