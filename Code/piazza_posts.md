# Title: BIBIFI Build it: approved libraries, master keys, and admin permissions
## Body:
Hi all,

A group asked some BIBIFI questions whose answers affect everyone. Here they are for all groups:

1. Approved libraries

    You can use these for the functionality listed without asking:
        C++17 standard library (including std::filesystem) approved for anything
        OpenSSL approved for Cryptography
        libsodium approved for Cryptography (encryption, signatures, hashing/key derivation, secure random numbers, secure-memory helpers)
        nlohmann/json approved for JSON parsing and serialization

    For anything else, make a private Piazza post to the instructors first, with a link to the code and the functionality you need.
    Don’t implement cryptographic primitives yourselves.
    Your submission must be a standalone static executable, so make sure your libraries link statically on the lab Ubuntu image.


2. Master keys and internal secrets.

    The spec says only the private keyfiles are secret, everything else on the host is accessible to all users, and internal secrets are safe.
    A key held inside your program (e.g., compiled into it) counts as an internal secret. Extracting it from your source or binary is not a Break it finding.
    A key stored anywhere on disk, placed in users’ keyfiles, or derived from public information (usernames, public keys, paths) is not an internal secret. Recovering it is a valid weak-cryptography finding.
    Confidentiality covers more than file contents. Someone browsing "filesystem/" must not learn file or directory names, who owns what, or who shared what with whom.
    Anyone can modify, copy, or move files on disk. Use authenticated encryption and tie each ciphertext to its owner and location, so copied or edited files and metadata can’t grant access.
    A single master key and per-user keys are both acceptable designs. Explain your choice in the design report.


3. Admin permissions.

    The admin is also a regular user, with its own "/personal" and "/shared", and has all user features there, including sharing its own files.
    The admin can read every user’s files (cd, ls, cat, pwd), but can’t create, modify, or share files in other users’ directories. Only the owner can share a file, which is also why a user can’t re-share a file shared with them (FAQ #2). Refuse these, e.g. by printing "Forbidden".


If your design already relies on a different assumption, please send us a private post.

Best,
Mohsen

## Comment 1:
Hello Professor,

just quick question 

How should we handle encryption-key management when a user changes their password or when access to a shared file is revoked?

### Answer to comment 1:
Hi Nishant,

Neither of these is part of the spec, so you don’t need to handle them:

Password changes: there are no passwords. Users log in with their keyfile, and there’s no command to change or reissue it.
Revoking access: there’s no unshare command. Once a file is shared it stays shared. The only update you need to support is mkfile on a shared file: the recipient must see the new contents.

Please don’t add extra commands for these. The spec asks you to keep the architecture simple, and every extra feature is more code for other groups to attack in Break it. If your design would make either one hard to add later, you can mention it as a limitation in your design report.

## Comment 2:
Hello Mosen,

I need some clarification. I see conflicting instructions: On one hand, FAQ #4 implies that admin is strictly read-only on the filesystem; it cannot create/modify files. On the other hand, in this post you say that admin is also a regular user: own /personal + /shared, full user features there (including share); read-only on other users’ trees.

What approach should prevail?

Thanks in advance for your response.

### Answer to comment 2:
Hi Kevin,

You’re right, they differ. Please follow the rule in this post: the admin is read-only in other users’ directories and has all user features in its own /personal and /shared.

If your admin follows FAQ #4 and is read-only in its own directories too, that’s fine as well. We won’t count it as an issue.

# Title: BIBIFI Build-it: Storage threat model, POSIX APIs, and concurrent sessions (Group 5)
## Body:
Hi Mohsen and Mohammad,

our current design stores accounts, public-key bindings, file contents, filenames, ownership, and sharing grants together in filesystem/auth.enc. It uses libsodium authenticated encryption with a program-held master key, following the internal-secret clarification. The program decrypts and validates the snapshot in memory, then saves updates by writing an encrypted temporary file and renaming it over auth.enc.

Could you clarify:

    Can attackers directly modify the storage? Should we assume they can edit, delete, replace, or restore an older copy of auth.enc, including while the server is running? Can they also rename the filesystem directory or replace it with a symlink? Or may we assume the storage file and directory are protected from direct modification?
    What protection is expected against destructive changes? Modified ciphertext is rejected, but deletion or replacement with invalid data can make the filesystem unavailable. Is detecting corruption and refusing to continue sufficient, or must we also preserve availability/recover the data? Is detecting rollback to an older, valid encrypted snapshot required?
    Are Linux/POSIX filesystem APIs permitted? If host storage can be attacker-controlled, we’d like to use APIs such as openat, fstat, renameat, and unlinkat, with flags such as O_NOFOLLOW and O_EXCL. These would let us operate relative to an opened directory and reduce symlink/path-replacement races that separate std::filesystem checks cannot prevent.

    We have been working on the assumption that only one active fileserver session per filesystem is required at a time. Multiple users would access the same persistent filesystem sequentially, and additional sessions would be rejected while one is active. Is this assumption correct?

## Comment 1:
Hello,

Storage modification: Yes, attackers can do all.

Required protection: Well, detecting corrupted or unauthenticated storage and a fail-safe feature should be part of your implementation, considering that you are developing secure software. Recovery is not expected.

POSIX APIs: Yes, the listed Linux/POSIX APIs and flags are permitted for secure filesystem operations.

Concurrency: Yes. One active session per filesystem is sufficient.

Your system must correctly implement all specified functionality. Missing or incorrect functionality will be penalized. During Break-It, attackers may use any approach permitted by the project’s scope to demonstrate a functional or security flaw.

# Title: Group 4 - Concurrency Requirements
## Body:
Hi,

We wanted to clarify the concurrency assumptions for the BIBIFI, as they affect our storage architecture.

1. Single executable instance: Can we assume that only one instance of "fileserver" will be running at a time, or should our implementation support multiple users running separate instances simultaneously?

2. Single session per user: If multiple instances can run concurrently, can we at least assume that each user will have only one active session at a time? For example, Alice and Bob could each run "fileserver" simultaneously, but Alice would not run two instances using the same keyfile.

We are considering a single encrypted JSON file for the entire filesystem under the first assumption, or separate encrypted JSON files per user under the second.

## Comment 1:
Hello,


You may assume that only one file server instance runs at a time. The filesystem must support multiple registered users, but simultaneous sessions are not required. 

# Title: BIBIFI Group 6: are POSIX system calls allowed?
## Body:
Hi,

Are POSIX/Linux system calls (for example flock(), open(), chmod()) allowed in BIBIFI, or should we stick to the C++17 standard library only?

We’d use flock() only to lock our encrypted store file during each command, so two shells running at the same time don’t overwrite each other’s changes:
https://man7.org/linux/man-pages/man2/flock.2.html

Thank you!
Group 6

## Comment 1:
Hi,

You are allowed. Note that other external libraries or code remain subject to the stated approval process ...

# Title: Clarifications
## Body:
Dear instruction team

    Can our unit tests involve other libraries? We have a test suite that partially uses python
    Is there a prescribed tool for build, or any one we want? Must the lab machines support both test and build, in addition to the executable?
    When A is sharing files to B, should A be able to share multiple files of the same name, but from different folders? eg /personal/file.txt and /personal/folder/file.txt
    During Break-It phase, if we are unsure if something is a bug or is permitted by the spec, can we still ask the instruction team? Or should we first report the issue?

Thank you

## Comment 1:
Hello,

1- Yes
2- Your project should be built and run on the latest version of Ubuntu that SFU Labs supports. "Currently, Ubuntu 24.04 is running on CSIL Linux physical workstations, CSIL CPU servers, and CSIL VDI."
3- You may choose how to handle name collisions: either keep both files distinguishable or reject the second share with a clear error message. Do not overwrite an existing shared file, and document your approach.

4- Either approach is fine. You may ask the TA for clarification or report the issue directly. The TA will review your reports, and the evaluated team may submit a dispute.