# BIBIFI test evidence

Overall result **PASS**

Source commit `5707694f035c36a0046b2dee945a21123c19a35b`

Environment Ubuntu 24.04.5 LTS, kernel 6.6.87.2-microsoft-standard-WSL2

Started 2026-11-11T05:49:09.586165+00:00

Finished 2026-11-11T05:51:00.911705+00:00

Binary SHA-256 `fbbaf31b4a44a09d6679dddd1a1d78fb35a0fd490f5df5a4fac77e39d430e889`

Each stress case used a fresh temporary installation and generated its own accounts and files.

| Check | Result | Seconds | Evidence |
| --- | --- | --- | --- |
| build | PASS | 17.557 | [build.log](build.log) |
| automated-tests | PASS | 55.894 | [automated-tests.log](automated-tests.log) |
| static-binary | PASS | 0.024 | [static-binary.log](static-binary.log) |
| test_concurrent_writers | PASS | 5.071 | [test_concurrent_writers.log](test_concurrent_writers.log) |
| test_file_size_boundary | PASS | 0.352 | [test_file_size_boundary.log](test_file_size_boundary.log) |
| test_file_spam | PASS | 19.332 | [test_file_spam.log](test_file_spam.log) |
| test_invalid_command_spam | PASS | 0.222 | [test_invalid_command_spam.log](test_invalid_command_spam.log) |
| test_name_length_boundary | PASS | 0.265 | [test_name_length_boundary.log](test_name_length_boundary.log) |
| test_repeated_overwrite | PASS | 8.178 | [test_repeated_overwrite.log](test_repeated_overwrite.log) |
| test_repeated_share | PASS | 0.413 | [test_repeated_share.log](test_repeated_share.log) |

## Measured cases

- test_concurrent_writers: `{"concurrent_processes": 4, "final_shared_contents": "writer-1-update-9", "unique_files_verified": 100, "writes_to_shared_file": 40}`
- test_file_size_boundary: `{"accepted_bytes": 1048576, "index_preserved_on_rejection": true, "rejected_bytes": 1048577}`
- test_file_spam: `{"files_created_and_verified": 300, "other_user_read": "passed"}`
- test_invalid_command_spam: `{"index_preserved": true, "invalid_commands": 500, "subsequent_valid_commands": "passed"}`
- test_name_length_boundary: `{"accepted_name_length": 64, "rejected_name_length": 65}`
- test_repeated_overwrite: `{"blobs_after": 1, "blobs_before": 1, "latest_version": 499, "overwrites": 500}`
- test_repeated_share: `{"blob_count": 1, "index_before_and_after_sha256": "05d27ba589e84967e5d5c8241fc1ee33e3ec51714bbd4239f759fb3e07a9ee3d", "repeated_shares": 500, "shared_entries": 1}`

## Reproduction

From the repository root on Ubuntu

```bash
python3 Code/tests/stress_test.py --evidence-dir Report/TestEvidence/new-run
```

The JSON records exact source, binary, test-script hashes, and outcomes. Per-case folders contain
CLI inputs, outputs, exit codes, timings, and SHA-256 hashes of complete input/output streams.
Streams over 20,000 characters use a labelled preview in the log.

## Scope

These are bounded functional and stress tests. Disk exhaustion, power loss, and
unbounded resource consumption were outside this run. The app has no per-user storage quota.
