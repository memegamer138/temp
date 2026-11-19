# BIBIFI test evidence

Overall result **PASS**

Source commit `ec8d571d1d7b95becd7ee086284444a7b8cc2276`

Environment Ubuntu 24.04.5 LTS, kernel 6.6.87.2-microsoft-standard-WSL2

Started 2026-11-09T19:51:10.183425+00:00

Finished 2026-11-09T19:52:06.629061+00:00

Binary SHA-256 `fbbaf31b4a44a09d6679dddd1a1d78fb35a0fd490f5df5a4fac77e39d430e889`

Each stress case used a fresh temporary installation and generated its own accounts and files.

| Check | Result | Seconds | Evidence |
| --- | --- | --- | --- |
| build | PASS | 4.14 | [build.log](build.log) |
| automated-tests | PASS | 20.814 | [automated-tests.log](automated-tests.log) |
| static-binary | PASS | 0.006 | [static-binary.log](static-binary.log) |
| test_concurrent_writers | PASS | 4.837 | [test_concurrent_writers.log](test_concurrent_writers.log) |
| test_file_size_boundary | PASS | 0.264 | [test_file_size_boundary.log](test_file_size_boundary.log) |
| test_file_spam | PASS | 19.914 | [test_file_spam.log](test_file_spam.log) |
| test_invalid_command_spam | PASS | 0.158 | [test_invalid_command_spam.log](test_invalid_command_spam.log) |
| test_name_length_boundary | PASS | 0.194 | [test_name_length_boundary.log](test_name_length_boundary.log) |
| test_repeated_overwrite | PASS | 7.421 | [test_repeated_overwrite.log](test_repeated_overwrite.log) |
| test_repeated_share | PASS | 0.329 | [test_repeated_share.log](test_repeated_share.log) |

## Measured cases

- test_concurrent_writers: `{"concurrent_processes": 4, "final_shared_contents": "writer-3-update-9", "unique_files_verified": 100, "writes_to_shared_file": 40}`
- test_file_size_boundary: `{"accepted_bytes": 1048576, "index_preserved_on_rejection": true, "rejected_bytes": 1048577}`
- test_file_spam: `{"files_created_and_verified": 300, "other_user_read": "passed"}`
- test_invalid_command_spam: `{"index_preserved": true, "invalid_commands": 500, "subsequent_valid_commands": "passed"}`
- test_name_length_boundary: `{"accepted_name_length": 64, "rejected_name_length": 65}`
- test_repeated_overwrite: `{"blobs_after": 1, "blobs_before": 1, "latest_version": 499, "overwrites": 500}`
- test_repeated_share: `{"blob_count": 1, "index_before_and_after_sha256": "c6ecbf1ab3a561ee8dcf7aa6bcb1e604e20f92605fdf826d0db2e4da5533b1ef", "repeated_shares": 500, "shared_entries": 1}`

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
