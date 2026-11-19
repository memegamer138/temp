"""Run bounded CLI stress tests and write reviewable evidence in a chosen folder.

Run on Ubuntu from the repository root:
    python3 Code/tests/stress_test.py --evidence-dir Report/TestEvidence/<run-name>
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import platform
import subprocess
import sys
import time
import unittest

import test_auth


REPO = Path(__file__).resolve().parents[2]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def transcript(text):
    """Keep large-input logs readable while retaining their full-stream hash."""
    encoded = text.encode()
    header = f"{len(encoded)} bytes; SHA-256 {digest(encoded)}\n"
    if len(text) > 20000:
        return header + text[:4000] + "\n[preview truncated]\n"
    return header + text


class StressTests(unittest.TestCase):
    def setUp(self):
        test_auth.AuthenticationTests.setUp(self)
        self.addCleanup(test_auth.AuthenticationTests.tearDown, self)
        self.logs = self.evidence / self._testMethodName
        self.logs.mkdir()
        self.metrics = {}
        self.run_cli("provision", "admin", ["adduser alice", "adduser bob"], "")
        self.run_cli("baseline", "alice", [
            "mkfile /personal/keep.txt baseline-data",
            "share /personal/keep.txt bob",
        ], "")

    def run_cli(self, label, user, commands, expected=None):
        payload = "\n".join(commands + ["exit"]) + "\n"
        log = self.logs / (label + ".log")
        log.write_text(f"User {user}\nINPUT\n{transcript(payload)}\n", encoding="utf-8")
        started = time.monotonic()
        result = subprocess.run(["./fileserver", f"{user}_keyfile"], cwd=self.root,
                                input=payload, text=True, capture_output=True, timeout=180)
        with log.open("a", encoding="utf-8") as stream:
            stream.write(f"\nElapsed {time.monotonic() - started:.3f} seconds\n")
            stream.write(f"Exit code {result.returncode}\n")
            stream.write(f"\nSTDOUT\n{transcript(result.stdout)}\n")
            stream.write(f"\nSTDERR\n{transcript(result.stderr)}\n")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout[:2000])
        self.assertEqual(result.stderr, "")
        self.assertTrue(result.stdout.startswith(f"Logged in as {user}\n"), result.stdout[:2000])
        _, separator, output = result.stdout.partition("exit\n")
        self.assertTrue(separator, "Missing command menu")
        if expected is not None:
            self.assertEqual(output, expected)
        return output

    def index_hash(self):
        return digest((self.root / "filesystem/index.enc").read_bytes())

    def blobs(self):
        return list((self.root / "filesystem/blobs").iterdir())

    def test_file_spam(self):
        count = 300
        commands = ["mkdir /personal/spam", "cd /personal/spam"]
        commands += [f"mkfile file_{i:04d}.txt contents-{i}" for i in range(count)]
        self.run_cli("create-files", "alice", commands, "")
        expected = "d -> .\nd -> ..\n" + "".join(f"f -> file_{i:04d}.txt\n" for i in range(count))
        self.run_cli("list-after-reopen", "alice", ["cd /personal/spam", "ls"], expected)
        self.run_cli("read-every-file", "alice",
                     [f"cat /personal/spam/file_{i:04d}.txt" for i in range(count)],
                     "".join(f"contents-{i}\n" for i in range(count)))
        self.run_cli("other-user", "bob", ["cat /shared/keep.txt"], "baseline-data\n")
        self.metrics = {"files_created_and_verified": count, "other_user_read": "passed"}

    def test_repeated_share(self):
        before = self.index_hash()
        blob_count = len(self.blobs())
        self.run_cli("share-500-times", "alice", ["share /personal/keep.txt bob"] * 500, "")
        self.assertEqual(self.index_hash(), before, "Repeated shares changed the authenticated index")
        self.assertEqual(len(self.blobs()), blob_count)
        self.run_cli("recipient-list", "bob", ["cd /shared", "ls"], "d -> .\nd -> ..\nf -> keep.txt\n")
        self.run_cli("recipient-read", "bob", ["cat /shared/keep.txt"], "baseline-data\n")
        self.metrics = {"repeated_shares": 500, "index_before_and_after_sha256": before,
                        "shared_entries": 1, "blob_count": blob_count}

    def test_repeated_overwrite(self):
        count = 500
        blob_count = len(self.blobs())
        self.run_cli("overwrite-500-times", "alice",
                     [f"mkfile /personal/keep.txt version-{i}" for i in range(count)], "")
        self.run_cli("owner-read", "alice", ["cat /personal/keep.txt"], f"version-{count - 1}\n")
        self.run_cli("recipient-read", "bob", ["cat /shared/keep.txt"], f"version-{count - 1}\n")
        self.assertEqual(len(self.blobs()), blob_count, "Superseded blobs or staging files remain")
        self.metrics = {"overwrites": count, "latest_version": count - 1,
                        "blobs_before": blob_count, "blobs_after": len(self.blobs())}

    def test_concurrent_writers(self):
        workers, per_worker = 4, 25
        self.run_cli("create-directory", "alice", ["mkdir /personal/concurrent"], "")

        def write(worker):
            commands = [f"mkfile /personal/concurrent/w{worker}_{i:03d}.txt worker-{worker}-value-{i}"
                        for i in range(per_worker)]
            commands += [f"mkfile /personal/keep.txt writer-{worker}-update-{i}" for i in range(10)]
            self.run_cli(f"writer-{worker}", "alice", commands, "")

        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(write, range(workers)))
        self.run_cli("verify-every-write", "alice",
                     [f"cat /personal/concurrent/w{worker}_{i:03d}.txt"
                      for worker in range(workers) for i in range(per_worker)],
                     "".join(f"worker-{worker}-value-{i}\n"
                             for worker in range(workers) for i in range(per_worker)))
        latest = self.run_cli("owner-final-value", "alice", ["cat /personal/keep.txt"])
        self.assertIn(latest, {f"writer-{worker}-update-9\n" for worker in range(workers)})
        self.run_cli("recipient-final-value", "bob", ["cat /shared/keep.txt"], latest)
        self.assertEqual(len(self.blobs()), workers * per_worker + 1)
        self.metrics = {"concurrent_processes": workers, "unique_files_verified": workers * per_worker,
                        "writes_to_shared_file": workers * 10, "final_shared_contents": latest.strip()}

    def test_file_size_boundary(self):
        limit = 1024 * 1024
        contents = "A" * limit
        self.run_cli("write-exact-limit", "alice", ["mkfile /personal/large.txt " + contents], "")
        self.run_cli("read-exact-limit", "alice", ["cat /personal/large.txt"], contents + "\n")
        before = self.index_hash()
        self.run_cli("reject-over-limit", "alice", ["mkfile /personal/large.txt " + contents + "B"], "Forbidden\n")
        self.assertEqual(self.index_hash(), before, "Rejected oversized write changed metadata")
        self.run_cli("preserved-contents", "alice", ["cat /personal/large.txt"], contents + "\n")
        self.run_cli("other-user", "bob", ["cat /shared/keep.txt"], "baseline-data\n")
        self.metrics = {"accepted_bytes": limit, "rejected_bytes": limit + 1,
                        "index_preserved_on_rejection": True}

    def test_name_length_boundary(self):
        valid_file, invalid_file = "a" * 64, "b" * 65
        valid_dir, invalid_dir = "c" * 64, "d" * 65
        self.run_cli("valid-names", "alice", [f"mkfile /personal/{valid_file} valid-name",
                                               f"mkdir /personal/{valid_dir}"], "")
        before = self.index_hash()
        self.run_cli("invalid-names", "alice", [f"mkfile /personal/{invalid_file} rejected",
                                                 f"mkdir /personal/{invalid_dir}"], "Forbidden\nForbidden\n")
        self.assertEqual(self.index_hash(), before)
        self.run_cli("verify-valid-names", "alice", [f"cat /personal/{valid_file}",
                                                      f"cd /personal/{valid_dir}", "pwd"],
                     f"valid-name\n/personal/{valid_dir}\n")
        self.metrics = {"accepted_name_length": 64, "rejected_name_length": 65}

    def test_invalid_command_spam(self):
        malformed = ["unknown", "cd", "share keep.txt", "pwd extra", "exit extra", "ls extra", "mkfile"]
        count = 500
        commands = [malformed[i % len(malformed)] for i in range(count)]
        before = self.index_hash()
        self.run_cli("invalid-500-times", "alice", commands + ["pwd", "cat /personal/keep.txt"],
                     "Invalid Command\n" * count + "/\nbaseline-data\n")
        self.assertEqual(self.index_hash(), before)
        self.run_cli("other-user", "bob", ["cat /shared/keep.txt"], "baseline-data\n")
        self.metrics = {"invalid_commands": count, "subsequent_valid_commands": "passed",
                        "index_preserved": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--commit", help="Source commit when running from a git archive")
    args = parser.parse_args()
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    if (evidence / "results.json").exists():
        parser.error("Choose a new evidence directory for each run")
    commit = args.commit or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    metadata = {"source_commit": commit, "started_utc": datetime.now(timezone.utc).isoformat(),
                "os": platform.freedesktop_os_release().get("PRETTY_NAME"),
                "kernel": platform.release(), "python": platform.python_version(),
                "test_script_sha256": digest(Path(__file__).read_bytes())}
    records = []
    for label, command in [("build", ["make", "-j2"]), ("automated-tests", ["make", "test"]),
                           ("static-binary", ["readelf", "-d", "fileserver"])]:
        print(f"Running {label}", flush=True)
        started = time.monotonic()
        with (evidence / (label + ".log")).open("w", encoding="utf-8") as stream:
            result = subprocess.run(command, cwd=REPO, stdout=stream, stderr=subprocess.STDOUT, timeout=300)
        records.append({"name": label, "command": command, "passed": result.returncode == 0,
                        "exit_code": result.returncode, "seconds": round(time.monotonic() - started, 3)})
        if result.returncode != 0:
            break
    if all(record["passed"] for record in records):
        executable = REPO / "fileserver"
        metadata["binary_sha256"] = digest(executable.read_bytes())
        StressTests.executable = executable
        StressTests.evidence = evidence
        for name in unittest.defaultTestLoader.getTestCaseNames(StressTests):
            print(f"Running {name}", flush=True)
            case = StressTests(name)
            output = io.StringIO()
            started = time.monotonic()
            result = unittest.TextTestRunner(stream=output, verbosity=2).run(unittest.TestSuite([case]))
            (evidence / (name + ".log")).write_text(output.getvalue(), encoding="utf-8")
            record = {"name": name, "passed": result.wasSuccessful(),
                      "seconds": round(time.monotonic() - started, 3),
                      "metrics": getattr(case, "metrics", {}),
                      "failures": [message for _, message in result.failures + result.errors]}
            records.append(record)
            print(f"{'PASS' if record['passed'] else 'FAIL'} {name} ({record['seconds']}s)", flush=True)
    metadata["finished_utc"] = datetime.now(timezone.utc).isoformat()
    passed = all(record["passed"] for record in records)
    (evidence / "results.json").write_text(json.dumps({"environment": metadata, "passed": passed,
                                                       "results": records}, indent=2) + "\n", encoding="utf-8")
    report = ["# BIBIFI test evidence", "", f"Overall result **{'PASS' if passed else 'FAIL'}**", "",
              f"Source commit `{commit}`", "", f"Environment {metadata['os']}, kernel {metadata['kernel']}", "",
              f"Started {metadata['started_utc']}", "", f"Finished {metadata['finished_utc']}", "",
              f"Binary SHA-256 `{metadata.get('binary_sha256', 'build failed')}`", "",
              "Each stress case used a fresh temporary installation and generated its own accounts and files.", "",
              "| Check | Result | Seconds | Evidence |", "| --- | --- | --- | --- |"]
    for record in records:
        name = record["name"]
        report.append(f"| {name} | {'PASS' if record['passed'] else 'FAIL'} | {record['seconds']} | [{name}.log]({name}.log) |")
    report += ["", "## Measured cases", ""]
    for record in records:
        if "metrics" in record:
            report.append(f"- {record['name']}: `{json.dumps(record['metrics'], sort_keys=True)}`")
    report += ["", "## Reproduction", "", "From the repository root on Ubuntu", "", "```bash",
               "python3 Code/tests/stress_test.py --evidence-dir Report/TestEvidence/new-run", "```", "",
               "The JSON records exact source, binary, test-script hashes, and outcomes. Per-case folders contain",
               "CLI inputs, outputs, exit codes, timings, and SHA-256 hashes of complete input/output streams.",
               "Streams over 20,000 characters use a labelled preview in the log.", "",
               "## Scope", "", "These are bounded functional and stress tests. Disk exhaustion, power loss, and",
               "unbounded resource consumption were outside this run. The app has no per-user storage quota.", ""]
    (evidence / "SUMMARY.md").write_text("\n".join(report), encoding="utf-8")
    print(f"Evidence saved to {evidence}", flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
