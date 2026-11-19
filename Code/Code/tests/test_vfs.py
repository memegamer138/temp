"""CLI regression tests for the virtual filesystem, permissions, and live shares."""

import os
from pathlib import Path
import resource
import signal
import subprocess
import unittest

import test_auth


class FilesystemTests(unittest.TestCase):
    # Reuse isolated build/installation helpers without inheriting auth tests.
    setUpClass = classmethod(test_auth.AuthenticationTests.setUpClass.__func__)
    tearDownClass = classmethod(test_auth.AuthenticationTests.tearDownClass.__func__)
    setUp = test_auth.AuthenticationTests.setUp
    tearDown = test_auth.AuthenticationTests.tearDown
    run_server = test_auth.AuthenticationTests.run_server
    assert_login = test_auth.AuthenticationTests.assert_login

    def provision(self):
        self.assert_login(self.run_server(commands="adduser alice\nadduser bob\nadduser carol\nexit\n"), "admin")

    def commands(self, user, text, **kwargs):
        result = subprocess.run(["./fileserver", f"{user}_keyfile"], cwd=self.root,
                                input=text + "\nexit\n", text=True, capture_output=True,
                                timeout=10, **kwargs)
        self.assert_login(result, user)
        self.assertEqual(result.stderr, "")
        # Drop login and advertised commands.
        return result.stdout.split("exit\n", 1)[1]

    def test_paths_and_names(self):
        self.provision()
        self.assertEqual(self.commands("alice", "pwd\nls"),
                         "/\nd -> .\nd -> ..\nd -> personal\nd -> shared\n")
        out = self.commands("alice", "cd /personal\nmkdir a\nmkdir a\ncd a\nmkdir b\n"
                            "cd b/../../a/./b\npwd\ncd missing/../..\npwd\n"
                            "cd ../../../../..\npwd\ncd missing/../personal\npwd\n"
                            "cd /personal\nmkfile f data\ncd f/..\npwd\n"
                            "mkdir f\nmkfile a nope\nmkdir ../escape\nmkdir .\nmkdir ..")
        self.assertEqual(out, "Directory already exists\n/personal/a/b\nmissing/../.. doesn't exist\n"
                         "/personal/a/b\n/\nmissing/../personal doesn't exist\n/\nf/.. doesn't exist\n"
                         "/personal\nDirectory already exists\nForbidden\nForbidden\nForbidden\nForbidden\n")
        self.assertEqual(self.commands("alice", "cd //personal///a/b/\npwd"), "/personal/a/b\n")
        self.assertEqual(self.commands("alice", "cd /personal\nmkfile notes.txt   spaced  \ncat notes.txt\n"
                                       "mkfile empty\ncat empty"), "  spaced  \n\n")
        # Virtual labels and plaintext never become host paths or host data.
        for path in (self.root / "filesystem").rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                self.assertNotIn(b"spaced", data)
                self.assertNotIn(b"notes.txt", data)
        self.assertFalse((self.root / "escape").exists())

    def test_permissions_admin_and_live_updates(self):
        self.provision()
        self.assertEqual(self.commands("alice", "mkdir bad\nmkfile bad data\ncd /shared\nmkdir bad\n"
                                       "mkfile bad data\ncd /bob/personal\ncd /personal\n"
                                       "mkfile secret original\nshare secret bob"),
                         "Forbidden\nForbidden\nForbidden\nForbidden\n/bob/personal doesn't exist\n")
        self.assertEqual(self.commands("bob", "cat /shared/secret\nmkfile /shared/secret changed\n"
                                       "mkdir /shared/child\nshare /shared/secret carol\n"
                                       "cd /alice/personal\ncat /personal/secret"),
                         "original\nForbidden\nForbidden\nForbidden\n/alice/personal doesn't exist\n"
                         "/personal/secret doesn't exist\n")
        self.assertEqual(self.commands("carol", "cat /shared/secret"), "/shared/secret doesn't exist\n")
        self.assertEqual(self.commands("alice", "mkfile /personal/secret updated"), "")
        self.assertEqual(self.commands("bob", "cat /shared/secret"), "updated\n")
        out = self.commands("admin", "cat /alice/personal/secret\ncat /bob/shared/secret\n"
                            "mkfile /alice/personal/secret nope\nmkdir /alice/personal/nope\n"
                            "share /alice/personal/secret carol\nmkdir /personal/own\n"
                            "mkfile /personal/own/file admin-data\nshare /personal/own/file bob")
        self.assertEqual(out, "updated\nupdated\nForbidden\nForbidden\nForbidden\n")
        self.assertEqual(self.commands("bob", "cat /shared/file"), "admin-data\n")
        # Sharing to admin reuses its existing global read envelope.
        self.assertEqual(self.commands("alice", "share /personal/secret admin"), "")
        self.assertEqual(self.commands("admin", "cat /shared/secret"), "updated\n")

    def test_share_errors_idempotence_and_collisions(self):
        self.provision()
        self.assertEqual(self.commands("alice", "share absent nobody\nshare /personal nobody\n"
                                       "mkfile /personal/f one\nshare /personal/f nobody\n"
                                       "share /personal/f alice"),
                         "File absent doesn't exist\nFile /personal doesn't exist\n"
                         "User nobody doesn't exist\nForbidden\n")
        self.assertEqual(self.commands("carol", "mkfile /personal/f carol\nshare /personal/f bob"), "")
        self.assertEqual(self.commands("alice", "share /personal/f bob\nshare /personal/f bob\n"
                                       "mkdir /personal/sub\nmkfile /personal/sub/f two\n"
                                       "share /personal/sub/f bob\nmkdir /personal/other\n"
                                       "mkfile /personal/other/f three\nshare /personal/other/f bob"), "")
        listing = self.commands("bob", "cd /shared\nls").splitlines()[2:]
        self.assertEqual(len(listing), 4)
        self.assertIn("f -> f", listing)
        self.assertIn("f -> f@alice", listing)
        generated = [line[5:] for line in listing if line.startswith("f -> f@alice-")]
        self.assertEqual(len(generated), 2)
        self.assertEqual(self.commands("bob", "cat /shared/f\ncat /shared/f@alice"), "carol\none\n")
        self.assertEqual({self.commands("bob", f"cat /shared/{name}") for name in generated}, {"two\n", "three\n"})

    def test_public_key_substitution_and_ciphertext_tampering(self):
        self.provision()
        # Published keys are never trusted for wrapping or identity lookup.
        for public in (self.root / "public_keys").glob("*.pub"):
            public.write_bytes(bytes(64))
        self.assertEqual(self.commands("alice", "mkfile /personal/f private\nshare /personal/f bob"), "")
        self.assertEqual(self.commands("bob", "cat /shared/f"), "private\n")
        subprocess.run([str(Path(self.build.name) / "vfs_security_test")],
                       cwd=self.root, capture_output=True, check=True, timeout=10)
        blob = next((self.root / "filesystem/blobs").glob("*.enc"))
        original = blob.read_bytes()
        tampered = bytearray(original)
        tampered[-1] ^= 1
        blob.write_bytes(tampered)
        self.assertEqual(self.commands("bob", "cat /shared/f"), "Could not complete command\n")
        self.assertEqual(self.commands("admin", "cat /alice/personal/f"), "Could not complete command\n")
        blob.write_bytes(original)
        self.assertEqual(self.commands("bob", "cat /shared/f"), "private\n")

    def test_overwrite_commit_failure_and_concurrent_commands(self):
        self.provision()
        self.commands("alice", "mkfile /personal/f original\nshare /personal/f bob")
        index = self.root / "filesystem/index.enc"
        before = index.read_bytes()

        def fail_writes():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))

        self.assertEqual(self.commands("alice", "mkfile /personal/f aborted", preexec_fn=fail_writes),
                         "Could not complete command\n")
        self.assertEqual(index.read_bytes(), before)
        self.assertEqual(self.commands("bob", "cat /shared/f"), "original\n")
        env = dict(os.environ, BIBIFI_FAIL_AFTER_RENAME="1")
        self.assertEqual(self.commands("alice", "mkfile /personal/f committed", env=env),
                         "Could not complete command\n")
        self.assertEqual(self.commands("bob", "cat /shared/f"), "committed\n")
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda n: self.commands("alice", f"mkfile /personal/f{n} content{n}"), range(4)))
        self.assertEqual(results, [""] * 4)
        for n in range(4):
            self.assertEqual(self.commands("alice", f"cat /personal/f{n}"), f"content{n}\n")

    def test_share_commit_failures(self):
        self.provision()
        self.commands("alice", "mkfile /personal/f original")
        index = self.root / "filesystem/index.enc"
        before = index.read_bytes()

        def fail_writes():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))

        self.assertEqual(self.commands("alice", "share /personal/f bob", preexec_fn=fail_writes),
                         "Could not complete command\n")
        self.assertEqual(index.read_bytes(), before)
        self.assertEqual(self.commands("bob", "cat /shared/f"), "/shared/f doesn't exist\n")
        env = dict(os.environ, BIBIFI_FAIL_AFTER_RENAME="1")
        self.assertEqual(self.commands("alice", "share /personal/f bob", env=env),
                         "Could not complete command\n")
        self.assertEqual(self.commands("bob", "cat /shared/f"), "original\n")
        self.assertEqual(self.commands("alice", "share /personal/f bob"), "")
        self.assertEqual(self.commands("bob", "cd /shared\nls"), "d -> .\nd -> ..\nf -> f\n")


if __name__ == "__main__":
    unittest.main()
