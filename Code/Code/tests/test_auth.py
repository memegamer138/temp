"""Integration checks for OpenSSL login, registry updates, and the command shell."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import resource
import shutil
import signal
import stat
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
STATE = Path.home() / ".bibifi-state"


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="bibifi-build-")
        cls.executable = Path(cls.build.name) / "fileserver"
        common = ["g++", "-std=c++17", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                  "-static", "-ICode", "-ICode/third_party"]
        sources = ["Code/accounts.cpp", "Code/command_shell.cpp", "Code/vfs.cpp",
                   "Code/fs_schema.cpp", "Code/storage.cpp", "Code/crypto_store.cpp"]
        objects = []
        for source in sources:
            obj = Path(cls.build.name) / (Path(source).stem + ".o")
            subprocess.run(common + ["-c", source, "-o", str(obj)], cwd=REPO,
                           capture_output=True, check=True)
            objects.append(str(obj))
        for entry, executable in [
                ("Code/main.cpp", cls.executable),
                ("Code/tests/shell_test.cpp", Path(cls.build.name) / "shell_test"),
                ("Code/tests/vfs_security_test.cpp", Path(cls.build.name) / "vfs_security_test")]:
            subprocess.run(common + [entry] + objects + ["-lcrypto", "-ldl", "-pthread",
                           "-o", str(executable)], cwd=REPO, capture_output=True, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="bibifi-auth-")
        self.root = Path(self.temporary.name).resolve()
        shutil.copy2(self.executable, self.root / "fileserver")
        raw_path = os.fsencode(self.root)
        self.installation_name = "openssl-" + hashlib.sha256(raw_path).hexdigest()
        self.state_files = [STATE / self.installation_name,
                            STATE / (self.installation_name + ".lock"),
                            STATE / (self.installation_name + ".fs")]
        self.assertFalse(any(path.exists() for path in self.state_files))

    def tearDown(self):
        for path in self.state_files:
            path.unlink(missing_ok=True)
        self.temporary.cleanup()

    def run_server(self, key="admin_keyfile", commands="exit\n"):
        return subprocess.run(["./fileserver", str(key)], cwd=self.root, input=commands,
                              text=True, capture_output=True, timeout=10)

    def assert_login(self, result, username):
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertTrue(result.stdout.startswith(f"Logged in as {username}\n"), result.stdout)

    def assert_invalid(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "Invalid keyfile\n")

    def test_login_permissions_and_identity(self):
        self.assert_invalid(self.run_server("missing_keyfile"))
        self.assertFalse((self.root / "filesystem").exists())
        self.assert_login(self.run_server(commands="adduser alice\nexit\n"), "admin")
        alice = self.root / "alice_keyfile"
        self.assertEqual(stat.S_IMODE(alice.stat().st_mode), 0o600)
        renamed = self.root / "renamed_keyfile"
        alice.rename(renamed)
        self.assert_login(self.run_server(renamed), "alice")
        denied = self.run_server(renamed, "adduser bob\nexit\n")
        self.assertIn("Invalid Command\n", denied.stdout)
        self.assertFalse((self.root / "bob_keyfile").exists())

        forged = self.root / "forged_keyfile"
        shutil.copy2(renamed, forged)
        content = bytearray(forged.read_bytes())
        content[8] ^= 1
        forged.write_bytes(content)
        self.assert_invalid(self.run_server(forged))
        renamed.chmod(0o644)
        self.assert_invalid(self.run_server(renamed))
        renamed.chmod(0o600)
        (self.root / "link_keyfile").symlink_to(renamed)
        self.assert_invalid(self.run_server("link_keyfile"))
        os.mkfifo(self.root / "pipe_keyfile", 0o600)
        self.assert_invalid(self.run_server("pipe_keyfile"))
        for public in (self.root / "public_keys").glob("*.pub"):
            public.write_bytes(bytes(64))
        self.assert_login(self.run_server(renamed), "alice")

    def test_atomic_enrollment_and_concurrent_writers(self):
        self.assert_login(self.run_server(), "admin")
        blocked = self.root / "alice_keyfile"
        blocked.write_bytes(b"keep")
        self.assertIn("Could not create user\n", self.run_server(commands="adduser alice\nexit\n").stdout)
        self.assertEqual(blocked.read_bytes(), b"keep")
        blocked.unlink()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda name: self.run_server(
                commands=f"adduser {name}\nexit\n"), ["alice", "bob", "carol", "carol"]))
        self.assertEqual(sum("User carol already exists\n" in result.stdout for result in results), 1)
        self.assertTrue(all("Could not create user" not in result.stdout for result in results))
        for name in ("alice", "bob", "carol"):
            self.assert_login(self.run_server(f"{name}_keyfile"), name)

    def test_failed_initialization_can_be_retried(self):
        # Fail once before the bootstrap index lands, then during admin roots.
        for limit in (80, 256):
            with self.subTest(file_size_limit=limit), tempfile.TemporaryDirectory(dir=self.root) as folder:
                root = Path(folder).resolve()
                shutil.copy2(self.executable, root / "fileserver")
                name = "openssl-" + hashlib.sha256(os.fsencode(root)).hexdigest()
                state = STATE / name
                index_state = STATE / (name + ".fs")
                self.state_files.extend([state, index_state, STATE / (name + ".lock")])

                def fail_writes():
                    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
                    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

                failed = subprocess.run(["./fileserver", "admin_keyfile"], cwd=root, input="exit\n",
                                        text=True, capture_output=True, timeout=10, preexec_fn=fail_writes)
                self.assert_invalid(failed)
                self.assertFalse((root / "admin_keyfile").exists())
                self.assertFalse((root / "filesystem").exists())
                self.assertFalse(state.exists())
                self.assertFalse(index_state.exists())
                self.assertEqual(list((root / "public_keys").iterdir()), [])

                retry = subprocess.run(["./fileserver", "admin_keyfile"], cwd=root,
                                       input="adduser alice\nexit\n", text=True, capture_output=True, timeout=10)
                self.assert_login(retry, "admin")
                self.assertNotIn("Could not create user", retry.stdout)
                alice = subprocess.run(["./fileserver", "alice_keyfile"], cwd=root,
                                       input="pwd\nls\nexit\n", text=True, capture_output=True, timeout=10)
                self.assert_login(alice, "alice")
                self.assertTrue(alice.stdout.endswith("/\nd -> .\nd -> ..\nd -> personal\nd -> shared\n"))

    def test_initialization_preserves_existing_data(self):
        keyfile = self.root / "admin_keyfile"
        keyfile.write_bytes(b"existing credential")
        self.assert_invalid(self.run_server())
        self.assertEqual(keyfile.read_bytes(), b"existing credential")
        self.assertFalse((self.root / "filesystem").exists())
        keyfile.unlink()

        filesystem = self.root / "filesystem"
        filesystem.mkdir()
        sentinel = filesystem / "index.enc"
        sentinel.write_bytes(b"existing filesystem")
        self.assert_invalid(self.run_server())
        self.assertEqual(sentinel.read_bytes(), b"existing filesystem")
        self.assertFalse(keyfile.exists())

    def test_reserved_names_preserve_admin(self):
        self.assert_login(self.run_server(), "admin")
        keyfile = (self.root / "admin_keyfile").read_bytes()
        registry = next((self.root / "filesystem").glob("accounts.*")).read_bytes()
        index = (self.root / "filesystem/index.enc").read_bytes()
        result = self.run_server(commands="adduser admin\nadduser personal\nadduser shared\nexit\n")
        self.assert_login(result, "admin")
        self.assertTrue(result.stdout.endswith("User admin already exists\nInvalid Command\nInvalid Command\n"))
        self.assertEqual((self.root / "admin_keyfile").read_bytes(), keyfile)
        self.assertEqual(next((self.root / "filesystem").glob("accounts.*")).read_bytes(), registry)
        self.assertEqual((self.root / "filesystem/index.enc").read_bytes(), index)
        self.assertFalse((self.root / "personal_keyfile").exists())
        self.assertFalse((self.root / "shared_keyfile").exists())
        self.assert_login(self.run_server(), "admin")

    def test_registry_tampering_and_rollback(self):
        self.assert_login(self.run_server(), "admin")
        old = next((self.root / "filesystem").glob("accounts.*")).read_bytes()
        self.assert_login(self.run_server(commands="adduser alice\nexit\n"), "admin")
        current = next((self.root / "filesystem").glob("accounts.*"))
        encrypted = current.read_bytes()
        self.assertEqual(encrypted[:8], b"BIBIFIR\x01")
        nonce = encrypted[40:52]
        self.assertEqual(self.state_files[0].read_bytes(), b"BIBIFIS\x03" + nonce)
        self.assertEqual(current.name, "accounts." + nonce.hex())
        for offset in (8, 52, 68):  # Salt, tag, and ciphertext.
            damaged = bytearray(encrypted)
            damaged[offset] ^= 1
            current.write_bytes(damaged)
            self.assert_invalid(self.run_server())
        current.write_bytes(old)
        self.assert_invalid(self.run_server())
        current.write_bytes(encrypted)
        self.assert_login(self.run_server("alice_keyfile"), "alice")

    def test_registry_and_version_pin_cannot_move_to_another_installation(self):
        self.assert_login(self.run_server(), "admin")
        foreign = self.root / "foreign"
        foreign.mkdir()
        foreign_name = "openssl-" + hashlib.sha256(os.fsencode(foreign)).hexdigest()
        foreign_state = STATE / foreign_name
        self.state_files.extend([foreign_state, STATE / (foreign_name + ".lock"), STATE / (foreign_name + ".fs")])
        result = subprocess.run([str(self.root / "fileserver"), "admin_keyfile"], cwd=foreign,
                                input="exit\n", text=True, capture_output=True, timeout=10)
        self.assert_login(result, "admin")

        foreign_registry = next((foreign / "filesystem").glob("accounts.*"))
        shutil.copy2(foreign_registry, self.root / "filesystem" / foreign_registry.name)
        shutil.copy2(foreign_state, self.state_files[0])
        self.assert_invalid(self.run_server(foreign / "admin_keyfile"))

    def test_shell_handoff_and_static_build(self):
        subprocess.run([str(Path(self.build.name) / "shell_test")], check=True, timeout=10)
        dynamic = subprocess.check_output(["readelf", "-d", str(self.executable)], text=True)
        self.assertNotIn("(NEEDED)", dynamic)
        denied = self.run_server(commands="mkdir d\nmkfile f hello\nshare f alice\nexit\n")
        self.assert_login(denied, "admin")
        self.assertIn("Forbidden\nForbidden\nFile f doesn't exist\n", denied.stdout)


if __name__ == "__main__":
    unittest.main()
