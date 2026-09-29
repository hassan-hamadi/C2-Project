"""Filesystem confidentiality checks, using disposable files only."""

import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from server.storage_permissions import private_database, private_directory, private_file


@unittest.skipUnless(os.name == "posix", "POSIX permission checks")
class StoragePermissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def mode(self, path):
        return path.stat().st_mode & 0o777

    def test_creation_is_private_with_permissive_umask(self):
        old_umask = os.umask(0)
        self.addCleanup(os.umask, old_umask)
        directory = self.root / "storage"
        private_directory(directory)
        private_file(directory / "data", create=True)
        self.assertEqual(self.mode(directory), 0o700)
        self.assertEqual(self.mode(directory / "data"), 0o600)

    def test_existing_contents_are_preserved_and_permissions_are_idempotent(self):
        directory = self.root / "storage"
        nested = directory / "nested"
        nested.mkdir(parents=True)
        data = nested / "data"
        data.write_bytes(b"keep these exact bytes")
        data.chmod(0o666)
        for _ in range(2):
            private_directory(directory)
            self.assertEqual(self.mode(directory), 0o700)
            self.assertEqual(self.mode(nested), 0o700)
            self.assertEqual(self.mode(data), 0o600)
            self.assertEqual(data.read_bytes(), b"keep these exact bytes")

    def test_build_storage_retains_only_owner_execute(self):
        executable = self.root / "executable"
        executable.write_bytes(b"fixture")
        executable.chmod(0o755)
        data = self.root / "data"
        data.write_bytes(b"fixture")
        data.chmod(0o644)
        private_directory(self.root, preserve_execute=True)
        self.assertEqual(self.mode(executable), 0o700)
        self.assertEqual(self.mode(data), 0o600)

    def test_symlinks_are_rejected_without_changing_the_target(self):
        target = self.root / "target"
        target.write_bytes(b"untouched")
        target.chmod(0o644)
        directory = self.root / "storage"
        directory.mkdir()
        link = directory / "link"
        link.symlink_to(target)
        with self.assertRaises(OSError):
            private_file(link, create=True)
        with self.assertRaises(OSError):
            private_directory(directory)
        self.assertEqual(self.mode(target), 0o644)
        self.assertEqual(target.read_bytes(), b"untouched")

    def test_database_and_sidecars_are_private_without_changing_parent(self):
        self.root.chmod(0o755)
        database = self.root / "data.db"
        private_database(database)
        connection = sqlite3.connect(database)
        try:
            connection.execute("CREATE TABLE sample (value TEXT)")
            connection.execute("INSERT INTO sample VALUES ('preserved')")
            connection.commit()
        finally:
            connection.close()

        database.chmod(0o644)
        sidecars = [Path(str(database) + suffix) for suffix in ("-journal", "-wal", "-shm")]
        for sidecar in sidecars:
            sidecar.write_bytes(b"fixture")
            sidecar.chmod(0o644)
        private_database(database)
        self.assertEqual(self.mode(self.root), 0o755)
        for path in [database, *sidecars]:
            self.assertEqual(self.mode(path), 0o600)
        for sidecar in sidecars:
            self.assertEqual(sidecar.read_bytes(), b"fixture")
            sidecar.unlink()
        connection = sqlite3.connect(database)
        try:
            self.assertEqual(connection.execute("SELECT value FROM sample").fetchone()[0], "preserved")
        finally:
            connection.close()

    def test_sqlite_creates_private_sidecars_with_permissive_umask(self):
        old_umask = os.umask(0)
        self.addCleanup(os.umask, old_umask)
        for journal_mode, suffixes in (("DELETE", ("-journal",)), ("WAL", ("-wal", "-shm"))):
            with self.subTest(journal_mode=journal_mode):
                database = self.root / (journal_mode + ".db")
                private_database(database)
                connection = sqlite3.connect(database)
                try:
                    connection.execute(f"PRAGMA journal_mode={journal_mode}")
                    connection.execute("CREATE TABLE sample (value TEXT)")
                    connection.execute("INSERT INTO sample VALUES ('private')")
                    for suffix in suffixes:
                        self.assertEqual(self.mode(Path(str(database) + suffix)), 0o600)
                    connection.rollback()
                finally:
                    connection.close()
