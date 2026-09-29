"""Server regression tests using a disposable database and isolated storage."""

import base64
from concurrent.futures import ThreadPoolExecutor
import ctypes
import ctypes.util
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


class ReviewFixesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp_dir.cleanup)

        previous_db_path = os.environ.get("C2_DB_PATH")

        def restore_environment():
            if previous_db_path is None:
                os.environ.pop("C2_DB_PATH", None)
            else:
                os.environ["C2_DB_PATH"] = previous_db_path

        cls.addClassCleanup(restore_environment)
        previous_sys_path = sys.path[:]
        cls.addClassCleanup(lambda: sys.path.__setitem__(slice(None), previous_sys_path))

        cls.test_db_path = (Path(cls.temp_dir.name) / "test.db").resolve()
        os.environ["C2_DB_PATH"] = str(cls.test_db_path)
        sys.path.insert(0, str(Path(__file__).parent))

        if "database" in sys.modules:
            cls.database = importlib.reload(sys.modules["database"])
        else:
            cls.database = importlib.import_module("database")
        cls._assert_test_database()
        cls.crypto = importlib.import_module("crypto")
        storage = importlib.import_module("storage_permissions")
        private_directory = storage.private_directory
        with patch.object(storage, "private_directory", side_effect=lambda path, **kwargs:
                          private_directory(Path(cls.temp_dir.name) / Path(path).name, **kwargs)):
            if "app" in sys.modules:
                cls.server = importlib.reload(sys.modules["app"])
            else:
                cls.server = importlib.import_module("app")

        if cls.server.get_db_connection is not cls.database.get_db_connection:
            raise RuntimeError("Refusing to use a cached app with a different database connection.")

        cls.addClassCleanup(setattr, cls.server, "LOOT_DIR", cls.server.LOOT_DIR)
        cls.addClassCleanup(setattr, cls.server, "STAGED_DIR", cls.server.STAGED_DIR)

        cls.server.LOOT_DIR = str(Path(cls.temp_dir.name) / "loot")
        cls.server.STAGED_DIR = str(Path(cls.temp_dir.name) / "staged")
        Path(cls.server.LOOT_DIR).mkdir(parents=True, exist_ok=True)
        Path(cls.server.STAGED_DIR).mkdir(parents=True, exist_ok=True)

    @classmethod
    def _assert_test_database(cls):
        if Path(cls.database.DB_PATH).resolve() != cls.test_db_path:
            raise RuntimeError(
                "Refusing to modify a database outside this test's temporary directory. "
                "Run tests in a fresh process."
            )

    def setUp(self):
        self._assert_test_database()
        self.client = self.server.app.test_client()
        conn = self.database.get_db_connection()
        for table in ("results", "tasks", "agents", "staged_files", "builds", "build_cleanup_queue", "file_cleanup_queue", "seen_nonces", "loot"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()

        # Clean storage directories
        for d in (self.server.LOOT_DIR, self.server.STAGED_DIR, self.server.BUILDS_DIR):
            for f in Path(d).glob("*"):
                if f.is_file():
                    f.unlink()

        self.key_hex, self.kid = self.crypto.generate_key()
        self.agent_id = "agent-test-01"
        self.agent_secret = os.urandom(32).hex()
        self.agent_secret_hash = hashlib.sha256(bytes.fromhex(self.agent_secret)).hexdigest()

        conn = self.database.get_db_connection()
        conn.execute(
            "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, "
            "file_path, key_id, encryption_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("agent_linux_amd64", "linux", "amd64", "http://127.0.0.1:5000", "5s",
             "/tmp/build", self.kid, self.key_hex),
        )
        conn.execute(
            "INSERT INTO agents (id, hostname, ip, os, key_id, secret_hash) VALUES (?, ?, ?, ?, ?, ?)",
            (self.agent_id, "testhost", "127.0.0.1", "linux", self.kid, self.agent_secret_hash),
        )
        conn.commit()
        conn.close()

    def _prepare_upload(self, content: bytes, filename: str = "loot.txt"):
        sha256 = hashlib.sha256(content).hexdigest()
        meta = {
            "agent_id": self.agent_id,
            "agent_secret": self.agent_secret,
            "sha256": sha256,
        }
        enc_meta = self.crypto.encrypt_payload(self.key_hex, json.dumps(meta).encode())
        auth = json.dumps({"kid": self.kid, "data": enc_meta})
        data = {
            "auth": auth,
            "file": (io.BytesIO(content), filename),
            "original_path": f"/tmp/{filename}",
        }
        return data

    def test_dashboard_html_requires_server_side_login(self):
        anonymous = self.client.get("/")
        self.assertEqual(anonymous.status_code, 302)
        self.assertTrue(anonymous.headers["Location"].endswith("/login"))
        login_page = self.client.get("/login")
        self.assertEqual(login_page.status_code, 200)
        self.assertNotIn(b'id="section-control"', login_page.data)
        self.assertEqual(login_page.headers["Cache-Control"], "no-store")

        rejected = self.client.post("/login", data={"api_key": "wrong"})
        self.assertEqual(rejected.status_code, 401)
        self.assertNotIn(b'id="section-control"', rejected.data)

        accepted = self.client.post("/login", data={"api_key": self.server.API_KEY})
        self.assertEqual(accepted.status_code, 302)
        session_cookie = accepted.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", session_cookie)
        self.assertIn("SameSite=Strict", session_cookie)
        dashboard = self.client.get("/")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b'id="section-control"', dashboard.data)
        self.assertNotIn(b'id="auth-overlay"', dashboard.data)
        self.assertEqual(dashboard.headers["Cache-Control"], "no-store")
        self.assertEqual(self.client.get("/api/stats").status_code, 200)

        self.assertEqual(self.client.post("/logout").status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 302)
        self.assertEqual(self.client.get("/api/stats").status_code, 401)

    # ------------------------------------------------------------------
    # DATA-02: Accepted uploads must contain every byte
    # ------------------------------------------------------------------

    def test_data_02_short_writes_rejected(self):
        """Injected short write, zero-byte write, or write error must reject upload and leave no record."""
        content = b"0123456789ABCDEF"  # 16 bytes

        # 1. Short write: write 5 bytes on first call, then 0 on second call (unable to write all bytes)
        real_os_write = os.write
        call_count = [0]
        def short_then_stop(fd, data):
            call_count[0] += 1
            if call_count[0] == 1:
                return real_os_write(fd, data[:5])
            return 0

        with patch.object(self.server.os, "write", side_effect=short_then_stop):
            resp = self.client.post(self.server.AGENT_PATH_UPLOAD, data=self._prepare_upload(content, "short.txt"))
            self.assertNotEqual(resp.status_code, 200)

        # Confirm no database record and no leftover file
        conn = self.database.get_db_connection()
        loot_rows = conn.execute("SELECT * FROM loot").fetchall()
        conn.close()
        self.assertEqual(len(loot_rows), 0)
        self.assertEqual(list(Path(self.server.LOOT_DIR).glob("*")), [])

        # 2. Zero-byte write: os.write writes 0 bytes
        def zero_write(fd, data):
            return 0

        with patch.object(self.server.os, "write", side_effect=zero_write):
            resp = self.client.post(self.server.AGENT_PATH_UPLOAD, data=self._prepare_upload(content, "zero.txt"))
            self.assertNotEqual(resp.status_code, 200)

        conn = self.database.get_db_connection()
        loot_rows = conn.execute("SELECT * FROM loot").fetchall()
        conn.close()
        self.assertEqual(len(loot_rows), 0)
        self.assertEqual(list(Path(self.server.LOOT_DIR).glob("*")), [])

        # 3. Write exception after partial write (e.g. disk full)
        def error_after_partial(fd, data):
            real_os_write(fd, data[:4])
            raise OSError("Disk full")

        with patch.object(self.server.os, "write", side_effect=error_after_partial):
            resp = self.client.post(self.server.AGENT_PATH_UPLOAD, data=self._prepare_upload(content, "err.txt"))
            self.assertNotEqual(resp.status_code, 200)

        conn = self.database.get_db_connection()
        loot_rows = conn.execute("SELECT * FROM loot").fetchall()
        conn.close()
        self.assertEqual(len(loot_rows), 0)
        self.assertEqual(list(Path(self.server.LOOT_DIR).glob("*")), [])

    def test_data_02_normal_upload_stores_exact_bytes(self):
        """Normal upload stores byte-for-byte exact content and truthful metadata."""
        content = b"Hello, World! Exact bytes test: \x00\xff\xfe\x01\x02"
        resp = self.client.post(self.server.AGENT_PATH_UPLOAD, data=self._prepare_upload(content, "normal.bin"))
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["size"], len(content))

        conn = self.database.get_db_connection()
        loot = conn.execute("SELECT * FROM loot").fetchall()
        conn.close()
        self.assertEqual(len(loot), 1)
        self.assertEqual(loot[0]["file_size"], len(content))
        stored_path = loot[0]["file_path"]
        self.assertTrue(os.path.exists(stored_path))
        with open(stored_path, "rb") as f:
            self.assertEqual(f.read(), content)

    # ------------------------------------------------------------------
    # DATA-03: Failed upload must not leave untracked file or damage pre-existing
    # ------------------------------------------------------------------

    def test_data_03_cleanup_on_db_insert_or_commit_failure(self):
        """Insert and commit failures each roll back rows/nonces and remove the file."""
        content = b"Test cleanup on DB error"
        class FailingConn:
            def __init__(self, actual, failure):
                self.actual = actual
                self.failure = failure
                self.commit_attempted = False
            def execute(self, sql, *args, **kwargs):
                if self.failure == "insert" and "INSERT INTO loot" in sql:
                    raise sqlite3.OperationalError("Simulated DB loot insert failure")
                return self.actual.execute(sql, *args, **kwargs)
            def commit(self):
                self.commit_attempted = True
                raise sqlite3.OperationalError("Simulated DB commit failure")
            def close(self):
                return self.actual.close()

        for failure in ("insert", "commit"):
            with self.subTest(failure=failure):
                connections = []
                def connect():
                    conn = FailingConn(self.database.get_db_connection(), failure)
                    connections.append(conn)
                    return conn
                with patch.object(self.server, "get_db_connection", side_effect=connect):
                    resp = self.client.post(self.server.AGENT_PATH_UPLOAD,
                                            data=self._prepare_upload(content, "dberr.txt"))
                    self.assertEqual(resp.status_code, 500)
                self.assertEqual(any(c.commit_attempted for c in connections), failure == "commit")
                self.assertEqual(list(Path(self.server.LOOT_DIR).glob("*")), [])
                conn = self.database.get_db_connection()
                try:
                    self.assertEqual(conn.execute("SELECT COUNT(*) FROM loot").fetchone()[0], 0)
                    self.assertEqual(conn.execute("SELECT COUNT(*) FROM seen_nonces").fetchone()[0], 0)
                finally:
                    conn.close()

    def test_upload_storage_is_owner_only(self):
        """Both upload routes keep content private under a permissive umask."""
        old_umask = os.umask(0)
        self.addCleanup(os.umask, old_umask)
        response = self.client.post(self.server.AGENT_PATH_UPLOAD,
                                    data=self._prepare_upload(b"private", "private.txt"))
        self.assertEqual(response.status_code, 200)
        response = self.client.post("/api/files/stage",
                                    data={"file": (io.BytesIO(b"private"), "private.txt")},
                                    headers={"X-API-Key": self.server.API_KEY})
        self.assertEqual(response.status_code, 200)
        for directory in (self.server.LOOT_DIR, self.server.STAGED_DIR):
            for path in Path(directory).iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_data_03_preexisting_files_remain_intact(self):
        """Cleanup on failed attempt must never remove or modify an older pre-existing upload."""
        # Create an existing file in LOOT_DIR
        pre_existing_path = Path(self.server.LOOT_DIR) / "pre_existing.txt"
        pre_existing_content = b"IMPORTANT OLD DATA"
        pre_existing_path.write_bytes(pre_existing_content)

        # Attempt an upload that fails during write
        def fail_write(fd, data):
            raise OSError("I/O failure")

        with patch.object(self.server.os, "write", side_effect=fail_write):
            resp = self.client.post(self.server.AGENT_PATH_UPLOAD, data=self._prepare_upload(b"new data", "pre_existing.txt"))
            self.assertNotEqual(resp.status_code, 200)

        # Pre-existing file must remain byte-for-byte identical
        self.assertTrue(pre_existing_path.exists())
        self.assertEqual(pre_existing_path.read_bytes(), pre_existing_content)
        # And no other files were created
        self.assertEqual(list(Path(self.server.LOOT_DIR).glob("*")), [pre_existing_path])

    # ------------------------------------------------------------------
    # DATA-04: Staged files must not share fallback path
    # ------------------------------------------------------------------

    def test_data_04_three_uploads_same_name_fixed_timestamp(self):
        """Three staged uploads with the same name at a fixed timestamp must each point to their own unchanged bytes."""
        fixed_dt = unittest.mock.MagicMock()
        fixed_dt.strftime.return_value = "20260924_120000"

        contents = [b"version_1_data", b"version_2_data", b"version_3_data"]
        file_records = []

        with patch.object(self.server, "datetime") as mock_dt:
            mock_dt.now.return_value = fixed_dt
            for content in contents:
                resp = self.client.post(
                    "/api/files/stage",
                    data={"file": (io.BytesIO(content), "payload.bin")},
                    headers={"X-API-Key": self.server.API_KEY},
                )
                self.assertEqual(resp.status_code, 200)
                data = resp.get_json()
                self.assertEqual(data["status"], "ok")
                file_records.append(data)

        self.assertEqual(len(file_records), 3)

        # Verify DB records and physical file contents
        conn = self.database.get_db_connection()
        db_rows = conn.execute("SELECT * FROM staged_files ORDER BY id ASC").fetchall()
        conn.close()

        self.assertEqual(len(db_rows), 3)
        paths = [r["file_path"] for r in db_rows]
        # Paths must all be distinct
        self.assertEqual(len(set(paths)), 3)

        # Each path must contain its own exact original bytes
        for row, expected_content in zip(db_rows, contents):
            self.assertTrue(os.path.exists(row["file_path"]))
            with open(row["file_path"], "rb") as f:
                self.assertEqual(f.read(), expected_content)
            self.assertEqual(row["file_size"], len(expected_content))

    def test_data_04_preexisting_candidate_fallback_preserved_and_safe_cleanup(self):
        """If candidate fallback path already exists, it is not overwritten, and a failed upload cleans up only its new file."""
        fixed_dt = unittest.mock.MagicMock()
        fixed_dt.strftime.return_value = "20260924_150000"

        # Pre-create candidate 1 (tool.exe) and candidate 2 (tool_20260924_150000.exe)
        p1 = Path(self.server.STAGED_DIR) / "tool.exe"
        p1.write_bytes(b"ORIGINAL_TOOL")
        p2 = Path(self.server.STAGED_DIR) / "tool_20260924_150000.exe"
        p2.write_bytes(b"ORIGINAL_FALLBACK")

        with patch.object(self.server, "datetime") as mock_dt:
            mock_dt.now.return_value = fixed_dt

            # Staging tool.exe will see p1 exists, p2 exists, and must allocate a random suffix
            new_content = b"THIRD_UPLOAD_DATA"
            resp = self.client.post(
                "/api/files/stage",
                data={"file": (io.BytesIO(new_content), "tool.exe")},
                headers={"X-API-Key": self.server.API_KEY},
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data["filename"].startswith("tool_20260924_150000_"))

        # Pre-existing p1 and p2 must be 100% intact
        self.assertEqual(p1.read_bytes(), b"ORIGINAL_TOOL")
        self.assertEqual(p2.read_bytes(), b"ORIGINAL_FALLBACK")

        # Now test failure cleanup with pre-existing fallback path present:
        with patch.object(self.server, "datetime") as mock_dt:
            mock_dt.now.return_value = fixed_dt
            with patch.object(self.server, "get_db_connection", side_effect=sqlite3.OperationalError("Simulated DB failure")):
                resp = self.client.post(
                    "/api/files/stage",
                    data={"file": (io.BytesIO(b"FAIL_DATA"), "tool.exe")},
                    headers={"X-API-Key": self.server.API_KEY},
                )
                self.assertNotEqual(resp.status_code, 200)

        # Pre-existing p1 and p2 must STILL be intact
        self.assertEqual(p1.read_bytes(), b"ORIGINAL_TOOL")
        self.assertEqual(p2.read_bytes(), b"ORIGINAL_FALLBACK")

    # ------------------------------------------------------------------
    # API-03: One registered agent must produce one response row
    # ------------------------------------------------------------------

    def test_api_03_duplicate_and_missing_build_keys(self):
        """Ambiguous legacy keys must not acquire another build's metadata."""
        conn = self.database.get_db_connection()
        conn.execute("DELETE FROM agents")
        conn.execute("DELETE FROM builds")

        # 1. Agent with 0 builds
        conn.execute(
            "INSERT INTO agents (id, hostname, ip, os, key_id, last_seen) VALUES ('agent-no-build', 'host0', '1.1.1.1', 'linux', 'key-none', '2026-09-24 10:00:00')"
        )

        # 2. Agent with 1 build
        conn.execute(
            "INSERT INTO agents (id, hostname, ip, os, key_id, last_seen) VALUES ('agent-single-build', 'host1', '1.1.1.2', 'linux', 'key-single', '2026-09-24 11:00:00')"
        )
        conn.execute(
            "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, transport_mode, decoy_domain) "
            "VALUES ('b1', 'linux', 'amd64', 'https://127.0.0.1', '5s', '/tmp', 'key-single', 'https_pinned', 'pinned.example')"
        )

        # 3. Agent with 2 builds (duplicate key_ids)
        conn.execute(
            "INSERT INTO agents (id, hostname, ip, os, key_id, last_seen) VALUES ('agent-dup-build', 'host2', '1.1.1.3', 'linux', 'key-dup', '2026-09-24 12:00:00')"
        )
        conn.execute(
            "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, transport_mode, decoy_domain) "
            "VALUES ('b2_old', 'linux', 'amd64', 'http://127.0.0.1', '5s', '/tmp', 'key-dup', 'http', NULL)"
        )
        conn.execute(
            "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, transport_mode, decoy_domain) "
            "VALUES ('b2_new', 'linux', 'amd64', 'http://127.0.0.1', '5s', '/tmp', 'key-dup', 'reality', 'decoy.example')"
        )

        # 4. Agent with NULL key_id
        conn.execute(
            "INSERT INTO agents (id, hostname, ip, os, key_id, last_seen) VALUES ('agent-null-key', 'host3', '1.1.1.4', 'linux', NULL, '2026-09-24 09:00:00')"
        )

        # 5. Agent with empty key_id, and a build with empty key_id
        conn.execute(
            "INSERT INTO agents (id, hostname, ip, os, key_id, last_seen) VALUES ('agent-empty-key', 'host4', '1.1.1.5', 'linux', '', '2026-09-24 08:00:00')"
        )
        conn.execute(
            "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, transport_mode, decoy_domain) "
            "VALUES ('b_empty', 'linux', 'amd64', 'http://127.0.0.1', '5s', '/tmp', '', 'http', NULL)"
        )

        conn.commit()
        conn.close()

        resp = self.client.get("/api/agents", headers={"X-API-Key": self.server.API_KEY})
        self.assertEqual(resp.status_code, 200)
        agents = resp.get_json()["agents"]

        # Exactly 5 agents returned (one per agent)
        self.assertEqual(len(agents), 5)
        by_id = {a["id"]: a for a in agents}

        # Verify metadata consistency
        self.assertEqual(by_id["agent-no-build"]["transport_mode"], "")
        self.assertIsNone(by_id["agent-no-build"]["decoy_domain"])

        self.assertEqual(by_id["agent-single-build"]["transport_mode"], "https_pinned")
        self.assertEqual(by_id["agent-single-build"]["decoy_domain"], "pinned.example")

        # Duplicate key cannot identify either build without an explicit ID.
        self.assertEqual(by_id["agent-dup-build"]["transport_mode"], "")
        self.assertIsNone(by_id["agent-dup-build"]["decoy_domain"])

        self.assertEqual(by_id["agent-null-key"]["transport_mode"], "")
        self.assertEqual(by_id["agent-empty-key"]["transport_mode"], "")

    # ------------------------------------------------------------------
    # API-04: Build-key collisions and ambiguous associations resolved
    # ------------------------------------------------------------------

    def test_api_04_key_generation_entropy(self):
        """generate_key produces 256-bit keys and full 64-hex SHA-256 fingerprints."""
        keys = set()
        kids = set()
        for _ in range(50):
            k_hex, kid = self.crypto.generate_key()
            self.assertEqual(len(k_hex), 64)
            self.assertEqual(len(kid), 64)
            # Must be valid hex
            bytes.fromhex(k_hex)
            bytes.fromhex(kid)
            keys.add(k_hex)
            kids.add(kid)
        self.assertEqual(len(keys), 50)
        self.assertEqual(len(kids), 50)

    def test_api_04_collision_disambiguation_checkin_and_transport(self):
        """Colliding key_ids are disambiguated by AEAD decryption, assigning correct build_id and transport."""
        conn = self.database.get_db_connection()
        conn.execute("DELETE FROM results")
        conn.execute("DELETE FROM tasks")
        conn.execute("DELETE FROM agents")
        conn.execute("DELETE FROM builds")
        conn.execute("DELETE FROM seen_nonces")

        # Create two keys that share the SAME key_id (simulating a collision)
        shared_kid = "colliding_kid_abc123"
        key_hex_1 = os.urandom(32).hex()
        key_hex_2 = os.urandom(32).hex()

        # Build 1: HTTP transport
        cursor = conn.execute(
            "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, encryption_key, transport_mode) "
            "VALUES ('b_old_http', 'linux', 'amd64', 'http://127.0.0.1:5000', '5s', '/tmp/b1', ?, ?, 'http')",
            (shared_kid, key_hex_1),
        )
        build_1_id = cursor.lastrowid

        # Build 2: REALITY transport (newer build with colliding kid)
        cursor = conn.execute(
            "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, encryption_key, transport_mode, decoy_domain) "
            "VALUES ('b_new_reality', 'linux', 'amd64', 'http://127.0.0.1:5000', '5s', '/tmp/b2', ?, ?, 'reality', 'decoy.example')",
            (shared_kid, key_hex_2),
        )
        build_2_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # Agent 1 (from Build 1, HTTP) checks in
        agent_1_secret = os.urandom(32).hex()
        payload_1 = {
            "agent_id": "agent-from-b1",
            "agent_secret": agent_1_secret,
            "hostname": "host-http",
            "os": "linux",
        }
        enc_1 = self.crypto.encrypt_payload(key_hex_1, json.dumps(payload_1).encode())
        resp_1 = self.client.post(
            self.server.AGENT_PATH_CHECKIN,
            json={"kid": shared_kid, "data": enc_1},
        )
        self.assertEqual(resp_1.status_code, 200)
        resp_1_json = resp_1.get_json()
        dec_resp_1 = json.loads(self.crypto.decrypt_payload(key_hex_1, resp_1_json["data"]))
        self.assertEqual(dec_resp_1["status"], "ok")

        # Agent 2 (from Build 2, REALITY) checks in
        agent_2_secret = os.urandom(32).hex()
        payload_2 = {
            "agent_id": "agent-from-b2",
            "agent_secret": agent_2_secret,
            "hostname": "host-reality",
            "os": "linux",
        }
        enc_2 = self.crypto.encrypt_payload(key_hex_2, json.dumps(payload_2).encode())
        resp_2 = self.client.post(
            self.server.AGENT_PATH_CHECKIN,
            json={"kid": shared_kid, "data": enc_2},
        )
        self.assertEqual(resp_2.status_code, 200)
        resp_2_json = resp_2.get_json()
        dec_resp_2 = json.loads(self.crypto.decrypt_payload(key_hex_2, resp_2_json["data"]))
        self.assertEqual(dec_resp_2["status"], "ok")

        # Verify DB records have distinct, correct build_ids
        conn = self.database.get_db_connection()
        agents_db = {a["id"]: dict(a) for a in conn.execute("SELECT * FROM agents").fetchall()}
        conn.close()

        self.assertEqual(agents_db["agent-from-b1"]["build_id"], build_1_id)
        self.assertEqual(agents_db["agent-from-b2"]["build_id"], build_2_id)

        # Verify /api/agents reports truthful, separate transport metadata for each agent
        agents_resp = self.client.get("/api/agents", headers={"X-API-Key": self.server.API_KEY})
        self.assertEqual(agents_resp.status_code, 200)
        agents_api = {a["id"]: a for a in agents_resp.get_json()["agents"]}

        self.assertEqual(len(agents_api), 2)
        # Agent 1 correctly shows HTTP, NOT overwritten by latest build's reality
        self.assertEqual(agents_api["agent-from-b1"]["transport_mode"], "http")
        self.assertIsNone(agents_api["agent-from-b1"]["decoy_domain"])

        # Agent 2 correctly shows REALITY
        self.assertEqual(agents_api["agent-from-b2"]["transport_mode"], "reality")
        self.assertEqual(agents_api["agent-from-b2"]["decoy_domain"], "decoy.example")

        # Queue and execute tasks for both agents to verify result submission
        conn = self.database.get_db_connection()
        cursor = conn.execute("INSERT INTO tasks (agent_id, command, status) VALUES ('agent-from-b1', 'id', 'sent')")
        task_1_id = cursor.lastrowid
        cursor = conn.execute("INSERT INTO tasks (agent_id, command, status) VALUES ('agent-from-b2', 'uname', 'sent')")
        task_2_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # Submit result for Agent 1 (uses key_hex_1)
        res_payload_1 = {
            "task_id": task_1_id,
            "agent_id": "agent-from-b1",
            "agent_secret": agent_1_secret,
            "output": "uid=0(root)",
        }
        res_enc_1 = self.crypto.encrypt_payload(key_hex_1, json.dumps(res_payload_1).encode())
        res_resp_1 = self.client.post(self.server.AGENT_PATH_RESULT, json={"kid": shared_kid, "data": res_enc_1})
        self.assertEqual(res_resp_1.status_code, 200)

        # Submit result for Agent 2 (uses key_hex_2)
        res_payload_2 = {
            "task_id": task_2_id,
            "agent_id": "agent-from-b2",
            "agent_secret": agent_2_secret,
            "output": "Linux 6.1",
        }
        res_enc_2 = self.crypto.encrypt_payload(key_hex_2, json.dumps(res_payload_2).encode())
        res_resp_2 = self.client.post(self.server.AGENT_PATH_RESULT, json={"kid": shared_kid, "data": res_enc_2})
        self.assertEqual(res_resp_2.status_code, 200)

        # Upload file for Agent 1
        file_bytes = b"agent-1-dump"
        auth_1 = {
            "agent_id": "agent-from-b1",
            "agent_secret": agent_1_secret,
            "sha256": hashlib.sha256(file_bytes).hexdigest(),
        }
        enc_auth_1 = self.crypto.encrypt_payload(key_hex_1, json.dumps(auth_1).encode())
        up_resp_1 = self.client.post(
            self.server.AGENT_PATH_UPLOAD,
            data={
                "auth": json.dumps({"kid": shared_kid, "data": enc_auth_1}),
                "original_path": "/var/log/dump1.log",
                "file": (io.BytesIO(file_bytes), "dump1.log"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(up_resp_1.status_code, 200)

    def test_api_04_identical_key_collision_retains_unknown_association(self):
        """Historical builds sharing both key_id and encryption_key cannot be distinguished, retaining unknown association."""
        conn = self.database.get_db_connection()
        conn.execute("DELETE FROM results")
        conn.execute("DELETE FROM tasks")
        conn.execute("DELETE FROM agents")
        conn.execute("DELETE FROM builds")
        conn.execute("DELETE FROM seen_nonces")

        # Two historical builds that share BOTH key_id AND encryption_key
        shared_kid = "indistinguishable_kid"
        shared_key_hex = os.urandom(32).hex()

        conn.execute(
            "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, encryption_key, transport_mode) "
            "VALUES ('b_old_http', 'linux', 'amd64', 'http://127.0.0.1:5000', '5s', '/tmp/b_old', ?, ?, 'http')",
            (shared_kid, shared_key_hex),
        )
        conn.execute(
            "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, encryption_key, transport_mode, decoy_domain) "
            "VALUES ('b_new_reality', 'linux', 'amd64', 'http://127.0.0.1:5000', '5s', '/tmp/b_new', ?, ?, 'reality', 'decoy.example')",
            (shared_kid, shared_key_hex),
        )
        conn.commit()
        conn.close()

        # Agent checks in using shared_kid and shared_key_hex
        agent_secret = os.urandom(32).hex()
        payload = {
            "agent_id": "agent-ambiguous-keys",
            "agent_secret": agent_secret,
            "hostname": "host-ambig",
            "os": "linux",
        }
        enc = self.crypto.encrypt_payload(shared_key_hex, json.dumps(payload).encode())
        resp = self.client.post(
            self.server.AGENT_PATH_CHECKIN,
            json={"kid": shared_kid, "data": enc},
        )
        self.assertEqual(resp.status_code, 200)
        dec_resp = json.loads(self.crypto.decrypt_payload(shared_key_hex, resp.get_json()["data"]))
        self.assertEqual(dec_resp["status"], "ok")

        # In DB, build_id must remain NULL (not arbitrarily attributed to newest build)
        conn = self.database.get_db_connection()
        agent_row = conn.execute("SELECT * FROM agents WHERE id = 'agent-ambiguous-keys'").fetchone()
        conn.close()
        self.assertIsNotNone(agent_row)
        self.assertIsNone(agent_row["build_id"], "Ambiguous agent must not be attributed to a specific build")

        # /api/agents reports unknown transport (empty string) rather than false certainty
        agents_resp = self.client.get("/api/agents", headers={"X-API-Key": self.server.API_KEY})
        self.assertEqual(agents_resp.status_code, 200)
        agents_data = {a["id"]: a for a in agents_resp.get_json()["agents"]}
        self.assertEqual(agents_data["agent-ambiguous-keys"]["transport_mode"], "")
        self.assertIsNone(agents_data["agent-ambiguous-keys"]["decoy_domain"])

        # Agent can still execute tasks and submit results cleanly
        conn = self.database.get_db_connection()
        cursor = conn.execute("INSERT INTO tasks (agent_id, command, status) VALUES ('agent-ambiguous-keys', 'whoami', 'sent')")
        task_id = cursor.lastrowid
        conn.commit()
        conn.close()

        res_payload = {
            "task_id": task_id,
            "agent_id": "agent-ambiguous-keys",
            "agent_secret": agent_secret,
            "output": "sheriff",
        }
        res_enc = self.crypto.encrypt_payload(shared_key_hex, json.dumps(res_payload).encode())
        res_resp = self.client.post(self.server.AGENT_PATH_RESULT, json={"kid": shared_kid, "data": res_enc})
        self.assertEqual(res_resp.status_code, 200)

    def test_api_04_audit_and_migration(self):
        """Collision audit reports duplicate keys and init_db migrates unambiguous agents."""
        conn = self.database.get_db_connection()
        conn.execute("DELETE FROM results")
        conn.execute("DELETE FROM tasks")
        conn.execute("DELETE FROM agents")
        conn.execute("DELETE FROM builds")

        # Set up a collision
        conn.execute("INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, encryption_key, transport_mode) VALUES ('b1', 'linux', 'amd64', 'http://1', '5s', '/tmp', 'dup_k', 'k1', 'http')")
        conn.execute("INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, encryption_key, transport_mode) VALUES ('b2', 'linux', 'amd64', 'http://1', '5s', '/tmp', 'dup_k', 'k2', 'reality')")
        # And a unique build
        cursor = conn.execute("INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, encryption_key, transport_mode) VALUES ('b3_unique', 'linux', 'amd64', 'http://1', '5s', '/tmp', 'uniq_k', 'k3', 'https_pinned')")
        unique_build_id = cursor.lastrowid

        # Agent with unique build (initially NULL build_id)
        conn.execute("INSERT INTO agents (id, hostname, key_id, build_id) VALUES ('agent-unique', 'h-uniq', 'uniq_k', NULL)")
        # Agent with duplicate key (initially NULL build_id)
        conn.execute("INSERT INTO agents (id, hostname, key_id, build_id) VALUES ('agent-dup', 'h-dup', 'dup_k', NULL)")
        conn.commit()

        # Audit collisions
        collisions = self.database.audit_build_key_collisions(conn)
        self.assertEqual(len(collisions), 1)
        self.assertEqual(collisions[0]["key_id"], "dup_k")
        self.assertEqual(collisions[0]["build_count"], 2)
        self.assertEqual(len(collisions[0]["builds"]), 2)
        self.assertTrue(all("encryption_key" not in row for row in collisions[0]["builds"]))
        self.assertEqual(len(collisions[0]["agents"]), 1)
        self.assertEqual(collisions[0]["agents"][0]["id"], "agent-dup")

        # Run init_db() migration: unambiguous agent should be migrated to unique_build_id
        self.database.init_db()

        agents = {a["id"]: dict(a) for a in conn.execute("SELECT * FROM agents").fetchall()}
        self.assertEqual(agents["agent-unique"]["build_id"], unique_build_id)
        # Ambiguous agent remains NULL (awaiting checkin disambiguation)
        self.assertIsNone(agents["agent-dup"]["build_id"])
        conn.close()

    def test_build_delete_preserves_referenced_artifact(self):
        """Failed deletion leaves the build row and file intact, with or without FK enforcement."""
        artifact = Path(self.server.BUILDS_DIR) / "build-under-test"
        artifact.write_bytes(b"build bytes")
        conn = self.database.get_db_connection()
        build_id = conn.execute("SELECT id FROM builds WHERE key_id = ?", (self.kid,)).fetchone()[0]
        conn.execute("UPDATE builds SET file_path = ? WHERE id = ?", (str(artifact), build_id))
        conn.execute("UPDATE agents SET build_id = ? WHERE id = ?", (build_id, self.agent_id))
        conn.commit()
        conn.close()

        for foreign_keys in (True, False):
            def get_connection():
                db = self.database.get_db_connection()
                db.execute(f"PRAGMA foreign_keys = {'ON' if foreign_keys else 'OFF'}")
                return db

            with patch.object(self.server, "get_db_connection", side_effect=get_connection):
                resp = self.client.delete(
                    f"/api/builds/{build_id}", headers={"X-API-Key": self.server.API_KEY}
                )
            self.assertEqual(resp.status_code, 409)
            self.assertEqual(artifact.read_bytes(), b"build bytes")
            conn = self.database.get_db_connection()
            self.assertIsNotNone(conn.execute("SELECT id FROM builds WHERE id = ?", (build_id,)).fetchone())
            conn.close()

        conn = self.database.get_db_connection()
        conn.execute("DELETE FROM agents WHERE id = ?", (self.agent_id,))
        conn.commit()
        conn.close()
        resp = self.client.delete(f"/api/builds/{build_id}", headers={"X-API-Key": self.server.API_KEY})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(artifact.exists())
        conn = self.database.get_db_connection()
        self.assertIsNone(conn.execute("SELECT id FROM builds WHERE id = ?", (build_id,)).fetchone())
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM build_cleanup_queue").fetchone()[0], 0)
        conn.close()

    def test_build_cleanup_retries_after_unlink_failure(self):
        artifact = Path(self.server.BUILDS_DIR) / "retry-build"
        artifact.write_bytes(b"retry bytes")
        conn = self.database.get_db_connection()
        build_id = conn.execute("SELECT id FROM builds WHERE key_id = ?", (self.kid,)).fetchone()[0]
        conn.execute("UPDATE builds SET file_path = ? WHERE id = ?", (str(artifact), build_id))
        conn.execute("DELETE FROM agents WHERE id = ?", (self.agent_id,))
        conn.commit()
        conn.close()

        with patch.object(self.server.os, "remove", side_effect=PermissionError("simulated unlink failure")):
            response = self.client.delete(
                f"/api/builds/{build_id}", headers={"X-API-Key": self.server.API_KEY}
            )
        self.assertEqual(response.status_code, 500)
        self.assertIn("queued for retry", response.get_json()["error"])
        self.assertEqual(artifact.read_bytes(), b"retry bytes")
        conn = self.database.get_db_connection()
        self.assertIsNone(conn.execute("SELECT id FROM builds WHERE id = ?", (build_id,)).fetchone())
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM build_cleanup_queue").fetchone()[0], 1)
        conn.close()

        self.server.retry_queued_build_cleanup()
        self.assertFalse(artifact.exists())
        conn = self.database.get_db_connection()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM build_cleanup_queue").fetchone()[0], 0)
        conn.close()

    def test_build_cleanup_preserves_artifact_shared_by_another_build(self):
        artifact = Path(self.server.BUILDS_DIR) / "shared-build"
        artifact.write_bytes(b"shared bytes")
        conn = self.database.get_db_connection()
        build_id = conn.execute("SELECT id FROM builds WHERE key_id = ?", (self.kid,)).fetchone()[0]
        conn.execute("UPDATE builds SET file_path = ? WHERE id = ?", (str(artifact), build_id))
        conn.execute("DELETE FROM agents WHERE id = ?", (self.agent_id,))
        other_id = conn.execute(
            "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("other", "linux", "amd64", "http://example.invalid", "10", str(artifact)),
        ).lastrowid
        conn.commit()
        conn.close()

        response = self.client.delete(
            f"/api/builds/{build_id}", headers={"X-API-Key": self.server.API_KEY}
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(artifact.read_bytes(), b"shared bytes")
        conn = self.database.get_db_connection()
        self.assertIsNotNone(conn.execute("SELECT id FROM builds WHERE id = ?", (build_id,)).fetchone())
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM build_cleanup_queue").fetchone()[0], 0)
        conn.execute("INSERT INTO build_cleanup_queue (file_path) VALUES (?)", (str(artifact),))
        conn.commit()
        conn.close()
        self.server.retry_queued_build_cleanup()
        self.assertEqual(artifact.read_bytes(), b"shared bytes")
        conn = self.database.get_db_connection()
        self.assertIsNotNone(conn.execute("SELECT id FROM builds WHERE id = ?", (other_id,)).fetchone())
        conn.close()

    def test_data_06_build_names_are_unique_and_failed_insert_cleans_artifact(self):
        def fake_build(command, **kwargs):
            Path(command[command.index("-o") + 1]).write_bytes(b"built agent")
            return SimpleNamespace(returncode=0, stderr="", stdout="")

        payload = {"target_os": "linux", "arch": "amd64", "server_url": "http://example.invalid",
                   "jitter_min": 8, "jitter_max": 15, "persist_method": "none"}
        with patch.object(self.server.subprocess, "run", side_effect=fake_build):
            first = self.client.post("/api/build", json=payload, headers={"X-API-Key": self.server.API_KEY})
            second = self.client.post("/api/build", json=payload, headers={"X-API-Key": self.server.API_KEY})
        self.assertEqual((first.status_code, second.status_code), (200, 200))
        self.assertNotEqual(first.json["filename"], second.json["filename"])
        for response in (first, second):
            self.assertEqual((Path(self.server.BUILDS_DIR) / response.json["filename"]).read_bytes(), b"built agent")

        before = {p.name for p in Path(self.server.BUILDS_DIR).iterdir()}
        conn = self.database.get_db_connection()
        conn.execute("CREATE TRIGGER fail_build_record BEFORE INSERT ON builds "
                     "BEGIN SELECT RAISE(FAIL, 'simulated insert failure'); END")
        conn.commit()
        conn.close()
        try:
            with patch.object(self.server.subprocess, "run", side_effect=fake_build):
                failed = self.client.post("/api/build", json=payload, headers={"X-API-Key": self.server.API_KEY})
            self.assertEqual(failed.status_code, 500)
            self.assertEqual({p.name for p in Path(self.server.BUILDS_DIR).iterdir()}, before)
        finally:
            conn = self.database.get_db_connection()
            conn.execute("DROP TRIGGER fail_build_record")
            conn.commit()
            conn.close()

        class FailingCommit:
            def __init__(self, actual):
                self.actual = actual
            def execute(self, *args):
                return self.actual.execute(*args)
            def commit(self):
                raise sqlite3.OperationalError("simulated build commit failure")
            def close(self):
                self.actual.close()

        connections = 0
        def connect():
            nonlocal connections
            connections += 1
            actual = self.database.get_db_connection()
            return FailingCommit(actual) if connections == 2 else actual

        with patch.object(self.server, "get_db_connection", side_effect=connect), \
             patch.object(self.server.subprocess, "run", side_effect=fake_build):
            failed = self.client.post("/api/build", json=payload, headers={"X-API-Key": self.server.API_KEY})
        self.assertEqual(failed.status_code, 500)
        self.assertEqual({p.name for p in Path(self.server.BUILDS_DIR).iterdir()}, before)

    def test_data_07_failed_deletes_keep_file_row_and_release_lock(self):
        for kind, table, directory, route in (
            ("loot", "loot", self.server.LOOT_DIR, "/api/loot"),
            ("staged", "staged_files", self.server.STAGED_DIR, "/api/files"),
        ):
            with self.subTest(kind=kind):
                path = Path(directory) / f"delete-{kind}"
                path.write_bytes(b"retained")
                conn = self.database.get_db_connection()
                if kind == "loot":
                    record_id = conn.execute(
                        "INSERT INTO loot (agent_id, filename, file_path) VALUES (?, ?, ?)",
                        (self.agent_id, path.name, str(path)),
                    ).lastrowid
                else:
                    record_id = conn.execute(
                        "INSERT INTO staged_files (filename, file_path) VALUES (?, ?)",
                        (path.name, str(path)),
                    ).lastrowid
                conn.execute(f"CREATE TRIGGER fail_{kind}_delete BEFORE DELETE ON {table} "
                             "BEGIN SELECT RAISE(FAIL, 'simulated delete failure'); END")
                conn.commit()
                conn.close()
                try:
                    response = self.client.delete(f"{route}/{record_id}", headers={"X-API-Key": self.server.API_KEY})
                    self.assertEqual(response.status_code, 500)
                    self.assertEqual(path.read_bytes(), b"retained")
                    conn = self.database.get_db_connection()
                    conn.execute("BEGIN IMMEDIATE")  # a leaked connection would hold this lock
                    self.assertIsNotNone(conn.execute(f"SELECT id FROM {table} WHERE id = ?", (record_id,)).fetchone())
                    self.assertEqual(conn.execute("SELECT COUNT(*) FROM file_cleanup_queue").fetchone()[0], 0)
                    conn.rollback()
                    conn.close()
                finally:
                    conn = self.database.get_db_connection()
                    conn.execute(f"DROP TRIGGER fail_{kind}_delete")
                    conn.commit()
                    conn.close()

    def test_data_07_unlink_failure_is_queued_and_retried(self):
        path = Path(self.server.STAGED_DIR) / "queued-delete"
        path.write_bytes(b"queued")
        conn = self.database.get_db_connection()
        record_id = conn.execute("INSERT INTO staged_files (filename, file_path) VALUES (?, ?)",
                                 (path.name, str(path))).lastrowid
        conn.commit()
        conn.close()
        with patch.object(self.server.os, "remove", side_effect=PermissionError("simulated unlink failure")):
            response = self.client.delete(f"/api/files/{record_id}", headers={"X-API-Key": self.server.API_KEY})
        self.assertEqual(response.status_code, 500)
        self.assertIn("queued", response.json["error"])
        self.assertEqual(path.read_bytes(), b"queued")
        conn = self.database.get_db_connection()
        self.assertIsNone(conn.execute("SELECT id FROM staged_files WHERE id = ?", (record_id,)).fetchone())
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM file_cleanup_queue").fetchone()[0], 1)
        conn.close()
        self.server.retry_queued_file_cleanup()
        self.server.retry_queued_file_cleanup()  # acknowledgment is idempotent
        self.assertFalse(path.exists())
        conn = self.database.get_db_connection()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM file_cleanup_queue").fetchone()[0], 0)
        conn.close()

    def test_api_05_bad_build_and_tls_field_types_return_client_errors(self):
        build = {"target_os": "linux", "arch": "amd64", "server_url": "http://example.invalid",
                 "jitter_min": 8, "jitter_max": 15, "persist_method": "none"}
        for field, value in (("jitter_min", None), ("jitter_max", []), ("server_url", None),
                             ("locale", None), ("profile_id", True)):
            with self.subTest(field=field):
                response = self.client.post("/api/build", json={**build, field: value},
                                            headers={"X-API-Key": self.server.API_KEY})
                self.assertEqual(response.status_code, 400)
        for field in ("target_os", "arch", "server_url", "jitter_min", "jitter_max", "persist_method"):
            with self.subTest(missing=field):
                incomplete = {key: value for key, value in build.items() if key != field}
                response = self.client.post("/api/build", json=incomplete,
                                            headers={"X-API-Key": self.server.API_KEY})
                self.assertEqual(response.status_code, 400)
                self.assertIn(field, response.json["error"])
        unsupported = self.client.post(
            "/api/build", json={**build, "target_os": "mac", "arch": "386"},
            headers={"X-API-Key": self.server.API_KEY},
        )
        self.assertEqual(unsupported.status_code, 400)
        self.assertIn("Invalid arch for mac", unsupported.json["error"])
        for value in ({"cn": None}, {"days": "wrong"}, {"san_ips": [None]}, {"san_dns": "example.com"}):
            with self.subTest(value=value):
                response = self.client.post("/api/tls/generate", json=value,
                                            headers={"X-API-Key": self.server.API_KEY})
                self.assertEqual(response.status_code, 400)

    def test_api_05_certificate_value_errors_preserve_active_bundle(self):
        headers = {"X-API-Key": self.server.API_KEY}
        with tempfile.TemporaryDirectory() as certs_dir, patch.object(self.server, "CERTS_DIR", certs_dir):
            valid = self.client.post("/api/tls/generate", json={"cn": "a" * 64}, headers=headers)
            self.assertEqual(valid.status_code, 200)
            bundle = Path(certs_dir) / "server.pem"
            previous = bundle.read_bytes()
            for data, field in (
                ({"cn": "a" * 65}, "cn"),
                ({"cn": "é" * 33}, "cn"),
                ({"cn": "é.example"}, "DNS"),
                ({"san_dns": ["é.example"]}, "DNS"),
                ({"days": "9" * 5000}, "days"),
            ):
                with self.subTest(data=data), patch(
                    "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key"
                ) as generate_key:
                    response = self.client.post("/api/tls/generate", json=data, headers=headers)
                    self.assertEqual(response.status_code, 400)
                    self.assertIn(field, response.json["error"])
                    generate_key.assert_not_called()
                    self.assertEqual(bundle.read_bytes(), previous)
                    self.assertEqual(sorted(p.name for p in Path(certs_dir).iterdir()), ["server.pem"])

    def test_tls_malformed_bodies_do_not_generate_or_replace_certificate(self):
        headers = {"X-API-Key": self.server.API_KEY}
        with tempfile.TemporaryDirectory() as cert_dir, patch.object(self.server, "CERTS_DIR", cert_dir):
            bundle = Path(cert_dir) / "server.pem"
            bundle.write_bytes(b"existing certificate fixture")
            for body, content_type in (("{", "application/json"), ("null", "application/json"),
                                       ("[]", "application/json"), ("", "application/json"),
                                       ("{}", "text/plain")):
                with self.subTest(body=body, content_type=content_type), patch(
                    "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key",
                    side_effect=AssertionError("Invalid request reached key generation"),
                ) as generate:
                    response = self.client.post("/api/tls/generate", data=body,
                                                content_type=content_type, headers=headers)
                    self.assertEqual(response.status_code, 400)
                    self.assertIsInstance(response.json["error"], str)
                    generate.assert_not_called()
                    self.assertEqual(bundle.read_bytes(), b"existing certificate fixture")
                    self.assertEqual(list(Path(cert_dir).iterdir()), [bundle])
            # An explicit empty object still requests the documented defaults.
            response = self.client.post("/api/tls/generate", json={}, headers=headers)
            self.assertEqual(response.status_code, 200)

    def test_task_invalid_inputs_are_rejected_before_database_access(self):
        headers = {"X-API-Key": self.server.API_KEY}
        valid = {"agent_id": self.agent_id, "command": "echo fixture", "type": "exec"}
        cases = [None, [], "text", {}, *[
            {**valid, field: value}
            for field in ("agent_id", "command")
            for value in (None, [], {}, 1, True, "", "  ", "bad\x00value")
        ], {**valid, "type": []}]
        with patch.object(self.server, "get_db_connection", side_effect=AssertionError("Opened DB")):
            for data in cases:
                with self.subTest(data=data):
                    response = self.client.post("/api/task", data=json.dumps(data),
                                                content_type="application/json", headers=headers)
                    self.assertEqual(response.status_code, 400)
                    self.assertIsInstance(response.json["error"], str)

    def test_task_valid_input_and_unknown_agent(self):
        headers = {"X-API-Key": self.server.API_KEY}
        command = "echo  spaced fixture  "
        response = self.client.post("/api/task", json={
            "agent_id": self.agent_id, "command": command,
        }, headers=headers)
        self.assertEqual(response.status_code, 200)
        task_id = response.json["task_id"]
        unknown = self.client.post("/api/task", json={
            "agent_id": "absent-agent", "command": "fixture",
        }, headers=headers)
        self.assertEqual(unknown.status_code, 404)
        conn = self.database.get_db_connection()
        try:
            rows = conn.execute("SELECT id, command, type FROM tasks").fetchall()
            self.assertEqual([tuple(row) for row in rows], [(task_id, command, "shell")])
        finally:
            conn.close()

    def test_task_database_failures_rollback_close_and_release_write_lock(self):
        headers = {"X-API-Key": self.server.API_KEY}
        for failure in ("insert", "commit"):
            with self.subTest(failure=failure):
                real = self.database.get_db_connection()
                class FailingConnection:
                    def execute(inner, sql, params=()):
                        result = real.execute(sql, params)
                        if failure == "insert" and sql.lstrip().startswith("INSERT INTO tasks"):
                            raise sqlite3.OperationalError("injected insert failure")
                        return result
                    def commit(inner):
                        raise sqlite3.OperationalError("injected commit failure")
                    def rollback(inner):
                        real.rollback()
                    def close(inner):
                        real.close()
                try:
                    with patch.object(self.server, "get_db_connection", return_value=FailingConnection()):
                        response = self.client.post("/api/task", json={
                            "agent_id": self.agent_id, "command": "echo fixture",
                        }, headers=headers)
                    self.assertEqual(response.status_code, 500)
                    self.assertIsInstance(response.json["error"], str)
                    with self.assertRaises(sqlite3.ProgrammingError):
                        real.execute("SELECT 1")
                    other = self.database.get_db_connection()
                    try:
                        other.execute("PRAGMA busy_timeout = 50")
                        other.execute("BEGIN IMMEDIATE")
                        self.assertEqual(other.execute("SELECT COUNT(*) FROM tasks").fetchone()[0], 0)
                    finally:
                        other.close()
                finally:
                    real.close()

    def test_certificate_cli_rotates_the_bundle_selected_by_server(self):
        import ssl
        cli = importlib.import_module("gen_cert")
        headers = {"X-API-Key": self.server.API_KEY}
        with tempfile.TemporaryDirectory() as cert_dir, patch.object(self.server, "CERTS_DIR", cert_dir), \
                patch.object(cli, "CERTS_DIR", cert_dir):
            first = self.client.post("/api/tls/generate", json={"cn": "dashboard.example"}, headers=headers)
            self.assertEqual(first.status_code, 200)
            output = io.StringIO()
            with patch.object(sys, "argv", ["gen_cert.py", "--cn", "cli.example"]), patch("sys.stdout", output):
                cli.main()
            status = self.client.get("/api/tls/status", headers=headers).json["cert"]
            self.assertEqual(status["cn"], "cli.example")
            self.assertNotEqual(status["spki_pin"], first.json["spki_pin"])
            self.assertIn(status["spki_pin"], output.getvalue())
            bundle = Path(cert_dir) / "server.pem"
            self.assertEqual(self.server._active_tls_paths(), (str(bundle), str(bundle)))
            self.assertEqual(bundle.stat().st_mode & 0o777, 0o600)
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(str(bundle))
            self.assertEqual(sorted(p.name for p in Path(cert_dir).iterdir()), ["server.pem"])
            previous = bundle.read_bytes()
            for operation in ("replace", "fsync"):
                output = io.StringIO()
                with self.subTest(operation=operation), patch.object(sys, "argv", ["gen_cert.py"]), \
                        patch("sys.stdout", output), patch.object(os, operation, side_effect=OSError("injected failure")):
                    with self.assertRaises(OSError):
                        cli.main()
                    self.assertNotIn("TLS Certificate Generated", output.getvalue())
                self.assertEqual(bundle.read_bytes(), previous)
                self.assertEqual(list(Path(cert_dir).glob(".server-pair-*")), [])

    def test_result_acknowledgement_is_encrypted_and_bound_to_submission(self):
        conn = self.database.get_db_connection()
        try:
            task_id = conn.execute(
                "INSERT INTO tasks (agent_id, command, status) VALUES (?, 'whoami', 'sent')",
                (self.agent_id,),
            ).lastrowid
            conn.commit()
        finally:
            conn.close()

        report_id = os.urandom(32).hex()
        output = "bound result"
        payload = {
            "agent_id": self.agent_id,
            "agent_secret": self.agent_secret,
            "task_id": task_id,
            "report_id": report_id,
            "output": output,
        }
        for already_recorded in (False, True):
            encrypted = self.crypto.encrypt_payload(self.key_hex, json.dumps(payload).encode())
            response = self.client.post(
                self.server.AGENT_PATH_RESULT,
                json={"kid": self.kid, "data": encrypted},
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json["kid"], self.kid)
            acknowledgement = json.loads(
                self.crypto.decrypt_payload(self.key_hex, response.json["data"])
            )
            self.assertEqual(acknowledgement, {
                "status": "ok",
                "agent_id": self.agent_id,
                "task_id": task_id,
                "report_id": report_id,
                "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
                "already_recorded": already_recorded,
            })

        invalid_payload = dict(payload, report_id="not-a-report-id")
        encrypted = self.crypto.encrypt_payload(
            self.key_hex, json.dumps(invalid_payload).encode()
        )
        response = self.client.post(
            self.server.AGENT_PATH_RESULT,
            json={"kid": self.kid, "data": encrypted},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"], "Invalid report ID")

    def test_generated_agent_resumes_cleanup_before_reinstalling_persistence(self):
        generated = self.server._generate_main_go("registry")
        lock = generated.index("if err := acquireAgentProcessLock()")
        initialize = generated.index("InitializeTelemetry()")
        state = generated.index("if err := initializeDurableResultState()")
        cleanup = generated.index("if resumePendingCleanup()")
        persistence = generated.index("funcs.InstallAutoUpdater()")
        checkin = generated.index("jobs, err := SyncDeviceState")
        self.assertLess(lock, initialize)
        self.assertLess(initialize, state)
        self.assertLess(state, cleanup)
        self.assertLess(cleanup, persistence)
        self.assertLess(cleanup, checkin)

    def test_task_01_self_destruct_lost_ack_retries_against_tombstone(self):
        """Lost flush acknowledgments must remain idempotent via a destroyed tombstone."""
        conn = self.database.get_db_connection()
        try:
            task_id = conn.execute(
                "INSERT INTO tasks (agent_id, command, status) VALUES (?, '__flush_cache__', 'sent')",
                (self.agent_id,),
            ).lastrowid
            conn.execute(
                "INSERT INTO tasks (agent_id, command, status) VALUES (?, 'whoami', 'complete')",
                (self.agent_id,),
            )
            conn.commit()
        finally:
            conn.close()
        payload = {"agent_id": self.agent_id, "agent_secret": self.agent_secret,
                   "task_id": task_id, "output": "fixture"}
        responses = []
        for _ in range(2):
            encrypted = self.crypto.encrypt_payload(self.key_hex, json.dumps(payload).encode())
            responses.append(self.client.post(self.server.AGENT_PATH_RESULT,
                                              json={"kid": self.kid, "data": encrypted}))
        self.assertEqual([r.status_code for r in responses], [200, 200])
        second = json.loads(self.crypto.decrypt_payload(self.key_hex, responses[1].json["data"]))
        self.assertTrue(second.get("already_recorded"))

        conn = self.database.get_db_connection()
        try:
            agent = conn.execute(
                "SELECT status, destroyed_at, secret_hash FROM agents WHERE id = ?",
                (self.agent_id,),
            ).fetchone()
            self.assertEqual(agent["status"], "destroyed")
            self.assertIsNotNone(agent["destroyed_at"])
            self.assertEqual(agent["secret_hash"], self.agent_secret_hash)
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM tasks WHERE agent_id = ?", (self.agent_id,)).fetchone()[0],
                1,
            )
            self.assertEqual(
                conn.execute("SELECT status FROM tasks WHERE id = ?", (task_id,)).fetchone()[0],
                "complete",
            )
        finally:
            conn.close()

        agents = self.client.get("/api/agents", headers={"X-API-Key": self.server.API_KEY}).json["agents"]
        self.assertEqual(agents, [])
        stats = self.client.get("/api/stats", headers={"X-API-Key": self.server.API_KEY}).json
        self.assertEqual(stats["agents"], 0)

        checkin = {"agent_id": self.agent_id, "agent_secret": self.agent_secret,
                   "hostname": "fixture", "os": "linux"}
        encrypted = self.crypto.encrypt_payload(self.key_hex, json.dumps(checkin).encode())
        response = self.client.post(self.server.AGENT_PATH_CHECKIN, json={"kid": self.kid, "data": encrypted})
        self.assertEqual(response.status_code, 410)
        self.assertEqual(response.json["error"], "Agent destroyed")

        task_response = self.client.post(
            "/api/task",
            headers={"X-API-Key": self.server.API_KEY},
            json={"agent_id": self.agent_id, "command": "whoami", "type": "exec"},
        )
        self.assertEqual(task_response.status_code, 404)

    def test_task_01_force_delete_rejects_flush_retry(self):
        """After a hard delete, retries fail auth so the agent fail-safe can wipe locally."""
        conn = self.database.get_db_connection()
        try:
            task_id = conn.execute(
                "INSERT INTO tasks (agent_id, command, status) VALUES (?, '__flush_cache__', 'sent')",
                (self.agent_id,),
            ).lastrowid
            conn.commit()
        finally:
            conn.close()
        payload = {"agent_id": self.agent_id, "agent_secret": self.agent_secret,
                   "task_id": task_id, "output": "fixture"}
        encrypted = self.crypto.encrypt_payload(self.key_hex, json.dumps(payload).encode())
        first = self.client.post(self.server.AGENT_PATH_RESULT, json={"kid": self.kid, "data": encrypted})
        self.assertEqual(first.status_code, 200)

        force = self.client.delete(
            f"/api/agents/{self.agent_id}/force",
            headers={"X-API-Key": self.server.API_KEY},
        )
        self.assertEqual(force.status_code, 200)

        encrypted = self.crypto.encrypt_payload(self.key_hex, json.dumps(payload).encode())
        retry = self.client.post(self.server.AGENT_PATH_RESULT, json={"kid": self.kid, "data": encrypted})
        self.assertEqual(retry.status_code, 403)
        self.assertEqual(retry.json["error"], "Invalid agent identity")

    def test_task_01_destroyed_tombstone_purges_after_grace_period(self):
        conn = self.database.get_db_connection()
        try:
            task_id = conn.execute(
                "INSERT INTO tasks (agent_id, command, status) VALUES (?, '__flush_cache__', 'complete')",
                (self.agent_id,),
            ).lastrowid
            conn.execute(
                "INSERT INTO results (task_id, output) VALUES (?, ?)",
                (task_id, "fixture"),
            )
            conn.execute(
                "UPDATE agents SET status = 'destroyed', "
                "destroyed_at = datetime('now', '-25 hours') WHERE id = ?",
                (self.agent_id,),
            )
            conn.commit()
        finally:
            conn.close()

        self.database.purge_destroyed_agents(max_age_hours=24)

        conn = self.database.get_db_connection()
        try:
            self.assertIsNone(
                conn.execute("SELECT 1 FROM agents WHERE id = ?", (self.agent_id,)).fetchone()
            )
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM results").fetchone()[0], 0)
        finally:
            conn.close()

    def test_sec_07_replay_record_lives_as_long_as_build_key(self):
        payload = {"agent_id": self.agent_id, "agent_secret": self.agent_secret,
                   "hostname": "fixture", "os": "linux"}
        encrypted = self.crypto.encrypt_payload(self.key_hex, json.dumps(payload).encode())
        envelope = {"kid": self.kid, "data": encrypted}
        self.assertEqual(self.client.post(self.server.AGENT_PATH_CHECKIN, json=envelope).status_code, 200)
        self.assertEqual(self.client.post(self.server.AGENT_PATH_CHECKIN, json=envelope).status_code, 409)
        conn = self.database.get_db_connection()
        conn.execute("UPDATE seen_nonces SET received_at = datetime('now', '-30 days') WHERE kid = ?", (self.kid,))
        conn.commit()
        conn.close()
        self.database.purge_retired_build_nonces()
        self.assertEqual(self.client.post(self.server.AGENT_PATH_CHECKIN, json=envelope).status_code, 409)
        conn = self.database.get_db_connection()
        conn.execute("DELETE FROM agents WHERE id = ?", (self.agent_id,))
        conn.execute("DELETE FROM builds WHERE key_id = ?", (self.kid,))
        conn.commit()
        conn.close()
        self.database.purge_retired_build_nonces()
        conn = self.database.get_db_connection()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM seen_nonces WHERE kid = ?", (self.kid,)).fetchone()[0], 0)
        conn.close()
        self.assertEqual(self.client.post(self.server.AGENT_PATH_CHECKIN, json=envelope).status_code, 403)

    def test_task_01_lost_response_requires_manual_abandonment_and_late_result_is_accepted(self):
        conn = self.database.get_db_connection()
        task_id = conn.execute("INSERT INTO tasks (agent_id, command, type) VALUES (?, ?, 'exec')",
                               (self.agent_id, "whoami")).lastrowid
        conn.commit()
        conn.close()
        payload = {"agent_id": self.agent_id, "agent_secret": self.agent_secret,
                   "hostname": "fixture", "os": "linux"}
        first = self.crypto.encrypt_payload(self.key_hex, json.dumps(payload).encode())
        response = self.client.post(self.server.AGENT_PATH_CHECKIN, json={"kid": self.kid, "data": first})
        self.assertEqual(response.status_code, 200)
        # Drop response without decrypting/using its task list.
        second = self.crypto.encrypt_payload(self.key_hex, json.dumps(payload).encode())
        response = self.client.post(self.server.AGENT_PATH_CHECKIN, json={"kid": self.kid, "data": second})
        self.assertEqual(response.status_code, 200)
        body = json.loads(self.crypto.decrypt_payload(self.key_hex, response.json["data"]))
        self.assertEqual(body["tasks"], [])
        history = self.client.get(f"/api/tasks/{self.agent_id}", headers={"X-API-Key": self.server.API_KEY}).json
        self.assertEqual(history["tasks"][0]["status"], "sent")
        self.assertTrue(history["tasks"][0]["delivery_uncertain"])
        response = self.client.post(f"/api/tasks/{task_id}/abandon", headers={"X-API-Key": self.server.API_KEY})
        self.assertEqual(response.status_code, 200)
        self.assertIn("may execute the command twice", response.json["warning"])
        conn = self.database.get_db_connection()
        self.assertEqual(conn.execute("SELECT status FROM tasks WHERE id = ?", (task_id,)).fetchone()[0], "abandoned")
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0], 1)
        conn.close()
        result_payload = {"agent_id": self.agent_id, "agent_secret": self.agent_secret,
                          "task_id": task_id, "output": "fixture output"}
        for attempt in range(2):
            encrypted = self.crypto.encrypt_payload(self.key_hex, json.dumps(result_payload).encode())
            response = self.client.post(self.server.AGENT_PATH_RESULT,
                                        json={"kid": self.kid, "data": encrypted})
            self.assertEqual(response.status_code, 200)
            decoded = json.loads(self.crypto.decrypt_payload(self.key_hex, response.json["data"]))
            self.assertEqual(decoded.get("already_recorded", False), attempt == 1)
        conn = self.database.get_db_connection()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM results WHERE task_id = ?", (task_id,)).fetchone()[0], 1)
        conn.close()

    def test_task_01_overlapping_checkins_dispatch_once(self):
        conn = self.database.get_db_connection()
        task_id = conn.execute("INSERT INTO tasks (agent_id, command, type) VALUES (?, ?, 'exec')",
                               (self.agent_id, "whoami")).lastrowid
        conn.commit()
        conn.close()
        payload = {"agent_id": self.agent_id, "agent_secret": self.agent_secret,
                   "hostname": "fixture", "os": "linux"}

        def checkin(_):
            encrypted = self.crypto.encrypt_payload(self.key_hex, json.dumps(payload).encode())
            response = self.server.app.test_client().post(
                self.server.AGENT_PATH_CHECKIN, json={"kid": self.kid, "data": encrypted}
            )
            self.assertEqual(response.status_code, 200)
            return json.loads(self.crypto.decrypt_payload(self.key_hex, response.json["data"]))["tasks"]

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(checkin, range(2)))
        self.assertEqual([task["id"] for batch in results for task in batch], [task_id])

    def test_tls_01_failed_rotation_keeps_matching_active_bundle(self):
        import ssl
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        with tempfile.TemporaryDirectory() as cert_dir, patch.object(self.server, "CERTS_DIR", cert_dir):
            headers = {"X-API-Key": self.server.API_KEY}
            first = self.client.post("/api/tls/generate", json={"cn": "first.example"}, headers=headers)
            self.assertEqual(first.status_code, 200)
            bundle = Path(cert_dir) / "server.pem"
            original = bundle.read_bytes()
            cert = x509.load_pem_x509_certificate(original)
            key = serialization.load_pem_private_key(
                original[original.index(b"-----BEGIN RSA PRIVATE KEY-----"):], password=None
            )
            self.assertEqual(cert.public_key().public_numbers(), key.public_key().public_numbers())
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(str(bundle), str(bundle))
            self.assertTrue(self.client.get("/api/tls/status", headers=headers).json["enabled"])
            for patch_name in ("replace", "fsync"):
                with self.subTest(patch_name=patch_name), patch.object(
                    self.server.os, patch_name, side_effect=OSError("simulated rotation failure")
                ):
                    failed = self.client.post("/api/tls/generate", json={"cn": "second.example"}, headers=headers)
                    self.assertEqual(failed.status_code, 500)
                    self.assertEqual(bundle.read_bytes(), original)
                    self.assertEqual(self.server._active_tls_paths(), (str(bundle), str(bundle)))
            self.assertEqual(list(Path(cert_dir).glob(".server-pair-*")), [])
            (Path(cert_dir) / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            (Path(cert_dir) / "server.key").write_bytes(
                key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption())
            )
            bundle.unlink()
            self.assertEqual(self.server._active_tls_paths(),
                             (str(Path(cert_dir) / "server.crt"), str(Path(cert_dir) / "server.key")))

    # ------------------------------------------------------------------
    # PERF-01: Agent refresh work does not scale with build history
    # ------------------------------------------------------------------

    def test_perf_01_query_plan_and_operation_scaling(self):
        """Query plan must use idx_builds_key_id without full scans, and SQLite VM steps remain constant at 1k vs 10k builds."""
        conn = self.database.get_db_connection()

        # Check EXPLAIN QUERY PLAN
        plan = conn.execute("""
            EXPLAIN QUERY PLAN
            SELECT a.id, a.hostname, a.ip, a.os, a.last_seen,
               COALESCE(b.transport_mode, '') AS transport_mode,
               b.decoy_domain
            FROM agents a
            LEFT JOIN builds b ON b.id = COALESCE(
                a.build_id,
                CASE WHEN a.key_id IS NOT NULL AND a.key_id != '' THEN (
                    SELECT b2.id FROM builds b2 WHERE b2.key_id = a.key_id
                    GROUP BY b2.key_id HAVING COUNT(*) = 1
                ) END
            )
            ORDER BY a.last_seen DESC
        """).fetchall()

        plan_str = " ".join([p[3] for p in plan])
        # Must NOT use AUTOMATIC COVERING INDEX or full table scan of builds
        self.assertNotIn("AUTOMATIC COVERING INDEX", plan_str)
        self.assertIn("idx_builds_key_id", plan_str)
        conn.close()

        # Measure SQLite VM step counts using libsqlite3
        lib_path = ctypes.util.find_library("sqlite3")
        if lib_path:
            lib = ctypes.CDLL(lib_path)
            SQLITE_STMTSTATUS_VM_STEP = 4

            def count_vm_steps(num_unrelated_builds):
                db_ptr = ctypes.c_void_p()
                lib.sqlite3_open(b":memory:", ctypes.byref(db_ptr))
                def exec_sql(s):
                    err = ctypes.c_char_p()
                    lib.sqlite3_exec(db_ptr, s.encode("utf-8"), None, None, ctypes.byref(err))
                    if err.value:
                        raise Exception(err.value.decode("utf-8"))

                exec_sql("""
                    CREATE TABLE agents (
                        id TEXT PRIMARY KEY,
                        hostname TEXT NOT NULL,
                        ip TEXT,
                        os TEXT,
                        key_id TEXT,
                        build_id INTEGER,
                        secret_hash TEXT,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE builds (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        filename TEXT NOT NULL,
                        target_os TEXT NOT NULL,
                        arch TEXT NOT NULL,
                        server_url TEXT NOT NULL,
                        callback_interval TEXT NOT NULL,
                        persistence TEXT DEFAULT 'none',
                        file_path TEXT NOT NULL,
                        file_size INTEGER DEFAULT 0,
                        key_id TEXT,
                        encryption_key TEXT,
                        cert_pin TEXT,
                        transport_mode TEXT DEFAULT 'http',
                        decoy_domain TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE INDEX idx_builds_key_id ON builds(key_id, id DESC);
                    CREATE INDEX idx_agents_last_seen ON agents(last_seen DESC);
                    INSERT INTO agents (id, hostname, key_id, last_seen) VALUES ('agent-1', 'host1', 'key-1', '2026-09-24 12:00:00');
                """)

                for i in range(num_unrelated_builds):
                    exec_sql(f"INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, transport_mode, decoy_domain) VALUES ('b_{i}', 'linux', 'amd64', 'http://1', '5s', '/tmp', 'other_{i}', 'http', NULL);")

                sql = """
                    SELECT a.id, a.hostname, a.ip, a.os, a.last_seen,
                           COALESCE(b.transport_mode, '') AS transport_mode,
                           b.decoy_domain
                    FROM agents a
                    LEFT JOIN builds b ON b.id = COALESCE(
                        a.build_id,
                        CASE WHEN a.key_id IS NOT NULL AND a.key_id != '' THEN (
                            SELECT b2.id FROM builds b2 WHERE b2.key_id = a.key_id
                            GROUP BY b2.key_id HAVING COUNT(*) = 1
                        ) END
                    )
                    ORDER BY a.last_seen DESC
                """
                stmt_ptr = ctypes.c_void_p()
                lib.sqlite3_prepare_v2(db_ptr, sql.encode("utf-8"), -1, ctypes.byref(stmt_ptr), None)
                while lib.sqlite3_step(stmt_ptr) == 100:
                    pass
                vm_steps = lib.sqlite3_stmt_status(stmt_ptr, SQLITE_STMTSTATUS_VM_STEP, 0)
                lib.sqlite3_finalize(stmt_ptr)
                lib.sqlite3_close(db_ptr)
                return vm_steps

            steps_1k = count_vm_steps(1000)
            steps_10k = count_vm_steps(10000)
            # The steps should be virtually identical and tiny (< 100 steps vs 70,000 without index)
            self.assertLess(steps_1k, 100)
            self.assertLess(steps_10k, 100)
            self.assertEqual(steps_1k, steps_10k)

    # ------------------------------------------------------------------
    # UI-01: Build and agent labels describe the same state
    # ------------------------------------------------------------------

    def test_ui_01_legacy_migration_and_idempotency(self):
        """Legacy pinned rows with transport_mode='http' are normalized to 'https_pinned'; repeated init preserves all fields."""
        conn = self.database.get_db_connection()
        conn.execute("DELETE FROM builds")

        # 1. Direct HTTP build
        conn.execute(
            "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, cert_pin, transport_mode) "
            "VALUES ('b_http', 'linux', 'amd64', 'http://1.1.1.1:5000', '5s', '/tmp/b1', 'k1', NULL, 'http')"
        )
        # 2. Pinned HTTPS build
        conn.execute(
            "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, cert_pin, transport_mode) "
            "VALUES ('b_https', 'linux', 'amd64', 'https://1.1.1.1:5000', '5s', '/tmp/b2', 'k2', 'pin123', 'https_pinned')"
        )
        # 3. Legacy row: cert_pin present but transport_mode is 'http'
        conn.execute(
            "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, cert_pin, transport_mode) "
            "VALUES ('b_legacy', 'linux', 'amd64', 'https://1.1.1.1:5000', '5s', '/tmp/b3', 'k3', 'pin_legacy', 'http')"
        )
        # 4. REALITY build
        conn.execute(
            "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, cert_pin, transport_mode, decoy_domain) "
            "VALUES ('b_reality', 'linux', 'amd64', 'http://127.0.0.1:5000', '5s', '/tmp/b4', 'k4', NULL, 'reality', 'decoy.org')"
        )
        conn.commit()
        conn.close()

        # Run init_db() to trigger migration
        self.database.init_db()

        conn = self.database.get_db_connection()
        builds = {b["filename"]: dict(b) for b in conn.execute("SELECT * FROM builds").fetchall()}
        conn.close()

        self.assertEqual(builds["b_http"]["transport_mode"], "http")
        self.assertEqual(builds["b_https"]["transport_mode"], "https_pinned")
        # Legacy row normalized:
        self.assertEqual(builds["b_legacy"]["transport_mode"], "https_pinned")
        self.assertEqual(builds["b_legacy"]["cert_pin"], "pin_legacy")
        self.assertEqual(builds["b_reality"]["transport_mode"], "reality")
        self.assertEqual(builds["b_reality"]["decoy_domain"], "decoy.org")

        # Run init_db() a second time; verify all rows remain unchanged
        self.database.init_db()

        conn = self.database.get_db_connection()
        builds_after = {b["filename"]: dict(b) for b in conn.execute("SELECT * FROM builds").fetchall()}
        conn.close()

        self.assertEqual(builds, builds_after)

    def test_ui_01_api_builds_and_agents_labels_agreement(self):
        """API endpoints /api/builds and /api/agents return consistent transport modes."""
        conn = self.database.get_db_connection()
        conn.execute("DELETE FROM agents")
        conn.execute("DELETE FROM builds")

        # Set up 3 scenarios:
        # 1. HTTP
        conn.execute("INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, transport_mode) VALUES ('b_http', 'linux', 'amd64', 'http://c2', '5s', '/tmp', 'k_http', 'http')")
        conn.execute("INSERT INTO agents (id, hostname, key_id) VALUES ('a_http', 'h_http', 'k_http')")

        # 2. HTTPS Pinned
        conn.execute("INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, cert_pin, transport_mode) VALUES ('b_pinned', 'linux', 'amd64', 'https://c2', '5s', '/tmp', 'k_pinned', 'pin_val', 'https_pinned')")
        conn.execute("INSERT INTO agents (id, hostname, key_id) VALUES ('a_pinned', 'h_pinned', 'k_pinned')")

        # 3. REALITY
        conn.execute("INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, file_path, key_id, transport_mode, decoy_domain) VALUES ('b_reality', 'linux', 'amd64', 'http://c2', '5s', '/tmp', 'k_reality', 'reality', 'decoy.com')")
        conn.execute("INSERT INTO agents (id, hostname, key_id) VALUES ('a_reality', 'h_reality', 'k_reality')")

        conn.commit()
        conn.close()

        builds_resp = self.client.get("/api/builds", headers={"X-API-Key": self.server.API_KEY})
        self.assertEqual(builds_resp.status_code, 200)
        builds = {b["filename"]: b for b in builds_resp.get_json()["builds"]}

        agents_resp = self.client.get("/api/agents", headers={"X-API-Key": self.server.API_KEY})
        self.assertEqual(agents_resp.status_code, 200)
        agents = {a["hostname"]: a for a in agents_resp.get_json()["agents"]}

        self.assertEqual(builds["b_http"]["transport_mode"], "http")
        self.assertEqual(agents["h_http"]["transport_mode"], "http")

        self.assertEqual(builds["b_pinned"]["transport_mode"], "https_pinned")
        self.assertEqual(agents["h_pinned"]["transport_mode"], "https_pinned")

        self.assertEqual(builds["b_reality"]["transport_mode"], "reality")
        self.assertEqual(agents["h_reality"]["transport_mode"], "reality")
        self.assertEqual(agents["h_reality"]["decoy_domain"], "decoy.com")


if __name__ == "__main__":
    unittest.main()
