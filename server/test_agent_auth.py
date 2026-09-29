"""Authorization checks for agent identity and staged-file assignments."""

import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


class AgentAuthorizationTests(unittest.TestCase):
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
        cls.database = importlib.import_module("database")
        cls._assert_test_database()
        cls.crypto = importlib.import_module("crypto")
        storage = importlib.import_module("storage_permissions")
        private_directory = storage.private_directory
        with patch.object(storage, "private_directory", side_effect=lambda path, **kwargs:
                          private_directory(Path(cls.temp_dir.name) / Path(path).name, **kwargs)):
            cls.server = importlib.import_module("app")
        if cls.server.get_db_connection is not cls.database.get_db_connection:
            raise RuntimeError("Refusing to use a cached app with a different database connection.")
        cls.addClassCleanup(setattr, cls.server, "LOOT_DIR", cls.server.LOOT_DIR)
        cls.server.LOOT_DIR = str(Path(cls.temp_dir.name) / "loot")
        Path(cls.server.LOOT_DIR).mkdir(exist_ok=True)

    @classmethod
    def _assert_test_database(cls):
        if Path(cls.database.DB_PATH).resolve() != cls.test_db_path:
            raise RuntimeError(
                "Refusing to modify a database outside this test's temporary directory. "
                "Run the authorization tests in a fresh process."
            )

    def setUp(self):
        self._assert_test_database()
        self.client = self.server.app.test_client()
        conn = self.database.get_db_connection()
        for table in ("results", "tasks", "agents", "staged_files", "builds", "seen_nonces"):
            conn.execute(f"DELETE FROM {table}")
        self.key_hex, self.kid = self.crypto.generate_key()
        conn.execute(
            "INSERT INTO builds (filename, target_os, arch, server_url, callback_interval, "
            "file_path, key_id, encryption_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("test-agent", "linux", "amd64", "https://localhost", "8s-15s", "unused",
             self.kid, self.key_hex),
        )
        self.file_path = Path(self.temp_dir.name) / "stage.bin"
        self.file_path.write_bytes(b"test staged content")
        self.file_id = conn.execute(
            "INSERT INTO staged_files (filename, file_path, file_size) VALUES (?, ?, ?)",
            ("stage.bin", str(self.file_path), self.file_path.stat().st_size),
        ).lastrowid
        conn.commit()
        conn.close()
        self.secret_a = "11" * 32
        self.secret_b = "22" * 32

    def encrypted_post(self, path, payload):
        envelope = {
            "kid": self.kid,
            "data": self.crypto.encrypt_payload(self.key_hex, json.dumps(payload).encode()),
        }
        return self.client.post(path, json=envelope)

    def checkin(self, agent_id, secret):
        return self.encrypted_post(
            self.server.AGENT_PATH_CHECKIN,
            {"agent_id": agent_id, "agent_secret": secret, "hostname": "lab", "os": "linux"},
        )

    def download(self, agent_id, secret, task_id, file_id=None):
        return self.client.get(
            f"{self.server.AGENT_PATH_FILES}/{self.file_id if file_id is None else file_id}",
            headers={
                "X-Agent-ID": agent_id,
                "X-Task-ID": str(task_id),
                "Authorization": "Bearer " + secret,
            },
        )

    def test_download_requires_agent_secret_and_matching_sent_task(self):
        self.assertEqual(self.checkin("agent-a", self.secret_a).status_code, 200)
        self.assertEqual(self.checkin("agent-b", self.secret_b).status_code, 200)
        queued = self.client.post(
            "/api/task",
            json={"agent_id": "agent-a", "command": f"download {self.file_id} target.bin"},
            headers={"X-API-Key": self.server.API_KEY},
        )
        self.assertEqual(queued.status_code, 200)
        task_id = queued.json["task_id"]
        self.assertEqual(self.checkin("agent-a", self.secret_a).status_code, 200)

        path = f"{self.server.AGENT_PATH_FILES}/{self.file_id}"
        self.assertEqual(self.client.get(path).status_code, 401)
        self.assertEqual(self.download("agent-a", self.secret_b, task_id).status_code, 401)
        self.assertEqual(self.download("agent-b", self.secret_b, task_id).status_code, 403)
        self.assertEqual(self.download("agent-a", self.secret_a, task_id + 1).status_code, 403)
        self.assertEqual(self.download("agent-a", self.secret_a, task_id, self.file_id + 1).status_code, 403)

        allowed = self.download("agent-a", self.secret_a, task_id)
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.data, b"test staged content")
        self.assertEqual(allowed.headers["Cache-Control"], "private, no-store")
        allowed.close()

        result = self.encrypted_post(
            self.server.AGENT_PATH_RESULT,
            {"task_id": task_id, "agent_id": "agent-a", "agent_secret": self.secret_a,
             "output": "Saved"},
        )
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.download("agent-a", self.secret_a, task_id).status_code, 403)

    def test_shared_build_key_cannot_impersonate_registered_agent(self):
        self.assertEqual(self.checkin("agent-a", self.secret_a).status_code, 200)
        self.assertEqual(self.checkin("agent-a", self.secret_b).status_code, 403)
        missing = self.encrypted_post(
            self.server.AGENT_PATH_CHECKIN, {"agent_id": "agent-a"}
        )
        self.assertEqual(missing.status_code, 400)
        conn = self.database.get_db_connection()
        stored = conn.execute("SELECT secret_hash FROM agents WHERE id = 'agent-a'").fetchone()
        conn.close()
        self.assertEqual(stored["secret_hash"], hashlib.sha256(bytes.fromhex(self.secret_a)).hexdigest())

    def test_result_and_upload_require_the_registered_agent_secret(self):
        self.assertEqual(self.checkin("agent-a", self.secret_a).status_code, 200)
        self.assertEqual(self.checkin("agent-b", self.secret_b).status_code, 200)
        queued = self.client.post(
            "/api/task",
            json={"agent_id": "agent-a", "command": "whoami"},
            headers={"X-API-Key": self.server.API_KEY},
        )
        task_id = queued.json["task_id"]
        self.assertEqual(self.checkin("agent-a", self.secret_a).status_code, 200)

        forged = self.encrypted_post(
            self.server.AGENT_PATH_RESULT,
            {"task_id": task_id, "agent_id": "agent-a", "agent_secret": self.secret_b,
             "output": "forged"},
        )
        self.assertEqual(forged.status_code, 403)
        other_agent = self.encrypted_post(
            self.server.AGENT_PATH_RESULT,
            {"task_id": task_id, "agent_id": "agent-b", "agent_secret": self.secret_b,
             "output": "forged"},
        )
        self.assertEqual(other_agent.status_code, 403)

        body = b"upload payload"
        meta = {"agent_id": "agent-a", "agent_secret": self.secret_b,
                "sha256": hashlib.sha256(body).hexdigest()}
        auth = {"kid": self.kid,
                "data": self.crypto.encrypt_payload(self.key_hex, json.dumps(meta).encode())}
        upload = self.client.post(
            self.server.AGENT_PATH_UPLOAD,
            data={"auth": json.dumps(auth), "file": (io.BytesIO(body), "sample.bin")},
        )
        self.assertEqual(upload.status_code, 403)

        meta["agent_secret"] = self.secret_a
        auth["data"] = self.crypto.encrypt_payload(self.key_hex, json.dumps(meta).encode())
        accepted = self.client.post(
            self.server.AGENT_PATH_UPLOAD,
            data={"auth": json.dumps(auth), "file": (io.BytesIO(body), "sample.bin")},
        )
        self.assertEqual(accepted.status_code, 200)


if __name__ == "__main__":
    unittest.main()
