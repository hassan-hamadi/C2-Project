"""Defensive web checks with no real database, network, or agent execution."""

import ast
from html.parser import HTMLParser
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

from flask import Flask, jsonify, request

from server import certificate_probe as probe
from server import test_agent_auth as auth_tests


ROOT = Path(__file__).resolve().parent.parent


class CertificateProbeTests(unittest.TestCase):
    def setUp(self):
        self.resolver = patch.object(probe.socket, "getaddrinfo").start()
        self.socket_factory = patch.object(probe.socket, "socket").start()
        self.tls_factory = patch.object(probe.ssl, "SSLContext").start()
        self.addCleanup(patch.stopall)
        self.resolver.return_value = [self.address("93.184.216.34")]
        self.connection = self.socket_factory.return_value.__enter__.return_value
        self.tls = self.tls_factory.return_value.wrap_socket.return_value.__enter__.return_value
        self.tls.get_unverified_chain.return_value = [b"leaf", b"issuer"]

    @staticmethod
    def address(ip):
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        endpoint = (ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443)
        return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", endpoint)

    def test_invalid_inputs_are_rejected_before_resolution(self):
        for value in (None, [], {}, 17, "", "https://example.com", "example.com:443", "a..example", "a" * 64 + ".com"):
            with self.subTest(value=value), self.assertRaises(probe.ProbeInputError):
                probe.measure_certificate_record(value)
        self.resolver.assert_not_called()

    def test_any_valid_public_hostname_can_be_measured(self):
        self.assertEqual(probe.measure_certificate_record("other.example"), 50)
        self.resolver.assert_called_once_with(
            "other.example", 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
        self.connection.connect.assert_called_once_with(("93.184.216.34", 443))

    def test_private_reserved_and_multicast_addresses_are_blocked(self):
        for ip in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "192.0.2.1", "224.0.0.1", "::1", "fc00::1", "ff02::1", "::ffff:127.0.0.1"):
            with self.subTest(ip=ip), self.assertRaises(probe.ProbeDenied):
                self.resolver.return_value = [self.address(ip)]
                probe.measure_certificate_record("example.com")
        self.socket_factory.assert_not_called()

    def test_mixed_public_and_private_answers_are_rejected(self):
        self.resolver.return_value = [self.address("93.184.216.34"), self.address("127.0.0.1")]
        with self.assertRaises(probe.ProbeDenied):
            probe.measure_certificate_record("example.com")
        self.socket_factory.assert_not_called()

    def test_normalized_domain_uses_validated_address_and_original_sni(self):
        self.assertEqual(probe.measure_certificate_record(" EXAMPLE.COM. "), 50)
        self.resolver.assert_called_once_with("example.com", 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        self.connection.connect.assert_called_once_with(("93.184.216.34", 443))
        self.tls_factory.return_value.wrap_socket.assert_called_once_with(self.connection, server_hostname="example.com")
        self.socket_factory.return_value.__exit__.assert_called_once()
        self.tls_factory.return_value.wrap_socket.return_value.__exit__.assert_called_once()

    def test_tls_failure_closes_the_socket(self):
        self.tls_factory.return_value.wrap_socket.side_effect = ssl.SSLError("fixture")
        with self.assertRaises(ssl.SSLError):
            probe.measure_certificate_record("example.com")
        self.socket_factory.return_value.__exit__.assert_called_once()


class MeasurementRouteTests(unittest.TestCase):
    def setUp(self):
        # Extract only these routes: importing app would initialize its database.
        tree = ast.parse((ROOT / "server/app.py").read_text())
        names = {"_require_api_key", "check_decoy_domain"}
        subset = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names], type_ignores=[])
        self.app = Flask("measurement_test")
        self.app.testing = True
        self.scope = dict(app=self.app, request=request, jsonify=jsonify, os=os,
                          hmac=hmac, API_KEY="fixture-key", _operator_session_valid=lambda: False,
                          measure_certificate_record=probe.measure_certificate_record,
                          REALITY_CERTIFICATE_LIMIT_BYTES=probe.REALITY_CERTIFICATE_LIMIT_BYTES,
                          ProbeInputError=probe.ProbeInputError, ProbeDenied=probe.ProbeDenied)
        exec(compile(subset, "server/app.py", "exec"), self.scope)
        self.client = self.app.test_client()
        self.headers = {"X-API-Key": "fixture-key"}

    def test_authentication_is_still_required(self):
        self.scope["measure_certificate_record"] = Mock()
        response = self.client.post("/api/reality/check-domain", json={"domain": "example.com"})
        self.assertEqual(response.status_code, 401)
        self.scope["measure_certificate_record"].assert_not_called()

    def test_bad_json_shapes_and_domain_types_return_400(self):
        for body in ([], "example.com", {}, {"domain": None}, {"domain": []}):
            with self.subTest(body=body):
                response = self.client.post("/api/reality/check-domain", json=body, headers=self.headers)
                self.assertEqual(response.status_code, 400)

    def test_measurement_reports_size_limit_and_fit(self):
        self.scope["measure_certificate_record"] = Mock(return_value=9000)
        response = self.client.post("/api/reality/check-domain", json={"domain": "example.com"}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.scope["measure_certificate_record"].assert_called_once_with("example.com")
        self.assertEqual(response.json["size_bytes"], 9000)
        self.assertEqual(response.json["limit_bytes"], 8192)
        self.assertIs(response.json["fits"], False)

        self.scope["measure_certificate_record"] = Mock(return_value=8192)
        response = self.client.post("/api/reality/check-domain", json={"domain": "example.com"}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertIs(response.json["fits"], True)

    def test_probe_errors_have_distinct_statuses(self):
        for error, expected in ((probe.ProbeDenied("fixture"), 403),
                                (TimeoutError(), 504), (socket.gaierror(), 502),
                                (ssl.SSLError(), 502), (OSError(), 502)):
            with self.subTest(error=type(error).__name__):
                self.scope["measure_certificate_record"] = Mock(side_effect=error)
                response = self.client.post("/api/reality/check-domain", json={"domain": "example.com"}, headers=self.headers)
                self.assertEqual(response.status_code, expected)


class TestDatabaseGuardTests(unittest.TestCase):
    def test_cached_database_is_rejected_before_app_import_or_deletion(self):
        class FixtureCase(auth_tests.AgentAuthorizationTests):
            pass

        original_env = os.environ.get("C2_DB_PATH")
        original_path = sys.path[:]
        database = SimpleNamespace(DB_PATH=str(ROOT / "do-not-open.db"), get_db_connection=Mock())
        try:
            with patch.object(auth_tests.importlib, "import_module", return_value=database) as importer:
                with self.assertRaisesRegex(RuntimeError, "Refusing to modify"):
                    FixtureCase.setUpClass()
                importer.assert_called_once_with("database")
                database.get_db_connection.assert_not_called()
        finally:
            FixtureCase.doClassCleanups()
        self.assertEqual(os.environ.get("C2_DB_PATH"), original_env)
        self.assertEqual(sys.path, original_path)

    def test_database_path_is_checked_again_before_each_destructive_setup(self):
        class FixtureCase(auth_tests.AgentAuthorizationTests):
            pass

        FixtureCase.test_db_path = Path("/tmp/review-fixture.db").resolve()
        FixtureCase.database = SimpleNamespace(DB_PATH=str(ROOT / "do-not-open.db"), get_db_connection=Mock())
        with self.assertRaisesRegex(RuntimeError, "Refusing to modify"):
            FixtureCase().setUp()
        FixtureCase.database.get_db_connection.assert_not_called()


class Tags(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.tags = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def with_class(self, name):
        return next(attrs for _, attrs in self.tags if name in attrs.get("class", "").split())


class PublicAssetsTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node.js is required for dashboard rendering checks")
    def test_untrusted_strings_remain_data_in_rendered_attributes_and_handlers(self):
        value = "lab's \"quoted\" \\ name <tag> & \n"
        original_path = 'report" data-review="marker'
        render = r'''
const {createDashboard,flush} = require('./server/tests/dashboard_harness.cjs');
const fs=require('node:fs');
(async()=>{
 const fixture=JSON.parse(fs.readFileSync(0,'utf8'));
 const {context,get}=createDashboard();
 context.apiFetch=async()=>({ok:true,json:async()=>({agents:[{id:fixture.value,hostname:'fixture',os:'linux',ip:'fixture',last_seen:'2026-09-24T00:00:00Z'}]})});
 context.refreshAgents(); await flush();
 context.apiFetch=async()=>({ok:true,json:async()=>({loot:[{id:1,filename:'fixture',agent_id:fixture.value,original_path:fixture.path}]})});
 context.loadLoot(); await flush();
 context.apiFetch=async()=>({ok:true,json:async()=>({builds:[{id:1,filename:fixture.value,target_os:'fixture',arch:'fixture',file_size:1}]})});
 context.loadBuilds(); await flush();
 console.log(JSON.stringify({agents:get('agent-list').innerHTML,loot:get('loot-list').innerHTML,builds:get('payload-list').innerHTML}));
})();
'''
        result = subprocess.run(["node", "-e", render], input=json.dumps({"value": value, "path": original_path}),
                                text=True, capture_output=True, cwd=ROOT, check=True, timeout=10)
        markup = json.loads(result.stdout)
        agents = Tags(markup["agents"])
        self.assertEqual(agents.with_class("agent-card")["data-agent-id"], value)
        path_attributes = Tags(markup["loot"]).with_class("loot-path")
        self.assertEqual(path_attributes["title"], original_path)
        self.assertNotIn("data-review", path_attributes)
        handlers = [agents.with_class("agent-card")["onclick"],
                    agents.with_class("btn-delete-agent")["onclick"],
                    Tags(markup["builds"]).with_class("btn-download")["onclick"]]
        execute = r'''
const vm=require('node:vm'),fs=require('node:fs'),calls=[];
for(const handler of JSON.parse(fs.readFileSync(0,'utf8')))
 vm.runInNewContext(handler,{selectAgent:x=>calls.push(x),deleteAgent:x=>calls.push(x),downloadBuild:(id,x)=>calls.push(x),event:{stopPropagation(){}}});
console.log(JSON.stringify(calls));
'''
        result = subprocess.run(["node", "-e", execute], input=json.dumps(handlers), text=True,
                                capture_output=True, check=True, timeout=10)
        self.assertEqual(json.loads(result.stdout), [value, value, value])


if __name__ == "__main__":
    unittest.main()
