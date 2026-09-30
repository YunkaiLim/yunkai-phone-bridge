"""GET /health acceptance entirely in-process; no sockets, device, or host lifecycle."""
import ast
import asyncio
import builtins
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
import logging
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch
import urllib.request

from starlette.requests import Request

import control_center
import passive_health
from phone_bridge import AndroidBridge
from reflex_native import NativeSemanticBridge
import reflex_mcp
import reflex_status
import reflex_tap
from reflex_tap import ReflexTapExecutor, RuntimePolicy
import server as server_module
from server import server
from test_reflex_tap import CANARY

ROOT = Path(__file__).parent
FIELDS = {
    "service", "schema_version", "version", "localhost_only", "observed_at", "status",
    "reflex_status_contract", "runtime_epoch", "policy_enabled", "allowed_ref_count",
    "production_atomic_context_guard", "production_backend_bound", "live_reflex_ready",
    "expected_post_predicates", "operation_correlation", "request_correlation",
    "observation_correlation", "durable_exactly_once", "automatic_action_retry",
}


def scope(**overrides):
    return {"type": "http", "http_version": "1.1", "scheme": "http", "method": "GET",
            "path": "/health", "raw_path": b"/health", "root_path": "", "query_string": b"",
            "client": ("127.0.0.1", 32100), "server": ("127.0.0.1", 8790),
            "headers": [(b"host", b"127.0.0.1:8790")], **overrides}


async def no_receive():
    raise AssertionError("health must not consume a body or device stream")


class PassiveHealthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.loop = asyncio.new_event_loop()
        cls.loop_errors = []
        cls.loop.set_exception_handler(lambda loop, context: cls.loop_errors.append(True))

    @classmethod
    def tearDownClass(cls):
        cls.loop.close()
        if cls.loop_errors:
            raise AssertionError("unexpected asyncio callback failure")

    def setUp(self):
        self.policy = patch.object(reflex_status, "load_runtime_policy", return_value=RuntimePolicy())
        self.policy_mock = self.policy.start()
        self.addCleanup(self.policy.stop)

    def call(self, **changes):
        return self.loop.run_until_complete(passive_health.get_health(Request(scope(**changes), receive=no_receive)))

    def body(self, **changes):
        response = self.call(**changes)
        self.assertEqual(response.status_code, 200)
        return json.loads(response.body)

    def no_effects(self):
        stack, mocks = ExitStack(), []
        self.addCleanup(stack.close)
        for owner, names in (
            (AndroidBridge, ("__init__", "_run", "_run_with_stdin", "devices", "select_device",
                             "screenshot_png", "ui_xml", "surface_identity", "refresh_wireless_connection")),
            (NativeSemanticBridge, ("__init__", "observe", "execute_guarded", "_device")),
            (ReflexTapExecutor, ("tap", "_permission")),
            (server_module, ("_bridge", "_control_center_request", "get_phone_automation_status",
                             "run_phone_daily_routine", "save_phone_daily_routine", "stop_phone_automation")),
            (server_module.LocalVisionAdapter, ("__init__",)),
            (control_center, ("load_config", "_read_json_file", "_write_json_file", "build_observation")),
            (control_center.ControlState, ("__init__", "status", "log", "public_config", "get_routine",
                                          "start_agent", "stop_agent", "_agent_loop", "_scheduler_loop")),
            (control_center.DeepSeekClient, ("__init__", "decide")),
            (logging.Logger, ("_log",)),
            (subprocess, ("run", "Popen")),
            (socket, ("create_connection", "getaddrinfo")),
            (socket.socket, ("__init__",)),
            (urllib.request, ("urlopen",)),
            (Path, ("read_text", "read_bytes", "write_text", "write_bytes")),
        ):
            for name in names:
                mocks.append(stack.enter_context(patch.object(owner, name, side_effect=AssertionError("forbidden effect"))))
        original_import = builtins.__import__
        def guarded_import(name, *args, **kwargs):
            if name.split(".")[0] in {"torch", "transformers", "diffusers", "onnxruntime", "llama_cpp",
                                      "local_vision", "control_center"}:
                raise AssertionError("model/runtime import forbidden")
            return original_import(name, *args, **kwargs)
        stack.enter_context(patch.object(builtins, "__import__", guarded_import))
        return stack, mocks

    def test_direct_handler_with_all_device_runtime_model_log_network_tripwires(self):
        stack, mocks = self.no_effects()
        with stack:
            body = self.body()
        self.assertEqual(body["status"], "ok")
        for mocked in mocks:
            mocked.assert_not_called()

    def test_real_policy_loader_reads_only_fixed_bounded_policy(self):
        raw = json.dumps({"schema_version": reflex_tap.POLICY_CONTRACT, "enabled": True,
                          "allowed_binding_ids": ["a" * 64]}).encode()
        reads = []
        class Bounded(io.BytesIO):
            def read(self, size=-1):
                reads.append(size)
                return super().read(size)
        paths = []
        def open_policy(path, *args, **kwargs):
            self.assertEqual(path, reflex_tap._POLICY_FILE)
            self.assertEqual(args, ("rb",))
            self.assertEqual(kwargs, {})
            paths.append(True)
            return Bounded(raw)
        stack, mocks = self.no_effects()
        with stack, patch.object(reflex_status, "load_runtime_policy", reflex_tap.load_runtime_policy), patch.object(Path, "open", open_policy):
            body = self.body()
        self.assertEqual(paths, [True])
        self.assertEqual(reads, [8193])
        self.assertEqual((body["policy_enabled"], body["allowed_ref_count"]), (True, 1))
        self.assertNotIn("a" * 64, json.dumps(body))
        for mocked in mocks:
            mocked.assert_not_called()

    def test_exact_schema_field_types_identity_and_size_bound(self):
        response = self.call()
        body = json.loads(response.body)
        self.assertEqual(set(body), FIELDS)
        self.assertEqual(len(body), 19)
        self.assertEqual(body["service"], "yunkai-phonebridge")
        self.assertEqual(body["schema_version"], "phonebridge.health.v1")
        self.assertEqual(body["version"], "0.7.2")
        self.assertEqual(body["reflex_status_contract"], "phonebridge.reflex.status.v1")
        self.assertIs(body["localhost_only"], True)
        strings = {"service", "schema_version", "version", "observed_at", "status", "reflex_status_contract", "runtime_epoch"}
        for key in FIELDS:
            self.assertIs(type(body[key]), str if key in strings else int if key == "allowed_ref_count" else bool)
        schema = passive_health.health_schema()
        self.assertEqual(set(schema["properties"]), FIELDS)
        self.assertEqual(set(schema["required"]), FIELDS)
        self.assertFalse(schema["additionalProperties"])
        self.assertLessEqual(len(response.body), 2048)
        self.assertEqual(int(response.headers["content-length"]), len(response.body))
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertNotIn("access-control-allow-origin", response.headers)

    def test_same_in_process_epoch_as_passive_mcp_status(self):
        body = self.body()
        status = self.loop.run_until_complete(server.call_tool("get_android_reflex_status", {})).structured_content
        self.assertEqual(body["runtime_epoch"], status["runtime_epoch"])
        self.assertEqual(body["runtime_epoch"], reflex_mcp.executor.runtime_epoch)

    def test_fresh_timestamp_generated_per_call_by_service(self):
        before = datetime.now(timezone.utc).timestamp()
        first = self.body()
        after = datetime.now(timezone.utc).timestamp()
        parsed = datetime.fromisoformat(first["observed_at"].replace("Z", "+00:00")).timestamp()
        self.assertTrue(before - .001 <= parsed <= after)
        with patch.object(passive_health, "_observed_at", side_effect=[
                "2026-09-23T00:00:00.000Z", "2026-09-23T00:00:01.000Z"]):
            self.assertNotEqual(self.body()["observed_at"], self.body()["observed_at"])

    def test_missing_unreadable_policy_is_service_healthy_disabled(self):
        for error in (FileNotFoundError(CANARY), PermissionError(CANARY), OSError(CANARY)):
            with patch.object(reflex_status, "load_runtime_policy", reflex_tap.load_runtime_policy), patch.object(Path, "open", side_effect=error):
                body = self.body()
            self.assertEqual((body["status"], body["policy_enabled"], body["allowed_ref_count"]), ("ok", False, 0))
            self.assertNotIn(CANARY, json.dumps(body))

    def test_malformed_policy_is_service_healthy_disabled(self):
        for raw in (b"{", b"null", b"x" * 8193, b'{"enabled":true}', json.dumps({
                "schema_version": reflex_tap.POLICY_CONTRACT, "enabled": True, "allowed_binding_ids": [CANARY]}).encode()):
            with patch.object(reflex_status, "load_runtime_policy", reflex_tap.load_runtime_policy), patch.object(Path, "open", return_value=io.BytesIO(raw)):
                body = self.body()
            self.assertEqual((body["status"], body["policy_enabled"], body["allowed_ref_count"]), ("ok", False, 0))
            self.assertNotIn(CANARY, json.dumps(body))

    def test_enabled_fixture_exposes_only_boolean_count_no_readiness_promotion(self):
        self.policy_mock.return_value = RuntimePolicy(True, ("a" * 64, "b" * 64))
        body = self.body()
        self.assertEqual((body["policy_enabled"], body["allowed_ref_count"]), (True, 2))
        for name in ("production_atomic_context_guard", "production_backend_bound", "live_reflex_ready",
                     "durable_exactly_once", "automatic_action_retry"):
            self.assertIs(body[name], False)
        for ref in ("a" * 64, "b" * 64, "allowed_binding_ids"):
            self.assertNotIn(ref, json.dumps(body))

    def test_valid_loopback_ipv4_ipv6_and_localhost_host(self):
        for peer, local, authority in (("127.0.0.1", "127.0.0.1", b"127.0.0.1:8790"),
                                       ("::1", "::1", b"[::1]:8790"),
                                       ("127.0.0.1", "127.0.0.1", b"localhost:8790")):
            self.assertEqual(self.call(client=(peer, 1), server=(local, 8790), headers=[(b"host", authority)]).status_code, 200)

    def test_non_loopback_missing_or_malformed_peer_local_server_denied(self):
        for changes in ({"client": None}, {"client": ("192.168.1.10", 1)}, {"client": ("localhost", 1)},
                        {"client": ("::ffff:127.0.0.1", 1)}, {"server": ("0.0.0.0", 8790)},
                        {"server": ("192.168.1.1", 8790)}, {"server": ("127.0.0.1", True)},
                        {"server": None}, {"scheme": "https"}, {"query_string": b"secret=private"}):
            self.assertEqual(self.call(**changes).status_code, 403)
        self.policy_mock.assert_not_called()

    def test_host_confusion_duplicates_dns_rebinding_and_bad_origins_denied(self):
        for headers in ([], [(b"host", b"private.invalid:8790")], [(b"host", b"127.0.0.1:8791")],
                        [(b"host", b"127.0.0.1:8790@private.invalid")],
                        [(b"host", b"127.0.0.1:8790"), (b"HOST", b"localhost:8790")],
                        [(b"host", b"127.0.0.1:8790"), (b"origin", b"https://private.invalid")],
                        [(b"host", b"127.0.0.1:8790"), (b"origin", b"null")]):
            response = self.call(headers=headers)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response.body, b"")
        self.policy_mock.assert_not_called()

    def test_forwarding_headers_rejected_even_with_loopback_claims(self):
        for key in (b"forwarded", b"x-forwarded-for", b"x-forwarded-host", b"x-forwarded-proto", b"X-Forwarded-Anything"):
            self.assertEqual(self.call(headers=[(b"host", b"127.0.0.1:8790"), (key, b"127.0.0.1")]).status_code, 403)
        self.policy_mock.assert_not_called()

    def test_only_get_no_body_or_query_inputs(self):
        for method in ("HEAD", "POST", "PUT", "DELETE", "OPTIONS"):
            response = self.call(method=method)
            self.assertEqual(response.status_code, 405)
            self.assertEqual(response.headers["allow"], "GET")
            self.assertEqual(response.body, b"")
        self.policy_mock.assert_not_called()

    def test_malformed_status_exact_fields_types_and_identity_fail_closed(self):
        base = reflex_status.read_status(reflex_mcp.executor.runtime_epoch)
        cases = [None, [], {}, {**base, "extra": CANARY}]
        for key, values in (
            ("schema_version", ("wrong.v1", CANARY)),
            ("semantic_tap_contract", ("wrong.v1",)),
            ("policy_contract", ("wrong.v1",)),
            ("runtime_epoch_scope", ("device_identity",)),
            ("production_backend_scope", ("unreviewed",)),
            ("policy_enabled", ("true", 1, None)),
            ("allowed_ref_count", (True, -1, 33, float("nan"), float("inf"), "1")),
            ("stock_adb_atomic_context_guard", (True, 0)),
            ("live_reflex_ready", (True,)),
            ("production_backend_bound", (True,)),
            ("expected_post_predicates", (False, 1)),
        ):
            cases.extend({**base, key: value} for value in values)
        for bad in cases:
            with patch.object(passive_health, "read_status", return_value=bad):
                response = self.call()
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.body, b"")

    def test_version_invalid_epoch_or_epoch_mismatch_fail_closed(self):
        base = reflex_status.read_status(reflex_mcp.executor.runtime_epoch)
        with patch.object(passive_health, "PHONE_BRIDGE_VERSION", CANARY):
            self.assertEqual(self.call().status_code, 503)
        with patch.object(reflex_mcp.executor, "runtime_epoch", CANARY):
            self.assertEqual(self.call().status_code, 503)
        with patch.object(passive_health, "read_status", return_value={**base, "runtime_epoch": "00000000-0000-4000-8000-000000000001"}):
            self.assertEqual(self.call().status_code, 503)

    def test_executor_or_epoch_change_during_observation_fails_closed(self):
        executor = reflex_mcp.executor
        base = reflex_status.read_status(executor.runtime_epoch)
        def change():
            reflex_mcp.executor = object()
            return base
        try:
            with patch.object(passive_health, "read_status", side_effect=lambda epoch: change()):
                self.assertEqual(self.call().status_code, 503)
        finally:
            reflex_mcp.executor = executor
        original_epoch = executor.runtime_epoch
        try:
            def change_epoch(epoch):
                executor.runtime_epoch = "00000000-0000-4000-8000-000000000001"
                return base
            with patch.object(passive_health, "read_status", side_effect=change_epoch):
                self.assertEqual(self.call().status_code, 503)
        finally:
            executor.runtime_epoch = original_epoch

    def test_invalid_clock_or_oversized_encoded_response_fails_closed(self):
        for invalid in (None, CANARY, "2026-99-23T00:00:00.000Z", "2026-09-23T00:00:00Z"):
            with patch.object(passive_health, "_observed_at", return_value=invalid):
                self.assertEqual(self.call().status_code, 503)
        with patch.object(passive_health.json, "dumps", return_value="x" * 2049):
            response = self.call()
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.body, b"")

    def test_no_cached_health_after_failed_observation_and_no_raw_errors_or_logs(self):
        self.assertEqual(self.call().status_code, 200)
        stream = io.StringIO()
        with redirect_stdout(stream), redirect_stderr(stream), patch.object(passive_health, "read_status", side_effect=RuntimeError(CANARY)):
            response = self.call()
        self.assertEqual((response.status_code, response.body), (503, b""))
        self.assertEqual(stream.getvalue(), "")
        self.assertNotIn(CANARY, str(response.headers))

    def test_route_registered_once_on_existing_mcp_app_without_new_listener(self):
        app = server.streamable_http_app(streamable_http_path="/mcp", json_response=True, stateless_http=True)
        routes = [r for r in app.routes if getattr(r, "path", None) == "/health"]
        self.assertEqual(len(routes), 1)
        self.assertIs(routes[0].endpoint, passive_health.get_health)
        self.assertFalse(routes[0].include_in_schema)
        self.assertEqual(len([r for r in app.routes if getattr(r, "path", None) == "/mcp"]), 1)
        self.assertEqual(len(server._custom_starlette_routes), 1)

    def test_in_process_asgi_get_and_head_with_effect_tripwires(self):
        app = server.streamable_http_app(streamable_http_path="/mcp", json_response=True, stateless_http=True)
        async def invoke(method):
            messages = []
            async def send(message):
                messages.append(message)
            await app(scope(method=method), no_receive, send)
            return messages
        stack, mocks = self.no_effects()
        with stack:
            get = self.loop.run_until_complete(invoke("GET"))
            head = self.loop.run_until_complete(invoke("HEAD"))
        self.assertEqual(get[0]["status"], 200)
        self.assertEqual(json.loads(get[1]["body"])["service"], "yunkai-phonebridge")
        self.assertEqual(head[0]["status"], 405)
        for mocked in mocks:
            mocked.assert_not_called()

    def test_public_mcp_catalog_and_http_entrypoint_are_bounded(self):
        tools = self.loop.run_until_complete(server.list_tools())
        self.assertEqual(len(tools), 44)
        names = [tool.name for tool in tools]
        self.assertEqual(len(names), len(set(names)))
        self.assertFalse(any(word in name for name in names for word in ("delete", "uninstall", "shell", "clear_data")))
        source = (ROOT / "server.py").read_bytes().decode("utf-8")
        tree = ast.parse(source)
        main = tree.body[-1]
        self.assertEqual(main.test.left.id, "__name__")
        self.assertIn('streamable_http_path="/mcp"', ast.get_source_segment(source, main))


if __name__ == "__main__":
    unittest.main()

