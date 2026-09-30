"""Passive status acceptance: no model/device/runtime path may be invoked."""
import ast
import asyncio
import builtins
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch
from uuid import UUID

from mcp.types import CallToolRequestParams
import companion_owned
from phone_bridge import AndroidBridge
from reflex_native import NativeSemanticBridge
import reflex_mcp
import reflex_status
from reflex_status import STATUS_TOOL_NAME, attach_runtime_epoch, read_status, status_schema
from reflex_tap import CONTRACT, POLICY_CONTRACT, ReflexTapExecutor, RuntimePolicy, contract_manifest
import server as server_module
from server import server
from test_reflex_tap import CANARY, Clock, FakeGuardedBridge

ROOT = Path(__file__).parent
FIELDS = {
    "schema_version", "semantic_tap_contract", "policy_contract", "runtime_epoch", "runtime_epoch_scope",
    "policy_enabled", "allowed_ref_count", "stock_adb_atomic_context_guard", "production_backend_bound",
    "production_backend_scope", "live_reflex_ready", "expected_post_predicates", "operation_correlation",
    "request_correlation", "observation_correlation", "durable_exactly_once", "automatic_action_retry",
}


class ReflexStatusTests(unittest.TestCase):
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

    def call(self, arguments=None):
        return self.loop.run_until_complete(server.call_tool(STATUS_TOOL_NAME, arguments))

    def tools(self):
        return self.loop.run_until_complete(server.list_tools())

    def no_effects(self):
        stack = ExitStack()
        mocks = []
        for owner, names in (
            (AndroidBridge, ("__init__", "_run", "_run_with_stdin", "devices", "select_device")),
            (NativeSemanticBridge, ("__init__", "observe", "execute_guarded", "_device")),
            (ReflexTapExecutor, ("tap", "_permission")),
            (server_module, ("_bridge", "_control_center_request")),
            (server_module.LocalVisionAdapter, ("__init__",)),
            (subprocess, ("run", "Popen")),
            (socket, ("create_connection", "getaddrinfo")),
            (socket.socket, ("__init__",)),
        ):
            for name in names:
                mocks.append(stack.enter_context(patch.object(owner, name, side_effect=AssertionError("effect forbidden"))))
        original_import = builtins.__import__
        def guarded_import(name, *args, **kwargs):
            if name.split(".")[0] in {"torch", "transformers", "diffusers", "onnxruntime", "llama_cpp",
                                      "local_vision", "control_center"}:
                raise AssertionError("model/runtime import forbidden")
            return original_import(name, *args, **kwargs)
        stack.enter_context(patch.object(builtins, "__import__", guarded_import))
        return stack, mocks

    def test_discovery_does_not_read_policy_or_touch_device_runtime(self):
        stack, mocks = self.no_effects()
        with stack, patch.object(reflex_status, "load_runtime_policy", side_effect=AssertionError("not during listing")) as policy:
            tools = self.tools()
        policy.assert_not_called()
        for mocked in mocks:
            mocked.assert_not_called()
        self.assertEqual(len(tools), 44)

    def test_status_call_has_no_android_subprocess_network_api_or_model_effect(self):
        stack, mocks = self.no_effects()
        with stack, patch.object(reflex_status, "load_runtime_policy", return_value=RuntimePolicy()):
            result = self.call({})
            direct = server_module.get_android_reflex_status()
        self.assertFalse(result.is_error)
        self.assertEqual(result.structured_content, direct)
        for mocked in mocks:
            mocked.assert_not_called()

    def test_enabled_policy_cannot_trigger_any_effect_or_readiness(self):
        stack, mocks = self.no_effects()
        with stack, patch.object(reflex_status, "load_runtime_policy", return_value=RuntimePolicy(True, ("a" * 64,))):
            result = self.call({}).structured_content
        self.assertTrue(result["policy_enabled"])
        self.assertEqual(result["allowed_ref_count"], 1)
        self.assertFalse(result["production_backend_bound"])
        self.assertFalse(result["live_reflex_ready"])
        for mocked in mocks:
            mocked.assert_not_called()

    def test_exact_fields_types_and_wire_schema(self):
        with patch.object(reflex_status, "load_runtime_policy", return_value=RuntimePolicy()):
            result = self.call({})
        body = result.structured_content
        self.assertEqual(set(body), FIELDS)
        self.assertEqual(json.loads(result.content[0].text), body)
        self.assertEqual(body["semantic_tap_contract"], CONTRACT)
        self.assertEqual(body["policy_contract"], POLICY_CONTRACT)
        self.assertEqual(body["schema_version"], "phonebridge.reflex.status.v1")
        string_fields = {"schema_version", "semantic_tap_contract", "policy_contract", "runtime_epoch",
                         "runtime_epoch_scope", "production_backend_scope"}
        for name in FIELDS:
            self.assertIs(type(body[name]), str if name in string_fields else int if name == "allowed_ref_count" else bool)
        schema = status_schema()
        self.assertEqual(set(schema["properties"]), FIELDS)
        self.assertEqual(set(schema["required"]), FIELDS)
        self.assertFalse(schema["additionalProperties"])
        tool = next(tool for tool in self.tools() if tool.name == STATUS_TOOL_NAME)
        self.assertEqual(tool.output_schema, schema)
        self.assertEqual(tool.input_schema, {"type": "object", "additionalProperties": False, "properties": {}, "required": []})

    def test_only_new_tool_is_read_only_closed_world_and_idempotent(self):
        tool = next(tool for tool in self.tools() if tool.name == STATUS_TOOL_NAME)
        wire = tool.model_dump(mode="json", by_alias=True)
        self.assertTrue(wire["annotations"]["readOnlyHint"])
        self.assertTrue(wire["annotations"]["idempotentHint"])
        self.assertFalse(wire["annotations"]["destructiveHint"])
        self.assertFalse(wire["annotations"]["openWorldHint"])

    def test_epoch_matches_current_executor_and_is_stable_across_reads(self):
        with patch.object(reflex_status, "load_runtime_policy", return_value=RuntimePolicy()):
            first, second = self.call().structured_content, self.call().structured_content
        self.assertEqual(first["runtime_epoch"], reflex_mcp.executor.runtime_epoch)
        self.assertEqual(first, second)
        self.assertEqual(UUID(first["runtime_epoch"]).version, 4)
        self.assertEqual(first["runtime_epoch_scope"], "executor_instance_metadata_only")

    def test_epoch_is_per_executor_not_device_identity_or_execution_input(self):
        a = ReflexTapExecutor(bridge=object())
        b = ReflexTapExecutor(bridge=object())
        first = attach_runtime_epoch(a)
        self.assertEqual(attach_runtime_epoch(a), first)
        self.assertNotEqual(attach_runtime_epoch(b), first)
        with patch.object(reflex_mcp, "executor", a), patch.object(reflex_status, "load_runtime_policy", return_value=RuntimePolicy()):
            self.assertEqual(self.call().structured_content["runtime_epoch"], first)

    def test_invalid_epoch_error_is_finite_sanitized_and_reads_no_policy(self):
        with patch.object(reflex_mcp.executor, "runtime_epoch", CANARY), patch.object(reflex_status, "load_runtime_policy") as policy:
            result = self.call()
        self.assertTrue(result.is_error)
        self.assertEqual(result.content[0].text, "STATUS_UNAVAILABLE")
        self.assertNotIn(CANARY, result.model_dump_json())
        policy.assert_not_called()

    def test_missing_unreadable_policy_disabled_and_count_zero(self):
        for error in (FileNotFoundError(CANARY), PermissionError(CANARY), OSError(CANARY)):
            with self.subTest(error=type(error).__name__), patch.object(Path, "open", side_effect=error):
                body = self.call().structured_content
            self.assertIs(body["policy_enabled"], False)
            self.assertEqual(body["allowed_ref_count"], 0)
            self.assertNotIn(CANARY, json.dumps(body))

    def test_malformed_policy_disabled_and_count_zero(self):
        valid = {"schema_version": POLICY_CONTRACT, "enabled": True, "allowed_binding_ids": ["a" * 64]}
        values = [
            b"", b"{", b"x" * 8193, b"[]", b"null",
            json.dumps({**valid, "enabled": "true"}).encode(),
            json.dumps({**valid, "allowed_binding_ids": [CANARY]}).encode(),
            json.dumps({**valid, "allowed_binding_ids": ["a" * 64, "a" * 64]}).encode(),
            json.dumps({**valid, "allowed_binding_ids": [f"{i:064x}" for i in range(33)]}).encode(),
            json.dumps({**valid, "extra": CANARY}).encode(),
            b'{"schema_version":"phonebridge.reflex.policy.v1","enabled":false,"enabled":true,"allowed_binding_ids":[]}',
        ]
        for raw in values:
            with self.subTest(size=len(raw)), patch.object(Path, "open", return_value=io.BytesIO(raw)):
                body = self.call().structured_content
            self.assertIs(body["policy_enabled"], False)
            self.assertEqual(body["allowed_ref_count"], 0)

    def test_enabled_fixture_reports_only_boolean_and_count_no_refs(self):
        refs = ["a" * 64, "b" * 64]
        raw = json.dumps({"schema_version": POLICY_CONTRACT, "enabled": True, "allowed_binding_ids": refs}).encode()
        with patch.object(Path, "open", return_value=io.BytesIO(raw)) as opened:
            body = self.call({}).structured_content
        opened.assert_called_once_with("rb")
        self.assertTrue(body["policy_enabled"])
        self.assertEqual(body["allowed_ref_count"], 2)
        for ref in refs:
            self.assertNotIn(ref, json.dumps(body))
        self.assertNotIn("allowed_binding_ids", body)

    def test_policy_reader_failure_or_malformed_object_never_echoed(self):
        for invalid in (None, {}, RuntimePolicy(1, ()), RuntimePolicy(True, (CANARY,))):
            with patch.object(reflex_status, "load_runtime_policy", return_value=invalid):
                body = self.call().structured_content
            self.assertEqual((body["policy_enabled"], body["allowed_ref_count"]), (False, 0))
        with patch.object(reflex_status, "load_runtime_policy", side_effect=RuntimeError(CANARY)):
            self.assertEqual(self.call().structured_content["allowed_ref_count"], 0)

    def test_no_policy_value_cache_and_no_readiness_promotion(self):
        with patch.object(reflex_status, "load_runtime_policy", side_effect=[
                RuntimePolicy(True, ("a" * 64,)), RuntimePolicy()]):
            first, second = self.call().structured_content, self.call().structured_content
        self.assertEqual((first["policy_enabled"], first["allowed_ref_count"]), (True, 1))
        self.assertEqual((second["policy_enabled"], second["allowed_ref_count"]), (False, 0))
        self.assertFalse(first["live_reflex_ready"])
        self.assertFalse(second["live_reflex_ready"])

    def test_strict_no_arguments_rejects_extras_without_reading_policy(self):
        with patch.object(reflex_status, "load_runtime_policy", side_effect=AssertionError("no policy read")) as policy:
            for value in ([], "", "{}", True, 0, {"enabled": True}, {"serial": CANARY}, {"request": {}}, {"profile": CANARY}):
                result = self.call(value)
                self.assertTrue(result.is_error)
                self.assertEqual(result.content[0].text, "INVALID_STATUS_REQUEST")
                self.assertNotIn(CANARY, result.model_dump_json())
            params = CallToolRequestParams(name=STATUS_TOOL_NAME, arguments={"enabled": True})
            actual = self.loop.run_until_complete(server._handle_call_tool(None, params))
            self.assertTrue(actual.is_error)
            self.assertEqual(actual.content[0].text, "INVALID_STATUS_REQUEST")
        policy.assert_not_called()

    def test_status_does_not_call_executor_policy_tap_or_mutate_audit_attempts(self):
        clock = Clock()
        bridge = FakeGuardedBridge(clock)
        executor = ReflexTapExecutor(bridge=bridge, clock=clock, policy=lambda: (_ for _ in ()).throw(AssertionError("callback")))
        attach_runtime_epoch(executor)
        before = (set(executor._attempted), executor.audit, bridge.dispatches, list(bridge.observations))
        with patch.object(reflex_mcp, "executor", executor), patch.object(reflex_status, "load_runtime_policy", return_value=RuntimePolicy()):
            self.assertFalse(self.call().is_error)
        self.assertEqual(before, (set(executor._attempted), executor.audit, bridge.dispatches, list(bridge.observations)))

    def test_sanitized_stdout_stderr_and_finite_error_paths(self):
        stream = io.StringIO()
        with redirect_stdout(stream), redirect_stderr(stream), patch.object(
                reflex_status, "load_runtime_policy", side_effect=RuntimeError(CANARY)):
            good, bad = self.call({}), self.call({"path": CANARY})
        output = good.model_dump_json() + bad.model_dump_json() + stream.getvalue()
        for value in (CANARY, "allowed_binding_ids", "serial", "selector", "Traceback", "/api/status"):
            self.assertNotIn(value, output)
        self.assertEqual(stream.getvalue(), "")

    def test_public_tool_catalog_is_unique_bounded_and_non_destructive_by_name(self):
        tools = self.tools()
        names = [tool.name for tool in tools]
        self.assertEqual(len(names), 44)
        self.assertEqual(len(names), len(set(names)))
        self.assertIn(STATUS_TOOL_NAME, names)
        self.assertIn(companion_owned.TOOL_NAME, names)
        self.assertIn(companion_owned.STATUS_TOOL_NAME, names)
        self.assertFalse(any(word in name for name in names for word in ("delete", "uninstall", "shell", "clear_data")))
        manifest = contract_manifest()
        self.assertFalse(manifest["automatic_action_retry"])
        self.assertFalse(manifest["live_reflex_ready"])

    def test_manifest_truth_and_correlations_are_scope_limited(self):
        with patch.object(reflex_status, "load_runtime_policy", return_value=RuntimePolicy(True, ("a" * 64,))):
            body = read_status(reflex_mcp.executor.runtime_epoch)
        for key in ("stock_adb_atomic_context_guard", "live_reflex_ready", "durable_exactly_once", "automatic_action_retry"):
            self.assertIs(body[key], contract_manifest()[key])
            self.assertFalse(body[key])
        self.assertFalse(body["production_backend_bound"])
        self.assertEqual(body["production_backend_scope"], "reviewed_atomic_reflex_backend")
        for key in ("expected_post_predicates", "operation_correlation", "request_correlation", "observation_correlation"):
            self.assertTrue(body[key])


if __name__ == "__main__":
    unittest.main()

