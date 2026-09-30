import asyncio
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

from device_contract_adapter import phone_capability_manifest, phone_runtime_policy
import companion_owned
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolRequestParams
import reflex_mcp
from reflex_tap import ReflexTapExecutor, RuntimePolicy, TOOL_NAME
from reflex_status import STATUS_TOOL_NAME
from server import server, tap_android_ui_element_reflex_verified
from test_reflex_tap import CANARY, Clock, FakeGuardedBridge, allowed, request


class ReflexMCPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.loop = asyncio.new_event_loop()
        cls.tools = cls.loop.run_until_complete(server.list_tools())

    @classmethod
    def tearDownClass(cls):
        cls.loop.close()

    def setUp(self):
        self.clock = Clock()
        self.bridge = FakeGuardedBridge(self.clock)
        self.executor = ReflexTapExecutor(bridge=self.bridge, clock=self.clock,
                                         policy=lambda: allowed())
        self.binding = patch.object(reflex_mcp, "executor", self.executor)
        self.binding.start()
        self.addCleanup(self.binding.stop)

    def call(self, arguments):
        return self.loop.run_until_complete(server.call_tool(TOOL_NAME, arguments))

    def test_all_40_legacy_tools_contracts_and_policy_are_exactly_unchanged(self):
        baseline = json.loads((Path(__file__).parent / "verification" / "reflex-p0-20260923"
                               / "legacy-baseline.json").read_text(encoding="utf-8"))
        legacy = [tool.model_dump(mode="json") for tool in self.tools if tool.name not in (
            TOOL_NAME, STATUS_TOOL_NAME, companion_owned.TOOL_NAME, companion_owned.STATUS_TOOL_NAME)]
        self.assertEqual(len(legacy), 40)
        self.assertEqual(legacy, baseline["tools"])
        self.assertEqual(phone_capability_manifest(), baseline["manifest"])
        self.assertEqual(phone_runtime_policy(), baseline["policy"])

    def test_exactly_one_new_non_destructive_tool_and_finite_schema(self):
        self.assertEqual(len(self.tools), 44)
        tool = next(tool for tool in self.tools if tool.name == TOOL_NAME)
        wire = tool.model_dump(mode="json", by_alias=True)
        self.assertIn("inputSchema", wire)
        self.assertIn("outputSchema", wire)
        self.assertFalse(wire["annotations"]["destructiveHint"])
        self.assertFalse(wire["annotations"]["idempotentHint"])
        self.assertFalse(wire["annotations"]["readOnlyHint"])
        metadata = wire["_meta"]["reflex_contract"]
        self.assertTrue(metadata["production_backend_implemented"])
        self.assertFalse(metadata["runtime_ready"])
        self.assertFalse(metadata["live_reflex_ready"])
        self.assertFalse(metadata["stock_adb_atomic_context_guard"])
        def check_objects(schema):
            if isinstance(schema, dict):
                if schema.get("type") == "object":
                    self.assertIs(schema["additionalProperties"], False)
                for child in schema.values():
                    check_objects(child)
            elif isinstance(schema, list):
                for child in schema:
                    check_objects(child)
        check_objects(wire["inputSchema"])
        self.assertEqual(set(wire["inputSchema"]["properties"]), {"request"})
        self.assertFalse(any(word in item.name for item in self.tools for word in ("delete", "uninstall", "shell", "reset")))

    def test_valid_call_returns_only_correlated_sanitized_contract(self):
        response = self.call({"request": request()})
        self.assertFalse(response.is_error)
        self.assertEqual(response.structured_content["verification_status"], "VERIFIED")
        self.assertEqual(json.loads(response.content[0].text), response.structured_content)
        self.assertIn("structuredContent", response.model_dump(mode="json", by_alias=True))
        self.assertEqual(len(self.bridge.inputs), 1)

    def test_actual_registered_dispatcher_uses_strict_raw_guard(self):
        params = CallToolRequestParams(name=TOOL_NAME, arguments={"request": request(), "permission": CANARY})
        response = self.loop.run_until_complete(server._handle_call_tool(None, params))
        self.assertEqual(response.structured_content["reason"], "INVALID_REQUEST")
        self.assertNotIn(CANARY, response.model_dump_json())
        self.assertEqual(self.bridge.observations, [])

    def test_sdk_does_not_drop_extras_or_coerce_json_strings(self):
        for arguments in (None, [], {}, {"request": json.dumps(request())},
                          {"request": request(), "enabled": True},
                          {"request": {**request(), "observed_at_ms": "1000"}},
                          {"request": {**request(), "observed_at_ms": True}},
                          {"request": {**request(), "serial": CANARY}}):
            with self.subTest(kind=type(arguments).__name__):
                response = self.call(arguments)
                self.assertEqual(response.structured_content["reason"], "INVALID_REQUEST")
                self.assertNotIn(CANARY, response.model_dump_json())
        self.assertEqual(self.bridge.observations, [])

    def test_default_executor_denies_without_constructing_android_bridge(self):
        from phone_bridge import AndroidBridge
        executor = ReflexTapExecutor(policy=lambda: RuntimePolicy())
        with patch.object(reflex_mcp, "executor", executor), patch.object(AndroidBridge, "__init__", side_effect=AssertionError("ADB")):
            self.assertEqual(self.call({"request": request()}).structured_content["reason"], "RUNTIME_PERMISSION_DENIED")
            self.assertEqual(tap_android_ui_element_reflex_verified(request())["reason"], "RUNTIME_PERMISSION_DENIED")

    def test_legacy_sdk_dispatch_preserves_name_arguments_and_context(self):
        args, context, sentinel = {"legacy": "same"}, object(), object()
        with patch.object(MCPServer, "call_tool", new_callable=AsyncMock, return_value=sentinel) as parent:
            result = self.loop.run_until_complete(server.call_tool("tap_android_verified", args, context))
        self.assertIs(result, sentinel)
        parent.assert_awaited_once_with("tap_android_verified", args, context)

    def test_exceptions_and_malformed_payloads_have_no_raw_log_leak(self):
        stream = io.StringIO()
        self.bridge.raise_after_input = True
        with redirect_stdout(stream), redirect_stderr(stream):
            result = self.call({"request": request()})
        self.assertEqual(result.structured_content["verification_status"], "UNCERTAIN")
        self.assertNotIn(CANARY, result.model_dump_json() + stream.getvalue())
        self.assertEqual(stream.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
