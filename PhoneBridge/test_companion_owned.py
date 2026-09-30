"""Offline scoped Companion host adapter checks; no real MCP or device call."""
import asyncio
from contextlib import ExitStack
import json
import os
import socket
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import UUID

import companion_owned as owned
import reflex_mcp
from server import server


REQUEST_ID = "a5884329-fd92-4c2b-ac8d-7b23fd4770f1"
OPERATION_ID = "d183a919-6162-41bb-92a7-e141de2bd374"
DEVICE_ID = "a3879937-fad9-47a9-9362-1dfa413878c5"
SESSION_ID = "c3ba71e1-0ad0-4fd2-84ca-c262e9925e8e"
OTHER_ID = "481952d5-dc55-4ded-a910-444d27390fe0"
TOKEN = "fixture-only-token-with-at-least-32-characters"
_DEFAULT = object()
ENV = {"PHONEBRIDGE_COMPANION_OWNED_CLICK_ENABLED": "1",
       "PHONEBRIDGE_COMPANION_MCP_URL": "http://127.0.0.1:8787/mcp",
       "MCP_BEARER_TOKEN": TOKEN}


def request(**changes):
    return {**{"requestId": REQUEST_ID, "ttlMillis": 5000, "deviceId": DEVICE_ID}, **changes}


def receipt(*, input_outcome="ONE_INPUT", post_outcome="VERIFIED", category="OWNED_TRANSITION"):
    data = {"version": 1, "operationId": OPERATION_ID, "deviceId": DEVICE_ID,
            "sessionId": SESSION_ID, "sessionGeneration": 2, "authorityGeneration": 3,
            "targetGeneration": 4, "inputOutcome": input_outcome,
            "postOutcome": post_outcome, "evidenceCategory": category}
    decision = "ALLOW" if input_outcome == "ONE_INPUT" else "DENY" if input_outcome == "NO_INPUT" else "UNAVAILABLE"
    value = {"success": True, "data": data, "error": None,
             "metadata": {"requestId": OPERATION_ID, "timestamp": "2026-09-24T00:00:00.000Z",
                          "tool": owned.PEER_TOOL_NAME, "riskLevel": "SENSITIVE",
                          "permissionDecision": decision, "durationMs": 1,
                          "protocolVersion": owned.PEER_PROTOCOL,
                          "deviceId": DEVICE_ID, "sessionId": SESSION_ID}}
    return {"is_error": False, "structured_content": value}


class FakeCaller:
    def __init__(self, response=None, error=None):
        self.response = receipt() if response is None else response
        self.error = error
        self.calls = []

    async def __call__(self, config, arguments):
        self.calls.append((config, dict(arguments)))
        if self.error is not None:
            raise self.error
        return self.response


class CompanionOwnedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.loop = asyncio.new_event_loop()

    @classmethod
    def tearDownClass(cls):
        cls.loop.close()

    def setUp(self):
        self.caller = FakeCaller()
        self.executor = owned.CompanionOwnedExecutor(
            caller=self.caller, environment=ENV,
            operation_factory=lambda: UUID(OPERATION_ID))

    def execute(self, value=_DEFAULT):
        return self.loop.run_until_complete(self.executor.execute(request() if value is _DEFAULT else value))

    def test_one_fixed_peer_call_and_cached_redelivery(self):
        first = self.execute()
        second = self.execute()
        self.assertEqual(first, second)
        self.assertEqual((first["input_outcome"], first["post_outcome"]), ("ONE_INPUT", "VERIFIED"))
        self.assertEqual((first["operation_id"], first["request_id"]), (OPERATION_ID, REQUEST_ID))
        self.assertEqual(len(self.caller.calls), 1)
        self.assertEqual(self.caller.calls[0][1], {
            "operationId": OPERATION_ID, "ttlMillis": 5000, "deviceId": DEVICE_ID})
        self.assertFalse(first["safe_to_retry_action"])
        self.assertFalse(first["automatic_action_retry"])
        self.assertEqual(first["live_acceptance"], "PENDING")
        self.assertEqual(self.caller.calls[0][0].url, ENV["PHONEBRIDGE_COMPANION_MCP_URL"])
        self.assertNotIn(TOKEN, repr(self.caller.calls[0][0]))

    def test_no_input_and_release_debug_required_are_preserved(self):
        for category in ("CONSENT_UNAVAILABLE", "DEBUG_BUILD_REQUIRED", "REPLAY_OR_CAPACITY"):
            self.setUp()
            self.caller.response = receipt(input_outcome="NO_INPUT", post_outcome="UNAVAILABLE",
                                           category=category)
            result = self.execute()
            self.assertEqual((result["input_outcome"], result["post_outcome"], result["evidence_category"]),
                             ("NO_INPUT", "UNAVAILABLE", category))
            self.assertEqual(len(self.caller.calls), 1)

    def test_peer_uncertain_stays_uncertain_with_no_retry(self):
        self.caller.response = receipt(input_outcome="UNCERTAIN", post_outcome="UNVERIFIED",
                                       category="TRANSITION_UNCERTAIN")
        result = self.execute()
        self.assertEqual((result["input_outcome"], result["post_outcome"]),
                         ("UNCERTAIN", "UNVERIFIED"))
        self.assertEqual(self.execute(), result)
        self.assertEqual(len(self.caller.calls), 1)

    def test_peer_auth_error_after_call_is_uncertain_and_not_retried(self):
        self.caller.response = {"is_error": True, "structured_content": {
            "success": False, "data": None,
            "error": {"code": "AUTH_FAILED", "message": "private canary", "retryable": False},
            "metadata": receipt()["structured_content"]["metadata"]}}
        result = self.execute()
        self.assertEqual((result["input_outcome"], result["post_outcome"], result["evidence_category"]),
                         ("UNCERTAIN", "UNAVAILABLE", "HOST_RECEIPT_UNAVAILABLE"))
        self.assertEqual(self.execute(), result)
        self.assertEqual(len(self.caller.calls), 1)
        self.assertNotIn("private canary", json.dumps(result))

    def test_host_uncertain_receipt_is_preserved(self):
        self.caller.response = receipt(input_outcome="UNCERTAIN", post_outcome="UNAVAILABLE",
                                       category="HOST_RECEIPT_UNAVAILABLE")
        data = self.caller.response["structured_content"]["data"]
        for key in ("sessionGeneration", "authorityGeneration", "targetGeneration"):
            data[key] = None
        result = self.execute()
        self.assertEqual(result["evidence_category"], "HOST_RECEIPT_UNAVAILABLE")
        self.assertEqual(result["session_id"], SESSION_ID)

    def test_timeout_transport_loss_and_late_reply_never_retry(self):
        for error in (TimeoutError("private canary"), OSError("private canary")):
            self.setUp()
            self.caller.error = error
            result = self.execute()
            self.assertEqual((result["input_outcome"], result["post_outcome"], result["evidence_category"]),
                             ("UNCERTAIN", "UNAVAILABLE", "HOST_RECEIPT_UNAVAILABLE"))
            self.assertEqual(result, self.execute())
            self.assertEqual(len(self.caller.calls), 1)
            self.assertNotIn("private canary", json.dumps(result))
        self.setUp()
        ticks = iter((0.0, 60.0))
        self.executor._clock = lambda: next(ticks)
        self.assertEqual(self.execute()["evidence_category"], "HOST_RECEIPT_UNAVAILABLE")
        self.assertEqual(len(self.caller.calls), 1)

    def test_malformed_and_mismatched_receipts_are_uncertain(self):
        variants = []
        for key, bad in (("operationId", OTHER_ID), ("deviceId", OTHER_ID),
                         ("sessionId", OTHER_ID), ("sessionGeneration", -1),
                         ("authorityGeneration", True), ("version", 2),
                         ("evidenceCategory", "DEBUG_BUILD_REQUIRED")):
            value = receipt()
            value["structured_content"]["data"][key] = bad
            variants.append(value)
        for key, bad in (("requestId", OTHER_ID), ("deviceId", OTHER_ID),
                         ("sessionId", OTHER_ID), ("protocolVersion", "wrong"),
                         ("permissionDecision", "DENY")):
            value = receipt()
            value["structured_content"]["metadata"][key] = bad
            variants.append(value)
        for modify in (lambda v: v.update(is_error=True),
                       lambda v: v.update(structured_content=None),
                       lambda v: v["structured_content"].update(success=False),
                       lambda v: v["structured_content"].update(extra="private canary"),
                       lambda v: v["structured_content"]["data"].update(extra="private canary")):
            value = receipt()
            modify(value)
            variants.append(value)
        for value in variants:
            self.setUp()
            self.caller.response = value
            result = self.execute()
            self.assertEqual((result["input_outcome"], result["post_outcome"], result["evidence_category"]),
                             ("UNCERTAIN", "UNAVAILABLE", "HOST_RECEIPT_UNAVAILABLE"))
            self.assertEqual(len(self.caller.calls), 1)
            self.assertNotIn("private canary", json.dumps(result))

    def test_optional_device_is_omitted_from_peer_input(self):
        value = request()
        del value["deviceId"]
        self.execute(value)
        self.assertEqual(self.caller.calls[0][1], {"operationId": OPERATION_ID, "ttlMillis": 5000})

    def test_invalid_request_and_forbidden_fields_never_call_peer(self):
        for value in (None, {}, [], {**request(), "ttlMillis": True},
                      {**request(), "ttlMillis": 0}, {**request(), "ttlMillis": 30001},
                      {**request(), "requestId": OTHER_ID.upper()},
                      {**request(), "deviceId": "invalid"},
                      {**request(), "selector": {"text": "Settings"}},
                      {**request(), "coordinates": [1, 2]},
                      {**request(), "permission": True},
                      {**request(), "operationId": OPERATION_ID}):
            result = self.execute(value)
            self.assertEqual(result["evidence_category"], "INVALID_REQUEST")
        self.assertEqual(self.caller.calls, [])

    def test_config_and_auth_default_off_no_peer_call(self):
        for environment in ({}, {**ENV, "PHONEBRIDGE_COMPANION_OWNED_CLICK_ENABLED": "0"},
                            {**ENV, "MCP_BEARER_TOKEN": ""},
                            {**ENV, "PHONEBRIDGE_COMPANION_MCP_URL": "http://example.invalid/mcp"},
                            {**ENV, "PHONEBRIDGE_COMPANION_MCP_URL": "http://127.0.0.1:8787/mcp?x=1"},
                            {**ENV, "PHONEBRIDGE_COMPANION_MCP_URL": "http://localhost:8787/mcp"}):
            executor = owned.CompanionOwnedExecutor(caller=self.caller, environment=environment,
                                                     operation_factory=lambda: UUID(OPERATION_ID))
            result = self.loop.run_until_complete(executor.execute(request()))
            self.assertEqual((result["input_outcome"], result["post_outcome"], result["evidence_category"]),
                             ("NO_INPUT", "UNAVAILABLE", "HOST_CONFIG_UNAVAILABLE"))
        self.assertEqual(self.caller.calls, [])

    def test_in_flight_redelivery_and_conflicting_request_do_not_call_again(self):
        async def scenario():
            entered, release = asyncio.Event(), asyncio.Event()
            calls = []
            async def pending(config, arguments):
                calls.append(arguments)
                entered.set()
                await release.wait()
                return receipt()
            executor = owned.CompanionOwnedExecutor(caller=pending, environment=ENV,
                                                     operation_factory=lambda: UUID(OPERATION_ID))
            first_task = asyncio.create_task(executor.execute(request()))
            await entered.wait()
            second = await executor.execute(request())
            conflict = await executor.execute(request(ttlMillis=6000, deviceId=OTHER_ID))
            release.set()
            first = await first_task
            third = await executor.execute(request())
            return first, second, conflict, third, calls
        first, second, conflict, third, calls = self.loop.run_until_complete(scenario())
        self.assertEqual(len(calls), 1)
        self.assertEqual(first, third)
        for item in (second, conflict):
            self.assertEqual(item["input_outcome"], "UNCERTAIN")
            self.assertEqual(item["operation_id"], OPERATION_ID)
            self.assertEqual(item["device_id"], DEVICE_ID)

    def test_passive_status_separates_config_from_reachability_and_acceptance(self):
        off = owned.status({})
        on = owned.status(ENV)
        self.assertFalse(off["configured"])
        self.assertTrue(on["configured"])
        for value in (off, on):
            self.assertTrue(value["implemented"])
            self.assertEqual((value["reachable"], value["accepted"]), ("UNKNOWN", "NOT_PERFORMED"))
            self.assertFalse(value["live_ready"])
            self.assertFalse(value["generic_reflex_ready"])
            self.assertFalse(value["stock_adb_atomic_context_guard"])
            self.assertFalse(value["automatic_action_retry"])
            self.assertNotIn(TOKEN, json.dumps(value))

    def test_mcp_scoped_dispatch_is_strict_and_generic_status_stays_false(self):
        with patch.object(reflex_mcp, "companion_executor", self.executor):
            tools = self.loop.run_until_complete(server.list_tools())
            names = [tool.name for tool in tools]
            self.assertEqual(len(names), 44)
            self.assertIn(owned.TOOL_NAME, names)
            self.assertIn(owned.STATUS_TOOL_NAME, names)
            good = self.loop.run_until_complete(server.call_tool(owned.TOOL_NAME, {"request": request()}))
            self.assertEqual(good.structured_content["input_outcome"], "ONE_INPUT")
            bad = self.loop.run_until_complete(server.call_tool(owned.TOOL_NAME, {
                "request": request(), "selector": "private canary"}))
            self.assertEqual(bad.structured_content["evidence_category"], "INVALID_REQUEST")
            self.assertNotIn("private canary", bad.model_dump_json())
            self.assertEqual(len(self.caller.calls), 1)
            with patch.dict(os.environ, {}, clear=True):
                scoped = self.loop.run_until_complete(server.call_tool(owned.STATUS_TOOL_NAME, {}))
            self.assertFalse(scoped.structured_content["configured"])
            generic = self.loop.run_until_complete(server.call_tool("get_android_reflex_status", {}))
            self.assertFalse(generic.structured_content["production_backend_bound"])
            self.assertFalse(generic.structured_content["live_reflex_ready"])

    def test_installed_mcp_http_client_wiring_has_one_tool_and_no_proxy(self):
        import httpx2
        import mcp
        import mcp.client.streamable_http as streamable

        seen = {"tools": []}
        class FakeContext:
            def __init__(self, value):
                self.value = value
            async def __aenter__(self):
                return self.value
            async def __aexit__(self, *args):
                return False
        class FakeSession:
            def __init__(self, read, write, **kwargs):
                seen["streams"] = (read, write)
                seen["session_kwargs"] = kwargs
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                return False
            async def initialize(self):
                seen["initialized"] = True
            async def call_tool(self, name, arguments, **kwargs):
                seen["tools"].append((name, arguments, kwargs))
                return SimpleNamespace(is_error=False, structured_content=receipt()["structured_content"])
        def fake_http(**kwargs):
            seen["http_kwargs"] = kwargs
            return FakeContext("http-client")
        def fake_stream(url, **kwargs):
            seen["stream"] = (url, kwargs)
            return FakeContext(("read", "write"))
        with (patch.object(httpx2, "AsyncClient", side_effect=fake_http),
              patch.object(streamable, "streamable_http_client", side_effect=fake_stream),
              patch.object(mcp, "ClientSession", FakeSession)):
            result = self.loop.run_until_complete(owned.CompanionMcpCaller()(
                owned.Config(ENV["PHONEBRIDGE_COMPANION_MCP_URL"], TOKEN),
                {"operationId": OPERATION_ID, "ttlMillis": 5000, "deviceId": DEVICE_ID}))
        self.assertFalse(result["is_error"])
        self.assertTrue(seen["initialized"])
        self.assertEqual(seen["tools"], [(owned.PEER_TOOL_NAME,
                                         {"operationId": OPERATION_ID, "ttlMillis": 5000,
                                          "deviceId": DEVICE_ID},
                                         {"read_timeout_seconds": owned.CALL_TIMEOUT_SECONDS})])
        self.assertEqual(seen["stream"][0], ENV["PHONEBRIDGE_COMPANION_MCP_URL"])
        self.assertFalse(seen["stream"][1]["terminate_on_close"])
        self.assertFalse(seen["http_kwargs"]["trust_env"])
        self.assertFalse(seen["http_kwargs"]["follow_redirects"])
        self.assertEqual(seen["http_kwargs"]["headers"], {"Authorization": "Bearer " + TOKEN})

    def test_offline_fakes_never_touch_device_process_or_socket(self):
        with ExitStack() as stack:
            for owner, name in ((subprocess, "run"), (subprocess, "Popen"),
                                (socket, "create_connection"), (socket.socket, "connect")):
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError("real effect")))
            self.assertEqual(self.execute()["input_outcome"], "ONE_INPUT")
        self.assertEqual(len(self.caller.calls), 1)


if __name__ == "__main__":
    unittest.main()
