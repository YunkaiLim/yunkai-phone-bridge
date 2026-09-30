"""Strict contract tests; all backend input is fake."""
from dataclasses import replace
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

from reflex_tap import (
    CONTRACT, MAX_AUDIT, MAX_OPERATIONS, POLICY_CONTRACT, Identity, Observation, Receipt,
    ReflexTapExecutor, RuntimePolicy, contract_manifest, load_runtime_policy, parse_request,
)

OP = "00000000-0000-4000-8000-000000000001"
OTHER_OP = "00000000-0000-4000-8000-000000000003"
CONTEXT = Identity("c" * 64, "d" * 64, "e" * 64)
CANARY = "PRIVATE_CANARY serial=SECRET raw-selector=private-account token=secret"


def request():
    return {"schema_version": CONTRACT, "operation_id": OP, "selector": {"text": "Settings"},
            "expected_package_name": "com.example", "observed_at_ms": 1000, "expires_at_ms": 4000,
            "expected_post": {"kind": "ui_element_presence", "selector": {"resource_id": "com.example:id/done"},
                              "present": True, "package_name": "com.example"}}


def allowed(value=None):
    return RuntimePolicy(True, (parse_request(value or request()).binding_id,))


class Clock:
    now = 2000

    def __call__(self):
        return self.now


class FakeGuardedBridge:
    safe_post_observation = True

    def __init__(self, clock):
        self.clock = clock
        self.inputs, self.observations = [], []
        self.dispatches = 0
        self.before_changes, self.guard_changes, self.after_changes, self.receipt_changes = {}, {}, {}, {}
        self.raise_after_input = False
        self.raise_observation = None
        self.on_dispatch = lambda: None
        self.finished = threading.Event()

    def evidence(self, req, phase):
        observation = Observation(req.operation_id, self.clock(), CONTEXT, True, True, 1, True,
                                  "a" * 64, phase == "after")
        return replace(observation, **(self.after_changes if phase == "after" else self.before_changes))

    def observe(self, req, phase):
        self.observations.append(phase)
        if phase == self.raise_observation:
            raise RuntimeError(CANARY)
        return self.evidence(req, phase)

    def execute_guarded(self, req, guard):
        self.dispatches += 1
        try:
            self.on_dispatch()
            permit = guard(replace(self.evidence(req, "before"), **self.guard_changes))
            if permit:
                self.inputs.append(req.operation_id)
                if self.raise_after_input:
                    raise RuntimeError(CANARY)
            return replace(Receipt(req.operation_id, permit), **self.receipt_changes)
        finally:
            self.finished.set()


class ReflexTapTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.bridge = FakeGuardedBridge(self.clock)
        self.permission = allowed()
        self.engine = ReflexTapExecutor(bridge=self.bridge, clock=self.clock, policy=lambda: self.permission)

    def denied(self, value, reason="INVALID_REQUEST"):
        result = self.engine.tap(value)
        self.assertEqual((result["verification_status"], result["reason"]), ("DENIED", reason))
        self.assertFalse(result["executed_once"])
        self.assertFalse(result["safe_to_retry_action"])
        self.assertEqual(self.bridge.inputs, [])
        return result

    def test_default_deny_before_backend_use(self):
        self.permission = RuntimePolicy()
        self.denied(request(), "RUNTIME_PERMISSION_DENIED")
        self.assertEqual(self.bridge.observations, [])

    def test_caller_cannot_enable_permission_or_select_profile(self):
        self.permission = RuntimePolicy()
        for key in ("enabled", "permission", "policy", "runtime_profile", "execution_mode", "allowed_binding_ids"):
            self.denied({**request(), key: True})
        self.assertEqual(self.bridge.observations, [])

    def test_exact_binding_includes_selector_package_and_predicate(self):
        variants = [
            {**request(), "selector": {"text": "Other"}},
            {**request(), "expected_package_name": "com.other"},
            {**request(), "expected_post": {**request()["expected_post"], "present": False}},
        ]
        for value in variants:
            self.denied(value, "RUNTIME_PERMISSION_DENIED")

    def test_valid_one_input_and_finite_correlated_before_after_receipt(self):
        result = self.engine.tap(request())
        self.assertEqual(result["verification_status"], "VERIFIED")
        self.assertEqual(result["operation_id"], OP)
        self.assertTrue(result["executed_once"])
        self.assertEqual(self.bridge.inputs, [OP])
        self.assertEqual(self.bridge.observations, ["before", "after"])
        self.assertEqual(set(result["before"]), {"observed_at_ms", "context_digest", "foreground_digest", "generation_digest"})
        self.assertEqual(result["before"], result["after"])
        self.assertFalse(result["safe_to_retry_action"])

    def test_each_exact_semantic_selector_is_supported(self):
        for selector in ({"text": "Settings"}, {"content_desc": "Settings"}, {"resource_id": "com.example:id/settings"}):
            self.setUp()
            value = {**request(), "selector": selector}
            self.permission = allowed(value)
            self.assertEqual(self.engine.tap(value)["verification_status"], "VERIFIED")

    def test_selector_one_of_only_bounded_and_not_free_input_text(self):
        for selector in (None, {}, [], "Settings", {"semantic_ref": "a" * 64},
                         {"text": "Settings", "content_desc": "Settings"}, {"text": ""},
                         {"text": " "}, {"text": " x"}, {"text": "x" * 129},
                         {"text": "\u0000"}, {"text": "\ud800"}, {"text": True},
                         {"resource_id": "https://private.invalid"}, {"text": "中" * 100}):
            self.denied({**request(), "selector": selector})

    def test_forbidden_fields_at_root_selector_and_predicate(self):
        for key in ("x", "y", "coordinates", "index", "serial", "url", "shell", "tool", "payload",
                    "account", "secret", "enabled", "input_text"):
            for level in ("root", "selector", "expected_post", "post_selector"):
                value = request()
                target = (value if level == "root" else value["expected_post"]["selector"]
                          if level == "post_selector" else value[level])
                target[key] = CANARY
                self.denied(value)
        self.assertEqual(self.bridge.observations, [])

    def test_operation_id_required_and_canonical_non_nil_uuid(self):
        value = request()
        del value["operation_id"]
        self.denied(value)
        for operation in (None, "", "invented", 1, True, "00000000-0000-0000-0000-000000000000",
                          "00000000-0000-4000-8000-ABCDEFABCDEF"):
            self.denied({**request(), "operation_id": operation})

    def test_foreground_package_required_and_bounded(self):
        value = request()
        del value["expected_package_name"]
        self.denied(value)
        for package in ("", "com", "com.example/Activity", "https://x.invalid", "x" * 129, None, True):
            self.denied({**request(), "expected_package_name": package})

    def test_expected_post_required_exact_and_non_coercing(self):
        value = request()
        del value["expected_post"]
        self.denied(value)
        for post in (None, {}, [], {**request()["expected_post"], "present": 1},
                     {**request()["expected_post"], "kind": "any_confident_change"},
                     {**request()["expected_post"], "selector": {"index": 0}}):
            self.denied({**request(), "expected_post": post})

    def test_time_finite_integer_range_and_maximum_age(self):
        for key in ("observed_at_ms", "expires_at_ms"):
            for value in (None, True, "2000", 2000.0, float("nan"), float("inf"), -1, 2**53):
                self.denied({**request(), key: value})
        self.denied({**request(), "expires_at_ms": 1000})
        self.denied({**request(), "expires_at_ms": 6001})

    def test_stale_or_future_precondition_no_input(self):
        for now in (999, 4000, 5000):
            self.clock.now = now
            self.denied(request(), "STALE_CONTEXT")
        self.assertEqual(self.bridge.observations, [])

    def test_missing_ambiguous_disabled_target_denies(self):
        for changes, reason in (({"match_count": 0}, "TARGET_NOT_UNIQUE"),
                                ({"match_count": 2}, "TARGET_NOT_UNIQUE"),
                                ({"target_enabled": False}, "TARGET_NOT_ALLOWED")):
            self.bridge.before_changes = changes
            self.denied(request(), reason)

    def test_device_authorization_and_package_uncertainty_no_input(self):
        for changes, reason in (({"authorized": False}, "DEVICE_AUTHORIZATION_UNCERTAIN"),
                                ({"foreground_matches": False}, "FOREGROUND_MISMATCH")):
            self.bridge.before_changes = changes
            self.denied(request(), reason)

    def test_context_foreground_generation_target_rechecked_at_input(self):
        for changes in (
            {"identity": replace(CONTEXT, context_digest="9" * 64)},
            {"identity": replace(CONTEXT, foreground_digest="9" * 64)},
            {"identity": replace(CONTEXT, generation_digest="9" * 64)},
            {"target_digest": "9" * 64}, {"match_count": 2}, {"authorized": False}, {"foreground_matches": False},
        ):
            self.setUp()
            self.bridge.guard_changes = changes
            self.denied(request(), "DISPATCH_GUARD_DENIED")

    def test_permission_and_expiry_rechecked_at_input(self):
        self.bridge.on_dispatch = lambda: setattr(self, "permission", RuntimePolicy())
        self.denied(request(), "DISPATCH_GUARD_DENIED")
        self.setUp()
        self.bridge.on_dispatch = lambda: setattr(self.clock, "now", 4000)
        self.denied(request(), "DISPATCH_GUARD_DENIED")

    def test_already_satisfied_or_unknown_pre_predicate_denies(self):
        for value in (True, None):
            self.bridge.before_changes = {"predicate_matched": value}
            self.denied(request(), "PRECONDITION_FAILED")

    def test_absent_or_mismatched_post_executes_once_unverified(self):
        for value in (False, None):
            self.setUp()
            self.bridge.after_changes = {"predicate_matched": value}
            result = self.engine.tap(request())
            self.assertEqual(result["verification_status"], "UNVERIFIED")
            self.assertTrue(result["executed_once"])
            self.assertEqual(self.bridge.inputs, [OP])
            self.assertFalse(result["safe_to_retry_action"])

    def test_generic_change_or_success_alone_not_verification(self):
        self.bridge.after_changes = {"predicate_matched": False,
                                     "identity": replace(CONTEXT, context_digest="9" * 64)}
        self.assertEqual(self.engine.tap(request())["verification_status"], "UNVERIFIED")

    def test_post_package_authorization_and_generation_are_required(self):
        for changes in ({"foreground_matches": False}, {"authorized": False},
                        {"identity": replace(CONTEXT, generation_digest="9" * 64)}):
            self.setUp()
            self.bridge.after_changes = changes
            self.assertEqual(self.engine.tap(request())["verification_status"], "UNVERIFIED")

    def test_receipt_operation_mismatch_not_cured_by_matching_post(self):
        self.bridge.receipt_changes = {"operation_id": OTHER_OP}
        result = self.engine.tap(request())
        self.assertEqual((result["verification_status"], result["reason"]), ("UNCERTAIN", "RECEIPT_MISMATCH"))
        self.assertIsNone(result["executed_once"])

    def test_invalid_receipt_boolean_fails_closed(self):
        self.bridge.receipt_changes = {"executed_once": 1}
        self.assertEqual(self.engine.tap(request())["verification_status"], "UNCERTAIN")

    def test_observation_correlation_shape_and_staleness_fail_closed(self):
        for changes in ({"operation_id": OTHER_OP}, {"observed_at_ms": 999}, {"observed_at_ms": 2001},
                        {"authorized": 1}, {"target_digest": "not-a-digest"}):
            self.setUp()
            self.bridge.before_changes = changes
            self.denied(request(), "OBSERVATION_INVALID")
            self.bridge.before_changes = {}
            self.bridge.after_changes = changes
            self.assertEqual(self.engine.tap(request())["verification_status"], "UNVERIFIED")

    def test_post_predating_input_not_verified(self):
        self.bridge.on_dispatch = lambda: setattr(self.clock, "now", 2500)
        self.bridge.after_changes = {"observed_at_ms": 2000}
        self.assertEqual(self.engine.tap(request())["verification_status"], "UNVERIFIED")

    def test_exception_after_input_no_retry_and_safe_post_observation(self):
        self.bridge.raise_after_input = True
        result = self.engine.tap(request())
        self.assertEqual(result["verification_status"], "UNCERTAIN")
        self.assertIsNone(result["executed_once"])
        self.assertIsNotNone(result["after"])
        self.assertEqual(self.bridge.observations, ["before", "after"])
        self.assertEqual(self.engine.tap(request())["reason"], "ALREADY_ATTEMPTED")
        self.assertEqual(self.bridge.inputs, [OP])

    def test_post_observation_exception_is_unverified_no_retry(self):
        self.bridge.raise_observation = "after"
        result = self.engine.tap(request())
        self.assertEqual(result["verification_status"], "UNVERIFIED")
        self.assertIsNone(result["after"])
        self.assertEqual(self.bridge.inputs, [OP])

    def test_pre_observation_exception_zero_input(self):
        self.bridge.raise_observation = "before"
        self.denied(request(), "BACKEND_UNAVAILABLE")

    def test_duplicate_claim_and_capacity_no_eviction(self):
        self.engine.tap(request())
        self.assertEqual(self.engine.tap(request())["reason"], "ALREADY_ATTEMPTED")
        self.assertEqual(self.bridge.inputs, [OP])
        self.setUp()
        self.engine._attempted = {str(i) for i in range(MAX_OPERATIONS)}
        self.denied(request(), "ATTEMPT_LIMIT")

    def test_timeout_no_queued_work_or_late_input(self):
        release = threading.Event()
        self.bridge.safe_post_observation = False
        self.bridge.on_dispatch = lambda: release.wait(2)
        engine = ReflexTapExecutor(bridge=self.bridge, clock=self.clock, policy=lambda: self.permission, timeout_ms=20)
        try:
            self.assertEqual(engine.tap(request())["verification_status"], "UNCERTAIN")
            self.assertEqual(engine.tap({**request(), "operation_id": OTHER_OP})["reason"], "BUSY")
            self.assertEqual(self.bridge.observations, ["before"])
        finally:
            release.set()
        self.assertTrue(self.bridge.finished.wait(1))
        self.assertEqual(self.bridge.inputs, [])

    def test_policy_resuming_after_timeout_cannot_enable_late_input(self):
        release, entered = threading.Event(), threading.Event()
        reads = []
        def policy():
            reads.append(True)
            if len(reads) == 2:
                entered.set()
                release.wait(2)
            return self.permission
        engine = ReflexTapExecutor(bridge=self.bridge, clock=self.clock, policy=policy, timeout_ms=100)
        try:
            self.assertEqual(engine.tap(request())["verification_status"], "UNCERTAIN")
            self.assertTrue(entered.is_set())
        finally:
            release.set()
        self.assertTrue(self.bridge.finished.wait(1))
        self.assertEqual(len(reads), 2)
        self.assertEqual(self.bridge.inputs, [])

    def test_sanitized_result_audit_and_stdout_stderr(self):
        stream = io.StringIO()
        self.bridge.raise_after_input = True
        with redirect_stdout(stream), redirect_stderr(stream):
            result = self.engine.tap(request())
            malformed = self.engine.tap({**request(), "serial": CANARY})
        output = json.dumps([result, malformed, self.engine.audit]) + stream.getvalue()
        for value in (CANARY, "Settings", "com.example", "resource_id", "Traceback"):
            self.assertNotIn(value, output)
        self.assertEqual(stream.getvalue(), "")

    def test_audit_bounded_and_copies_immutable_to_caller(self):
        for _ in range(MAX_AUDIT + 5):
            self.engine.tap(None)
        self.assertEqual(len(self.engine.audit), MAX_AUDIT)
        copied = self.engine.audit
        copied[0]["verification_status"] = "VERIFIED"
        self.assertEqual(self.engine.audit[0]["verification_status"], "DENIED")

    def test_policy_invalid_or_exception_default_denies(self):
        for policy in (None, {}, RuntimePolicy(1, ()), RuntimePolicy(True, ("invalid",)),
                       RuntimePolicy(True, ("a" * 64, "a" * 64))):
            self.permission = policy
            self.denied(request(), "RUNTIME_PERMISSION_DENIED")
        with patch.object(self.engine, "_policy", side_effect=RuntimeError(CANARY)):
            self.denied(request(), "RUNTIME_PERMISSION_DENIED")

    def test_policy_file_missing_invalid_oversize_or_duplicate_denies(self):
        valid = {"schema_version": POLICY_CONTRACT, "enabled": True,
                 "allowed_binding_ids": [parse_request(request()).binding_id]}
        for raw in (b"", b"{", b"x" * 8193, json.dumps({**valid, "enabled": "true"}).encode(),
                    json.dumps({**valid, "profile": "elevated"}).encode(),
                    json.dumps({**valid, "allowed_binding_ids": ["x"]}).encode(),
                    b'{"schema_version":"phonebridge.reflex.policy.v1","enabled":false,"enabled":true,"allowed_binding_ids":[]}'):
            with patch.object(Path, "open", return_value=io.BytesIO(raw)):
                self.assertEqual(load_runtime_policy(), RuntimePolicy())
        with patch.object(Path, "open", side_effect=FileNotFoundError(CANARY)):
            self.assertEqual(load_runtime_policy(), RuntimePolicy())
        with patch.object(Path, "open", return_value=io.BytesIO(json.dumps(valid).encode())):
            self.assertEqual(load_runtime_policy(), allowed())

    def test_manifest_separate_readiness_and_atomicity_remain_false(self):
        manifest = contract_manifest()
        self.assertTrue(manifest["production_backend_implemented"])
        for key in ("stock_adb_atomic_context_guard", "runtime_ready", "live_reflex_ready", "durable_exactly_once"):
            self.assertFalse(manifest[key])


if __name__ == "__main__":
    unittest.main()
