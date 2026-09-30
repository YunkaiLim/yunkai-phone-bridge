"""Native wrapper acceptance using existing Python primitives over a fake ADB transport."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import unittest
from unittest.mock import patch

from phone_bridge import AndroidBridge, AndroidDevice, PhoneBridgeError
from reflex_native import NativeSemanticBridge
from reflex_tap import ReflexTapExecutor, RuntimePolicy
from test_phone_bridge import FakeBridge
from test_reflex_tap import CANARY, Clock, allowed, request


class NativeFake(FakeBridge):
    def __init__(self):
        super().__init__()
        self.post_visible = False
        self.change_on_input = True
        self.fail_after_input = False
        self.rows = [AndroidDevice(serial="PRIVATE_SERIAL_CANARY", state="device", details="private-device")]
        self.selects = []
        self.surface_change = {}
        self.match_change = lambda value, kwargs: value
        self.surface_reads = 0
        self.on_surface = lambda: None

    def devices(self):
        return self.rows

    def select_device(self, serial=None):
        self.selects.append(serial)
        if serial is None:
            raise AssertionError("implicit selection forbidden")
        return super().select_device(serial)

    def surface_identity(self, serial=None, *, limit=12):
        self.surface_reads += 1
        self.on_surface()
        return {**super().surface_identity(serial, limit=limit), **self.surface_change}

    def ui_elements(self, **kwargs):
        return self.match_change(super().ui_elements(**kwargs), kwargs)

    def _run(self, args, *, serial=None, timeout=15, binary=False):
        value = super()._run(args, serial=serial, timeout=timeout, binary=binary)
        if args[:4] == ["exec-out", "uiautomator", "dump", "/dev/tty"]:
            value = value.replace('text="Settings" content-desc=""', 'text="Settings" content-desc="Settings description"')
            if self.post_visible:
                value = value.replace("</node></hierarchy>",
                    '<node text="Done" content-desc="" resource-id="com.example:id/done" '
                    'class="android.widget.TextView" package="com.example" clickable="false" enabled="true" '
                    'bounds="[10,10][50,50]" /></node></hierarchy>')
        if args[:3] == ["shell", "input", "tap"]:
            if self.change_on_input:
                self.post_visible = not self.post_visible
            if self.fail_after_input:
                raise PhoneBridgeError(CANARY)
        return value

    @property
    def inputs(self):
        return [row for row in self.commands if row[2:4] == ["shell", "input"]]


class ReflexNativeTests(unittest.TestCase):
    def setUp(self):
        self.clock, self.fake = Clock(), NativeFake()
        self.value = request()
        self.native = NativeSemanticBridge(clock=self.clock, bridge_factory=lambda: self.fake)
        self.engine = ReflexTapExecutor(bridge=self.native, clock=self.clock,
                                       policy=lambda: allowed(self.value), timeout_ms=1000)

    def tap(self):
        return self.engine.tap(self.value)

    def test_existing_verified_primitive_called_once_with_fixed_options(self):
        original = AndroidBridge.tap_ui_element_verified
        calls = []
        def spy(instance, **kwargs):
            calls.append(kwargs)
            return original(instance, **kwargs)
        with patch.object(AndroidBridge, "tap_ui_element_verified", spy):
            result = self.tap()
        self.assertEqual(result["verification_status"], "VERIFIED")
        self.assertTrue(result["executed_once"])
        self.assertEqual(len(self.fake.inputs), 1)
        self.assertEqual(len(calls), 1)
        self.assertIsNone(calls[0]["index"])
        self.assertTrue(calls[0]["exact"])
        self.assertTrue(calls[0]["case_sensitive"])
        self.assertEqual(calls[0]["observation_attempts"], 1)
        self.assertEqual(calls[0]["observation_delay_ms"], 0)
        self.assertTrue(all(self.fake.selects))
        self.assertFalse(any(part in ("connect", "disconnect", "pair", "monkey", "text", "swipe", "keyevent")
                             for row in self.fake.commands for part in row))
        self.assertNotEqual(result["before"]["context_digest"], result["after"]["context_digest"])

    def test_all_three_semantic_selector_types(self):
        for selector in ({"text": "Settings"}, {"content_desc": "Settings description"},
                         {"resource_id": "com.example:id/settings"}):
            self.setUp()
            self.value["selector"] = selector
            self.assertEqual(self.tap()["verification_status"], "VERIFIED")
            self.assertEqual(len(self.fake.inputs), 1)

    def test_missing_or_ambiguous_selector_zero_input(self):
        for text in ("Missing", "Duplicate"):
            self.setUp()
            self.value["selector"] = {"text": text}
            self.assertEqual(self.tap()["reason"], "TARGET_NOT_UNIQUE")
            self.assertEqual(self.fake.inputs, [])

    def test_missing_unauthorized_offline_or_multiple_devices_zero_input(self):
        for rows in ([], [AndroidDevice("private", "unauthorized", "")],
                     [AndroidDevice("private", "offline", "")],
                     [AndroidDevice("one", "device", ""), AndroidDevice("two", "device", "")]):
            self.setUp()
            self.fake.rows = rows
            self.assertEqual(self.tap()["verification_status"], "DENIED")
            self.assertEqual(self.fake.inputs, [])
            self.assertEqual(self.fake.commands, [])

    def test_weak_or_disagreeing_foreground_source_zero_input(self):
        for change in ({"source": "dumpsys_fallback"}, {"source": "uia_visible_package_override"},
                       {"reported_package_name": "com.other"}, {"visible_packages": ["com.example", "com.other"]}):
            self.setUp()
            self.fake.surface_change = change
            self.assertEqual(self.tap()["verification_status"], "DENIED")
            self.assertEqual(self.fake.inputs, [])

    def test_malformed_surface_dimensions_and_signature_zero_input(self):
        for change in ({"input_size": []}, {"input_size": [True, 10]}, {"input_size": [0, 10]},
                       {"input_size": [32769, 10]}, {"orientation": "unknown"},
                       {"orientation": "portrait"}, {"semantic_signature": "not-a-digest"}):
            self.setUp()
            self.fake.surface_change = change
            self.assertEqual(self.tap()["verification_status"], "DENIED")
            self.assertEqual(self.fake.inputs, [])

    def test_context_changed_between_observations_zero_input(self):
        def change():
            if self.fake.surface_reads >= 3:
                self.fake.surface_change["activity"] = "ChangedActivity"
        self.fake.on_surface = change
        self.assertEqual(self.tap()["reason"], "DISPATCH_GUARD_DENIED")
        self.assertEqual(self.fake.inputs, [])

    def test_change_during_one_observation_zero_input(self):
        def change():
            if self.fake.surface_reads == 2:
                self.fake.surface_change["activity"] = "ChangedActivity"
        self.fake.on_surface = change
        self.assertEqual(self.tap()["verification_status"], "DENIED")
        self.assertEqual(self.fake.inputs, [])

    def test_wrong_foreground_precondition_zero_input(self):
        self.value["expected_package_name"] = "com.other"
        self.assertEqual(self.tap()["verification_status"], "DENIED")
        self.assertEqual(self.fake.inputs, [])

    def test_malformed_match_count_or_serial_zero_input(self):
        for key, replacement in (("count", True), ("count", 99), ("serial", "wrong")):
            self.setUp()
            self.fake.match_change = lambda value, kwargs: {**value, key: replacement}
            self.assertEqual(self.tap()["verification_status"], "DENIED")
            self.assertEqual(self.fake.inputs, [])

    def test_wrong_target_package_or_disabled_target_zero_input(self):
        for key, replacement in (("package", "com.other"), ("enabled", False), ("clickable", False)):
            self.setUp()
            def change(value, kwargs):
                if kwargs.get("text") == "Settings":
                    value["matches"][0][key] = replacement
                return value
            self.fake.match_change = change
            self.assertEqual(self.tap()["verification_status"], "DENIED")
            self.assertEqual(self.fake.inputs, [])

    def test_recomputed_target_center_must_equal_primitive_point(self):
        reads = []
        def change(value, kwargs):
            if kwargs.get("text") == "Settings":
                reads.append(True)
                if len(reads) >= 2:
                    value["matches"][0]["input_center"][0] += 1
            return value
        self.fake.match_change = change
        self.assertEqual(self.tap()["reason"], "DISPATCH_GUARD_DENIED")
        self.assertEqual(self.fake.inputs, [])

    def test_generic_legacy_success_without_explicit_post_is_unverified(self):
        self.fake.change_on_input = False
        result = self.tap()
        self.assertEqual(result["verification_status"], "UNVERIFIED")
        self.assertTrue(result["executed_once"])
        self.assertFalse(result["safe_to_retry_action"])
        self.assertEqual(len(self.fake.inputs), 1)

    def test_explicit_absence_predicate_supported(self):
        self.fake.post_visible = True
        self.value["expected_post"]["present"] = False
        self.assertEqual(self.tap()["verification_status"], "VERIFIED")
        self.assertEqual(len(self.fake.inputs), 1)

    def test_wrong_post_match_package_never_verifies(self):
        def change(value, kwargs):
            if kwargs.get("resource_id") == "com.example:id/done" and value["matches"]:
                value["matches"][0]["package"] = "com.other"
            return value
        self.fake.match_change = change
        self.assertEqual(self.tap()["verification_status"], "UNVERIFIED")
        self.assertEqual(len(self.fake.inputs), 1)

    def test_exception_after_possible_input_observes_post_but_never_retries(self):
        self.fake.fail_after_input = True
        result = self.tap()
        self.assertEqual(result["verification_status"], "UNCERTAIN")
        self.assertIsNone(result["executed_once"])
        self.assertIsNotNone(result["after"])
        self.assertFalse(result["safe_to_retry_action"])
        self.assertEqual(self.tap()["reason"], "ALREADY_ATTEMPTED")
        self.assertEqual(len(self.fake.inputs), 1)

    def test_observation_timestamp_before_reads_expiry_zero_input(self):
        self.fake.on_surface = lambda: setattr(self.clock, "now", 4000)
        result = self.tap()
        self.assertEqual(result["verification_status"], "DENIED")
        self.assertEqual(result["before"]["observed_at_ms"], 2000)
        self.assertEqual(self.fake.inputs, [])

    def test_private_native_evidence_is_not_returned_or_logged(self):
        stream = io.StringIO()
        self.fake.fail_after_input = True
        with redirect_stdout(stream), redirect_stderr(stream):
            result = self.tap()
        serialized = json.dumps([result, self.engine.audit]) + stream.getvalue()
        for secret in (CANARY, "PRIVATE_SERIAL_CANARY", "Settings", "com.example", "<node", "bounds", "ADB command"):
            self.assertNotIn(secret, serialized)
        self.assertEqual(stream.getvalue(), "")

    def test_default_deny_never_constructs_bridge(self):
        with patch.object(self.native, "_factory", side_effect=AssertionError("no ADB")) as factory:
            engine = ReflexTapExecutor(bridge=self.native, clock=self.clock, policy=lambda: RuntimePolicy())
            self.assertEqual(engine.tap(self.value)["reason"], "RUNTIME_PERMISSION_DENIED")
            factory.assert_not_called()

    def test_native_atomicity_and_concurrent_post_are_not_advertised(self):
        self.assertFalse(self.native.atomic_context_guard)
        self.assertFalse(self.native.safe_post_observation)


if __name__ == "__main__":
    unittest.main()

