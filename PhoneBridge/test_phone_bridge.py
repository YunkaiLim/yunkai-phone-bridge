from __future__ import annotations

import asyncio
import struct
import unittest
from pathlib import Path

from device_contract_adapter import (
    phone_capability_manifest,
    phone_contract_surfaces,
)
from phone_bridge import AndroidBridge, AndroidDevice, PhoneBridgeError, SAFE_KEYEVENTS
from server import _err, server
from yunkai_shared.device_contract import validate_device_snapshot


class FakeBridge(AndroidBridge):
    def __init__(self):
        self.adb_path = "adb"
        self.commands: list[list[str]] = []
        self.visual_hash_value = "0000000000000000"
        self.region_visual_hash_value = "0000000000000000"

    def screen_visual_hash(self, serial=None, hash_size=8):
        return self.visual_hash_value

    def screen_region_visual_hash(self, serial=None, **kwargs):
        return self.region_visual_hash_value

    def devices(self):
        from phone_bridge import AndroidDevice
        return [AndroidDevice(serial="ABC123", state="device", details="model:Test")]

    def _run(self, args, *, serial=None, timeout=15, binary=False):
        self.commands.append((["-s", serial] if serial else []) + args)
        if args[:3] == ["shell", "wm", "size"]:
            return "Physical size: 1080x2400\n"
        if args[:3] == ["exec-out", "screencap", "-p"]:
            return (
                b"\x89PNG\r\n\x1a\n"
                + b"\x00\x00\x00\rIHDR"
                + struct.pack(">II", 2400, 1080)
                + b"FAKE"
            )
        if args[:4] == ["exec-out", "uiautomator", "dump", "/dev/tty"]:
            return (
                '<?xml version="1.0"?><hierarchy>'
                '<node text="" content-desc="" resource-id="" class="android.widget.FrameLayout" '
                'package="com.example" clickable="false" enabled="true" bounds="[0,0][600,400]">'
                '<node text="Settings" content-desc="" resource-id="com.example:id/settings" '
                'class="android.widget.TextView" package="com.example" clickable="true" enabled="true" '
                'bounds="[100,100][300,200]" />'
                '<node text="Duplicate" content-desc="" resource-id="com.example:id/dup1" '
                'class="android.widget.TextView" package="com.example" clickable="true" enabled="true" '
                'bounds="[100,300][300,400]" />'
                '<node text="Duplicate" content-desc="" resource-id="com.example:id/dup2" '
                'class="android.widget.TextView" package="com.example" clickable="true" enabled="true" '
                'bounds="[400,300][600,400]" />'
                '</node></hierarchy>\nUI hierchary dumped to: /dev/tty'
            )
        if args[:3] == ["shell", "dumpsys", "window"]:
            return "mCurrentFocus=Window{abc u0 com.example/.MainActivity}"
        if args[:2] == ["shell", "monkey"]:
            return "Events injected: 1"
        return ""


class FakeWirelessBridge(AndroidBridge):
    def __init__(self, *, service_count: int = 1):
        self.adb_path = "adb"
        self.commands: list[list[str]] = []
        self.stdin_calls: list[tuple[list[str], str]] = []
        self.connected = False
        self.service_count = service_count
        self.endpoint = "192.168.1.50:37123"
        self.pair_endpoint = "192.168.1.50:41234"

    def _run(self, args, *, serial=None, timeout=15, binary=False):
        self.commands.append((["-s", serial] if serial else []) + args)
        if args == ["devices", "-l"]:
            if self.connected:
                return (
                    "List of devices attached\n"
                    f"{self.endpoint} device product:Test model:Wireless device:test transport_id:2\n"
                )
            return "List of devices attached\n"
        if args == ["mdns", "services"]:
            lines = ["List of discovered mdns services"]
            lines.append(
                f"adb-test-pair _adb-tls-pairing._tcp {self.pair_endpoint}"
            )
            for index in range(self.service_count):
                endpoint = self.endpoint if index == 0 else f"192.168.1.{60 + index}:37{120 + index}"
                lines.append(
                    f"adb-test-{index} _adb-tls-connect._tcp {endpoint}"
                )
            return "\n".join(lines) + "\n"
        if args[:1] == ["connect"]:
            self.connected = True
            return f"connected to {args[1]}\n"
        if args[:1] == ["disconnect"]:
            self.connected = False
            return f"disconnected {args[1]}\n"
        return ""

    def _run_with_stdin(self, args, stdin_text, *, timeout=20):
        self.stdin_calls.append((list(args), stdin_text))
        return f"Successfully paired to {args[1]} [guid=test]\n"


class FakeOfflineRecoveryBridge(AndroidBridge):
    def __init__(
        self,
        *,
        device_rows=None,
        mdns_endpoints=None,
        connect_behavior="success",
        post_connect_state="device",
        fail_tap=False,
    ):
        self.adb_path = "adb"
        self.commands: list[list[str]] = []
        self.device_observations = 0
        self.device_rows = list(
            device_rows
            if device_rows is not None
            else [("192.168.1.50:37123", "offline", "product:Test model:Wireless")]
        )
        self.mdns_endpoints = list(mdns_endpoints or [])
        self.connect_behavior = connect_behavior
        self.post_connect_state = post_connect_state
        self.connected_endpoint = None
        self.fail_tap = fail_tap

    def _run(self, args, *, serial=None, timeout=15, binary=False):
        command = (["-s", serial] if serial else []) + args
        self.commands.append(command)
        if args == ["devices", "-l"]:
            self.device_observations += 1
            rows = list(self.device_rows)
            if self.connected_endpoint and all(row[0] != self.connected_endpoint for row in rows):
                rows.append((self.connected_endpoint, self.post_connect_state, "model:Recovered"))
            rendered = ["List of devices attached"]
            for endpoint, initial_state, details in rows:
                state = (
                    self.post_connect_state
                    if endpoint == self.connected_endpoint
                    else initial_state
                )
                rendered.append(f"{endpoint} {state} {details}".rstrip())
            return "\n".join(rendered) + "\n"
        if args == ["mdns", "services"]:
            rendered = ["List of discovered mdns services"]
            for index, endpoint in enumerate(self.mdns_endpoints):
                rendered.append(f"adb-test-{index} _adb-tls-connect._tcp {endpoint}")
            return "\n".join(rendered) + "\n"
        if args[:1] == ["connect"]:
            if self.connect_behavior == "timeout":
                raise PhoneBridgeError(f"ADB command timed out after {timeout}s.")
            if self.connect_behavior == "failure":
                raise PhoneBridgeError("ADB connect failed.")
            if self.connect_behavior == "unclear":
                return "unexpected adb output\n"
            self.connected_endpoint = args[1]
            return f"connected to {args[1]}\n"
        if args[:3] == ["shell", "input", "tap"]:
            if self.fail_tap:
                raise PhoneBridgeError("Simulated tap transport failure.")
            return ""
        return ""

    def _validate_point(self, x, y, serial):
        return int(x), int(y)


class FakeGameBridge(FakeBridge):
    def _run(self, args, *, serial=None, timeout=15, binary=False):
        if args[:4] == ["exec-out", "uiautomator", "dump", "/dev/tty"]:
            return (
                '<?xml version="1.0"?><hierarchy rotation="1">'
                '<node text="" content-desc="Game view" resource-id="" class="android.view.View" '
                'package="com.example.game" clickable="false" enabled="true" bounds="[0,0][1601,719]" />'
                '</hierarchy>'
            )
        return super()._run(args, serial=serial, timeout=timeout, binary=binary)


class FakeGameMotionBridge(FakeBridge):
    def _run(self, args, *, serial=None, timeout=15, binary=False):
        if len(args) >= 3 and args[:3] == ["shell", "input", "swipe"]:
            self.region_visual_hash_value = "000000000000001f"
        return super()._run(args, serial=serial, timeout=timeout, binary=binary)


class FakeTransientLauncherBridge(FakeBridge):
    def _run(self, args, *, serial=None, timeout=15, binary=False):
        if args[:3] == ["shell", "dumpsys", "window"]:
            return "mCurrentFocus=Window{abc u0 com.android.launcher3/.Launcher}"
        return super()._run(args, serial=serial, timeout=timeout, binary=binary)


class FakeLockedBridge(FakeBridge):
    def _run(self, args, *, serial=None, timeout=15, binary=False):
        if args[:4] == ["exec-out", "uiautomator", "dump", "/dev/tty"]:
            return (
                '<?xml version="1.0"?><hierarchy>'
                '<node text="" content-desc="上滑即可解锁设备" resource-id="com.android.systemui:id/main_content" '
                'class="android.widget.FrameLayout" package="com.android.systemui" clickable="false" enabled="true" '
                'bounds="[0,0][1080,2400]" />'
                '</hierarchy>'
            )
        if args[:3] == ["shell", "dumpsys", "window"]:
            return "mCurrentFocus=Window{abc u0 com.example/.MainActivity}"
        if args[:3] == ["shell", "dumpsys", "power"]:
            return "mWakefulness=Awake\nmInteractive=true\n"
        return super()._run(args, serial=serial, timeout=timeout, binary=binary)


class FakePortraitGameBridge(FakeBridge):
    def _run(self, args, *, serial=None, timeout=15, binary=False):
        if args[:3] == ["exec-out", "screencap", "-p"]:
            return (
                b"\x89PNG\r\n\x1a\n"
                + b"\x00\x00\x00\rIHDR"
                + struct.pack(">II", 1080, 2400)
                + b"FAKE"
            )
        return super()._run(args, serial=serial, timeout=timeout, binary=binary)


class PhoneBridgeTests(unittest.TestCase):
    def test_unified_phone_contract_is_deterministic_valid_and_fail_closed(self):
        first_manifest = phone_capability_manifest()
        second_manifest = phone_capability_manifest()
        self.assertEqual(first_manifest, second_manifest)
        self.assertEqual(first_manifest["bridge"]["id"], "phone.android")
        self.assertEqual(first_manifest["contract_versions"]["device_contract"], 1)
        for capability_ids in first_manifest["capability_groups"].values():
            self.assertTrue(all(item.startswith("phone.") for item in capability_ids))

        surfaces = phone_contract_surfaces(
            vision_recommended=False,
            local_vision_status={"configured": False, "enabled": False},
        )
        snapshot = surfaces["device_snapshot"]
        self.assertEqual(validate_device_snapshot(snapshot), snapshot)
        self.assertEqual(snapshot["device"]["device_id"], "phone.android")
        self.assertEqual(snapshot["contract"]["version"], "0.1")
        self.assertFalse(snapshot["observability"]["audit"]["supported"])
        self.assertFalse(snapshot["observability"]["operation_trace"]["supported"])

        tap_state = snapshot["capability_state"]["states"]["phone.touch.tap"]
        tap_permission = snapshot["permission_state"]["states"]["phone.touch.tap"]
        swipe_permission = snapshot["permission_state"]["states"]["phone.touch.swipe"]
        game_permission = snapshot["permission_state"]["states"]["phone.game.joystick_move"]
        self.assertEqual(tap_state["availability"], "available")
        self.assertEqual(snapshot["runtime_policy"]["runtime_profile"], "standard")
        self.assertEqual(tap_permission["state"], "allowed")
        self.assertEqual(swipe_permission["state"], "allowed")
        self.assertEqual(game_permission["state"], "denied")
        self.assertEqual(game_permission["required_tier"], "elevated_input")
        self.assertNotIn("permission", tap_state)
        self.assertEqual(
            snapshot["planner_routing_hints"]["routes"]["semantic_action"]["status"],
            "ready",
        )
        self.assertEqual(
            snapshot["planner_routing_hints"]["routes"]["connection"]["status"],
            "ready",
        )
        self.assertFalse(snapshot["safety_invariants"]["wireless_pairing_code_persisted"])
        self.assertFalse(snapshot["safety_invariants"]["wireless_public_endpoint_allowed"])
        self.assertEqual(
            snapshot["capability_state"]["states"]["phone.local_vision_fallback"][
                "availability"
            ],
            "unavailable",
        )

    def test_unified_phone_contract_marks_sparse_surface_degraded_without_inventing_support(self):
        surfaces = phone_contract_surfaces(
            vision_recommended=True,
            local_vision_status={"configured": False, "enabled": False},
        )
        snapshot = surfaces["device_snapshot"]
        self.assertEqual(
            snapshot["capability_state"]["states"]["phone.uia.inspect"]["availability"],
            "degraded",
        )
        self.assertEqual(
            snapshot["planner_routing_hints"]["routes"]["perception"]["status"],
            "degraded",
        )
        self.assertFalse(snapshot["verification"]["expected_postconditions_supported"])
        self.assertTrue(snapshot["verification"]["verified_single_action_supported"])
        self.assertTrue(snapshot["verification"]["bounded_observation_stabilization_supported"])

    def test_wireless_endpoint_validation_rejects_public_hosts(self):
        self.assertEqual(
            AndroidBridge._normalize_local_wireless_endpoint("192.168.1.50:37123"),
            "192.168.1.50:37123",
        )
        self.assertEqual(
            AndroidBridge._normalize_local_wireless_endpoint("phone.local:37123"),
            "phone.local:37123",
        )
        self.assertEqual(
            AndroidDevice("phone.local:37123", "offline", "").transport,
            "wireless",
        )
        with self.assertRaises(PhoneBridgeError):
            AndroidBridge._normalize_local_wireless_endpoint("8.8.8.8:37123")

    def test_wireless_status_parses_pair_and_connect_mdns_services(self):
        bridge = FakeWirelessBridge()
        status = bridge.wireless_status()
        self.assertTrue(status["wireless_supported"])
        self.assertFalse(status["pairing_code_persisted"])
        self.assertEqual(len(status["pairing_services"]), 1)
        self.assertEqual(len(status["connect_services"]), 1)
        self.assertEqual(status["connect_services"][0]["endpoint"], bridge.endpoint)

    def test_wireless_pair_uses_stdin_without_echoing_pairing_code(self):
        bridge = FakeWirelessBridge()
        result = bridge.pair_wireless(bridge.pair_endpoint, "123456", auto_connect=False)
        self.assertTrue(result["paired"])
        self.assertFalse(result["pairing_code_persisted"])
        self.assertNotIn("123456", str(result))
        args, stdin_text = bridge.stdin_calls[-1]
        self.assertEqual(args, ["pair", bridge.pair_endpoint])
        self.assertNotIn("123456", " ".join(args))
        self.assertEqual(stdin_text, "123456\n")
        with self.assertRaises(PhoneBridgeError):
            bridge.pair_wireless(bridge.pair_endpoint, "12ab56", auto_connect=False)

    def test_select_device_auto_reconnects_single_wireless_mdns_service(self):
        bridge = FakeWirelessBridge()
        self.assertFalse(bridge.connected)
        selected = bridge.select_device()
        self.assertTrue(bridge.connected)
        self.assertEqual(selected, bridge.endpoint)
        self.assertTrue(any(command[:1] == ["connect"] for command in bridge.commands))

    def test_wireless_refresh_fails_closed_on_ambiguous_mdns_services(self):
        bridge = FakeWirelessBridge(service_count=2)
        result = bridge.refresh_wireless_connection()
        self.assertFalse(result["connected"])
        self.assertEqual(result["reason_code"], "AMBIGUOUS_MDNS_CONNECT_SERVICE")
        self.assertFalse(any(command[:1] == ["connect"] for command in bridge.commands))

    def test_single_offline_wireless_endpoint_recovers_once_and_reobserves_once(self):
        bridge = FakeOfflineRecoveryBridge()
        result = bridge.refresh_wireless_connection()
        self.assertTrue(result["connected"])
        self.assertEqual(
            result["reason_code"],
            "RECOVERED_SINGLE_OFFLINE_WIRELESS_ENDPOINT",
        )
        self.assertEqual(result["recovery"]["source"], "offline_devices")
        self.assertEqual(result["recovery"]["adb_connect_attempts"], 1)
        self.assertEqual(result["recovery"]["adb_devices_reobserve_attempts"], 1)
        self.assertEqual(bridge.device_observations, 2)
        self.assertEqual(
            len([command for command in bridge.commands if command[:1] == ["connect"]]),
            1,
        )

    def test_multiple_offline_wireless_candidates_never_connect(self):
        bridge = FakeOfflineRecoveryBridge(
            device_rows=[
                ("192.168.1.50:37123", "offline", "model:One"),
                ("192.168.1.51:37124", "offline", "model:Two"),
            ]
        )
        result = bridge.refresh_wireless_connection()
        self.assertFalse(result["connected"])
        self.assertEqual(result["reason_code"], "AMBIGUOUS_OFFLINE_WIRELESS_ENDPOINT")
        self.assertFalse(any(command[:1] == ["connect"] for command in bridge.commands))
        self.assertEqual(bridge.device_observations, 1)

    def test_single_mdns_service_remains_preferred_over_offline_endpoint(self):
        mdns_endpoint = "192.168.1.77:37177"
        bridge = FakeOfflineRecoveryBridge(mdns_endpoints=[mdns_endpoint])
        result = bridge.refresh_wireless_connection()
        connect_commands = [command for command in bridge.commands if command[:1] == ["connect"]]
        self.assertTrue(result["connected"])
        self.assertEqual(result["reason_code"], "RECOVERED_SINGLE_MDNS_CONNECT_SERVICE")
        self.assertEqual(result["recovery"]["source"], "mdns")
        self.assertEqual(connect_commands, [["connect", mdns_endpoint]])

    def test_ambiguous_mdns_does_not_fall_through_to_single_offline_endpoint(self):
        bridge = FakeOfflineRecoveryBridge(
            mdns_endpoints=["192.168.1.77:37177", "192.168.1.78:37178"],
        )
        result = bridge.refresh_wireless_connection()
        self.assertFalse(result["connected"])
        self.assertEqual(result["reason_code"], "AMBIGUOUS_MDNS_CONNECT_SERVICE")
        self.assertFalse(any(command[:1] == ["connect"] for command in bridge.commands))

    def test_offline_recovery_connect_failure_and_timeout_fail_closed(self):
        for behavior, reason_code in (
            ("failure", "ADB_CONNECT_FAILED"),
            ("timeout", "ADB_CONNECT_TIMEOUT"),
        ):
            with self.subTest(behavior=behavior):
                bridge = FakeOfflineRecoveryBridge(connect_behavior=behavior)
                result = bridge.refresh_wireless_connection()
                self.assertFalse(result["connected"])
                self.assertEqual(result["reason_code"], reason_code)
                self.assertEqual(result["recovery"]["adb_connect_attempts"], 1)
                self.assertEqual(result["recovery"]["adb_devices_reobserve_attempts"], 0)
                self.assertEqual(bridge.device_observations, 1)
                self.assertEqual(
                    len([command for command in bridge.commands if command[:1] == ["connect"]]),
                    1,
                )

    def test_offline_recovery_unclear_connect_output_and_nonready_reobserve_fail_closed(self):
        unclear = FakeOfflineRecoveryBridge(connect_behavior="unclear")
        unclear_result = unclear.refresh_wireless_connection()
        self.assertEqual(unclear_result["reason_code"], "ADB_CONNECT_OUTPUT_UNCLEAR")
        self.assertEqual(unclear.device_observations, 1)

        nonready = FakeOfflineRecoveryBridge(post_connect_state="offline")
        nonready_result = nonready.refresh_wireless_connection()
        self.assertEqual(
            nonready_result["reason_code"],
            "WIRELESS_ENDPOINT_NOT_READY_AFTER_CONNECT",
        )
        self.assertEqual(nonready.device_observations, 2)
        self.assertEqual(
            len([command for command in nonready.commands if command[:1] == ["connect"]]),
            1,
        )

    def test_usb_unauthorized_unknown_and_public_endpoints_are_not_recovery_candidates(self):
        bridge = FakeOfflineRecoveryBridge(
            device_rows=[
                ("USB-OFFLINE", "offline", "usb:1-1 model:Usb"),
                ("192.168.1.60:37160", "unauthorized", "model:Unauthorized"),
                ("192.168.1.61:37161", "unknown", "model:Unknown"),
                ("8.8.8.8:37162", "offline", "model:Public"),
            ]
        )
        result = bridge.refresh_wireless_connection()
        self.assertFalse(result["connected"])
        self.assertEqual(result["reason_code"], "NO_ELIGIBLE_OFFLINE_WIRELESS_ENDPOINT")
        self.assertFalse(any(command[:1] == ["connect"] for command in bridge.commands))
        self.assertEqual(
            result["rejected_candidates"][0]["reason_code"],
            "NON_LOCAL_WIRELESS_ENDPOINT",
        )

    def test_ready_usb_is_unaffected_and_prevents_recovery(self):
        bridge = FakeOfflineRecoveryBridge(
            device_rows=[
                ("USB123", "device", "usb:1-1 model:Usb"),
                ("192.168.1.50:37123", "offline", "model:Wireless"),
            ],
            mdns_endpoints=["192.168.1.77:37177"],
        )
        self.assertEqual(bridge.select_device(), "USB123")
        self.assertFalse(any(command == ["mdns", "services"] for command in bridge.commands))
        self.assertFalse(any(command[:1] == ["connect"] for command in bridge.commands))

    def test_explicit_refresh_preserves_mdns_connect_with_ready_usb(self):
        mdns_endpoint = "192.168.1.77:37177"
        bridge = FakeOfflineRecoveryBridge(
            device_rows=[("USB123", "device", "usb:1-1 model:Usb")],
            mdns_endpoints=[mdns_endpoint],
        )
        result = bridge.refresh_wireless_connection()
        self.assertTrue(result["connected"])
        self.assertEqual(result["recovery"]["source"], "mdns")
        self.assertEqual(
            [command for command in bridge.commands if command[:1] == ["connect"]],
            [["connect", mdns_endpoint]],
        )

    def test_explicit_offline_serial_fails_without_automatic_recovery(self):
        endpoint = "192.168.1.50:37123"
        bridge = FakeOfflineRecoveryBridge(
            mdns_endpoints=["192.168.1.77:37177"],
        )
        with self.assertRaises(PhoneBridgeError):
            bridge.select_device(endpoint)
        self.assertFalse(any(command == ["mdns", "services"] for command in bridge.commands))
        self.assertFalse(any(command[:1] == ["connect"] for command in bridge.commands))

    def test_selection_failure_exposes_structured_recovery_diagnostics(self):
        bridge = FakeOfflineRecoveryBridge(
            device_rows=[
                ("192.168.1.50:37123", "offline", "model:One"),
                ("192.168.1.51:37124", "offline", "model:Two"),
            ]
        )
        with self.assertRaises(PhoneBridgeError) as raised:
            bridge.select_device()
        payload = _err(raised.exception)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["reason_code"], "AMBIGUOUS_OFFLINE_WIRELESS_ENDPOINT")
        self.assertEqual(
            payload["diagnostics"]["recovery"]["adb_connect_attempts"],
            0,
        )

    def test_transport_recovery_does_not_retry_ui_action(self):
        bridge = FakeOfflineRecoveryBridge(fail_tap=True)
        with self.assertRaises(PhoneBridgeError):
            bridge.tap(100, 200)
        self.assertEqual(
            len([command for command in bridge.commands if command[:1] == ["connect"]]),
            1,
        )
        self.assertEqual(
            len(
                [
                    command
                    for command in bridge.commands
                    if len(command) >= 5 and command[-5:-2] == ["shell", "input", "tap"]
                ]
            ),
            1,
        )

    def test_device_selection(self):
        bridge = FakeBridge()
        self.assertEqual(bridge.select_device(), "ABC123")

    def test_tap_validates_bounds(self):
        bridge = FakeBridge()
        result = bridge.tap(100, 200)
        self.assertEqual(result["action"], "tap")
        bridge.tap(2000, 200)
        with self.assertRaises(PhoneBridgeError):
            bridge.tap(2500, 200)

    def test_screenshot(self):
        bridge = FakeBridge()
        data = bridge.screenshot_png()
        self.assertTrue(data.startswith(b"\x89PNG"))

    def test_screen_size_uses_rotated_screenshot_dimensions(self):
        bridge = FakeBridge()
        self.assertEqual(bridge.screen_size(), (2400, 1080))

    def test_screen_context_compacts_accessibility_tree(self):
        bridge = FakeBridge()
        result = bridge.screen_context()
        self.assertEqual(result["orientation"], "landscape")
        self.assertEqual(result["packages"], ["com.example"])
        self.assertFalse(result["vision_recommended"])
        self.assertEqual(result["clickable_node_count"], 3)
        self.assertEqual(result["elements"][0]["text"], "Settings")
        self.assertEqual(len(result["semantic_signature"]), 24)
        self.assertFalse(result["semantic_signature_truncated"])

    def test_screen_context_signature_is_independent_of_return_limit(self):
        bridge = FakeBridge()
        compact = bridge.screen_context(limit=1)
        expanded = bridge.screen_context(limit=40)
        self.assertEqual(compact["semantic_signature"], expanded["semantic_signature"])
        self.assertEqual(compact["element_count"], 1)
        self.assertGreater(expanded["element_count"], compact["element_count"])

    def test_shared_verifier_detects_semantic_and_surface_state(self):
        bridge = FakeBridge()
        context = bridge.screen_context()
        unchanged = bridge.verify_state_change(
            context["semantic_signature"],
            previous_package_name="com.example",
            previous_activity=".MainActivity",
            verification_policy="semantic_or_window",
        )
        self.assertFalse(unchanged["verification_passed"])
        self.assertFalse(unchanged["semantic_changed"])
        self.assertFalse(unchanged["surface_identity_changed"])
        self.assertEqual(unchanged["verification_contract"]["schema_version"], 1)

        changed_surface = bridge.verify_state_change(
            context["semantic_signature"],
            previous_package_name="com.other",
            previous_activity=".OtherActivity",
            verification_policy="window_only",
        )
        self.assertTrue(changed_surface["verification_passed"])
        self.assertTrue(changed_surface["surface_identity_changed"])
        self.assertEqual(changed_surface["verification_contract"]["decision"], "pass")

    def test_visual_hash_distance_is_bounded_and_deterministic(self):
        self.assertEqual(AndroidBridge._hex_hamming_distance("00", "0f"), 4)
        with self.assertRaises(PhoneBridgeError):
            AndroidBridge._hex_hamming_distance("0", "00")

    def test_screen_context_recommends_vision_for_game_surface(self):
        bridge = FakeGameBridge()
        result = bridge.screen_context()
        self.assertTrue(result["vision_recommended"])
        self.assertEqual(result["packages"], ["com.example.game"])
        self.assertEqual(result["elements"][0]["content_desc"], "Game view")

    def test_find_ui_element_maps_bounds_to_input_coordinates(self):
        bridge = FakeBridge()
        result = bridge.ui_elements(text="Settings")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["matches"][0]["bounds"], [100, 100, 300, 200])
        self.assertEqual(result["matches"][0]["input_center"], [800, 405])

    def test_tap_ui_element_uses_mapped_center(self):
        bridge = FakeBridge()
        result = bridge.tap_ui_element(text="Settings")
        self.assertEqual(result["action"], "tap_ui_element")
        self.assertEqual(result["element"]["input_center"], [800, 405])
        self.assertIn(["-s", "ABC123", "shell", "input", "tap", "800", "405"], bridge.commands)

    def test_tap_ui_element_rejects_ambiguous_match_without_index(self):
        bridge = FakeBridge()
        with self.assertRaises(PhoneBridgeError):
            bridge.tap_ui_element(text="Duplicate")
        result = bridge.tap_ui_element(text="Duplicate", index=1)
        self.assertEqual(result["match_index"], 1)

    def test_verified_tap_executes_once_and_uses_bounded_observation(self):
        bridge = FakeBridge()
        result = bridge.tap_verified(
            100,
            200,
            expected_package_name="com.example",
            observation_attempts=2,
            observation_delay_ms=0,
        )
        self.assertTrue(result["action_executed_once"])
        self.assertFalse(result["automatic_action_retry"])
        tap_commands = [command for command in bridge.commands if command[-5:-2] == ["shell", "input", "tap"]]
        self.assertEqual(len(tap_commands), 1)
        self.assertEqual(result["observation_attempts_used"], 2)
        self.assertEqual(result["execution_status"], "EXECUTED_UNVERIFIED")
        self.assertFalse(result["safe_to_retry_action"])

    def test_verified_semantic_tap_uses_single_verified_action(self):
        bridge = FakeBridge()
        result = bridge.tap_ui_element_verified(
            text="Settings",
            expected_package_name="com.example",
            observation_attempts=1,
            observation_delay_ms=0,
        )
        self.assertEqual(result["action"], "tap_ui_element_verified")
        self.assertEqual(result["element"]["text"], "Settings")
        self.assertTrue(result["action_executed_once"])
        tap_commands = [command for command in bridge.commands if command[-5:-2] == ["shell", "input", "tap"]]
        self.assertEqual(len(tap_commands), 1)

    def test_verified_tap_fails_closed_on_foreground_package_mismatch(self):
        bridge = FakeBridge()
        with self.assertRaises(PhoneBridgeError):
            bridge.tap_verified(
                100,
                200,
                expected_package_name="com.other",
                observation_delay_ms=0,
            )
        self.assertFalse(any(command[-5:-2] == ["shell", "input", "tap"] for command in bridge.commands))

    def test_directional_swipe_uses_safe_center_origin(self):
        bridge = FakeBridge()
        result = bridge.swipe_direction("up", distance_ratio=0.30, duration_ms=300)
        self.assertEqual(result["action"], "swipe_direction")
        self.assertEqual(result["direction"], "up")
        self.assertEqual(result["start"], [1200, 540])
        self.assertLess(result["end"][1], result["start"][1])
        self.assertGreater(result["end"][1], 0)

    def test_verified_directional_swipe_executes_once(self):
        bridge = FakeBridge()
        result = bridge.swipe_direction_verified(
            "left",
            expected_package_name="com.example",
            observation_attempts=1,
            observation_delay_ms=0,
        )
        swipe_commands = [
            command
            for command in bridge.commands
            if len(command) >= 9 and command[-8:-5] == ["shell", "input", "swipe"]
        ]
        self.assertEqual(len(swipe_commands), 1)
        self.assertTrue(result["action_executed_once"])
        self.assertFalse(result["safe_to_retry_action"])
        self.assertEqual(result["direction"], "left")

    def test_verified_long_press_executes_once(self):
        bridge = FakeBridge()
        result = bridge.long_press_verified(
            100,
            200,
            expected_package_name="com.example",
            observation_attempts=1,
            observation_delay_ms=0,
        )
        long_press_commands = [
            command
            for command in bridge.commands
            if len(command) >= 10
            and command[-8:-5] == ["shell", "input", "swipe"]
            and command[-5] == command[-3]
            and command[-4] == command[-2]
        ]
        self.assertEqual(len(long_press_commands), 1)
        self.assertTrue(result["action_executed_once"])
        self.assertFalse(result["safe_to_retry_action"])

    def test_verified_text_and_key_execute_once(self):
        bridge = FakeBridge()
        typed = bridge.type_text_verified(
            "hello world",
            expected_package_name="com.example",
            observation_attempts=1,
            observation_delay_ms=0,
        )
        keyed = bridge.keyevent_verified(
            "BACK",
            expected_package_name="com.example",
            observation_attempts=1,
            observation_delay_ms=0,
        )
        text_commands = [command for command in bridge.commands if command[-4:-1] == ["shell", "input", "text"]]
        key_commands = [command for command in bridge.commands if command[-4:-1] == ["shell", "input", "keyevent"]]
        self.assertEqual(len(text_commands), 1)
        self.assertEqual(len(key_commands), 1)
        self.assertTrue(typed["action_executed_once"])
        self.assertTrue(keyed["action_executed_once"])
        self.assertFalse(typed["safe_to_retry_action"])
        self.assertFalse(keyed["safe_to_retry_action"])

    def test_wait_for_ui_element_is_read_only_and_bounded(self):
        bridge = FakeBridge()
        found = bridge.wait_for_ui_element(
            text="Settings",
            observation_attempts=3,
            observation_delay_ms=0,
        )
        missing = bridge.wait_for_ui_element(
            text="NeverThere",
            observation_attempts=2,
            observation_delay_ms=0,
        )
        self.assertTrue(found["condition_met"])
        self.assertEqual(found["attempts_used"], 1)
        self.assertFalse(missing["condition_met"])
        self.assertEqual(missing["attempts_used"], 2)
        self.assertFalse(any(command[-3:-1] == ["input", "tap"] for command in bridge.commands))

    def test_verifier_prefers_visible_uia_package_over_transient_launcher(self):
        bridge = FakeTransientLauncherBridge()
        context = bridge.screen_context()
        result = bridge.verify_state_change(
            context["semantic_signature"],
            previous_package_name="com.example",
            verification_policy="window_only",
        )
        self.assertFalse(result["verification_passed"])
        self.assertEqual(result["current"]["package_name"], "com.example")
        self.assertEqual(result["current"]["reported_package_name"], "com.android.launcher3")
        self.assertEqual(result["current"]["identity_source"], "uia_visible_package_override")

    def test_device_state_detects_lockscreen_and_blocks_game_input(self):
        bridge = FakeLockedBridge()
        state = bridge.device_state_snapshot()
        self.assertTrue(state["locked"])
        self.assertFalse(state["ready_for_landscape_game"])
        with self.assertRaisesRegex(PhoneBridgeError, "DEVICE_LOCKED"):
            bridge.game_joystick_move(
                "up",
                400,
                expected_package_name="com.example",
                observation_attempts=1,
                observation_delay_ms=0,
            )

    def test_game_input_rejects_portrait_orientation_before_action(self):
        bridge = FakePortraitGameBridge()
        with self.assertRaisesRegex(PhoneBridgeError, "GAME_ORIENTATION_MISMATCH"):
            bridge.game_joystick_move(
                "up",
                400,
                expected_package_name="com.example",
                observation_attempts=1,
                observation_delay_ms=0,
            )
        self.assertFalse(
            any(len(command) >= 8 and command[-7:-4] == ["shell", "input", "swipe"] for command in bridge.commands)
        )

    def test_game_camera_drag_stays_inside_safe_region_and_executes_once(self):
        bridge = FakeBridge()
        result = bridge.game_camera_drag(
            "right",
            180,
            expected_package_name="com.example",
            observation_attempts=1,
            observation_delay_ms=0,
        )
        self.assertTrue(result["action_executed_once"])
        left, top, right, bottom = result["safe_region"]
        start_x, start_y = result["action_result"]["start"]
        end_x, end_y = result["action_result"]["end"]
        self.assertTrue(left <= start_x <= right and top <= start_y <= bottom)
        self.assertTrue(left <= end_x <= right and top <= end_y <= bottom)

    def test_game_world_region_can_verify_motion_when_shared_hash_is_static(self):
        bridge = FakeGameMotionBridge()
        result = bridge.game_joystick_move(
            "up",
            600,
            expected_package_name="com.example",
            observation_attempts=1,
            observation_delay_ms=0,
        )
        self.assertTrue(result["verification_passed"])
        self.assertEqual(result["execution_status"], "EXECUTED_VERIFIED")
        self.assertEqual(result["verification_source"], "game_world_region")
        self.assertGreaterEqual(
            result["game_motion_verification"]["visual_hamming_distance"],
            result["game_motion_verification"]["visual_hamming_threshold"],
        )
        self.assertFalse(result["safe_to_retry_action"])

    def test_game_joystick_move_is_bounded_guarded_and_single_action(self):
        bridge = FakeBridge()
        result = bridge.game_joystick_move(
            "up",
            6000,
            expected_package_name="com.example",
            observation_attempts=1,
            observation_delay_ms=0,
        )
        self.assertEqual(result["action_result"]["direction"], "up")
        self.assertEqual(result["action_result"]["duration_ms"], 6000)
        self.assertEqual(result["action_result"]["motion_model"], "adb_long_swipe")
        self.assertTrue(result["action_executed_once"])
        joystick_commands = [
            command
            for command in bridge.commands
            if len(command) >= 9 and command[-8:-5] == ["shell", "input", "swipe"]
        ]
        self.assertEqual(len(joystick_commands), 1)
        self.assertEqual(result["execution_status"], "EXECUTED_UNVERIFIED")
        self.assertFalse(result["safe_to_retry_action"])

    def test_secure_tunnel_launcher_allows_phone_hotplug(self):
        script = Path(__file__).with_name("Start-PhoneBridge-SecureTunnel.ps1").read_text(encoding="utf-8")
        self.assertIn("[WAITING FOR PHONE]", script)
        self.assertIn("re-checks ADB on every tool call", script)
        self.assertNotIn("throw 'No authorized Android device is visible to ADB.'", script)

    def test_secure_tunnel_launcher_tolerates_normal_adb_startup_stderr(self):
        script = Path(__file__).with_name("Start-PhoneBridge-SecureTunnel.ps1").read_text(encoding="utf-8")
        self.assertIn("$previousErrorActionPreference = $ErrorActionPreference", script)
        self.assertIn("$ErrorActionPreference = 'Continue'", script)
        self.assertIn("$adbExitCode = $LASTEXITCODE", script)
        self.assertIn("$ErrorActionPreference = $previousErrorActionPreference", script)
        self.assertIn("ForEach-Object { $_.ToString() }", script)

    def test_text_input_rejects_shell_metacharacters(self):
        bridge = FakeBridge()
        with self.assertRaises(PhoneBridgeError):
            bridge.type_text("hello; rm -rf /")
        ok = bridge.type_text("hello world")
        self.assertEqual(ok["characters"], 11)

    def test_keyevent_allowlist(self):
        bridge = FakeBridge()
        self.assertIn("HOME", SAFE_KEYEVENTS)
        with self.assertRaises(PhoneBridgeError):
            bridge.keyevent("POWER")

    def test_open_app_verified_reports_execution_status(self):
        bridge = FakeBridge()
        result = bridge.open_app_verified(
            "com.example",
            observation_attempts=1,
            observation_delay_ms=0,
        )
        self.assertTrue(result["verification_passed"])
        self.assertEqual(result["execution_status"], "EXECUTED_VERIFIED")
        self.assertFalse(result["safe_to_retry_action"])

    def test_package_validation(self):
        bridge = FakeBridge()
        bridge.open_app("com.example.app")
        with self.assertRaises(PhoneBridgeError):
            bridge.open_app("com.example.app;bad")

    def test_no_destructive_tools_exposed(self):
        tools = asyncio.run(server.list_tools())
        names = {tool.name for tool in tools}
        forbidden_exact_or_prefixes = {"delete", "remove", "uninstall", "shell", "clear", "wipe", "root"}
        self.assertFalse(
            any(
                name.lower() == fragment or name.lower().startswith(fragment + "_")
                for name in names
                for fragment in forbidden_exact_or_prefixes
            )
        )
        self.assertIn("get_phonebridge_runtime_info", names)
        self.assertIn("get_android_wireless_status", names)
        self.assertIn("pair_android_wireless", names)
        self.assertIn("connect_android_wireless", names)
        self.assertIn("refresh_android_wireless_connection", names)
        self.assertIn("disconnect_android_wireless", names)
        self.assertIn("get_android_screenshot", names)
        self.assertIn("get_android_screen_context", names)
        self.assertIn("get_android_fast_context", names)
        self.assertIn("verify_android_state_change", names)
        self.assertIn("get_local_vision_status", names)

        by_name = {tool.name: tool for tool in tools}
        fast_schema = by_name["get_android_fast_context"].input_schema
        self.assertIn("include_visual_hash", fast_schema.get("properties", {}))
        verify_schema = by_name["verify_android_state_change"].input_schema
        self.assertIn("verification_policy", verify_schema.get("properties", {}))
        self.assertIn("find_android_ui_elements", names)
        self.assertIn("tap_android", names)
        self.assertIn("tap_android_ui_element", names)
        self.assertIn("tap_android_ui_element_verified", names)
        self.assertIn("tap_android_verified", names)
        self.assertIn("swipe_android_verified", names)
        self.assertIn("swipe_android_direction", names)
        self.assertIn("swipe_android_direction_verified", names)
        self.assertIn("long_press_android_verified", names)
        self.assertIn("type_android_text_verified", names)
        self.assertIn("press_android_key_verified", names)
        self.assertIn("wait_for_android_ui_element", names)
        self.assertIn("get_android_device_state", names)
        self.assertIn("game_joystick_move", names)
        self.assertIn("game_camera_drag", names)
        self.assertIn("open_android_app", names)
        self.assertIn("open_android_app_verified", names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
