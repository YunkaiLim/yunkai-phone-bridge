"""Strict, offline command transcripts for bounded wireless recovery."""
from __future__ import annotations

import os
import subprocess
import unittest
from unittest.mock import patch

from phone_bridge import ADB_SERVER_ROUTING_ENV, AndroidBridge, PhoneBridgeError
from server import _err


ENDPOINT = "192.168.1.50:37123"
MDNS_ENDPOINT = "192.168.1.77:37177"
IDENTITY = "product:test model:Phone device:test transport_id:1"
CASE_EVIDENCE: list[dict] = []


def devices(*rows):
    return "List of devices attached\n" + "\n".join(rows) + "\n"


def mdns(*endpoints):
    return "List of discovered mdns services\n" + "\n".join(
        f"adb-test-{index} _adb-tls-connect._tcp {endpoint}"
        for index, endpoint in enumerate(endpoints)
    ) + "\n"


class ScriptedBridge(AndroidBridge):
    def __init__(self, steps):
        self.adb_path = "NEVER_EXECUTE_ADB"
        self.steps = list(steps)
        self.commands = []

    def _run(self, args, *, serial=None, timeout=15, binary=False):
        self.commands.append({"args": list(args), "serial": serial, "timeout_seconds": timeout})
        if not self.steps:
            raise AssertionError(f"Unexpected extra command: {args}")
        expected, expected_timeout, response = self.steps.pop(0)
        if args != expected or serial is not None or binary or timeout != expected_timeout:
            raise AssertionError(f"Unexpected command: {args}; expected {expected}, {expected_timeout}s")
        if callable(response):
            response = response()
        if isinstance(response, Exception):
            raise response
        return response


class WirelessReliabilityTests(unittest.TestCase):
    def setUp(self):
        # Routing values are never printed, used, or forwarded to a process.
        self.environment = patch.dict(os.environ, {key: "" for key in ADB_SERVER_ROUTING_ENV})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def check(self, steps, reason, *, connected=False, select=False):
        bridge = ScriptedBridge(steps)
        if select:
            with self.assertRaises(PhoneBridgeError) as raised:
                bridge.select_device()
            payload = _err(raised.exception)
            self.assertFalse(payload["ok"])
            result = payload["diagnostics"]
        else:
            result = bridge.refresh_wireless_connection()
        self.assertEqual(result["reason_code"], reason)
        self.assertEqual(result["connected"], connected)
        self.assertFalse(bridge.steps, "Not all expected commands were observed")
        commands = bridge.commands
        connects = sum(command["args"][:1] == ["connect"] for command in commands)
        observations = sum(command["args"] == ["devices", "-l"] for command in commands)
        self.assertLessEqual(connects, 1)
        self.assertLessEqual(observations, 2)
        self.assertEqual(result["recovery"]["adb_connect_attempts"], connects)
        self.assertEqual(result["recovery"]["adb_devices_reobserve_attempts"], max(0, observations - 1))
        self.assertFalse(result["recovery"]["retry_loop"])
        self.assertFalse(result["recovery"]["ui_action_retried"])
        self.assertFalse(result["recovery"]["pairing_verified"])
        self.assertFalse(result["recovery"]["hardware_identity_verified"])
        self.assertTrue(result["recommendation"]["advisory_only"])
        self.assertFalse(result["recommendation"]["grants_permission"])
        self.assertFalse(result["recommendation"]["grants_device_action_authority"])
        self.assertFalse(result["recommendation"]["auto_execute"])
        CASE_EVIDENCE.append({"test_id": self.id(), "expected_reason": reason,
                              "actual_reason": result["reason_code"], "result": result,
                              "commands": commands})
        return result

    @staticmethod
    def initial(*rows, discovery=None):
        return [(["devices", "-l"], 15, devices(*rows)),
                (["mdns", "services"], 10, mdns() if discovery is None else discovery)]

    def recovery(self, *, before=None, discovery=None, endpoint=ENDPOINT, connect=None, after=None):
        return self.initial(
            f"{ENDPOINT} offline {IDENTITY}" if before is None else before,
            discovery=discovery,
        ) + [(["connect", endpoint], 20, f"connected to {endpoint}" if connect is None else connect),
             (["devices", "-l"], 15, devices(f"{endpoint} device {IDENTITY}") if after is None else after)]

    def test_offline_success_has_selection_and_single_command_evidence(self):
        result = self.check(self.recovery(), "RECOVERED_SINGLE_OFFLINE_WIRELESS_ENDPOINT", connected=True)
        self.assertEqual(result["recovery"]["selection_reason_code"], "KNOWN_OFFLINE_WIRELESS_ENDPOINT_SELECTED")

    def test_mdns_wins_even_with_multiple_offline_candidates(self):
        steps = self.initial(f"{ENDPOINT} offline", "192.168.1.51:37123 offline", discovery=mdns(MDNS_ENDPOINT))
        steps += [(["connect", MDNS_ENDPOINT], 20, f"already connected to {MDNS_ENDPOINT}"),
                  (["devices", "-l"], 15, devices(f"{MDNS_ENDPOINT} device"))]
        result = self.check(steps, "RECOVERED_SINGLE_MDNS_CONNECT_SERVICE", connected=True)
        self.assertEqual(result["recovery"]["selection_reason_code"], "MDNS_CONNECT_SERVICE_SELECTED")

    def test_mdns_failure_never_connects_offline_fallback(self):
        for response, reason in [(PhoneBridgeError("failure"), "ADB_CONNECT_FAILED"),
                                 ("failed to connect", "ADB_CONNECT_FAILED"),
                                 ("not connected to " + MDNS_ENDPOINT, "ADB_CONNECT_OUTPUT_UNCLEAR")]:
            with self.subTest(response=str(response)):
                steps = self.recovery(discovery=mdns(MDNS_ENDPOINT), endpoint=MDNS_ENDPOINT, connect=response)[:-1]
                self.check(steps, reason)

    def test_ambiguous_mdns_blocks_fallback_including_duplicates(self):
        for endpoints in [(MDNS_ENDPOINT, ENDPOINT), (MDNS_ENDPOINT, MDNS_ENDPOINT)]:
            with self.subTest(endpoints=endpoints):
                self.check(self.initial(f"{ENDPOINT} offline", discovery=mdns(*endpoints)),
                           "AMBIGUOUS_MDNS_CONNECT_SERVICE")

    def test_invalid_mdns_is_not_absence_or_single_valid_candidate(self):
        for endpoint in ["8.8.8.8:37123", "bad/name.local:37123", "192.168.1.77:0", "0.0.0.0:37123"]:
            for endpoints in [(endpoint,), (endpoint, MDNS_ENDPOINT)]:
                with self.subTest(endpoints=endpoints):
                    self.check(self.initial(f"{ENDPOINT} offline", discovery=mdns(*endpoints)),
                               "INVALID_MDNS_WIRELESS_ENDPOINT")

    def test_malformed_discovery_and_timeouts_stop_without_fallback(self):
        timeout = PhoneBridgeError("bounded discovery failure")
        timeout.__cause__ = subprocess.TimeoutExpired(["fixture"], 10)
        for response, reason in [("", "ADB_MDNS_DISCOVERY_OUTPUT_UNCLEAR"),
                                 ("List of discovered mdns services\nadb-test _adb-tls-connect._tcp", "ADB_MDNS_DISCOVERY_OUTPUT_UNCLEAR"),
                                 (timeout, "ADB_MDNS_DISCOVERY_TIMEOUT"),
                                 (PhoneBridgeError("failure"), "ADB_MDNS_DISCOVERY_FAILED")]:
            with self.subTest(reason=reason):
                self.check(self.initial(f"{ENDPOINT} offline", discovery=response), reason)

    def test_unknown_adb_service_type_cannot_unlock_fallback(self):
        for service_type in ["_adb-tls-connect._tcp.", "_adb-tls-connect._udp"]:
            with self.subTest(service_type=service_type):
                response = f"List of discovered mdns services\nadb-test {service_type} {MDNS_ENDPOINT}\n"
                self.check(self.initial(f"{ENDPOINT} offline", discovery=response), "ADB_MDNS_DISCOVERY_OUTPUT_UNCLEAR")

    def test_no_candidate_never_connects(self):
        for rows in [(), ("USB123 offline usb:1-1",), (f"{ENDPOINT} unauthorized",),
                     (f"{ENDPOINT} unknown",), ("example.com:37123 offline",)]:
            with self.subTest(rows=rows):
                self.check(self.initial(*rows), "NO_ELIGIBLE_OFFLINE_WIRELESS_ENDPOINT")

    def test_multiple_offline_endpoints_and_duplicate_rows_stop(self):
        for extra in [f"{ENDPOINT} offline", "192.168.1.51:37123 offline"]:
            with self.subTest(extra=extra):
                self.check(self.initial(f"{ENDPOINT} offline", extra), "AMBIGUOUS_OFFLINE_WIRELESS_ENDPOINT")

    def test_conflicting_known_states_do_not_hide_ambiguity(self):
        for state in ["unauthorized", "unknown"]:
            with self.subTest(state=state):
                self.check(self.initial(f"{ENDPOINT} offline", f"{ENDPOINT} {state}"),
                           "AMBIGUOUS_OFFLINE_WIRELESS_ENDPOINT")

    def test_mixed_invalid_or_foreign_offline_evidence_blocks_valid_candidate(self):
        for row in ["8.8.8.8:37123 offline", "example.com:37123 offline", "phone.local:bad offline",
                    "bad/name.local:37123 offline", "192.0.2.1:37123 offline",
                    "192.168.1.51:37123 offline usb:1-1", "adb-test._adb-tls-connect._tcp offline",
                    "phone.local offline", "192.168.1.51 offline", "bad/name.local offline"]:
            with self.subTest(row=row):
                self.check(self.initial(f"{ENDPOINT} offline", row), "INVALID_OFFLINE_WIRELESS_CANDIDATE")

    def test_local_endpoint_grammar_positive_and_negative(self):
        for endpoint in [ENDPOINT, "phone.local:12345", "[fd00::1]:12345", "[fe80::1%12]:12345",
                         "127.0.0.1:12345", "[::1]:12345", "169.254.1.2:12345"]:
            with self.subTest(endpoint=endpoint):
                AndroidBridge._normalize_local_wireless_endpoint(endpoint)
        for endpoint in ["8.8.8.8:12345", "0.0.0.0:12345", "192.0.2.1:12345", "198.18.0.1:12345",
                         "[::]:12345", "[2001:db8::1]:12345", "[ff02::1]:12345",
                         "bad/name.local:12345", "bad..local:12345", "-bad.local:12345", "bad-.local:12345",
                         "phone.local:+1", "phone.local:１２", "[192.168.1.50]:12345", "fe80::1:12345",
                         "192.168.1.50:0", "192.168.1.50:65536", "localhost:12345", "[fe80::1%bad/name]:1"]:
            with self.subTest(endpoint=endpoint), self.assertRaises(PhoneBridgeError):
                AndroidBridge._normalize_local_wireless_endpoint(endpoint)

    def test_connect_timeout_and_failure_no_second_connect_or_observation(self):
        timeout = PhoneBridgeError("bounded operation failed")
        timeout.__cause__ = subprocess.TimeoutExpired(["fixture"], 20)
        for response, reason in [(timeout, "ADB_CONNECT_TIMEOUT"), (PhoneBridgeError("failure"), "ADB_CONNECT_FAILED"),
                                 ("unable to connect", "ADB_CONNECT_FAILED"), ("unrecognized", "ADB_CONNECT_OUTPUT_UNCLEAR"),
                                 ("disconnected to " + ENDPOINT, "ADB_CONNECT_OUTPUT_UNCLEAR"),
                                 (f"connected to {ENDPOINT}\nfailed to connect", "ADB_CONNECT_OUTPUT_UNCLEAR"),
                                 (f"connected to {MDNS_ENDPOINT}", "WIRELESS_ENDPOINT_IDENTITY_CHANGED")]:
            with self.subTest(reason=reason, response=str(response)):
                self.check(self.recovery(connect=response)[:-1], reason)

    def test_reobserve_timeout_error_and_malformed_output_stop(self):
        timeout = PhoneBridgeError("bounded operation failed")
        timeout.__cause__ = subprocess.TimeoutExpired(["fixture"], 15)
        for response, reason in [(timeout, "ADB_DEVICES_REOBSERVE_TIMEOUT"),
                                 (PhoneBridgeError("failure"), "ADB_DEVICES_REOBSERVE_FAILED"),
                                 ("garbage", "ADB_DEVICES_OUTPUT_UNCLEAR"),
                                 (devices("incomplete"), "ADB_DEVICES_OUTPUT_UNCLEAR")]:
            with self.subTest(reason=reason):
                self.check(self.recovery(after=response), reason)

    def test_still_offline_missing_and_unauthorized_are_unverified(self):
        for response in [devices(), devices(f"{ENDPOINT} offline"), devices(f"{ENDPOINT} unauthorized"),
                         devices(f"{ENDPOINT} unknown")]:
            with self.subTest(response=response):
                self.check(self.recovery(after=response), "WIRELESS_ENDPOINT_NOT_READY_AFTER_CONNECT")

    def test_changed_endpoint_or_new_ready_usb_stops_selection(self):
        for response in [devices(f"{MDNS_ENDPOINT} device {IDENTITY}"),
                         devices(f"{ENDPOINT} device {IDENTITY}", "FOREIGN-USB device usb:1-1")]:
            with self.subTest(response=response):
                self.check(self.recovery(after=response), "WIRELESS_ENDPOINT_IDENTITY_CHANGED", select=True)

    def test_stable_identity_changed_missing_or_duplicated_stops(self):
        for details, reason in [(IDENTITY.replace("model:Phone", "model:Foreign"), "WIRELESS_ENDPOINT_IDENTITY_CHANGED"),
                                ("product:test device:test", "WIRELESS_ENDPOINT_IDENTITY_UNVERIFIED"),
                                (IDENTITY + " model:Phone", "WIRELESS_ENDPOINT_IDENTITY_UNVERIFIED")]:
            with self.subTest(details=details):
                self.check(self.recovery(after=devices(f"{ENDPOINT} device {details}")), reason)

    def test_postobserve_usb_provenance_is_foreign(self):
        self.check(self.recovery(after=devices(f"{ENDPOINT} device {IDENTITY} usb:1-1")),
                   "FOREIGN_WIRELESS_CANDIDATE")

    def test_mdns_cannot_override_same_endpoint_identity_conflict(self):
        self.check(self.initial(f"{ENDPOINT} offline {IDENTITY} model:Foreign", discovery=mdns(ENDPOINT)),
                   "WIRELESS_ENDPOINT_IDENTITY_UNVERIFIED")
        self.check(self.initial(f"{ENDPOINT} offline", f"{ENDPOINT} unauthorized", discovery=mdns(ENDPOINT)),
                   "AMBIGUOUS_OFFLINE_WIRELESS_ENDPOINT")

    def test_invalid_headers_cannot_be_interpreted_as_absence(self):
        self.check([(["devices", "-l"], 15, "List of devices attached garbage\n")], "ADB_DEVICES_OUTPUT_UNCLEAR")
        self.check(self.initial(f"{ENDPOINT} offline", discovery="List of discovered mdns services garbage\n"),
                   "ADB_MDNS_DISCOVERY_OUTPUT_UNCLEAR")

    def test_invalid_state_is_not_silently_ignored_in_candidate_snapshot(self):
        self.check([(["devices", "-l"], 15, devices(f"{ENDPOINT} offline", "garbage foobar"))],
                   "ADB_DEVICES_OUTPUT_UNCLEAR")

    def test_error_prefix_does_not_become_verified_discovery_or_success(self):
        prefix = "ERROR partial output from unavailable server\n"
        self.check([(["devices", "-l"], 15, prefix + devices(f"{ENDPOINT} offline"))],
                   "ADB_DEVICES_OUTPUT_UNCLEAR")
        self.check(self.initial(f"{ENDPOINT} offline", discovery=prefix + mdns()),
                   "ADB_MDNS_DISCOVERY_OUTPUT_UNCLEAR")
        self.check(self.recovery(after=prefix + devices(f"{ENDPOINT} device {IDENTITY}")),
                   "ADB_DEVICES_OUTPUT_UNCLEAR")

    def test_duplicate_reobservation_never_reports_success(self):
        for state in ["offline", "device"]:
            with self.subTest(state=state):
                self.check(self.recovery(after=devices(f"{ENDPOINT} device {IDENTITY}", f"{ENDPOINT} {state}")),
                           "AMBIGUOUS_WIRELESS_REOBSERVATION")

    def test_transport_id_change_and_absent_initial_metadata_allow_transport_observation(self):
        self.check(self.recovery(after=devices(f"{ENDPOINT} device {IDENTITY.replace('transport_id:1', 'transport_id:2')}")),
                   "RECOVERED_SINGLE_OFFLINE_WIRELESS_ENDPOINT", connected=True)
        self.check(self.recovery(before=f"{ENDPOINT} offline"), "RECOVERED_SINGLE_OFFLINE_WIRELESS_ENDPOINT", connected=True)

    def test_duplicate_identity_in_initial_candidate_blocks_connect(self):
        self.check(self.initial(f"{ENDPOINT} offline {IDENTITY} model:Foreign"), "NO_ELIGIBLE_OFFLINE_WIRELESS_ENDPOINT")

    def test_initial_observation_timeout_and_parse_error_are_typed(self):
        timeout = PhoneBridgeError("bounded observation failed")
        timeout.__cause__ = subprocess.TimeoutExpired(["fixture"], 15)
        for response, reason in [(timeout, "ADB_DEVICES_INITIAL_TIMEOUT"), ("garbage", "ADB_DEVICES_OUTPUT_UNCLEAR")]:
            for select in [False, True]:
                with self.subTest(reason=reason, select=select):
                    self.check([(["devices", "-l"], 15, response)], reason, select=select)

    def test_foreign_server_environment_rejected_before_observation(self):
        for key in ADB_SERVER_ROUTING_ENV:
            with self.subTest(key=key), patch.dict(os.environ, {key: "fixture-foreign-route"}):
                self.check([], "FOREIGN_ADB_SERVER_CONFIGURATION")

    def test_backend_routing_change_during_discovery_or_connect_stops(self):
        def change_during_discovery():
            os.environ["ADB_SERVER_SOCKET"] = "fixture-foreign-route"
            return mdns()
        self.check(self.initial(f"{ENDPOINT} offline", discovery=change_during_discovery), "FOREIGN_ADB_SERVER_CONFIGURATION")
        os.environ["ADB_SERVER_SOCKET"] = ""

        def change_during_connect():
            os.environ["ADB_SERVER_SOCKET"] = "fixture-foreign-route"
            return f"connected to {ENDPOINT}"
        self.check(self.recovery(connect=change_during_connect)[:-1], "FOREIGN_ADB_SERVER_CONFIGURATION")

    def test_subprocess_receives_validated_environment_snapshot(self):
        bridge = AndroidBridge.__new__(AndroidBridge)
        bridge.adb_path = "NEVER_EXECUTE_ADB"
        captured = []

        def completed(command, **kwargs):
            captured.append(kwargs["env"])
            os.environ["ADB_SERVER_SOCKET"] = "fixture-later-route"
            return subprocess.CompletedProcess(command, 0, "List of devices attached\n", "")

        with patch("phone_bridge.subprocess.run", side_effect=completed):
            bridge.devices()
        self.assertEqual(captured[0]["ADB_SERVER_SOCKET"], "")
        with patch("phone_bridge.subprocess.run", side_effect=AssertionError("must not launch")):
            with self.assertRaises(PhoneBridgeError) as raised:
                bridge.devices()
        self.assertEqual(raised.exception.reason_code, "FOREIGN_ADB_SERVER_CONFIGURATION")


if __name__ == "__main__":
    unittest.main()
