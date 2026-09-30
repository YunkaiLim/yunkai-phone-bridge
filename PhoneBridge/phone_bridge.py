from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from PIL import Image

_SHARED_ROOT = Path(__file__).resolve().parent.parent
if str(_SHARED_ROOT) not in sys.path:
    sys.path.insert(0, str(_SHARED_ROOT))

from yunkai_shared.verification_contract import (  # noqa: E402 - shared root is added above
    VerificationContractError,
    combine_verification_result,
    evaluate_verification_policy,
    normalize_verification_policy,
)


class PhoneBridgeError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        reason_code: str | None = None,
        diagnostics: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.diagnostics = diagnostics


PACKAGE_RE = re.compile(r"^[A-Za-z0-9_.]+$")
SAFE_TEXT_RE = re.compile(r"^[A-Za-z0-9 _.,@:+\-/]*$")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
UI_BOUNDS_RE = re.compile(r"^\[(\d+),(\d+)\]\[(\d+),(\d+)\]$")
VISUAL_VERIFY_HAMMING_THRESHOLD = 8
GAME_WORLD_VERIFY_HAMMING_THRESHOLD = 5
MAX_VERIFICATION_ATTEMPTS = 4
MAX_VERIFICATION_DELAY_MS = 1500
MAX_GAME_GESTURE_MS = 15000
MAX_GAME_CAMERA_GESTURE_MS = 2000
MAX_STABLE_SURFACE_SAMPLES = 4
MAX_STABLE_SURFACE_DELAY_MS = 500
MAX_UI_WAIT_ATTEMPTS = 12
MAX_UI_WAIT_DELAY_MS = 2000
WIRELESS_MDNS_TYPES = {"_adb-tls-pairing._tcp", "_adb-tls-connect._tcp"}
ADB_DEVICE_STATES = {
    "device", "offline", "unauthorized", "unknown", "bootloader", "recovery",
    "sideload", "rescue", "connecting", "authorizing", "host",
}
ADB_SERVER_ROUTING_ENV = (
    "ADB_SERVER_SOCKET", "ANDROID_ADB_SERVER_ADDRESS", "ANDROID_ADB_SERVER_PORT",
)
LOCAL_WIRELESS_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128",
))
PAIRING_CODE_RE = re.compile(r"^\d{6}$")
SWIPE_DIRECTIONS: dict[str, tuple[float, float]] = {
    "up": (0.0, -1.0),
    "down": (0.0, 1.0),
    "left": (-1.0, 0.0),
    "right": (1.0, 0.0),
}
GAME_JOYSTICK_DIRECTIONS: dict[str, tuple[float, float]] = {
    "up": (0.0, -1.0),
    "down": (0.0, 1.0),
    "left": (-1.0, 0.0),
    "right": (1.0, 0.0),
    "up_left": (-0.7071, -0.7071),
    "up_right": (0.7071, -0.7071),
    "down_left": (-0.7071, 0.7071),
    "down_right": (0.7071, 0.7071),
}
# Values describe finger-drag direction required to make the camera look in the
# named direction. Keeping this separate from joystick motion avoids accidental
# use of the Android gesture/navigation edges during game camera control.
GAME_CAMERA_DIRECTIONS: dict[str, tuple[float, float]] = {
    "left": (1.0, 0.0),
    "right": (-1.0, 0.0),
    "up": (0.0, 1.0),
    "down": (0.0, -1.0),
}
LOCKSCREEN_TOKENS = (
    "unlock",
    "keyguard",
    "lockscreen",
    "swipe up",
    "解锁",
    "锁屏",
    "上滑",
)

SAFE_KEYEVENTS: dict[str, int] = {
    "HOME": 3,
    "BACK": 4,
    "DPAD_UP": 19,
    "DPAD_DOWN": 20,
    "DPAD_LEFT": 21,
    "DPAD_RIGHT": 22,
    "DPAD_CENTER": 23,
    "VOLUME_UP": 24,
    "VOLUME_DOWN": 25,
    "TAB": 61,
    "ENTER": 66,
    "ESCAPE": 111,
}


@dataclass(frozen=True)
class AndroidDevice:
    serial: str
    state: str
    details: str

    @property
    def transport(self) -> str:
        serial = self.serial.casefold()
        if "._adb-tls-connect._tcp" in serial:
            return "wireless"
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}:\d+", self.serial):
            return "wireless"
        if self.serial.startswith("[") and "]:" in self.serial:
            return "wireless"
        if re.fullmatch(r"[^:\s]+\.local:\d{1,5}", self.serial, flags=re.IGNORECASE):
            return "wireless"
        return "usb"

    def as_dict(self) -> dict[str, str]:
        return {
            "serial": self.serial,
            "state": self.state,
            "details": self.details,
            "transport": self.transport,
        }


@dataclass(frozen=True)
class AndroidMDNSService:
    name: str
    service_type: str
    endpoint: str

    def as_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "service_type": self.service_type,
            "endpoint": self.endpoint,
        }


@dataclass(frozen=True)
class AndroidUIElement:
    text: str
    content_desc: str
    resource_id: str
    class_name: str
    package: str
    clickable: bool
    enabled: bool
    bounds: tuple[int, int, int, int]
    input_bounds: tuple[int, int, int, int]

    @property
    def input_center(self) -> tuple[int, int]:
        left, top, right, bottom = self.input_bounds
        return (left + right) // 2, (top + bottom) // 2

    def as_dict(self) -> dict[str, Any]:
        center_x, center_y = self.input_center
        return {
            "text": self.text,
            "content_desc": self.content_desc,
            "resource_id": self.resource_id,
            "class_name": self.class_name,
            "package": self.package,
            "clickable": self.clickable,
            "enabled": self.enabled,
            "bounds": list(self.bounds),
            "input_bounds": list(self.input_bounds),
            "input_center": [center_x, center_y],
        }


class AndroidBridge:
    """A deliberately limited ADB bridge for interactive phone control.

    The public API intentionally has no arbitrary shell tool, no delete API,
    no uninstall API, and no app-data clearing API.
    """

    def __init__(self, adb_path: str | None = None):
        self.adb_path = self._resolve_adb(adb_path)

    @staticmethod
    def _resolve_adb(explicit: str | None) -> str:
        candidates = [explicit, os.environ.get("ADB_PATH"), shutil.which("adb")]
        for candidate in candidates:
            if candidate and Path(candidate).exists():
                return str(Path(candidate))
        raise PhoneBridgeError(
            "ADB was not found. Run setup_android_phone.cmd first, then reopen the terminal or set ADB_PATH."
        )

    def _run(
        self,
        args: list[str],
        *,
        serial: str | None = None,
        timeout: int = 15,
        binary: bool = False,
    ) -> str | bytes:
        environment = None
        if args[:1] in (["devices"], ["mdns"], ["connect"]):
            # Validate and pass the same snapshot: discovery and connect must
            # use the default local ADB server, never inherited routing overrides.
            environment = dict(os.environ)
            self._require_local_adb_server(environment)
        command = [self.adb_path]
        if serial:
            command += ["-s", serial]
        command += args
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                timeout=timeout,
                text=not binary,
                env=environment,
            )
        except subprocess.TimeoutExpired as exc:
            raise PhoneBridgeError(f"ADB command timed out after {timeout}s.") from exc
        except OSError as exc:
            raise PhoneBridgeError(f"Unable to launch ADB: {exc}") from exc

        if completed.returncode != 0:
            stderr = completed.stderr
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            raise PhoneBridgeError((stderr or "ADB command failed.").strip())
        return completed.stdout

    def _run_with_stdin(
        self,
        args: list[str],
        stdin_text: str,
        *,
        timeout: int = 20,
    ) -> str:
        """Run an ADB command with secret-like ephemeral input kept out of argv."""
        try:
            completed = subprocess.run(
                [self.adb_path, *args],
                input=stdin_text,
                check=False,
                capture_output=True,
                timeout=timeout,
                text=True,
            )
        except subprocess.TimeoutExpired as exc:
            raise PhoneBridgeError(f"ADB command timed out after {timeout}s.") from exc
        except OSError as exc:
            raise PhoneBridgeError(f"Unable to launch ADB: {exc}") from exc
        if completed.returncode != 0:
            raise PhoneBridgeError((completed.stderr or "ADB command failed.").strip())
        return completed.stdout

    @staticmethod
    def _require_local_adb_server(environment: dict[str, str] | None = None) -> None:
        environment = os.environ if environment is None else environment
        overrides = [key for key in ADB_SERVER_ROUTING_ENV if environment.get(key)]
        if overrides:
            raise PhoneBridgeError(
                "Wireless recovery requires the default local ADB server; routing overrides are unverified.",
                reason_code="FOREIGN_ADB_SERVER_CONFIGURATION",
                diagnostics={"routing_override_names": overrides},
            )

    @staticmethod
    def _normalize_local_wireless_endpoint(endpoint: str) -> str:
        value = str(endpoint or "").strip()
        match = re.fullmatch(r"(?:\[([^\]\s]+)\]|([^:\s]+)):([0-9]{1,5})", value)
        if not match or len(value) > 300:
            raise PhoneBridgeError("Invalid wireless ADB host:port.", reason_code="MALFORMED_WIRELESS_ENDPOINT")
        ipv6_host, plain_host, port_text = match.groups()
        host = ipv6_host or plain_host
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise PhoneBridgeError("Wireless ADB port is out of range.", reason_code="MALFORMED_WIRELESS_ENDPOINT")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            labels = host.split(".")
            if (ipv6_host or len(host) > 253 or len(labels) < 2
                    or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                           for label in labels)):
                raise PhoneBridgeError("Invalid wireless host.", reason_code="MALFORMED_WIRELESS_ENDPOINT")
            if labels[-1].casefold() != "local":
                raise PhoneBridgeError("Wireless host is not local.", reason_code="NON_LOCAL_WIRELESS_ENDPOINT")
            normalized_host = host.casefold()
        else:
            if bool(ipv6_host) != (address.version == 6):
                raise PhoneBridgeError("Invalid IP brackets.", reason_code="MALFORMED_WIRELESS_ENDPOINT")
            if not any(address.version == network.version and address in network for network in LOCAL_WIRELESS_NETWORKS):
                raise PhoneBridgeError("Wireless address is not local.", reason_code="NON_LOCAL_WIRELESS_ENDPOINT")
            if "%" in host and not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", host.split("%", 1)[1]):
                raise PhoneBridgeError("Invalid IPv6 scope.", reason_code="MALFORMED_WIRELESS_ENDPOINT")
            normalized_host = f"[{address}]" if ipv6_host else str(address)
        return f"{normalized_host}:{port}"

    def mdns_services(self) -> list[AndroidMDNSService]:
        output = str(self._run(["mdns", "services"], timeout=10))
        lines = output.splitlines()
        header_index = next(
            (
                index
                for index, line in enumerate(lines)
                if line.strip().casefold() == "list of discovered mdns services"
            ),
            None,
        )
        if header_index is None or any(line.strip() for line in lines[:header_index]):
            raise PhoneBridgeError(
                "ADB mDNS services output was not recognized.",
                reason_code="ADB_MDNS_DISCOVERY_OUTPUT_UNCLEAR",
            )
        services: list[AndroidMDNSService] = []
        for raw_line in lines[header_index + 1 :]:
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 3:
                raise PhoneBridgeError(
                    "ADB mDNS services output contained an incomplete service row.",
                    reason_code="ADB_MDNS_DISCOVERY_OUTPUT_UNCLEAR",
                )
            name, service_type, endpoint = parts[0], parts[1], parts[-1]
            if service_type not in WIRELESS_MDNS_TYPES:
                if service_type.casefold().startswith("_adb"):
                    raise PhoneBridgeError(
                        "ADB mDNS service type is unrecognized.",
                        reason_code="ADB_MDNS_DISCOVERY_OUTPUT_UNCLEAR",
                    )
                continue
            try:
                endpoint = self._normalize_local_wireless_endpoint(endpoint)
            except PhoneBridgeError as exc:
                # Invalid discovery is not absence and cannot unlock fallback.
                raise PhoneBridgeError(
                    "ADB mDNS advertised an invalid or non-local wireless service.",
                    reason_code="INVALID_MDNS_WIRELESS_ENDPOINT",
                    diagnostics={"validation_reason": exc.reason_code},
                ) from exc
            services.append(
                AndroidMDNSService(
                    name=name,
                    service_type=service_type,
                    endpoint=endpoint,
                )
            )
        return services

    def wireless_status(self) -> dict[str, Any]:
        devices = self.devices()
        services = self.mdns_services()
        wireless_devices = [device.as_dict() for device in devices if device.transport == "wireless"]
        usb_devices = [device.as_dict() for device in devices if device.transport == "usb"]
        return {
            "status": "ok",
            "wireless_supported": True,
            "pairing_code_persisted": False,
            "auto_reconnect_supported": True,
            "usb_devices": usb_devices,
            "wireless_devices": wireless_devices,
            "mdns_services": [service.as_dict() for service in services],
            "pairing_services": [
                service.as_dict()
                for service in services
                if service.service_type == "_adb-tls-pairing._tcp"
            ],
            "connect_services": [
                service.as_dict()
                for service in services
                if service.service_type == "_adb-tls-connect._tcp"
            ],
        }

    def pair_wireless(
        self,
        endpoint: str,
        pairing_code: str,
        *,
        auto_connect: bool = True,
    ) -> dict[str, Any]:
        normalized_endpoint = self._normalize_local_wireless_endpoint(endpoint)
        code = str(pairing_code or "").strip()
        if not PAIRING_CODE_RE.fullmatch(code):
            raise PhoneBridgeError("Wireless ADB pairing code must be exactly six digits.")
        output = self._run_with_stdin(
            ["pair", normalized_endpoint],
            code + "\n",
            timeout=25,
        ).strip()
        if "successfully paired" not in output.casefold():
            raise PhoneBridgeError("ADB pairing did not report success.")
        result: dict[str, Any] = {
            "status": "ok",
            "action": "pair_wireless",
            "endpoint": normalized_endpoint,
            "paired": True,
            "pairing_code_persisted": False,
        }
        if auto_connect:
            result["connect_refresh"] = self.refresh_wireless_connection()
        return result

    def connect_wireless(self, endpoint: str) -> dict[str, Any]:
        normalized_endpoint = self._normalize_local_wireless_endpoint(endpoint)
        output = str(self._run(["connect", normalized_endpoint], timeout=20)).strip()
        match = re.fullmatch(r"(?:already )?connected to (\S+)", output, flags=re.IGNORECASE)
        if not match:
            failed = re.match(r"(?:failed|unable|cannot|error:)", output, flags=re.IGNORECASE)
            raise PhoneBridgeError(
                "ADB wireless connect did not report a successful connection.",
                reason_code="ADB_CONNECT_FAILED" if failed else "ADB_CONNECT_OUTPUT_UNCLEAR",
            )
        try:
            reported_endpoint = self._normalize_local_wireless_endpoint(match.group(1))
        except PhoneBridgeError as exc:
            raise PhoneBridgeError("ADB connect target is unverified.", reason_code="ADB_CONNECT_OUTPUT_UNCLEAR") from exc
        if reported_endpoint != normalized_endpoint:
            raise PhoneBridgeError("ADB connect reported a different target.", reason_code="WIRELESS_ENDPOINT_IDENTITY_CHANGED")
        return {
            "status": "ok",
            "action": "connect_wireless",
            "endpoint": normalized_endpoint,
            "connected": True,
        }

    def disconnect_wireless(self, endpoint: str) -> dict[str, Any]:
        normalized_endpoint = self._normalize_local_wireless_endpoint(endpoint)
        output = str(self._run(["disconnect", normalized_endpoint], timeout=15)).strip()
        normalized_output = output.casefold()
        if "disconnected" not in normalized_output and "no such device" not in normalized_output:
            raise PhoneBridgeError("ADB wireless disconnect did not report a completed result.")
        return {
            "status": "ok",
            "action": "disconnect_wireless",
            "endpoint": normalized_endpoint,
            "connected": False,
        }

    @staticmethod
    def _recovery_result(
        reason_code: str,
        *,
        connected: bool = False,
        source: str = "none",
        connect_attempts: int = 0,
        reobserve_attempts: int = 0,
        **details: Any,
    ) -> dict[str, Any]:
        return {
            "status": "ok",
            "action": "refresh_wireless_connection",
            "connected": connected,
            "reason_code": reason_code,
            "outcome": "SUCCESS_OBSERVED" if connected else "STOPPED",
            "recommendation": {
                "code": "TRANSPORT_READY_OBSERVED" if connected else "STOP_REOBSERVE_AND_REPLAN",
                "advisory_only": True,
                "grants_permission": False,
                "grants_device_action_authority": False,
                "auto_execute": False,
            },
            "recovery": {
                "scope": "transport_only",
                "source": source,
                "adb_connect_attempts": connect_attempts,
                "adb_connect_max": 1,
                "adb_devices_reobserve_attempts": reobserve_attempts,
                "adb_devices_reobserve_max": 1,
                "retry_loop": False,
                "ui_action_retried": False,
                "selection_reason_code": (
                    "MDNS_CONNECT_SERVICE_SELECTED" if source == "mdns"
                    else "KNOWN_OFFLINE_WIRELESS_ENDPOINT_SELECTED"
                ) if connect_attempts else None,
                "evidence_origin": "unverified" if reason_code == "FOREIGN_ADB_SERVER_CONFIGURATION" else "default_local_adb_server",
                "pairing_verified": False,
                "hardware_identity_verified": False,
                "identity_basis": "endpoint_and_available_product_model_device",
                "adb_connect_timeout_seconds": 20,
                "adb_devices_reobserve_timeout_seconds": 15,
            },
            **details,
        }

    @staticmethod
    def _bounded_adb_failure_reason(exc: PhoneBridgeError, operation: str) -> str:
        if exc.reason_code:
            return exc.reason_code
        if isinstance(exc.__cause__, subprocess.TimeoutExpired) or "timed out" in str(exc).casefold():
            return f"ADB_{operation}_TIMEOUT"
        return f"ADB_{operation}_FAILED"

    def _attempt_wireless_recovery_candidate(
        self,
        endpoint: str,
        *,
        source: str,
        candidate: dict[str, Any],
        observed_before: list[AndroidDevice],
    ) -> tuple[dict[str, Any], list[AndroidDevice] | None]:
        def stop(reason: str, *, reobserved: bool = False, **details: Any):
            return self._recovery_result(
                reason, source=source, connect_attempts=1,
                reobserve_attempts=int(reobserved), candidate=candidate, **details,
            ), None

        try:
            self._require_local_adb_server()
        except PhoneBridgeError as exc:
            return self._recovery_result(
                str(exc.reason_code), source=source, candidate=candidate, evidence=exc.diagnostics,
            ), None
        try:
            self.connect_wireless(endpoint)
        except PhoneBridgeError as exc:
            reason_code = self._bounded_adb_failure_reason(exc, "CONNECT")
            return (
                self._recovery_result(
                    reason_code,
                    source=source,
                    connect_attempts=1,
                    candidate=candidate,
                    error=str(exc),
                ),
                None,
            )

        try:
            self._require_local_adb_server()
        except PhoneBridgeError as exc:
            return stop(str(exc.reason_code), evidence=exc.diagnostics)
        try:
            observed_devices = self.devices()
        except PhoneBridgeError as exc:
            reason_code = self._bounded_adb_failure_reason(exc, "DEVICES_REOBSERVE")
            return (
                self._recovery_result(
                    reason_code,
                    source=source,
                    connect_attempts=1,
                    reobserve_attempts=1,
                    candidate=candidate,
                    error=str(exc),
                ),
                None,
            )

        matching = [device for device in observed_devices if self._device_endpoint(device) == endpoint]
        evidence = {"observed_devices": [device.as_dict() for device in observed_devices]}
        if len(matching) > 1:
            return stop("AMBIGUOUS_WIRELESS_REOBSERVATION", reobserved=True, **evidence)
        before_ready = {device.serial for device in observed_before if device.state == "device"}
        foreign_ready = [device for device in observed_devices if device.state == "device"
                         and self._device_endpoint(device) != endpoint and device.serial not in before_ready]
        if foreign_ready or (not matching and any(device.state == "device" for device in observed_devices)):
            return stop("WIRELESS_ENDPOINT_IDENTITY_CHANGED", reobserved=True, **evidence)
        recovered = matching[0] if matching and matching[0].state == "device" else None
        if recovered is None:
            return (
                self._recovery_result(
                    "WIRELESS_ENDPOINT_NOT_READY_AFTER_CONNECT",
                    source=source,
                    connect_attempts=1,
                    reobserve_attempts=1,
                    candidate=candidate,
                    observed_devices=[device.as_dict() for device in observed_devices],
                ),
                observed_devices,
            )

        previous = next((device for device in observed_before if self._device_endpoint(device) == endpoint), None)
        try:
            before_identity = self._wireless_device_identity(previous) if previous else {}
            after_identity = self._wireless_device_identity(recovered)
        except PhoneBridgeError as exc:
            return stop(str(exc.reason_code), reobserved=True, **evidence)
        if any(key not in after_identity for key in before_identity):
            return stop("WIRELESS_ENDPOINT_IDENTITY_UNVERIFIED", reobserved=True, **evidence)
        if any(after_identity[key] != value for key, value in before_identity.items()):
            return stop("WIRELESS_ENDPOINT_IDENTITY_CHANGED", reobserved=True, **evidence)

        success_code = (
            "RECOVERED_SINGLE_MDNS_CONNECT_SERVICE"
            if source == "mdns"
            else "RECOVERED_SINGLE_OFFLINE_WIRELESS_ENDPOINT"
        )
        return (
            self._recovery_result(
                success_code,
                connected=True,
                source=source,
                connect_attempts=1,
                reobserve_attempts=1,
                candidate=candidate,
                recovered_device=recovered.as_dict(),
                identity_evidence={"before": before_identity, "after": after_identity},
            ),
            observed_devices,
        )

    @classmethod
    def _device_endpoint(cls, device: AndroidDevice) -> str | None:
        try:
            return cls._normalize_local_wireless_endpoint(device.serial)
        except PhoneBridgeError:
            return None

    @staticmethod
    def _wireless_device_identity(device: AndroidDevice) -> dict[str, str]:
        identity: dict[str, str] = {}
        for token in device.details.split():
            key, separator, value = token.partition(":")
            if separator and key == "usb":
                raise PhoneBridgeError("Endpoint has USB provenance.", reason_code="FOREIGN_WIRELESS_CANDIDATE")
            if separator and key in {"product", "model", "device"}:
                if key in identity or not value:
                    raise PhoneBridgeError(
                        "Wireless device identity metadata is ambiguous.",
                        reason_code="WIRELESS_ENDPOINT_IDENTITY_UNVERIFIED",
                    )
                identity[key] = value
        return identity

    def _bounded_wireless_recovery(
        self,
        observed_devices: list[AndroidDevice],
        *,
        allow_offline_fallback: bool = True,
    ) -> tuple[dict[str, Any], list[AndroidDevice] | None]:
        """Attempt one transport-only recovery with mDNS strictly preferred."""
        try:
            self._require_local_adb_server()
            services = [
                service
                for service in self.mdns_services()
                if service.service_type == "_adb-tls-connect._tcp"
            ]
        except PhoneBridgeError as exc:
            reason_code = self._bounded_adb_failure_reason(exc, "MDNS_DISCOVERY")
            return (
                self._recovery_result(reason_code, source="mdns", error=str(exc), evidence=exc.diagnostics),
                None,
            )

        if len(services) > 1:
            return (
                self._recovery_result(
                    "AMBIGUOUS_MDNS_CONNECT_SERVICE",
                    source="mdns",
                    candidates=[service.as_dict() for service in services],
                ),
                None,
            )
        if len(services) == 1:
            service = services[0]
            # An endpoint already listed with conflicting identity is not made
            # trustworthy by an mDNS advertisement.
            known = [device for device in observed_devices if self._device_endpoint(device) == service.endpoint]
            try:
                if len(known) > 1:
                    raise PhoneBridgeError("Duplicate known endpoint.", reason_code="AMBIGUOUS_OFFLINE_WIRELESS_ENDPOINT")
                if known:
                    self._wireless_device_identity(known[0])
            except PhoneBridgeError as exc:
                return self._recovery_result(str(exc.reason_code), source="mdns", error=str(exc)), None
            return self._attempt_wireless_recovery_candidate(
                service.endpoint,
                source="mdns",
                candidate=service.as_dict(),
                observed_before=observed_devices,
            )
        if not allow_offline_fallback:
            return (
                self._recovery_result(
                    "NO_MDNS_CONNECT_SERVICE",
                    source="mdns",
                    requires_phone_wireless_debugging=True,
                ),
                None,
            )

        eligible: list[tuple[AndroidDevice, str]] = []
        rejected: list[dict[str, Any]] = []
        for device in observed_devices:
            if device.state != "offline":
                continue
            # Include malformed host:port-like rows in rejected evidence instead
            # of silently classifying them as USB and connecting another row.
            wireless_looking = (
                device.transport == "wireless" or ":" in device.serial
                or re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", device.serial)
                or re.search(r"\.local\.?$", device.serial, flags=re.IGNORECASE)
                or device.serial.startswith("[")
            )
            if not wireless_looking:
                continue
            try:
                endpoint = self._normalize_local_wireless_endpoint(device.serial)
                self._wireless_device_identity(device)
            except PhoneBridgeError as exc:
                rejected.append(
                    {
                        "device": device.as_dict(),
                        "reason_code": exc.reason_code,
                    }
                )
                continue
            eligible.append((device, endpoint))

        if not eligible:
            return (
                self._recovery_result(
                    "NO_ELIGIBLE_OFFLINE_WIRELESS_ENDPOINT",
                    source="offline_devices",
                    requires_phone_wireless_debugging=True,
                    rejected_candidates=rejected,
                ),
                None,
            )
        if len(eligible) > 1:
            return (
                self._recovery_result(
                    "AMBIGUOUS_OFFLINE_WIRELESS_ENDPOINT",
                    source="offline_devices",
                    candidates=[device.as_dict() for device, _endpoint in eligible],
                    rejected_candidates=rejected,
                ),
                None,
            )
        if rejected:
            return self._recovery_result(
                "INVALID_OFFLINE_WIRELESS_CANDIDATE", source="offline_devices",
                candidates=[device.as_dict() for device, _endpoint in eligible],
                rejected_candidates=rejected,
            ), None

        device, endpoint = eligible[0]
        known = [item for item in observed_devices if self._device_endpoint(item) == endpoint]
        if len(known) != 1:
            return self._recovery_result(
                "AMBIGUOUS_OFFLINE_WIRELESS_ENDPOINT", source="offline_devices",
                candidates=[item.as_dict() for item in known],
            ), None
        return self._attempt_wireless_recovery_candidate(
            endpoint,
            source="offline_devices",
            candidate=device.as_dict(),
            observed_before=observed_devices,
        )

    def _initial_recovery_devices(self) -> list[AndroidDevice]:
        try:
            self._require_local_adb_server()
            return self.devices()
        except PhoneBridgeError as exc:
            reason = self._bounded_adb_failure_reason(exc, "DEVICES_INITIAL")
            diagnostics = self._recovery_result(reason, error=str(exc), evidence=exc.diagnostics)
            raise PhoneBridgeError(str(exc), reason_code=reason, diagnostics=diagnostics) from exc

    def refresh_wireless_connection(self) -> dict[str, Any]:
        try:
            devices = self._initial_recovery_devices()
        except PhoneBridgeError as exc:
            return exc.diagnostics
        ready = [device for device in devices if device.state == "device"]
        result, _observed_after = self._bounded_wireless_recovery(
            devices,
            allow_offline_fallback=not ready,
        )
        return result

    def devices(self) -> list[AndroidDevice]:
        output = str(self._run(["devices", "-l"], timeout=15))
        lines = output.splitlines()
        header_index = next(
            (
                index
                for index, line in enumerate(lines)
                if line.strip().casefold() == "list of devices attached"
            ),
            None,
        )
        if header_index is None or any(line.strip() for line in lines[:header_index]):
            raise PhoneBridgeError(
                "ADB devices output was not recognized.",
                reason_code="ADB_DEVICES_OUTPUT_UNCLEAR",
            )
        devices: list[AndroidDevice] = []
        for raw_line in lines[header_index + 1 :]:
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split(maxsplit=2)
            if len(parts) < 2:
                raise PhoneBridgeError(
                    "ADB devices output contained an incomplete device row.",
                    reason_code="ADB_DEVICES_OUTPUT_UNCLEAR",
                )
            serial = parts[0]
            state = parts[1]
            details = parts[2] if len(parts) > 2 else ""
            if state not in ADB_DEVICE_STATES and not (state == "no" and details.startswith("permissions")):
                raise PhoneBridgeError(
                    "ADB devices output contained an unrecognized state.",
                    reason_code="ADB_DEVICES_OUTPUT_UNCLEAR",
                )
            devices.append(AndroidDevice(serial=serial, state=state, details=details))
        return devices

    def select_device(self, serial: str | None = None) -> str:
        devices = self.devices() if serial else self._initial_recovery_devices()
        if serial:
            for device in devices:
                if device.serial == serial:
                    if device.state != "device":
                        raise PhoneBridgeError(
                            f"Device {serial} is present but state is '{device.state}'. Accept the Android debugging authorization prompt."
                        )
                    return serial
            raise PhoneBridgeError(f"Android device '{serial}' was not found.")

        ready = [device for device in devices if device.state == "device"]
        if not ready:
            recovery, observed_after = self._bounded_wireless_recovery(devices)
            if recovery.get("connected") and observed_after is not None:
                devices = observed_after
                ready = [device for device in devices if device.state == "device"]
            else:
                states = ", ".join(f"{d.serial}:{d.state}" for d in devices) or "none"
                reason_code = str(recovery.get("reason_code") or "WIRELESS_RECOVERY_FAILED")
                raise PhoneBridgeError(
                    "No authorized Android device is connected. Use USB debugging or enable Wireless debugging and pair this workstation. "
                    f"Recovery stopped with {reason_code}. Detected: {states}.",
                    reason_code=reason_code,
                    diagnostics=recovery,
                )

        if not ready:
            states = ", ".join(f"{d.serial}:{d.state}" for d in devices) or "none"
            raise PhoneBridgeError(
                "No authorized Android device is connected. Use USB debugging or enable Wireless debugging and pair this workstation. "
                f"Detected: {states}."
            )

        usb_ready = [device for device in ready if device.transport == "usb"]
        wireless_ready = [device for device in ready if device.transport == "wireless"]
        if len(usb_ready) == 1:
            return usb_ready[0].serial
        if len(usb_ready) > 1:
            raise PhoneBridgeError(
                "More than one USB Android device is connected. Pass the desired serial explicitly: "
                + ", ".join(device.serial for device in usb_ready)
            )
        if len(wireless_ready) == 1:
            return wireless_ready[0].serial
        raise PhoneBridgeError(
            "More than one wireless Android device is connected. Pass the desired serial explicitly: "
            + ", ".join(device.serial for device in wireless_ready)
        )

    def screen_size(self, serial: str | None = None) -> tuple[int, int]:
        """Return the current screenshot/input coordinate size.

        Android's `wm size` reports the natural portrait dimensions even when an
        app is rotated into landscape. ADB `input tap/swipe` follows the current
        rotated surface, so derive the active width/height from `screencap`
        instead. Fall back to `wm size` if the PNG header cannot be read.
        """
        selected = self.select_device(serial)
        try:
            data = self._run(
                ["exec-out", "screencap", "-p"],
                serial=selected,
                binary=True,
                timeout=20,
            )
            if isinstance(data, bytes) and data.startswith(PNG_SIGNATURE) and len(data) >= 24:
                width, height = struct.unpack(">II", data[16:24])
                if width > 0 and height > 0:
                    return int(width), int(height)
        except PhoneBridgeError:
            pass

        output = str(self._run(["shell", "wm", "size"], serial=selected))
        sizes = re.findall(r"(\d+)x(\d+)", output)
        if not sizes:
            raise PhoneBridgeError(f"Could not parse Android screen size from: {output.strip()}")
        width, height = sizes[-1]
        return int(width), int(height)

    def _validate_point(self, x: int, y: int, serial: str) -> tuple[int, int]:
        width, height = self.screen_size(serial)
        x, y = int(x), int(y)
        if not (0 <= x < width and 0 <= y < height):
            raise PhoneBridgeError(f"Point ({x}, {y}) is outside the screen bounds {width}x{height}.")
        return x, y

    def screenshot_png(self, serial: str | None = None) -> bytes:
        selected = self.select_device(serial)
        data = self._run(["exec-out", "screencap", "-p"], serial=selected, binary=True, timeout=20)
        assert isinstance(data, bytes)
        if not data.startswith(PNG_SIGNATURE):
            raise PhoneBridgeError("ADB returned screenshot data that is not a valid PNG stream.")
        return data

    def screen_visual_hash(self, serial: str | None = None, hash_size: int = 8) -> str:
        hash_size = max(4, min(16, int(hash_size)))
        png = self.screenshot_png(serial)
        with Image.open(io.BytesIO(png)) as image:
            gray = image.convert("L").resize((hash_size + 1, hash_size))
            pixels = list(gray.getdata())
        bits: list[int] = []
        row_width = hash_size + 1
        for row in range(hash_size):
            start = row * row_width
            for col in range(hash_size):
                bits.append(1 if pixels[start + col] > pixels[start + col + 1] else 0)
        value = 0
        for bit in bits:
            value = (value << 1) | bit
        width = (len(bits) + 3) // 4
        return f"{value:0{width}x}"

    def screen_region_visual_hash(
        self,
        serial: str | None = None,
        *,
        left_ratio: float = 0.18,
        top_ratio: float = 0.12,
        right_ratio: float = 0.86,
        bottom_ratio: float = 0.78,
        hash_size: int = 8,
    ) -> str:
        """Return a dHash over a central game-world region, excluding most fixed HUD chrome."""
        ratios = [float(left_ratio), float(top_ratio), float(right_ratio), float(bottom_ratio)]
        if not (0.0 <= ratios[0] < ratios[2] <= 1.0 and 0.0 <= ratios[1] < ratios[3] <= 1.0):
            raise PhoneBridgeError("Invalid visual region ratios.")
        hash_size = max(4, min(16, int(hash_size)))
        png = self.screenshot_png(serial)
        with Image.open(io.BytesIO(png)) as image:
            width, height = image.size
            left = max(0, min(width - 1, round(width * ratios[0])))
            top = max(0, min(height - 1, round(height * ratios[1])))
            right = max(left + 1, min(width, round(width * ratios[2])))
            bottom = max(top + 1, min(height, round(height * ratios[3])))
            gray = image.crop((left, top, right, bottom)).convert("L").resize((hash_size + 1, hash_size))
            pixels = list(gray.getdata())
        bits: list[int] = []
        row_width = hash_size + 1
        for row in range(hash_size):
            start = row * row_width
            for col in range(hash_size):
                bits.append(1 if pixels[start + col] > pixels[start + col + 1] else 0)
        value = 0
        for bit in bits:
            value = (value << 1) | bit
        width_hex = (len(bits) + 3) // 4
        return f"{value:0{width_hex}x}"

    @staticmethod
    def _extract_uiautomator_xml(output: str) -> str | None:
        """Extract only the XML document from noisy uiautomator output.

        Some Android builds append status text such as
        `UI hierchary dumped to: /dev/tty` after the closing hierarchy tag.
        Feeding that suffix to ElementTree causes `junk after document element`.
        """
        start = output.find("<?xml")
        if start < 0:
            return None
        end_marker = "</hierarchy>"
        end = output.find(end_marker, start)
        if end < 0:
            return None
        return output[start : end + len(end_marker)].strip()

    def ui_xml(self, serial: str | None = None) -> str:
        selected = self.select_device(serial)
        try:
            output = str(
                self._run(
                    ["exec-out", "uiautomator", "dump", "/dev/tty"],
                    serial=selected,
                    timeout=20,
                )
            )
            xml_text = self._extract_uiautomator_xml(output)
            if xml_text is not None:
                return xml_text
        except PhoneBridgeError:
            pass

        dump_path = "/sdcard/phonebridge_window_dump.xml"
        self._run(["shell", "uiautomator", "dump", dump_path], serial=selected, timeout=20)
        output = str(self._run(["exec-out", "cat", dump_path], serial=selected, timeout=20))
        xml_text = self._extract_uiautomator_xml(output)
        if xml_text is None:
            raise PhoneBridgeError("UIAutomator did not return complete XML UI data.")
        return xml_text

    @staticmethod
    def _parse_ui_bounds(value: str) -> tuple[int, int, int, int] | None:
        match = UI_BOUNDS_RE.fullmatch(value.strip())
        if not match:
            return None
        left, top, right, bottom = (int(part) for part in match.groups())
        if right <= left or bottom <= top:
            return None
        return left, top, right, bottom

    @staticmethod
    def _matches_ui_value(actual: str, expected: str | None, *, exact: bool, case_sensitive: bool) -> bool:
        if expected is None:
            return True
        if case_sensitive:
            haystack, needle = actual, expected
        else:
            haystack, needle = actual.casefold(), expected.casefold()
        return haystack == needle if exact else needle in haystack

    def ui_elements(
        self,
        *,
        text: str | None = None,
        content_desc: str | None = None,
        resource_id: str | None = None,
        exact: bool = True,
        case_sensitive: bool = False,
        serial: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        """Find UIAutomator elements and map their bounds to active ADB input coordinates."""
        if text is None and content_desc is None and resource_id is None:
            raise PhoneBridgeError("Provide at least one of text, content_desc, or resource_id.")
        for label, value in (("text", text), ("content_desc", content_desc), ("resource_id", resource_id)):
            if value is not None and (not value.strip() or len(value) > 300):
                raise PhoneBridgeError(f"{label} must be 1-300 characters when provided.")

        selected = self.select_device(serial)
        xml_text = self.ui_xml(selected)
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise PhoneBridgeError(f"UIAutomator returned invalid XML: {exc}") from exc

        input_width, input_height = self.screen_size(selected)
        viewport_bounds: tuple[int, int, int, int] | None = None
        for node in root.iter():
            parsed = self._parse_ui_bounds(node.attrib.get("bounds", ""))
            if parsed:
                viewport_bounds = parsed
                break
        if viewport_bounds is None:
            viewport_bounds = (0, 0, input_width, input_height)

        view_left, view_top, view_right, view_bottom = viewport_bounds
        view_width = max(1, view_right - view_left)
        view_height = max(1, view_bottom - view_top)
        scale_x = input_width / view_width
        scale_y = input_height / view_height

        matches: list[AndroidUIElement] = []
        limit = max(1, min(100, int(limit)))
        for node in root.iter():
            bounds = self._parse_ui_bounds(node.attrib.get("bounds", ""))
            if bounds is None:
                continue

            node_text = node.attrib.get("text", "")
            node_desc = node.attrib.get("content-desc", "")
            node_resource = node.attrib.get("resource-id", "")
            if not self._matches_ui_value(node_text, text, exact=exact, case_sensitive=case_sensitive):
                continue
            if not self._matches_ui_value(node_desc, content_desc, exact=exact, case_sensitive=case_sensitive):
                continue
            if not self._matches_ui_value(node_resource, resource_id, exact=exact, case_sensitive=case_sensitive):
                continue

            left, top, right, bottom = bounds
            mapped_left = round((left - view_left) * scale_x)
            mapped_top = round((top - view_top) * scale_y)
            mapped_right = round((right - view_left) * scale_x)
            mapped_bottom = round((bottom - view_top) * scale_y)
            mapped_left = max(0, min(input_width - 1, mapped_left))
            mapped_top = max(0, min(input_height - 1, mapped_top))
            mapped_right = max(mapped_left + 1, min(input_width, mapped_right))
            mapped_bottom = max(mapped_top + 1, min(input_height, mapped_bottom))

            matches.append(
                AndroidUIElement(
                    text=node_text,
                    content_desc=node_desc,
                    resource_id=node_resource,
                    class_name=node.attrib.get("class", ""),
                    package=node.attrib.get("package", ""),
                    clickable=node.attrib.get("clickable", "false").lower() == "true",
                    enabled=node.attrib.get("enabled", "true").lower() == "true",
                    bounds=bounds,
                    input_bounds=(mapped_left, mapped_top, mapped_right, mapped_bottom),
                )
            )
            if len(matches) >= limit:
                break

        return {
            "serial": selected,
            "input_size": [input_width, input_height],
            "ui_viewport": list(viewport_bounds),
            "count": len(matches),
            "matches": [element.as_dict() for element in matches],
        }

    def screen_context(
        self,
        serial: str | None = None,
        limit: int = 40,
    ) -> dict[str, Any]:
        """Return a compact UI/accessibility snapshot for fast agent perception.

        This intentionally avoids returning the full XML tree. It surfaces the
        most useful text/accessibility/clickable nodes and tells callers when
        the accessibility tree is too sparse (for example, Unity games), where
        screenshot vision is likely to be more useful.
        """
        selected = self.select_device(serial)
        xml_text = self.ui_xml(selected)
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise PhoneBridgeError(f"UIAutomator returned invalid XML: {exc}") from exc

        input_width, input_height = self.screen_size(selected)
        orientation = "landscape" if input_width > input_height else "portrait"

        viewport_bounds: tuple[int, int, int, int] | None = None
        for node in root.iter():
            parsed = self._parse_ui_bounds(node.attrib.get("bounds", ""))
            if parsed:
                viewport_bounds = parsed
                break
        if viewport_bounds is None:
            viewport_bounds = (0, 0, input_width, input_height)

        view_left, view_top, view_right, view_bottom = viewport_bounds
        view_width = max(1, view_right - view_left)
        view_height = max(1, view_bottom - view_top)
        scale_x = input_width / view_width
        scale_y = input_height / view_height

        limit = max(1, min(100, int(limit)))
        packages: set[str] = set()
        elements: list[dict[str, Any]] = []
        signature_elements: list[list[Any]] = []
        clickable_count = 0
        informative_count = 0

        for node in root.iter():
            package = node.attrib.get("package", "")
            if package:
                packages.add(package)

            text = node.attrib.get("text", "").strip()
            content_desc = node.attrib.get("content-desc", "").strip()
            resource_id = node.attrib.get("resource-id", "").strip()
            class_name = node.attrib.get("class", "")
            clickable = node.attrib.get("clickable", "false").lower() == "true"
            enabled = node.attrib.get("enabled", "true").lower() == "true"
            bounds = self._parse_ui_bounds(node.attrib.get("bounds", ""))

            informative = bool(text or content_desc or clickable)
            if informative:
                informative_count += 1
                if bounds is not None and len(signature_elements) < 500:
                    signature_elements.append(
                        [
                            text[:300],
                            content_desc[:300],
                            resource_id[:300],
                            class_name[:200],
                            package[:200],
                            bool(clickable),
                            bool(enabled),
                            list(bounds),
                        ]
                    )
            if clickable:
                clickable_count += 1
            if not informative or bounds is None or len(elements) >= limit:
                continue

            left, top, right, bottom = bounds
            mapped_left = max(0, min(input_width - 1, round((left - view_left) * scale_x)))
            mapped_top = max(0, min(input_height - 1, round((top - view_top) * scale_y)))
            mapped_right = max(mapped_left + 1, min(input_width, round((right - view_left) * scale_x)))
            mapped_bottom = max(mapped_top + 1, min(input_height, round((bottom - view_top) * scale_y)))
            center_x = (mapped_left + mapped_right) // 2
            center_y = (mapped_top + mapped_bottom) // 2

            elements.append(
                {
                    "text": text,
                    "content_desc": content_desc,
                    "resource_id": resource_id,
                    "class_name": class_name,
                    "package": package,
                    "clickable": clickable,
                    "enabled": enabled,
                    "input_bounds": [mapped_left, mapped_top, mapped_right, mapped_bottom],
                    "input_center": [center_x, center_y],
                }
            )

        # Accessibility trees from games/canvas surfaces often contain only one
        # generic surface node and no meaningful controls. Mark those screens so
        # a future local VLM can be used only when it adds value.
        generic_surface_only = bool(elements) and all(
            not item["text"]
            and not item["content_desc"]
            and item["class_name"] in {"android.view.View", "android.view.SurfaceView"}
            for item in elements
        )
        vision_recommended = informative_count <= 2 or generic_surface_only

        signature_payload = {
            "input_size": [input_width, input_height],
            "orientation": orientation,
            "packages": sorted(packages),
            "informative_node_count": informative_count,
            "clickable_node_count": clickable_count,
            "elements": signature_elements,
        }
        semantic_signature = hashlib.sha256(
            json.dumps(signature_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:24]

        return {
            "serial": selected,
            "input_size": [input_width, input_height],
            "orientation": orientation,
            "packages": sorted(packages),
            "element_count": len(elements),
            "informative_node_count": informative_count,
            "clickable_node_count": clickable_count,
            "semantic_signature": semantic_signature,
            "semantic_signature_nodes": len(signature_elements),
            "semantic_signature_truncated": informative_count > len(signature_elements),
            "vision_recommended": vision_recommended,
            "elements": elements,
        }

    def tap_ui_element(
        self,
        *,
        text: str | None = None,
        content_desc: str | None = None,
        resource_id: str | None = None,
        exact: bool = True,
        case_sensitive: bool = False,
        index: int | None = None,
        serial: str | None = None,
    ) -> dict[str, Any]:
        """Find a UI element, require an unambiguous match by default, and tap its mapped center."""
        result = self.ui_elements(
            text=text,
            content_desc=content_desc,
            resource_id=resource_id,
            exact=exact,
            case_sensitive=case_sensitive,
            serial=serial,
            limit=100,
        )
        matches = result["matches"]
        if not matches:
            raise PhoneBridgeError("No matching Android UI element was found.")
        if index is None:
            if len(matches) != 1:
                raise PhoneBridgeError(
                    f"Found {len(matches)} matching UI elements. Refine the query or pass an explicit index."
                )
            chosen_index = 0
        else:
            chosen_index = int(index)
            if chosen_index < 0 or chosen_index >= len(matches):
                raise PhoneBridgeError(
                    f"Element index {chosen_index} is out of range for {len(matches)} matches."
                )

        chosen = matches[chosen_index]
        if not chosen["enabled"]:
            raise PhoneBridgeError("The selected Android UI element is disabled, so it was not tapped.")
        center_x, center_y = chosen["input_center"]
        tap_result = self.tap(center_x, center_y, result["serial"])
        return {
            **tap_result,
            "action": "tap_ui_element",
            "match_index": chosen_index,
            "match_count": len(matches),
            "element": chosen,
        }

    def tap_ui_element_verified(
        self,
        *,
        text: str | None = None,
        content_desc: str | None = None,
        resource_id: str | None = None,
        exact: bool = True,
        case_sensitive: bool = False,
        index: int | None = None,
        expected_package_name: str | None = None,
        observation_attempts: int = 3,
        observation_delay_ms: int = 250,
        serial: str | None = None,
    ) -> dict[str, Any]:
        """Resolve one semantic UI element, tap it once, then verify without automatic retry."""
        result = self.ui_elements(
            text=text,
            content_desc=content_desc,
            resource_id=resource_id,
            exact=exact,
            case_sensitive=case_sensitive,
            serial=serial,
            limit=100,
        )
        matches = result["matches"]
        if not matches:
            raise PhoneBridgeError("No matching Android UI element was found.")
        if index is None:
            if len(matches) != 1:
                raise PhoneBridgeError(
                    f"Found {len(matches)} matching UI elements. Refine the query or pass an explicit index."
                )
            chosen_index = 0
        else:
            chosen_index = int(index)
            if chosen_index < 0 or chosen_index >= len(matches):
                raise PhoneBridgeError(
                    f"Element index {chosen_index} is out of range for {len(matches)} matches."
                )
        chosen = matches[chosen_index]
        if not chosen["enabled"]:
            raise PhoneBridgeError("The selected Android UI element is disabled, so it was not tapped.")
        center_x, center_y = chosen["input_center"]
        expected = expected_package_name or str(chosen.get("package") or "") or None
        verified = self.tap_verified(
            center_x,
            center_y,
            expected_package_name=expected,
            observation_attempts=observation_attempts,
            observation_delay_ms=observation_delay_ms,
            serial=result["serial"],
        )
        return {
            **verified,
            "action": "tap_ui_element_verified",
            "match_index": chosen_index,
            "match_count": len(matches),
            "element": chosen,
        }

    def tap(self, x: int, y: int, serial: str | None = None) -> dict[str, Any]:
        selected = self.select_device(serial)
        x, y = self._validate_point(x, y, selected)
        self._run(["shell", "input", "tap", str(x), str(y)], serial=selected)
        return {"status": "ok", "action": "tap", "x": x, "y": y, "serial": selected}

    def long_press(
        self,
        x: int,
        y: int,
        duration_ms: int = 700,
        serial: str | None = None,
    ) -> dict[str, Any]:
        selected = self.select_device(serial)
        x, y = self._validate_point(x, y, selected)
        duration_ms = max(300, min(5000, int(duration_ms)))
        self._run(
            ["shell", "input", "swipe", str(x), str(y), str(x), str(y), str(duration_ms)],
            serial=selected,
        )
        return {
            "status": "ok",
            "action": "long_press",
            "x": x,
            "y": y,
            "duration_ms": duration_ms,
            "serial": selected,
        }

    def swipe(
        self,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        duration_ms: int = 400,
        serial: str | None = None,
    ) -> dict[str, Any]:
        selected = self.select_device(serial)
        start_x, start_y = self._validate_point(start_x, start_y, selected)
        end_x, end_y = self._validate_point(end_x, end_y, selected)
        duration_ms = max(100, min(5000, int(duration_ms)))
        self._run(
            [
                "shell",
                "input",
                "swipe",
                str(start_x),
                str(start_y),
                str(end_x),
                str(end_y),
                str(duration_ms),
            ],
            serial=selected,
        )
        return {
            "status": "ok",
            "action": "swipe",
            "start": [start_x, start_y],
            "end": [end_x, end_y],
            "duration_ms": duration_ms,
            "serial": selected,
        }

    def _directional_swipe_points(
        self,
        direction: str,
        distance_ratio: float,
        serial: str,
    ) -> tuple[str, float, tuple[int, int], tuple[int, int]]:
        """Return safe center-origin swipe coordinates for one cardinal finger direction."""
        normalized = direction.strip().lower()
        if normalized not in SWIPE_DIRECTIONS:
            raise PhoneBridgeError(
                "Unsupported swipe direction. Allowed values: " + ", ".join(sorted(SWIPE_DIRECTIONS))
            )
        ratio = float(distance_ratio)
        if not 0.10 <= ratio <= 0.70:
            raise PhoneBridgeError("distance_ratio must be between 0.10 and 0.70.")

        width, height = self.screen_size(serial)
        center_x = width // 2
        center_y = height // 2
        margin_x = max(24, round(width * 0.12))
        margin_y = max(24, round(height * 0.12))
        vector_x, vector_y = SWIPE_DIRECTIONS[normalized]
        axis_size = height if vector_y else width
        distance = max(48, round(axis_size * ratio))
        end_x = round(center_x + vector_x * distance)
        end_y = round(center_y + vector_y * distance)
        end_x = max(margin_x, min(width - 1 - margin_x, end_x))
        end_y = max(margin_y, min(height - 1 - margin_y, end_y))
        return normalized, ratio, (center_x, center_y), (end_x, end_y)

    def swipe_direction(
        self,
        direction: str,
        *,
        distance_ratio: float = 0.35,
        duration_ms: int = 400,
        serial: str | None = None,
    ) -> dict[str, Any]:
        """Swipe in a cardinal direction from screen center while staying away from gesture edges."""
        selected = self.select_device(serial)
        normalized, ratio, start, end = self._directional_swipe_points(
            direction,
            distance_ratio,
            selected,
        )
        result = self.swipe(
            start[0],
            start[1],
            end[0],
            end[1],
            duration_ms,
            selected,
        )
        return {
            **result,
            "action": "swipe_direction",
            "direction": normalized,
            "distance_ratio": ratio,
        }

    def wait_for_ui_element(
        self,
        *,
        text: str | None = None,
        content_desc: str | None = None,
        resource_id: str | None = None,
        exact: bool = True,
        case_sensitive: bool = False,
        expected_present: bool = True,
        observation_attempts: int = 4,
        observation_delay_ms: int = 250,
        limit: int = 20,
        serial: str | None = None,
    ) -> dict[str, Any]:
        """Poll UIAutomator for one bounded semantic presence/absence condition without acting on the phone."""
        selected = self.select_device(serial)
        attempts = max(1, min(MAX_UI_WAIT_ATTEMPTS, int(observation_attempts)))
        delay_ms = max(0, min(MAX_UI_WAIT_DELAY_MS, int(observation_delay_ms)))
        observations: list[dict[str, Any]] = []
        last_result: dict[str, Any] | None = None

        for attempt in range(1, attempts + 1):
            last_result = self.ui_elements(
                text=text,
                content_desc=content_desc,
                resource_id=resource_id,
                exact=exact,
                case_sensitive=case_sensitive,
                serial=selected,
                limit=limit,
            )
            present = bool(last_result["count"])
            condition_met = present == bool(expected_present)
            observations.append(
                {
                    "attempt": attempt,
                    "present": present,
                    "match_count": int(last_result["count"]),
                    "condition_met": condition_met,
                }
            )
            if condition_met:
                return {
                    "status": "ok",
                    "action": "wait_for_ui_element",
                    "serial": selected,
                    "condition_met": True,
                    "expected_present": bool(expected_present),
                    "attempts_used": attempt,
                    "attempts_max": attempts,
                    "observation_delay_ms": delay_ms,
                    "matches": last_result["matches"],
                    "observations": observations,
                }
            if delay_ms and attempt < attempts:
                time.sleep(delay_ms / 1000.0)

        assert last_result is not None
        return {
            "status": "ok",
            "action": "wait_for_ui_element",
            "serial": selected,
            "condition_met": False,
            "expected_present": bool(expected_present),
            "attempts_used": attempts,
            "attempts_max": attempts,
            "observation_delay_ms": delay_ms,
            "matches": last_result["matches"],
            "observations": observations,
        }

    @staticmethod
    def _normalize_expected_package(expected_package_name: str | None) -> str | None:
        if expected_package_name is None:
            return None
        package_name = expected_package_name.strip()
        if not PACKAGE_RE.fullmatch(package_name):
            raise PhoneBridgeError("Invalid expected Android package name.")
        return package_name

    def _require_foreground_package(
        self,
        expected_package_name: str | None,
        serial: str,
        *,
        phase: str,
    ) -> dict[str, Any]:
        expected = self._normalize_expected_package(expected_package_name)
        current = self.surface_identity(serial, limit=12)
        if expected is None:
            return current
        actual = current.get("package_name", "")
        if actual != expected:
            actual_label = actual or "<unknown>"
            raise PhoneBridgeError(
                f"Foreground package guard failed {phase}: expected '{expected}', got '{actual_label}'."
            )
        return current

    def _verification_baseline(
        self,
        serial: str,
        *,
        limit: int,
    ) -> dict[str, Any]:
        context = self.screen_context(serial=serial, limit=limit)
        reported_app = self.current_app(serial)
        visible_packages = [str(item) for item in context.get("packages", []) if str(item)]
        visible_package = visible_packages[0] if len(visible_packages) == 1 else ""
        reported_package = str(reported_app.get("package_name") or "")
        reported_activity = str(reported_app.get("activity") or "")
        package_name = visible_package or reported_package
        activity = reported_activity if not visible_package or visible_package == reported_package else ""
        return {
            "semantic_signature": context["semantic_signature"],
            "visual_dhash": self.screen_visual_hash(serial),
            "package_name": package_name,
            "activity": activity,
            "identity_source": (
                "uia_visible_package" if visible_package else "dumpsys_fallback"
            ),
        }

    def _observe_verified_action(
        self,
        baseline: dict[str, Any],
        *,
        expected_package_name: str | None,
        verification_policy: str,
        observation_attempts: int,
        observation_delay_ms: int,
        limit: int,
        serial: str,
    ) -> dict[str, Any]:
        expected = self._normalize_expected_package(expected_package_name)
        attempts = max(1, min(MAX_VERIFICATION_ATTEMPTS, int(observation_attempts)))
        delay_ms = max(0, min(MAX_VERIFICATION_DELAY_MS, int(observation_delay_ms)))
        observations: list[dict[str, Any]] = []
        final_verification: dict[str, Any] | None = None
        final_guard_ok = expected is None

        for attempt in range(1, attempts + 1):
            if delay_ms:
                time.sleep(delay_ms / 1000.0)
            verification = self.verify_state_change(
                baseline["semantic_signature"],
                previous_visual_dhash=baseline["visual_dhash"],
                previous_package_name=baseline.get("package_name") or None,
                previous_activity=baseline.get("activity") or None,
                verification_policy=verification_policy,
                limit=limit,
                serial=serial,
            )
            current_package = str(verification["current"].get("package_name") or "")
            guard_ok = expected is None or current_package == expected
            observations.append(
                {
                    "attempt": attempt,
                    "verification_passed": bool(verification.get("verification_passed")),
                    "state_change_detected": bool(verification.get("state_change_detected")),
                    "foreground_guard_ok": guard_ok,
                    "current_package_name": current_package,
                }
            )
            final_verification = verification
            final_guard_ok = guard_ok
            if verification.get("verification_passed") and guard_ok:
                break

        assert final_verification is not None
        verification_passed = bool(final_verification.get("verification_passed")) and final_guard_ok
        if verification_passed:
            execution_status = "EXECUTED_VERIFIED"
        elif final_guard_ok:
            execution_status = "EXECUTED_UNVERIFIED"
        else:
            execution_status = "RECOVERABLE_ERROR"
        return {
            "verification_passed": verification_passed,
            "foreground_guard_ok": final_guard_ok,
            "execution_status": execution_status,
            "safe_to_retry_action": False,
            "requires_reobserve": not verification_passed,
            "observation_attempts_used": len(observations),
            "observation_attempts_max": attempts,
            "observation_delay_ms": delay_ms,
            "automatic_action_retry": False,
            "observations": observations,
            "verification": final_verification,
        }

    def _game_verification_baseline(self, serial: str, *, limit: int) -> dict[str, Any]:
        baseline = self._verification_baseline(serial, limit=limit)
        baseline["game_world_dhash"] = self.screen_region_visual_hash(serial)
        return baseline

    def _observe_game_action(
        self,
        baseline: dict[str, Any],
        *,
        expected_package_name: str,
        observation_attempts: int,
        observation_delay_ms: int,
        limit: int,
        serial: str,
    ) -> dict[str, Any]:
        observed = self._observe_verified_action(
            baseline,
            expected_package_name=expected_package_name,
            verification_policy="any_confident_change",
            observation_attempts=observation_attempts,
            observation_delay_ms=observation_delay_ms,
            limit=limit,
            serial=serial,
        )
        previous_world_hash = str(baseline.get("game_world_dhash") or "")
        current_world_hash = self.screen_region_visual_hash(serial)
        world_distance = self._hex_hamming_distance(previous_world_hash, current_world_hash)
        world_change_confident = world_distance >= GAME_WORLD_VERIFY_HAMMING_THRESHOLD
        guard_ok = bool(observed.get("foreground_guard_ok"))
        shared_verified = bool(observed.get("verification_passed"))
        game_verified = guard_ok and (shared_verified or world_change_confident)
        if game_verified:
            execution_status = "EXECUTED_VERIFIED"
            verification_source = "shared_contract" if shared_verified else "game_world_region"
        elif guard_ok:
            execution_status = "EXECUTED_UNVERIFIED"
            verification_source = "none"
        else:
            execution_status = "RECOVERABLE_ERROR"
            verification_source = "foreground_guard"
        return {
            **observed,
            "verification_passed": game_verified,
            "execution_status": execution_status,
            "safe_to_retry_action": False,
            "requires_reobserve": not game_verified,
            "verification_source": verification_source,
            "game_motion_verification": {
                "previous_visual_dhash": previous_world_hash,
                "current_visual_dhash": current_world_hash,
                "visual_hamming_distance": world_distance,
                "visual_hamming_threshold": GAME_WORLD_VERIFY_HAMMING_THRESHOLD,
                "visual_change_confident": world_change_confident,
            },
        }

    def tap_verified(
        self,
        x: int,
        y: int,
        *,
        expected_package_name: str | None = None,
        verification_policy: str = "any_confident_change",
        observation_attempts: int = 3,
        observation_delay_ms: int = 250,
        limit: int = 40,
        serial: str | None = None,
    ) -> dict[str, Any]:
        """Execute one tap, then observe bounded post-action state without retrying the tap."""
        selected = self.select_device(serial)
        expected = self._normalize_expected_package(expected_package_name)
        self._require_foreground_package(expected, selected, phase="before tap")
        baseline = self._verification_baseline(selected, limit=limit)
        action_result = self.tap(x, y, selected)
        observed = self._observe_verified_action(
            baseline,
            expected_package_name=expected,
            verification_policy=verification_policy,
            observation_attempts=observation_attempts,
            observation_delay_ms=observation_delay_ms,
            limit=limit,
            serial=selected,
        )
        return {
            "status": "ok",
            "action": "tap_verified",
            "serial": selected,
            "expected_package_name": expected,
            "action_executed_once": True,
            "action_result": action_result,
            "baseline": baseline,
            **observed,
        }

    def long_press_verified(
        self,
        x: int,
        y: int,
        *,
        duration_ms: int = 700,
        expected_package_name: str | None = None,
        verification_policy: str = "any_confident_change",
        observation_attempts: int = 3,
        observation_delay_ms: int = 250,
        limit: int = 40,
        serial: str | None = None,
    ) -> dict[str, Any]:
        """Execute one long press, then observe bounded post-action state without retrying it."""
        selected = self.select_device(serial)
        expected = self._normalize_expected_package(expected_package_name)
        self._require_foreground_package(expected, selected, phase="before long press")
        baseline = self._verification_baseline(selected, limit=limit)
        action_result = self.long_press(x, y, duration_ms, selected)
        observed = self._observe_verified_action(
            baseline,
            expected_package_name=expected,
            verification_policy=verification_policy,
            observation_attempts=observation_attempts,
            observation_delay_ms=observation_delay_ms,
            limit=limit,
            serial=selected,
        )
        return {
            "status": "ok",
            "action": "long_press_verified",
            "serial": selected,
            "expected_package_name": expected,
            "action_executed_once": True,
            "action_result": action_result,
            "baseline": baseline,
            **observed,
        }

    def swipe_verified(
        self,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        *,
        duration_ms: int = 400,
        expected_package_name: str | None = None,
        verification_policy: str = "any_confident_change",
        observation_attempts: int = 3,
        observation_delay_ms: int = 250,
        limit: int = 40,
        serial: str | None = None,
    ) -> dict[str, Any]:
        """Execute one swipe, then observe bounded post-action state without retrying the swipe."""
        selected = self.select_device(serial)
        expected = self._normalize_expected_package(expected_package_name)
        self._require_foreground_package(expected, selected, phase="before swipe")
        baseline = self._verification_baseline(selected, limit=limit)
        action_result = self.swipe(
            start_x,
            start_y,
            end_x,
            end_y,
            duration_ms,
            selected,
        )
        observed = self._observe_verified_action(
            baseline,
            expected_package_name=expected,
            verification_policy=verification_policy,
            observation_attempts=observation_attempts,
            observation_delay_ms=observation_delay_ms,
            limit=limit,
            serial=selected,
        )
        return {
            "status": "ok",
            "action": "swipe_verified",
            "serial": selected,
            "expected_package_name": expected,
            "action_executed_once": True,
            "action_result": action_result,
            "baseline": baseline,
            **observed,
        }

    def swipe_direction_verified(
        self,
        direction: str,
        *,
        distance_ratio: float = 0.35,
        duration_ms: int = 400,
        expected_package_name: str | None = None,
        verification_policy: str = "any_confident_change",
        observation_attempts: int = 3,
        observation_delay_ms: int = 250,
        limit: int = 40,
        serial: str | None = None,
    ) -> dict[str, Any]:
        """Execute one safe center-origin directional swipe, then verify without automatic retry."""
        selected = self.select_device(serial)
        normalized, ratio, start, end = self._directional_swipe_points(
            direction,
            distance_ratio,
            selected,
        )
        result = self.swipe_verified(
            start[0],
            start[1],
            end[0],
            end[1],
            duration_ms=duration_ms,
            expected_package_name=expected_package_name,
            verification_policy=verification_policy,
            observation_attempts=observation_attempts,
            observation_delay_ms=observation_delay_ms,
            limit=limit,
            serial=selected,
        )
        return {
            **result,
            "action": "swipe_direction_verified",
            "direction": normalized,
            "distance_ratio": ratio,
        }

    def game_joystick_move(
        self,
        direction: str,
        duration_ms: int,
        *,
        expected_package_name: str,
        center_x: int | None = None,
        center_y: int | None = None,
        radius_px: int | None = None,
        observation_attempts: int = 2,
        observation_delay_ms: int = 200,
        limit: int = 20,
        serial: str | None = None,
    ) -> dict[str, Any]:
        """Approximate one bounded virtual-joystick hold with a long ADB drag and verify its effect.

        This is intentionally implemented with Android's documented `input swipe` primitive.
        It does not use sendevent, root, accessibility injection, or anti-cheat bypasses.
        """
        normalized_direction = direction.strip().lower().replace("-", "_")
        if normalized_direction not in GAME_JOYSTICK_DIRECTIONS:
            raise PhoneBridgeError(
                "Unsupported joystick direction. Allowed values: "
                + ", ".join(sorted(GAME_JOYSTICK_DIRECTIONS))
            )
        expected = self._normalize_expected_package(expected_package_name)
        assert expected is not None
        selected = self.select_device(serial)
        session = self._require_landscape_game_session(expected, selected)
        width, height = [int(value) for value in session["input_size"]]

        default_center_x = round(width * 0.19)
        default_center_y = round(height * 0.78)
        start_x = default_center_x if center_x is None else int(center_x)
        start_y = default_center_y if center_y is None else int(center_y)
        start_x, start_y = self._validate_point(start_x, start_y, selected)

        default_radius = max(48, round(min(width, height) * 0.22))
        radius = default_radius if radius_px is None else int(radius_px)
        radius = max(24, min(round(min(width, height) * 0.35), radius))
        vector_x, vector_y = GAME_JOYSTICK_DIRECTIONS[normalized_direction]
        end_x = round(start_x + vector_x * radius)
        end_y = round(start_y + vector_y * radius)
        end_x = max(0, min(width - 1, end_x))
        end_y = max(0, min(height - 1, end_y))
        duration = max(200, min(MAX_GAME_GESTURE_MS, int(duration_ms)))

        baseline = self._game_verification_baseline(selected, limit=limit)
        self._run(
            [
                "shell",
                "input",
                "swipe",
                str(start_x),
                str(start_y),
                str(end_x),
                str(end_y),
                str(duration),
            ],
            serial=selected,
            timeout=max(15, duration // 1000 + 10),
        )
        action_result = {
            "status": "ok",
            "action": "game_joystick_drag",
            "direction": normalized_direction,
            "start": [start_x, start_y],
            "end": [end_x, end_y],
            "radius_px": radius,
            "duration_ms": duration,
            "motion_model": "adb_long_swipe",
            "serial": selected,
        }
        observed = self._observe_game_action(
            baseline,
            expected_package_name=expected,
            observation_attempts=observation_attempts,
            observation_delay_ms=observation_delay_ms,
            limit=limit,
            serial=selected,
        )
        return {
            "status": "ok",
            "action": "game_joystick_move",
            "serial": selected,
            "expected_package_name": expected,
            "action_executed_once": True,
            "session_guard": session,
            "action_result": action_result,
            "baseline": baseline,
            **observed,
        }

    def game_camera_drag(
        self,
        direction: str,
        distance_px: int,
        *,
        expected_package_name: str,
        duration_ms: int = 350,
        start_x: int | None = None,
        start_y: int | None = None,
        observation_attempts: int = 2,
        observation_delay_ms: int = 180,
        limit: int = 20,
        serial: str | None = None,
    ) -> dict[str, Any]:
        """Drag the game camera from a bounded safe-right region and verify one action only.

        The default start point deliberately avoids the Android gesture edges, the
        lower-left joystick, and the usual lower-right skill cluster used by landscape games.
        """
        normalized_direction = direction.strip().lower()
        if normalized_direction not in GAME_CAMERA_DIRECTIONS:
            raise PhoneBridgeError(
                "Unsupported camera direction. Allowed values: "
                + ", ".join(sorted(GAME_CAMERA_DIRECTIONS))
            )
        expected = self._normalize_expected_package(expected_package_name)
        assert expected is not None
        selected = self.select_device(serial)
        session = self._require_landscape_game_session(expected, selected)
        width, height = [int(value) for value in session["input_size"]]

        safe_left = round(width * 0.42)
        safe_right = round(width * 0.72)
        safe_top = round(height * 0.28)
        safe_bottom = round(height * 0.62)
        sx = round(width * 0.58) if start_x is None else int(start_x)
        sy = round(height * 0.45) if start_y is None else int(start_y)
        if not (safe_left <= sx <= safe_right and safe_top <= sy <= safe_bottom):
            raise PhoneBridgeError(
                "Camera drag start is outside the bounded game-camera safe region: "
                f"x={safe_left}-{safe_right}, y={safe_top}-{safe_bottom}."
            )

        max_distance = max(60, round(min(width, height) * 0.28))
        distance = max(40, min(max_distance, int(distance_px)))
        vector_x, vector_y = GAME_CAMERA_DIRECTIONS[normalized_direction]
        ex = round(sx + vector_x * distance)
        ey = round(sy + vector_y * distance)
        ex = max(safe_left, min(safe_right, ex))
        ey = max(safe_top, min(safe_bottom, ey))
        duration = max(120, min(MAX_GAME_CAMERA_GESTURE_MS, int(duration_ms)))

        baseline = self._game_verification_baseline(selected, limit=limit)
        action_result = self.swipe(sx, sy, ex, ey, duration, selected)
        observed = self._observe_game_action(
            baseline,
            expected_package_name=expected,
            observation_attempts=observation_attempts,
            observation_delay_ms=observation_delay_ms,
            limit=limit,
            serial=selected,
        )
        return {
            "status": "ok",
            "action": "game_camera_drag",
            "serial": selected,
            "expected_package_name": expected,
            "direction": normalized_direction,
            "action_executed_once": True,
            "session_guard": session,
            "safe_region": [safe_left, safe_top, safe_right, safe_bottom],
            "action_result": action_result,
            "baseline": baseline,
            **observed,
        }

    def open_app_verified(
        self,
        package_name: str,
        *,
        observation_attempts: int = 4,
        observation_delay_ms: int = 250,
        serial: str | None = None,
    ) -> dict[str, Any]:
        """Launch an app once and wait for stable visible-surface ownership without retrying launch."""
        package_name = package_name.strip()
        if not PACKAGE_RE.fullmatch(package_name):
            raise PhoneBridgeError("Invalid Android package name.")
        selected = self.select_device(serial)
        action_result = self.open_app(package_name, selected)
        attempts = max(1, min(MAX_STABLE_SURFACE_SAMPLES, int(observation_attempts)))
        delay = max(0, min(MAX_STABLE_SURFACE_DELAY_MS, int(observation_delay_ms)))
        observations: list[dict[str, Any]] = []
        final: dict[str, Any] | None = None
        for attempt in range(1, attempts + 1):
            if delay:
                time.sleep(delay / 1000.0)
            final = self.stable_surface_identity(selected, samples=2, delay_ms=60, limit=12)
            observations.append(
                {
                    "attempt": attempt,
                    "package_name": final.get("package_name", ""),
                    "stable": bool(final.get("stable")),
                    "orientation": final.get("orientation"),
                }
            )
            if final.get("stable") and final.get("package_name") == package_name:
                break
        assert final is not None
        verified = bool(final.get("stable") and final.get("package_name") == package_name)
        return {
            "status": "ok",
            "action": "open_app_verified",
            "serial": selected,
            "package_name": package_name,
            "action_executed_once": True,
            "action_result": action_result,
            "verification_passed": verified,
            "execution_status": "EXECUTED_VERIFIED" if verified else "EXECUTED_UNVERIFIED",
            "safe_to_retry_action": False,
            "requires_reobserve": not verified,
            "surface": final,
            "observations": observations,
            "automatic_action_retry": False,
        }

    def type_text(self, text: str, serial: str | None = None) -> dict[str, Any]:
        if not text:
            raise PhoneBridgeError("Text must not be empty.")
        if len(text) > 500:
            raise PhoneBridgeError("Text is limited to 500 characters per tool call.")
        if not SAFE_TEXT_RE.fullmatch(text):
            raise PhoneBridgeError(
                "For safety, ADB text input currently accepts ASCII letters/numbers, spaces, and . , _ @ : + - / only."
            )
        selected = self.select_device(serial)
        adb_text = text.replace(" ", "%s")
        self._run(["shell", "input", "text", adb_text], serial=selected)
        return {"status": "ok", "action": "type_text", "characters": len(text), "serial": selected}

    def type_text_verified(
        self,
        text: str,
        *,
        expected_package_name: str | None = None,
        verification_policy: str = "any_confident_change",
        observation_attempts: int = 3,
        observation_delay_ms: int = 250,
        limit: int = 40,
        serial: str | None = None,
    ) -> dict[str, Any]:
        """Type once into the focused field, then verify bounded state change without retrying input."""
        selected = self.select_device(serial)
        expected = self._normalize_expected_package(expected_package_name)
        self._require_foreground_package(expected, selected, phase="before text input")
        baseline = self._verification_baseline(selected, limit=limit)
        action_result = self.type_text(text, selected)
        observed = self._observe_verified_action(
            baseline,
            expected_package_name=expected,
            verification_policy=verification_policy,
            observation_attempts=observation_attempts,
            observation_delay_ms=observation_delay_ms,
            limit=limit,
            serial=selected,
        )
        return {
            "status": "ok",
            "action": "type_text_verified",
            "serial": selected,
            "expected_package_name": expected,
            "action_executed_once": True,
            "action_result": action_result,
            "baseline": baseline,
            **observed,
        }

    def keyevent(self, key: str, serial: str | None = None) -> dict[str, Any]:
        normalized = key.strip().upper()
        if normalized not in SAFE_KEYEVENTS:
            raise PhoneBridgeError("Unsupported key. Allowed keys: " + ", ".join(sorted(SAFE_KEYEVENTS)))
        selected = self.select_device(serial)
        self._run(["shell", "input", "keyevent", str(SAFE_KEYEVENTS[normalized])], serial=selected)
        return {"status": "ok", "action": "keyevent", "key": normalized, "serial": selected}

    def keyevent_verified(
        self,
        key: str,
        *,
        expected_package_name: str | None = None,
        expected_post_package_name: str | None = None,
        verification_policy: str = "any_confident_change",
        observation_attempts: int = 3,
        observation_delay_ms: int = 250,
        limit: int = 40,
        serial: str | None = None,
    ) -> dict[str, Any]:
        """Press one allowlisted key, then verify bounded post-action state without retrying it."""
        selected = self.select_device(serial)
        expected_before = self._normalize_expected_package(expected_package_name)
        expected_after = self._normalize_expected_package(expected_post_package_name)
        self._require_foreground_package(expected_before, selected, phase="before key press")
        baseline = self._verification_baseline(selected, limit=limit)
        action_result = self.keyevent(key, selected)
        observed = self._observe_verified_action(
            baseline,
            expected_package_name=expected_after,
            verification_policy=verification_policy,
            observation_attempts=observation_attempts,
            observation_delay_ms=observation_delay_ms,
            limit=limit,
            serial=selected,
        )
        return {
            "status": "ok",
            "action": "keyevent_verified",
            "serial": selected,
            "expected_package_name": expected_before,
            "expected_post_package_name": expected_after,
            "action_executed_once": True,
            "action_result": action_result,
            "baseline": baseline,
            **observed,
        }

    def open_app(self, package_name: str, serial: str | None = None) -> dict[str, Any]:
        package_name = package_name.strip()
        if not PACKAGE_RE.fullmatch(package_name):
            raise PhoneBridgeError("Invalid Android package name.")
        selected = self.select_device(serial)
        output = str(
            self._run(
                ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
                serial=selected,
                timeout=20,
            )
        )
        if "No activities found" in output or "monkey aborted" in output.lower():
            raise PhoneBridgeError(f"No launchable app found for package '{package_name}'.")
        return {"status": "ok", "action": "open_app", "package_name": package_name, "serial": selected}

    def current_app(self, serial: str | None = None) -> dict[str, str]:
        """Return the best-effort foreground package/activity across Android vendor formats."""
        selected = self.select_device(serial)
        outputs: list[str] = []
        for args in (
            ["shell", "dumpsys", "window", "windows"],
            ["shell", "dumpsys", "activity", "activities"],
        ):
            try:
                outputs.append(str(self._run(args, serial=selected, timeout=20)))
            except PhoneBridgeError:
                continue

        patterns = (
            r"mCurrentFocus=.*?\s(?:u\d+\s+)?([A-Za-z0-9_.]+)/([^\s}]+)",
            r"mFocusedApp=.*?\s(?:u\d+\s+)?([A-Za-z0-9_.]+)/([^\s}]+)",
            r"topResumedActivity=.*?\s(?:u\d+\s+)?([A-Za-z0-9_.]+)/([^\s}]+)",
            r"mResumedActivity=.*?\s(?:u\d+\s+)?([A-Za-z0-9_.]+)/([^\s}]+)",
            r"ResumedActivity:.*?\s(?:u\d+\s+)?([A-Za-z0-9_.]+)/([^\s}]+)",
        )
        for output in outputs:
            for pattern in patterns:
                matches = re.findall(pattern, output)
                if matches:
                    package_name, activity = matches[-1]
                    return {
                        "serial": selected,
                        "package_name": package_name,
                        "activity": activity,
                    }
        return {"serial": selected, "package_name": "", "activity": ""}

    def surface_identity(self, serial: str | None = None, *, limit: int = 12) -> dict[str, Any]:
        """Return the best visible surface identity, preferring UIAutomator when it is unambiguous.

        Android vendor launchers and transient task switches can make dumpsys report a
        launcher for a fraction of a second while the visible app surface is still the
        game. Conversely, a lockscreen/system overlay must override the underlying game.
        This mirrors the reconciliation used by Fast Context and exposes the evidence.
        """
        selected = self.select_device(serial)
        context = self.screen_context(serial=selected, limit=max(1, min(40, int(limit))))
        reported = self.current_app(selected)
        visible_packages = [str(item) for item in context.get("packages", []) if str(item)]
        visible_package = visible_packages[0] if len(visible_packages) == 1 else ""
        reported_package = str(reported.get("package_name") or "")
        reported_activity = str(reported.get("activity") or "")
        if visible_package:
            package_name = visible_package
            activity = reported_activity if visible_package == reported_package else ""
            source = (
                "uia_and_dumpsys_agree"
                if visible_package == reported_package
                else "uia_visible_package_override"
            )
        else:
            package_name = reported_package
            activity = reported_activity
            source = "dumpsys_fallback"
        return {
            "serial": selected,
            "package_name": package_name,
            "activity": activity,
            "source": source,
            "reported_package_name": reported_package,
            "reported_activity": reported_activity,
            "visible_packages": visible_packages,
            "orientation": context.get("orientation"),
            "input_size": list(context.get("input_size") or []),
            "semantic_signature": context.get("semantic_signature"),
            "elements": list(context.get("elements") or []),
        }

    def stable_surface_identity(
        self,
        serial: str | None = None,
        *,
        samples: int = 2,
        delay_ms: int = 120,
        limit: int = 12,
    ) -> dict[str, Any]:
        """Require consecutive agreement before treating a package as foreground-stable."""
        selected = self.select_device(serial)
        sample_count = max(1, min(MAX_STABLE_SURFACE_SAMPLES, int(samples)))
        delay = max(0, min(MAX_STABLE_SURFACE_DELAY_MS, int(delay_ms)))
        observations: list[dict[str, Any]] = []
        consecutive = 0
        last_package = ""
        last: dict[str, Any] | None = None
        for index in range(sample_count):
            if index and delay:
                time.sleep(delay / 1000.0)
            current = self.surface_identity(selected, limit=limit)
            package_name = str(current.get("package_name") or "")
            observations.append(
                {
                    "package_name": package_name,
                    "activity": str(current.get("activity") or ""),
                    "source": str(current.get("source") or ""),
                    "orientation": current.get("orientation"),
                }
            )
            if package_name and package_name == last_package:
                consecutive += 1
            else:
                last_package = package_name
                consecutive = 1 if package_name else 0
            last = current
        assert last is not None
        required_consecutive = 1 if sample_count == 1 else 2
        return {
            **last,
            "stable": bool(last_package and consecutive >= required_consecutive),
            "samples_requested": sample_count,
            "consecutive_agreement": consecutive,
            "observations": observations,
        }

    @staticmethod
    def _lockscreen_from_surface(surface: dict[str, Any]) -> bool:
        package_name = str(surface.get("package_name") or "")
        if package_name != "com.android.systemui":
            return False
        haystacks: list[str] = []
        for item in surface.get("elements") or []:
            if not isinstance(item, dict):
                continue
            haystacks.extend(
                str(item.get(key) or "").casefold()
                for key in ("text", "content_desc", "resource_id")
            )
        joined = "\n".join(haystacks)
        return any(token.casefold() in joined for token in LOCKSCREEN_TOKENS)

    def device_state_snapshot(self, serial: str | None = None) -> dict[str, Any]:
        """Return a read-only device/session guard snapshot for reliable phone actions."""
        selected = self.select_device(serial)
        surface = self.stable_surface_identity(selected, samples=2, delay_ms=80, limit=20)
        width, height = self.screen_size(selected)
        orientation = "landscape" if width > height else "portrait"
        screen_on: bool | None = None
        try:
            power = str(self._run(["shell", "dumpsys", "power"], serial=selected, timeout=20))
            if re.search(r"mInteractive\s*=\s*true|mWakefulness\s*=\s*Awake", power, re.I):
                screen_on = True
            elif re.search(r"mInteractive\s*=\s*false|mWakefulness\s*=\s*Asleep", power, re.I):
                screen_on = False
        except PhoneBridgeError:
            pass
        locked = self._lockscreen_from_surface(surface)
        return {
            "serial": selected,
            "connected": True,
            "screen_on": screen_on,
            "locked": locked,
            "orientation": orientation,
            "input_size": [width, height],
            "surface": {
                "package_name": surface.get("package_name", ""),
                "activity": surface.get("activity", ""),
                "source": surface.get("source", ""),
                "stable": bool(surface.get("stable")),
                "observations": surface.get("observations", []),
            },
            "ready_for_landscape_game": bool(
                surface.get("stable") and not locked and screen_on is not False and orientation == "landscape"
            ),
        }

    def _require_landscape_game_session(self, expected_package_name: str, serial: str) -> dict[str, Any]:
        state = self.device_state_snapshot(serial)
        if state.get("screen_on") is False:
            raise PhoneBridgeError("SCREEN_OFF: wake and unlock the Android device before game input.")
        if state.get("locked"):
            raise PhoneBridgeError("DEVICE_LOCKED: unlock the Android device before game input.")
        if state.get("orientation") != "landscape":
            raise PhoneBridgeError(
                "GAME_ORIENTATION_MISMATCH: expected landscape before game input; "
                f"current input size is {state.get('input_size')}."
            )
        surface = state.get("surface") or {}
        if not surface.get("stable"):
            raise PhoneBridgeError("APP_TRANSITIONING: foreground surface is not stable yet.")
        actual = str(surface.get("package_name") or "")
        if actual != expected_package_name:
            raise PhoneBridgeError(
                f"Foreground package guard failed before game input: expected '{expected_package_name}', got '{actual or '<unknown>'}'."
            )
        return state

    @staticmethod
    def _hex_hamming_distance(left: str, right: str) -> int:
        left_value = str(left or "").strip().casefold()
        right_value = str(right or "").strip().casefold()
        if not left_value or not right_value or len(left_value) != len(right_value):
            raise PhoneBridgeError("Visual hash values must be non-empty hexadecimal strings of equal length.")
        if not re.fullmatch(r"[0-9a-f]+", left_value) or not re.fullmatch(r"[0-9a-f]+", right_value):
            raise PhoneBridgeError("Visual hash values must contain hexadecimal characters only.")
        return (int(left_value, 16) ^ int(right_value, 16)).bit_count()

    def verify_state_change(
        self,
        previous_semantic_signature: str,
        *,
        previous_visual_dhash: str | None = None,
        previous_package_name: str | None = None,
        previous_activity: str | None = None,
        verification_policy: str = "any_confident_change",
        limit: int = 40,
        serial: str | None = None,
    ) -> dict[str, Any]:
        previous_signature = str(previous_semantic_signature or "").strip().casefold()
        if not re.fullmatch(r"[0-9a-f]{24}", previous_signature):
            raise PhoneBridgeError("previous_semantic_signature must be a 24-character hexadecimal token.")
        try:
            policy = normalize_verification_policy(verification_policy)
        except VerificationContractError as exc:
            raise PhoneBridgeError(str(exc)) from exc

        context = self.screen_context(serial=serial, limit=limit)
        reported_app = self.current_app(context["serial"])
        visible_packages = [str(item) for item in context.get("packages", []) if str(item)]
        visible_package = visible_packages[0] if len(visible_packages) == 1 else ""
        reported_package = str(reported_app.get("package_name") or "")
        reported_activity = str(reported_app.get("activity") or "")
        if visible_package:
            current_package = visible_package
            current_activity = reported_activity if visible_package == reported_package else ""
            current_identity_source = (
                "uia_and_dumpsys_agree"
                if visible_package == reported_package
                else "uia_visible_package_override"
            )
        else:
            current_package = reported_package
            current_activity = reported_activity
            current_identity_source = "dumpsys_fallback"
        semantic_changed = previous_signature != str(context["semantic_signature"]).casefold()

        previous_package = str(previous_package_name or "").strip()
        previous_activity_value = str(previous_activity or "").strip()
        surface_identity_checked = bool(previous_package or previous_activity_value)
        surface_identity_changed = False
        if surface_identity_checked:
            surface_identity_changed = bool(
                (previous_package and previous_package != current_package)
                or (previous_activity_value and previous_activity_value != current_activity)
            )

        current_visual_dhash: str | None = None
        visual_hamming_distance: int | None = None
        visual_changed = False
        visual_change_confident = False
        if previous_visual_dhash is not None:
            current_visual_dhash = self.screen_visual_hash(context["serial"])
            visual_hamming_distance = self._hex_hamming_distance(
                str(previous_visual_dhash),
                current_visual_dhash,
            )
            visual_changed = visual_hamming_distance > 0
            visual_change_confident = visual_hamming_distance >= VISUAL_VERIFY_HAMMING_THRESHOLD

        signals = {
            "state_change_detected": bool(
                semantic_changed or surface_identity_changed or visual_change_confident
            ),
            "semantic_changed": semantic_changed,
            "surface_identity_changed": surface_identity_changed,
            "visual_change_confident": visual_change_confident,
        }
        policy_result = evaluate_verification_policy(signals, policy)
        contract_result = combine_verification_result(policy_result)

        return {
            "status": "ok",
            "action": "verify_android_state_change",
            "verification_policy": policy,
            "verification_passed": bool(contract_result["verification_passed"]),
            "policy": policy_result,
            "verification_contract": contract_result,
            "state_change_detected": bool(signals["state_change_detected"]),
            "semantic_changed": semantic_changed,
            "surface_identity_checked": surface_identity_checked,
            "surface_identity_changed": surface_identity_changed,
            "visual_changed": visual_changed,
            "visual_change_confident": visual_change_confident,
            "visual_hamming_distance": visual_hamming_distance,
            "visual_hamming_threshold": VISUAL_VERIFY_HAMMING_THRESHOLD,
            "previous": {
                "semantic_signature": previous_signature,
                "visual_dhash": str(previous_visual_dhash or "").strip().casefold() or None,
                "package_name": previous_package or None,
                "activity": previous_activity_value or None,
            },
            "current": {
                "semantic_signature": context["semantic_signature"],
                "visual_dhash": current_visual_dhash,
                "package_name": current_package,
                "activity": current_activity,
                "identity_source": current_identity_source,
                "reported_package_name": reported_package,
                "reported_activity": reported_activity,
                "serial": context["serial"],
            },
        }
