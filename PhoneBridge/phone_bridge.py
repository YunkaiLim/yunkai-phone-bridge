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

[Showing lines 1-1236 of 2566 (50.0KB limit). Use offset=1237 to continue.]