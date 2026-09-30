from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.server.mcpserver.utilities.types import Image
from mcp.types import ToolAnnotations

import companion_owned
from device_contract_adapter import PHONE_BRIDGE_VERSION, phone_contract_surfaces
from local_vision import LocalVisionAdapter, LocalVisionConfig, local_vision_status
from phone_bridge import AndroidBridge, PhoneBridgeError
from reflex_mcp import ReflexMCPServer
from reflex_tap import TOOL_NAME, contract_manifest
import reflex_mcp
from reflex_status import STATUS_TOOL_NAME, read_status
from passive_health import get_health


SERVER_STARTED_AT = datetime.now(timezone.utc).isoformat(timespec="seconds")


server = ReflexMCPServer(
    name="Yunkai Phone Bridge",
    title="Yunkai Phone Bridge",
    description="Safely view and interact with an authorized Android device over ADB.",
    instructions=(
        "Use read-only tools first to understand the phone state. "
        "Only perform tap/swipe/type/key/app-open actions when the user asks for them. "
        "No delete, uninstall, clear-data, root, or arbitrary shell tools are exposed."
    ),
    version=PHONE_BRIDGE_VERSION,
)


server.custom_route("/health", methods=["GET"], name="phonebridge_health", include_in_schema=False)(get_health)


def _bridge() -> AndroidBridge:
    return AndroidBridge(os.environ.get("ADB_PATH"))


def _err(exc: Exception) -> dict[str, Any]:
    result: dict[str, Any] = {"ok": False, "error": str(exc)}
    if isinstance(exc, PhoneBridgeError):
        if exc.reason_code:
            result["reason_code"] = exc.reason_code
        if exc.diagnostics:
            result["diagnostics"] = exc.diagnostics
    return result


def _project_root() -> Path:
    return Path(__file__).resolve().parent


def _control_center_request(path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Call the localhost-only PhoneBridge Control Center without exposing it publicly."""
    base_url = os.environ.get("PHONEBRIDGE_CONTROL_URL", "http://127.0.0.1:8792").rstrip("/")
    if not (
        base_url.startswith("http://127.0.0.1:")
        or base_url.startswith("http://localhost:")
        or base_url.startswith("http://[::1]:")
    ):
        raise RuntimeError("PHONEBRIDGE_CONTROL_URL must point to localhost.")
    body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        base_url + path,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="GET" if payload is None else "POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:600]
        raise RuntimeError(f"Control Center HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "PhoneBridge Control Center is not reachable. Start Start-PhoneBridge-ControlCenter.cmd first. "
            f"Details: {exc}"
        ) from exc
    if not isinstance(result, dict):
        raise RuntimeError("Control Center returned an invalid response.")
    return result


READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
ACTION = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False)


@server.tool(name=STATUS_TOOL_NAME, annotations=READ_ONLY)
def get_android_reflex_status() -> dict[str, Any]:
    """Read passive Reflex contract and local policy summary; no device or backend probe.

    Epoch is executor-instance metadata only, not device identity or a tap precondition.
    Backend-bound means a reviewed atomic Reflex backend; the existing non-atomic
    wrapper does not qualify. Policy evidence grants no permission or live readiness.
    """
    return read_status(reflex_mcp.executor.runtime_epoch)


@server.tool(name=TOOL_NAME, annotations=ACTION, meta={"reflex_contract": contract_manifest()})
def tap_android_ui_element_reflex_verified(request: Any) -> dict[str, Any]:
    """Default-deny semantic tap: one text/content_desc/resource_id selector and explicit post.

    No coordinates, index, arbitrary text, serial, runtime profile or permission
    enablement accepted. Require foreground package, fresh context and owner-local
    binding permission. Reuse the existing verified primitive exactly once, then
    verify the explicit predicate independently. Native atomicity is not claimed;
    no transport recovery or permission grant is performed by this tool.
    """
    return reflex_mcp.executor.tap(request)


@server.tool(name=companion_owned.STATUS_TOOL_NAME, annotations=READ_ONLY)
def get_phonebridge_companion_owned_click_status() -> dict[str, Any]:
    """Read default-off scoped configuration; no Companion or device probe."""
    return companion_owned.status()


@server.tool(name=companion_owned.TOOL_NAME, annotations=ACTION)
async def phonebridge_companion_owned_click_scoped(request: Any) -> dict[str, Any]:
    """Request only Companion's fixed debug-owned fixture, once per request ID."""
    return await reflex_mcp.companion_executor.execute(request)


@server.tool(name="get_phonebridge_runtime_info", annotations=READ_ONLY)
def get_phonebridge_runtime_info() -> dict[str, Any]:
    """Return runtime identity so callers can detect stale PhoneBridge processes after upgrades."""
    return {
        "ok": True,
        "name": "Yunkai Phone Bridge",
        "version": PHONE_BRIDGE_VERSION,
        "pid": os.getpid(),
        "started_at_utc": SERVER_STARTED_AT,
        "server_file": str(Path(__file__).resolve()),
        "python_executable": os.sys.executable,
    }


@server.tool(name="list_android_devices", annotations=READ_ONLY)
def list_android_devices() -> dict[str, Any]:
    """List Android devices visible to ADB and their authorization states."""
    try:
        return {"ok": True, "devices": [device.as_dict() for device in _bridge().devices()]}
    except Exception as exc:
        return _err(exc)


@server.tool(name="get_android_wireless_status", annotations=READ_ONLY)
def get_android_wireless_status() -> dict[str, Any]:
    """Inspect USB/wireless ADB transports and local mDNS pairing/connect services without changing device state."""
    try:
        return {"ok": True, **_bridge().wireless_status()}
    except Exception as exc:
        return _err(exc)


@server.tool(name="pair_android_wireless", annotations=ACTION)
def pair_android_wireless(
    endpoint: str,
    pairing_code: str,
    auto_connect: bool = True,
) -> dict[str, Any]:
    """Pair this workstation to one private/local Wireless ADB endpoint using a six-digit one-time code."""
    try:
        return {
            "ok": True,
            **_bridge().pair_wireless(
                endpoint,
                pairing_code,
                auto_connect=auto_connect,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="connect_android_wireless", annotations=ACTION)
def connect_android_wireless(endpoint: str) -> dict[str, Any]:
    """Connect ADB to one already-paired private/local Wireless ADB endpoint."""
    try:
        return {"ok": True, **_bridge().connect_wireless(endpoint)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="refresh_android_wireless_connection", annotations=ACTION)
def refresh_android_wireless_connection() -> dict[str, Any]:
    """Run one bounded transport recovery: prefer one local mDNS service, else one known offline endpoint."""
    try:
        return {"ok": True, **_bridge().refresh_wireless_connection()}
    except Exception as exc:
        return _err(exc)


@server.tool(name="disconnect_android_wireless", annotations=ACTION)
def disconnect_android_wireless(endpoint: str) -> dict[str, Any]:
    """Disconnect one private/local Wireless ADB endpoint without revoking its pairing authorization."""
    try:
        return {"ok": True, **_bridge().disconnect_wireless(endpoint)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="get_android_device_state", annotations=READ_ONLY)
def get_android_device_state(serial: str | None = None) -> dict[str, Any]:
    """Return a stable device/session guard snapshot including lock, orientation, and visible surface."""
    try:
        return {"ok": True, **_bridge().device_state_snapshot(serial)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="get_android_screen_size", annotations=READ_ONLY)
def get_android_screen_size(serial: str | None = None) -> dict[str, Any]:
    """Return the active Android display size in pixels."""
    try:
        width, height = _bridge().screen_size(serial)
        return {"ok": True, "serial": _bridge().select_device(serial), "width": width, "height": height}
    except Exception as exc:
        return _err(exc)


@server.tool(name="get_android_screenshot", annotations=READ_ONLY, structured_output=False)
def get_android_screenshot(serial: str | None = None) -> Image | dict[str, Any]:
    """Capture the current Android screen as a PNG image."""
    try:
        return Image(data=_bridge().screenshot_png(serial), format="png")
    except Exception as exc:
        return _err(exc)


@server.tool(name="read_android_ui", annotations=READ_ONLY, structured_output=False)
def read_android_ui(serial: str | None = None) -> str:
    """Return the current Android accessibility/UIAutomator hierarchy as XML."""
    try:
        return _bridge().ui_xml(serial)
    except Exception as exc:
        return f"ERROR: {exc}"


@server.tool(name="get_local_vision_status", annotations=READ_ONLY)
def get_local_vision_status() -> dict[str, Any]:
    """Return whether the optional localhost-only Ollama/LM Studio vision adapter is configured."""
    return {"ok": True, **local_vision_status(_project_root())}


@server.tool(name="get_android_fast_context", annotations=READ_ONLY)
def get_android_fast_context(
    force_vision: bool = False,
    include_visual_hash: bool = False,
    limit: int = 40,
    serial: str | None = None,
) -> dict[str, Any]:
    """Return compact Android UI context and invoke the local VLM only when useful or explicitly forced."""
    try:
        bridge = _bridge()
        context = bridge.screen_context(serial=serial, limit=limit)
        current_app = bridge.current_app(context["serial"])
        visible_packages = [str(item) for item in context.get("packages", []) if str(item)]
        visible_package = visible_packages[0] if len(visible_packages) == 1 else ""
        reported_package = current_app.get("package_name", "")
        reported_activity = current_app.get("activity", "")
        if visible_package and reported_package and visible_package != reported_package:
            context["surface_identity"] = {
                "package_name": visible_package,
                "activity": "",
                "source": "uia_visible_package_override",
            }
            context["reported_app_identity"] = {
                "package_name": reported_package,
                "activity": reported_activity,
            }
        else:
            context["surface_identity"] = {
                "package_name": reported_package or visible_package,
                "activity": reported_activity if reported_package else "",
                "source": "dumpsys_window" if reported_package else "uia_visible_package_fallback",
            }
        if include_visual_hash:
            context["visual_dhash"] = bridge.screen_visual_hash(context["serial"])
        should_use_vision = bool(force_vision or context.get("vision_recommended"))
        status = local_vision_status(_project_root())
        context.update(
            phone_contract_surfaces(
                vision_recommended=bool(context.get("vision_recommended")),
                local_vision_status=status,
            )
        )
        vision: dict[str, Any] = {
            "used": False,
            "recommended": bool(context.get("vision_recommended")),
            "configured": bool(status.get("enabled")),
        }
        if should_use_vision and status.get("enabled"):
            config = LocalVisionConfig.load(_project_root())
            assert config is not None
            width, height = context["input_size"]
            result = LocalVisionAdapter(config).analyze_png(
                bridge.screenshot_png(context["serial"]),
                width=int(width),
                height=int(height),
                ui_hint={
                    "packages": context.get("packages", []),
                    "elements": context.get("elements", []),
                    "visible_text": [
                        item.get("text") or item.get("content_desc")
                        for item in context.get("elements", [])
                        if item.get("text") or item.get("content_desc")
                    ],
                },
            )
            vision = {"used": True, "recommended": bool(context.get("vision_recommended")), **result}
        elif should_use_vision and status.get("error"):
            vision["error"] = status["error"]
        elif should_use_vision and not status.get("enabled"):
            vision["reason"] = "Local vision is recommended for this screen but is not configured."

        return {"ok": True, "context": context, "vision": vision}
    except Exception as exc:
        return _err(exc)


@server.tool(name="verify_android_state_change", annotations=READ_ONLY)
def verify_android_state_change(
    previous_semantic_signature: str,
    previous_visual_dhash: str | None = None,
    previous_package_name: str | None = None,
    previous_activity: str | None = None,
    verification_policy: str = "any_confident_change",
    limit: int = 40,
    serial: str | None = None,
) -> dict[str, Any]:
    """Compare current Android semantic/surface/optional visual state using the shared Yunkai verification contract."""
    try:
        return {
            "ok": True,
            **_bridge().verify_state_change(
                previous_semantic_signature,
                previous_visual_dhash=previous_visual_dhash,
                previous_package_name=previous_package_name,
                previous_activity=previous_activity,
                verification_policy=verification_policy,
                limit=limit,
                serial=serial,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="get_android_screen_context", annotations=READ_ONLY)
def get_android_screen_context(
    limit: int = 40,
    serial: str | None = None,
) -> dict[str, Any]:
    """Return a compact accessibility/UI snapshot and whether screenshot vision is recommended."""
    try:
        return {"ok": True, **_bridge().screen_context(serial=serial, limit=limit)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="find_android_ui_elements", annotations=READ_ONLY)
def find_android_ui_elements(
    text: str | None = None,
    content_desc: str | None = None,
    resource_id: str | None = None,
    exact: bool = True,
    case_sensitive: bool = False,
    limit: int = 20,
    serial: str | None = None,
) -> dict[str, Any]:
    """Find Android UI elements by visible text, accessibility description, or resource-id without touching the phone."""
    try:
        return {
            "ok": True,
            **_bridge().ui_elements(
                text=text,
                content_desc=content_desc,
                resource_id=resource_id,
                exact=exact,
                case_sensitive=case_sensitive,
                limit=limit,
                serial=serial,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="get_current_android_app", annotations=READ_ONLY)
def get_current_android_app(serial: str | None = None) -> dict[str, Any]:
    """Return the package/activity currently focused on the Android device."""
    try:
        result = _bridge().current_app(serial)
        return {"ok": True, **result}
    except Exception as exc:
        return _err(exc)


@server.tool(name="tap_android", annotations=ACTION)
def tap_android(x: int, y: int, serial: str | None = None) -> dict[str, Any]:
    """Tap one on-screen coordinate."""
    try:
        return {"ok": True, **_bridge().tap(x, y, serial)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="tap_android_ui_element", annotations=ACTION)
def tap_android_ui_element(
    text: str | None = None,
    content_desc: str | None = None,
    resource_id: str | None = None,
    exact: bool = True,
    case_sensitive: bool = False,
    index: int | None = None,
    serial: str | None = None,
) -> dict[str, Any]:
    """Find an Android UI element and tap its mapped center; ambiguous matches are rejected unless index is explicit."""
    try:
        return {
            "ok": True,
            **_bridge().tap_ui_element(
                text=text,
                content_desc=content_desc,
                resource_id=resource_id,
                exact=exact,
                case_sensitive=case_sensitive,
                index=index,
                serial=serial,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="tap_android_ui_element_verified", annotations=ACTION)
def tap_android_ui_element_verified(
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
    """Resolve one Android UI element, tap it once, then verify without automatic retry."""
    try:
        return {
            "ok": True,
            **_bridge().tap_ui_element_verified(
                text=text,
                content_desc=content_desc,
                resource_id=resource_id,
                exact=exact,
                case_sensitive=case_sensitive,
                index=index,
                expected_package_name=expected_package_name,
                observation_attempts=observation_attempts,
                observation_delay_ms=observation_delay_ms,
                serial=serial,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="wait_for_android_ui_element", annotations=READ_ONLY)
def wait_for_android_ui_element(
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
    """Wait for one bounded UIAutomator element presence/absence condition without touching the phone."""
    try:
        return {
            "ok": True,
            **_bridge().wait_for_ui_element(
                text=text,
                content_desc=content_desc,
                resource_id=resource_id,
                exact=exact,
                case_sensitive=case_sensitive,
                expected_present=expected_present,
                observation_attempts=observation_attempts,
                observation_delay_ms=observation_delay_ms,
                limit=limit,
                serial=serial,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="long_press_android", annotations=ACTION)
def long_press_android(
    x: int,
    y: int,
    duration_ms: int = 700,
    serial: str | None = None,
) -> dict[str, Any]:
    """Long-press one on-screen coordinate for 300-5000 ms."""
    try:
        return {"ok": True, **_bridge().long_press(x, y, duration_ms, serial)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="long_press_android_verified", annotations=ACTION)
def long_press_android_verified(
    x: int,
    y: int,
    duration_ms: int = 700,
    expected_package_name: str | None = None,
    verification_policy: str = "any_confident_change",
    observation_attempts: int = 3,
    observation_delay_ms: int = 250,
    limit: int = 40,
    serial: str | None = None,
) -> dict[str, Any]:
    """Long-press once, then perform bounded verification without automatic retry."""
    try:
        return {
            "ok": True,
            **_bridge().long_press_verified(
                x,
                y,
                duration_ms=duration_ms,
                expected_package_name=expected_package_name,
                verification_policy=verification_policy,
                observation_attempts=observation_attempts,
                observation_delay_ms=observation_delay_ms,
                limit=limit,
                serial=serial,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="swipe_android", annotations=ACTION)
def swipe_android(
    start_x: int,
    start_y: int,
    end_x: int,
    end_y: int,
    duration_ms: int = 400,
    serial: str | None = None,
) -> dict[str, Any]:
    """Swipe between two screen coordinates."""
    try:
        return {
            "ok": True,
            **_bridge().swipe(start_x, start_y, end_x, end_y, duration_ms, serial),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="swipe_android_direction", annotations=ACTION)
def swipe_android_direction(
    direction: str,
    distance_ratio: float = 0.35,
    duration_ms: int = 400,
    serial: str | None = None,
) -> dict[str, Any]:
    """Swipe from screen center in one cardinal direction without using raw coordinates."""
    try:
        return {
            "ok": True,
            **_bridge().swipe_direction(
                direction,
                distance_ratio=distance_ratio,
                duration_ms=duration_ms,
                serial=serial,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="tap_android_verified", annotations=ACTION)
def tap_android_verified(
    x: int,
    y: int,
    expected_package_name: str | None = None,
    verification_policy: str = "any_confident_change",
    observation_attempts: int = 3,
    observation_delay_ms: int = 250,
    limit: int = 40,
    serial: str | None = None,
) -> dict[str, Any]:
    """Tap once, then perform bounded read-only verification without automatic action retry."""
    try:
        return {
            "ok": True,
            **_bridge().tap_verified(
                x,
                y,
                expected_package_name=expected_package_name,
                verification_policy=verification_policy,
                observation_attempts=observation_attempts,
                observation_delay_ms=observation_delay_ms,
                limit=limit,
                serial=serial,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="swipe_android_verified", annotations=ACTION)
def swipe_android_verified(
    start_x: int,
    start_y: int,
    end_x: int,
    end_y: int,
    duration_ms: int = 400,
    expected_package_name: str | None = None,
    verification_policy: str = "any_confident_change",
    observation_attempts: int = 3,
    observation_delay_ms: int = 250,
    limit: int = 40,
    serial: str | None = None,
) -> dict[str, Any]:
    """Swipe once, then perform bounded read-only verification without automatic action retry."""
    try:
        return {
            "ok": True,
            **_bridge().swipe_verified(
                start_x,
                start_y,
                end_x,
                end_y,
                duration_ms=duration_ms,
                expected_package_name=expected_package_name,
                verification_policy=verification_policy,
                observation_attempts=observation_attempts,
                observation_delay_ms=observation_delay_ms,
                limit=limit,
                serial=serial,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="swipe_android_direction_verified", annotations=ACTION)
def swipe_android_direction_verified(
    direction: str,
    distance_ratio: float = 0.35,
    duration_ms: int = 400,
    expected_package_name: str | None = None,
    verification_policy: str = "any_confident_change",
    observation_attempts: int = 3,
    observation_delay_ms: int = 250,
    limit: int = 40,
    serial: str | None = None,
) -> dict[str, Any]:
    """Perform one safe directional swipe, then verify without automatic retry."""
    try:
        return {
            "ok": True,
            **_bridge().swipe_direction_verified(
                direction,
                distance_ratio=distance_ratio,
                duration_ms=duration_ms,
                expected_package_name=expected_package_name,
                verification_policy=verification_policy,
                observation_attempts=observation_attempts,
                observation_delay_ms=observation_delay_ms,
                limit=limit,
                serial=serial,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="game_joystick_move", annotations=ACTION)
def game_joystick_move(
    direction: str,
    duration_ms: int,
    expected_package_name: str,
    center_x: int | None = None,
    center_y: int | None = None,
    radius_px: int | None = None,
    observation_attempts: int = 2,
    observation_delay_ms: int = 200,
    limit: int = 20,
    serial: str | None = None,
) -> dict[str, Any]:
    """Perform one bounded joystick-style hold using ADB input swipe, guarded to the expected foreground package."""
    try:
        return {
            "ok": True,
            **_bridge().game_joystick_move(
                direction,
                duration_ms,
                expected_package_name=expected_package_name,
                center_x=center_x,
                center_y=center_y,
                radius_px=radius_px,
                observation_attempts=observation_attempts,
                observation_delay_ms=observation_delay_ms,
                limit=limit,
                serial=serial,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="game_camera_drag", annotations=ACTION)
def game_camera_drag(
    direction: str,
    distance_px: int,
    expected_package_name: str,
    duration_ms: int = 350,
    start_x: int | None = None,
    start_y: int | None = None,
    observation_attempts: int = 2,
    observation_delay_ms: int = 180,
    limit: int = 20,
    serial: str | None = None,
) -> dict[str, Any]:
    """Perform one bounded game-camera drag from a safe landscape region and verify it without retrying."""
    try:
        return {
            "ok": True,
            **_bridge().game_camera_drag(
                direction,
                distance_px,
                expected_package_name=expected_package_name,
                duration_ms=duration_ms,
                start_x=start_x,
                start_y=start_y,
                observation_attempts=observation_attempts,
                observation_delay_ms=observation_delay_ms,
                limit=limit,
                serial=serial,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="type_android_text", annotations=ACTION)
def type_android_text(text: str, serial: str | None = None) -> dict[str, Any]:
    """Type short ASCII text into the currently focused Android input field."""
    try:
        return {"ok": True, **_bridge().type_text(text, serial)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="type_android_text_verified", annotations=ACTION)
def type_android_text_verified(
    text: str,
    expected_package_name: str | None = None,
    verification_policy: str = "any_confident_change",
    observation_attempts: int = 3,
    observation_delay_ms: int = 250,
    limit: int = 40,
    serial: str | None = None,
) -> dict[str, Any]:
    """Type once into the focused field, then verify bounded state change without retrying input."""
    try:
        return {
            "ok": True,
            **_bridge().type_text_verified(
                text,
                expected_package_name=expected_package_name,
                verification_policy=verification_policy,
                observation_attempts=observation_attempts,
                observation_delay_ms=observation_delay_ms,
                limit=limit,
                serial=serial,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="press_android_key", annotations=ACTION)
def press_android_key(key: str, serial: str | None = None) -> dict[str, Any]:
    """Press a safe Android key: HOME, BACK, ENTER, TAB, DPAD directions, ESCAPE, or volume."""
    try:
        return {"ok": True, **_bridge().keyevent(key, serial)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="press_android_key_verified", annotations=ACTION)
def press_android_key_verified(
    key: str,
    expected_package_name: str | None = None,
    expected_post_package_name: str | None = None,
    verification_policy: str = "any_confident_change",
    observation_attempts: int = 3,
    observation_delay_ms: int = 250,
    limit: int = 40,
    serial: str | None = None,
) -> dict[str, Any]:
    """Press one allowlisted Android key once, then verify bounded post-action state."""
    try:
        return {
            "ok": True,
            **_bridge().keyevent_verified(
                key,
                expected_package_name=expected_package_name,
                expected_post_package_name=expected_post_package_name,
                verification_policy=verification_policy,
                observation_attempts=observation_attempts,
                observation_delay_ms=observation_delay_ms,
                limit=limit,
                serial=serial,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="open_android_app", annotations=ACTION)
def open_android_app(package_name: str, serial: str | None = None) -> dict[str, Any]:
    """Launch an installed Android app by package name, without installing or removing anything."""
    try:
        return {"ok": True, **_bridge().open_app(package_name, serial)}
    except Exception as exc:
        return _err(exc)


@server.tool(name="open_android_app_verified", annotations=ACTION)
def open_android_app_verified(
    package_name: str,
    observation_attempts: int = 4,
    observation_delay_ms: int = 250,
    serial: str | None = None,
) -> dict[str, Any]:
    """Launch an app once and wait for stable visible-surface ownership without retrying launch."""
    try:
        return {
            "ok": True,
            **_bridge().open_app_verified(
                package_name,
                observation_attempts=observation_attempts,
                observation_delay_ms=observation_delay_ms,
                serial=serial,
            ),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="get_phone_automation_status", annotations=READ_ONLY)
def get_phone_automation_status() -> dict[str, Any]:
    """Read the localhost Control Center state and saved daily routines without exposing the DeepSeek API key."""
    try:
        result = _control_center_request("/api/status")
        return {
            "ok": True,
            "config": result.get("config", {}),
            "run": result.get("run", {}),
            "routines": result.get("routines", []),
            "vision": result.get("vision", {}),
        }
    except Exception as exc:
        return _err(exc)


@server.tool(name="save_phone_daily_routine", annotations=ACTION)
def save_phone_daily_routine(
    name: str,
    time: str,
    prompt: str,
    days: list[int] | None = None,
    max_actions: int = 24,
    enabled: bool = True,
    routine_id: str | None = None,
) -> dict[str, Any]:
    """Create or update a local daily phone routine for the Control Center scheduler."""
    try:
        payload: dict[str, Any] = {
            "name": name,
            "time": time,
            "prompt": prompt,
            "days": days if days is not None else list(range(7)),
            "max_actions": max_actions,
            "enabled": enabled,
        }
        if routine_id:
            payload["id"] = routine_id
        return _control_center_request("/api/routines/upsert", payload)
    except Exception as exc:
        return _err(exc)


@server.tool(name="run_phone_daily_routine", annotations=ACTION)
def run_phone_daily_routine(routine_id: str) -> dict[str, Any]:
    """Run one saved phone routine immediately through the local Control Center."""
    try:
        return _control_center_request("/api/routines/run", {"id": routine_id})
    except Exception as exc:
        return _err(exc)


@server.tool(name="stop_phone_automation", annotations=ACTION)
def stop_phone_automation() -> dict[str, Any]:
    """Request that the local Control Center stop before its next autonomous Android action."""
    try:
        return _control_center_request("/api/agent/stop", {})
    except Exception as exc:
        return _err(exc)


if __name__ == "__main__":
    host = os.environ.get("PHONEBRIDGE_HOST", "127.0.0.1")
    port = int(os.environ.get("PHONEBRIDGE_PORT", "8790"))
    server.run(
        transport="streamable-http",
        host=host,
        port=port,
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
    )
