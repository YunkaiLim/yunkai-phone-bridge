from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def main() -> None:
    root = Path(__file__).resolve().parent
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(root / "server_stdio.py")],
        cwd=str(root),
        env=dict(os.environ),
    )

    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [tool.name for tool in tools.tools]
            print("TOOLS", ",".join(names))
            assert "get_android_screenshot" in names
            assert "verify_android_state_change" in names
            assert "tap_android" in names
            assert "tap_android_verified" in names
            assert "swipe_android_verified" in names
            assert "game_joystick_move" in names
            assert "get_android_wireless_status" in names
            assert "refresh_android_wireless_connection" in names
            assert all("delete" not in name.lower() for name in names)
            assert all("uninstall" not in name.lower() for name in names)
            assert all("shell" not in name.lower() for name in names)

            if os.environ.get("PHONEBRIDGE_DISCOVERY_ONLY") == "1" or "--discovery-only" in sys.argv:
                print("DISCOVERY_ONLY no ADB device calls performed")
                return

            devices = await session.call_tool("list_android_devices", {})
            print("DEVICES_CONTENT_ITEMS", len(devices.content))
            device_payload = None
            for item in devices.content:
                if getattr(item, "type", None) != "text":
                    continue
                try:
                    parsed = json.loads(item.text)
                except (TypeError, json.JSONDecodeError):
                    continue
                if isinstance(parsed, dict):
                    device_payload = parsed
                    break
            has_ready_device = bool(
                device_payload
                and device_payload.get("ok")
                and any(device.get("state") == "device" for device in device_payload.get("devices", []))
            )

            if has_ready_device:
                fast_context = await session.call_tool(
                    "get_android_fast_context",
                    {"force_vision": False, "include_visual_hash": False, "limit": 20},
                )
                print("FAST_CONTEXT_CONTENT_ITEMS", len(fast_context.content))
                assert not getattr(fast_context, "isError", False)
                fast_context_text = "\n".join(
                    getattr(item, "text", "")
                    for item in fast_context.content
                    if getattr(item, "type", None) == "text"
                )
                assert "capability_manifest" in fast_context_text
                assert "capability_state" in fast_context_text
                assert "planner_routing_hints" in fast_context_text
                assert "runtime_policy" in fast_context_text
                assert "device_snapshot" in fast_context_text
                assert "yunkai.unified_device_contract" in fast_context_text
                assert "phone.android" in fast_context_text
            else:
                print("FAST_CONTEXT_CHECK_SKIPPED no authorized Android device")

            screenshot = await session.call_tool("get_android_screenshot", {})
            image_items = [item for item in screenshot.content if getattr(item, "type", None) == "image"]
            print("SCREENSHOT_IMAGE_ITEMS", len(image_items))
            if has_ready_device:
                assert image_items, "Expected screenshot content while an authorized Android device is ready"
                assert image_items[0].mime_type == "image/png"
            else:
                print("SCREENSHOT_CHECK_SKIPPED no authorized Android device")


if __name__ == "__main__":
    asyncio.run(main())
