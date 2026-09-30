from __future__ import annotations

import unittest
from datetime import datetime

from control_center import (
    ALLOWED_ACTIONS,
    ControlState,
    contains_blocked_term,
    deepseek_endpoint,
    extract_json_object,
    normalize_config,
    observation_surface_package,
    routine_due,
)


class FakeActionBridge:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def game_joystick_move(self, direction, duration_ms, **kwargs):
        self.calls.append(("game_joystick_move", {"direction": direction, "duration_ms": duration_ms, **kwargs}))
        return {"status": "ok", "action": "game_joystick_move", "execution_status": "EXECUTED_VERIFIED"}

    def game_camera_drag(self, direction, distance_px, **kwargs):
        self.calls.append(("game_camera_drag", {"direction": direction, "distance_px": distance_px, **kwargs}))
        return {"status": "ok", "action": "game_camera_drag", "execution_status": "EXECUTED_VERIFIED"}

    def swipe_verified(self, start_x, start_y, end_x, end_y, **kwargs):
        self.calls.append(("swipe_verified", {"start_x": start_x, "start_y": start_y, "end_x": end_x, "end_y": end_y, **kwargs}))
        return {"status": "ok", "action": "swipe_verified", "execution_status": "EXECUTED_UNVERIFIED"}

    def open_app_verified(self, package_name, **kwargs):
        self.calls.append(("open_app_verified", {"package_name": package_name, **kwargs}))
        return {"status": "ok", "action": "open_app_verified", "verification_passed": True}


class ControlCenterTests(unittest.TestCase):
    def test_deepseek_endpoint(self) -> None:
        self.assertEqual(
            deepseek_endpoint("https://api.deepseek.com/"),
            "https://api.deepseek.com/chat/completions",
        )
        self.assertEqual(
            deepseek_endpoint("https://example.test/chat/completions"),
            "https://example.test/chat/completions",
        )

    def test_extract_json_object_accepts_fenced_json(self) -> None:
        value = extract_json_object(
            '```json\n{"reason":"ok","action":{"type":"wait","seconds":1}}\n```'
        )
        self.assertEqual(value["action"]["type"], "wait")

    def test_extract_json_object_finds_embedded_object(self) -> None:
        value = extract_json_object('prefix {"reason":"ok","action":{"type":"finish"}} suffix')
        self.assertEqual(value["action"]["type"], "finish")

    def test_blocked_target_terms(self) -> None:
        self.assertEqual(contains_blocked_term("前往充值"), "充值")
        self.assertIsNotNone(contains_blocked_term("purchase now"))
        self.assertIsNone(contains_blocked_term("查看圣杯"))

    def test_visible_package_wins_over_transient_current_app(self) -> None:
        observation = {
            "context": {"packages": ["com.example.game"]},
            "current_app": {"package_name": "com.android.launcher3"},
        }
        self.assertEqual(observation_surface_package(observation), "com.example.game")

    def test_control_center_routes_game_navigation_to_guarded_game_tools(self) -> None:
        self.assertIn("joystick", ALLOWED_ACTIONS)
        self.assertIn("camera_drag", ALLOWED_ACTIONS)
        state = ControlState.__new__(ControlState)
        state.bridge = FakeActionBridge()
        observation = {
            "context": {
                "serial": "ABC123",
                "input_size": [2400, 1080],
                "orientation": "landscape",
                "packages": ["com.example.game"],
                "vision_recommended": True,
            },
            "current_app": {"package_name": "com.android.launcher3"},
            "vision": {"screen_type": "game"},
        }
        result = state._verify_and_execute(
            {"type": "joystick", "direction": "up_right", "duration_ms": 650, "target": "quest marker"},
            observation,
        )
        self.assertEqual(result["action"], "game_joystick_move")
        call_name, kwargs = state.bridge.calls[-1]
        self.assertEqual(call_name, "game_joystick_move")
        self.assertEqual(kwargs["expected_package_name"], "com.example.game")
        self.assertEqual(kwargs["direction"], "up_right")

        with self.assertRaisesRegex(ValueError, "Raw swipe is disabled"):
            state._verify_and_execute(
                {"type": "swipe", "start_x": 100, "start_y": 100, "end_x": 200, "end_y": 200},
                observation,
            )

    def test_control_center_uses_verified_swipe_and_app_launch(self) -> None:
        state = ControlState.__new__(ControlState)
        state.bridge = FakeActionBridge()
        observation = {
            "context": {
                "serial": "ABC123",
                "input_size": [1080, 2400],
                "orientation": "portrait",
                "packages": ["com.example.app"],
                "vision_recommended": False,
            },
            "current_app": {"package_name": "com.example.app"},
            "vision": {"screen_type": "app"},
        }
        swipe = state._verify_and_execute(
            {"type": "swipe", "start_x": 500, "start_y": 1600, "end_x": 500, "end_y": 800},
            observation,
        )
        self.assertEqual(swipe["action"], "swipe_verified")
        self.assertEqual(state.bridge.calls[-1][0], "swipe_verified")
        opened = state._verify_and_execute(
            {"type": "open_app", "package_name": "com.other.app", "target": "open app"},
            observation,
        )
        self.assertEqual(opened["action"], "open_app_verified")
        self.assertEqual(state.bridge.calls[-1][0], "open_app_verified")

    def test_normalize_config_clamps_values(self) -> None:
        value = normalize_config(
            {
                "deepseek_base_url": "https://api.deepseek.com/",
                "deepseek_model": "deepseek-chat",
                "max_actions": 999,
                "step_delay_seconds": 0,
            }
        )
        self.assertEqual(value["deepseek_base_url"], "https://api.deepseek.com")
        self.assertEqual(value["max_actions"], 80)
        self.assertEqual(value["step_delay_seconds"], 0.25)

    def test_routine_due_once_per_day(self) -> None:
        now = datetime(2026, 8, 29, 9, 30)  # Saturday / weekday=5
        routine = {
            "enabled": True,
            "time": "09:30",
            "days": [5],
            "last_run": "",
        }
        self.assertTrue(routine_due(routine, now))
        routine["last_run"] = "2026-08-29"
        self.assertFalse(routine_due(routine, now))

    def test_disabled_routine_is_not_due(self) -> None:
        now = datetime(2026, 8, 29, 9, 30)
        self.assertFalse(
            routine_due(
                {"enabled": False, "time": "09:30", "days": [5], "last_run": ""},
                now,
            )
        )


if __name__ == "__main__":
    unittest.main()
