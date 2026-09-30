from __future__ import annotations

import argparse
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from local_vision import LocalVisionAdapter, LocalVisionConfig, local_vision_status
from phone_bridge import AndroidBridge

ROOT = Path(__file__).resolve().parent
UI_FILE = ROOT / "control_center_ui.html"
ROUTINES_FILE = ROOT / "phonebridge_routines.json"
CONFIG_FILE = ROOT / "phonebridge_control_center.json"

DEFAULT_CONFIG: dict[str, Any] = {
    "deepseek_base_url": "https://api.deepseek.com",
    "deepseek_model": "deepseek-chat",
    "max_actions": 24,
    "step_delay_seconds": 1.0,
}

# Autonomous control deliberately keeps a permanent purchase/gacha guard.
# Manual phone use remains unaffected.
BLOCKED_TERMS = {
    "充值",
    "购买",
    "支付",
    "付款",
    "订单",
    "结算",
    "抽卡",
    "跃迁",
    "星琼",
    "古老梦华",
    "创世结晶",
    "原石",
    "月卡",
    "通行证购买",
    "商城",
    "商店购买",
    "buy",
    "purchase",
    "checkout",
    "payment",
    "recharge",
    "top up",
    "gacha",
}

ALLOWED_ACTIONS = {
    "tap_ui",
    "tap",
    "swipe",
    "joystick",
    "camera_drag",
    "press_key",
    "open_app",
    "type_text",
    "wait",
    "finish",
}


def _read_json_file(path: Path, default: Any) -> Any:
    try:
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _write_json_file(path: Path, value: Any) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def load_config() -> dict[str, Any]:
    raw = _read_json_file(CONFIG_FILE, {})
    result = dict(DEFAULT_CONFIG)
    if isinstance(raw, dict):
        for key in DEFAULT_CONFIG:
            if key in raw:
                result[key] = raw[key]
    return normalize_config(result)


def normalize_config(raw: dict[str, Any]) -> dict[str, Any]:
    base = str(raw.get("deepseek_base_url") or DEFAULT_CONFIG["deepseek_base_url"]).strip().rstrip("/")
    model = str(raw.get("deepseek_model") or DEFAULT_CONFIG["deepseek_model"]).strip()
    try:
        max_actions = int(raw.get("max_actions", DEFAULT_CONFIG["max_actions"]))
    except (TypeError, ValueError):
        max_actions = int(DEFAULT_CONFIG["max_actions"])
    try:
        step_delay = float(raw.get("step_delay_seconds", DEFAULT_CONFIG["step_delay_seconds"]))
    except (TypeError, ValueError):
        step_delay = float(DEFAULT_CONFIG["step_delay_seconds"])
    return {
        "deepseek_base_url": base or DEFAULT_CONFIG["deepseek_base_url"],
        "deepseek_model": model or DEFAULT_CONFIG["deepseek_model"],
        "max_actions": max(1, min(80, max_actions)),
        "step_delay_seconds": max(0.25, min(8.0, step_delay)),
    }


def deepseek_endpoint(base_url: str) -> str:
    base = base_url.strip().rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    return base + "/chat/completions"


def extract_json_object(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        value = json.loads(cleaned)
        if isinstance(value, dict):
            return value
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for index, char in enumerate(cleaned):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(cleaned[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise ValueError("DeepSeek response did not contain a JSON object.")


def contains_blocked_term(text: str) -> str | None:
    lowered = text.casefold()
    for term in BLOCKED_TERMS:
        if term.casefold() in lowered:
            return term
    return None


def routine_due(routine: dict[str, Any], now: datetime) -> bool:
    if not routine.get("enabled", True):
        return False
    time_text = str(routine.get("time") or "").strip()
    if not re.fullmatch(r"\d{2}:\d{2}", time_text):
        return False
    try:
        hour, minute = (int(part) for part in time_text.split(":", 1))
    except ValueError:
        return False
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        return False
    days = routine.get("days", list(range(7)))
    if not isinstance(days, list) or now.weekday() not in days:
        return False
    if (now.hour, now.minute) != (hour, minute):
        return False
    return str(routine.get("last_run") or "") != now.strftime("%Y-%m-%d")


def _vision_observation(bridge: AndroidBridge, context: dict[str, Any]) -> dict[str, Any]:
    status = local_vision_status(ROOT)
    result: dict[str, Any] = {
        "used": False,
        "recommended": bool(context.get("vision_recommended")),
        "configured": bool(status.get("enabled")),
    }
    if not context.get("vision_recommended"):
        return result
    if not status.get("enabled"):
        if status.get("error"):
            result["error"] = status["error"]
        else:
            result["reason"] = "Local vision is recommended but is not configured."
        return result

    config = LocalVisionConfig.load(ROOT)
    if config is None:
        result["reason"] = "Local vision config could not be loaded."
        return result
    width, height = context["input_size"]
    vision = LocalVisionAdapter(config).analyze_png(
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
    return {"used": True, "recommended": True, **vision}


def build_observation(bridge: AndroidBridge, serial: str | None = None) -> dict[str, Any]:
    context = bridge.screen_context(serial=serial, limit=50)
    current_app = bridge.current_app(context["serial"])
    vision = _vision_observation(bridge, context)
    return {
        "context": context,
        "current_app": current_app,
        "vision": vision,
    }


def observation_surface_package(observation: dict[str, Any]) -> str:
    """Prefer one visible UI package over transient dumpsys focus for action guards."""
    context = observation.get("context", {})
    packages = [str(item) for item in context.get("packages", []) if str(item)]
    if len(packages) == 1:
        return packages[0]
    current_app = observation.get("current_app", {})
    return str(current_app.get("package_name") or "")


def compact_observation(observation: dict[str, Any]) -> dict[str, Any]:
    context = observation.get("context", {})
    vision = observation.get("vision", {})
    return {
        "serial": context.get("serial"),
        "input_size": context.get("input_size"),
        "orientation": context.get("orientation"),
        "packages": context.get("packages", []),
        "current_app": observation.get("current_app", {}),
        "vision_recommended": context.get("vision_recommended"),
        "ui_elements": context.get("elements", []),
        "vision": {
            "used": vision.get("used", False),
            "summary": vision.get("summary", ""),
            "screen_type": vision.get("screen_type", ""),
            "texts": vision.get("texts", []),
            "candidate_targets": vision.get("candidate_targets", []),
            "actionable_targets": vision.get("actionable_targets", []),
            "warnings": vision.get("warnings", []),
            "error": vision.get("error"),
        },
    }


SYSTEM_PROMPT = """You are the decision controller for Yunkai PhoneBridge.
You receive a user's goal plus a compact Android observation. UIAutomator is authoritative when useful; local vision is already included only when UIAutomator was sparse.

Return exactly ONE JSON object and no markdown. Never provide chain-of-thought. Use only a short reason.
Schema:
{
  "reason": "brief reason, <= 120 chars",
  "action": {
    "type": "tap_ui|tap|swipe|joystick|camera_drag|press_key|open_app|type_text|wait|finish",
    "target": "human-readable target label when relevant",
    "text": "for tap_ui or type_text",
    "x": 0, "y": 0,
    "start_x": 0, "start_y": 0, "end_x": 0, "end_y": 0,
    "duration_ms": 400,
    "direction": "up|down|left|right|up_left|up_right|down_left|down_right",
    "distance_px": 160,
    "key": "BACK",
    "package_name": "com.example.app",
    "seconds": 1,
    "summary": "for finish"
  }
}

Rules:
- Never buy, pay, recharge, subscribe, perform gacha/pulls, or spend premium currency.
- Never delete files, uninstall apps, clear app data, install APKs, root the phone, or use arbitrary shell commands.
- If a transaction/gacha/premium-currency screen is involved, finish and ask the user to take over.
- Prefer tap_ui when a normal Android UI element is available.
- On sparse Unity/canvas screens, use only coordinates grounded in local-vision candidate/actionable targets. Do not invent coordinates.
- For landscape game movement, prefer joystick. For looking around, prefer camera_drag. Do not use raw swipe as a virtual joystick/camera gesture.
- If no reliable target exists, wait once if the screen may be loading; otherwise finish with a concise explanation.
- One action per response. Do not claim an action succeeded before the next observation confirms it.
"""


class DeepSeekClient:
    def __init__(self, api_key: str, base_url: str, model: str):
        self.api_key = api_key
        self.endpoint = deepseek_endpoint(base_url)
        self.model = model

    def decide(
        self,
        goal: str,
        observation: dict[str, Any],
        previous_action: dict[str, Any] | None,
        step_index: int,
    ) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "goal": goal,
                            "step": step_index,
                            "previous_action": previous_action,
                            "observation": compact_observation(observation),
                        },
                        ensure_ascii=False,
                    ),
                },
            ],
        }
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:800]
            raise RuntimeError(f"DeepSeek HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"DeepSeek request failed: {exc}") from exc

        try:
            content = raw["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError("DeepSeek response did not contain choices[0].message.content") from exc
        return extract_json_object(str(content))


@dataclass
class RunState:
    running: bool = False
    source: str = ""
    goal: str = ""
    started_at: str = ""
    step: int = 0
    last_error: str = ""
    last_summary: str = ""


class ControlState:
    def __init__(self):
        self.bridge = AndroidBridge()
        self.config = load_config()
        self.api_key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
        self.logs: deque[dict[str, Any]] = deque(maxlen=300)
        self.log_counter = 0
        self.run_state = RunState()
        self.run_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.runner_thread: threading.Thread | None = None
        raw_routines = _read_json_file(ROUTINES_FILE, [])
        self.routines: list[dict[str, Any]] = raw_routines if isinstance(raw_routines, list) else []
        self.routines_lock = threading.Lock()
        self.scheduler_stop = threading.Event()
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, name="phonebridge-scheduler", daemon=True)
        self.scheduler_thread.start()
        self.log("system", "Control Center ready on localhost.")

    def log(self, level: str, message: str, data: Any | None = None) -> None:
        self.log_counter += 1
        entry: dict[str, Any] = {
            "id": self.log_counter,
            "time": datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "message": message,
        }
        if data is not None:
            entry["data"] = data
        self.logs.append(entry)

    def public_config(self) -> dict[str, Any]:
        return {**self.config, "api_key_set": bool(self.api_key)}

    def update_config(self, payload: dict[str, Any]) -> None:
        candidate = dict(self.config)
        for key in DEFAULT_CONFIG:
            if key in payload:
                candidate[key] = payload[key]
        self.config = normalize_config(candidate)
        _write_json_file(CONFIG_FILE, self.config)
        if "api_key" in payload:
            self.api_key = str(payload.get("api_key") or "").strip()
        self.log("system", f"DeepSeek config updated: {self.config['deepseek_model']}")

    def _routine_copy(self) -> list[dict[str, Any]]:
        with self.routines_lock:
            return json.loads(json.dumps(self.routines, ensure_ascii=False))

    def upsert_routine(self, payload: dict[str, Any]) -> dict[str, Any]:
        routine_id = str(payload.get("id") or uuid.uuid4().hex[:10])
        routine = {
            "id": routine_id,
            "name": str(payload.get("name") or "每日任务").strip()[:80],
            "enabled": bool(payload.get("enabled", True)),
            "time": str(payload.get("time") or "09:00").strip(),
            "days": payload.get("days") if isinstance(payload.get("days"), list) else list(range(7)),
            "prompt": str(payload.get("prompt") or "").strip()[:4000],
            "max_actions": max(1, min(80, int(payload.get("max_actions") or self.config["max_actions"]))),
            "last_run": str(payload.get("last_run") or ""),
        }
        if not routine["prompt"]:
            raise ValueError("Routine prompt must not be empty.")
        with self.routines_lock:
            for index, existing in enumerate(self.routines):
                if existing.get("id") == routine_id:
                    if not payload.get("last_run"):
                        routine["last_run"] = str(existing.get("last_run") or "")
                    self.routines[index] = routine
                    break
            else:
                self.routines.append(routine)
            _write_json_file(ROUTINES_FILE, self.routines)
        self.log("system", f"Saved routine: {routine['name']} at {routine['time']}")
        return routine

    def delete_routine(self, routine_id: str) -> None:
        with self.routines_lock:
            self.routines = [item for item in self.routines if item.get("id") != routine_id]
            _write_json_file(ROUTINES_FILE, self.routines)
        self.log("system", f"Deleted routine: {routine_id}")

    def get_routine(self, routine_id: str) -> dict[str, Any] | None:
        with self.routines_lock:
            for routine in self.routines:
                if routine.get("id") == routine_id:
                    return dict(routine)
        return None

    def mark_routine_run(self, routine_id: str, date_text: str) -> None:
        with self.routines_lock:
            for routine in self.routines:
                if routine.get("id") == routine_id:
                    routine["last_run"] = date_text
                    break
            _write_json_file(ROUTINES_FILE, self.routines)

    def start_agent(self, goal: str, source: str = "manual", max_actions: int | None = None) -> bool:
        goal = goal.strip()
        if not goal:
            raise ValueError("Goal must not be empty.")
        # Do not reject goals merely because they mention protected concepts in a
        # negative rule such as "不要抽卡/不要消耗星琼". The hard guard is applied
        # to the model-selected target/action immediately before execution.
        if not self.api_key:
            raise ValueError("Set the DeepSeek API key first. The key is kept in memory only.")
        with self.run_lock:
            if self.run_state.running:
                return False
            self.stop_event.clear()
            self.run_state = RunState(
                running=True,
                source=source,
                goal=goal,
                started_at=datetime.now().isoformat(timespec="seconds"),
            )
            action_limit = max(1, min(80, int(max_actions or self.config["max_actions"])))
            self.runner_thread = threading.Thread(
                target=self._agent_loop,
                args=(goal, source, action_limit),
                name="phonebridge-agent",
                daemon=True,
            )
            self.runner_thread.start()
        return True

    def stop_agent(self) -> None:
        self.stop_event.set()
        self.log("warning", "Stop requested; the agent will stop before the next action.")

    def _verify_and_execute(self, action: dict[str, Any], observation: dict[str, Any]) -> dict[str, Any]:
        action_type = str(action.get("type") or "").strip()
        if action_type not in ALLOWED_ACTIONS:
            raise ValueError(f"Unsupported autonomous action: {action_type}")

        target_label = str(action.get("target") or action.get("text") or "")
        blocked = contains_blocked_term(target_label)
        if blocked and action_type not in {"finish", "wait"}:
            raise ValueError(f"Purchase/gacha guard blocked target: {blocked}")

        context = observation.get("context", {})
        serial = context.get("serial")
        width, height = context.get("input_size", [0, 0])
        expected_package = observation_surface_package(observation) or None
        vision = observation.get("vision", {})
        is_game_surface = str(vision.get("screen_type") or "").casefold() == "game"

        if action_type == "finish":
            return {"status": "finished", "summary": str(action.get("summary") or "Done")}
        if action_type == "wait":
            seconds = max(0.25, min(10.0, float(action.get("seconds") or 1.0)))
            time.sleep(seconds)
            return {"status": "ok", "action": "wait", "seconds": seconds}
        if action_type == "tap_ui":
            text = str(action.get("text") or target_label).strip()
            if not text:
                raise ValueError("tap_ui requires text.")
            return self.bridge.tap_ui_element_verified(
                text=text,
                exact=False,
                expected_package_name=expected_package,
                serial=serial,
            )
        if action_type == "tap":
            if not target_label:
                raise ValueError("Coordinate taps require a target label for safety verification.")
            x, y = int(action.get("x")), int(action.get("y"))
            if not (0 <= x < int(width) and 0 <= y < int(height)):
                raise ValueError("Tap coordinates are outside the current Android screen.")

            # On sparse game/canvas screens, DeepSeek only gets text/structured targets,
            # not the raw screenshot. Require the coordinate to be grounded in local vision.
            if context.get("vision_recommended"):
                targets = list(vision.get("actionable_targets") or vision.get("candidate_targets") or [])
                normalized = target_label.casefold()
                matching = [
                    item
                    for item in targets
                    if normalized in str(item.get("label") or "").casefold()
                    or str(item.get("label") or "").casefold() in normalized
                ]
                if not matching:
                    raise ValueError("Sparse game screen: coordinate tap was not grounded in a local-vision target.")
                nearest = min(
                    matching,
                    key=lambda item: abs(int(item.get("x", x)) - x) + abs(int(item.get("y", y)) - y),
                )
                x, y = int(nearest["x"]), int(nearest["y"])
            return self.bridge.tap_verified(
                x,
                y,
                expected_package_name=expected_package,
                serial=serial,
            )
        if action_type == "swipe":
            if is_game_surface:
                raise ValueError("Raw swipe is disabled for game navigation; use joystick or camera_drag.")
            return self.bridge.swipe_verified(
                int(action.get("start_x")),
                int(action.get("start_y")),
                int(action.get("end_x")),
                int(action.get("end_y")),
                duration_ms=int(action.get("duration_ms") or 400),
                expected_package_name=expected_package,
                serial=serial,
            )
        if action_type == "joystick":
            if not expected_package:
                raise ValueError("joystick requires a stable visible package.")
            return self.bridge.game_joystick_move(
                str(action.get("direction") or "up"),
                int(action.get("duration_ms") or 700),
                expected_package_name=expected_package,
                serial=serial,
            )
        if action_type == "camera_drag":
            if not expected_package:
                raise ValueError("camera_drag requires a stable visible package.")
            return self.bridge.game_camera_drag(
                str(action.get("direction") or "right"),
                int(action.get("distance_px") or 160),
                expected_package_name=expected_package,
                duration_ms=int(action.get("duration_ms") or 350),
                serial=serial,
            )
        if action_type == "press_key":
            return self.bridge.keyevent(str(action.get("key") or "BACK"), serial=serial)
        if action_type == "open_app":
            return self.bridge.open_app_verified(str(action.get("package_name") or ""), serial=serial)
        if action_type == "type_text":
            return self.bridge.type_text(str(action.get("text") or ""), serial=serial)
        raise ValueError(f"Unhandled action: {action_type}")

    def _agent_loop(self, goal: str, source: str, max_actions: int) -> None:
        client = DeepSeekClient(
            api_key=self.api_key,
            base_url=self.config["deepseek_base_url"],
            model=self.config["deepseek_model"],
        )
        previous_action: dict[str, Any] | None = None
        self.log("run", f"Started {source} run: {goal}")
        try:
            for step in range(1, max_actions + 1):
                if self.stop_event.is_set():
                    self.run_state.last_summary = "Stopped by user."
                    self.log("warning", "Agent stopped by user.")
                    return
                self.run_state.step = step
                observation = build_observation(self.bridge)
                vision = observation.get("vision", {})
                self.log(
                    "observe",
                    f"Step {step}: UI read; local vision {'used' if vision.get('used') else 'not needed' if not vision.get('recommended') else 'unavailable'}.",
                )
                decision = client.decide(goal, observation, previous_action, step)
                reason = str(decision.get("reason") or "")[:160]
                action = decision.get("action")
                if not isinstance(action, dict):
                    raise ValueError("DeepSeek decision did not contain an action object.")
                self.log("decision", reason or "DeepSeek selected the next safe action.", action)

                if self.stop_event.is_set():
                    self.run_state.last_summary = "Stopped by user."
                    return
                result = self._verify_and_execute(action, observation)
                previous_action = {"decision": action, "result": result}
                if result.get("status") == "finished":
                    summary = str(result.get("summary") or "Finished")
                    self.run_state.last_summary = summary
                    self.log("success", summary)
                    return
                self.log("action", f"Executed {result.get('action', action.get('type'))}.", result)
                time.sleep(float(self.config["step_delay_seconds"]))

            self.run_state.last_summary = f"Stopped after reaching max_actions={max_actions}."
            self.log("warning", self.run_state.last_summary)
        except Exception as exc:  # Keep the local controller alive and surface the error in the UI.
            self.run_state.last_error = str(exc)
            self.log("error", str(exc))
        finally:
            self.run_state.running = False

    def _scheduler_loop(self) -> None:
        while not self.scheduler_stop.wait(15):
            now = datetime.now()
            for routine in self._routine_copy():
                if not routine_due(routine, now):
                    continue
                try:
                    started = self.start_agent(
                        str(routine.get("prompt") or ""),
                        source=f"routine:{routine.get('name', 'daily')}",
                        max_actions=int(routine.get("max_actions") or self.config["max_actions"]),
                    )
                    if started:
                        self.mark_routine_run(str(routine.get("id")), now.strftime("%Y-%m-%d"))
                        self.log("schedule", f"Daily routine started: {routine.get('name')}")
                except Exception as exc:
                    self.log("error", f"Routine {routine.get('name')} could not start: {exc}")

    def status(self) -> dict[str, Any]:
        try:
            devices = [device.as_dict() for device in self.bridge.devices()]
        except Exception as exc:
            devices = [{"state": "error", "details": str(exc)}]
        try:
            vision = local_vision_status(ROOT)
        except Exception as exc:
            vision = {"enabled": False, "error": str(exc)}
        return {
            "ok": True,
            "config": self.public_config(),
            "devices": devices,
            "vision": vision,
            "run": self.run_state.__dict__.copy(),
            "routines": self._routine_copy(),
            "logs": list(self.logs)[-120:],
        }


STATE: ControlState | None = None


class ControlHandler(BaseHTTPRequestHandler):
    server_version = "PhoneBridgeControl/0.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    @property
    def state(self) -> ControlState:
        assert STATE is not None
        return STATE

    def _send_json(self, status: int, value: Any) -> None:
        data = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or "0")
        if length <= 0:
            return {}
        if length > 1024 * 1024:
            raise ValueError("Request body is too large.")
        raw = self.rfile.read(length).decode("utf-8")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object.")
        return value

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            if not UI_FILE.exists():
                self.send_error(404, "control_center_ui.html is missing")
                return
            data = UI_FILE.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            return
        if parsed.path == "/api/status":
            self._send_json(200, self.state.status())
            return
        if parsed.path == "/api/screenshot":
            try:
                data = self.state.bridge.screenshot_png()
            except Exception as exc:
                self._send_json(503, {"ok": False, "error": str(exc)})
                return
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_error(404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            payload = self._read_json()
            if parsed.path == "/api/config":
                self.state.update_config(payload)
                self._send_json(200, {"ok": True, "config": self.state.public_config()})
                return
            if parsed.path == "/api/agent/start":
                started = self.state.start_agent(
                    str(payload.get("goal") or ""),
                    source="manual",
                    max_actions=payload.get("max_actions"),
                )
                self._send_json(200 if started else 409, {"ok": started, "running": not started})
                return
            if parsed.path == "/api/agent/stop":
                self.state.stop_agent()
                self._send_json(200, {"ok": True})
                return
            if parsed.path == "/api/routines/upsert":
                routine = self.state.upsert_routine(payload)
                self._send_json(200, {"ok": True, "routine": routine})
                return
            if parsed.path == "/api/routines/delete":
                self.state.delete_routine(str(payload.get("id") or ""))
                self._send_json(200, {"ok": True})
                return
            if parsed.path == "/api/routines/run":
                routine = self.state.get_routine(str(payload.get("id") or ""))
                if not routine:
                    self._send_json(404, {"ok": False, "error": "Routine not found."})
                    return
                started = self.state.start_agent(
                    str(routine.get("prompt") or ""),
                    source=f"routine:{routine.get('name', 'daily')}",
                    max_actions=int(routine.get("max_actions") or self.state.config["max_actions"]),
                )
                self._send_json(200 if started else 409, {"ok": started})
                return
        except Exception as exc:
            self.state.log("error", str(exc))
            self._send_json(400, {"ok": False, "error": str(exc)})
            return
        self.send_error(404)


def main() -> int:
    parser = argparse.ArgumentParser(description="Local UI and scheduler for Yunkai PhoneBridge.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host. Keep 127.0.0.1 for normal use.")
    parser.add_argument("--port", type=int, default=8792, help="Local Control Center port.")
    parser.add_argument("--open", action="store_true", help="Open the UI in the default browser after startup.")
    args = parser.parse_args()

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("For safety the Control Center may only bind to localhost.")

    global STATE
    STATE = ControlState()
    server = ThreadingHTTPServer((args.host, args.port), ControlHandler)
    url = f"http://127.0.0.1:{args.port}/"
    print(f"[PhoneBridge Control] UI: {url}")
    print("[PhoneBridge Control] DeepSeek API key is kept in memory only.")
    print("[PhoneBridge Control] Autonomous purchase/gacha guard: ON")
    if args.open:
        import webbrowser

        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        if STATE is not None:
            STATE.scheduler_stop.set()
            STATE.stop_agent()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
