"""Additive wrapper around the unchanged verified primitive; no device calls on import."""
import hashlib
import hmac
import json
import re
import secrets

from phone_bridge import AndroidBridge
from reflex_tap import Identity, Observation, Receipt


class _GuardDenied(Exception):
    pass


class NativeSemanticBridge:
    atomic_context_guard = False  # ADB observation and input are separate Android operations.
    safe_post_observation = False  # Never overlap observations with a still-running native dispatch.

    def __init__(self, *, clock, bridge_factory=AndroidBridge):
        self._clock, self._factory = clock, bridge_factory
        self._bridge = None
        self._key = secrets.token_bytes(32)
        self._center = None
        self._center_operation = None

    def _digest(self, value):
        # Process-private HMACs prevent raw identifiers/selector text from becoming
        # recoverable dictionary hashes in receipts. Never persist/export the key.
        return hmac.new(self._key, json.dumps(value, sort_keys=True, ensure_ascii=True,
                                             separators=(",", ":")).encode(), hashlib.sha256).hexdigest()

    def _device(self):
        if self._bridge is None:
            self._bridge = self._factory()
        rows = self._bridge.devices()  # Discovery only; NEVER implicit select_device(None).
        if len(rows) != 1 or rows[0].state != "device" or not rows[0].serial:
            raise _GuardDenied()
        return self._bridge, rows[0]

    @staticmethod
    def _surface_data(surface):
        package = surface.get("package_name")
        activity = surface.get("activity")
        signature = surface.get("semantic_signature")
        size = surface.get("input_size")
        orientation = surface.get("orientation")
        if (surface.get("source") != "uia_and_dumpsys_agree" or type(package) is not str
                or not package or surface.get("reported_package_name") != package
                or surface.get("visible_packages") != [package]
                or type(activity) is not str or not 1 <= len(activity) <= 256
                or type(signature) is not str or re.fullmatch(r"[0-9a-f]{24}", signature) is None
                or type(size) is not list or len(size) != 2
                or not all(type(value) is int and 1 <= value <= 32768 for value in size)
                or orientation != ("landscape" if size[0] > size[1] else "portrait")
                or AndroidBridge._lockscreen_from_surface(surface)):
            raise _GuardDenied()
        return {"package": package, "activity": activity, "semantic_signature": signature,
                "orientation": orientation, "input_size": size}

    @staticmethod
    def _matches(bridge, serial, selector):
        found = bridge.ui_elements(**selector.wire(), exact=True, case_sensitive=True,
                                   serial=serial, limit=100)
        matches = found.get("matches")
        if (type(matches) is not list or type(found.get("count")) is not int
                or found.get("serial") != serial
                or found["count"] != len(matches) or len(matches) > 100
                or not all(type(item) is dict for item in matches)):
            raise _GuardDenied()
        return matches

    def observe(self, request, phase):
        started = self._clock()  # Timestamp before potentially slow reads.
        bridge, device = self._device()
        serial = device.serial
        first = self._surface_data(bridge.surface_identity(serial, limit=40))
        targets = self._matches(bridge, serial, request.selector) if phase != "after" else []
        post_matches = self._matches(bridge, serial, request.expected_post.selector)
        last = self._surface_data(bridge.surface_identity(serial, limit=40))
        _, current_device = self._device()
        if first != last or current_device != device:
            raise _GuardDenied()
        if (any(item.get("package") != request.expected_package_name for item in targets)
                or any(item.get("package") != request.expected_post.package_name for item in post_matches)):
            raise _GuardDenied()
        predicate = None
        if len(post_matches) <= 1:
            predicate = ((len(post_matches) == 1) == request.expected_post.present
                         and last["package"] == request.expected_post.package_name)
        chosen = targets[0] if len(targets) == 1 else None
        enabled = (chosen is not None and chosen.get("enabled") is True and chosen.get("clickable") is True)
        center = chosen.get("input_center") if chosen is not None else None
        if enabled and (type(center) is not list or len(center) != 2
                        or not all(type(value) is int and 0 <= value <= 32768 for value in center)):
            raise _GuardDenied()
        if phase != "after":
            self._center = tuple(center) if enabled else None
            self._center_operation = request.operation_id
        expected_package = (request.expected_post.package_name if phase == "after"
                            else request.expected_package_name)
        identity = Identity(self._digest(last), self._digest([last["package"], last["activity"]]),
                            self._digest([device.serial, device.state, device.details]))
        return Observation(request.operation_id, started, identity, True,
                           last["package"] == expected_package, len(targets), enabled,
                           self._digest(chosen), predicate)

    def execute_guarded(self, request, guard):
        bridge, device = self._device()
        owner = self
        state = {"attempts": 0}

        class GuardedPrimitive(AndroidBridge):
            def __init__(self):
                self.adb_path = bridge.adb_path

            def devices(self):
                return bridge.devices()

            def select_device(self, serial=None):
                # All inherited reads/actions must keep the privately pinned device.
                rows = bridge.devices()
                if serial != device.serial or len(rows) != 1 or rows[0] != device or rows[0].state != "device":
                    raise _GuardDenied()
                return device.serial

            def screen_visual_hash(self, serial=None, hash_size=8):
                return bridge.screen_visual_hash(self.select_device(serial), hash_size)

            def _run(self, args, *, serial=None, timeout=15, binary=False):
                if args[:2] == ["shell", "input"]:
                    if args[:3] != ["shell", "input", "tap"] or len(args) != 5 or state["attempts"]:
                        raise _GuardDenied()
                    current = owner.observe(request, "guard")
                    point = tuple(int(value) for value in args[3:])
                    if (owner._center_operation != request.operation_id or owner._center != point
                            or self.select_device(serial) != device.serial or not guard(current)):
                        raise _GuardDenied()
                    state["attempts"] = 1  # Set BEFORE the only possibly effective input.
                return bridge._run(args, serial=serial, timeout=timeout, binary=binary)

        try:
            # Use the existing primitive unchanged. Its generic verification is
            # deliberately discarded; the executor independently observes the predicate.
            result = GuardedPrimitive().tap_ui_element_verified(
                **request.selector.wire(), exact=True, case_sensitive=True, index=None,
                expected_package_name=request.expected_package_name, observation_attempts=1,
                observation_delay_ms=0, serial=device.serial,
            )
        except Exception:
            if state["attempts"]:
                raise RuntimeError("execution uncertain") from None
            return Receipt(request.operation_id, False)
        if state["attempts"] != 1 or result.get("action_executed_once") is not True:
            raise RuntimeError("execution uncertain")
        return Receipt(request.operation_id, True)
