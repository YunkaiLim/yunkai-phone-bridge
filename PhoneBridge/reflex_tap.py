"""Default-deny PhoneBridge semantic tap. Native atomicity is NOT claimed."""
from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import threading
import time
from uuid import UUID

CONTRACT = "phonebridge.reflex.semantic_tap.v2"
POLICY_CONTRACT = "phonebridge.reflex.policy.v1"
TOOL_NAME = "tap_android_ui_element_reflex_verified"
MAX_AGE_MS = 5000
MAX_OPERATIONS = 4096
MAX_AUDIT = 128
_POLICY_FILE = Path(__file__).with_name("phonebridge_reflex_policy.json")
_REASONS = (
    "INVALID_REQUEST", "RUNTIME_PERMISSION_DENIED", "STALE_CONTEXT", "CONTEXT_CHANGED",
    "TARGET_NOT_UNIQUE", "TARGET_NOT_ALLOWED", "PRECONDITION_FAILED", "OBSERVATION_INVALID",
    "DEVICE_AUTHORIZATION_UNCERTAIN", "FOREGROUND_MISMATCH", "BACKEND_UNAVAILABLE", "BUSY",
    "ALREADY_ATTEMPTED", "ATTEMPT_LIMIT", "DISPATCH_GUARD_DENIED", "RECEIPT_MISMATCH",
    "EXECUTION_UNCERTAIN", "EXPECTED_POST_UNPROVEN", "VERIFIED",
)


def _fields(value, names):
    return (type(value) is dict and len(value) == len(names)
            and all(type(key) is str for key in value) and value.keys() == set(names))


def _digest(value):
    return type(value) is str and len(value) == 64 and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _uuid(value):
    if type(value) is not str or len(value) != 36:
        return False
    try:
        return str(UUID(value)) == value and UUID(value).int != 0
    except ValueError:
        return False


def _millis(value):
    return type(value) is int and 0 <= value <= 2**53 - 1


def _package(value):
    return (type(value) is str and 1 <= len(value) <= 128
            and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", value) is not None)


@dataclass(frozen=True)
class Selector:
    field: str
    value: str

    def wire(self):
        return {self.field: self.value}


def _selector(value):
    if type(value) is not dict or len(value) != 1:
        return None
    field = next(iter(value))
    if type(field) is not str or field not in ("text", "content_desc", "resource_id"):
        return None
    text = value[field]
    if (type(text) is not str or not 1 <= len(text) <= 128 or text != text.strip()
            or any(ord(char) < 32 or 127 <= ord(char) <= 159 or 0xD800 <= ord(char) <= 0xDFFF for char in text)
            or len(text.encode("utf-8")) > 256):
        return None
    if field == "resource_id" and re.fullmatch(r"[A-Za-z0-9_.]+:id/[A-Za-z0-9_]+", text) is None:
        return None
    return Selector(field, text)


@dataclass(frozen=True)
class ExpectedPost:
    selector: Selector
    present: bool
    package_name: str

    def wire(self):
        return {"kind": "ui_element_presence", "selector": self.selector.wire(),
                "present": self.present, "package_name": self.package_name}


@dataclass(frozen=True)
class TapRequest:
    operation_id: str
    selector: Selector
    expected_package_name: str
    observed_at_ms: int
    expires_at_ms: int
    expected_post: ExpectedPost

    @property
    def binding_id(self):
        # Owner allowlist key only: never returned, logged, or treated as permission by itself.
        value = {"selector": self.selector.wire(), "expected_package_name": self.expected_package_name,
                 "expected_post": self.expected_post.wire()}
        return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                         separators=(",", ":")).encode()).hexdigest()


def parse_request(value):
    names = ("schema_version", "operation_id", "selector", "expected_package_name",
             "observed_at_ms", "expires_at_ms", "expected_post")
    if (not _fields(value, names) or type(value["schema_version"]) is not str
            or value["schema_version"] != CONTRACT or not _uuid(value["operation_id"])
            or not _package(value["expected_package_name"])):
        return None
    selector = _selector(value["selector"])
    before, expiry = value["observed_at_ms"], value["expires_at_ms"]
    post = value["expected_post"]
    if (selector is None or not _millis(before) or not _millis(expiry)
            or not 0 < expiry - before <= MAX_AGE_MS
            or not _fields(post, ("kind", "selector", "present", "package_name"))
            or type(post["kind"]) is not str or post["kind"] != "ui_element_presence"
            or type(post["present"]) is not bool or not _package(post["package_name"])):
        return None
    post_selector = _selector(post["selector"])
    if post_selector is None:
        return None
    return TapRequest(value["operation_id"], selector, value["expected_package_name"], before, expiry,
                      ExpectedPost(post_selector, post["present"], post["package_name"]))


@dataclass(frozen=True)
class RuntimePolicy:
    enabled: bool = False
    allowed_binding_ids: tuple[str, ...] = ()

    def valid(self):
        refs = self.allowed_binding_ids
        return (type(self.enabled) is bool and type(refs) is tuple and len(refs) <= 32
                and all(_digest(ref) for ref in refs) and len(set(refs)) == len(refs))


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("invalid policy")
        result[key] = value
    return result


def load_runtime_policy():
    """Fixed owner file; the disabled example is never an active fallback."""
    try:
        with _POLICY_FILE.open("rb") as source:
            raw = source.read(8193)
        if len(raw) > 8192:
            return RuntimePolicy()
        value = json.loads(raw, object_pairs_hook=_unique_object)
        if (not _fields(value, ("schema_version", "enabled", "allowed_binding_ids"))
                or value["schema_version"] != POLICY_CONTRACT or type(value["allowed_binding_ids"]) is not list):
            return RuntimePolicy()
        policy = RuntimePolicy(value["enabled"], tuple(value["allowed_binding_ids"]))
        return policy if policy.valid() else RuntimePolicy()
    except (OSError, ValueError, TypeError, RecursionError):
        return RuntimePolicy()


@dataclass(frozen=True)
class Identity:
    context_digest: str
    foreground_digest: str
    generation_digest: str

    def valid(self):
        return all(_digest(value) for value in (self.context_digest, self.foreground_digest, self.generation_digest))


@dataclass(frozen=True)
class Observation:
    operation_id: str
    observed_at_ms: int
    identity: Identity
    authorized: bool
    foreground_matches: bool
    match_count: int
    target_enabled: bool
    target_digest: str
    predicate_matched: bool | None


@dataclass(frozen=True)
class Receipt:
    operation_id: str
    executed_once: bool


class _Unavailable(Exception):
    pass


class _CallGate:
    """At most one in-flight worker, bounded wait, no queued work or retry."""
    def __init__(self):
        self._slot = threading.Lock()

    @property
    def busy(self):
        return self._slot.locked()

    def call(self, callback, timeout_ms):
        if timeout_ms <= 0 or not self._slot.acquire(blocking=False):
            raise _Unavailable()
        done, output = threading.Event(), []

        def run():
            try:
                output.append((True, callback()))
            except BaseException:
                output.append((False, None))
            finally:
                self._slot.release()
                done.set()
        try:
            threading.Thread(target=run, daemon=True).start()
        except Exception:
            self._slot.release()
            raise _Unavailable() from None
        if not done.wait(timeout_ms / 1000) or not output[0][0]:
            raise _Unavailable()
        return output[0][1]


class ReflexTapExecutor:
    """Observe -> recheck at sole input -> independent explicit post. No atomic claim."""
    def __init__(self, *, bridge=None, clock=None, policy=load_runtime_policy, timeout_ms=250):
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 1000 or not callable(policy):
            raise ValueError("invalid reflex configuration")
        self._clock = clock or (lambda: time.time_ns() // 1_000_000)
        if bridge is None:
            from reflex_native import NativeSemanticBridge
            bridge = NativeSemanticBridge(clock=self._clock)
        self._bridge, self._policy, self._timeout_ms = bridge, policy, timeout_ms
        self._attempted = set()
        self._audit = deque(maxlen=MAX_AUDIT)
        self._lock = threading.Lock()
        self._dispatch, self._observe = _CallGate(), _CallGate()

    @property
    def audit(self):
        with self._lock:
            return tuple(dict(item) for item in self._audit)

    def _evidence(self, req, observation):
        if not self._observation_valid(req, observation):
            return None
        return {"observed_at_ms": observation.observed_at_ms, **asdict(observation.identity)}

    def _result(self, req, status, reason, *, executed=False, before=None, after=None):
        result = {"schema_version": CONTRACT, "operation_id": req.operation_id if req else None,
                  "executed_once": executed, "verification_status": status, "reason": reason,
                  "before": self._evidence(req, before) if req else None,
                  "after": self._evidence(req, after) if req else None,
                  "safe_to_retry_action": False, "automatic_action_retry": False}
        self._audit.append({key: result[key] for key in
                            ("operation_id", "executed_once", "verification_status", "reason")})
        return result

    def _permission(self, req):
        try:
            policy = self._policy()
            return (type(policy) is RuntimePolicy and policy.valid() and policy.enabled
                    and req.binding_id in policy.allowed_binding_ids)
        except Exception:
            return False

    def _fresh(self, req):
        now = self._clock()
        return _millis(now) and req.observed_at_ms <= now < req.expires_at_ms

    def _observation_valid(self, req, item):
        # Shape/correlation is separate from freshness, so stale evidence can be
        # reported as bounded evidence without ever being accepted as current.
        return (req is not None and type(item) is Observation and item.operation_id == req.operation_id
                and _millis(item.observed_at_ms) and type(item.identity) is Identity and item.identity.valid()
                and type(item.authorized) is bool and type(item.foreground_matches) is bool
                and type(item.match_count) is int and 0 <= item.match_count <= 100
                and type(item.target_enabled) is bool and _digest(item.target_digest)
                and (item.predicate_matched is None or type(item.predicate_matched) is bool))

    def _current(self, req, item):
        now = self._clock()
        return (self._observation_valid(req, item) and _millis(now)
                and req.observed_at_ms <= item.observed_at_ms <= now < req.expires_at_ms
                and now - item.observed_at_ms <= MAX_AGE_MS)

    def _precondition(self, req, item):
        if not self._current(req, item):
            return "OBSERVATION_INVALID"
        if not item.authorized:
            return "DEVICE_AUTHORIZATION_UNCERTAIN"
        if not item.foreground_matches:
            return "FOREGROUND_MISMATCH"
        if item.match_count != 1:
            return "TARGET_NOT_UNIQUE"
        if not item.target_enabled:
            return "TARGET_NOT_ALLOWED"
        # An already-satisfied or unknown predicate cannot prove this action's result.
        if item.predicate_matched is not False:
            return "PRECONDITION_FAILED"
        return None

    def tap(self, value):
        req = parse_request(value)
        if not self._lock.acquire(blocking=False):
            return {"schema_version": CONTRACT, "operation_id": req.operation_id if req else None,
                    "executed_once": False, "verification_status": "DENIED", "reason": "BUSY",
                    "before": None, "after": None, "safe_to_retry_action": False, "automatic_action_retry": False}
        cancel, before, after = threading.Event(), None, None
        attempted = False
        try:
            if req is None:
                return self._result(None, "DENIED", "INVALID_REQUEST")
            if not self._permission(req):
                return self._result(req, "DENIED", "RUNTIME_PERMISSION_DENIED")
            if not self._fresh(req):
                return self._result(req, "DENIED", "STALE_CONTEXT")
            if self._dispatch.busy or self._observe.busy:
                return self._result(req, "DENIED", "BUSY")
            if req.operation_id in self._attempted:
                return self._result(req, "DENIED", "ALREADY_ATTEMPTED")
            if len(self._attempted) >= MAX_OPERATIONS:
                return self._result(req, "DENIED", "ATTEMPT_LIMIT")
            before = self._observe.call(lambda: self._bridge.observe(req, "before"), self._timeout_ms)
            reason = self._precondition(req, before)
            if reason:
                return self._result(req, "DENIED", reason, before=before)
            self._attempted.add(req.operation_id)
            state, guard_lock = {"calls": 0, "allowed": False, "at": before.observed_at_ms}, threading.Lock()
            deadline = time.monotonic() + self._timeout_ms / 1000

            def guard(current):
                with guard_lock:
                    state["calls"] += 1
                    allowed = (not cancel.is_set() and state["calls"] == 1 and self._permission(req)
                               and self._precondition(req, current) is None
                               and current.identity == before.identity and current.target_digest == before.target_digest)
                    now = self._clock()
                    allowed = bool(allowed and _millis(now) and req.observed_at_ms <= now < req.expires_at_ms
                                   and time.monotonic() < deadline and not cancel.is_set())
                    state["allowed"], state["at"] = allowed, now
                    return allowed

            attempted, uncertain = True, False
            try:
                receipt = self._dispatch.call(lambda: self._bridge.execute_guarded(req, guard), self._timeout_ms)
            except _Unavailable:
                receipt, uncertain = None, True
            cancel.set()
            if (not uncertain or not self._dispatch.busy
                    or getattr(self._bridge, "safe_post_observation", False) is True):
                try:
                    after = self._observe.call(lambda: self._bridge.observe(req, "after"), self._timeout_ms)
                except _Unavailable:
                    pass
            if uncertain:
                return self._result(req, "UNCERTAIN", "EXECUTION_UNCERTAIN", executed=None, before=before, after=after)
            valid_receipt = (type(receipt) is Receipt and receipt.operation_id == req.operation_id
                             and type(receipt.executed_once) is bool)
            if (not valid_receipt or (receipt.executed_once and
                                     not (state["calls"] == 1 and state["allowed"]))):
                return self._result(req, "UNCERTAIN", "RECEIPT_MISMATCH", executed=None, before=before, after=after)
            if not receipt.executed_once:
                return self._result(req, "DENIED", "DISPATCH_GUARD_DENIED", before=before, after=after)
            matched = (self._current(req, after) and after.authorized and after.foreground_matches
                       and after.predicate_matched is True and after.observed_at_ms >= state["at"]
                       and after.identity.generation_digest == before.identity.generation_digest)
            return self._result(req, "VERIFIED" if matched else "UNVERIFIED",
                                "VERIFIED" if matched else "EXPECTED_POST_UNPROVEN",
                                executed=True, before=before, after=after)
        except Exception:
            return self._result(req, "UNCERTAIN" if attempted else "DENIED", "BACKEND_UNAVAILABLE",
                                executed=None if attempted else False, before=before, after=after)
        finally:
            cancel.set()
            self._lock.release()


def contract_manifest():
    return {"schema_version": CONTRACT, "milestone": "0.8-P0",
            "runtime_permission_default": "denied", "caller_can_enable": False,
            "legacy_action_authority_unchanged": True, "stock_adb_atomic_context_guard": False,
            "production_backend_implemented": True, "runtime_ready": False, "live_reflex_ready": False,
            "expected_post_predicates": True, "action_audit_scope": "bounded_in_memory_new_tool_only",
            "operation_trace_scope": "correlated_new_tool_only", "durable_exactly_once": False,
            "automatic_action_retry": False}


def request_schema():
    def obj(properties):
        return {"type": "object", "additionalProperties": False, "required": list(properties), "properties": properties}
    selector = {"oneOf": [obj({key: {"type": "string", "minLength": 1, "maxLength": 128}})
                          for key in ("text", "content_desc", "resource_id")]}
    package = {"type": "string", "minLength": 1, "maxLength": 128,
               "pattern": r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$"}
    return obj({"schema_version": {"const": CONTRACT},
                "operation_id": {"type": "string", "format": "uuid", "minLength": 36, "maxLength": 36},
                "selector": selector, "expected_package_name": package,
                "observed_at_ms": {"type": "integer", "minimum": 0, "maximum": 2**53 - 1},
                "expires_at_ms": {"type": "integer", "minimum": 0, "maximum": 2**53 - 1},
                "expected_post": obj({"kind": {"const": "ui_element_presence"}, "selector": selector,
                                      "present": {"type": "boolean"}, "package_name": package})})


def response_schema():
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$", "minLength": 64, "maxLength": 64}
    evidence = {"type": ["object", "null"], "additionalProperties": False,
                "required": ["observed_at_ms", "context_digest", "foreground_digest", "generation_digest"],
                "properties": {"observed_at_ms": {"type": "integer", "minimum": 0, "maximum": 2**53 - 1},
                               **{key: dict(digest) for key in ("context_digest", "foreground_digest", "generation_digest")}}}
    properties = {"schema_version": {"const": CONTRACT}, "operation_id": {"type": ["string", "null"]},
                  "executed_once": {"type": ["boolean", "null"]},
                  "verification_status": {"enum": ["DENIED", "VERIFIED", "UNVERIFIED", "UNCERTAIN"]},
                  "reason": {"enum": list(_REASONS)}, "before": evidence, "after": evidence,
                  "safe_to_retry_action": {"const": False}, "automatic_action_retry": {"const": False}}
    return {"type": "object", "additionalProperties": False, "required": list(properties), "properties": properties}
