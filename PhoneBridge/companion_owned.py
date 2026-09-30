"""Default-off host adapter for Companion's fixed debug-owned click fixture.

This module has no Android/ADB access and performs no I/O on import. The only
remote action it can request is Companion's phone_v0_8_owned_click MCP tool.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
import os
import re
import threading
import time
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4


TOOL_NAME = "phonebridge_companion_owned_click_scoped"
STATUS_TOOL_NAME = "get_phonebridge_companion_owned_click_status"
PEER_TOOL_NAME = "phone_v0_8_owned_click"
CONTRACT = "phonebridge.companion_owned_click.v1"
STATUS_CONTRACT = "phonebridge.companion_owned_click.status.v1"
SCOPE = "com.yunkai.companion.debug.phone_v0_8_semantic_click_target"
PEER_PROTOCOL = "2026-07-28"
MAX_ATTEMPTS = 4096
CALL_TIMEOUT_SECONDS = 60
_ENV_ENABLED = "PHONEBRIDGE_COMPANION_OWNED_CLICK_ENABLED"
_ENV_URL = "PHONEBRIDGE_COMPANION_MCP_URL"
_ENV_TOKEN = "MCP_BEARER_TOKEN"  # Companion's existing server bearer boundary.
_NO_INPUT_CATEGORIES = frozenset({
    "MALFORMED_REQUEST", "REPLAY_OR_CAPACITY", "CONTEXT_CHANGED",
    "CONSENT_UNAVAILABLE", "AUTHORIZATION_UNAVAILABLE", "DEBUG_BUILD_REQUIRED",
})


def _uuid(value: Any) -> bool:
    if type(value) is not str or len(value) != 36:
        return False
    try:
        parsed = UUID(value)
        return str(parsed) == value and parsed.int != 0
    except ValueError:
        return False


def _fields(value: Any, required: set[str], optional: set[str] = frozenset()) -> bool:
    return (type(value) is dict and all(type(key) is str for key in value)
            and required <= value.keys() and value.keys() <= required | optional)


def _local_mcp_url(value: Any) -> str | None:
    if type(value) is not str or not value or value != value.strip() or len(value) > 200:
        return None
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"}
                or parsed.port is None or not 1 <= parsed.port <= 65535
                or parsed.path != "/mcp" or parsed.query or parsed.fragment
                or parsed.username is not None or parsed.password is not None):
            return None
    except ValueError:
        return None
    return value


@dataclass(frozen=True)
class Config:
    url: str
    bearer: str = field(repr=False)


def load_config(environment: dict[str, str] | None = None) -> Config | None:
    """Require explicit enablement, exact loopback endpoint and existing bearer."""
    env = os.environ if environment is None else environment
    if env.get(_ENV_ENABLED) != "1":
        return None
    url = _local_mcp_url(env.get(_ENV_URL))
    bearer = env.get(_ENV_TOKEN)
    if (url is None or type(bearer) is not str or not 32 <= len(bearer) <= 4096
            or bearer != bearer.strip() or any(ord(char) < 33 or ord(char) > 126 for char in bearer)):
        return None
    return Config(url, bearer)


def status(environment: dict[str, str] | None = None) -> dict[str, Any]:
    """Passive configuration evidence; never probes Companion or a device."""
    try:
        configured = load_config(environment) is not None
    except Exception:
        configured = False
    return {"schema_version": STATUS_CONTRACT, "scope": SCOPE,
            "implemented": True, "configured": configured, "reachable": "UNKNOWN",
            "accepted": "NOT_PERFORMED", "live_ready": False,
            "generic_reflex_ready": False, "stock_adb_atomic_context_guard": False,
            "automatic_action_retry": False}


def parse_request(value: Any) -> tuple[str, int, str | None] | None:
    if not _fields(value, {"requestId", "ttlMillis"}, {"deviceId"}):
        return None
    request_id, ttl, device_id = value["requestId"], value["ttlMillis"], value.get("deviceId")
    if (not _uuid(request_id) or type(ttl) is not int or not 1 <= ttl <= 30000
            or ("deviceId" in value and not _uuid(device_id))):
        return None
    return request_id, ttl, device_id


def request_schema() -> dict[str, Any]:
    uuid = {"type": "string", "format": "uuid", "minLength": 36, "maxLength": 36,
            "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"}
    return {"type": "object", "additionalProperties": False,
            "required": ["requestId", "ttlMillis"],
            "properties": {"requestId": uuid, "ttlMillis": {"type": "integer", "minimum": 1, "maximum": 30000},
                           "deviceId": uuid}}


def status_schema() -> dict[str, Any]:
    properties = {"schema_version": {"const": STATUS_CONTRACT}, "scope": {"const": SCOPE},
                  "implemented": {"const": True}, "configured": {"type": "boolean"},
                  "reachable": {"const": "UNKNOWN"}, "accepted": {"const": "NOT_PERFORMED"},
                  "live_ready": {"const": False}, "generic_reflex_ready": {"const": False},
                  "stock_adb_atomic_context_guard": {"const": False},
                  "automatic_action_retry": {"const": False}}
    return {"type": "object", "additionalProperties": False,
            "required": list(properties), "properties": properties}


def response_schema() -> dict[str, Any]:
    properties = {"schema_version": {"const": CONTRACT}, "scope": {"const": SCOPE},
                  "request_id": {"type": ["string", "null"]},
                  "operation_id": {"type": ["string", "null"]},
                  "device_id": {"type": ["string", "null"]},
                  "session_id": {"type": ["string", "null"]},
                  "input_outcome": {"enum": ["NO_INPUT", "ONE_INPUT", "UNCERTAIN"]},
                  "post_outcome": {"enum": ["VERIFIED", "UNVERIFIED", "UNAVAILABLE"]},
                  "evidence_category": {"enum": [
                      "OWNED_TRANSITION", "TRANSITION_UNCERTAIN", "MALFORMED_REQUEST",
                      "REPLAY_OR_CAPACITY", "CONTEXT_CHANGED", "CONSENT_UNAVAILABLE",
                      "AUTHORIZATION_UNAVAILABLE", "DEBUG_BUILD_REQUIRED",
                      "HOST_RECEIPT_UNAVAILABLE", "HOST_CONFIG_UNAVAILABLE", "INVALID_REQUEST",
                      "HOST_ATTEMPT_LIMIT", "HOST_OPERATION_UNAVAILABLE"]},
                  "safe_to_retry_action": {"const": False},
                  "automatic_action_retry": {"const": False},
                  "live_acceptance": {"const": "PENDING"}}
    return {"type": "object", "additionalProperties": False,
            "required": list(properties), "properties": properties}


def _result(request_id: str | None, operation_id: str | None, device_id: str | None,
            session_id: str | None, input_outcome: str, post_outcome: str,
            evidence_category: str) -> dict[str, Any]:
    return {"schema_version": CONTRACT, "scope": SCOPE, "request_id": request_id,
            "operation_id": operation_id, "device_id": device_id, "session_id": session_id,
            "input_outcome": input_outcome, "post_outcome": post_outcome,
            "evidence_category": evidence_category, "safe_to_retry_action": False,
            "automatic_action_retry": False, "live_acceptance": "PENDING"}


def _uncertain(request_id: str, operation_id: str, device_id: str | None) -> dict[str, Any]:
    return _result(request_id, operation_id, device_id, None,
                   "UNCERTAIN", "UNAVAILABLE", "HOST_RECEIPT_UNAVAILABLE")


def _valid_receipt(raw: Any, operation_id: str, requested_device: str | None) -> dict[str, Any] | None:
    """Validate both MCP result envelope and Android receipt before projection."""
    if not _fields(raw, {"is_error", "structured_content"}) or raw["is_error"] is not False:
        return None
    value = raw["structured_content"]
    if (not _fields(value, {"success", "data", "error", "metadata"})
            or value["success"] is not True or value["error"] is not None):
        return None
    data, meta = value["data"], value["metadata"]
    if not _fields(data, {"version", "operationId", "deviceId", "sessionId",
                          "sessionGeneration", "authorityGeneration", "targetGeneration",
                          "inputOutcome", "postOutcome", "evidenceCategory"}):
        return None
    if not _fields(meta, {"requestId", "timestamp", "tool", "riskLevel",
                          "permissionDecision", "durationMs", "protocolVersion"},
                   {"deviceId", "sessionId"}):
        return None
    if (type(data["version"]) is not int or data["version"] != 1
            or not all(_uuid(data[key]) for key in ("operationId", "deviceId", "sessionId"))
            or data["operationId"] != operation_id
            or (requested_device is not None and data["deviceId"] != requested_device)
            or not all(type(data[key]) is int and 0 <= data[key] <= 2**53 - 1 for key in
                       ("sessionGeneration", "authorityGeneration", "targetGeneration")
                       if data[key] is not None)
            or not _uuid(meta["requestId"]) or meta["requestId"] != operation_id
            or meta["tool"] != PEER_TOOL_NAME or meta["riskLevel"] != "SENSITIVE"
            or meta["protocolVersion"] != PEER_PROTOCOL
            or type(meta["durationMs"]) is not int or not 0 <= meta["durationMs"] <= 2**53 - 1
            or ("deviceId" in meta and meta["deviceId"] != data["deviceId"])
            or (requested_device is not None and meta.get("deviceId") != requested_device)
            or meta.get("sessionId") != data["sessionId"]):
        return None
    timestamp = meta["timestamp"]
    if type(timestamp) is not str or len(timestamp) > 64 or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", timestamp):
        return None
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    input_outcome, post_outcome, category = (data[key] for key in
                                             ("inputOutcome", "postOutcome", "evidenceCategory"))
    if input_outcome not in {"NO_INPUT", "ONE_INPUT", "UNCERTAIN"} or post_outcome not in {
            "VERIFIED", "UNVERIFIED", "UNAVAILABLE"}:
        return None
    if ((category == "OWNED_TRANSITION") != (input_outcome == "ONE_INPUT")
            or (category == "TRANSITION_UNCERTAIN") != (input_outcome == "UNCERTAIN" and
                                                         data["sessionGeneration"] is not None)
            or (input_outcome == "NO_INPUT" and
                (category not in _NO_INPUT_CATEGORIES or post_outcome != "UNAVAILABLE"))):
        return None
    host_uncertain = category == "HOST_RECEIPT_UNAVAILABLE"
    generations = (data[key] for key in ("sessionGeneration", "authorityGeneration", "targetGeneration"))
    if (host_uncertain and (input_outcome != "UNCERTAIN" or post_outcome != "UNAVAILABLE"
                            or any(item is not None for item in generations))) or (
            not host_uncertain and any(data[key] is None for key in
                                       ("sessionGeneration", "authorityGeneration", "targetGeneration"))):
        return None
    decision = "ALLOW" if input_outcome == "ONE_INPUT" else "DENY" if input_outcome == "NO_INPUT" else "UNAVAILABLE"
    if meta["permissionDecision"] != decision:
        return None
    return data


class CompanionMcpCaller:
    """One SDK call over an explicit loopback endpoint; no tool fallback."""

    async def __call__(self, config: Config, arguments: dict[str, Any]) -> dict[str, Any]:
        import httpx2
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        async with httpx2.AsyncClient(
                headers={"Authorization": "Bearer " + config.bearer},
                timeout=httpx2.Timeout(CALL_TIMEOUT_SECONDS),
                follow_redirects=False, trust_env=False) as client:
            async with streamable_http_client(config.url, http_client=client,
                                              terminate_on_close=False) as (read, write):
                async with ClientSession(read, write,
                                         read_timeout_seconds=CALL_TIMEOUT_SECONDS) as session:
                    await session.initialize()
                    result = await session.call_tool(PEER_TOOL_NAME, arguments,
                                                     read_timeout_seconds=CALL_TIMEOUT_SECONDS)
                    return {"is_error": result.is_error,
                            "structured_content": result.structured_content}


class CompanionOwnedExecutor:
    """Single-use request ledger; repeated deliveries never invoke the peer twice."""

    def __init__(self, *, caller=None, environment=None, operation_factory=uuid4, clock=time.monotonic):
        self._caller = caller if caller is not None else CompanionMcpCaller()
        self._environment = environment
        self._operation_factory = operation_factory
        self._clock = clock
        self._lock = threading.Lock()
        self._attempts: dict[str, tuple[tuple[str, int, str | None], str, dict[str, Any] | None]] = {}

    async def execute(self, value: Any) -> dict[str, Any]:
        parsed = parse_request(value)
        if parsed is None:
            return _result(None, None, None, None, "NO_INPUT", "UNAVAILABLE", "INVALID_REQUEST")
        request_id, ttl, device_id = parsed
        with self._lock:
            prior = self._attempts.get(request_id)
            if prior is not None:
                old_request, operation_id, completed = prior
                if old_request != parsed or completed is None:
                    return _uncertain(request_id, operation_id, old_request[2])
                return dict(completed)
            if len(self._attempts) >= MAX_ATTEMPTS:
                return _result(request_id, None, device_id, None,
                               "NO_INPUT", "UNAVAILABLE", "HOST_ATTEMPT_LIMIT")
            operation_id = str(self._operation_factory())
            if not _uuid(operation_id):
                return _result(request_id, None, device_id, None,
                               "NO_INPUT", "UNAVAILABLE", "HOST_OPERATION_UNAVAILABLE")
            self._attempts[request_id] = (parsed, operation_id, None)
        try:
            config = load_config(self._environment)
            if config is None:
                result = _result(request_id, operation_id, device_id, None,
                                 "NO_INPUT", "UNAVAILABLE", "HOST_CONFIG_UNAVAILABLE")
            else:
                arguments = {"operationId": operation_id, "ttlMillis": ttl}
                if device_id is not None:
                    arguments["deviceId"] = device_id
                started = self._clock()
                raw = await asyncio.wait_for(self._caller(config, arguments), CALL_TIMEOUT_SECONDS)
                data = _valid_receipt(raw, operation_id, device_id)
                if data is None or self._clock() - started >= CALL_TIMEOUT_SECONDS:
                    result = _uncertain(request_id, operation_id, device_id)
                else:
                    result = _result(request_id, operation_id, data["deviceId"], data["sessionId"],
                                     data["inputOutcome"], data["postOutcome"], data["evidenceCategory"])
        except (Exception, asyncio.CancelledError):
            # A dispatch may have reached Companion. Never reveal errors or retry.
            result = _uncertain(request_id, operation_id, device_id)
        with self._lock:
            self._attempts[request_id] = (parsed, operation_id, result)
        return dict(result)
