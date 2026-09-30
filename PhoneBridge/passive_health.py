"""Loopback-only passive HTTP metadata. No device, action, log or model calls."""
from datetime import datetime, timezone
import json
import re
from uuid import UUID

from starlette.requests import Request
from starlette.responses import Response

from device_contract_adapter import PHONE_BRIDGE_VERSION
import reflex_mcp
from reflex_status import read_status

SERVICE = "yunkai-phonebridge"
HEALTH_CONTRACT = "phonebridge.health.v1"
REVIEWED_SERVICE_VERSION = "0.7.2"
MAX_HEALTH_BYTES = 2048
HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}

# Consumer identity pins, not a second runtime policy. Unknown producer shape or
# capabilities require review; malformed evidence never becomes cached readiness.
_STATUS_CONSTANTS = {
    "schema_version": "phonebridge.reflex.status.v1",
    "semantic_tap_contract": "phonebridge.reflex.semantic_tap.v2",
    "policy_contract": "phonebridge.reflex.policy.v1",
    "runtime_epoch_scope": "executor_instance_metadata_only",
    "production_backend_scope": "reviewed_atomic_reflex_backend",
    "stock_adb_atomic_context_guard": False,
    "production_backend_bound": False,
    "live_reflex_ready": False,
    "expected_post_predicates": True,
    "operation_correlation": True,
    "request_correlation": True,
    "observation_correlation": True,
    "durable_exactly_once": False,
    "automatic_action_retry": False,
}


def _loopback_request(request):
    scope = request.scope
    if (scope.get("type") != "http" or scope.get("scheme") != "http"
            or scope.get("path") != "/health" or scope.get("query_string", b"") != b""):
        return False
    peer, local = scope.get("client"), scope.get("server")
    if (type(peer) is not tuple or len(peer) != 2 or peer[0] not in ("127.0.0.1", "::1")
            or type(peer[1]) is not int or not 0 <= peer[1] <= 65535
            or type(local) is not tuple or len(local) != 2 or local[0] not in ("127.0.0.1", "::1")
            or type(local[1]) is not int or not 1 <= local[1] <= 65535):
        return False
    headers = scope.get("headers")
    if type(headers) is not list or len(headers) > 64:
        return False
    hosts, origins = [], []
    for row in headers:
        if type(row) is not tuple or len(row) != 2 or not all(type(item) is bytes for item in row):
            return False
        name, value = row[0].lower(), row[1]
        if name == b"forwarded" or name.startswith(b"x-forwarded-"):
            return False
        if name == b"host":
            hosts.append(value)
        elif name == b"origin":
            origins.append(value)
    if len(hosts) != 1 or len(origins) > 1:
        return False
    port = local[1]
    authorities = {f"{host}:{port}".encode("ascii") for host in ("127.0.0.1", "[::1]", "localhost")}
    if port == 80:
        authorities.update((b"127.0.0.1", b"[::1]", b"localhost"))
    return (hosts[0] in authorities and
            (not origins or origins[0] == b"http://" + hosts[0]))


def _valid_status(status, epoch):
    if type(status) is not dict or len(status) != len(_STATUS_CONSTANTS) + 3 or set(status) != set(_STATUS_CONSTANTS) | {
            "runtime_epoch", "policy_enabled", "allowed_ref_count"}:
        return False
    if any(type(status[key]) is not type(value) or status[key] != value
           for key, value in _STATUS_CONSTANTS.items()):
        return False
    if (type(epoch) is not str or len(epoch) != 36 or status["runtime_epoch"] != epoch
            or type(status["runtime_epoch"]) is not str):
        return False
    try:
        if str(UUID(epoch)) != epoch or UUID(epoch).version != 4:
            return False
    except ValueError:
        return False
    return (type(status["policy_enabled"]) is bool and type(status["allowed_ref_count"]) is int
            and 0 <= status["allowed_ref_count"] <= 32)


def _observed_at():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _valid_timestamp(value):
    if (type(value) is not str or len(value) != 24
            or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value, flags=re.ASCII) is None):
        return False
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
        return True
    except ValueError:
        return False


def health_schema():
    properties = {
        "service": {"const": SERVICE},
        "schema_version": {"const": HEALTH_CONTRACT},
        "version": {"const": REVIEWED_SERVICE_VERSION},
        "localhost_only": {"const": True},
        "observed_at": {"type": "string", "format": "date-time", "minLength": 24, "maxLength": 24,
                        "pattern": r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"},
        "status": {"const": "ok"},
        "reflex_status_contract": {"const": _STATUS_CONSTANTS["schema_version"]},
        "runtime_epoch": {"type": "string", "format": "uuid", "minLength": 36, "maxLength": 36,
                          "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"},
        "policy_enabled": {"type": "boolean"},
        "allowed_ref_count": {"type": "integer", "minimum": 0, "maximum": 32},
        "production_atomic_context_guard": {"const": False},
    }
    for key in ("production_backend_bound", "live_reflex_ready", "expected_post_predicates",
                "operation_correlation", "request_correlation", "observation_correlation",
                "durable_exactly_once", "automatic_action_retry"):
        properties[key] = {"const": _STATUS_CONSTANTS[key]}
    return {"type": "object", "additionalProperties": False,
            "required": list(properties), "properties": properties}


async def get_health(request: Request) -> Response:
    try:
        if request.method != "GET":
            return Response(b"", status_code=405, headers={**HEADERS, "Allow": "GET"})
        if not _loopback_request(request):
            return Response(b"", status_code=403, headers=HEADERS)
        executor = reflex_mcp.executor
        epoch = vars(executor).get("runtime_epoch")
        status = read_status(epoch)
        # Preserve the same in-process executor epoch, with no second executor,
        # callback, backend probe, or historical/last-known-good status cache.
        if (reflex_mcp.executor is not executor or vars(executor).get("runtime_epoch") != epoch
                or PHONE_BRIDGE_VERSION != REVIEWED_SERVICE_VERSION
                or type(PHONE_BRIDGE_VERSION) is not str or not _valid_status(status, epoch)):
            return Response(b"", status_code=503, headers=HEADERS)
        observed_at = _observed_at()
        if not _valid_timestamp(observed_at):
            return Response(b"", status_code=503, headers=HEADERS)
        value = {
            "service": SERVICE, "schema_version": HEALTH_CONTRACT, "version": PHONE_BRIDGE_VERSION,
            "localhost_only": True, "observed_at": observed_at, "status": "ok",
            "reflex_status_contract": status["schema_version"], "runtime_epoch": epoch,
            "policy_enabled": status["policy_enabled"], "allowed_ref_count": status["allowed_ref_count"],
            "production_atomic_context_guard": status["stock_adb_atomic_context_guard"],
        }
        for key in ("production_backend_bound", "live_reflex_ready", "expected_post_predicates",
                    "operation_correlation", "request_correlation", "observation_correlation",
                    "durable_exactly_once", "automatic_action_retry"):
            value[key] = status[key]
        body = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")
        if len(body) > MAX_HEALTH_BYTES:
            return Response(b"", status_code=503, headers=HEADERS)
        return Response(body, media_type="application/json", headers=HEADERS)
    except Exception:
        # No errors, paths, policy contents or stale device state reach the wire.
        return Response(b"", status_code=503, headers=HEADERS)

