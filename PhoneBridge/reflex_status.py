"""Passive host contract evidence only. No device/backend access or permission grant."""
from uuid import UUID, uuid4

from reflex_tap import CONTRACT, POLICY_CONTRACT, RuntimePolicy, contract_manifest, load_runtime_policy

STATUS_TOOL_NAME = "get_android_reflex_status"
STATUS_CONTRACT = "phonebridge.reflex.status.v1"
EPOCH_SCOPE = "executor_instance_metadata_only"
BACKEND_SCOPE = "reviewed_atomic_reflex_backend"


def _valid_epoch(value):
    if type(value) is not str or len(value) != 36:
        return False
    try:
        return str(UUID(value)) == value and UUID(value).version == 4
    except ValueError:
        return False


def attach_runtime_epoch(executor):
    """Attach host-only metadata once; never change the execution request or receipt."""
    epoch = vars(executor).get("runtime_epoch")
    if epoch is None:
        epoch = str(uuid4())
        executor.runtime_epoch = epoch
    if not _valid_epoch(epoch):
        raise ValueError("STATUS_UNAVAILABLE")
    return epoch


def read_status(runtime_epoch):
    """Read only the existing fixed local policy; never invoke executor callbacks."""
    if not _valid_epoch(runtime_epoch):
        raise ValueError("STATUS_UNAVAILABLE")
    try:
        policy = load_runtime_policy()
        if type(policy) is not RuntimePolicy or not policy.valid():
            policy = RuntimePolicy()
    except Exception:
        # Do not surface a raw path, policy value, or parser/provider exception.
        policy = RuntimePolicy()
    manifest = contract_manifest()
    return {
        "schema_version": STATUS_CONTRACT,
        "semantic_tap_contract": CONTRACT,
        "policy_contract": POLICY_CONTRACT,
        "runtime_epoch": runtime_epoch,
        "runtime_epoch_scope": EPOCH_SCOPE,
        "policy_enabled": policy.enabled,
        "allowed_ref_count": len(policy.allowed_binding_ids),
        "stock_adb_atomic_context_guard": manifest["stock_adb_atomic_context_guard"],
        # The v2 non-atomic guarded wrapper is implemented. It is not a bound,
        # reviewed atomic Reflex backend. No status call probes or binds one.
        "production_backend_bound": False,
        "production_backend_scope": BACKEND_SCOPE,
        "live_reflex_ready": manifest["live_reflex_ready"],
        "expected_post_predicates": manifest["expected_post_predicates"],
        "operation_correlation": True,
        "request_correlation": True,
        "observation_correlation": True,
        "durable_exactly_once": manifest["durable_exactly_once"],
        "automatic_action_retry": manifest["automatic_action_retry"],
    }


def status_schema():
    properties = {
        "schema_version": {"const": STATUS_CONTRACT},
        "semantic_tap_contract": {"const": CONTRACT},
        "policy_contract": {"const": POLICY_CONTRACT},
        "runtime_epoch": {"type": "string", "format": "uuid", "minLength": 36, "maxLength": 36,
                          "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"},
        "runtime_epoch_scope": {"const": EPOCH_SCOPE},
        "policy_enabled": {"type": "boolean"},
        "allowed_ref_count": {"type": "integer", "minimum": 0, "maximum": 32},
        "stock_adb_atomic_context_guard": {"const": False},
        "production_backend_bound": {"const": False},
        "production_backend_scope": {"const": BACKEND_SCOPE},
        "live_reflex_ready": {"const": False},
        "expected_post_predicates": {"const": True},
        "operation_correlation": {"const": True},
        "request_correlation": {"const": True},
        "observation_correlation": {"const": True},
        "durable_exactly_once": {"const": False},
        "automatic_action_retry": {"const": False},
    }
    return {"type": "object", "additionalProperties": False,
            "required": list(properties), "properties": properties}

