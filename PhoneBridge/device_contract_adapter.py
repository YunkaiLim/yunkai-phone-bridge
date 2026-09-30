from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
from typing import Any


_SHARED_ROOT = Path(__file__).resolve().parent.parent
if str(_SHARED_ROOT) not in sys.path:
    sys.path.insert(0, str(_SHARED_ROOT))

from yunkai_shared.device_contract import (  # noqa: E402 - shared root is added above
    CAPABILITY_AVAILABILITY_VALUES,
    CAPABILITY_MANIFEST_SCHEMA_VERSION,
    CAPABILITY_STATE_SCHEMA_VERSION,
    DEVICE_CONTRACT_SCHEMA_VERSION,
    PERMISSION_STATE_SCHEMA_VERSION,
    PERMISSION_STATE_VALUES,
    PLANNER_ROUTING_SCHEMA_VERSION,
    DeviceIdentity,
    build_device_snapshot,
)
from yunkai_shared.runtime_policy import (  # noqa: E402 - shared root is added above
    RUNTIME_POLICY_SCHEMA_VERSION,
    runtime_policy_manifest,
)
from yunkai_shared.verification_contract import (  # noqa: E402 - shared root is added above
    CONTRACT_SCHEMA_VERSION,
)


PHONE_BRIDGE_VERSION = "0.7.2"

_CAPABILITY_GROUPS: dict[str, tuple[str, ...]] = {
    "connection": (
        "phone.connection.wireless_status",
        "phone.connection.wireless_pair",
        "phone.connection.wireless_connect",
        "phone.connection.wireless_refresh",
        "phone.connection.wireless_disconnect",
    ),
    "perception": (
        "phone.device.list",
        "phone.screen.size",
        "phone.screen.capture",
        "phone.app.current",
        "phone.device.state",
        "phone.uia.inspect",
        "phone.fast_context",
        "phone.local_vision_fallback",
    ),
    "interaction": (
        "phone.touch.tap",
        "phone.touch.long_press",
        "phone.touch.long_press_verified",
        "phone.touch.swipe",
        "phone.touch.swipe_direction",
        "phone.touch.tap_verified",
        "phone.touch.swipe_verified",
        "phone.touch.swipe_direction_verified",
        "phone.game.joystick_move",
        "phone.game.camera_drag",
        "phone.keyboard.type",
        "phone.keyboard.type_verified",
        "phone.keyboard.safe_key",
        "phone.keyboard.safe_key_verified",
        "phone.app.launch",
        "phone.app.launch_verified",
        "phone.uia.semantic_tap",
    ),
    "verification": (
        "phone.state_change.verify",
        "phone.uia.wait_condition",
    ),
    "automation": (
        "phone.automation.status",
        "phone.automation.daily_routine",
    ),
}

_REQUIRED_TIERS: dict[str, str] = {
    "phone.connection.wireless_status": "observe",
    "phone.connection.wireless_pair": "interact",
    "phone.connection.wireless_connect": "interact",
    "phone.connection.wireless_refresh": "interact",
    "phone.connection.wireless_disconnect": "interact",
    **{capability: "observe" for capability in _CAPABILITY_GROUPS["perception"]},
    **{capability: "interact" for capability in _CAPABILITY_GROUPS["interaction"]},
    "phone.game.joystick_move": "elevated_input",
    "phone.game.camera_drag": "elevated_input",
    "phone.state_change.verify": "observe",
    "phone.uia.wait_condition": "observe",
    "phone.automation.status": "observe",
    "phone.automation.daily_routine": "interact",
}

_SAFETY_INVARIANTS: dict[str, bool] = {
    "arbitrary_shell_exposed": False,
    "file_delete_exposed": False,
    "software_uninstall_exposed": False,
    "clear_app_data_exposed": False,
    "root_device_exposed": False,
    "apk_install_exposed": False,
    "caller_selectable_runtime_profile": False,
    "verified_action_loop_supported": True,
    "legacy_action_authority_unchanged": True,
    "runtime_permission_enforced_by_legacy_actions": False,
    "wireless_pairing_code_persisted": False,
    "wireless_public_endpoint_allowed": False,
    "automatic_wireless_transport_reconnect_only": True,
}


def phone_runtime_policy() -> dict[str, Any]:
    """Return the standard phone interaction policy while keeping game input elevated."""

    policy = runtime_policy_manifest("standard")
    policy.update(
        {
            "profile_source": "unified_contract_compatibility_adapter",
            "enforcement_scope": "unified_planner_routing_only",
            "legacy_action_authority_unchanged": True,
            "bridge_enforced_for_existing_actions": False,
        }
    )
    return policy


def phone_capability_manifest() -> dict[str, Any]:
    manifest = {
        "schema_version": CAPABILITY_MANIFEST_SCHEMA_VERSION,
        "bridge": {
            "id": "phone.android",
            "name": "Yunkai Phone Bridge",
            "version": PHONE_BRIDGE_VERSION,
            "device_class": "phone",
            "platform": "android",
        },
        "adapter": {
            "role": "compatibility_device_adapter",
            "transport": "mcp",
            "transport_is_device_identity": False,
            "tool_catalog_authoritative": False,
        },
        "contract_versions": {
            "device_contract": DEVICE_CONTRACT_SCHEMA_VERSION,
            "capability_manifest": CAPABILITY_MANIFEST_SCHEMA_VERSION,
            "capability_state": CAPABILITY_STATE_SCHEMA_VERSION,
            "permission_state": PERMISSION_STATE_SCHEMA_VERSION,
            "planner_routing": PLANNER_ROUTING_SCHEMA_VERSION,
            "verification": CONTRACT_SCHEMA_VERSION,
            "runtime_policy": RUNTIME_POLICY_SCHEMA_VERSION,
            "action_audit": 0,
            "operation_trace": 0,
        },
        "capability_groups": {
            group: list(capabilities) for group, capabilities in _CAPABILITY_GROUPS.items()
        },
        "feature_flags": {
            "uiautomator_semantics": True,
            "local_vision_fallback": True,
            "state_change_verification": True,
            "verified_action_loop": True,
            "directional_swipe": True,
            "wait_for_ui_condition": True,
            "verified_text_input": True,
            "verified_safe_key": True,
            "verified_long_press": True,
            "wireless_adb": True,
            "wireless_mdns_discovery": True,
            "wireless_auto_reconnect": True,
            "wireless_pairing_code_persisted": False,
            "expected_post_predicates": False,
            "bounded_observation_stabilization": True,
            "automatic_action_retry": False,
            "action_audit": False,
            "operation_trace": False,
            "unified_device_contract": True,
        },
        "permission_model": {
            "capabilities_are_permissions": False,
            "separate_runtime_policy": True,
            "runtime_policy_manifest_field": "runtime_policy",
            "caller_selectable_profile": False,
            "compatibility_default": "standard",
            "legacy_action_enforcement_unchanged": True,
        },
        "safety_invariants": dict(_SAFETY_INVARIANTS),
    }
    return deepcopy(manifest)


def phone_capability_state(
    *,
    vision_recommended: bool,
    local_vision_status: dict[str, Any],
) -> dict[str, Any]:
    local_status = dict(local_vision_status or {})
    local_configured = bool(local_status.get("configured"))
    local_enabled = bool(local_status.get("enabled"))
    local_error = str(local_status.get("error") or "").strip()
    states: dict[str, dict[str, Any]] = {}
    availability_counts = {value: 0 for value in CAPABILITY_AVAILABILITY_VALUES}

    for group, capability_ids in _CAPABILITY_GROUPS.items():
        for capability_id in capability_ids:
            availability = "available"
            reason_code = "implemented"
            reason = "PhoneBridge capability is implemented and the current context call succeeded."
            basis = "bridge_runtime"

            if capability_id in {"phone.uia.inspect", "phone.uia.semantic_tap"}:
                basis = "current_surface"
                if vision_recommended:
                    availability = "degraded"
                    reason_code = "uia_surface_sparse"
                    reason = (
                        "UIAutomator is reachable, but the current Android surface exposes sparse semantics."
                    )

            if capability_id == "phone.local_vision_fallback":
                basis = "configuration_only"
                if local_error:
                    availability = "unavailable"
                    reason_code = "local_vision_configuration_error"
                    reason = "Local vision configuration is invalid."
                elif not local_configured or not local_enabled:
                    availability = "unavailable"
                    reason_code = "local_vision_not_configured"
                    reason = "Local vision is supported but not configured and enabled."
                else:
                    reason_code = "local_vision_configured"
                    reason = "Local vision is configured on an allowed localhost endpoint."

            if capability_id.startswith("phone.automation."):
                availability = "degraded"
                reason_code = "optional_control_center_not_probed"
                reason = (
                    "The legacy optional Control Center surface exists, but the compatibility adapter "
                    "does not probe or authorize scheduler execution."
                )
                basis = "declared_without_external_probe"

            states[capability_id] = {
                "group": group,
                "availability": availability,
                "reason_code": reason_code,
                "reason": reason,
                "basis": basis,
            }
            availability_counts[availability] += 1

    surface = {
        "semantic_source": "uiautomator_sparse" if vision_recommended else "uiautomator",
        "vision_recommended": bool(vision_recommended),
        "local_vision_configured": local_configured,
        "local_vision_enabled": local_enabled,
        "local_vision_error_present": bool(local_error),
    }
    probe_semantics = {
        "external_health_checks_performed": False,
        "local_vision_availability_basis": "configuration_only",
        "automation_availability_basis": "declared_without_external_probe",
    }

    return {
        "schema_version": CAPABILITY_STATE_SCHEMA_VERSION,
        "bridge_id": "phone.android",
        "bridge_version": PHONE_BRIDGE_VERSION,
        "device_id": "phone.android",
        "availability_values": list(CAPABILITY_AVAILABILITY_VALUES),
        "availability_independent_from_permission": True,
        "probe_semantics": probe_semantics,
        "surface": surface,
        "summary": {**availability_counts, "total": len(states)},
        "states": states,
        "adapter_context": {
            "surface": surface,
            "probe_semantics": probe_semantics,
        },
    }


def phone_permission_state(runtime_policy: dict[str, Any]) -> dict[str, Any]:
    allowed_tiers = {str(value) for value in runtime_policy.get("allowed_tiers", [])}
    runtime_profile = str(runtime_policy.get("runtime_profile") or "observe_only")
    states: dict[str, dict[str, Any]] = {}
    permission_counts = {value: 0 for value in PERMISSION_STATE_VALUES}
    for capability_id in sorted(_REQUIRED_TIERS):
        required_tier = _REQUIRED_TIERS[capability_id]
        state = "allowed" if required_tier in allowed_tiers else "denied"
        states[capability_id] = {
            "required_tier": required_tier,
            "state": state,
            "runtime_profile": runtime_profile,
        }
        permission_counts[state] += 1
    return {
        "schema_version": PERMISSION_STATE_SCHEMA_VERSION,
        "device_id": "phone.android",
        "permission_values": list(PERMISSION_STATE_VALUES),
        "separate_from_availability": True,
        "states": states,
        "summary": {**permission_counts, "total": len(states)},
    }


def phone_planner_routing_hints(
    *,
    capability_state: dict[str, Any],
    permission_state: dict[str, Any],
    runtime_policy: dict[str, Any],
) -> dict[str, Any]:
    states = dict(capability_state.get("states") or {})
    permissions = dict(permission_state.get("states") or {})

    def availability(capability_id: str) -> str:
        value = str(dict(states.get(capability_id) or {}).get("availability") or "unavailable")
        return value if value in CAPABILITY_AVAILABILITY_VALUES else "unavailable"

    def permitted(capability_id: str) -> bool:
        return dict(permissions.get(capability_id) or {}).get("state") == "allowed"

    def usable(capability_id: str) -> bool:
        return availability(capability_id) != "unavailable" and permitted(capability_id)

    def route(
        *,
        status: str,
        preferred_strategy: str,
        reason_code: str,
        reason: str,
        capability_steps: list[str],
        fallbacks: list[dict[str, Any]] | None = None,
        constraints: list[str] | None = None,
    ) -> dict[str, Any]:
        return {
            "status": status,
            "preferred_strategy": preferred_strategy,
            "reason_code": reason_code,
            "reason": reason,
            "capability_steps": list(capability_steps),
            "fallbacks": list(fallbacks or []),
            "constraints": list(constraints or []),
        }

    routes: dict[str, dict[str, Any]] = {}
    uia_availability = availability("phone.uia.inspect")
    if uia_availability == "available" and permitted("phone.uia.inspect"):
        routes["perception"] = route(
            status="ready",
            preferred_strategy="uiautomator_semantic_first",
            reason_code="uiautomator_informative",
            reason="Use bounded UIAutomator semantics before screenshot or local vision.",
            capability_steps=["phone.fast_context", "phone.uia.inspect"],
            fallbacks=(
                [
                    {
                        "strategy": "local_vision_fallback",
                        "when": "the accessibility tree becomes sparse",
                        "capability_steps": ["phone.local_vision_fallback"],
                    }
                ]
                if availability("phone.local_vision_fallback") == "available"
                and permitted("phone.local_vision_fallback")
                else []
            )
            + [
                {
                    "strategy": "screenshot_reasoning",
                    "when": "semantic context is insufficient",
                    "capability_steps": ["phone.screen.capture"],
                }
            ],
            constraints=["read_only_observation_first"],
        )
    elif usable("phone.local_vision_fallback"):
        routes["perception"] = route(
            status="degraded",
            preferred_strategy="local_vision_after_sparse_uiautomator",
            reason_code="uiautomator_sparse",
            reason="UIAutomator is sparse; use localhost vision only as a perception fallback.",
            capability_steps=["phone.fast_context", "phone.local_vision_fallback"],
            fallbacks=[
                {
                    "strategy": "screenshot_reasoning",
                    "when": "local vision is insufficient",
                    "capability_steps": ["phone.screen.capture"],
                }
            ],
            constraints=["vision_is_not_action_authority"],
        )
    else:
        routes["perception"] = route(
            status="degraded",
            preferred_strategy="screenshot_reasoning",
            reason_code="uiautomator_sparse_local_vision_unavailable",
            reason="UIAutomator is sparse and local vision is unavailable; expose screenshot evidence only.",
            capability_steps=["phone.fast_context", "phone.screen.capture"],
            constraints=["read_only_observation_first"],
        )

    if usable("phone.uia.semantic_tap"):
        routes["semantic_action"] = route(
            status="ready" if availability("phone.uia.semantic_tap") == "available" else "degraded",
            preferred_strategy="unique_uiautomator_target",
            reason_code="semantic_tap_permitted",
            reason="Use one unambiguous UIAutomator target when separately authorized.",
            capability_steps=["phone.uia.semantic_tap", "phone.touch.tap_verified", "phone.uia.wait_condition"],
            constraints=["single_intended_action", "no_automatic_retry", "verify_before_replanning"],
        )
    else:
        routes["semantic_action"] = route(
            status="blocked",
            preferred_strategy="none",
            reason_code="phone_interaction_not_authorized_by_compatibility_policy",
            reason="The compatibility policy does not grant Phone interaction authority.",
            capability_steps=[],
            constraints=["permission_bypass_forbidden", "legacy_tools_are_not_contract_authority"],
        )

    routes["connection"] = route(
        status="ready",
        preferred_strategy="paired_wireless_adb_with_usb_fallback",
        reason_code="wireless_adb_transport_ready",
        reason=(
            "Prefer an already-authorized ADB transport; when none is connected, PhoneBridge may reconnect only "
            "to one unambiguous local mDNS Wireless ADB service."
        ),
        capability_steps=[
            "phone.connection.wireless_status",
            "phone.connection.wireless_refresh",
        ],
        fallbacks=[
            {
                "strategy": "usb_debugging_fallback",
                "when": "wireless debugging is disabled, unavailable, or ambiguous",
                "capability_steps": ["phone.device.list"],
            }
        ],
        constraints=[
            "private_or_link_local_endpoints_only",
            "pairing_code_not_persisted",
            "ambiguous_mdns_fails_closed",
            "transport_reconnect_never_retries_phone_ui_actions",
        ],
    )

    routes["verification"] = route(
        status="ready",
        preferred_strategy="shared_state_change_verification",
        reason_code="shared_verification_ready",
        reason="Use the shared semantic/surface/optional visual state-change verifier.",
        capability_steps=["phone.state_change.verify"],
        constraints=["verification_does_not_trigger_retry", "expected_post_predicates_not_supported"],
    )
    routes["observability"] = route(
        status="blocked",
        preferred_strategy="none",
        reason_code="audit_and_trace_not_supported",
        reason="PhoneBridge does not yet expose shared action audit or operation trace support.",
        capability_steps=[],
        constraints=["do_not_infer_unrecorded_execution"],
    )
    routes["automation"] = route(
        status="blocked",
        preferred_strategy="none",
        reason_code="scheduler_outside_unified_contract_scope",
        reason="The optional legacy Control Center is not authorized through Unified Device Contract v0.1.",
        capability_steps=[],
        constraints=["no_automatic_task_execution", "permission_bypass_forbidden"],
    )

    counts = {"ready": 0, "degraded": 0, "blocked": 0}
    for entry in routes.values():
        counts[entry["status"]] += 1
    return {
        "schema_version": PLANNER_ROUTING_SCHEMA_VERSION,
        "bridge_id": "phone.android",
        "device_id": "phone.android",
        "bridge_version": PHONE_BRIDGE_VERSION,
        "advisory_only": True,
        "planner_owns_final_selection": True,
        "bridge_auto_executes": False,
        "automatic_fallback_execution": False,
        "permission_bypass_allowed": False,
        "tool_catalog_authoritative": False,
        "routing_inputs": {
            "capability_state_schema_version": capability_state.get("schema_version"),
            "permission_state_schema_version": permission_state.get("schema_version"),
            "runtime_policy_schema_version": runtime_policy.get("schema_version"),
            "runtime_profile": runtime_policy.get("runtime_profile"),
            "legacy_action_enforcement_unchanged": True,
        },
        "summary": {**counts, "total": len(routes)},
        "routes": routes,
    }


def phone_device_snapshot(
    *,
    capability_manifest: dict[str, Any],
    capability_state: dict[str, Any],
    permission_state: dict[str, Any],
    planner_routing_hints: dict[str, Any],
    runtime_policy: dict[str, Any],
) -> dict[str, Any]:
    return build_device_snapshot(
        identity=DeviceIdentity(
            device_id="phone.android",
            device_class="phone",
            platform="android",
            display_name="Yunkai Phone Bridge",
            adapter_version=PHONE_BRIDGE_VERSION,
        ),
        adapter={
            "role": "compatibility_device_adapter",
            "transport": "mcp",
            "transport_is_device_identity": False,
            "tool_catalog_authoritative": False,
            "compatibility_source": "phone_fast_context_v0.6",
        },
        contract_versions=capability_manifest["contract_versions"],
        capability_manifest=capability_manifest,
        capability_state=capability_state,
        permission_state=permission_state,
        runtime_policy=runtime_policy,
        planner_routing_hints=planner_routing_hints,
        verification={
            "supported": True,
            "schema_version": CONTRACT_SCHEMA_VERSION,
            "expected_postconditions_supported": False,
            "bounded_observation_stabilization_supported": True,
            "verified_single_action_supported": True,
            "automatic_retry": False,
        },
        observability={
            "audit": {"supported": False, "reason_code": "not_implemented"},
            "operation_trace": {"supported": False, "reason_code": "not_implemented"},
        },
        safety_invariants=_SAFETY_INVARIANTS,
    )


def phone_contract_surfaces(
    *,
    vision_recommended: bool,
    local_vision_status: dict[str, Any],
) -> dict[str, Any]:
    """Build all planner-facing surfaces without probing or acting on a device."""

    manifest = phone_capability_manifest()
    runtime_policy = phone_runtime_policy()
    capability_state = phone_capability_state(
        vision_recommended=vision_recommended,
        local_vision_status=local_vision_status,
    )
    permission_state = phone_permission_state(runtime_policy)
    routing = phone_planner_routing_hints(
        capability_state=capability_state,
        permission_state=permission_state,
        runtime_policy=runtime_policy,
    )
    snapshot = phone_device_snapshot(
        capability_manifest=manifest,
        capability_state=capability_state,
        permission_state=permission_state,
        planner_routing_hints=routing,
        runtime_policy=runtime_policy,
    )
    return {
        "capability_manifest": manifest,
        "capability_state": capability_state,
        "planner_routing_hints": routing,
        "runtime_policy": runtime_policy,
        "device_snapshot": snapshot,
    }
