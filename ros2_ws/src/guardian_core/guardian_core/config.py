"""Configuration adapters for the ROS 2 Guardian runtime."""
from __future__ import annotations

import json
from typing import Any

from .models import ActionType, ContainmentPolicy


DEFAULT_CONTAINMENT_POLICY_JSON = (
    '{"default":{"action":"ISOLATE_COMPONENT","speed_limit":0.15,"mission_allowed":false}}'
)
DEFAULT_SECURITY_PROFILE_JSON = (
    '{"profile_id":"amr-default","adapter_id":"default-actuator",'
    '"trusted_sources":["scenario_injector","amr_simulator"],'
    '"resources":{"left_wheels":{"tau":2,"epsilon":0,"mitigatable":true},'
    '"right_wheels":{"tau":2,"epsilon":0,"mitigatable":true},'
    '"left_arm":{"tau":1,"epsilon":0,"mitigatable":true},'
    '"right_arm":{"tau":1,"epsilon":0,"mitigatable":true},'
    '"left_gripper":{"tau":2,"epsilon":0,"mitigatable":true},'
    '"right_gripper":{"tau":1,"epsilon":0,"mitigatable":true},'
    '"distance_sensor":{"tau":0,"epsilon":0,"mitigatable":false}}}'
)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate containment JSON key")
        result[key] = value
    return result


def parse_containment_policies(
    payload: str,
) -> tuple[dict[tuple[str, str], ContainmentPolicy], ContainmentPolicy]:
    """Parse the bounded JSON policy parameter used by ROS 2 YAML files."""
    raw: Any = json.loads(payload, object_pairs_hook=_unique_json_object)
    if not isinstance(raw, dict):
        raise ValueError("containment_policy_json must be a JSON object")

    policies: dict[tuple[str, str], ContainmentPolicy] = {}
    default = ContainmentPolicy(ActionType.ISOLATE_COMPONENT, 0.15, False)
    for attack_type, value in raw.items():
        if not isinstance(attack_type, str) or not isinstance(value, dict):
            raise ValueError("containment policy keys and values must be objects")
        if "action" in value:
            policy = _policy_from_mapping(value)
            if attack_type == "default":
                default = policy
            else:
                policies[(attack_type, "*")] = policy
            continue
        seen_phases: set[str] = set()
        for phase, phase_value in value.items():
            if not isinstance(phase, str) or not isinstance(phase_value, dict):
                raise ValueError("phase containment policies must be objects")
            normalized_phase = "*" if phase == "default" else phase
            if normalized_phase in seen_phases:
                raise ValueError("duplicate normalized containment phase")
            seen_phases.add(normalized_phase)
            policy = _policy_from_mapping(phase_value)
            if attack_type == "default" and normalized_phase == "*":
                default = policy
            else:
                policies[(attack_type, normalized_phase)] = policy
    return policies, default


def _policy_from_mapping(value: dict[str, Any]) -> ContainmentPolicy:
    try:
        action = ActionType(str(value["action"]))
        speed_limit = value["speed_limit"]
        mission_allowed = value["mission_allowed"]
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("containment policy requires action, speed_limit and mission_allowed") from error
    if not isinstance(mission_allowed, bool):
        raise ValueError("containment policy mission_allowed must be boolean")
    return ContainmentPolicy(action, speed_limit, mission_allowed)
