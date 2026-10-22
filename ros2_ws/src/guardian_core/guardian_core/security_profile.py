from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, FrozenSet, Mapping


_PROFILE_FIELD_LIMITS = {
    "profile_id": 96,
    "adapter_id": 96,
}
_RESOURCE_NAME_LIMIT = 96
_SOURCE_NAME_LIMIT = 64


@dataclass(frozen=True)
class ResourcePolicy:
    name: str
    tau: int
    epsilon: int
    mitigatable: bool


@dataclass(frozen=True)
class SecurityProfile:
    profile_id: str
    adapter_id: str
    trusted_sources: FrozenSet[str]
    resources: Mapping[str, ResourcePolicy]

    @property
    def tau(self) -> dict[str, int]:
        return {name: resource.tau for name, resource in self.resources.items()}

    @property
    def epsilon(self) -> dict[str, int]:
        return {name: resource.epsilon for name, resource in self.resources.items()}

    @property
    def mitigatable_devices(self) -> FrozenSet[str]:
        return frozenset(
            name for name, resource in self.resources.items() if resource.mitigatable
        )


def parse_security_profile(payload: str) -> SecurityProfile:
    """Parse a strict, device-neutral ROS 2 Guardian resource profile."""
    try:
        raw: Any = json.loads(payload, object_pairs_hook=_unique_profile_object)
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError("invalid security profile JSON") from error
    if not isinstance(raw, dict):
        raise ValueError("security profile must be a JSON object")

    profile_id = _bounded_string(raw.get("profile_id"), "profile_id", _PROFILE_FIELD_LIMITS["profile_id"])
    adapter_id = _bounded_string(raw.get("adapter_id"), "adapter_id", _PROFILE_FIELD_LIMITS["adapter_id"])
    trusted_sources = _parse_names(raw.get("trusted_sources"), "trusted_sources", _SOURCE_NAME_LIMIT)
    resources_value = raw.get("resources")
    if not isinstance(resources_value, dict) or not resources_value:
        raise ValueError("security profile resources must be a non-empty object")

    resources: dict[str, ResourcePolicy] = {}
    for name, value in resources_value.items():
        resource_name = _bounded_string(name, "resource name", _RESOURCE_NAME_LIMIT)
        if not isinstance(value, dict):
            raise ValueError("security resource values must be objects")
        if set(value) != {"tau", "epsilon", "mitigatable"}:
            raise ValueError(
                f"security resource {resource_name!r} requires only tau, epsilon and mitigatable"
            )
        tau = _bounded_level(value["tau"], f"{resource_name}.tau")
        epsilon = _bounded_level(value["epsilon"], f"{resource_name}.epsilon")
        if type(value["mitigatable"]) is not bool:
            raise ValueError(f"{resource_name}.mitigatable must be boolean")
        resources[resource_name] = ResourcePolicy(
            resource_name, tau, epsilon, value["mitigatable"]
        )

    return SecurityProfile(
        profile_id=profile_id,
        adapter_id=adapter_id,
        trusted_sources=frozenset(trusted_sources),
        resources=resources,
    )


def _unique_profile_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate security profile key")
        result[key] = value
    return result


def _bounded_string(value: Any, name: str, limit: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > limit
        or value != value.strip()
        or "|" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError(f"{name} must be a bounded non-empty string")
    return value


def _parse_names(value: Any, name: str, limit: int) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{name} must be a non-empty string array")
    names = [_bounded_string(item, name, limit) for item in value]
    if len(set(names)) != len(names):
        raise ValueError(f"{name} must not contain duplicates")
    return names


def _bounded_level(value: Any, name: str) -> int:
    if type(value) is not int or value < 0 or value > 2:
        raise ValueError(f"{name} must be an integer in [0, 2]")
    return value
