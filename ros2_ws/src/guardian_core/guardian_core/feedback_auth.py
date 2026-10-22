"""Message-level authentication for Guardian command and feedback topics."""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
from collections.abc import Iterable


def _payload(kind: str, fields: dict[str, object]) -> bytes:
    return json.dumps(
        {"kind": kind, **fields},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _sign(secret: bytes, kind: str, fields: dict[str, object]) -> str:
    return hmac.new(secret, _payload(kind, fields), hashlib.sha256).hexdigest()


def _verify(secret: bytes | None, kind: str, fields: dict[str, object], signature: str) -> bool:
    if not secret or not isinstance(signature, str) or not signature.isascii():
        return False
    expected = _sign(secret, kind, fields)
    return hmac.compare_digest(expected, signature)


def _components(values: Iterable[object]) -> list[str]:
    return sorted(str(value) for value in values)


def _float32(value: float) -> float:
    return struct.unpack("!f", struct.pack("!f", float(value)))[0]


def sign_command(
    secret: bytes,
    *,
    timestamp: float,
    profile_id: str,
    command_epoch: int,
    transmission_id: int,
    adapter_id: str,
    plan_id: str,
    action: str,
    components: Iterable[object],
    requires_safe_stop: bool,
) -> str:
    return _sign(secret, "mitigation_command", {
        "timestamp": float(timestamp),
        "profile_id": profile_id,
        "command_epoch": int(command_epoch),
        "transmission_id": int(transmission_id),
        "adapter_id": adapter_id,
        "plan_id": plan_id,
        "action": action,
        "components": _components(components),
        "requires_safe_stop": bool(requires_safe_stop),
    })


def verify_command(secret: bytes | None, signature: str, **fields: object) -> bool:
    if "timestamp" not in fields:
        return False
    fields = {
        "timestamp": float(fields["timestamp"]),
        "profile_id": str(fields["profile_id"]),
        "command_epoch": int(fields["command_epoch"]),
        "transmission_id": int(fields["transmission_id"]),
        "adapter_id": str(fields["adapter_id"]),
        "plan_id": str(fields["plan_id"]),
        "action": str(fields["action"]),
        "components": _components(fields["components"]),  # type: ignore[arg-type]
        "requires_safe_stop": bool(fields["requires_safe_stop"]),
    }
    return _verify(secret, "mitigation_command", fields, signature)


def sign_ack(
    secret: bytes,
    *,
    profile_id: str,
    command_epoch: int,
    transmission_id: int,
    feedback_sequence: int,
    adapter_id: str,
    plan_id: str,
    action: str,
    components: Iterable[object],
    accepted: bool,
    active: bool,
    safe_stop_confirmed: bool,
) -> str:
    return _sign(secret, "mitigation_ack", {
        "profile_id": profile_id,
        "command_epoch": int(command_epoch),
        "transmission_id": int(transmission_id),
        "feedback_sequence": int(feedback_sequence),
        "adapter_id": adapter_id,
        "plan_id": plan_id,
        "action": action,
        "components": _components(components),
        "accepted": bool(accepted),
        "active": bool(active),
        "safe_stop_confirmed": bool(safe_stop_confirmed),
    })


def verify_ack(secret: bytes | None, signature: str, **fields: object) -> bool:
    expected_fields = {
        "profile_id": str(fields["profile_id"]),
        "command_epoch": int(fields["command_epoch"]),
        "transmission_id": int(fields["transmission_id"]),
        "feedback_sequence": int(fields["feedback_sequence"]),
        "adapter_id": str(fields["adapter_id"]),
        "plan_id": str(fields["plan_id"]),
        "action": str(fields["action"]),
        "components": _components(fields["components"]),  # type: ignore[arg-type]
        "accepted": bool(fields["accepted"]),
        "active": bool(fields["active"]),
        "safe_stop_confirmed": bool(fields["safe_stop_confirmed"]),
    }
    return _verify(secret, "mitigation_ack", expected_fields, signature)


def sign_status(
    secret: bytes,
    *,
    timestamp: float,
    profile_id: str,
    command_epoch: int,
    transmission_id: int,
    adapter_id: str,
    state: str,
    speed_limit: float,
    mission_allowed: bool,
    plan_id: str,
) -> str:
    return _sign(secret, "safety_status", {
        "timestamp": float(timestamp),
        "profile_id": profile_id,
        "command_epoch": int(command_epoch),
        "transmission_id": int(transmission_id),
        "adapter_id": adapter_id,
        "state": state,
        "speed_limit": _float32(float(speed_limit)),
        "mission_allowed": bool(mission_allowed),
        "plan_id": plan_id,
    })


def verify_status(secret: bytes | None, signature: str, **fields: object) -> bool:
    if "timestamp" not in fields:
        return False
    expected_fields = {
        "timestamp": float(fields["timestamp"]),
        "profile_id": str(fields["profile_id"]),
        "command_epoch": int(fields["command_epoch"]),
        "transmission_id": int(fields["transmission_id"]),
        "adapter_id": str(fields["adapter_id"]),
        "state": str(fields["state"]),
        "speed_limit": _float32(float(fields["speed_limit"])),
        "mission_allowed": bool(fields["mission_allowed"]),
        "plan_id": str(fields["plan_id"]),
    }
    return _verify(secret, "safety_status", expected_fields, signature)


RECOVERY_TELEMETRY_FIELDS = (
    "timestamp", "profile_id", "adapter_id", "command_epoch", "transmission_id",
    "observation_sequence", "actual_speed", "free_distance", "sensor_fresh",
    "attack_active", "commands_cleared", "probe_success",
)


def sign_recovery_telemetry(secret: bytes, **fields: object) -> str:
    return _sign(secret, "recovery_telemetry", {key: fields[key] for key in RECOVERY_TELEMETRY_FIELDS})


def verify_recovery_telemetry(secret: bytes | None, signature: str, **fields: object) -> bool:
    return _verify(secret, "recovery_telemetry", {key: fields[key] for key in RECOVERY_TELEMETRY_FIELDS}, signature)


INDEPENDENT_OBSERVATION_FIELDS = (
    "timestamp", "observer_id", "observer_session", "profile_id", "command_epoch", "transmission_id",
    "observation_sequence", "odom_timestamp", "scan_timestamp", "actual_speed",
    "free_distance", "valid",
)


def sign_independent_observation(secret: bytes, **fields: object) -> str:
    return _sign(secret, "independent_observation", {key: fields[key] for key in INDEPENDENT_OBSERVATION_FIELDS})


def verify_independent_observation(secret: bytes | None, signature: str, **fields: object) -> bool:
    return _verify(secret, "independent_observation", {key: fields[key] for key in INDEPENDENT_OBSERVATION_FIELDS}, signature)
