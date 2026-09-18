"""Evidence-gated recovery from a contained or stopped robot state."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RecoveryEvidence:
    """Independent conditions that must be true before motion is restored."""

    no_active_attacks: bool
    graph_stable: bool
    sensor_fresh: bool
    policy_valid: bool
    commands_cleared: bool
    dwell_elapsed: bool


@dataclass(frozen=True)
class RecoveryDecision:
    allowed: bool
    missing: tuple[str, ...]


class RecoveryGate:
    """Require all safety conditions before leaving a safe-stop state."""

    REQUIRED = (
        "no_active_attacks",
        "graph_stable",
        "sensor_fresh",
        "policy_valid",
        "commands_cleared",
        "dwell_elapsed",
    )

    def evaluate(self, evidence: RecoveryEvidence) -> RecoveryDecision:
        missing = tuple(
            name for name in self.REQUIRED if not getattr(evidence, name)
        )
        return RecoveryDecision(allowed=not missing, missing=missing)
