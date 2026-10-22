"""Bounded full-control trace features for offline Hypothesis targets.

This module never reads mutant outcomes, safety violations or input actions.
Raw binding values are compared exactly, then only relation names are retained.
"""
from dataclasses import dataclass
import math


@dataclass(frozen=True)
class BoundaryFeedback:
    ttl: frozenset
    context: frozenset
    repair: frozenset
    expiry_proximity: float

    @classmethod
    def from_trace(cls, frames):
        ttl, context, repair = set(), set(), set()
        proximity, previous, repair_active = 0.0, None, False

        def health_reason(frame):
            if frame.evidence_state != "healthy":
                return frame.evidence_state
            if frame.unresolved:
                return "unresolved"
            if frame.forced_stop:
                return "forced_stop"
            if not all((frame.graph_fingerprint, frame.policy_fingerprint, frame.ledger_anchor)):
                return "context_missing"
            return "healthy"

        for frame in frames:
            if not math.isfinite(frame.now) or (previous is not None and frame.now < previous.now):
                raise ValueError("boundary feedback requires a finite monotonic clock")
            if frame.pending_proof:
                lifetime = frame.pending_proof["expires_at"] - frame.pending_proof["issued_at"]
                if not math.isfinite(lifetime) or lifetime <= 0:
                    raise ValueError("boundary feedback requires a positive proof lifetime")
            # Duplicate audit frames are not a new consumption opportunity.
            if previous is not None and frame.now > previous.now:
                proof = previous.pending_proof
                if proof and previous.recovery_phase == "RECOVERY_CANDIDATE":
                    lifetime = proof["expires_at"] - proof["issued_at"]
                    remaining = proof["expires_at"] - frame.now
                    bucket = ("at_expiry" if remaining == 0 else
                        "expired" if remaining < 0 else
                        "near_expiry" if remaining <= .1 * lifetime + 1e-9 else "fresh")
                    ttl.add(bucket)
                    proximity = max(proximity, 1 / (1 + abs(remaining) / lifetime))
                    changed = {name for name in ("graph_fingerprint", "policy_fingerprint", "ledger_anchor")
                        if getattr(frame, name) != proof[name]}
                    if frame.command_epoch + 1 != proof["command_epoch"]:
                        changed.add("command_epoch")
                    context.update(changed or {"matched"})
                current_reason, previous_reason = health_reason(frame), health_reason(previous)
                if current_reason != "healthy":
                    repair_active = False
                elif previous_reason != "healthy":
                    repair.add(f"{previous_reason}_to_healthy")
                    repair_active = True
                if repair_active:
                    if frame.pending_proof and frame.recovery_phase == "RECOVERY_CANDIDATE":
                        repair.add("candidate_after_repair")
                    if frame.recovery_phase == "RESUMABLE" and frame.mission_allowed:
                        repair.add("resumed_after_repair")
            previous = frame
        return cls(frozenset(ttl), frozenset(context), frozenset(repair), proximity)

    def targets(self):
        return {"permit_ttl_diversity": len(self.ttl), "permit_expiry_proximity": self.expiry_proximity,
            "permit_context_diversity": len(self.context), "repair_transition_diversity": len(self.repair)}

    def features(self):
        return {f"{family}:{value}" for family in ("ttl", "context", "repair")
            for value in getattr(self, family)}
