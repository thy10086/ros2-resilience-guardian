"""Full-control trace targets for sustained health and recovery progress.

This is a search proxy, not a liveness oracle. Correctly resumed motion can
extend a healthy window; parking forever is never a search requirement.
No actions, injected-defect outcomes or SafetyOracle results are consumed.
"""
from dataclasses import dataclass
import math


@dataclass(frozen=True)
class RecoveryLivenessFeedback:
    health_window_sec: float
    recovery_progress: int
    coverage: frozenset

    @staticmethod
    def configuration():
        return {"max_frame_gap_sec": .25, "frame_gap_tolerance_sec": 1e-9,
            "window_cap_sec": 6.0, "duration_precision": 6}

    @classmethod
    def from_trace(cls, frames):
        config = cls.configuration()
        previous = None
        window_start = None
        longest, progress, features = 0.0, 0, set()
        for frame in frames:
            if not math.isfinite(frame.now) or (previous is not None and frame.now < previous.now):
                raise ValueError("liveness feedback requires a finite monotonic clock")
            if previous is not None and frame.now == previous.now:
                if frame != previous:
                    raise ValueError("conflicting frames at the same time")
                continue
            context = (frame.graph_fingerprint, frame.policy_fingerprint, frame.ledger_anchor)
            healthy = (frame.evidence_state == "healthy" and not frame.unresolved
                and not frame.forced_stop and all(context) and math.isfinite(frame.observed_speed)
                and frame.observed_speed >= 0
                and (frame.mission_allowed or (frame.stopped_ack and frame.observed_speed <= 1e-6)))
            # Absorb clock subtraction roundoff in this proxy, not in SafetyOracle.
            continuous = (previous is not None and frame.now - previous.now <=
                config["max_frame_gap_sec"] + config["frame_gap_tolerance_sec"]
                and context == (previous.graph_fingerprint, previous.policy_fingerprint, previous.ledger_anchor)
                and frame.command_epoch == previous.next_command_epoch)
            if not healthy:
                window_start = None
            else:
                if window_start is None or not continuous:
                    window_start = frame.now
                longest = max(longest, min(config["window_cap_sec"],
                    round(frame.now - window_start, config["duration_precision"])))
                stage = 0
                if frame.recovery_phase == "RECOVERY_PROBING":
                    stage = 1
                elif frame.recovery_phase == "RECOVERY_CANDIDATE":
                    stage = 2 if frame.pending_proof else 1
                elif frame.mission_allowed and frame.consumed_proof_id:
                    stage = {"RESUMABLE": 3, "NORMAL": 4}.get(frame.recovery_phase, 0)
                progress = max(progress, stage)
                features.add(f"progress:{stage}")
            previous = frame
        for threshold in (0, 1, 3, 6):
            if (threshold == 0 and longest > 0) or (threshold > 0 and longest >= threshold):
                features.add(f"health_window:ge_{threshold}" if threshold else "health_window:positive")
        return cls(longest, progress, frozenset(features))

    def targets(self):
        return {"recovery_stable_health_sec": self.health_window_sec, "recovery_progress": self.recovery_progress}

    def features(self):
        return set(self.coverage)
