"""Coordinate existing evidence, motion envelope and one-shot recovery modules.

All timestamps here use the receiver's monotonic clock. The ROS adapter is
responsible for authentication and transport replay protection.
"""
from __future__ import annotations

from dataclasses import dataclass
import math

from .evidence_ledger import Evidence, EvidenceLedger
from .predictive_envelope import MotionSample, PredictiveConfig, PredictiveEnvelope
from .recovery_protocol import RecoveryConfig, RecoveryObservation, RecoveryProtocol


@dataclass(frozen=True)
class RecoveryTelemetry:
    received_at: float
    speed: float
    free_distance: float
    sensor_fresh: bool
    attack_active: bool
    commands_cleared: bool
    probe_success: bool

    def healthy(self, now: float, max_age: float) -> bool:
        return (
            all(type(x) in (int, float) and math.isfinite(x)
                for x in (self.received_at, self.speed, self.free_distance))
            and 0 <= now - self.received_at <= max_age
            and self.speed >= 0 and self.free_distance >= 0
            and all(type(x) is bool for x in (self.sensor_fresh, self.attack_active,
                self.commands_cleared, self.probe_success))
            and self.sensor_fresh and not self.attack_active
            and self.commands_cleared and self.probe_success
        )


@dataclass(frozen=True)
class BoundRecoveryDecision:
    phase: str
    mission_allowed: bool
    speed_limit: float
    reason: str
    proof_id: str = ""


class EvidenceBoundRecovery:
    def __init__(self, config: RecoveryConfig | None = None, *, max_age_sec: float = 0.5,
                 predictive_config: PredictiveConfig | None = None, max_evidence: int = 1024):
        self.config = config or RecoveryConfig()
        if not math.isfinite(max_age_sec) or max_age_sec <= 0:
            raise ValueError("telemetry max age must be finite and positive")
        if type(max_evidence) is not int or max_evidence <= 0:
            raise ValueError("max evidence must be a positive integer")
        self.max_age_sec = max_age_sec
        self.max_evidence = max_evidence
        self.ledger = EvidenceLedger()
        self.envelope = PredictiveEnvelope(predictive_config)
        self.protocol = RecoveryProtocol(self.config)
        self.pending_proof = None
        self.last_proof_id = ""
        self._running_context = None
        self._evidence_context = None
        self._last_now = None
        self._clock_fault = False
        self._first_safe_at = None
        self._capacity_fault = False
        self._incident_ids: dict[str, list[str]] = {}

    def _append(self, *, source, kind, node, now, confidence, severity, policy, supersedes=None):
        count = self.ledger.anchor().count
        if count >= self.max_evidence:
            self._capacity_fault = True
            return None
        record = Evidence(f"{kind}-{count + 1}", source, kind, node,
            now, now + 86400.0, confidence, severity, policy,
            supersedes=supersedes, verified=True)
        self.ledger.append(record)
        return record.evidence_id

    def record_incident(self, event, *, now: float, policy: str):
        identifier = self._append(source=event.source, kind="verified_attack",
            node=event.component, now=now, confidence=event.confidence, severity=1.0, policy=policy)
        if identifier:
            self._incident_ids.setdefault(event.source, []).append(identifier)
        return identifier

    def resolve_source(self, source: str, *, now: float, policy: str) -> bool:
        identifiers = self._incident_ids.get(source, [])
        if self.ledger.anchor().count + len(identifiers) > self.max_evidence:
            self._capacity_fault = True
            return False
        for identifier in identifiers:
            self._append(source=source, kind="incident_resolution", node="amr",
                now=now, confidence=1.0, severity=0.0, policy=policy, supersedes=identifier)
        self._incident_ids.pop(source, None)
        return not self._capacity_fault

    def _stop(self, reason: str) -> BoundRecoveryDecision:
        self.pending_proof = None
        self._running_context = None
        self.protocol = RecoveryProtocol(self.config)
        self._first_safe_at = None
        return BoundRecoveryDecision("SAFE_STOP", False, 0.0, reason)

    def update(self, *, now: float, telemetry: RecoveryTelemetry | None,
               graph_fingerprint: str, policy_fingerprint: str, command_epoch: int,
               stopped_ack: bool, unresolved: bool, forced_stop: bool) -> BoundRecoveryDecision:
        if not math.isfinite(now) or (self._last_now is not None and now < self._last_now):
            self._clock_fault = True
        if self._clock_fault:
            return self._stop("monotonic clock invalid or moved backwards")
        self._last_now = now
        if self._capacity_fault:
            return self._stop("evidence capacity exhausted; restart after review")
        if not self.ledger.verify():
            return self._stop("evidence ledger integrity failed")
        healthy = telemetry is not None and telemetry.healthy(now, self.max_age_sec)
        context = (graph_fingerprint, policy_fingerprint, healthy, unresolved, forced_stop)
        if context != self._evidence_context:
            count = self.ledger.anchor().count
            if count >= self.max_evidence:
                self._capacity_fault = True
                return self._stop("evidence capacity exhausted; restart after review")
            self.ledger.append(Evidence(
                f"context-{count + 1}", "guardian", "recovery_context", "amr",
                now, now + 86400.0, 1.0, 0.0 if healthy and not unresolved else 1.0,
                policy_fingerprint or "unavailable", verified=True,
            ))
            self._evidence_context = context
        anchor = self.ledger.anchor()
        anchor_id = f"{anchor.count}:{anchor.head}"
        if forced_stop or unresolved or not healthy or not graph_fingerprint or not policy_fingerprint:
            return self._stop("unresolved incident, missing context or unhealthy/stale observation")
        motion = self.envelope.evaluate(MotionSample(
            telemetry.speed, telemetry.free_distance, 0.0, sensor_fresh=telemetry.sensor_fresh,
        ))
        if not motion.mission_allowed:
            return self._stop(motion.reason)
        current = (graph_fingerprint, policy_fingerprint, anchor_id, command_epoch)
        if self._running_context is not None:
            if current != self._running_context:
                return self._stop("authorized recovery context changed")
            return BoundRecoveryDecision("NORMAL", True, motion.speed_limit,
                "fresh observations preserve authorized context", self.last_proof_id)
        if not stopped_ack or telemetry.speed > 1e-6:
            return self._stop("matching stop ACK and zero-speed observation required")
        observation = RecoveryObservation(
            now, True, graph_fingerprint, policy_fingerprint, anchor_id,
            telemetry.commands_cleared, telemetry.sensor_fresh, True,
            telemetry.probe_success, command_epoch + 1, 0.0,
        )
        if self.pending_proof is not None:
            proof = self.pending_proof
            self.pending_proof = None
            result = self.protocol.authorize_command(proof, observation)
            if not result.allowed:
                return self._stop(result.reason)
            self.last_proof_id = proof.proof_id
            self._running_context = (*current[:3], proof.command_epoch)
            return BoundRecoveryDecision("RESUMABLE", True, motion.speed_limit,
                result.reason, proof.proof_id)
        result = self.protocol.observe(observation)
        if result.state == "SAFE_STOP":
            return self._stop(result.reason)
        if self._first_safe_at is None:
            self._first_safe_at = now
        if (result.state == "RECOVERY_CANDIDATE"
                and now - self._first_safe_at >= self.config.dwell_sec):
            self.pending_proof = self.protocol.issue_observed(observation)
            return BoundRecoveryDecision("RECOVERY_CANDIDATE", False, 0.0, "one-shot proof issued")
        return BoundRecoveryDecision(result.state, False, 0.0, result.reason)
