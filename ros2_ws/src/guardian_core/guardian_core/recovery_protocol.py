"""Two-phase, context-bound recovery protocol for stopped robots."""

from __future__ import annotations

import hashlib
import math
import secrets
from dataclasses import dataclass


def _finite(value: float, name: str) -> float:
    value = float(value)
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    return value


@dataclass(frozen=True)
class RecoveryConfig:
    dwell_sec: float = 1.0
    stable_window_sec: float = 0.5
    proof_ttl_sec: float = 0.5
    max_observation_gap_sec: float = 2.0

    def __post_init__(self) -> None:
        for name in ("dwell_sec", "stable_window_sec", "proof_ttl_sec", "max_observation_gap_sec"):
            if _finite(getattr(self, name), name) < 0:
                raise ValueError(f"{name} must be non-negative")
        if self.proof_ttl_sec == 0:
            raise ValueError("proof_ttl_sec must be positive")


@dataclass(frozen=True)
class RecoveryObservation:
    now: float
    no_active_attacks: bool
    graph_fingerprint: str
    policy_fingerprint: str
    ledger_anchor: str
    commands_cleared: bool
    sensor_fresh: bool
    policy_valid: bool
    probe_success: bool
    command_epoch: int
    risk: float

    def __post_init__(self) -> None:
        _finite(self.now, "now")
        if not self.graph_fingerprint or not self.policy_fingerprint or not self.ledger_anchor:
            raise ValueError("recovery context fingerprints cannot be empty")
        if not isinstance(self.command_epoch, int) or isinstance(self.command_epoch, bool) or self.command_epoch < 0:
            raise ValueError("command_epoch must be a non-negative integer")
        risk = _finite(self.risk, "risk")
        if not 0.0 <= risk <= 1.0:
            raise ValueError("risk must be in [0, 1]")
        if not all(isinstance(value, bool) for value in (
            self.no_active_attacks, self.commands_cleared, self.sensor_fresh,
            self.policy_valid, self.probe_success,
        )):
            raise ValueError("recovery evidence flags must be boolean")

    @property
    def safe(self) -> bool:
        return (
            self.no_active_attacks
            and self.commands_cleared
            and self.sensor_fresh
            and self.policy_valid
            and self.probe_success
            and self.risk <= 0.35
        )

    @property
    def context(self) -> tuple[str, str, str, int]:
        return (self.graph_fingerprint, self.policy_fingerprint, self.ledger_anchor, self.command_epoch)


@dataclass(frozen=True)
class RecoveryProof:
    proof_id: str
    graph_fingerprint: str
    policy_fingerprint: str
    ledger_anchor: str
    command_epoch: int
    risk: float
    issued_at: float
    expires_at: float
    signature: str
    issuer: str


@dataclass(frozen=True)
class RecoveryDecision:
    state: str
    allowed: bool
    reason: str


class RecoveryProtocol:
    def __init__(self, config: RecoveryConfig | None = None) -> None:
        self.config = config or RecoveryConfig()
        self._state = "SAFE_STOP"
        self._first_safe_at: float | None = None
        self._last_observation: RecoveryObservation | None = None
        self._used_proofs: set[str] = set()
        self._issuer = secrets.token_hex(16)

    def observe(self, observation: RecoveryObservation) -> RecoveryDecision:
        if self._last_observation and observation.now <= self._last_observation.now:
            return self._fail("time moved backwards")
        previous = self._last_observation
        self._last_observation = observation
        if not observation.safe:
            return self._fail("recovery evidence is incomplete")
        if previous and observation.context != previous.context:
            return self._fail("recovery context changed")
        if previous and observation.now - previous.now > self.config.max_observation_gap_sec:
            return self._fail("recovery observation gap is too large")
        if self._first_safe_at is None:
            self._first_safe_at = observation.now
            self._state = "RECOVERY_CANDIDATE" if self.config.stable_window_sec == 0 else "RECOVERY_PROBING"
        elif observation.now - self._first_safe_at >= self.config.stable_window_sec:
            self._state = "RECOVERY_CANDIDATE"
        return RecoveryDecision(self._state, False, "recovery evidence is being observed")

    def commit(self, observation: RecoveryObservation) -> RecoveryProof:
        decision = self.observe(observation)
        if decision.state != "RECOVERY_CANDIDATE":
            raise ValueError("recovery is not a candidate")
        if self._first_safe_at is None or observation.now - self._first_safe_at < self.config.dwell_sec:
            raise ValueError("recovery dwell time has not elapsed")
        material = "|".join(str(item) for item in (*observation.context, observation.now))
        proof_id = hashlib.sha256(material.encode()).hexdigest()
        expires_at = observation.now + self.config.proof_ttl_sec
        signature = self._sign(observation, observation.now, expires_at, proof_id)
        return RecoveryProof(
            proof_id=proof_id,
            graph_fingerprint=observation.graph_fingerprint,
            policy_fingerprint=observation.policy_fingerprint,
            ledger_anchor=observation.ledger_anchor,
            command_epoch=observation.command_epoch,
            risk=observation.risk,
            issued_at=observation.now,
            expires_at=expires_at,
            signature=signature,
            issuer=self._issuer,
        )

    def authorize_command(self, proof: RecoveryProof, observation: RecoveryObservation) -> RecoveryDecision:
        if not isinstance(proof, RecoveryProof):
            return self._fail("recovery proof type is invalid")
        if proof.proof_id in self._used_proofs:
            return self._fail("recovery proof replayed")
        if self._state != "RECOVERY_CANDIDATE":
            return self._reject_proof(proof, "recovery protocol is not at candidate state")
        if proof.issuer != self._issuer:
            return self._reject_proof(proof, "recovery proof belongs to another protocol")
        if proof.signature != self._sign_values(
            proof.graph_fingerprint, proof.policy_fingerprint, proof.ledger_anchor,
            proof.command_epoch, proof.risk, proof.issued_at, proof.expires_at, proof.proof_id,
        ):
            return self._reject_proof(proof, "recovery proof signature is invalid")
        latest = self._last_observation
        proof_context = (
            proof.graph_fingerprint,
            proof.policy_fingerprint,
            proof.ledger_anchor,
            proof.command_epoch,
        )
        if latest is None:
            return self._reject_proof(proof, "recovery candidate is missing")
        if latest.context != proof_context:
            return self._reject_proof(proof, "latest recovery context changed")
        if latest.now != proof.issued_at:
            return self._reject_proof(proof, "recovery proof is stale")
        if abs(latest.risk - proof.risk) > 1e-12:
            return self._reject_proof(proof, "latest recovery risk changed")
        if observation.now <= proof.issued_at or observation.now >= proof.expires_at:
            return self._reject_proof(proof, "recovery proof expired")
        if observation.context != (
            proof.graph_fingerprint,
            proof.policy_fingerprint,
            proof.ledger_anchor,
            proof.command_epoch,
        ):
            return self._reject_proof(proof, "recovery context changed")
        if abs(observation.risk - proof.risk) > 1e-12:
            return self._reject_proof(proof, "recovery risk changed")
        if not observation.safe:
            return self._reject_proof(proof, "recovery evidence is incomplete")
        self._used_proofs.add(proof.proof_id)
        self._state = "RESUMABLE"
        return RecoveryDecision("RESUMABLE", True, "single recovery command authorized")

    def _fail(self, reason: str) -> RecoveryDecision:
        self._state = "SAFE_STOP"
        self._first_safe_at = None
        return RecoveryDecision("SAFE_STOP", False, reason)

    def _reject_proof(self, proof: RecoveryProof, reason: str) -> RecoveryDecision:
        self._used_proofs.add(proof.proof_id)
        return self._fail(reason)

    def _sign(self, observation: RecoveryObservation, issued_at: float, expires_at: float, proof_id: str) -> str:
        return self._sign_values(
            observation.graph_fingerprint, observation.policy_fingerprint,
            observation.ledger_anchor, observation.command_epoch, observation.risk,
            issued_at, expires_at, proof_id,
        )

    def _sign_values(
        self, graph: str, policy: str, ledger: str, epoch: int, risk: float, issued_at: float, expires_at: float,
        proof_id: str,
    ) -> str:
        payload = "|".join(map(str, (self._issuer, graph, policy, ledger, epoch, risk, issued_at, expires_at, proof_id)))
        return hashlib.sha256(payload.encode()).hexdigest()


__all__ = [
    "RecoveryConfig", "RecoveryDecision", "RecoveryObservation",
    "RecoveryProof", "RecoveryProtocol",
]
