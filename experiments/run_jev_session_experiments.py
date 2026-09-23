#!/usr/bin/env python3
"""Deterministic experiments for Jev incident sessions and soft evidence."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ros2_ws" / "src" / "guardian_core"))

from guardian_core import (  # noqa: E402
    Evidence,
    EvidenceLedger,
    JevAdvisorConfig,
    JevEfficientJudge,
    JevEfficiencyPolicy,
    JevIncidentSession,
    JevRoute,
    JevSemanticAdvisor,
    JevSessionConfig,
    JevSessionRoute,
    JevSessionState,
    SemanticContext,
)


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class StubTransport:
    def __init__(self, error: Exception | None = None) -> None:
        self.calls = 0
        self.error = error

    def __call__(self, endpoint: str, headers: dict[str, str], body: bytes, timeout: float) -> bytes:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return json.dumps(
            {
                "model": "jev-session-stub",
                "answers": {
                    "attack_type": {
                        "type": "choice",
                        "choice": "unsafe_command",
                        "confidence": 0.9,
                        "probabilities": {"unsafe_command": 0.9},
                    },
                    "mission_impact": {
                        "type": "choice",
                        "choice": "critical",
                        "confidence": 0.9,
                        "probabilities": {"critical": 0.9},
                    },
                    "needs_human_review": {"type": "noul", "noul": 1.0},
                },
            }
        ).encode("utf-8")


def make_context(event_id: str, sequence: int, *, risk: float = 0.6, normal: bool = True) -> SemanticContext:
    return SemanticContext(
        event_id=event_id,
        component="nav",
        attack_type="UNSAFE_COMMAND",
        event_confidence=0.95 if normal and risk < 0.2 else 0.8,
        source_verified=True,
        temporal_codes=() if normal and risk < 0.2 else ("REPLAY",),
        graph_risk=risk,
        mission_criticality=0.1 if normal and risk < 0.2 else 0.6,
        active_components=("nav", "base"),
        safety_state="NORMAL" if normal else "SAFE_STOP",
        sequence=sequence,
        summary="verified command anomaly",
    )


def make_ledger() -> EvidenceLedger:
    ledger = EvidenceLedger()
    ledger.append(Evidence(
        evidence_id="event-proof",
        source="verifier",
        kind="verified_event",
        node="nav",
        observed_at=0.0,
        expires_at=100.0,
        confidence=1.0,
        severity=0.6,
        policy_version="p1",
        verified=True,
    ))
    return ledger


def append_parent(ledger: EvidenceLedger, evidence_id: str) -> None:
    """Add a second deterministic verifier record for re-binding checks."""
    root = Evidence(**ledger.export()[0]["evidence"])
    ledger.append(Evidence(
        evidence_id=evidence_id,
        source=root.source,
        kind=root.kind,
        node=root.node,
        observed_at=root.observed_at,
        expires_at=root.expires_at,
        confidence=root.confidence,
        severity=root.severity,
        policy_version=root.policy_version,
        parent_ids=root.parent_ids,
        supersedes=root.supersedes,
        verified=root.verified,
        hard_stop=root.hard_stop,
    ))


def make_session(clock: Clock, transport: StubTransport, ledger: EvidenceLedger) -> JevIncidentSession:
    advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="offline-stub", cache_ttl_sec=30.0),
        transport=transport,
        clock=lambda: 100.0,
    )
    judge = JevEfficientJudge(
        advisor,
        policy=JevEfficiencyPolicy(max_remote_calls=20, cache_ttl_sec=30.0),
        clock=clock,
    )
    return JevIncidentSession(
        judge,
        ledger,
        config=JevSessionConfig(min_query_interval_sec=1.0, stable_window_sec=2.0, soft_evidence_ttl_sec=5.0),
        clock=clock,
    )


def main() -> int:
    clock = Clock()
    transport = StubTransport()
    ledger = make_ledger()
    session = make_session(clock, transport, ledger)

    burst = []
    for index in range(10):
        clock.now = index * 0.1
        burst.append(session.observe(
            make_context(f"burst-{index}", index),
            parent_evidence_id="event-proof",
            incident_key="incident-burst",
        ))

    clock.now = 1.0
    entered = session.observe(
        make_context("risk-high", 20, risk=0.8),
        parent_evidence_id="event-proof",
        incident_key="incident-recovery",
    )
    clock.now = 2.0
    below = session.observe(
        make_context("risk-low", 21, risk=0.1),
        parent_evidence_id="event-proof",
        incident_key="incident-recovery",
    )
    clock.now = 4.1
    recovered = session.observe(
        make_context("risk-low-2", 22, risk=0.1),
        parent_evidence_id="event-proof",
        incident_key="incident-recovery",
    )

    invalid_ledger = make_ledger()
    invalid_ledger._records[0] = Evidence(
        evidence_id="event-proof",
        source="verifier",
        kind="verified_event",
        node="nav",
        observed_at=0.0,
        expires_at=100.0,
        confidence=0.0,
        severity=0.6,
        policy_version="p1",
        verified=True,
    )
    blocked_session = make_session(clock, StubTransport(), invalid_ledger)
    blocked = blocked_session.observe(
        make_context("blocked", 30),
        parent_evidence_id="event-proof",
        incident_key="incident-blocked",
    )

    # A cached semantic result may be re-bound to a new verified parent once,
    # but the new soft record must retain the original lease deadline.
    lease_clock = Clock()
    lease_transport = StubTransport()
    lease_ledger = make_ledger()
    append_parent(lease_ledger, "event-proof-2")
    lease_session = make_session(lease_clock, lease_transport, lease_ledger)
    lease_first = lease_session.observe(
        make_context("lease-1", 40),
        parent_evidence_id="event-proof",
        incident_key="incident-lease",
    )
    lease_clock.now = 2.0
    lease_rebound = lease_session.observe(
        make_context("lease-2", 41),
        parent_evidence_id="event-proof-2",
        incident_key="incident-lease",
    )
    lease_bound = [item for item in lease_ledger.active(2.0) if item.source == "jev"]
    lease_clock.now = 5.0
    lease_expired = lease_session.observe(
        make_context("lease-3", 42),
        parent_evidence_id="event-proof-2",
        incident_key="incident-lease",
    )

    evidence = {
        "burst_provider_calls": transport.calls,
        "burst_routes": [item.route.value for item in burst],
        "burst_reuse_count": sum(item.route == JevSessionRoute.SESSION_REUSE for item in burst),
        "burst_soft_evidence_records": len(ledger.export()),
        "risk_recovery_states": [entered.state.value, below.state.value, recovered.state.value],
        "blocked_route": blocked.route.value,
        "blocked_state": blocked.state.value,
        "session_ledger_valid": ledger.verify(),
        "lease_provider_calls": lease_transport.calls,
        "lease_first_expires_at": next(item for item in lease_ledger.export() if item["evidence"]["evidence_id"] == lease_first.ledger_evidence_id)["evidence"]["expires_at"],
        "lease_rebound_expires_at": lease_bound[0].expires_at,
        "lease_expired_route": lease_expired.route.value,
        "lease_active_records_at_deadline": len([item for item in lease_ledger.active(5.0) if item.source == "jev"]),
    }
    assert transport.calls == 2
    assert burst[0].route == JevSessionRoute.QUERIED
    assert all(item.route == JevSessionRoute.SESSION_REUSE for item in burst[1:])
    assert evidence["burst_soft_evidence_records"] == 3
    assert entered.state == JevSessionState.REVIEW_REQUIRED
    assert below.state == JevSessionState.REVIEW_REQUIRED
    assert recovered.state == JevSessionState.OBSERVING
    assert blocked.route == JevSessionRoute.LEDGER_BLOCKED
    assert blocked.state == JevSessionState.CONTAINING
    assert blocked.ledger_bound is False
    assert lease_first.ledger_bound and lease_rebound.ledger_bound
    assert lease_transport.calls == 1
    assert lease_bound and lease_bound[0].expires_at == 5.0
    assert lease_expired.ledger_bound is False
    assert evidence["lease_active_records_at_deadline"] == 0
    print(json.dumps({"passed": True, "experiment": "jev_incident_session", "evidence": evidence}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
