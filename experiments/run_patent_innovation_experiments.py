#!/usr/bin/env python3
"""Deterministic experiments for the provenance-bound predictive safety design."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ros2_ws" / "src" / "guardian_core"))

from guardian_core import (  # noqa: E402
    AssuranceController,
    CausalEdge,
    CausalNode,
    Evidence,
    EvidenceLedger,
    GraphSnapshot,
    MotionSample,
    PredictiveConfig,
    PredictiveEnvelope,
    RecoveryConfig,
    RecoveryEvidence,
    RecoveryGate,
    RecoveryObservation,
    RecoveryProtocol,
    compare_graphs,
    trace_risk,
)
from guardian_core.safety_envelope import SafetyEnvelopeController  # noqa: E402


def snapshot(weight: float = 0.8, observed_at: float = 10.0) -> GraphSnapshot:
    return GraphSnapshot(
        nodes=(
            CausalNode("nav", "node", "mission", 0.5),
            CausalNode("cmd_vel", "topic", "control", 0.7),
            CausalNode("base", "actuator", "physical", 1.0),
        ),
        edges=(
            CausalEdge("nav", "cmd_vel", weight, "publishes"),
            CausalEdge("cmd_vel", "base", 0.9, "controls"),
        ),
        observed_at=observed_at,
    )


def evidence(
    evidence_id: str,
    *,
    source: str,
    kind: str,
    node: str,
    confidence: float,
    severity: float,
    hard_stop: bool = False,
    parents: tuple[str, ...] = (),
    observed_at: float = 1.0,
    expires_at: float = 5.0,
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        source=source,
        kind=kind,
        node=node,
        observed_at=observed_at,
        expires_at=expires_at,
        confidence=confidence,
        severity=severity,
        policy_version="policy-v2",
        parent_ids=parents,
        verified=True,
        hard_stop=hard_stop,
    )


def observation(
    now: float,
    *,
    graph: str = "graph-v1",
    ledger: str = "ledger-v1",
    command_epoch: int = 4,
    no_active_attacks: bool = True,
    probe_success: bool = True,
) -> RecoveryObservation:
    return RecoveryObservation(
        now=now,
        no_active_attacks=no_active_attacks,
        graph_fingerprint=graph,
        policy_fingerprint="policy-v2",
        ledger_anchor=ledger,
        commands_cleared=True,
        sensor_fresh=True,
        policy_valid=True,
        probe_success=probe_success,
        command_epoch=command_epoch,
        risk=0.1,
    )


def experiment_causal_provenance() -> dict[str, object]:
    current = snapshot()
    trace = trace_risk(current, {"nav": 0.9}, now=10.2, max_age_sec=1.0)
    changed = compare_graphs(current, snapshot(weight=0.5))
    try:
        trace_risk(current, {"nav": 0.9}, now=12.0, max_age_sec=1.0)
    except ValueError as error:
        stale_rejected = str(error)
    else:
        stale_rejected = ""
    result = {
        "base_risk": trace.risk_by_node["base"],
        "base_path": trace.paths_by_node["base"],
        "critical_nodes": sorted(trace.critical_nodes),
        "changed_edges": changed.changed_edges,
        "stale_rejected": stale_rejected,
    }
    assert abs(result["base_risk"] - 0.648) < 1e-9
    assert result["base_path"] == ("nav", "cmd_vel", "base")
    assert result["changed_edges"] == ("nav->cmd_vel",)
    assert stale_rejected
    return {"name": "causal_provenance", "passed": True, "evidence": result}


def experiment_evidence_integrity() -> dict[str, object]:
    ledger = EvidenceLedger()
    root = ledger.append(evidence(
        "temporal-1", source="policy", kind="temporal", node="cmd_vel",
        confidence=0.9, severity=0.6,
    ))
    derived = ledger.append(evidence(
        "graph-1", source="graph", kind="propagation", node="base",
        confidence=0.8, severity=0.8, parents=(root.evidence_id,),
    ))
    anchor = ledger.anchor()
    before = ledger.verify()
    ledger._records[1] = Evidence(**{**derived.__dict__, "severity": 0.1})
    after = ledger.verify()
    result = {
        "anchor_count": anchor.count,
        "anchor_head_present": bool(anchor.head),
        "valid_before_tamper": before,
        "valid_after_tamper": after,
        "active_records": [item.evidence_id for item in ledger.active(2.0)],
    }
    assert before and not after
    assert result["active_records"] == ["temporal-1", "graph-1"]
    return {"name": "evidence_integrity", "passed": True, "evidence": result}


def experiment_predictive_envelope() -> dict[str, object]:
    baseline = SafetyEnvelopeController(default_speed_limit=0.35, braking_acceleration=0.8)
    predictor = PredictiveEnvelope(PredictiveConfig(
        default_speed_limit=0.35,
        braking_acceleration=0.8,
        control_latency_sec=0.2,
        sensor_latency_sec=0.1,
        prediction_horizon_sec=0.5,
    ))
    baseline_decision = baseline.compute(risk=0.1, free_distance=2.0, sensor_fresh=True)
    calm = predictor.evaluate(MotionSample(0.2, 2.0, 0.1, risk_rate=0.0, uncertainty=0.02))
    growing = predictor.evaluate(MotionSample(0.2, 2.0, 0.1, risk_rate=0.8, uncertainty=0.02))
    result = {
        "baseline_speed": baseline_decision.speed_limit,
        "calm_speed": calm.speed_limit,
        "growing_speed": growing.speed_limit,
        "growing_predicted_risk": growing.predicted_risk,
        "growing_stop_distance": growing.stop_distance,
        "speed_reduction": baseline_decision.speed_limit - growing.speed_limit,
        "growing_state": growing.state,
    }
    assert 0.0 < growing.speed_limit < baseline_decision.speed_limit
    assert growing.predicted_risk > calm.predicted_risk
    assert growing.state == "CONTAINING"
    return {"name": "predictive_envelope_vs_baseline", "passed": True, "evidence": result}


def experiment_recovery_protocol() -> dict[str, object]:
    legacy_gate = RecoveryGate()
    legacy = legacy_gate.evaluate(
        # The existing gate accepts one all-true snapshot.
        RecoveryEvidence(True, True, True, True, True, True)
    )
    protocol = RecoveryProtocol(RecoveryConfig(dwell_sec=1.0, stable_window_sec=0.5, proof_ttl_sec=0.5))
    probing = protocol.observe(observation(0.0))
    candidate = protocol.observe(observation(0.6))
    proof = protocol.commit(observation(1.1))
    resumed = protocol.authorize_command(proof, observation(1.2))
    replay = protocol.authorize_command(proof, observation(1.3))
    changed = RecoveryProtocol(RecoveryConfig(dwell_sec=0.0, stable_window_sec=0.0, proof_ttl_sec=1.0))
    changed.observe(observation(2.0))
    changed_proof = changed.commit(observation(2.1))
    graph_changed = changed.authorize_command(changed_proof, observation(2.2, graph="graph-v2"))
    result = {
        "legacy_one_snapshot_allowed": legacy.allowed,
        "states": [probing.state, candidate.state, resumed.state],
        "replay_state": replay.state,
        "graph_change_state": graph_changed.state,
        "graph_change_reason": graph_changed.reason,
    }
    assert legacy.allowed
    assert result["states"] == ["RECOVERY_PROBING", "RECOVERY_CANDIDATE", "RESUMABLE"]
    assert replay.state == "SAFE_STOP"
    assert graph_changed.state == "SAFE_STOP"
    return {"name": "two_phase_recovery", "passed": True, "evidence": result}


def experiment_assurance_explanation() -> dict[str, object]:
    ledger = EvidenceLedger()
    ledger.append(evidence(
        "physical-stop", source="sensor", kind="physical", node="base",
        confidence=1.0, severity=1.0, hard_stop=True,
    ))
    ledger.append(evidence(
        "graph-soft", source="graph", kind="propagation", node="cmd_vel",
        confidence=0.8, severity=0.6,
    ))
    assurance = AssuranceController()
    decision = assurance.assess(ledger, now=2.0)
    counterfactuals = assurance.counterfactuals(ledger, now=2.0)
    result = {
        "level": decision.level,
        "score": decision.score,
        "hard_stop_ids": decision.hard_stop_ids,
        "reasons": decision.reasons,
        "counterfactuals": [
            {"evidence_id": item.evidence_id, "level_without": item.level_without}
            for item in counterfactuals
        ],
    }
    assert decision.level == "SAFE_STOP"
    assert any(item["evidence_id"] == "physical-stop" and item["level_without"] != "SAFE_STOP" for item in result["counterfactuals"])
    return {"name": "assurance_explanation", "passed": True, "evidence": result}


def main() -> int:
    experiments = [
        experiment_causal_provenance(),
        experiment_evidence_integrity(),
        experiment_predictive_envelope(),
        experiment_recovery_protocol(),
        experiment_assurance_explanation(),
    ]
    report = {"passed": all(item["passed"] for item in experiments), "experiments": experiments}
    output_path = ROOT / "experiments" / "results" / "patent_innovation_validation.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
