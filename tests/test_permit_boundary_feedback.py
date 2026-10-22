from dataclasses import replace
from pathlib import Path
import math
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))
from recovery_scenarios import Action, execute_scenario
from permit_boundary_feedback import BoundaryFeedback


def candidate_pair(delay=.05):
    trace = execute_scenario([Action("healthy", .35)])
    index = next(i for i, f in enumerate(trace) if f.pending_proof)
    return [trace[index], replace(trace[index + 1], now=trace[index].now + delay)]


@pytest.mark.parametrize("delay,expected", [(.05, "fresh"), (.49, "near_expiry"),
    (.5, "at_expiry"), (.51, "expired")])
def test_expiry_opportunity_uses_prior_issued_proof(delay, expected):
    feedback = BoundaryFeedback.from_trace(candidate_pair(delay))
    assert feedback.ttl == frozenset({expected})
    assert 0 < feedback.expiry_proximity <= 1
    assert feedback.expiry_proximity == pytest.approx(1 / (1 + abs(.5 - delay) / .5))


@pytest.mark.parametrize("field", ["graph_fingerprint", "policy_fingerprint", "ledger_anchor", "command_epoch"])
def test_each_binding_change_is_a_separate_boundary(field):
    a, b = candidate_pair()
    b = replace(b, **{field: getattr(b, field) + 1 if field == "command_epoch" else "different"})
    feedback = BoundaryFeedback.from_trace([a, b])
    assert field in feedback.context
    assert "matched" not in feedback.context


def test_repair_features_require_preceding_unhealthy_evidence_and_later_recovery():
    startup = BoundaryFeedback.from_trace(execute_scenario([Action("healthy", .6)]))
    repaired = BoundaryFeedback.from_trace(execute_scenario([
        Action("healthy", .5), Action("near_obstacle", .2), Action("healthy", .6)]))
    assert not startup.repair
    assert "near_obstacle_to_healthy" in repaired.repair
    assert "candidate_after_repair" in repaired.repair
    assert "resumed_after_repair" in repaired.repair


def test_boundary_targets_are_invariant_to_duplicate_frames_and_absolute_values():
    a, b = candidate_pair(.49)
    original = BoundaryFeedback.from_trace([a, b])
    duplicate = BoundaryFeedback.from_trace([a, a, b, b])
    shifted = []
    for frame in (a, b):
        proof = None if frame.pending_proof is None else {**frame.pending_proof,
            "proof_id": "new-proof", "graph_fingerprint": "new-graph",
            "issued_at": frame.pending_proof["issued_at"] + 100,
            "expires_at": frame.pending_proof["expires_at"] + 100}
        shifted.append(replace(frame, now=frame.now + 100, graph_fingerprint="new-graph",
            pending_proof=proof, consumed_proof_id="new-proof"))
    assert original.targets() == duplicate.targets()
    assert original.targets() == pytest.approx(BoundaryFeedback.from_trace(shifted).targets())


def test_invalid_clock_or_lifetime_rejected_instead_of_targeting_nan():
    a, b = candidate_pair()
    for bad in ([a, replace(b, now=float("nan"))], [a, replace(b, now=a.now - .1)],
            [replace(a, pending_proof={**a.pending_proof, "expires_at": a.now}), b]):
        with pytest.raises(ValueError):
            BoundaryFeedback.from_trace(bad)


def test_adjacent_floating_point_values_preserve_strict_expiry_boundary():
    a, b = candidate_pair()
    expiry = a.pending_proof["expires_at"]
    for moment, expected in ((math.nextafter(expiry, -math.inf), "near_expiry"),
            (expiry, "at_expiry"), (math.nextafter(expiry, math.inf), "expired")):
        assert BoundaryFeedback.from_trace([a, replace(b, now=moment)]).ttl == frozenset({expected})
