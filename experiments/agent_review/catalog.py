"""Fixed repository-owned scenarios; trigger validity is separate from safety."""
from __future__ import annotations

from experiments.recovery_scenarios import Action, execute_scenario
from guardian_core.recovery_feedback import RecoveryFrame


SCENARIOS = {
    "healthy_resume": (("healthy", .5),),
    "ttl_gap": (("healthy", .25), ("gap", .51), ("wait", .5)),
    "graph_change": (("healthy", .25), ("graph_change", .05), ("wait", .6)),
    "policy_change": (("healthy", .25), ("policy_change", .05), ("wait", .6)),
    "epoch_change": (("healthy", .25), ("epoch_change", .05), ("wait", .6)),
    "proof_replay": (("healthy", .35), ("replay_proof", .05), ("healthy", .6)),
}
TEST_IDS = tuple(SCENARIOS)
CATALOG_VERSION = "guardian-recovery-fixed-v1"


def require_test_id(test_id):
    if type(test_id) is not str or test_id not in SCENARIOS:
        raise ValueError("unknown registered test ID")
    return test_id


def validate_case(test_id, frames, events):
    """Evaluate observations, without repairing or replacing any raw trace."""
    require_test_id(test_id)
    parsed = [RecoveryFrame.from_dict(frame) for frame in frames]
    candidates = [i for i, frame in enumerate(parsed) if frame.pending_proof is not None]
    consumed = [event["frame_index"] for event in events if event["kind"] == "proof_consumed"]
    motion = [i for i, frame in enumerate(parsed) if frame.mission_allowed
        and frame.speed_limit > 0 and frame.observed_speed > 0]
    replays = [event for event in events if event["kind"] == "proof_replay" and event["previously_consumed"]]
    challenges = [event for event in events if event["kind"] == "candidate_challenge"]
    eligible = [event for event in events if event["kind"] == "observation"
        and event["healthy"] and event["stopped_ack"] and event["zero_speed"]]
    # A normal-control precondition depends on supplied observations, never on
    # whether the controller decided to issue a candidate or resume.
    healthy_span = 0.
    beginning = previous = None
    for event in eligible:
        if previous is None or event["frame_index"] != previous["frame_index"] + 1:
            beginning = event["now"]
        healthy_span = max(healthy_span, event["now"] - beginning)
        previous = event
    witnesses = {"events": events, "candidate_frames": candidates,
        "consumed_proof_frames": consumed, "motion_frames": motion,
        "healthy_ack_duration_sec": healthy_span, "proof_replay_attempts": len(replays),
        "proof_replay_rejections": sum(not event["allowed"] for event in replays)}
    if test_id == "healthy_resume":
        valid = healthy_span >= .2 - 1e-9
        relevant = []
    elif test_id == "proof_replay":
        valid = bool(replays)
        relevant = []
    else:
        changed_field = {"graph_change": "graph_fingerprint", "policy_change": "policy_fingerprint",
            "epoch_change": "command_epoch"}.get(test_id)
        relevant = [event for event in challenges if (event["expired"] if test_id == "ttl_gap"
            else changed_field in event["changed_fields"])]
        valid = bool(relevant)
    failures = []
    if valid:
        def fail(code, index=None):
            failures.append({"code": code, "frame_index": index})
        if not candidates:
            fail("missing_candidate")
        if not consumed:
            fail("missing_proof_consumption")
        if not motion:
            fail("missing_motion")
        for event in replays:
            if event["allowed"]:
                fail("replayed_proof_accepted", event["frame_index"])
        for event in relevant:
            index, old = event["frame_index"], event["proof"]["proof_id"]
            if index >= len(parsed) or parsed[index].mission_allowed or parsed[index].pending_proof is not None:
                fail("old_candidate_not_rejected", index)
            if any(frame.recovery_phase == "RESUMABLE" and frame.consumed_proof_id == old
                    for frame in parsed[index:]):
                fail("old_candidate_consumed", index)
            if not any(frame.mission_allowed and frame.consumed_proof_id and frame.consumed_proof_id != old
                    for frame in parsed[index + 1:]):
                fail("missing_new_proof_recovery", index)
    return {"test_id": test_id, "frames": frames, "witnesses": witnesses,
        "validity": "VALID" if valid else "NOT_EXERCISED",
        "assertion_result": ("FAIL" if failures else "PASS") if valid else "NOT_EVALUATED",
        "assertion_failures": failures}


def run_case(test_id):
    require_test_id(test_id)
    events = []
    frames = execute_scenario([Action(kind, duration) for kind, duration in SCENARIOS[test_id]],
        variant="full", witnesses=events)
    return validate_case(test_id, [frame.to_dict() for frame in frames], events)
