"""Real fixture orchestration must retain deterministic execution and boundaries."""
import json
from pathlib import Path
import threading
import sys

import pytest


def api():
    if sys.platform != "linux":
        pytest.skip("optional offline agent runner requires Linux")
    pytest.importorskip("langgraph", reason="optional agent review environment")
    pytest.importorskip("pyseccomp", reason="optional agent review isolation")
    from experiments.agent_review.orchestration import run_review
    return run_review


def test_four_role_fixture_executes_six_actual_cases():
    result = api()({"sample": "guardian_recovery_virtual_model"})
    assert result["execution_status"] == "COMPLETE"
    assert result["provider_mode"] == "fixture"
    assert result["actuation"] == "none"
    assert result["external_calls"] == 0
    assert {e["role"] for e in result["role_events"]} == {"goals", "planner", "worker", "reviewer"}
    assert {e["test_id"] for e in result["executions"]} == {
        "healthy_resume", "ttl_gap", "graph_change", "policy_change", "epoch_change", "proof_replay"}
    assert all(e["frame_count"] > 0 for e in result["executions"])
    assert all(e["validity"] == "VALID" and e["assertion_result"] == "PASS" for e in result["executions"])
    assert result["detection"] == "NO_VIOLATIONS"
    assert result["target"]["kind"] == "guardian_recovery_virtual_model"
    assert result["target"]["uploaded_source_executed"] is False


def test_planner_cannot_smuggle_command_or_forge_claimed_pass(tmp_path):
    from experiments.agent_review.orchestration import FixtureProvider
    marker = tmp_path / "must-not-exist"
    provider = FixtureProvider({"planner": {"intents": [{"test_id": "healthy_resume",
        "command": f"touch {marker}", "passed": True}], "stop_reason": "", "gaps": []}})
    result = api()({"sample": "guardian_recovery_virtual_model"}, provider=provider)
    assert result["execution_status"] == "INCOMPLETE"
    assert result["executions"] == []
    assert result["detection"] == "NOT_RUN"
    assert not marker.exists()


def test_fixture_cannot_invent_artifact_or_override_oracle():
    from experiments.agent_review.orchestration import FixtureProvider
    result = api()({"sample": "guardian_recovery_virtual_model"}, provider=FixtureProvider({
        "reviewer": {"reviews": [{"finding_id": "made-up", "intent_id": "other-run",
            "artifact_refs": ["forged"], "assessment": "REPRODUCED", "counterevidence": "", "missing": ""}]}}))
    assert result["execution_status"] == "INCOMPLETE"
    assert result["detection"] == "NO_VIOLATIONS"
    assert not result["reviews"]


def test_cancelled_or_expired_job_does_not_run_tests():
    event = threading.Event()
    event.set()
    cancelled = api()({"sample": "guardian_recovery_virtual_model"}, cancel=event)
    assert cancelled["execution_status"] == "CANCELLED"
    assert cancelled["executions"] == []
    expired = api()({"sample": "guardian_recovery_virtual_model"}, timeout_sec=.001)
    assert expired["execution_status"] == "INCOMPLETE"
    assert expired["detection"] == "NOT_RUN"


def test_replay_matches_each_finding_not_whole_intent():
    from experiments.agent_review.orchestration import replay_assessment
    first = {"test_id": "proof_replay", "rule": "AUTH_WITHOUT_PROOF", "frame_index": 7}
    second = {"test_id": "proof_replay", "rule": "PROOF_REUSED", "frame_index": 7}
    assert replay_assessment(first, [dict(first)], comparable=True) == "REPRODUCED"
    assert replay_assessment(second, [dict(first)], comparable=True) == "NOT_REPRODUCED"
    assert replay_assessment(first, [dict(first)], comparable=False) == "INCONCLUSIVE"


def test_submitted_trace_violation_survives_successful_model_tests(tmp_path):
    api()
    from guardian_core.recovery_feedback import RecoveryFrame
    frames = [RecoveryFrame(now=1 + i * .05, task_phase="navigate", recovery_phase="SAFE_STOP",
        evidence_state="healthy", stopped_ack=True, unresolved=False, forced_stop=False,
        graph_fingerprint="g", policy_fingerprint="p", ledger_anchor="l",
        command_epoch=1, next_command_epoch=1, mission_allowed=False, speed_limit=0).to_dict()
        for i in range(65)]
    import subprocess
    target = tmp_path / "report.json"
    source = tmp_path / "trace.json"
    source.write_text(json.dumps({"frames": frames}))
    script = Path(__file__).resolve().parents[1] / "experiments/run_agent_review.py"
    run = subprocess.run([sys.executable, str(script), "--input", str(source), "--output", str(target)],
        capture_output=True, text=True, timeout=35)
    report = json.loads(target.read_text())
    assert report["detection"] == "VIOLATIONS"
    assert run.returncode == 1
    assert report["target"]["kind"] == "submitted_recovery_trace"
    assert report["model_detection"] == "NO_VIOLATIONS"
    original = [f for f in report["findings"] if f["verification_kind"] == "TRACE_RECHECK"]
    assert original and original[0]["rule"] == "oracle:recovery_stalled"
    assert original[0]["intent_id"] is None
    assert all(r["assessment"] == "INCONCLUSIVE" for r in report["reviews"])


def test_cli_writes_exclusive_report_and_rejects_extra_fields(tmp_path):
    api()
    import os
    import subprocess
    import sys
    script = Path(__file__).resolve().parents[1] / "experiments/run_agent_review.py"
    target = tmp_path / "review.json"
    done = subprocess.run([sys.executable, str(script), "--sample", "--output", str(target)],
        capture_output=True, text=True, timeout=35)
    assert done.returncode == 0, done.stderr
    raw = target.read_bytes()
    assert json.loads(raw)["execution_status"] == "COMPLETE"
    repeat = subprocess.run([sys.executable, str(script), "--sample", "--output", str(target)],
        capture_output=True, text=True, timeout=35)
    assert repeat.returncode == 2
    assert target.read_bytes() == raw
    bad = tmp_path / "input.json"
    bad.write_text('{"sample":"guardian_recovery_virtual_model","source_verified":true}')
    rejected = subprocess.run([sys.executable, str(script), "--input", str(bad),
        "--output", str(tmp_path / "bad-output.json")], capture_output=True, text=True, timeout=35)
    assert rejected.returncode == 2
    assert not (tmp_path / "bad-output.json").exists()
