"""Submitted static evidence must survive unrelated successful model executions."""
import json
from pathlib import Path
import subprocess
import sys

import pytest


UNSAFE_SOURCE = '''import subprocess
from rclpy.node import Node
class UnsafeController(Node):
 def __init__(self):
  super().__init__("unsafe_controller")
  self.drive_pub = self.create_publisher(object, "/cmd_vel", 10)
 def callback(self,message):
  eval(message.command)
  subprocess.run(["sh", "-c", message.command])
  self.drive_pub.publish(message)
'''


def review_api():
    if sys.platform != "linux":
        pytest.skip("optional agent runner requires Linux")
    pytest.importorskip("langgraph")
    pytest.importorskip("pyseccomp")
    from experiments.agent_review.orchestration import run_review
    return run_review


def unsafe_input():
    return {"files": [{"filename": "controller.py", "source": UNSAFE_SOURCE}]}


def test_static_high_risk_survives_six_clean_model_tests_and_cli(tmp_path):
    # Catches source findings being dropped and model success overwriting risk.
    review_api()
    source = tmp_path / "source.json"
    output = tmp_path / "report.json"
    source.write_text(json.dumps(unsafe_input()), encoding="utf-8")
    script = Path(__file__).resolve().parents[1] / "experiments/run_agent_review.py"
    completed = subprocess.run([sys.executable, str(script), "--input", str(source),
        "--output", str(output)], capture_output=True, text=True, timeout=35)
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["execution_status"] == "COMPLETE"
    assert len(report["executions"]) == 6
    assert report["model_detection"] == "NO_VIOLATIONS"
    assert report["input_summary"]["static"]["counts"]["critical"] == 1
    assert report["input_summary"]["static"]["counts"]["high"] == 4
    assert completed.returncode == 1
    assert report["detection"] == "STATIC_REVIEW_REQUIRED"
    assert report["static_detection"] == "BLOCKED"
    assert report["target"]["kind"] == "submitted_source_static"
    assert report["execution_target"]["kind"] == "guardian_recovery_virtual_model"
    submitted = next(t for t in report["targets"] if t["kind"] == "submitted_source_static")
    assert submitted["detection"] == "BLOCKED"
    assert submitted["runtime_verified"] is False
    findings = report["findings"]
    assert len(findings) == 5
    assert {f["severity"] for f in findings} == {"critical", "high"}
    for finding in findings:
        assert finding["verification_kind"] == "STATIC_REVIEW"
        assert finding["intent_id"] is None and finding["test_id"] is None
        assert finding["file"] == "controller.py" and finding["line"] > 0
        assert finding["authenticated"] is False and finding["runtime_verified"] is False
        assert finding["evidence_refs"] and finding["artifact_refs"]
    assert len(report["reviews"]) == 5
    assert all(r["assessment"] == "INCONCLUSIVE" for r in report["reviews"])


@pytest.mark.parametrize(("filename", "source", "provenance", "unsupported"), [
    ("controller.cpp", "int main() { return 0; }", "UNSUPPORTED", ["controller.cpp"]),
    ("controller.py", "def broken(:\n", "EXTRACTED", []),
])
def test_static_parser_gaps_remain_visible_after_clean_model_tests(filename, source, provenance, unsupported):
    # Catches unsupported/failed extraction disappearing behind clean model tests.
    report = review_api()({"files": [{"filename": filename, "source": source}]})
    assert report["execution_status"] == "COMPLETE"
    assert report["model_detection"] == "NO_VIOLATIONS"
    assert report["detection"] == "STATIC_REVIEW_REQUIRED"
    assert report["static_detection"] == "BLOCKED"
    assert report["input_summary"]["static"]["unsupported_files"] == unsupported
    assert report["input_summary"]["static"]["assurance"]["runtime_verified"] is False
    assert any(f["rule"] == "static:GRAPH-PARSE-001" and f["provenance"] == provenance
        for f in report["findings"])


def test_static_findings_checkpoint_survives_invalid_planner():
    # Catches failure paths discarding deterministic input findings before workers.
    from experiments.agent_review.orchestration import FixtureProvider
    report = review_api()(unsafe_input(), provider=FixtureProvider({"planner": {
        "intents": [{"command": "forbidden"}], "stop_reason": "", "gaps": []}}))
    assert report["execution_status"] == "INCOMPLETE"
    assert report["executions"] == []
    assert report["model_detection"] == "NOT_RUN"
    assert report["detection"] == "STATIC_REVIEW_REQUIRED"
    assert report["static_detection"] == "BLOCKED"
    assert len(report["findings"]) == 5


def test_reviewer_cannot_claim_static_risk_was_reproduced_or_dismissed():
    # Catches model assessments overriding the program's lack of target execution.
    run_review = review_api()
    from experiments.agent_review.orchestration import FixtureProvider
    first = run_review(unsafe_input())
    assert first["reviews"], "static findings must receive program-bound reviews"
    forged = [{**row, "assessment": "NOT_REPRODUCED"} for row in first["reviews"]]
    report = run_review(unsafe_input(), provider=FixtureProvider({"reviewer": {"reviews": forged}}))
    assert report["execution_status"] == "INCOMPLETE"
    assert report["detection"] == "STATIC_REVIEW_REQUIRED"
    assert report["static_detection"] == "BLOCKED"
    assert len(report["findings"]) == 5
    assert report["reviews"] == []
