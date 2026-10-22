"""Export a verified evaluation snapshot and replay traces for the dashboard.

The dashboard never starts fuzzing or imports experimental mutants at runtime.
"""
import argparse
import hashlib
import json
from pathlib import Path

from run_recovery_evaluation import ROOT, aggregate_runs, violation_codes
from recovery_scenarios import Action, execute_scenario
from guardian_core.recovery_feedback import SafetyOracle


def export_dashboard(summary_path, destination):
    summary_path, destination = Path(summary_path), Path(destination)
    raw = summary_path.read_bytes()
    report = json.loads(raw)
    modes = ["unguided", "guided", "boundary", "ttl", "context_repair"]
    runs = report["runs"]
    if (report["modes"] != modes or report["protocol"]["seed_role"] != "unseen_validation"
            or report["full_mechanism_violations"] or report["counterexample_replay_mismatches"]
            or report["corpus_replay_mismatches"] or report["qualification"]["control_violations"]
            or report["qualification"]["detected_families"] != 4
            or report["replay_verification"]["corpora"] != len(runs)
            or len(runs) != len(modes) * len(report["seeds"])
            or {(r["mode"], r["seed"]) for r in runs} != {(m, s) for m in modes for s in report["seeds"]}
            or any(r["generated_executions"] != report["budget"] or r["seed_executions"] or r["violations"] for r in runs)
            or aggregate_runs(runs) != report["aggregate"]):
        raise ValueError("Only a complete, passing paired validation can be published")
    for path, expected in report["protocol"]["source_sha256"].items():
        if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != expected:
            raise ValueError(f"Frozen evaluation source changed: {path}")
    oracle = SafetyOracle()
    if report["protocol"]["oracle_config"] != {"liveness_sec": oracle.liveness_sec,
            "max_frame_gap_sec": oracle.max_frame_gap_sec}:
        raise ValueError("Oracle parameters differ from the recorded batch")
    snapshot = {"schema": "guardian-recovery-evaluation/v1", "round": 6,
        "source_summary_sha256": hashlib.sha256(raw).hexdigest(),
        "source_report": "feedback_target_ablation_corrected/summary.json",
        "generated_executions": sum(r["generated_executions"] for r in runs),
        **{key: report[key] for key in ("seeds", "budget", "modes", "protocol", "aggregate", "replay_verification")},
        "full_mechanism_violations": 0,
        "interpretation": "本批次边界反馈提高 TTL 缺陷检出，但总转移覆盖下降；与前批次方向不同，尚未证明稳定全面优势。",
        "raw_batch_note": "原始批次两例连续活性误报已保留；修正采样空窗前提后重跑相同种子，两批不合并统计。"}
    samples = []
    for sample_id, title, actions in (
            ("healthy", "正常恢复", [Action("healthy", .6)]),
            ("gaps", "控制暂停后恢复（活性空窗）", [Action("gap", .6)] * 6 + [Action("wait", .6)])):
        trace = execute_scenario(actions)
        if violation_codes(trace):
            raise ValueError("Healthy control failed")
        samples.append({"id": sample_id, "title": title, "kind": "完整机制控制",
            "expected_codes": [], "frames": [f.to_dict() for f in trace]})
    titles = {"no_proof_ttl": "过期许可被消费", "no_context_binding": "消费上下文错配",
        "accept_proof_replay": "一次性许可被重放", "no_independent_observation": "缺少独立观测约束"}
    for case in report["qualification"]["cases"]:
        saved = json.loads((ROOT / case["counterexample_path"]).read_text())
        from guardian_core.recovery_feedback import RecoveryFrame
        if violation_codes([RecoveryFrame.from_dict(f) for f in saved["frames"]]) != case["violation_codes"]:
            raise ValueError("Saved qualification trace differs from its Oracle result")
        samples.append({"id": case["variant"], "title": titles[case["variant"]], "kind": "受控缺陷轨迹",
            "expected_codes": case["violation_codes"], "frames": saved["frames"]})
    destination.mkdir(parents=True, exist_ok=True)
    for name, value in (("recovery-evaluation.json", snapshot), ("recovery-samples.json", {"samples": samples})):
        (destination / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return snapshot


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary", type=Path)
    parser.add_argument("--destination", type=Path, default=ROOT / "ros2_ws/src/guardian_core/guardian_core/frontend")
    args = parser.parse_args()
    result = export_dashboard(args.summary, args.destination)
    print(json.dumps({"exported_executions": result["generated_executions"], "destination": str(args.destination)}))
