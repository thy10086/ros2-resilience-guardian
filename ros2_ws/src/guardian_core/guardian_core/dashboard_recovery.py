"""Bounded, read-only dashboard adapter for the existing recovery trace Oracle."""
from dataclasses import asdict
import math

from .recovery_feedback import RecoveryFrame, SafetyOracle, SemanticCoverage

MAX_TRACE_FRAMES = 2000
MAX_TRACE_BYTES = 2 * 1024 * 1024
RECOVERY_PHASES = {"SAFE_STOP", "RECOVERY_PROBING", "RECOVERY_CANDIDATE", "RESUMABLE", "NORMAL"}


def inspect_recovery_trace(payload):
    if not isinstance(payload, dict) or set(payload) != {"frames"}:
        raise ValueError("仅支持 frames 轨迹字段")
    rows = payload["frames"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_TRACE_FRAMES:
        raise ValueError(f"轨迹需包含 1–{MAX_TRACE_FRAMES} 帧")
    frames = []
    for index, row in enumerate(rows):
        try:
            if not isinstance(row, dict):
                raise ValueError("帧必须是对象")
            frame = RecoveryFrame.from_dict(row)
            if frame.recovery_phase not in RECOVERY_PHASES:
                raise ValueError("恢复阶段无效")
            if frame.pending_proof and frame.pending_proof["expires_at"] <= frame.pending_proof["issued_at"]:
                raise ValueError("许可有效期必须为正")
            if any(not math.isfinite(getattr(frame, key)) for key in ("now", "speed_limit", "observed_speed")):
                raise ValueError("轨迹数值必须有限")
            if any(len(value) > 256 for value in row.values() if isinstance(value, str)):
                raise ValueError("标识符过长")
        except (TypeError, ValueError, OverflowError) as error:
            raise ValueError(f"第 {index + 1} 帧格式无效") from error
        frames.append(frame)
    oracle = SafetyOracle()
    violations = oracle.check_trace(frames)
    coverage = SemanticCoverage()
    coverage.observe_trace(frames)
    gaps = [index for index in range(1, len(frames))
        if frames[index].now - frames[index - 1].now > oracle.max_frame_gap_sec]
    return {
        "schema": "guardian-recovery-inspection/v1", "actuation": "none",
        "verdict": "VIOLATIONS" if violations else "NO_VIOLATIONS",
        "frame_count": len(frames), "coverage": coverage.summary(),
        "violation_codes": sorted({v.code for v in violations}), "violation_count": len(violations),
        "violations": [{**asdict(v), "now": frames[v.frame_index].now,
            "recovery_phase": frames[v.frame_index].recovery_phase,
            "graph_fingerprint": frames[v.frame_index].graph_fingerprint,
            "policy_fingerprint": frames[v.frame_index].policy_fingerprint,
            "ledger_anchor": frames[v.frame_index].ledger_anchor,
            "consumed_proof_id": frames[v.frame_index].consumed_proof_id}
            for v in violations[:100]],
        "violations_truncated": len(violations) > 100,
        "liveness_gaps": len(gaps), "liveness_gap_indices": gaps,
        "oracle_config": {"liveness_sec": oracle.liveness_sec, "max_frame_gap_sec": oracle.max_frame_gap_sec},
        "limitations": "只检查提交的审计帧，无法认证日志来源或证明物理安全；未发现违规不等于安全认证。",
    }
