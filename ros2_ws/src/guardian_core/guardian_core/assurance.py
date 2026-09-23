"""Explainable assurance decisions derived from the evidence ledger."""

from __future__ import annotations

from dataclasses import dataclass

from .evidence_ledger import Evidence, EvidenceLedger


@dataclass(frozen=True)
class AssuranceDecision:
    level: str
    score: float
    evidence_ids: tuple[str, ...]
    hard_stop_ids: tuple[str, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class Counterfactual:
    evidence_id: str
    level_without: str
    score_without: float
    explanation: str


class AssuranceController:
    def __init__(self, contain_threshold: float = 0.35, stop_threshold: float = 0.70) -> None:
        if not 0.0 <= contain_threshold < stop_threshold <= 1.0:
            raise ValueError("assurance thresholds must satisfy 0 <= contain < stop <= 1")
        self.contain_threshold = contain_threshold
        self.stop_threshold = stop_threshold

    def assess(self, ledger: EvidenceLedger, *, now: float) -> AssuranceDecision:
        if not ledger.verify():
            return AssuranceDecision(
                level="SAFE_STOP",
                score=1.0,
                evidence_ids=(),
                hard_stop_ids=("ledger-integrity",),
                reasons=("evidence ledger integrity verification failed",),
            )
        records = ledger.active(now)
        score, hard_stop_ids, reasons = self._score(records)
        level = "SAFE_STOP" if hard_stop_ids or score >= self.stop_threshold else (
            "CONTAIN" if score >= self.contain_threshold else "ALLOW"
        )
        return AssuranceDecision(
            level=level,
            score=score,
            evidence_ids=tuple(item.evidence_id for item in records),
            hard_stop_ids=hard_stop_ids,
            reasons=reasons,
        )

    def counterfactuals(self, ledger: EvidenceLedger, *, now: float) -> tuple[Counterfactual, ...]:
        if not ledger.verify():
            return ()
        records = ledger.active(now)
        result: list[Counterfactual] = []
        for removed in records:
            excluded = {removed.evidence_id}
            changed = True
            while changed:
                changed = False
                for item in records:
                    if item.evidence_id not in excluded and set(item.parent_ids) & excluded:
                        excluded.add(item.evidence_id)
                        changed = True
            remaining = tuple(item for item in records if item.evidence_id not in excluded)
            score, hard_stop_ids, _ = self._score(remaining)
            level = "SAFE_STOP" if hard_stop_ids or score >= self.stop_threshold else (
                "CONTAIN" if score >= self.contain_threshold else "ALLOW"
            )
            result.append(Counterfactual(
                evidence_id=removed.evidence_id,
                level_without=level,
                score_without=score,
                explanation=f"remove {removed.evidence_id} and recompute active evidence",
            ))
        return tuple(result)

    def _score(self, records: tuple[Evidence, ...]) -> tuple[float, tuple[str, ...], tuple[str, ...]]:
        if not records:
            return 0.0, (), ()
        hard_stop_ids = tuple(item.evidence_id for item in records if item.hard_stop)
        score = max(
            (item.confidence * item.severity for item in records),
            default=0.0,
        )
        reasons = tuple(
            f"{item.kind} evidence from {item.source} affects {item.node}"
            for item in records
            if item.severity * item.confidence >= self.contain_threshold
        )
        return score, hard_stop_ids, reasons


__all__ = ["AssuranceController", "AssuranceDecision", "Counterfactual"]
