"""Explainable fusion of identity, temporal, graph and physical evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


def _bounded(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


@dataclass(frozen=True)
class EvidenceBundle:
    event_confidence: float
    source_trust: float
    temporal_violation: float
    graph_risk: float
    mission_criticality: float
    physical_inconsistency: float


@dataclass(frozen=True)
class FusionDecision:
    score: float
    level: str
    reasons: tuple[str, ...]


class EvidenceFusion:
    """Turn heterogeneous normalized evidence into one explainable risk score."""

    DEFAULT_WEIGHTS: Mapping[str, float] = {
        "event_confidence": 0.15,
        "source_trust": 0.20,
        "temporal_violation": 0.15,
        "graph_risk": 0.20,
        "mission_criticality": 0.15,
        "physical_inconsistency": 0.15,
    }
    EVIDENCE_KEYS = frozenset(DEFAULT_WEIGHTS)

    def __init__(self, weights: Mapping[str, float] | None = None, contain_threshold: float = 0.35, stop_threshold: float = 0.70) -> None:
        self.weights = dict(weights or self.DEFAULT_WEIGHTS)
        unknown_keys = set(self.weights) - self.EVIDENCE_KEYS
        if unknown_keys:
            raise ValueError(f"unknown evidence weights: {sorted(unknown_keys)}")
        if not self.weights or any(value < 0 for value in self.weights.values()) or sum(self.weights.values()) <= 0:
            raise ValueError("evidence weights must be non-negative and non-empty")
        if not 0.0 <= contain_threshold < stop_threshold <= 1.0:
            raise ValueError("thresholds must satisfy 0 <= contain < stop <= 1")
        self.contain_threshold = contain_threshold
        self.stop_threshold = stop_threshold

    def evaluate(self, evidence: EvidenceBundle) -> FusionDecision:
        values = {
            "event_confidence": 1.0 - _bounded(evidence.event_confidence),
            "source_trust": 1.0 - _bounded(evidence.source_trust),
            "temporal_violation": _bounded(evidence.temporal_violation),
            "graph_risk": _bounded(evidence.graph_risk),
            "mission_criticality": _bounded(evidence.mission_criticality),
            "physical_inconsistency": _bounded(evidence.physical_inconsistency),
        }
        total_weight = sum(self.weights.values())
        score = _bounded(sum(self.weights.get(key, 0.0) * value for key, value in values.items()) / total_weight)
        if score >= self.stop_threshold:
            level = "SAFE_STOP"
        elif score >= self.contain_threshold:
            level = "CONTAIN"
        else:
            level = "ALLOW"
        reasons = tuple(
            label for key, label in (
                ("event_confidence", "event confidence is low"),
                ("source_trust", "source trust is low"),
                ("temporal_violation", "temporal policy is violated"),
                ("graph_risk", "risk reaches a connected component"),
                ("mission_criticality", "mission component is critical"),
                ("physical_inconsistency", "physical telemetry is inconsistent"),
            ) if values[key] >= 0.35
        )
        return FusionDecision(score, level, reasons)
