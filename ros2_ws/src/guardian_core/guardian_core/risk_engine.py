from __future__ import annotations

import math
from typing import Iterable, Mapping

from .models import AttackEvent, AttackRecord, GuardianConfig, RiskAssessment


class RiskEngine:
    """Paper-compatible delta/psi/gamma plus a bounded runtime risk score."""

    def __init__(self, config: GuardianConfig) -> None:
        self.config = config

    def criticality(self, component: str) -> int:
        return max(self.config.tau.get(component, 0), self.config.epsilon.get(component, 0))

    def evaluate(self, records: Iterable[AttackRecord], now: float, excluded: frozenset[str] = frozenset()) -> RiskAssessment:
        # Multiple telemetry events may describe the same ongoing component attack.
        # Count a component once and use its newest verified event for severity/confidence.
        latest_by_component: dict[str, AttackRecord] = {}
        for record in records:
            component = record.event.component
            if component in excluded:
                continue
            previous = latest_by_component.get(component)
            if previous is None or record.event.sequence >= previous.event.sequence:
                latest_by_component[component] = record
        records = tuple(latest_by_component.values())
        active = frozenset(record.event.component for record in records)
        critical = frozenset(component for component in active if self.criticality(component) == 2)
        k_crit = sum(max(0.0, record.event.confidence) for record in records if self.criticality(record.event.component) == 2)
        k_base = sum(max(0.0, record.event.confidence) for record in records if self.criticality(record.event.component) == 1)
        psi = math.exp(-self.config.alpha_crit * k_crit) * math.exp(-self.config.alpha_base * k_base)
        delta = 0 if critical else 1
        threshold = self.config.theta_crit if critical else self.config.theta_base
        gamma = 1 if psi >= threshold else 0

        # Runtime score adds persistence and confidence while preserving [0, 1].
        degradation = 1.0 - psi
        persistence = 0.0
        if records:
            persistence = min(1.0, sum(min(1.0, record.age / max(self.config.max_event_age_sec, 0.1)) for record in records) / len(records))
        confidence_risk = 0.0
        if records:
            confidence_risk = sum(1.0 - record.event.confidence for record in records) / len(records)
        critical_risk = 1.0 if critical else 0.0
        risk = min(1.0, 0.55 * degradation + 0.25 * critical_risk + 0.15 * persistence + 0.05 * confidence_risk)

        if not active:
            reason = "no active verified attacks"
        elif delta == 0 and gamma == 0:
            reason = "critical component and degradation threshold both violated"
        elif delta == 0:
            reason = "critical component remains active"
        elif gamma == 0:
            reason = "aggregate non-critical degradation exceeds threshold"
        else:
            reason = "verified attacks remain within mission tolerance"
        return RiskAssessment(now, delta, gamma, psi, risk, critical, active, k_crit, k_base, reason)
