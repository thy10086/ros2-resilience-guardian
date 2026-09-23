"""Append-only, hash-chained evidence with bounded lineage semantics."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any


def _finite(value: float, name: str) -> float:
    value = float(value)
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    return value


def _bounded(value: float, name: str) -> float:
    value = _finite(value, name)
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be in [0, 1]")
    return value


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    source: str
    kind: str
    node: str
    observed_at: float
    expires_at: float
    confidence: float
    severity: float
    policy_version: str
    parent_ids: tuple[str, ...] = ()
    supersedes: str | None = None
    verified: bool = False
    hard_stop: bool = False

    def __post_init__(self) -> None:
        if not all((self.evidence_id, self.source, self.kind, self.node, self.policy_version)):
            raise ValueError("evidence identity fields cannot be empty")
        observed = _finite(self.observed_at, "observed_at")
        expires = _finite(self.expires_at, "expires_at")
        if expires <= observed:
            raise ValueError("evidence must expire after observation")
        _bounded(self.confidence, "confidence")
        _bounded(self.severity, "severity")
        if len(set(self.parent_ids)) != len(self.parent_ids):
            raise ValueError("duplicate evidence parent")

    def canonical(self) -> dict[str, Any]:
        return {
            "confidence": self.confidence,
            "evidence_id": self.evidence_id,
            "expires_at": self.expires_at,
            "hard_stop": self.hard_stop,
            "kind": self.kind,
            "node": self.node,
            "observed_at": self.observed_at,
            "parent_ids": list(self.parent_ids),
            "policy_version": self.policy_version,
            "severity": self.severity,
            "source": self.source,
            "supersedes": self.supersedes,
            "verified": self.verified,
        }


@dataclass(frozen=True)
class LedgerAnchor:
    count: int
    head: str


class EvidenceLedger:
    def __init__(self) -> None:
        self._records: list[Evidence] = []
        self._hashes: list[str] = []
        self._superseded: set[str] = set()

    def append(self, evidence: Evidence) -> Evidence:
        if any(item.evidence_id == evidence.evidence_id for item in self._records):
            raise ValueError("duplicate evidence id")
        by_id = {item.evidence_id: item for item in self._records}
        for parent_id in evidence.parent_ids:
            parent = by_id.get(parent_id)
            if parent is None or not parent.verified or parent.expires_at <= evidence.observed_at:
                raise ValueError("evidence parent is missing, expired, or unverified")
            if parent.policy_version != evidence.policy_version:
                raise ValueError("evidence parent policy version differs")
        if evidence.supersedes:
            if not evidence.verified:
                raise ValueError("unverified evidence cannot supersede")
            target = by_id.get(evidence.supersedes)
            if target is None:
                raise ValueError("superseded evidence is missing")
            if target.source != evidence.source:
                raise ValueError("cross-source evidence replacement is forbidden")
            if target.hard_stop and not evidence.hard_stop:
                raise ValueError("hard-stop evidence cannot be cleared by a soft replacement")
            self._superseded.add(target.evidence_id)
        previous = self._hashes[-1] if self._hashes else "GENESIS"
        self._records.append(evidence)
        self._hashes.append(self._hash_entry(previous, evidence))
        return evidence

    def active(self, now: float) -> tuple[Evidence, ...]:
        now = _finite(now, "now")
        by_id = {item.evidence_id: item for item in self._records}

        def lineage_active(item: Evidence, seen: frozenset[str] = frozenset()) -> bool:
            if item.evidence_id in seen:
                return False
            if not item.verified or item.evidence_id in self._superseded:
                return False
            if not item.observed_at <= now < item.expires_at:
                return False
            return all(
                parent_id in by_id and lineage_active(by_id[parent_id], seen | {item.evidence_id})
                for parent_id in item.parent_ids
            )

        return tuple(
            item for item in self._records
            if lineage_active(item)
        )

    def anchor(self) -> LedgerAnchor:
        return LedgerAnchor(len(self._records), self._hashes[-1] if self._hashes else "GENESIS")

    def export(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            {"evidence": item.canonical(), "hash": self._hashes[index]}
            for index, item in enumerate(self._records)
        )

    @staticmethod
    def verify_export(exported: tuple[dict[str, Any], ...], anchor: LedgerAnchor) -> bool:
        if len(exported) != anchor.count:
            return False
        previous = "GENESIS"
        known: dict[str, Evidence] = {}
        expected_superseded: set[str] = set()
        try:
            for entry in exported:
                evidence = Evidence(**entry["evidence"])
                if evidence.evidence_id in known:
                    return False
                for parent_id in evidence.parent_ids:
                    parent = known.get(parent_id)
                    if parent is None or not parent.verified or parent.expires_at <= evidence.observed_at:
                        return False
                    if parent.policy_version != evidence.policy_version:
                        return False
                if evidence.supersedes:
                    target = known.get(evidence.supersedes)
                    if target is None or not evidence.verified or target.source != evidence.source:
                        return False
                    if target.hard_stop and not evidence.hard_stop:
                        return False
                    expected_superseded.add(target.evidence_id)
                expected = EvidenceLedger._hash_entry(previous, evidence)
                if entry.get("hash") != expected:
                    return False
                known[evidence.evidence_id] = evidence
                previous = expected
        except (KeyError, TypeError, ValueError):
            return False
        return previous == anchor.head

    def verify(self) -> bool:
        previous = "GENESIS"
        known: dict[str, Evidence] = {}
        expected_superseded: set[str] = set()
        for index, item in enumerate(self._records):
            if item.evidence_id in known:
                return False
            try:
                item.__post_init__()
            except (TypeError, ValueError):
                return False
            if any(parent not in known for parent in item.parent_ids):
                return False
            for parent_id in item.parent_ids:
                parent = known[parent_id]
                if not parent.verified or parent.expires_at <= item.observed_at:
                    return False
                if parent.policy_version != item.policy_version:
                    return False
            if item.supersedes:
                target = known.get(item.supersedes)
                if target is None or not item.verified or target.source != item.source:
                    return False
                if target.hard_stop and not item.hard_stop:
                    return False
                expected_superseded.add(target.evidence_id)
            expected = self._hash_entry(previous, item)
            if index >= len(self._hashes) or self._hashes[index] != expected:
                return False
            known[item.evidence_id] = item
            previous = expected
        return len(self._hashes) == len(self._records) and expected_superseded == self._superseded

    @staticmethod
    def _hash_entry(previous: str, evidence: Evidence) -> str:
        payload = json.dumps(
            {"previous": previous, "evidence": evidence.canonical()},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(payload).hexdigest()


__all__ = ["Evidence", "EvidenceLedger", "LedgerAnchor"]
