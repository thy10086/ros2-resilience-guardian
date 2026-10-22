from __future__ import annotations

from typing import Dict, Iterable, Set

from .models import AttackEvent, AttackRecord


class AttackRegistry:
    """Event-sourced attack registry; active state is not overwritten by a new message."""

    def __init__(self, expiry_sec: float = 5.0, max_records: int = 1024) -> None:
        self.expiry_sec = expiry_sec
        if type(max_records) is not int or max_records <= 0:
            raise ValueError("max_records must be a positive integer")
        self.max_records = max_records
        self.capacity_exceeded = False
        self._records: Dict[tuple[str, str], AttackRecord] = {}

    def upsert(self, event: AttackEvent, now: float) -> AttackRecord:
        key = (event.source, event.event_id)
        existing = self._records.get(key)
        if existing is None:
            if len(self._records) >= self.max_records:
                self.capacity_exceeded = True
                raise RuntimeError("attack registry capacity exceeded")
            record = AttackRecord(event=event, first_seen=now, last_seen=now)
            self._records[key] = record
            return record
        existing.last_seen = now
        existing.event = event
        existing.status = "ACTIVE"
        return existing

    def expire(self, now: float) -> list[str]:
        expired: list[str] = []
        for key, record in list(self._records.items()):
            if now - record.last_seen > self.expiry_sec:
                record.status = "EXPIRED"
                expired.append(record.event.event_id)
                del self._records[key]
        return expired

    def clear_component(self, component: str) -> list[str]:
        removed = [
            record.event.event_id
            for key, record in self._records.items()
            if record.event.component == component
        ]
        for key, record in list(self._records.items()):
            if record.event.component == component:
                del self._records[key]
        return removed

    def clear_source(self, source: str) -> list[str]:
        """Resolve a source only after an adapter supplies authenticated health evidence."""
        removed = []
        for key, record in list(self._records.items()):
            if record.event.source == source:
                removed.append(record.event.event_id)
                del self._records[key]
        return removed

    def active_records(self) -> tuple[AttackRecord, ...]:
        return tuple(self._records.values())

    def active_events(self) -> tuple[AttackEvent, ...]:
        return tuple(record.event for record in self._records.values())

    def active_components(self) -> frozenset[str]:
        return frozenset(record.event.component for record in self._records.values())

    def __len__(self) -> int:
        return len(self._records)
