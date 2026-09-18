from __future__ import annotations

from typing import Dict, Iterable, Set

from .models import AttackEvent, AttackRecord


class AttackRegistry:
    """Event-sourced attack registry; active state is not overwritten by a new message."""

    def __init__(self, expiry_sec: float = 5.0) -> None:
        self.expiry_sec = expiry_sec
        self._records: Dict[str, AttackRecord] = {}

    def upsert(self, event: AttackEvent, now: float) -> AttackRecord:
        existing = self._records.get(event.event_id)
        if existing is None:
            record = AttackRecord(event=event, first_seen=now, last_seen=now)
            self._records[event.event_id] = record
            return record
        existing.last_seen = now
        existing.event = event
        existing.status = "ACTIVE"
        return existing

    def expire(self, now: float) -> list[str]:
        expired: list[str] = []
        for event_id, record in list(self._records.items()):
            if now - record.last_seen > self.expiry_sec:
                record.status = "EXPIRED"
                expired.append(event_id)
                del self._records[event_id]
        return expired

    def clear_component(self, component: str) -> list[str]:
        removed = [event_id for event_id, record in self._records.items() if record.event.component == component]
        for event_id in removed:
            del self._records[event_id]
        return removed

    def active_records(self) -> tuple[AttackRecord, ...]:
        return tuple(self._records.values())

    def active_events(self) -> tuple[AttackEvent, ...]:
        return tuple(record.event for record in self._records.values())

    def active_components(self) -> frozenset[str]:
        return frozenset(record.event.component for record in self._records.values())

    def __len__(self) -> int:
        return len(self._records)
