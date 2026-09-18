from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Dict, Iterable, Set

from .models import AttackEvent, VerificationCode, VerificationResult


@dataclass
class EventVerifier:
    trusted_sources: Set[str]
    max_event_age_sec: float = 5.0
    max_future_skew_sec: float = 0.5
    signature_secret: bytes | None = None
    require_signature: bool = False

    def __post_init__(self) -> None:
        self._last_sequence: Dict[str, int] = {}

    def verify(self, event: AttackEvent, now: float) -> VerificationResult:
        if not event.event_id or not event.source or not event.component or not event.attack_type:
            return VerificationResult(False, VerificationCode.INVALID, "required event field is empty")
        if event.source not in self.trusted_sources:
            return VerificationResult(False, VerificationCode.UNKNOWN_SOURCE, f"source {event.source!r} is not trusted")
        if event.confidence < 0.0 or event.confidence > 1.0:
            return VerificationResult(False, VerificationCode.INVALID, "confidence must be in [0, 1]")
        if self.require_signature and not self._valid_signature(event):
            return VerificationResult(False, VerificationCode.INVALID, "event signature is invalid")
        if event.timestamp > now + self.max_future_skew_sec:
            return VerificationResult(False, VerificationCode.FUTURE, "event timestamp is too far in the future")
        if now - event.timestamp > self.max_event_age_sec:
            return VerificationResult(False, VerificationCode.STALE, "event is older than the replay window")
        previous = self._last_sequence.get(event.source, -1)
        if event.sequence <= previous:
            return VerificationResult(False, VerificationCode.REPLAY, "sequence number is not strictly increasing")
        self._last_sequence[event.source] = event.sequence
        return VerificationResult(True, VerificationCode.ACCEPTED, "event accepted")

    def _valid_signature(self, event: AttackEvent) -> bool:
        if not self.signature_secret or not event.signature:
            return False
        payload = "|".join([
            event.event_id, event.source, event.component, event.attack_type,
            str(event.sequence), f"{event.timestamp:.6f}", f"{event.confidence:.6f}",
        ]).encode("utf-8")
        expected = hmac.new(self.signature_secret, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, event.signature)

    def verify_batch(self, events: Iterable[AttackEvent], now: float) -> list[VerificationResult]:
        return [self.verify(event, now) for event in events]
