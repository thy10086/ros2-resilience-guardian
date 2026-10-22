from __future__ import annotations

import hashlib
import hmac
import math
from dataclasses import dataclass
from typing import Dict, Iterable, Set

from .models import AttackEvent, VerificationCode, VerificationResult


_UINT64_MAX = 2**64 - 1
_IDENTITY_LIMITS = {
    "event_id": 128,
    "source": 64,
    "component": 96,
    "attack_type": 64,
}


@dataclass
class EventVerifier:
    trusted_sources: Set[str]
    max_event_age_sec: float = 5.0
    max_future_skew_sec: float = 0.5
    signature_secret: bytes | None = None
    require_signature: bool = False

    def __post_init__(self) -> None:
        if not self._is_finite_number(self.max_event_age_sec) or self.max_event_age_sec < 0:
            raise ValueError("max_event_age_sec must be a finite non-negative number")
        if not self._is_finite_number(self.max_future_skew_sec) or self.max_future_skew_sec < 0:
            raise ValueError("max_future_skew_sec must be a finite non-negative number")
        if type(self.require_signature) is not bool:
            raise ValueError("require_signature must be a native bool")
        if self.signature_secret is not None and not isinstance(self.signature_secret, bytes):
            raise ValueError("signature_secret must be bytes or None")
        if self.require_signature and not self.signature_secret:
            raise ValueError("signature_secret is required when signatures are required")
        self._last_sequence: Dict[str, int] = {}

    def verify(self, event: AttackEvent, now: float) -> VerificationResult:
        if not self._is_finite_number(now):
            return VerificationResult(False, VerificationCode.INVALID, "now must be finite")
        if not self._valid_identity_fields(event):
            return VerificationResult(False, VerificationCode.INVALID, "event identity fields are malformed")
        if not self._valid_sequence(event.sequence):
            return VerificationResult(False, VerificationCode.INVALID, "sequence must be an unsigned uint64 integer")
        if not self._is_finite_number(event.timestamp):
            return VerificationResult(False, VerificationCode.INVALID, "timestamp must be finite")
        if not self._is_finite_number(event.confidence):
            return VerificationResult(False, VerificationCode.INVALID, "confidence must be finite")
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
        if (
            not self.signature_secret
            or not isinstance(event.signature, str)
            or not event.signature
            or not event.signature.isascii()
        ):
            return False
        expected = self.sign_event(self.signature_secret, event)
        return hmac.compare_digest(expected, event.signature)

    @staticmethod
    def sign_event(secret: bytes, event: AttackEvent) -> str:
        payload = "|".join([
            event.event_id, event.source, event.component, event.attack_type,
            str(event.sequence), f"{event.timestamp:.6f}", f"{event.confidence:.6f}",
        ]).encode("utf-8")
        return hmac.new(secret, payload, hashlib.sha256).hexdigest()

    @staticmethod
    def _is_finite_number(value: object) -> bool:
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return False
        try:
            return math.isfinite(float(value))
        except (OverflowError, ValueError):
            return False

    @staticmethod
    def _valid_sequence(sequence: object) -> bool:
        return (
            isinstance(sequence, int)
            and not isinstance(sequence, bool)
            and 0 <= sequence <= _UINT64_MAX
        )

    @staticmethod
    def _valid_identity_fields(event: AttackEvent) -> bool:
        for field, limit in _IDENTITY_LIMITS.items():
            value = getattr(event, field, None)
            if (
                not isinstance(value, str)
                or not value
                or len(value) > limit
                or "|" in value
                or value != value.strip()
                or any(ord(char) < 32 or ord(char) == 127 for char in value)
            ):
                return False
        return True

    def verify_batch(self, events: Iterable[AttackEvent], now: float) -> list[VerificationResult]:
        return [self.verify(event, now) for event in events]
