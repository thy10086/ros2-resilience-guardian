import hashlib
import hmac
import math
from dataclasses import replace

import pytest

from guardian_core import AttackEvent, AttackRegistry, EventVerifier, RiskEngine
from guardian_core.models import GuardianConfig


def event(
    event_id="event-1",
    source="scenario_injector",
    component="left_arm",
    attack_type="STOP",
    sequence=1,
    timestamp=10.0,
    confidence=1.0,
    signature="",
):
    return AttackEvent(
        event_id,
        source,
        component,
        attack_type,
        sequence,
        timestamp,
        confidence,
        signature,
    )


def config(**kwargs):
    values = dict(
        task="navigate_to_goal",
        goal="box2",
        tau={"left_arm": 1},
        theta_base=0.72,
        theta_crit=0.8,
        alpha_base=0.2,
        alpha_crit=0.15,
        max_event_age_sec=5.0,
    )
    values.update(kwargs)
    return GuardianConfig(**values)


def test_stationary_event_persistence_uses_elapsed_time_since_first_seen():
    registry = AttackRegistry(expiry_sec=10.0)
    registry.upsert(event(), now=10.0)

    assessment = RiskEngine(config()).evaluate(registry.active_records(), now=15.0)

    assert assessment.risk == pytest.approx(0.249698178, rel=1e-6)


def test_component_persistence_uses_oldest_active_event_without_double_counting():
    registry = AttackRegistry(expiry_sec=10.0)
    registry.upsert(event(event_id="event-1", sequence=100), now=10.0)
    registry.upsert(event(event_id="event-2", sequence=1), now=12.0)

    assessment = RiskEngine(config()).evaluate(registry.active_records(), now=12.0)

    assert assessment.active_components == frozenset({"left_arm"})
    assert assessment.k_base == pytest.approx(1.0)
    assert assessment.risk == pytest.approx(0.159698178, rel=1e-6)


def test_latest_component_observation_uses_last_seen_and_timestamp_not_sequence():
    registry = AttackRegistry(expiry_sec=10.0)
    registry.upsert(event(event_id="event-a", source="source-a", sequence=100, confidence=1.0), now=10.0)
    registry.upsert(event(event_id="event-b", source="source-b", sequence=1, confidence=0.2), now=12.0)

    assessment = RiskEngine(config()).evaluate(registry.active_records(), now=12.0)

    assert assessment.k_base == pytest.approx(0.2)


def test_equal_observation_time_keeps_more_conservative_confidence():
    registry = AttackRegistry(expiry_sec=10.0)
    registry.upsert(event(event_id="event-a", source="source-a", sequence=100, confidence=0.2), now=10.0)
    registry.upsert(event(event_id="event-b", source="source-b", sequence=1, confidence=0.9), now=10.0)

    assessment = RiskEngine(config()).evaluate(registry.active_records(), now=10.0)

    assert assessment.k_base == pytest.approx(0.9)


def test_registry_keeps_same_event_id_separate_for_different_sources():
    registry = AttackRegistry(expiry_sec=5.0)
    first = registry.upsert(event(source="source-a"), now=10.0)
    second = registry.upsert(event(source="source-b"), now=10.0)

    assert first is not second
    assert len(registry) == 2
    assert {record.event.source for record in registry.active_records()} == {"source-a", "source-b"}
    assert registry.expire(now=16.0) == ["event-1", "event-1"]


def test_registry_fails_closed_when_active_event_capacity_is_exhausted():
    registry = AttackRegistry(expiry_sec=5.0, max_records=1)
    registry.upsert(event(event_id="first"), now=10.0)

    with pytest.raises(RuntimeError, match="capacity"):
        registry.upsert(event(event_id="second"), now=10.0)
    assert registry.capacity_exceeded


@pytest.mark.parametrize(
    "invalid_event",
    [
        event(timestamp=math.nan, sequence=2),
        event(timestamp=math.inf, sequence=2),
        event(confidence=math.nan, sequence=2),
        event(confidence=-math.inf, sequence=2),
        event(sequence=True),
        event(sequence=1.5),
        event(sequence=-1),
        event(sequence=2**64),
        event(event_id="x" * 257, sequence=2),
        event(source=object(), sequence=2),
        event(component="", sequence=2),
    ],
)
def test_malformed_event_is_rejected_without_advancing_replay_high_water(invalid_event):
    verifier = EventVerifier({"scenario_injector"})
    assert verifier.verify(event(sequence=1), now=10.0).accepted

    result = verifier.verify(invalid_event, now=10.0)

    assert not result.accepted
    assert result.code.value == "INVALID"
    assert verifier.verify(event(sequence=2), now=10.0).accepted


def test_nonfinite_now_is_rejected_without_advancing_replay_high_water():
    verifier = EventVerifier({"scenario_injector"})
    assert verifier.verify(event(sequence=1), now=10.0).accepted

    result = verifier.verify(event(sequence=2), now=math.nan)

    assert not result.accepted
    assert result.code.value == "INVALID"
    assert verifier.verify(event(sequence=2), now=10.0).accepted


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_event_age_sec": math.nan},
        {"max_event_age_sec": math.inf},
        {"max_event_age_sec": -1.0},
        {"max_event_age_sec": 10**1000},
        {"max_future_skew_sec": math.nan},
        {"max_future_skew_sec": math.inf},
        {"max_future_skew_sec": -1.0},
        {"require_signature": 1},
    ],
)
def test_verifier_rejects_invalid_configuration(kwargs):
    with pytest.raises((TypeError, ValueError)):
        EventVerifier({"scenario_injector"}, **kwargs)


def test_verifier_requires_secret_when_signatures_are_required():
    with pytest.raises(ValueError):
        EventVerifier({"scenario_injector"}, require_signature=True)


def test_optional_hmac_secret_does_not_require_a_signature():
    secret = b"test-secret"
    unsigned = event()
    payload = "|".join(
        [
            unsigned.event_id,
            unsigned.source,
            unsigned.component,
            unsigned.attack_type,
            str(unsigned.sequence),
            f"{unsigned.timestamp:.6f}",
            f"{unsigned.confidence:.6f}",
        ]
    ).encode()
    signed = event(
        sequence=2,
        signature=hmac.new(secret, payload, hashlib.sha256).hexdigest(),
    )

    verifier = EventVerifier({"scenario_injector"}, signature_secret=secret)

    assert verifier.verify(unsigned, now=10.0).accepted
    assert verifier.verify(signed, now=10.0).accepted


@pytest.mark.parametrize("signature", ["\u00e9" * 64, "a" * 63 + "\u4e2d", "\ud800"])
def test_non_ascii_signature_is_invalid_without_advancing_replay_high_water(signature):
    secret = b"test-secret"
    verifier = EventVerifier(
        {"scenario_injector"}, signature_secret=secret, require_signature=True
    )
    first = event(
        signature=hmac.new(
            secret,
            b"event-1|scenario_injector|left_arm|STOP|1|10.000000|1.000000",
            hashlib.sha256,
        ).hexdigest()
    )
    assert verifier.verify(first, now=10.0).accepted

    result = verifier.verify(event(sequence=2, signature=signature), now=10.0)

    assert not result.accepted
    assert result.code.value == "INVALID"
    corrected = event(
        sequence=2,
        signature=hmac.new(
            secret,
            b"event-1|scenario_injector|left_arm|STOP|2|10.000000|1.000000",
            hashlib.sha256,
        ).hexdigest(),
    )
    assert verifier.verify(corrected, now=10.0).accepted
    assert verifier.verify(corrected, now=10.0).code.value == "REPLAY"


@pytest.mark.parametrize("field", ["event_id", "source", "component", "attack_type"])
@pytest.mark.parametrize("require_signature", [False, True])
def test_pipe_in_identity_is_invalid_before_replay_update(field, require_signature):
    secret = b"test-secret"
    malformed = replace(event(sequence=2), **{field: "left|right"})
    payload = "|".join(
        [
            malformed.event_id, malformed.source, malformed.component,
            malformed.attack_type, "2", "10.000000", "1.000000",
        ]
    ).encode("utf-8")
    malformed = replace(
        malformed, signature=hmac.new(secret, payload, hashlib.sha256).hexdigest()
    )
    verifier = EventVerifier(
        {"scenario_injector", "left|right"},
        signature_secret=secret,
        require_signature=require_signature,
    )

    result = verifier.verify(malformed, now=10.0)

    assert not result.accepted
    assert result.code.value == "INVALID"
    corrected = event(
        sequence=2,
        signature=hmac.new(
            secret,
            b"event-1|scenario_injector|left_arm|STOP|2|10.000000|1.000000",
            hashlib.sha256,
        ).hexdigest(),
    )
    assert verifier.verify(corrected, now=10.0).accepted


@pytest.mark.parametrize(
    "component,attack_type",
    [("left_arm|STOP", "FAULT"), ("left_arm", "STOP|FAULT")],
)
def test_ambiguous_identity_cannot_reuse_the_same_hmac(component, attack_type):
    secret = b"test-secret"
    signature = hmac.new(
        secret,
        b"event-1|scenario_injector|left_arm|STOP|FAULT|1|10.000000|1.000000",
        hashlib.sha256,
    ).hexdigest()
    verifier = EventVerifier(
        {"scenario_injector"}, signature_secret=secret, require_signature=True
    )

    result = verifier.verify(
        event(component=component, attack_type=attack_type, signature=signature),
        now=10.0,
    )

    assert not result.accepted
    assert result.code.value == "INVALID"
