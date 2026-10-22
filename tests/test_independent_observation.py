import math

import pytest

from guardian_core.bound_recovery import RecoveryTelemetry
from guardian_core.independent_observation import SensorObservationBuffer, IndependentSample, fuse_observations
from guardian_core.feedback_auth import sign_independent_observation, verify_independent_observation


def inputs(buffer, stamp=10.0, speed=0.0, ranges=(2.0, 2.0, 2.0)):
    buffer.observe_odometry(stamp=stamp, received_at=100.0, now_ros=stamp,
        frame="map", child_frame="base_link", linear=(speed, 0.0, 0.0), angular=(0.0, 0.0, 0.0))
    buffer.observe_scan(stamp=stamp, received_at=100.0, now_ros=stamp, frame="base_scan",
        angle_min=-0.3, angle_increment=0.3, range_min=0.05, range_max=10.0, ranges=ranges)


def test_independent_speed_and_forward_distance_are_computed_from_raw_samples():
    buffer = SensorObservationBuffer()
    assert buffer.evaluate(now_ros=10.0, now=100.0) is None
    inputs(buffer, speed=0.2, ranges=(3.0, 1.0, 2.0))
    sample = buffer.evaluate(now_ros=10.1, now=100.1)
    assert sample.speed == pytest.approx(0.2)
    assert sample.free_distance == 1.0
    assert sample.odom_at == sample.scan_at == 10.0


def test_cached_sample_cannot_be_refreshed_by_observer_heartbeat():
    buffer = SensorObservationBuffer()
    inputs(buffer)
    assert buffer.evaluate(now_ros=10.6, now=100.6) is None


@pytest.mark.parametrize("ranges", [(), (math.nan, 1, 1), (math.inf, 1, 1), (-1, 1, 1), (20, 1, 1)])
def test_unknown_or_invalid_forward_ranges_block_observation(ranges):
    buffer = SensorObservationBuffer()
    inputs(buffer, ranges=ranges)
    assert buffer.evaluate(now_ros=10.0, now=100.0) is None


@pytest.mark.parametrize("speed", [math.nan, math.inf])
def test_nonfinite_motion_blocks_observation(speed):
    buffer = SensorObservationBuffer()
    inputs(buffer, speed=speed)
    assert buffer.evaluate(now_ros=10.0, now=100.0) is None


@pytest.mark.parametrize("linear", [(-0.2, 0.0, 0.0), (0.0, 0.2, 0.0)])
def test_forward_scan_cannot_certify_reverse_or_lateral_motion(linear):
    buffer = SensorObservationBuffer()
    inputs(buffer)
    buffer.observe_odometry(stamp=10.1, received_at=100.1, now_ros=10.1,
        frame="map", child_frame="base_link", linear=linear, angular=(0, 0, 0))
    assert buffer.evaluate(now_ros=10.1, now=100.1) is None


def test_raw_replay_invalidates_previous_healthy_sample():
    buffer = SensorObservationBuffer()
    inputs(buffer)
    inputs(buffer)  # same source timestamp, even though values are healthy
    assert buffer.evaluate(now_ros=10.0, now=100.0) is None


def test_wrong_frame_and_future_timestamp_are_rejected():
    buffer = SensorObservationBuffer()
    inputs(buffer)
    buffer.observe_odometry(stamp=10.1, received_at=100.1, now_ros=10.0,
        frame="wrong", child_frame="base_link", linear=(0, 0, 0), angular=(0, 0, 0))
    assert buffer.evaluate(now_ros=10.1, now=100.1) is None


def test_unsynchronized_samples_are_rejected():
    buffer = SensorObservationBuffer()
    inputs(buffer)
    buffer.observe_odometry(stamp=10.3, received_at=100.3, now_ros=10.3,
        frame="map", child_frame="base_link", linear=(0, 0, 0), angular=(0, 0, 0))
    assert buffer.evaluate(now_ros=10.3, now=100.3) is None


def test_epoch_reset_requires_new_source_samples():
    buffer = SensorObservationBuffer()
    inputs(buffer)
    buffer.reset(now_ros=10.2)
    assert buffer.evaluate(now_ros=10.2, now=100.2) is None
    inputs(buffer, stamp=10.1)
    assert buffer.evaluate(now_ros=10.2, now=100.2) is None


def test_two_source_fusion_uses_independent_distance_and_conservative_speed():
    adapter = RecoveryTelemetry(100, 0.2, 5, True, False, True, True)
    independent = IndependentSample(100, 0.21, 0.4, 10, 10)
    fused = fuse_observations(adapter, independent, now=100.1, max_age=0.5)
    assert fused.speed == 0.21
    assert fused.free_distance == 0.4
    assert fuse_observations(adapter, None, now=100.1, max_age=0.5) is None
    assert fuse_observations(adapter, independent, now=100.6, max_age=0.5) is None


def test_contradictory_speed_blocks_recovery_even_when_adapter_claims_stopped():
    adapter = RecoveryTelemetry(100, 0, 5, True, False, True, True)
    independent = IndependentSample(100, 0.4, 2, 10, 10)
    assert fuse_observations(adapter, independent, now=100.1, max_age=0.5) is None


def test_negative_adapter_speed_is_not_normalized_into_healthy_evidence():
    adapter = RecoveryTelemetry(100, -0.2, 5, True, False, True, True)
    independent = IndependentSample(100, 0.2, 2, 10, 10)
    assert fuse_observations(adapter, independent, now=100.1, max_age=0.5) is None


def test_independent_report_has_separate_authentication_domain():
    fields = dict(timestamp=10.0, observer_id="recovery-observer", observer_session="a" * 32, profile_id="amr-default",
        command_epoch=1, transmission_id=2, observation_sequence=3,
        odom_timestamp=10.0, scan_timestamp=10.0, actual_speed=0.0,
        free_distance=2.0, valid=True)
    signature = sign_independent_observation(b"observer-secret", **fields)
    assert verify_independent_observation(b"observer-secret", signature, **fields)
    assert not verify_independent_observation(b"adapter-secret", signature, **fields)
    fields["free_distance"] = 9.0
    assert not verify_independent_observation(b"observer-secret", signature, **fields)


def test_observer_restart_uses_new_session_and_endpoint_without_replaying_retired_session():
    from guardian_core.independent_observation import ObserverSessionTracker
    tracker = ObserverSessionTracker()
    assert tracker.accept("a" * 32, "endpoint-A", 90000)
    assert not tracker.accept("a" * 32, "endpoint-A", 90000)
    assert not tracker.accept("b" * 32, "endpoint-A", 1)
    assert tracker.accept("b" * 32, "endpoint-B", 1)
    assert not tracker.accept("a" * 32, "endpoint-B", 90001)
    assert not tracker.accept("b" * 32, "endpoint-C", 2)


def test_restart_session_history_is_bounded_and_fails_closed():
    from guardian_core.independent_observation import ObserverSessionTracker
    tracker = ObserverSessionTracker(max_retired=1)
    assert tracker.accept("a" * 32, "A", 1)
    assert tracker.accept("b" * 32, "B", 1)
    assert not tracker.accept("c" * 32, "C", 1)
    assert not tracker.accept("b" * 32, "B", 2)
