import json

import pytest

from guardian_core.amr_simulator import AmrSimulationModel


def _running_model(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("guardian_core.amr_simulator.time.monotonic", lambda: clock[0])
    model = AmrSimulationModel()
    command = {"command_epoch": 1, "transmission_id": 1, "action": "NONE", "components": []}
    status = {"command_epoch": 1, "transmission_id": 1,
        "state": "NORMAL", "speed_limit": 0.35, "mission_allowed": True}
    model.update_mitigation(command)
    model.update_safety(status)
    model.handle_command({"action": "start"})
    model.update(0.1)
    assert model.actual_speed == 0.2
    return model, clock, command, status


@pytest.mark.parametrize("replay", [False, True])
def test_execution_stops_when_guardian_publication_stalls(monkeypatch, replay):
    model, clock, command, status = _running_model(monkeypatch)
    clock[0] = 100.4
    if replay:
        model.update_mitigation(command)
        model.update_safety(status)
    clock[0] = 100.5
    model.update(0.0)
    assert model.actual_speed == 0.0
    assert not model.mission_allowed
    assert model.mitigation_ack(10.0) is None


@pytest.mark.parametrize("stream", ["command", "status"])
def test_each_execution_authorization_stream_has_its_own_deadline(monkeypatch, stream):
    model, clock, command, status = _running_model(monkeypatch)
    clock[0] = 100.4
    if stream == "command":
        model.update_mitigation({**command, "transmission_id": 2})
    else:
        model.update_safety({**status, "transmission_id": 2})
    clock[0] = 100.5
    model.update(0.1)
    assert model.actual_speed == 0.0
    assert not model.command_accepted
    assert not model.mission_allowed


def test_new_transmissions_keep_execution_alive_and_old_epoch_cannot_renew(monkeypatch):
    model, clock, command, status = _running_model(monkeypatch)
    for transmission in range(2, 8):
        clock[0] += 0.2
        model.update_mitigation({**command, "transmission_id": transmission})
        model.update_safety({**status, "transmission_id": transmission})
        model.update(0.1)
        assert model.actual_speed == 0.2
    model.update_mitigation({**command, "command_epoch": 2, "transmission_id": 8})
    model.update_safety({**status, "command_epoch": 2, "transmission_id": 8})
    clock[0] += 0.4
    model.update_mitigation({**command, "transmission_id": 100})
    model.update_safety({**status, "transmission_id": 100})
    clock[0] += 0.1
    model.update(0.1)
    assert model.actual_speed == 0.0


def test_execution_clock_rollback_revokes_cached_authorization(monkeypatch):
    model, clock, _, _ = _running_model(monkeypatch)
    clock[0] = 99.9
    model.update(0.1)
    assert model.actual_speed == 0.0
    assert not model.command_accepted


def test_model_runs_pallet_mission_and_clamps_motion_after_containment():
    model = AmrSimulationModel()
    model.update_mitigation({
        "command_epoch": 1,
        "transmission_id": 1,
        "action": "NONE",
        "components": [],
    })
    model.update_safety({
        "command_epoch": 1,
        "transmission_id": 1,
        "state": "NORMAL",
        "speed_limit": 0.35,
        "mission_allowed": True,
    })
    model.handle_command({"action": "start"})
    model.update(1.0)
    assert model.snapshot()["mission_running"] is True
    assert model.snapshot()["pallet_loaded"] is True
    assert model.snapshot()["x"] > 0

    model.handle_command({"action": "attack", "type": "speed_abuse"})
    model.update_safety({"state": "CONTAINING", "speed_limit": 0.15, "mission_allowed": False})
    model.update(1.0)
    snapshot = model.snapshot()
    assert snapshot["requested_speed"] == 0.62
    assert snapshot["actual_speed"] == 0.0
    assert snapshot["safety_state"] == "CONTAINING"
    events = model.poll_attack_events(123.0)
    assert [event["attack_type"] for event in events] == ["UNSAFE_COMMAND"]
    assert events[0]["source"] == "amr_simulator"


def test_model_replay_and_gripper_fault_are_deterministic():
    model = AmrSimulationModel()
    model.handle_command({"action": "start"})
    model.handle_command({"action": "attack", "type": "replay"})
    first = model.poll_attack_events(1.0)
    second = model.poll_attack_events(1.1)
    assert first[0]["sequence"] == second[0]["sequence"] == 7001
    assert first[0]["event_id"] != second[0]["event_id"]

    model.handle_command({"action": "attack", "type": "gripper_fault"})
    fault = model.poll_attack_events(2.0)
    assert fault[0]["component"] == "right_arm"
    assert fault[0]["attack_type"] == "SEMANTIC_MISBEHAVIOR"
    assert json.loads(model.gripper_payload())["grip_force"] == 0.0


def test_new_attacks_keep_increasing_source_sequence_across_scene_resets():
    from guardian_core.models import AttackEvent
    from guardian_core.verifier import EventVerifier
    model = AmrSimulationModel()
    verifier = EventVerifier({"amr_simulator"})
    events = []
    for index, attack in enumerate(("speed_abuse", "speed_abuse", "gripper_fault", "speed_abuse")):
        model.handle_command({"action": "reset"})
        model.handle_command({"action": "attack", "type": attack})
        event = model.poll_attack_events(10.0 + index)[0]
        result = verifier.verify(AttackEvent(**event), 10.0 + index)
        assert result.accepted, result.reason
        events.append(event)
    assert all(new["sequence"] > old["sequence"] for old, new in zip(events, events[1:]))
    assert len({event["event_id"] for event in events}) == 4


def test_only_deliberate_replay_is_rejected_and_later_new_attack_is_accepted():
    from guardian_core.models import AttackEvent, VerificationCode
    from guardian_core.verifier import EventVerifier
    model = AmrSimulationModel()
    verifier = EventVerifier({"amr_simulator"})
    model.handle_command({"action": "attack", "type": "gripper_fault"})
    initial = model.poll_attack_events(1.0)[0]
    assert verifier.verify(AttackEvent(**initial), 1.0).accepted
    model.handle_command({"action": "reset"})
    model.handle_command({"action": "attack", "type": "replay"})
    first = model.poll_attack_events(2.0)[0]
    replayed = model.poll_attack_events(2.1)[0]
    assert verifier.verify(AttackEvent(**first), 2.0).accepted
    assert verifier.verify(AttackEvent(**replayed), 2.1).code == VerificationCode.REPLAY
    assert first["sequence"] == replayed["sequence"]
    model.handle_command({"action": "attack", "type": "speed_abuse"})
    subsequent = model.poll_attack_events(3.0)[0]
    assert verifier.verify(AttackEvent(**subsequent), 3.0).accepted


def test_model_reset_clears_faults_and_returns_to_idle():
    model = AmrSimulationModel()
    model.handle_command({"action": "start"})
    model.handle_command({"action": "attack", "type": "gripper_fault"})
    model.handle_command({"action": "reset"})
    snapshot = model.snapshot()
    assert snapshot["mission_running"] is False
    assert snapshot["attack_mode"] is None
    assert snapshot["x"] == 0.0
    assert json.loads(model.gripper_payload())["grip_force"] == 45.0
    assert snapshot["safety_state"] == "SAFE_STOP"
    assert snapshot["mission_allowed"] is False
    assert snapshot["actual_speed"] == 0.0


def test_model_starts_and_resets_fail_closed_until_current_command_and_status():
    model = AmrSimulationModel()
    model.handle_command({"action": "start"})
    model.update(0.1)

    assert model.snapshot()["actual_speed"] == 0.0
    assert model.snapshot()["safety_state"] == "SAFE_STOP"
    assert model.snapshot()["mission_allowed"] is False
    assert model.command_accepted is False

    model.update_mitigation({
        "command_epoch": 7,
        "transmission_id": 9,
        "profile_id": "amr-default",
        "adapter_id": "default-actuator",
        "plan_id": "none",
        "action": "NONE",
        "components": [],
    })
    model.update_safety({
        "command_epoch": 7,
        "transmission_id": 9,
        "profile_id": "amr-default",
        "adapter_id": "default-actuator",
        "state": "NORMAL",
        "speed_limit": 0.35,
        "mission_allowed": True,
    })
    model.update(0.1)
    assert model.snapshot()["actual_speed"] == 0.2

    model.handle_command({"action": "reset"})
    model.handle_command({"action": "start"})
    model.update(0.1)
    assert model.snapshot()["actual_speed"] == 0.0
    assert model.snapshot()["safety_state"] == "SAFE_STOP"


def test_model_bootstraps_from_a_late_first_command_without_ordering_fault():
    model = AmrSimulationModel()

    model.update_mitigation({
        "command_epoch": 2,
        "transmission_id": 5,
        "profile_id": "amr-default",
        "adapter_id": "default-actuator",
        "plan_id": "none",
        "action": "NONE",
        "components": [],
    })

    assert model.command_epoch == 2
    assert model.command_transmission_id == 5
    assert model.command_accepted is True
    assert model.snapshot()["safety_state"] == "SAFE_STOP"
    assert model.snapshot()["mission_allowed"] is False


def test_scene_reset_preserves_feedback_sequence_and_requires_fresh_authorization():
    model = AmrSimulationModel()
    command = {
        "command_epoch": 7, "transmission_id": 9,
        "action": "NONE", "components": [],
    }
    status = {
        "command_epoch": 7, "transmission_id": 9,
        "state": "NORMAL", "speed_limit": 0.35, "mission_allowed": True,
    }
    model.update_mitigation(command)
    model.update_safety(status)
    for _ in range(30):
        model.mitigation_ack(1.0)

    model.handle_command({"action": "reset"})
    model.handle_command({"action": "start"})
    model.update_mitigation(command)
    model.update_safety(status)
    model.update(0.1)
    assert model.actual_speed == 0.0
    assert model.mitigation_ack(2.0) is None

    model.update_mitigation({**command, "transmission_id": 10})
    model.update(0.1)
    assert model.actual_speed == 0.0
    model.update_safety({**status, "transmission_id": 10})
    model.update(0.1)
    assert model.actual_speed == 0.2
    ack = model.mitigation_ack(2.1)
    assert ack["feedback_sequence"] == 31
    assert ack["transmission_id"] == 10


def test_scene_reset_cannot_clear_an_ordering_fault():
    model = AmrSimulationModel()
    command = {"action": "NONE", "components": []}
    model.update_mitigation({**command, "command_epoch": 1, "transmission_id": 1})
    model.update_mitigation({**command, "command_epoch": 3, "transmission_id": 3})
    model.handle_command({"action": "reset"})
    model.handle_command({"action": "start"})
    model.update_mitigation({**command, "command_epoch": 4, "transmission_id": 4})
    model.update_safety({
        "command_epoch": 4, "transmission_id": 4,
        "state": "NORMAL", "speed_limit": 0.35, "mission_allowed": True,
    })
    model.update(0.1)
    assert model.actual_speed == 0.0
    assert model.mitigation_ack(2.0) is None


def test_model_applies_isolation_and_degraded_run_actions():
    model = AmrSimulationModel()
    model.handle_command({"action": "start"})

    model.update_mitigation({
        "command_epoch": 1, "transmission_id": 1,
        "action": "DEGRADED_RUN", "components": [],
    })
    model.update_safety({"state": "DEGRADED", "speed_limit": 0.2, "mission_allowed": True})
    model.update(1.0)
    assert 0.0 < model.snapshot()["actual_speed"] <= 0.2

    model.update_mitigation({
        "command_epoch": 2, "transmission_id": 2,
        "action": "ISOLATE_COMPONENT", "components": ["left_wheels"],
    })
    model.update_safety({"state": "CONTAINING", "speed_limit": 0.15, "mission_allowed": True})
    model.update(1.0)
    assert model.snapshot()["actual_speed"] == 0.0

    model.update_mitigation({
        "command_epoch": 3, "transmission_id": 3,
        "action": "ISOLATE_COMPONENT", "components": ["right_arm"],
    })
    model.update_safety({
        "command_epoch": 3, "transmission_id": 3,
        "state": "CONTAINING", "speed_limit": 0.15, "mission_allowed": True,
    })
    model.update(1.0)
    assert 0.0 < model.snapshot()["actual_speed"] <= 0.15


def test_model_reports_applied_mitigation_command():
    model = AmrSimulationModel()
    model.update_mitigation({
        "command_epoch": 1,
        "transmission_id": 11,
        "profile_id": "amr-default",
        "adapter_id": "default-actuator",
        "plan_id": "contain-7",
        "action": "SAFE_STOP",
        "components": [],
    })
    model.update_safety({"state": "SAFE_STOP", "speed_limit": 0.0, "mission_allowed": False})
    model.update(0.1)

    ack = model.mitigation_ack(12.0)

    assert ack == {
        "timestamp": 12.0,
        "profile_id": "amr-default",
        "command_epoch": 1,
        "transmission_id": 11,
        "adapter_id": "default-actuator",
        "plan_id": "contain-7",
        "action": "SAFE_STOP",
        "components": [],
        "accepted": True,
        "active": True,
        "safe_stop_confirmed": True,
        "feedback_sequence": 1,
        "reason": "mitigation command applied",
    }


def test_model_does_not_allow_old_or_jumped_mitigation_epochs_to_override_state():
    model = AmrSimulationModel()
    model.update_mitigation({
        "command_epoch": 1, "transmission_id": 2,
        "action": "ISOLATE_COMPONENT", "components": ["left_wheels"],
    })
    model.update_mitigation({
        "command_epoch": 3, "transmission_id": 3,
        "action": "ISOLATE_COMPONENT", "components": ["right_arm"],
    })
    assert model.mitigation_action == "SAFE_STOP"
    assert model.isolated_components == set()

    model.update_mitigation({
        "command_epoch": 4, "transmission_id": 4,
        "action": "DEGRADED_RUN", "components": [],
    })
    assert model.mitigation_action == "SAFE_STOP"
    assert model.command_accepted is False


def test_model_ignores_old_safety_status_and_requires_matching_command_identity():
    model = AmrSimulationModel()
    model.update_mitigation({
        "command_epoch": 1, "transmission_id": 1,
        "action": "DEGRADED_RUN", "components": [],
    })
    model.update_safety({
        "command_epoch": 1, "transmission_id": 1,
        "profile_id": "amr-default",
        "state": "DEGRADED", "speed_limit": 0.2, "mission_allowed": True,
    })
    model.update_safety({
        "command_epoch": 0, "transmission_id": 0,
        "state": "NORMAL", "speed_limit": 1.0, "mission_allowed": True,
    })
    model.update(1.0)
    assert model.safety_state == "DEGRADED"
    assert model.snapshot()["actual_speed"] <= 0.2


def test_model_requires_safety_status_from_the_current_profile():
    model = AmrSimulationModel()
    model.update_mitigation({
        "command_epoch": 1, "transmission_id": 1,
        "profile_id": "amr-default",
        "action": "DEGRADED_RUN", "components": [],
    })
    model.update_safety({
        "command_epoch": 1, "transmission_id": 1,
        "profile_id": "other-profile",
        "state": "DEGRADED", "speed_limit": 0.2, "mission_allowed": True,
    })
    model.handle_command({"action": "start"})
    model.update(1.0)
    assert model.snapshot()["actual_speed"] == 0.0
