import json

from guardian_core.amr_simulator import AmrSimulationModel


def test_model_runs_pallet_mission_and_clamps_motion_after_containment():
    model = AmrSimulationModel()
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
