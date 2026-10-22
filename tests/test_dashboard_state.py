from types import SimpleNamespace

from guardian_core.dashboard_state import DashboardState


def test_dashboard_state_tracks_latest_messages_and_timeline():
    state = DashboardState(timeline_limit=3)
    state.update_risk(SimpleNamespace(
        timestamp=1.0,
        state="DEGRADED",
        risk=0.42,
        psi=0.8,
        delta=True,
        gamma=False,
        active_components=["right_arm"],
        critical_components=["right_arm"],
        reason="component risk",
    ))
    state.update_mitigation(SimpleNamespace(
        timestamp=1.1,
        plan_id="plan-1",
        action="ISOLATE",
        components=["right_arm"],
        requires_safe_stop=False,
        reason="isolate arm",
    ))
    state.update_safety(SimpleNamespace(
        timestamp=1.2,
        state="CONTAINING",
        speed_limit=0.15,
        mission_allowed=True,
        reason="mission continues",
        plan_id="plan-1",
    ))

    snapshot = state.snapshot()
    assert snapshot["risk"]["state"] == "DEGRADED"
    assert snapshot["mitigation"]["plan_id"] == "plan-1"
    assert snapshot["safety"]["speed_limit"] == 0.15
    assert len(snapshot["timeline"]) == 3
    assert snapshot["timeline"][0]["category"] == "safety"


def test_dashboard_state_exposes_ack_and_rejects_late_messages():
    state = DashboardState(timeline_limit=10)
    state.update_mitigation(SimpleNamespace(
        timestamp=10.0,
        profile_id="p",
        command_epoch=2,
        transmission_id=3,
        adapter_id="a",
        plan_id="plan-new",
        action="SAFE_STOP",
        components=[],
        requires_safe_stop=True,
        reason="stop",
    ))
    state.update_safety(SimpleNamespace(
        timestamp=10.0,
        profile_id="p",
        command_epoch=2,
        transmission_id=3,
        adapter_id="a",
        state="SAFE_STOP",
        speed_limit=0.0,
        mission_allowed=False,
        reason="stop",
        plan_id="plan-new",
    ))
    state.update_ack(SimpleNamespace(
        timestamp=10.1,
        profile_id="p",
        command_epoch=2,
        transmission_id=3,
        feedback_sequence=4,
        adapter_id="a",
        plan_id="plan-new",
        action="SAFE_STOP",
        components=[],
        accepted=True,
        active=True,
        safe_stop_confirmed=True,
        reason="applied",
    ))

    state.update_mitigation(SimpleNamespace(
        timestamp=5.0,
        profile_id="p",
        command_epoch=1,
        transmission_id=1,
        adapter_id="a",
        plan_id="old-plan",
        action="NONE",
        components=[],
        requires_safe_stop=False,
        reason="late",
    ))
    state.update_safety(SimpleNamespace(
        timestamp=5.0,
        profile_id="p",
        command_epoch=1,
        transmission_id=1,
        adapter_id="a",
        state="NORMAL",
        speed_limit=0.35,
        mission_allowed=True,
        reason="late",
        plan_id="old-plan",
    ))

    snapshot = state.snapshot()
    assert snapshot["mitigation"]["plan_id"] == "plan-new"
    assert snapshot["safety"]["state"] == "SAFE_STOP"
    assert snapshot["ack"]["feedback_sequence"] == 4
    assert any(item["category"] == "ack" for item in snapshot["timeline"])
    assert any(item["category"] == "mitigation" and item.get("stale") for item in snapshot["timeline"])


def test_dashboard_state_tracks_bounded_simulation_telemetry_without_timeline_flooding():
    state = DashboardState(timeline_limit=1)
    state.update_simulation(SimpleNamespace(data='{"phase":"DOCK_TO_PALLET","x":1.25,"actual_speed":0.0,"pallet_loaded":true,"attack_mode":"speed_abuse","mitigation_components":["left_wheels"],"extra":"discard"}'))
    snapshot = state.snapshot()
    assert snapshot["simulation"]["phase"] == "DOCK_TO_PALLET"
    assert snapshot["simulation"]["x"] == 1.25
    assert snapshot["simulation"]["actual_speed"] == 0.0
    assert snapshot["simulation"]["pallet_loaded"] is True
    assert snapshot["simulation"]["mitigation_components"] == ["left_wheels"]
    assert "extra" not in snapshot["simulation"]
    assert snapshot["timeline"] == []
    state.update_simulation(SimpleNamespace(data='{"phase":"IDLE","attack_mode":null,"mitigation_action":"NONE"}'))
    assert state.snapshot()["simulation"]["attack_mode"] is None
