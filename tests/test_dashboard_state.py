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
