from experiments.run_warehouse_amr_case import guardian_sample, run_case
from guardian_core.dashboard_experiments import run_replay


def test_warehouse_amr_case_maps_real_topics_and_contains_motion():
    result = run_case()
    report = result["guardian_replay"]
    assert result["scenario"]["topics"] == ["/cmd_vel", "/gripper/command"]
    assert report["summary"] == {"total": 4, "accepted": 3, "rejected": 1}
    assert report["steps"][1]["verification"]["code"] == "REPLAY"
    assert report["final"]["safety"]["state"] == "CONTAINING"
    assert report["final"]["plan"]["action"] == "ISOLATE_COMPONENT"
    assert report["final"]["safety"]["speed_limit"] == 0.15
    assert "Jev receives only" in result["jev_boundary"]


def test_warehouse_fixture_is_accepted_by_upload_contract():
    sample = guardian_sample()
    report = run_replay(sample)
    assert report["schema"] == "guardian-replay/v1"
    assert report["profile"] == "navigation"
