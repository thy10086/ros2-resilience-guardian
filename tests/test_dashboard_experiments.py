"""Offline protection replay exercises the same decisions as the ROS node."""
import copy
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from guardian_core.dashboard_experiments import sample_catalog, run_replay, ReplayError
from guardian_core.dashboard import DashboardHTTPServer
from guardian_core.dashboard_auth import DashboardAuth
from guardian_core.dashboard_state import DashboardState

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "ros2_ws" / "src" / "guardian_core" / "guardian_core" / "frontend"


def request_json(url: str, *, data: bytes | None = None, headers: dict[str, str] | None = None):
    request = urllib.request.Request(url, data=data, headers=headers or {}, method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status, dict(response.headers), json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), json.loads(error.read())


@pytest.fixture()
def server():
    http = DashboardHTTPServer(("127.0.0.1", 0), DashboardState(), FRONTEND,
                               auth=DashboardAuth(username="admin", password="admin", ttl_sec=60))
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{http.server_port}"
    finally:
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)


def fixture(name):
    return next(item["sample"] for item in sample_catalog() if item["id"] == name)


@pytest.mark.parametrize("name,codes,state,action", [
    ("normal", [], "NORMAL", "NONE"),
    ("untrusted", ["UNKNOWN_SOURCE"], "NORMAL", "NONE"),
    ("replay", ["ACCEPTED", "REPLAY"], "RESUMABLE", "NONE"),
    ("critical", ["ACCEPTED"], "CONTAINING", "ISOLATE_COMPONENT"),
    ("stop", ["ACCEPTED"], "SAFE_STOP", "SAFE_STOP"),
])
def test_examples_produce_real_protection_decisions(name, codes, state, action):
    report = run_replay(fixture(name))
    assert report["mode"] == "offline_replay"
    assert report["actuation"] == "none"
    assert [row["verification"]["code"] for row in report["steps"] if row["event"]] == codes
    assert report["final"]["safety"]["state"] == state
    assert report["final"]["plan"]["action"] == action
    assert report["final"]["safety"]["speed_limit"] == (0 if state == "SAFE_STOP" else .15 if state == "CONTAINING" else .35)
    json.dumps(report, allow_nan=False)


def test_replays_have_fresh_verifier_and_registry():
    sample = fixture("critical")
    before = copy.deepcopy(sample)
    first = run_replay(sample)
    second = run_replay(sample)
    assert sample == before
    assert second["summary"] == first["summary"]
    assert second["steps"][0]["verification"]["code"] == "ACCEPTED"
    assert run_replay(fixture("normal"))["final"]["risk"]["active_components"] == []


@pytest.mark.parametrize("field,value", [
    ("at", float("nan")), ("timestamp", float("inf")), ("sequence", True),
    ("sequence", -1), ("confidence", 2), ("source", ""),
    ("component", "unconfigured_actuator"), ("at", 3601),
])
def test_malformed_event_rejected_before_evaluation(field, value):
    sample = fixture("critical")
    sample["events"][0][field] = value
    with pytest.raises(ReplayError):
        run_replay(sample)


def test_bounded_schema_and_monotonic_observations():
    for change in [{"profile": "custom"}, {"schema": "bad"}, {"api_key": "not-a-real-key"},
                   {"events": [fixture("critical")["events"][0]] * 65}]:
        with pytest.raises(ReplayError):
            run_replay({**fixture("critical"), **change})
    sample = fixture("replay")
    sample["events"][1]["at"] = 0
    with pytest.raises(ReplayError):
        run_replay(sample)


def test_expiry_future_and_stale_are_visible_without_automatic_enforcement():
    sample = fixture("critical")
    event = sample["events"][0]
    sample["events"] += [dict(event, event_id="future", sequence=2, at=11, timestamp=15),
                         dict(event, event_id="old", sequence=3, at=20, timestamp=10)]
    report = run_replay(sample)
    assert [row["verification"]["code"] for row in report["steps"]] == ["ACCEPTED", "FUTURE", "STALE"]
    assert report["steps"][1]["safety"]["state"] == "CONTAINING"
    assert report["steps"][2]["expired_event_ids"] == [event["event_id"]]
    assert report["final"]["safety"]["state"] == "NORMAL"


def test_experiment_http_contract_is_authenticated_and_maps_protection_steps(server):
    status, _, payload = request_json(f"{server}/api/experiments/samples")
    assert status == 401
    assert payload["error"]["code"] == "auth_required"

    status, headers, _ = request_json(
        f"{server}/api/login", data=b'{"username":"admin","password":"admin"}',
        headers={"Content-Type": "application/json"})
    assert status == 200
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    status, _, payload = request_json(f"{server}/api/experiments/samples", headers={"Cookie": cookie})
    assert status == 200
    assert payload["schema"] == "guardian-replay/v1"
    assert {item["id"] for item in payload["samples"]} == {"normal", "untrusted", "replay", "critical", "stop", "warehouse_amr"}
    samples_payload = payload

    critical = next(item["sample"] for item in payload["samples"] if item["id"] == "critical")
    status, _, payload = request_json(
        f"{server}/api/experiments/replay", data=json.dumps(critical).encode(),
        headers={"Cookie": cookie, "Content-Type": "application/json"})
    assert status == 200
    assert payload["status"] == "OK"
    report = payload["report"]
    assert report["actuation"] == "none"
    assert report["final"]["safety"]["state"] == "CONTAINING"
    assert report["final"]["plan"]["action"] == "ISOLATE_COMPONENT"
    assert report["steps"][0]["verification"]["code"] == "ACCEPTED"

    warehouse = next(item for item in samples_payload["samples"] if item["id"] == "warehouse_amr")
    assert warehouse["robot"] == "amr-07"
    assert warehouse["topics"] == ["/cmd_vel", "/gripper/command"]
    assert warehouse["jev_boundary"] == "advisory_only"
    assert warehouse["jev_context"]["summary"]
    status, _, payload = request_json(
        f"{server}/api/experiments/replay", data=json.dumps(warehouse["sample"]).encode(),
        headers={"Cookie": cookie, "Content-Type": "application/json"})
    assert status == 200
    assert payload["report"]["summary"] == {"total": 4, "accepted": 3, "rejected": 1}
    assert payload["report"]["steps"][1]["verification"]["code"] == "REPLAY"
    assert payload["report"]["final"]["safety"]["state"] == "CONTAINING"

    status, _, payload = request_json(
        f"{server}/api/experiments/replay", data=b'{"schema":"wrong"}',
        headers={"Cookie": cookie, "Content-Type": "application/json"})
    assert status == 400
    assert payload["error"]["code"] == "invalid_sample"


def test_frontend_exposes_industrial_case_and_jev_boundary():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")
    assert "仓储 AMR 托盘运输" in html
    assert "protection-industrial" in html
    assert "protection-jev-summary" in html
    assert "jev_context" in script


def test_frontend_uses_security_testing_copy_without_proposal_language():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")

    assert "安全测试分析" in html
    assert "安全策略说明" in html
    assert "运行测试套件" in html
    assert "研究与创新" not in html
    assert "工程创新与可申请方向" not in html
    assert "专利边界" not in html
    assert "研究套件" not in html
    assert "创新组合" not in html
    assert "研究套件" not in script
