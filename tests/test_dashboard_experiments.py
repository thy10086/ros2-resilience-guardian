"""Offline protection replay exercises the same decisions as the ROS node."""
import copy
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

import guardian_core.dashboard_experiments as dashboard_experiments
from guardian_core.dashboard_experiments import ReplayError, run_replay, sample_catalog
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


def test_replay_report_declares_offline_evidence_boundary():
    report = run_replay(fixture("warehouse_amr"))
    assurance = report["assurance"]
    assert assurance["mode"] == "OFFLINE_REPLAY"
    assert assurance["runtime_verified"] is False
    assert assurance["actuation"] == "none"
    assert "ROS 2/Gazebo" in " ".join(assurance["limitations"])


def test_jev_replay_scores_each_verified_event_and_keeps_replay_local():
    calls = []

    def fake_jev(state):
        context = json.loads(state)
        calls.append(context)
        return {
            "status": "OK",
            "connected": True,
            "assessment": {
                "status": "OK",
                "label": "unsafe_command" if context["component"] == "left_wheels" else "semantic_misbehavior",
                "score": 0.92 if context["component"] == "left_wheels" else 0.78,
                "confidence": 0.88,
                "mission_impact": "critical" if context["component"] == "left_wheels" else "medium",
                "needs_human_review": True,
                "model": "jev-test",
                "reason": "semantic evidence supports elevated risk",
            },
        }

    report = dashboard_experiments.run_replay_with_jev(fixture("warehouse_amr"), fake_jev)
    evaluation = report["jev_evaluation"]

    assert len(calls) == 3
    assert [context["event_id"] for context in calls] == [
        "amr-dock-left-wheel-7001",
        "amr-dock-left-wheel-7002",
        "amr-pallet-gripper-7003",
    ]
    assert [item["jev"]["status"] for item in evaluation["events"]] == [
        "OK", "SKIPPED_UNVERIFIED", "OK", "OK"
    ]
    assert evaluation["events"][1]["jev"]["reason"] == "REPLAY was blocked before Jev"
    assert evaluation["events"][0]["scoring"]["composite_risk"] >= evaluation["events"][0]["scoring"]["guardian_risk"]
    assert evaluation["aggregate"]["risk_score"] >= 75
    assert evaluation["aggregate"]["level"] == "CRITICAL"
    assert "Guardian hard floor" in " ".join(evaluation["aggregate"]["basis"])


def test_aggregate_risk_never_drops_below_any_event_hard_floor():
    report = dashboard_experiments.run_replay_with_jev(fixture("warehouse_amr"), lambda _: {
        "status": "OK",
        "assessment": {
            "score": 0.01,
            "confidence": 0.99,
            "label": "benign",
            "mission_impact": "low",
        },
    })
    evaluation = report["jev_evaluation"]
    hard_floor = max(item["scoring"]["hard_floor"] for item in evaluation["events"])
    assert evaluation["aggregate"]["risk_score"] >= round(hard_floor * 100, 1)


def test_low_confidence_jev_cannot_reduce_guardian_risk():
    def low_confidence_jev(_state):
        return {
            "status": "OK",
            "connected": True,
            "assessment": {
                "status": "OK",
                "label": "benign",
                "score": 0.05,
                "confidence": 0.40,
                "mission_impact": "low",
                "needs_human_review": True,
                "model": "jev-low-confidence",
                "reason": "semantic response is uncertain",
            },
        }

    report = dashboard_experiments.run_replay_with_jev(fixture("critical"), low_confidence_jev)
    scoring = report["jev_evaluation"]["events"][0]["scoring"]
    assert scoring["fusion_mode"] == "CONSERVATIVE_LOW_CONFIDENCE"
    assert scoring["composite_risk"] >= scoring["guardian_risk"]
    assert scoring["confidence_gate"] == 0.70


def test_empty_jev_assessment_is_invalid_and_requires_review():
    report = dashboard_experiments.run_replay_with_jev(
        fixture("critical"),
        lambda _: {"status": "OK", "assessment": {}},
    )
    event = report["jev_evaluation"]["events"][0]
    assert event["jev"]["status"] == "INVALID"
    assert event["jev"]["risk"] is None
    assert report["jev_evaluation"]["status"] == "PARTIAL"
    assert report["safety_summary"]["evidence"]["invalid_jev_events"] == 1


def test_empty_replay_is_insufficient_not_one_hundred_percent_safe():
    report = dashboard_experiments.run_replay_with_jev(fixture("normal"), lambda _: pytest.fail("empty"))
    assert report["jev_evaluation"]["status"] == "INSUFFICIENT_EVIDENCE"
    assert report["jev_evaluation"]["aggregate"]["safety_score"] is None
    assert report["safety_summary"]["runtime_verified"] is False


def test_guardian_rejected_event_is_not_summarized_as_safe():
    report = dashboard_experiments.run_replay_with_jev(
        fixture("untrusted"),
        lambda _: pytest.fail("unverified event must not be sent to Jev"),
    )
    assert report["jev_evaluation"]["status"] == "LOCAL_ONLY"
    assert "不能据此判定为安全" in report["safety_summary"]["decision"]
    assert report["safety_summary"]["evidence"]["locally_rejected"] == 1


@pytest.mark.parametrize("score", [None, True, "0.8", float("nan"), 1.5])
def test_invalid_jev_scores_are_unavailable_not_zero_risk(score):
    report = dashboard_experiments.run_replay_with_jev(fixture("critical"), lambda _: {
        "status": "OK", "assessment": {"score": score, "confidence": .9, "label": "benign"},
    })
    event = report["jev_evaluation"]["events"][0]
    assert event["jev"]["status"] == "INVALID"
    assert event["jev"]["risk"] is None
    assert event["scoring"]["fusion_mode"] == "GUARDIAN_ONLY"
    assert report["jev_evaluation"]["status"] == "PARTIAL"


def test_chinese_summary_links_evidence_to_policy_without_claiming_actuation():
    report = dashboard_experiments.run_replay_with_jev(fixture("warehouse_amr"), lambda _: {
        "status": "OK", "assessment": {
            "score": .93, "confidence": .69, "label": "unsafe_command",
            "mission_impact": "critical", "needs_human_review": True,
        },
    })
    summary = report["safety_summary"]
    assert summary["decision"] == "保持任务锁定，整改后复核"
    assert summary["runtime_verified"] is False
    assert summary["evidence"]["total_events"] == 4
    assert summary["evidence"]["jev_successes"] == 3
    assert summary["evidence"]["locally_rejected"] == 1
    assert summary["evidence"]["low_confidence_events"] == 3
    assert report["jev_evaluation"]["aggregate"]["risk_score"] == 85.0
    event = report["jev_evaluation"]["events"][1]
    assert "序列号" in " ".join(event["scoring"]["basis_zh"])
    assert "85.0" in " ".join(event["scoring"]["basis_zh"])
    assert "未执行" in summary["limitations"]


def test_jev_replay_http_endpoint_uses_saved_key_and_returns_auditable_scores(tmp_path):
    calls = []

    class FakeJevService:
        def test(self, api_key, state):
            context = json.loads(state)
            calls.append((api_key, context))
            return SimpleNamespace(
                http_status=200,
                payload={
                    "status": "OK",
                    "connected": True,
                    "assessment": {
                        "status": "OK",
                        "label": "unsafe_command",
                        "score": 0.9,
                        "confidence": 0.9,
                        "mission_impact": "critical",
                        "needs_human_review": True,
                        "model": "jev-http-test",
                        "reason": "critical component evidence",
                    },
                },
            )

    auth = DashboardAuth(username="admin", password="admin", ttl_sec=60)
    http = DashboardHTTPServer(
        ("127.0.0.1", 0),
        DashboardState(),
        FRONTEND,
        auth=auth,
        jev_service=FakeJevService(),
    )
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{http.server_port}"
        status, headers, _ = request_json(
            f"{base}/api/login",
            data=b'{"username":"admin","password":"admin"}',
            headers={"Content-Type": "application/json"},
        )
        assert status == 200
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, _, payload = request_json(
            f"{base}/api/jev/key",
            data=b'{"api_key":"saved-jev-key"}',
            headers={"Cookie": cookie, "Content-Type": "application/json"},
        )
        assert status == 200
        assert payload == {"saved": True}

        status, _, payload = request_json(
            f"{base}/api/experiments/jev-evaluate",
            data=json.dumps({"sample": fixture("warehouse_amr")}).encode(),
            headers={"Cookie": cookie, "Content-Type": "application/json"},
        )
        assert status == 200
        assert payload["status"] == "OK"
        assert payload["report"]["jev_evaluation"]["aggregate"]["level"] == "CRITICAL"
        assert len(calls) == 3
        assert all(api_key == "saved-jev-key" for api_key, _ in calls)
    finally:
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)


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
    assert "protection-jev-run" in html
    assert "protection-jev-result" in html
    assert "/api/experiments/jev-evaluate" in script
    assert "jev_evaluation" in script
    assert "composite_risk" in script
    assert "safety_score" in script


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
