"""The dashboard checks real traces with the shared Oracle, behind login."""
import json
from pathlib import Path
import threading
import urllib.error
import urllib.request

import pytest

from guardian_core.dashboard import DashboardHTTPServer
from guardian_core.dashboard_auth import DashboardAuth
from guardian_core.dashboard_state import DashboardState

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "ros2_ws/src/guardian_core/guardian_core/frontend"


@pytest.fixture
def server():
    http = DashboardHTTPServer(("127.0.0.1", 0), DashboardState(), FRONTEND,
        auth=DashboardAuth(username="admin", password="admin", ttl_sec=60))
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield http, f"http://127.0.0.1:{http.server_port}"
    finally:
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)


def request(url, payload, cookie=""):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Cookie": cookie})
    try:
        # Local HTTP assertions must reach this fixture, regardless of proxy env.
        response = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=3)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read()
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = {"raw": raw.decode()}
        return response.status, response.headers, body


def login(url):
    status, headers, _ = request(url + "/api/login", {"username": "admin", "password": "admin"})
    assert status == 200
    return headers["Set-Cookie"].split(";", 1)[0]


def sample_frames():
    from guardian_core.recovery_feedback import RecoveryFrame
    return [RecoveryFrame(now=1 + i * .05, task_phase="navigate", recovery_phase="SAFE_STOP",
        evidence_state="healthy", stopped_ack=True, unresolved=False, forced_stop=False,
        graph_fingerprint="g", policy_fingerprint="p", ledger_anchor="l",
        command_epoch=1, next_command_epoch=1, mission_allowed=False, speed_limit=0).to_dict()
        for i in range(65)]


def test_trace_inspection_requires_login_and_has_no_actuation(server):
    http, url = server
    before = http.state.snapshot()
    status, _, _ = request(url + "/api/recovery/inspect", {"frames": sample_frames()})
    assert status == 401
    cookie = login(url)
    status, _, payload = request(url + "/api/recovery/inspect", {"frames": sample_frames()}, cookie)
    assert status == 200
    report = payload["report"]
    assert report["violation_codes"] == ["recovery_stalled"]
    assert report["frame_count"] == 65
    assert report["oracle_config"] == {"liveness_sec": 3.0, "max_frame_gap_sec": .25}
    assert report["actuation"] == "none"
    assert http.state.snapshot() == before


def test_gap_qualification_and_cross_gap_expiry_use_shared_oracle(server):
    _, url = server
    cookie = login(url)
    frames = sample_frames()[:6]
    for i, frame in enumerate(frames):
        frame["now"] = 1 + i * .6
    status, _, payload = request(url + "/api/recovery/inspect", {"frames": frames}, cookie)
    assert status == 200 and payload["report"]["violation_codes"] == []
    assert payload["report"]["liveness_gaps"] == 5
    proof = dict(proof_id="one", graph_fingerprint="g", policy_fingerprint="p",
        ledger_anchor="l", command_epoch=2, issued_at=1, expires_at=1.5)
    frames = sample_frames()[:2]
    frames[0].update(recovery_phase="RECOVERY_CANDIDATE", pending_proof=proof)
    frames[1].update(now=1.6, recovery_phase="RESUMABLE", mission_allowed=True,
        consumed_proof_id="one", next_command_epoch=2)
    status, _, payload = request(url + "/api/recovery/inspect", {"frames": frames}, cookie)
    assert status == 200
    assert "expired_proof" in payload["report"]["violation_codes"]


@pytest.mark.parametrize("payload", [
    {"frames": []}, {"frames": sample_frames(), "execute": True},
    {"frames": [dict(sample_frames()[0], mission_allowed="false")]},
    {"frames": [dict(sample_frames()[0], recovery_phase="anything")]},
    {"frames": sample_frames()[:1] * 2001},
])
def test_invalid_trace_is_rejected_not_reported_as_pass(server, payload):
    _, url = server
    status, _, body = request(url + "/api/recovery/inspect", payload, login(url))
    assert status == 400 and body["error"]["code"] == "invalid_recovery_trace"


def test_packaged_comparison_matches_frozen_experiment_and_samples():
    from guardian_core.dashboard_recovery import inspect_recovery_trace
    public = json.loads((FRONTEND / "recovery-evaluation.json").read_text())
    assert len(public["source_summary_sha256"]) == 64
    assert public["replay_verification"] == {"counterexamples": 184, "corpora": 50}
    assert [public["aggregate"]["groups"][mode]["defect_detection"]["no_proof_ttl"]["detected_runs"]
        for mode in public["modes"]] == [5, 4, 7, 6, 4]
    assert public["generated_executions"] == 50000
    samples = json.loads((FRONTEND / "recovery-samples.json").read_text())["samples"]
    assert len(samples) == 6
    for item in samples:
        result = inspect_recovery_trace({"frames": item["frames"]})
        assert result["violation_codes"] == item["expected_codes"]


@pytest.mark.parametrize("expires_at", [1.0, .9])
def test_candidate_permit_requires_positive_lifetime(server, expires_at):
    _, url = server
    frames = sample_frames()[:1]
    frames[0].update(recovery_phase="RECOVERY_CANDIDATE", pending_proof=dict(
        proof_id="one", graph_fingerprint="g", policy_fingerprint="p", ledger_anchor="l",
        command_epoch=2, issued_at=1.0, expires_at=expires_at))
    status, _, body = request(url + "/api/recovery/inspect", {"frames": frames}, login(url))
    assert status == 400 and body["error"]["code"] == "invalid_recovery_trace"


@pytest.mark.parametrize("missing_field", list(sample_frames()[0]))
def test_import_requires_explicit_safety_fields(missing_field):
    from guardian_core.dashboard_recovery import inspect_recovery_trace
    row = sample_frames()[0]
    del row[missing_field]

    with pytest.raises(ValueError):
        inspect_recovery_trace({"frames": [row]})


def test_speed_omission_cannot_hide_unsafe_candidate_and_resume(server):
    from experiments.recovery_scenarios import Action, execute_scenario
    _, url = server
    cookie = login(url)
    rows = [frame.to_dict() for frame in execute_scenario([Action("healthy", .6)])]
    for row in rows:
        if row["pending_proof"] is not None or row["recovery_phase"] == "RESUMABLE":
            row["observed_speed"] = .2
    status, _, payload = request(url + "/api/recovery/inspect", {"frames": rows}, cookie)
    assert status == 200
    assert {"unsafe_candidate", "unsafe_resume"} <= set(payload["report"]["violation_codes"])

    for row in rows:
        del row["observed_speed"]
    status, _, payload = request(url + "/api/recovery/inspect", {"frames": rows}, cookie)

    assert status == 400 and payload["error"]["code"] == "invalid_recovery_trace"


def test_dashboard_detects_normal_published_epoch_tampering():
    from experiments.recovery_scenarios import Action, execute_scenario
    from guardian_core.dashboard_recovery import inspect_recovery_trace
    rows = [frame.to_dict() for frame in execute_scenario([Action("healthy", .6)])]
    assert rows[-1]["recovery_phase"] == "NORMAL"
    assert inspect_recovery_trace({"frames": rows})["verdict"] == "NO_VIOLATIONS"
    rows[-1]["next_command_epoch"] = 999

    report = inspect_recovery_trace({"frames": rows})

    assert report["verdict"] == "VIOLATIONS"
    assert report["violation_codes"] == ["unauthorized_continuation"]
