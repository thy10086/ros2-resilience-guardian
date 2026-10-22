"""Live review API ownership and lifecycle use a real local dashboard server."""
import json
from pathlib import Path
import threading
import time
import urllib.error
import urllib.request

import pytest

from guardian_core.dashboard import DashboardHTTPServer
from guardian_core.dashboard_auth import DashboardAuth
from guardian_core.dashboard_state import DashboardState

ROOT = Path(__file__).resolve().parents[1]
REQUEST = {"base_url": "http://127.0.0.1:1234/v1", "api_key": "test-secret",
    "model": "fixture", "input": {"sample": "guardian_recovery_virtual_model"}}


def request(url, payload=None, cookie="", raw=None):
    data = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
    req = urllib.request.Request(url, data=data,
        headers={"Content-Type": "application/json", "Cookie": cookie})
    try:
        response = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=3)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read()
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            body = {"raw": body.decode()}
        return response.status, response.headers, body


def login(url):
    status, headers, _ = request(url + "/api/login", {"username": "admin", "password": "admin"})
    assert status == 200
    return headers["Set-Cookie"].split(";", 1)[0]


@pytest.fixture
def server():
    http = DashboardHTTPServer(("127.0.0.1", 0), DashboardState(),
        ROOT / "ros2_ws/src/guardian_core/guardian_core/frontend",
        auth=DashboardAuth(username="admin", password="admin", ttl_sec=60))
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield http, f"http://127.0.0.1:{http.server_port}"
    finally:
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)


def install_runtime(monkeypatch, run):
    from guardian_core import dashboard_agents
    from experiments.agent_review.contracts import make_bundle
    from experiments.agent_review.provider import OpenAICompatibleProvider
    monkeypatch.setattr(dashboard_agents, "_load_runtime",
        lambda: (OpenAICompatibleProvider, run, make_bundle, "/fixed/venv/bin/python"))


def wait_job(url, cookie, job_id):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        status, _, body = request(url + "/api/agents/job?id=" + job_id, cookie=cookie)
        assert status == 200
        if body["status"] not in {"RUNNING", "CANCELLING"}:
            return body
        time.sleep(.01)
    pytest.fail("review did not finish")


@pytest.mark.parametrize("path,payload", [
    ("/api/agents/models", {"base_url": "https://example.invalid/v1", "api_key": "secret"}),
    ("/api/agents/jobs", REQUEST), ("/api/agents/cancel", {"job_id": "unknown"}),
    ("/api/agents/job?id=unknown", None),
    ("/api/agents/report?id=unknown", None),
])
def test_live_agent_routes_require_login(server, path, payload):
    _, url = server
    status, _, _ = request(url + path, payload)
    assert status == 401


def test_job_result_is_owned_by_exact_session_and_has_no_side_effects(server, monkeypatch):
    def run(payload, **options):
        assert payload == {"sample": "guardian_recovery_virtual_model"}
        assert options["python_executable"] == "/fixed/venv/bin/python"
        assert options["timeout_sec"] == 180
        return {"status": "OK", "overall_verdict": "NO_VIOLATIONS", "actuation": "none"}
    install_runtime(monkeypatch, run)
    http, url = server
    before = http.state.snapshot()
    owner, other = login(url), login(url)
    status, _, created = request(url + "/api/agents/jobs", REQUEST, owner)
    assert status == 202
    job = wait_job(url, owner, created["job_id"])
    assert job["status"] == "COMPLETED"
    assert job["report"]["overall_verdict"] == "NO_VIOLATIONS"
    assert "test-secret" not in json.dumps(job)
    assert request(url + "/api/agents/job?id=" + created["job_id"], cookie=other)[0] == 404
    assert request(url + "/api/agents/cancel", {"job_id": created["job_id"]}, other)[0] == 404
    assert http.state.snapshot() == before


def test_report_download_preserves_float_tokens_and_session_ownership(server, monkeypatch):
    expected = {"execution_status": "COMPLETE", "frames": [{"now": 1.0, "speed": 0.0}],
        "binding": "hash-of-exact-canonical-values"}
    install_runtime(monkeypatch, lambda *args, **kwargs: expected)
    _, url = server
    owner, other = login(url), login(url)
    _, _, created = request(url + "/api/agents/jobs", REQUEST, owner)
    wait_job(url, owner, created["job_id"])
    endpoint = url + "/api/agents/report?id=" + created["job_id"]
    assert request(endpoint, cookie=other)[0] == 404
    status, headers, report = request(endpoint, cookie=owner)
    assert status == 200
    assert report == expected
    assert type(report["frames"][0]["now"]) is float
    assert type(report["frames"][0]["speed"]) is float
    assert "attachment" in headers["Content-Disposition"]


def test_report_download_rejects_running_job(server, monkeypatch):
    def run(payload, **options):
        options["cancel"].wait(3)
        return {"execution_status": "CANCELLED"}
    install_runtime(monkeypatch, run)
    _, url = server
    owner = login(url)
    _, _, created = request(url + "/api/agents/jobs", REQUEST, owner)
    status, _, result = request(url + "/api/agents/report?id=" + created["job_id"], cookie=owner)
    assert status == 409
    assert result["error"]["code"] == "agent_report_not_ready"
    request(url + "/api/agents/cancel", {"job_id": created["job_id"]}, owner)


def test_global_capacity_cancel_and_logout_stop_running_job(server, monkeypatch):
    entered = threading.Event()
    def run(payload, **options):
        entered.set()
        assert options["cancel"].wait(3), "cancel never reached runner"
        return {"status": "CANCELLED"}
    install_runtime(monkeypatch, run)
    _, url = server
    owner, other = login(url), login(url)
    status, _, created = request(url + "/api/agents/jobs", REQUEST, owner)
    assert status == 202 and entered.wait(1)
    assert request(url + "/api/agents/jobs", REQUEST, other)[0] == 409
    assert request(url + "/api/agents/cancel", {"job_id": created["job_id"]}, other)[0] == 404
    assert request(url + "/api/agents/cancel", {"job_id": created["job_id"]}, owner)[0] == 200
    assert wait_job(url, owner, created["job_id"])["status"] == "CANCELLED"
    entered.clear()
    status, _, _ = request(url + "/api/agents/jobs", REQUEST, owner)
    assert status == 202 and entered.wait(1)
    assert request(url + "/api/logout", {}, owner)[0] == 200
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        status, _, created = request(url + "/api/agents/jobs", REQUEST, other)
        if status == 202:
            request(url + "/api/agents/cancel", {"job_id": created["job_id"]}, other)
            break
        time.sleep(.01)
    assert status == 202


@pytest.mark.parametrize("payload", [
    {**REQUEST, "execute": True}, {**REQUEST, "model": ""},
    {**REQUEST, "input": {"sample": "guardian_recovery_virtual_model", "frames": []}},
    {**REQUEST, "input": {"files": [{"filename": "../node.py", "source": "x"}]}},
    {**REQUEST, "api_key": ""},
])
def test_bad_requests_fail_before_starting_job(server, monkeypatch, payload):
    def run(*args, **kwargs):
        pytest.fail("invalid request reached worker")
    install_runtime(monkeypatch, run)
    _, url = server
    status, _, body = request(url + "/api/agents/jobs", payload, login(url))
    assert status == 400 and body["status"] == "INVALID_REQUEST"


@pytest.mark.parametrize("raw", [b'{"api_key":"one","api_key":"two"}', b'{"input":NaN}', b'"' + b'x' * (2 * 1024 * 1024) + b'"'], ids=["duplicate", "nonfinite", "oversized"])
def test_request_json_is_strict_and_bounded(server, raw):
    _, url = server
    status, _, _ = request(url + "/api/agents/jobs", cookie=login(url), raw=raw)
    assert status == 400


def test_unavailable_runtime_does_not_fall_back_to_fixture(server, monkeypatch):
    from guardian_core import dashboard_agents
    def missing():
        raise dashboard_agents.AgentRequestError("runtime_unavailable", "运行环境不可用", 503)
    monkeypatch.setattr(dashboard_agents, "_load_runtime", missing)
    _, url = server
    status, _, body = request(url + "/api/agents/jobs", REQUEST, login(url))
    assert status == 503 and body["status"] == "UNAVAILABLE"


def test_worker_exception_is_redacted_in_report(server, monkeypatch):
    def run(*args, **kwargs):
        raise RuntimeError("test-secret https://private-provider.example")
    install_runtime(monkeypatch, run)
    _, url = server
    cookie = login(url)
    status, _, created = request(url + "/api/agents/jobs", REQUEST, cookie)
    assert status == 202
    job = wait_job(url, cookie, created["job_id"])
    assert job["status"] == "FAILED"
    assert "test-secret" not in json.dumps(job) and "private-provider" not in json.dumps(job)


@pytest.mark.parametrize("execution_status,want", [
    ("COMPLETE", "COMPLETED"), ("CANCELLED", "CANCELLED"),
    ("INCOMPLETE", "FAILED"), ("UNAVAILABLE", "FAILED"), ("STALE_CONTEXT", "FAILED"),
])
def test_runner_incomplete_is_not_reported_as_completed(server, monkeypatch, execution_status, want):
    install_runtime(monkeypatch, lambda *args, **kwargs: {"execution_status": execution_status})
    _, url = server
    cookie = login(url)
    status, _, created = request(url + "/api/agents/jobs", REQUEST, cookie)
    assert status == 202
    assert wait_job(url, cookie, created["job_id"])["status"] == want


def test_models_uses_configured_http_endpoint_and_redacts_echo(server, monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    class ModelHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/v1/models" or self.headers.get("Authorization") != "Bearer test-secret":
                self.send_error(403)
                return
            body = json.dumps({"data": [{"id": "fixture-b"}, {"id": "test-secret-fixture"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass
    endpoint = ThreadingHTTPServer(("127.0.0.1", 0), ModelHandler)
    thread = threading.Thread(target=endpoint.serve_forever, daemon=True)
    thread.start()
    install_runtime(monkeypatch, lambda *args, **kwargs: {})
    _, url = server
    try:
        status, _, body = request(url + "/api/agents/models", {
            "base_url": f"http://127.0.0.1:{endpoint.server_port}/v1/chat/completions",
            "api_key": "test-secret"}, login(url))
        assert status == 200 and body["models"] == ["<redacted>-fixture", "fixture-b"]
        assert body["mode"] == "llm" and "test-secret" not in json.dumps(body)
    finally:
        endpoint.shutdown()
        endpoint.server_close()
        thread.join(timeout=2)


def test_only_eight_bounded_history_reports_are_retained(server, monkeypatch):
    install_runtime(monkeypatch, lambda *args, **kwargs: {
        "execution_status": "COMPLETE", "note": "test-secret", "detection": "NO_VIOLATIONS"})
    _, url = server
    cookie = login(url)
    ids = []
    for _ in range(9):
        status, _, created = request(url + "/api/agents/jobs", REQUEST, cookie)
        assert status == 202
        ids.append(created["job_id"])
        job = wait_job(url, cookie, ids[-1])
        assert job["report"]["note"] == "<redacted>"
    assert request(url + "/api/agents/job?id=" + ids[0], cookie=cookie)[0] == 404
    assert request(url + "/api/agents/job?id=" + ids[1], cookie=cookie)[0] == 200


@pytest.mark.parametrize("pause_at", ["runtime_initialization", "before_service_start"])
def test_logout_prevents_authenticated_inflight_request_from_starting_billable_job(server, monkeypatch, pause_at):
    """A revoked session must not launch even if its route previously authenticated."""
    from guardian_core import dashboard_agents
    entered, release, worker_started = threading.Event(), threading.Event(), threading.Event()
    def run(*args, **kwargs):
        worker_started.set()
        return {"execution_status": "COMPLETE"}
    install_runtime(monkeypatch, run)
    http, url = server
    cookie = login(url)
    if pause_at == "runtime_initialization":
        original = dashboard_agents._load_runtime
        def paused():
            entered.set()
            assert release.wait(3)
            return original()
        monkeypatch.setattr(dashboard_agents, "_load_runtime", paused)
    else:
        original = http.agent_jobs.start
        def paused(*args, **kwargs):
            entered.set()
            assert release.wait(3)
            return original(*args, **kwargs)
        monkeypatch.setattr(http.agent_jobs, "start", paused)
    result = []
    thread = threading.Thread(target=lambda: result.append(request(url + "/api/agents/jobs", REQUEST, cookie)))
    thread.start()
    try:
        assert entered.wait(2), "job request did not reach the controlled boundary"
        assert request(url + "/api/logout", {}, cookie)[0] == 200
    finally:
        release.set()
        thread.join(timeout=3)
    assert not thread.is_alive()
    assert result[0][0] == 401
    assert not worker_started.is_set()
    assert request(url + "/api/agents/jobs", REQUEST, login(url))[0] == 202
