import json
import threading

import pytest
from pathlib import Path

from guardian_core.dashboard import DashboardHTTPServer
from guardian_core.dashboard_auth import DashboardAuth
from guardian_core.dashboard_state import DashboardState

from tests.test_dashboard_experiments import request_json


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "ros2_ws" / "src" / "guardian_core" / "guardian_core" / "frontend"


@pytest.fixture()
def server():
    """Run the HTTP bridge with no simulator callback for API contract tests."""
    http = DashboardHTTPServer(
        ("127.0.0.1", 0),
        DashboardState(),
        FRONTEND,
        auth=DashboardAuth(username="admin", password="admin", ttl_sec=60),
    )
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{http.server_port}"
    finally:
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)


def test_simulation_control_requires_auth_and_forwards_bounded_commands(server):
    status, _, payload = request_json(f"{server}/api/simulation/control", data=b'{"action":"start"}', headers={"Content-Type": "application/json"})
    assert status == 401
    assert payload["error"]["code"] == "auth_required"

    status, headers, _ = request_json(
        f"{server}/api/login", data=b'{"username":"admin","password":"admin"}',
        headers={"Content-Type": "application/json"})
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    status, _, payload = request_json(
        f"{server}/api/simulation/control", data=json.dumps({"action": "attack", "type": "speed_abuse"}).encode(),
        headers={"Cookie": cookie, "Content-Type": "application/json"})
    assert status == 503
    assert payload["error"]["code"] == "simulation_unavailable"

    status, _, payload = request_json(
        f"{server}/api/simulation/control", data=b'{"action":"exec","command":"rm -rf"}',
        headers={"Cookie": cookie, "Content-Type": "application/json"})
    assert status == 400
    assert payload["error"]["code"] == "invalid_simulation_command"


def test_frontend_exposes_closed_loop_simulation_controls_and_telemetry():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")
    styles = (FRONTEND / "styles.css").read_text(encoding="utf-8")
    assert 'data-panel="simulation"' in html
    assert 'id="panel-simulation"' in html
    assert 'id="simulation-start"' in html
    assert 'id="simulation-attack-speed"' in html
    assert 'id="simulation-actual-speed"' in html
    assert "SIMULATION_CONTROL_ENDPOINT" in script
    assert "renderSimulation" in script
    assert "simulation-grid" in styles


def test_authenticated_simulation_control_forwards_only_allowlisted_payloads():
    received = []
    http = DashboardHTTPServer(
        ("127.0.0.1", 0),
        DashboardState(),
        FRONTEND,
        auth=DashboardAuth(username="admin", password="admin", ttl_sec=60),
        simulation_control=received.append,
    )
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        status, headers, _ = request_json(
            f"http://127.0.0.1:{http.server_port}/api/login",
            data=b'{"username":"admin","password":"admin"}',
            headers={"Content-Type": "application/json"},
        )
        assert status == 200
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, _, payload = request_json(
            f"http://127.0.0.1:{http.server_port}/api/simulation/control",
            data=b'{"action":"attack","type":"replay"}',
            headers={"Cookie": cookie, "Content-Type": "application/json"},
        )
        assert status == 200
        assert payload == {"status": "SENT", "command": {"action": "attack", "type": "replay"}}
        assert received == [{"action": "attack", "type": "replay"}]
    finally:
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)
