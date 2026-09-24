from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

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
    auth = DashboardAuth(username="admin", password="admin", ttl_sec=60.0)
    http = DashboardHTTPServer(("127.0.0.1", 0), DashboardState(), FRONTEND, auth=auth)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{http.server_port}"
    finally:
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)


def test_dashboard_auth_accepts_admin_admin_and_expires_tokens():
    auth = DashboardAuth(username="admin", password="admin", ttl_sec=5.0)

    assert auth.login("admin", "wrong", now=10.0) is None
    token = auth.login("admin", "admin", now=10.0)
    assert token
    assert auth.validate(token, now=14.9)
    assert not auth.validate(token, now=15.0)


def test_dashboard_requires_login_for_state_but_keeps_health_public(server):
    status, _, payload = request_json(f"{server}/api/health")
    assert status == 200
    assert payload["status"] == "ok"

    status, _, payload = request_json(f"{server}/api/state")
    assert status == 401
    assert payload["error"]["code"] == "auth_required"


def test_dashboard_login_cookie_unlocks_state_and_logout_revokes_it(server):
    body = json.dumps({"username": "admin", "password": "admin"}).encode()
    status, headers, payload = request_json(
        f"{server}/api/login",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    assert status == 200
    assert payload["authenticated"] is True
    cookie = headers["Set-Cookie"].split(";", 1)[0]

    status, _, payload = request_json(f"{server}/api/state", headers={"Cookie": cookie})
    assert status == 200
    assert payload["safety"]["state"] == "STARTING"

    status, _, payload = request_json(f"{server}/api/logout", data=b"{}", headers={"Cookie": cookie, "Content-Type": "application/json"})
    assert status == 200
    assert payload["authenticated"] is False
    status, _, payload = request_json(f"{server}/api/state", headers={"Cookie": cookie})
    assert status == 401
