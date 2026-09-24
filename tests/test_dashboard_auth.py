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
from guardian_core.dashboard_jev import JevDashboardService


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "ros2_ws" / "src" / "guardian_core" / "guardian_core" / "frontend"


class FakeJevTransport:
    """Return a bounded provider fixture while recording the forwarded key."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def __call__(self, endpoint, headers, body, timeout):
        self.calls.append({"endpoint": endpoint, "headers": dict(headers), "body": body, "timeout": timeout})
        return json.dumps(
            {
                "model": "jev-test",
                "answers": {
                    "attack_type": {
                        "type": "choice",
                        "choice": "unsafe_command",
                        "confidence": 0.9,
                        "probabilities": {"unsafe_command": 0.9},
                    },
                    "mission_impact": {
                        "type": "choice",
                        "choice": "critical",
                        "confidence": 0.8,
                        "probabilities": {"critical": 0.8},
                    },
                    "needs_human_review": {"type": "noul", "noul": 1.0},
                },
            }
        ).encode()


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


@pytest.fixture()
def server_with_jev():
    transport = FakeJevTransport()
    auth = DashboardAuth(username="admin", password="admin", ttl_sec=60.0)
    service = JevDashboardService(transport=transport)
    http = DashboardHTTPServer(("127.0.0.1", 0), DashboardState(), FRONTEND, jev_service=service, auth=auth)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{http.server_port}", transport
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


def test_dashboard_jev_key_is_bound_to_session_and_expires_with_it():
    auth = DashboardAuth(username="admin", password="admin", ttl_sec=5.0)
    token = auth.login("admin", "admin", now=10.0)
    assert token

    assert auth.remember_jev_key(token, "jev-session-key", now=10.0)
    assert auth.has_jev_key(token, now=14.9)
    assert auth.get_jev_key(token, now=14.9) == "jev-session-key"
    assert not auth.has_jev_key(token, now=15.0)

    token = auth.login("admin", "admin", now=20.0)
    assert token
    assert auth.remember_jev_key(token, "jev-session-key", now=20.0)
    auth.logout(token)
    assert not auth.has_jev_key(token, now=20.1)


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


def test_dashboard_jev_key_status_is_protected_and_saved_without_echoing_key(server):
    body = json.dumps({"username": "admin", "password": "admin"}).encode()
    status, headers, _ = request_json(
        f"{server}/api/login",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    assert status == 200
    cookie = headers["Set-Cookie"].split(";", 1)[0]

    status, _, payload = request_json(f"{server}/api/jev/key", headers={"Cookie": cookie})
    assert status == 200
    assert payload == {"saved": False}

    key = "jev-session-key"
    status, _, payload = request_json(
        f"{server}/api/jev/key",
        data=json.dumps({"api_key": key}).encode(),
        headers={"Cookie": cookie, "Content-Type": "application/json"},
    )
    assert status == 200
    assert payload == {"saved": True}
    assert key not in json.dumps(payload)

    status, _, payload = request_json(f"{server}/api/jev/key", headers={"Cookie": cookie})
    assert status == 200
    assert payload == {"saved": True}

    status, _, payload = request_json(
        f"{server}/api/jev/key/clear",
        data=b"{}",
        headers={"Cookie": cookie, "Content-Type": "application/json"},
    )
    assert status == 200
    assert payload == {"saved": False}


def test_dashboard_jev_test_uses_saved_session_key_when_request_omits_it(server_with_jev):
    server, transport = server_with_jev
    body = json.dumps({"username": "admin", "password": "admin"}).encode()
    status, headers, _ = request_json(
        f"{server}/api/login",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    assert status == 200
    cookie = headers["Set-Cookie"].split(";", 1)[0]

    key = "jev-session-key"
    status, _, payload = request_json(
        f"{server}/api/jev/key",
        data=json.dumps({"api_key": key}).encode(),
        headers={"Cookie": cookie, "Content-Type": "application/json"},
    )
    assert status == 200
    assert payload == {"saved": True}

    status, _, payload = request_json(
        f"{server}/api/jev/test",
        data=json.dumps({"state": "uploaded sample: unsafe command burst"}).encode(),
        headers={"Cookie": cookie, "Content-Type": "application/json"},
    )
    assert status == 200
    assert payload["status"] == "OK"
    assert payload["connected"] is True
    assert key not in json.dumps(payload)
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["headers"]["Authorization"] == f"Bearer {key}"
    forwarded = json.loads(call["body"].decode())
    assert forwarded["state"]["summary"] == "uploaded sample: unsafe command burst"

    status, _, payload = request_json(
        f"{server}/api/jev/key/clear",
        data=b"{}",
        headers={"Cookie": cookie, "Content-Type": "application/json"},
    )
    assert status == 200
    assert payload == {"saved": False}

    status, _, payload = request_json(
        f"{server}/api/jev/test",
        data=json.dumps({"state": "second sample"}).encode(),
        headers={"Cookie": cookie, "Content-Type": "application/json"},
    )
    assert status == 400
    assert payload["error"]["code"] == "missing_api_key"
    assert len(transport.calls) == 1
