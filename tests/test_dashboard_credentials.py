"""Persistent credentials must outlive sessions without leaking through HTTP."""
import json
import os
import stat
import threading

import pytest

from guardian_core.dashboard_credentials import JevKeyStore, CredentialStoreError
from guardian_core.dashboard_auth import DashboardAuth
from guardian_core.dashboard import DashboardHTTPServer
from guardian_core.dashboard_state import DashboardState
from test_dashboard_auth import FRONTEND, request_json


def test_saved_key_survives_logout_expiry_and_new_auth_instance(tmp_path):
    path = tmp_path / "private" / "key.json"
    auth = DashboardAuth(ttl_sec=5, key_store=JevKeyStore(path))
    token = auth.login("admin", "admin", now=0)
    assert auth.remember_jev_key(token, "test-persistent-key", now=0)
    auth.logout(token)
    assert auth.get_jev_key(token, now=1) is None
    auth = DashboardAuth(ttl_sec=5, key_store=JevKeyStore(path))
    token = auth.login("admin", "admin", now=10)
    assert auth.get_jev_key(token, now=10) == "test-persistent-key"
    assert auth.get_jev_key(token, now=15) is None
    token = auth.login("admin", "admin", now=20)
    assert auth.get_jev_key(token, now=20) == "test-persistent-key"


def test_replace_and_delete_are_durable_and_restricted(tmp_path):
    path = tmp_path / "private" / "key.json"
    store = JevKeyStore(path)
    store.save("old-test-key")
    store.save("new-test-key")
    assert JevKeyStore(path).get() == "new-test-key"
    assert "old-test-key" not in path.read_text()
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    store.clear()
    assert JevKeyStore(path).get() is None
    store.clear()  # Idempotent deletion.


def test_failed_replace_keeps_old_key_and_does_not_echo_secret(tmp_path, monkeypatch):
    path = tmp_path / "private" / "key.json"
    store = JevKeyStore(path)
    store.save("existing-test-key")
    def fail(*args):
        raise OSError("sensitive filesystem detail")
    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(CredentialStoreError) as error:
        store.save("replacement-test-key")
    assert "sensitive" not in str(error.value)
    assert "replacement" not in str(error.value)
    assert store.get() == "existing-test-key"
    assert len(list(path.parent.iterdir())) == 1


def test_corrupt_file_reports_error_without_overwriting_it(tmp_path):
    path = tmp_path / "key.json"
    path.write_text("corrupt-test-data")
    path.chmod(0o600)
    with pytest.raises(CredentialStoreError):
        JevKeyStore(path).get()
    assert path.read_text() == "corrupt-test-data"


@pytest.mark.skipif(os.name != "posix", reason="Linux credential boundary")
def test_store_refuses_symlink_and_world_readable_file(tmp_path):
    path = tmp_path / "key.json"
    store = JevKeyStore(path)
    store.save("test-key")
    path.chmod(0o644)
    with pytest.raises(CredentialStoreError):
        store.get()
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(CredentialStoreError):
        JevKeyStore(link).get()


def test_http_key_survives_server_restart_then_delete(tmp_path):
    path = tmp_path / "private" / "key.json"
    def serve(action):
        auth = DashboardAuth(key_store=JevKeyStore(path))
        server = DashboardHTTPServer(("127.0.0.1", 0), DashboardState(), FRONTEND, auth=auth)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        url = f"http://127.0.0.1:{server.server_port}"
        try:
            assert request_json(url + "/api/jev/key")[0] == 401
            status, headers, _ = request_json(url + "/api/login", data=b'{"username":"admin","password":"admin"}')
            assert status == 200
            headers = {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "Content-Type": "application/json"}
            action(url, headers)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(2)
    def save(url, headers):
        status, _, payload = request_json(url + "/api/jev/key", data=b'{"api_key":"http-test-key"}', headers=headers)
        assert status == 200 and payload == {"saved": True}
        assert "http-test-key" not in json.dumps(payload)
    def delete(url, headers):
        assert request_json(url + "/api/jev/key", headers=headers)[2] == {"saved": True}
        assert request_json(url + "/api/jev/key/clear", data=b"{}", headers=headers)[2] == {"saved": False}
    serve(save)
    serve(delete)
    serve(lambda url, headers: assert_deleted(url, headers))


def assert_deleted(url, headers):
    assert request_json(url + "/api/jev/key", headers=headers)[2] == {"saved": False}


def test_http_storage_failure_is_not_reported_as_saved(tmp_path, monkeypatch):
    store = JevKeyStore(tmp_path / "private" / "key.json")
    def fail(*args):
        raise CredentialStoreError()
    monkeypatch.setattr(store, "save", fail)
    auth = DashboardAuth(key_store=store)
    server = DashboardHTTPServer(("127.0.0.1", 0), DashboardState(), FRONTEND, auth=auth)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    url = f"http://127.0.0.1:{server.server_port}"
    try:
        _, headers, _ = request_json(url + "/api/login", data=b'{"username":"admin","password":"admin"}')
        status, _, payload = request_json(url + "/api/jev/key", data=b'{"api_key":"http-test-key"}', headers={"Cookie": headers["Set-Cookie"].split(";", 1)[0]})
        assert status == 503
        assert payload["error"]["code"] == "credential_store_unavailable"
        assert "http-test-key" not in json.dumps(payload)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)
