"""Regression checks for request deadlines and honest trace property coverage."""
import json
from pathlib import Path
import socketserver
import threading
import time
from contextlib import contextmanager
from urllib.error import HTTPError

import pytest

from guardian_core.dashboard_jev import JevDashboardService
from guardian_core.dashboard_recovery import inspect_recovery_trace


@contextmanager
def provider(behavior):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            received = b""
            while b"\r\n\r\n" not in received:
                received += self.request.recv(4096)
            try:
                if behavior == "headers":
                    self.request.sendall(b"HTTP/1.1 200 OK\r\nX-Drip: ")
                    for _ in range(20):
                        self.request.sendall(b"a")
                        time.sleep(.05)
                    self.request.sendall(b"\r\nContent-Length: 2\r\n\r\n{}")
                elif behavior == "body":
                    self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 22\r\n\r\n")
                    for byte in b'{"probe":true}        ':
                        self.request.sendall(bytes([byte]))
                        time.sleep(.05)
                elif behavior == "401":
                    self.request.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 1000000\r\n\r\n")
                elif behavior == "redirect":
                    self.request.sendall(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/private\r\nContent-Length: 0\r\n\r\n")
                else:
                    self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
            except (BrokenPipeError, ConnectionResetError):
                pass

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.02), daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


@pytest.mark.parametrize("behavior", ["headers", "body"])
def test_jev_default_transport_has_absolute_deadline_and_reaps_child(behavior, monkeypatch):
    import subprocess
    original = subprocess.Popen
    children = []

    def capture(*args, **kwargs):
        assert "priority-dummy-key" not in str(args)
        assert "priority-dummy-key" not in str(kwargs.get("env", {}))
        child = original(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", capture)
    with provider(behavior) as endpoint:
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            JevDashboardService._default_transport(endpoint,
                {"Authorization": "Bearer priority-dummy-key"}, b"{}", .25)
        assert time.monotonic() - started < 1.0
    assert children and all(child.poll() is not None for child in children)


@pytest.mark.parametrize("behavior,status", [("401", 401), ("redirect", 302)])
def test_jev_http_errors_do_not_read_body_or_follow_redirect(behavior, status):
    with provider(behavior) as endpoint:
        with pytest.raises(HTTPError) as error:
            JevDashboardService._default_transport(endpoint, {}, b"{}", .5)
        assert error.value.code == status


def test_trace_reports_authorization_separately_from_missing_motion_evidence():
    from experiments.recovery_scenarios import Action, execute_scenario
    frames = [frame.to_dict() for frame in execute_scenario([Action("healthy", .6)])]
    frames[-1]["speed_limit"] = 1e100
    report = inspect_recovery_trace({"frames": frames})
    assert report["verdict"] == "NO_VIOLATIONS"
    properties = report["property_assessments"]
    assert properties["recovery_authorization"]["status"] == "SATISFIED"
    assert properties["motion_envelope"]["status"] == "INSUFFICIENT_EVIDENCE"
    assert properties["source_authenticity"]["status"] == "INSUFFICIENT_EVIDENCE"
    assert report["evidence_sufficiency"] == "PARTIAL"


def test_trace_property_violation_and_gap_are_kept_separate():
    samples = json.loads((Path(__file__).resolve().parents[1] /
        "ros2_ws/src/guardian_core/guardian_core/frontend/recovery-samples.json").read_text(encoding="utf-8"))["samples"]
    expired = next(sample for sample in samples if "expired_proof" in sample["expected_codes"])
    report = inspect_recovery_trace({"frames": expired["frames"]})
    assert report["property_assessments"]["recovery_authorization"]["status"] == "VIOLATED"
    assert report["property_assessments"]["motion_envelope"]["status"] == "INSUFFICIENT_EVIDENCE"


def test_short_stop_prefix_does_not_claim_bounded_recovery_was_observed():
    from guardian_core.recovery_feedback import RecoveryFrame
    frame = RecoveryFrame(now=1, task_phase="stop", recovery_phase="SAFE_STOP",
        evidence_state="healthy", stopped_ack=True, unresolved=False, forced_stop=False,
        graph_fingerprint="g", policy_fingerprint="p", ledger_anchor="l", command_epoch=1,
        next_command_epoch=1, mission_allowed=False, speed_limit=0).to_dict()
    report = inspect_recovery_trace({"frames": [frame]})
    assert report["property_assessments"]["bounded_recovery"]["status"] == "INSUFFICIENT_EVIDENCE"


def test_unverified_running_frame_does_not_prove_bounded_recovery():
    from guardian_core.recovery_feedback import RecoveryFrame
    frame = RecoveryFrame(now=1, task_phase="run", recovery_phase="NORMAL",
        evidence_state="healthy", stopped_ack=False, unresolved=False, forced_stop=False,
        graph_fingerprint="g", policy_fingerprint="p", ledger_anchor="l", command_epoch=1,
        next_command_epoch=1, mission_allowed=True, speed_limit=.2, observed_speed=.2).to_dict()
    report = inspect_recovery_trace({"frames": [frame]})
    assert report["property_assessments"]["recovery_authorization"]["status"] == "VIOLATED"
    assert report["property_assessments"]["bounded_recovery"]["status"] == "INSUFFICIENT_EVIDENCE"
