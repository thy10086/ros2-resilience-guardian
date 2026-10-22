"""Real local HTTP regressions for total deadlines and transport reclamation."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import threading
import time

import pytest

from experiments.agent_review.provider import OpenAICompatibleProvider, ProviderError


@contextmanager
def slow_server(phase="body"):
    reached = threading.Event()
    stopped = threading.Event()
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            requests.append(self.path)
            raw = json.dumps({"data": [{"id": "local-model"}], "padding": "x" * 240}).encode()
            try:
                if phase == "redirect" and self.path == "/v1/models":
                    self.send_response(302)
                    self.send_header("Location", "/redirect-target")
                    self.end_headers()
                    return
                if phase == "error":
                    self.send_response(429)
                    self.send_header("Content-Length", "1000000")
                    self.end_headers()
                    reached.set()
                    while not stopped.wait(.03):
                        self.wfile.write(b"synthetic-secret-canary")
                        self.wfile.flush()
                    return
                if phase == "oversized":
                    raw = b"x" * (128 * 1024 + 1)
                if phase == "headers":
                    self.wfile.write(b"HTTP/1.0 200 OK\r\nX-Drip: ")
                    self.wfile.flush()
                    reached.set()
                    while not stopped.wait(.03):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                reached.set()
                if phase in {"oversized", "redirect"}:
                    self.wfile.write(raw)
                    return
                for offset in range(0, len(raw), 10):
                    self.wfile.write(raw[offset:offset + 10])
                    self.wfile.flush()
                    if stopped.wait(.03):
                        return
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1", reached, requests
    finally:
        stopped.set()
        server.shutdown()
        server.server_close()
        thread.join(2)


def client(url, timeout=.15):
    return OpenAICompatibleProvider(base_url=url, api_key="synthetic-secret-canary",
                                    model="local-model", timeout_sec=timeout)


def capture_processes(monkeypatch):
    """Observe real OS process handles without replacing their behavior."""
    original = subprocess.Popen
    processes = []

    def launch(*args, **kwargs):
        process = original(*args, **kwargs)
        processes.append((process, args, kwargs))
        return process

    monkeypatch.setattr(subprocess, "Popen", launch)
    return processes


def assert_reaped(processes):
    assert processes, "HTTP must run in a terminable transport process"
    for process, _, _ in processes:
        assert process.poll() is not None
        if os.name == "posix":
            with pytest.raises(ChildProcessError):
                os.waitpid(process.pid, os.WNOHANG)
        assert process.stdin.closed
        assert process.stdout.closed


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_total_deadline_expires_even_when_response_never_idles(phase, monkeypatch):
    # Replacing a total deadline with urllib's socket timeout must fail this test.
    processes = capture_processes(monkeypatch)
    with slow_server(phase) as (url, reached, requests):
        started = time.monotonic()
        with pytest.raises(ProviderError, match="超时"):
            client(url).list_models()
        elapsed = time.monotonic() - started
        assert reached.is_set()
        assert elapsed < .6
        assert requests == ["/v1/models"]
    assert_reaped(processes)


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_cancel_kills_and_reaps_inflight_transport_and_latches(phase, monkeypatch):
    # Dropping only the coordinator's result must fail: the HTTP process must exit.
    processes = capture_processes(monkeypatch)
    errors = []
    with slow_server(phase) as (url, reached, requests):
        provider = client(url, timeout=5)

        def request():
            try:
                provider.list_models()
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=request, daemon=True)
        thread.start()
        try:
            assert reached.wait(2)
            started = time.monotonic()
            assert provider.cancel() is None
            assert provider.cancel() is None
            thread.join(.6)
            assert not thread.is_alive()
            assert time.monotonic() - started < .6
            assert len(errors) == 1 and isinstance(errors[0], ProviderError)
            assert "取消" in str(errors[0])
            with pytest.raises(ProviderError, match="取消"):
                provider.list_models()
            assert requests == ["/v1/models"]
            assert_reaped(processes)
        finally:
            # Preserve cleanup even while demonstrating the missing cancel method.
            if hasattr(provider, "cancel"):
                provider.cancel()
    thread.join(6)


def test_repeated_timeouts_do_not_leak_descriptors(monkeypatch):
    if not Path("/proc/self/fd").exists():
        pytest.skip("Linux descriptor accounting")
    processes = capture_processes(monkeypatch)
    before = len(list(Path("/proc/self/fd").iterdir()))
    with slow_server() as (url, _, _):
        for _ in range(3):
            with pytest.raises(ProviderError):
                client(url).list_models()
    # Close the fixture's accepted server sockets before counting parent FDs.
    assert len(list(Path("/proc/self/fd").iterdir())) == before
    assert_reaped(processes)


def test_transport_does_not_receive_key_or_url_in_argv_or_environment(monkeypatch):
    processes = capture_processes(monkeypatch)
    monkeypatch.setenv("GUARDIAN_AGENT_TEST_KEY", "synthetic-secret-canary")
    monkeypatch.setenv("HTTPS_PROXY", "http://untrusted.invalid")
    with slow_server() as (url, _, _):
        with pytest.raises(ProviderError):
            client(url).list_models()
    assert_reaped(processes)
    for _, args, kwargs in processes:
        exposed = repr(args) + repr(kwargs.get("env"))
        assert "synthetic-secret-canary" not in exposed
        assert url not in exposed
        assert "GUARDIAN_AGENT_TEST_KEY" not in kwargs["env"]
        assert "HTTPS_PROXY" not in kwargs["env"]


def test_oversized_request_is_rejected_before_starting_transport(monkeypatch):
    processes = capture_processes(monkeypatch)
    with slow_server() as (url, _, requests):
        with pytest.raises(ProviderError, match="请求超过限制"):
            client(url)._request("/chat/completions", {"data": "x" * (2 * 1024 * 1024)})
        assert requests == []
    assert processes == []


def test_oversized_response_is_rejected_and_transport_is_reaped(monkeypatch):
    processes = capture_processes(monkeypatch)
    with slow_server("oversized") as (url, _, requests):
        with pytest.raises(ProviderError, match="响应超过限制"):
            client(url, timeout=2).list_models()
        assert requests == ["/v1/models"]
    assert_reaped(processes)


def test_redirect_is_not_followed_or_retried(monkeypatch):
    processes = capture_processes(monkeypatch)
    with slow_server("redirect") as (url, _, requests):
        with pytest.raises(ProviderError, match="HTTP 302"):
            client(url, timeout=2).list_models()
        assert requests == ["/v1/models"]
    assert_reaped(processes)


def test_http_error_does_not_read_slow_credential_echo_body(monkeypatch):
    processes = capture_processes(monkeypatch)
    with slow_server("error") as (url, _, requests):
        started = time.monotonic()
        with pytest.raises(ProviderError, match="HTTP 429") as error:
            client(url, timeout=2).list_models()
        assert time.monotonic() - started < .6
        assert "synthetic-secret-canary" not in str(error.value)
        assert requests == ["/v1/models"]
    assert_reaped(processes)
