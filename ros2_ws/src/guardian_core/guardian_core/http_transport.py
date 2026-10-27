"""Shared fixed HTTP worker with bounded stdin and an absolute-deadline parent.

Credentials never enter process arguments/environment. The child cannot follow
redirects or environment proxies, and is killed/reaped even during header drip.
"""
import base64
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

MAX_REQUEST = 2 * 1024 * 1024
MAX_RESPONSE = 128 * 1024


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def worker_main():
    """Accept the original agent envelope and the bytes-based Jev envelope."""
    result = {"error": "transport"}
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if len(raw) > MAX_REQUEST:
            raise ValueError()
        request = json.loads(raw)
        limit = request.get("max_response_bytes", MAX_RESPONSE)
        if type(limit) is not int or not 1 <= limit <= MAX_RESPONSE:
            raise ValueError()
        if "body_b64" in request:
            body = base64.b64decode(request["body_b64"], validate=True)
            headers = request["headers"]
        else:
            payload = request["payload"]
            body = None if payload is None else json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
            headers = {"Content-Type": "application/json", "Authorization": "Bearer " + request["api_key"]}
        if body is not None and len(body) > MAX_REQUEST:
            raise ValueError()
        http_request = Request(request["url"], data=body, headers=headers,
                               method="GET" if body is None else "POST")
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        try:
            with opener.open(http_request, timeout=request["timeout_sec"]) as response:
                content = response.read(limit + 1)
                status = response.status
            result = ({"error": "response_limit"} if len(content) > limit else
                {"status": status, "body": base64.b64encode(content).decode("ascii"), "error": None})
        except HTTPError as error:
            status = error.code
            error.close()
            result = {"status": status, "body": "", "error": None}
    except TimeoutError:
        result = {"error": "timeout"}
    except URLError as error:
        result = {"error": "timeout" if isinstance(error.reason, TimeoutError) else "transport"}
    except Exception:
        pass
    sys.stdout.write(json.dumps(result, ensure_ascii=True, allow_nan=False))
    sys.stdout.flush()


def _reap(process):
    if process.poll() is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=.2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def request_bytes(endpoint, headers, body, timeout, *, max_response_bytes=64 * 1024):
    """Return bounded bytes or a sanitized HTTP/timeout/transport exception."""
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not .05 <= timeout <= 30:
        raise ValueError("invalid HTTP deadline")
    if type(max_response_bytes) is not int or not 1 <= max_response_bytes <= MAX_RESPONSE:
        raise ValueError("invalid HTTP response limit")
    if type(body) is not bytes or len(body) > MAX_REQUEST:
        raise ValueError("invalid HTTP request body")
    deadline = time.monotonic() + timeout
    packet = json.dumps({"url": endpoint, "headers": dict(headers),
        "body_b64": base64.b64encode(body).decode("ascii"),
        "timeout_sec": timeout, "max_response_bytes": max_response_bytes},
        ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(packet) > MAX_REQUEST:
        raise ValueError("HTTP request exceeds limit")
    environment = {"PATH": os.defpath, "LANG": "C.UTF-8"}
    if os.name == "nt" and "SystemRoot" in os.environ:
        environment["SystemRoot"] = os.environ["SystemRoot"]
    process = None
    try:
        process = subprocess.Popen([sys.executable, "-I", str(Path(__file__).resolve())],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            close_fds=True, env=environment)
        raw, _ = process.communicate(packet, timeout=max(0, deadline - time.monotonic()))
        if time.monotonic() > deadline:
            raise TimeoutError("HTTP total deadline exceeded")
        if process.returncode != 0 or len(raw) > 2 * MAX_RESPONSE:
            raise OSError("HTTP transport unavailable")
        response = json.loads(raw)
        if response.get("error") == "timeout":
            raise TimeoutError("HTTP total deadline exceeded")
        if response.get("error") == "response_limit":
            raise ValueError("HTTP response exceeds limit")
        if response.get("error") is not None:
            raise OSError("HTTP transport unavailable")
        status = response.get("status")
        if type(status) is not int or not 100 <= status <= 599:
            raise OSError("HTTP transport unavailable")
        if not 200 <= status < 300:
            raise HTTPError("", status, "provider HTTP error", None, None)
        content = base64.b64decode(response["body"], validate=True)
        if len(content) > max_response_bytes:
            raise ValueError("HTTP response exceeds limit")
        return content
    except subprocess.TimeoutExpired:
        raise TimeoutError("HTTP total deadline exceeded") from None
    finally:
        if process is not None:
            _reap(process)
            for pipe in (process.stdin, process.stdout):
                if pipe is not None:
                    pipe.close()


if __name__ == "__main__":
    worker_main()
