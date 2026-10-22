"""Fixed stdlib-only HTTP child. Credentials enter through bounded stdin only.

The parent enforces a monotonic total deadline and kills/reaps this process on
timeout or cancellation, even if a remote server continuously drips headers.
No exception details, request URLs or HTTP error bodies leave this process.
"""
import base64
import json
import sys
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

MAX_REQUEST = 2 * 1024 * 1024
MAX_RESPONSE = 128 * 1024


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    result = {"error": "transport"}
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if len(raw) > MAX_REQUEST:
            raise ValueError()
        request = json.loads(raw)
        payload = request["payload"]
        body = None if payload is None else json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if body is not None and len(body) > MAX_REQUEST:
            raise ValueError()
        http_request = Request(request["url"], data=body,
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + request["api_key"]},
            method="GET" if payload is None else "POST")
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        try:
            with opener.open(http_request, timeout=request["timeout_sec"]) as response:
                content = response.read(MAX_RESPONSE + 1)
                status = response.status
            if len(content) > MAX_RESPONSE:
                result = {"error": "response_limit"}
            else:
                result = {"status": status, "body": base64.b64encode(content).decode("ascii"), "error": None}
        except HTTPError as error:
            # Do not read a potentially unbounded or credential-bearing body.
            status = error.code
            error.close()
            result = {"status": status, "body": "", "error": None}
    except Exception:
        pass
    sys.stdout.write(json.dumps(result, ensure_ascii=True, allow_nan=False))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
