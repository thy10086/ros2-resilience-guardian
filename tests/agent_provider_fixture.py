"""Local Chat Completions protocol fixture; this is not an actual language model."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time


@contextmanager
def provider_server(*, behavior="valid"):
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            raw = json.dumps({"data": [{"id": "local-protocol-fixture"}]}).encode()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append(request)
            if behavior == "slow":
                time.sleep(1)
            context = json.loads(request["messages"][1]["content"])
            role, task = context["role"], context["task"]
            if role == "goals":
                reply = {"goals": [{"summary": "Inspect proof replay", "evidence_refs": [context["evidence"][0]["id"]]}], "gaps": []}
            elif role == "planner":
                goal = task["goals"][0]
                reply = {"intents": [{"goal_id": goal["goal_id"], "test_id": "proof_replay",
                    "evidence_refs": goal["evidence_refs"], "reason": "Inspect single-use proof"}],
                    "stop_reason": "Bounded review", "gaps": []}
                if behavior == "malicious":
                    reply["intents"][0]["command"] = "touch /tmp/should-never-run"
            elif role == "worker":
                reply = {"intent_id": task["intent_id"]}
            else:
                reply = {"reviews": [{"finding_id": f["finding_id"], "intent_id": f["intent_id"],
                    "artifact_refs": f["artifact_refs"], "assessment": task["comparisons"][f["finding_id"]],
                    "counterevidence": "Protocol fixture only", "missing": "Physical validation"}
                    for f in task["findings"]]}
            if behavior == "echo_secret":
                reply["note"] = self.headers["Authorization"].removeprefix("Bearer ")
            content = json.dumps(reply)
            result = {"choices": [{"finish_reason": "stop", "message": {"content": content}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 20}}
            if behavior == "invalid":
                result["choices"][0]["message"]["content"] = "not-json"
            if behavior == "refusal":
                result["choices"][0]["message"]["refusal"] = "Refused"
            raw = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1", calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
