"""Exercise actual HTTP and supervised graph, with no external model or API charge."""
import json
import sys
import threading
import time

import pytest

from agent_provider_fixture import provider_server


def provider(url):
    from experiments.agent_review.provider import OpenAICompatibleProvider
    return OpenAICompatibleProvider(base_url=url, api_key="synthetic-secret-canary",
        model="local-protocol-fixture")


def test_provider_uses_real_json_protocol_and_hides_key():
    with provider_server() as (url, calls):
        client = provider(url)
        assert client.list_models() == ["local-protocol-fixture"]
        reply = client.complete("worker", {"role": "worker", "task": {"intent_id": "assigned-1"}})
        assert reply == {"intent_id": "assigned-1"}
        assert calls[0]["response_format"] == {"type": "json_object"}
        assert "tools" not in calls[0]
        assert "synthetic-secret-canary" not in json.dumps(calls)
        assert "synthetic-secret-canary" not in repr(client)


@pytest.mark.parametrize("url", ["http://example.com/v1", "https://u:p@example.com/v1",
    "https://example.com/v1?api_key=secret", "https://example.com/v1#fragment", "file:///tmp/key"])
def test_invalid_url_is_rejected_before_network(url):
    with pytest.raises(ValueError):
        provider(url)


def test_escaped_secret_echo_is_redacted_after_json_decoding():
    from experiments.agent_review.provider import OpenAICompatibleProvider
    secret = 'synthetic-"\\-canary'
    with provider_server(behavior="echo_secret") as (url, _):
        client = OpenAICompatibleProvider(base_url=url, api_key=secret, model="local-protocol-fixture")
        output = client.complete("worker", {"role": "worker", "task": {"intent_id": "assigned"}})
    assert output["note"] == "<redacted>"
    assert client.redact({"future_report": {"nested": [secret]}}) == {"future_report": {"nested": ["<redacted>"]}}


@pytest.mark.parametrize("behavior", ["invalid", "refusal"])
def test_invalid_or_refused_output_is_not_retried(behavior):
    from experiments.agent_review.provider import ProviderError
    with provider_server(behavior=behavior) as (url, calls):
        with pytest.raises(ProviderError):
            provider(url).complete("worker", {"role": "worker", "task": {"intent_id": "assigned"}})
        assert len(calls) == 1


def run_api():
    if sys.platform != "linux":
        pytest.skip("supervised Linux worker")
    pytest.importorskip("langgraph")
    pytest.importorskip("pyseccomp")
    from experiments.agent_review.orchestration import run_review
    return run_review


def test_real_provider_selects_tests_instead_of_fixture_default():
    with provider_server() as (url, calls):
        report = run_api()({"sample": "guardian_recovery_virtual_model"}, provider=provider(url), timeout_sec=30)
    assert report["execution_status"] == "COMPLETE", report.get("reason")
    assert report["provider_mode"] == "llm"
    assert report["model_reasoning"] is True
    assert report["external_calls"] == len(calls) == 5
    assert {row["test_id"] for row in report["executions"]} == {"proof_replay", "healthy_resume"}
    assert {row["role"] for row in report["role_events"]} == {"goals", "planner", "worker", "reviewer"}
    assert all(row["mode"] == "llm" for row in report["role_events"])
    review_context = json.loads(calls[-1]["messages"][1]["content"])["task"]["review_context"]
    assert review_context["plan_digest"] == report["plan_digest"]
    assert review_context["source_snapshot_unchanged"] is True
    assert {row["test_id"] for row in review_context["executions"]} == {"healthy_resume", "proof_replay"}
    assert all(row["frame_count"] > 0 and row["validity"] == "VALID"
               and row["witness_summary"]["motion_frames"] > 0 for row in review_context["executions"])
    assert "synthetic-secret-canary" not in json.dumps(report)
    assert report["detection"] == "NO_VIOLATIONS"


def test_malicious_provider_plan_is_refused_without_fixture_fallback():
    with provider_server(behavior="malicious") as (url, calls):
        report = run_api()({"sample": "guardian_recovery_virtual_model"}, provider=provider(url))
    assert report["execution_status"] == "INCOMPLETE"
    assert report["provider_mode"] == "llm"
    assert report["executions"] == []
    assert len(calls) == 2


def test_provider_failure_keeps_live_mode_and_does_not_execute_tests():
    with provider_server(behavior="invalid") as (url, calls):
        report = run_api()({"sample": "guardian_recovery_virtual_model"}, provider=provider(url))
    assert report["execution_status"] == "INCOMPLETE"
    assert report["provider_mode"] == "llm"
    assert report["external_calls"] == 1
    assert report["executions"] == []


def test_cancellation_during_actual_http_drops_late_reply():
    run_review = run_api()
    cancelled = threading.Event()
    holder = {}
    with provider_server(behavior="slow") as (url, calls):
        client = provider(url)
        thread = threading.Thread(target=lambda: holder.update(report=run_review(
            {"sample": "guardian_recovery_virtual_model"}, provider=client, cancel=cancelled)))
        thread.start()
        deadline = time.monotonic() + 20
        while not calls and time.monotonic() < deadline:
            time.sleep(.01)
        assert calls, "coordinator never requested the provider"
        cancelled.set()
        thread.join(2)
        assert not thread.is_alive(), "cancellation waited for model response"
        report = holder["report"]
        assert report["execution_status"] == "CANCELLED"
        assert report["executions"] == []
        assert report["external_calls"] == 1
        time.sleep(1.1)
        assert report["executions"] == []
        assert len(calls) == 1


def test_live_cli_uses_explicit_key_environment_without_exposing_it(tmp_path):
    run_api()
    import os
    from pathlib import Path
    import subprocess
    script = Path(__file__).resolve().parents[1] / "experiments/run_agent_review.py"
    output = tmp_path / "live.json"
    environment = dict(os.environ, GUARDIAN_AGENT_TEST_KEY="synthetic-secret-canary")
    with provider_server() as (url, calls):
        completed = subprocess.run([sys.executable, str(script), "--sample", "--output", str(output),
            "--provider", "llm", "--base-url", url, "--model", "local-protocol-fixture",
            "--api-key-env", "GUARDIAN_AGENT_TEST_KEY"], env=environment,
            capture_output=True, text=True, timeout=35)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(output.read_text())["provider_mode"] == "llm"
    assert "synthetic-secret-canary" not in output.read_text() + completed.stdout + completed.stderr
    assert len(calls) == 5


def test_failed_coordinator_start_returns_unavailable_without_leaking_descriptors():
    run_review = run_api()
    from pathlib import Path
    before = len(list(Path("/proc/self/fd").iterdir()))
    for _ in range(3):
        report = run_review({"sample": "guardian_recovery_virtual_model"},
                            python_executable="/nonexistent/guardian-python")
        assert report["execution_status"] == "UNAVAILABLE"
    assert len(list(Path("/proc/self/fd").iterdir())) == before
