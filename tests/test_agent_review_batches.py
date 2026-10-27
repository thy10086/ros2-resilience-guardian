"""Bounded graph contracts; the runner seam uses only the fixed owned model."""
import copy
from functools import lru_cache
import json

import pytest

from experiments.agent_review import orchestration


@lru_cache(maxsize=6)
def fixed_case(test_id):
    from experiments.agent_review.catalog import run_case
    result = run_case(test_id)
    result.update(status="COMPLETE", isolation={"mode": "TEST_OWNED_MODEL_SEAM"})
    return result


@pytest.fixture
def graph(monkeypatch):
    pytest.importorskip("langgraph")
    from experiments.agent_review import runner, contracts
    # Source-binding and process isolation have separate integration tests. Freeze
    # this seam's manifest so concurrent implementation work cannot invalidate a
    # graph contract test, and reuse only trusted fixed-model computations.
    manifest = contracts.source_manifest()
    monkeypatch.setattr(contracts, "source_manifest", lambda: dict(manifest))

    monkeypatch.setattr(runner, "run_registered_test",
        lambda test_id, **kwargs: copy.deepcopy(fixed_case(test_id)))
    return lambda payload, complete=None, replies=None: orchestration._run_graph(
        payload, replies or {}, 30, lambda event: None, complete=complete)


def cpp_files(count):
    return {"files": [{"filename": f"unit_{index:03}.cpp", "source": "int main() { return 0; }"}
        for index in range(count)]}


@pytest.mark.parametrize("position", [8, 127])
def test_risk_at_late_file_is_visible_to_goals_and_planner(graph, position):
    payload = {"files": [{"filename": f"unit_{index:03}.py", "source": "x = 1"}
        for index in range(position + 1)]}
    from test_agent_review_static import UNSAFE_SOURCE
    payload["files"][position]["source"] = UNSAFE_SOURCE
    report = graph(payload)
    risk_ids = {item["id"] for item in report["evidence"] if item.get("severity") == "critical"}
    assert report["execution_status"] == "COMPLETE", report.get("reason")
    for event in report["role_events"]:
        if event["role"] in {"goals", "planner"}:
            assert risk_ids.intersection(event["evidence_refs"])
    assert any(risk_ids.intersection(goal["evidence_refs"]) for goal in report["goals"])


def compact_reply(context):
    return {"reviews": [{"i": index, "a": context["task"]["comparisons"][finding["finding_id"]],
        "c": "静态线索", "m": "无运行证据"}
        for index, finding in enumerate(context["task"]["findings"])]}


def test_128_cpp_files_complete_within_16_role_calls_and_reply_budget(graph):
    report = graph(cpp_files(128))
    assert report["execution_status"] == "COMPLETE", report.get("reason")
    assert len(report["findings"]) == len(report["reviews"]) == 128
    assert report["role_calls"] == 16 and report["scenario_executions"] <= 12
    batches = [event for event in report["role_events"] if event["role"] == "reviewer"]
    assert len(batches) == 8
    assert all(event["input_bytes"] < 16384 and event["output_bytes"] <= 2048 for event in batches)
    assert {r["finding_id"] for r in report["reviews"]} == {f["finding_id"] for f in report["findings"]}


@pytest.mark.parametrize("attack", ["missing", "duplicate", "forged", "assessment"])
def test_invalid_later_batch_keeps_previously_validated_reviews(graph, attack):
    # Fixture and provider callbacks use the same response validation and limits.
    from experiments.agent_review.contracts import make_bundle
    bundle = make_bundle(cpp_files(32))
    calls = {"reviewer": 0}
    def complete(role, context):
        if role == "goals":
            return {"goals": [{"summary": "静态范围", "evidence_refs": [context["evidence"][0]["id"]]}], "gaps": []}
        if role == "planner":
            goal = context["task"]["goals"][0]
            return {"intents": [{"goal_id": goal["goal_id"], "test_id": "healthy_resume",
                "evidence_refs": goal["evidence_refs"], "reason": "正常对照"}], "stop_reason": "", "gaps": []}
        if role == "worker":
            return {"intent_id": context["task"]["intent_id"]}
        calls[role] += 1
        reply = compact_reply(context)
        if calls[role] == 2:
            if attack == "missing":
                reply["reviews"].pop()
            elif attack == "duplicate":
                reply["reviews"][-1] = dict(reply["reviews"][0])
            elif attack == "forged":
                reply["reviews"][-1]["i"] = 999
            else:
                reply["reviews"][-1]["a"] = "REPRODUCED"
        return reply
    report = graph(cpp_files(32), complete)
    assert bundle["evidence"]
    assert report["execution_status"] == "INCOMPLETE"
    assert len(report["findings"]) == 32 and len(report["reviews"]) == 16
    assert report["detection"] == "STATIC_REVIEW_REQUIRED"
    assert len(report["review_pending_ids"]) == 16


def test_fixture_and_provider_share_compact_review_contract(graph):
    payload = cpp_files(1)
    fixture = graph(payload, replies={"reviewer": {"reviews": [{"i": 0,
        "a": "INCONCLUSIVE", "c": "静态线索", "m": "未执行"}]}})
    assert fixture["execution_status"] == "COMPLETE", fixture.get("reason")
    assert fixture["reviews"][0]["counterevidence"] == "静态线索"


def test_provider_class_parses_same_multi_batch_wire_with_maximal_short_text(graph, monkeypatch):
    from experiments.agent_review.provider import OpenAICompatibleProvider
    client = OpenAICompatibleProvider(base_url="http://127.0.0.1:1234/v1",
        api_key="synthetic-contract-fixture", model="contract-fixture")
    requests = []
    def transport_seam(suffix, payload):
        assert suffix == "/chat/completions"
        requests.append(payload)
        context = json.loads(payload["messages"][1]["content"])
        role, task = context["role"], context["task"]
        if role == "goals":
            reply = {"goals": [{"summary": "范围复核", "evidence_refs": [context["evidence"][0]["id"]]}], "gaps": []}
        elif role == "planner":
            goal = task["goals"][0]
            reply = {"intents": [{"goal_id": goal["goal_id"], "test_id": "healthy_resume",
                "evidence_refs": goal["evidence_refs"], "reason": "正常对照"}], "stop_reason": "", "gaps": []}
        elif role == "worker":
            reply = {"intent_id": task["intent_id"]}
        else:
            reply = compact_reply(context)
            for row in reply["reviews"]:
                row.update(c="\U00020000" * 8, m="\U00020000" * 8)
        return {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(reply)}}]}
    monkeypatch.setattr(client, "_request", transport_seam)
    report = graph(cpp_files(17), client.complete)
    assert report["execution_status"] == "COMPLETE", report.get("reason")
    assert len(report["reviews"]) == 17 and client.calls == len(requests) == 5
    assert all(request["max_completion_tokens"] == 2048 for request in requests)
    assert all(event["output_bytes"] <= 2048 for event in report["role_events"] if event["role"] == "reviewer")


def test_call_budget_exhaustion_keeps_completed_review_batches(graph):
    from test_agent_review_static import UNSAFE_SOURCE
    payload = {"files": [{"filename": f"controller_{index:03}.py", "source": UNSAFE_SOURCE}
        for index in range(32)]}
    report = graph(payload)
    assert report["execution_status"] == "INCOMPLETE"
    assert report["reason"] == "role budget exhausted"
    assert report["role_calls"] == 16 and report["scenario_executions"] <= 12
    assert len(report["reviews"]) == 128
    assert len(report["review_pending_ids"]) == len(report["findings"]) - 128


def test_installed_layout_finds_fixed_research_root(tmp_path, monkeypatch):
    from guardian_core import dashboard_agents
    root = tmp_path / "repository"
    for relative in ("PROJECT_GUIDE.md", "experiments/agent_review/orchestration.py",
            "experiments/agent_review/contracts.py", "docs/artex_ros2_agent_prompts.md",
            "ros2_ws/src/guardian_core/guardian_core/dashboard_agents.py",
            "output/agent-review-venv/bin/python"):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("marker")
    installed = root / "ros2_ws/install/humble/guardian_core/lib/python3.10/site-packages/guardian_core/dashboard_agents.py"
    monkeypatch.setattr(dashboard_agents, "__file__", str(installed))
    monkeypatch.delenv("GUARDIAN_RESEARCH_ROOT", raising=False)
    assert dashboard_agents._research_root() == root.resolve()
    monkeypatch.setenv("GUARDIAN_RESEARCH_ROOT", str(tmp_path / "invalid"))
    with pytest.raises(dashboard_agents.AgentRequestError):
        dashboard_agents._research_root()


def test_admin_root_requires_source_markers_and_fixed_venv(tmp_path, monkeypatch):
    from guardian_core import dashboard_agents
    monkeypatch.setenv("GUARDIAN_RESEARCH_ROOT", str(tmp_path))
    (tmp_path / "PROJECT_GUIDE.md").write_text("marker")
    with pytest.raises(dashboard_agents.AgentRequestError):
        dashboard_agents._research_root()
