"""Evidence identity and capability checks reject untrusted model claims."""
import copy
import hashlib
import json
from pathlib import Path

import pytest

from experiments.agent_review import contracts


SAMPLE = {"sample": "guardian_recovery_virtual_model"}
FILES = [{"filename": "controller.py", "source": "# secret marker must stay local\nx = 1\n"}]


def proposal(bundle, test_id="healthy_resume"):
    return {"goal_id": "g1", "test_id": test_id,
        "evidence_refs": [bundle["evidence"][0]["id"]], "reason": "检查恢复约束"}


def frame(now=1.0):
    return {"now": now, "task_phase": "navigate", "recovery_phase": "SAFE_STOP",
        "evidence_state": "healthy", "stopped_ack": True, "unresolved": False,
        "forced_stop": False, "graph_fingerprint": "g", "policy_fingerprint": "p",
        "ledger_anchor": "l", "command_epoch": 1, "next_command_epoch": 1,
        "mission_allowed": False, "speed_limit": 0, "observed_speed": 0.0,
        "pending_proof": None, "consumed_proof_id": ""}


def test_digest_uses_utf8_canonical_json_and_rejects_non_json_values():
    expected = hashlib.sha256('{"a":1,"z":"中"}'.encode("utf-8")).hexdigest()
    assert contracts.digest({"z": "中", "a": 1}) == expected
    for value in (float("nan"), {"x": float("inf")}, {1: "numeric key"}, (1, 2)):
        with pytest.raises(ValueError):
            contracts.digest(value)


@pytest.mark.parametrize("text", [
    '{"a":1,"a":2}', '{"nested":{"a":1,"a":2}}',
    '{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}', '{"x":1e309}',
])
def test_strict_json_rejects_duplicate_keys_and_nonfinite_numbers(text):
    with pytest.raises(ValueError):
        contracts.strict_loads(text)


def test_strict_json_preserves_valid_data():
    assert contracts.strict_loads('{"ok":[1,true,null,"中"]}') == {"ok": [1, True, None, "中"]}


def test_strict_json_rejects_strings_that_cannot_form_canonical_utf8():
    with pytest.raises(ValueError):
        contracts.strict_loads('"\\ud800"')


@pytest.mark.parametrize("payload", [
    {}, {"sample": "unknown"}, {"sample": SAMPLE["sample"], "frames": []},
    {"files": FILES, "authenticated": True}, {"frames": [frame()], "findings": []},
    {"files": [{**FILES[0], "trusted": True}]},
    {"files": [{"filename": "../controller.py", "source": "x = 1"}]},
    {"files": [{"filename": "controller.py", "source": "x = 1"}] * 2},
    {"frames": [{**frame(), "authenticated": True}]},
    {"frames": [{**frame(), "now": float("nan")}]},
])
def test_bundle_accepts_only_raw_bounded_inputs(payload):
    with pytest.raises(ValueError):
        contracts.make_bundle(payload)


def test_file_identity_is_stable_sorted_and_keeps_exact_source_bytes():
    files = FILES + [{"filename": "other.py", "source": "value = 2\n"}]
    first = contracts.make_bundle({"files": files})
    second = contracts.make_bundle({"files": list(reversed(files))})
    assert first["context_digest"] == second["context_digest"]
    changed = copy.deepcopy(files)
    changed[0]["source"] += "# a comment changes the reviewed snapshot\n"
    assert contracts.make_bundle({"files": changed})["context_digest"] != first["context_digest"]
    assert len({item["id"] for item in first["evidence"]}) == len(first["evidence"])
    assert "secret marker must stay local" not in json.dumps(first)
    assert first["summary"]["input_kind"] == "files"
    assert first["summary"]["source_kind"] == "user_supplied"
    assert first["target"]["kind"] == "guardian_recovery_virtual_model"
    assert first["target"]["uploaded_source_executed"] is False
    assert all(item["authenticated"] is False for item in first["evidence"])
    assert all(item["verification_kind"] == "STATIC_REVIEW" for item in first["evidence"])
    assert any(item["provenance"] == "EXTRACTED" for item in first["evidence"])


def test_submitted_trace_is_rechecked_by_the_existing_oracle_without_authentication():
    bundle = contracts.make_bundle({"frames": [frame(1 + i * .05) for i in range(65)]})
    assert bundle["summary"]["trace"]["violation_codes"] == ["recovery_stalled"]
    assert bundle["summary"]["input_kind"] == "frames"
    assert bundle["summary"]["source_kind"] == "user_supplied"
    assert all(item["verification_kind"] == "TRACE_RECHECK" for item in bundle["evidence"])
    assert all(item["authenticated"] is False for item in bundle["evidence"])
    assert bundle["target"]["uploaded_source_executed"] is False


def test_sample_remains_an_explicit_virtual_model_before_execution():
    bundle = contracts.make_bundle(SAMPLE)
    assert bundle["summary"]["input_kind"] == "sample"
    assert bundle["summary"]["source_kind"] == "project_owned_model"
    assert bundle["target"]["kind"] == "guardian_recovery_virtual_model"
    assert bundle["summary"]["registered_tests_executed"] is False
    assert all(item["authenticated"] is False for item in bundle["evidence"])
    json.dumps(bundle, allow_nan=False)


def test_source_manifest_is_relative_complete_and_detects_changed_code(tmp_path, monkeypatch):
    frozen = contracts.source_manifest()
    root = Path(__file__).resolve().parents[1]
    assert "experiments/recovery_scenarios.py" in frozen
    assert "experiments/agent_review/contracts.py" in frozen
    assert "ros2_ws/src/guardian_core/guardian_core/recovery_feedback.py" in frozen
    assert "docs/artex_ros2_agent_prompts.md" in frozen
    assert contracts.verify_sources(frozen)
    for relative, sha in frozen.items():
        assert not Path(relative).is_absolute() and ".." not in Path(relative).parts
        assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == sha
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((root / relative).read_bytes())
    monkeypatch.setattr(contracts, "REPO_ROOT", tmp_path)
    original = contracts.make_bundle(SAMPLE)
    changed = tmp_path / "experiments/recovery_scenarios.py"
    changed.write_bytes(changed.read_bytes() + b"\n# changed snapshot\n")
    assert not contracts.verify_sources(frozen)
    assert contracts.make_bundle(SAMPLE)["context_digest"] != original["context_digest"]
    assert not contracts.verify_sources({"../outside.py": "0" * 64})
    assert not contracts.verify_sources({})


def test_planner_receives_server_identity_and_cannot_repeat_a_test():
    bundle = contracts.make_bundle(SAMPLE)
    intents = contracts.approve_plan("planner", [proposal(bundle)], bundle, ["g1"])
    assert len(intents) == 1
    intent = intents[0]
    assert intent["intent_id"] and intent["context_digest"] == bundle["context_digest"]
    assert intent["test_id"] == "healthy_resume"
    assert intent["evidence_refs"] == [bundle["evidence"][0]["id"]]
    with pytest.raises(ValueError):
        contracts.approve_plan("planner", [proposal(bundle)], bundle, ["g1"], seen=["healthy_resume"])
    with pytest.raises(ValueError):
        contracts.approve_plan("planner", [proposal(bundle), proposal(bundle)], bundle, ["g1"])


@pytest.mark.parametrize("role", ["goals", "worker", "reviewer", "admin"])
def test_only_planner_may_propose_test_intents(role):
    bundle = contracts.make_bundle(SAMPLE)
    with pytest.raises(ValueError):
        contracts.approve_plan(role, [proposal(bundle)], bundle, ["g1"])


@pytest.mark.parametrize("changes", [
    {"command": "run anything"}, {"intent_id": "chosen"}, {"context_digest": "forged"},
    {"passed": True}, {"goal_id": "other"}, {"test_id": "unregistered"},
    {"evidence_refs": []}, {"evidence_refs": ["forged"]},
    {"reason": "x" * 513}, {"reason": ""},
])
def test_plan_rejects_untrusted_execution_fields_or_invalid_scope(changes):
    bundle = contracts.make_bundle(SAMPLE)
    with pytest.raises(ValueError):
        contracts.approve_plan("planner", [{**proposal(bundle), **changes}], bundle, ["g1"])


def test_plan_rejects_cross_bundle_refs_repeated_refs_and_excess_work():
    bundle = contracts.make_bundle(SAMPLE)
    other = contracts.make_bundle({"files": FILES})
    invalid = proposal(bundle)
    invalid["evidence_refs"] = [other["evidence"][0]["id"]]
    with pytest.raises(ValueError):
        contracts.approve_plan("planner", [invalid], bundle, ["g1"])
    invalid["evidence_refs"] = proposal(bundle)["evidence_refs"] * 2
    with pytest.raises(ValueError):
        contracts.approve_plan("planner", [invalid], bundle, ["g1"])
    with pytest.raises(ValueError):
        contracts.approve_plan("planner", [proposal(bundle)] * 7, bundle, ["g1"])
    with pytest.raises(ValueError):
        contracts.approve_plan("planner", [proposal(bundle)], bundle, ["g1"] * 7)


def test_plan_rejects_malformed_evidence_records_as_invalid_data():
    bundle = contracts.make_bundle(SAMPLE)
    valid_proposal = proposal(bundle)
    bundle["evidence"][0] = None
    with pytest.raises(ValueError):
        contracts.approve_plan("planner", [valid_proposal], bundle, ["g1"])


def test_plan_rejects_modified_bundle_identity_and_claimed_authentication():
    bundle = contracts.make_bundle(SAMPLE)
    valid_proposal = proposal(bundle)
    forged = copy.deepcopy(bundle)
    forged["evidence"][0]["id"] = "chosen-id"
    with pytest.raises(ValueError):
        contracts.approve_plan("planner", [valid_proposal], forged, ["g1"])
    forged = copy.deepcopy(bundle)
    forged["evidence"][0]["authenticated"] = True
    with pytest.raises(ValueError):
        contracts.approve_plan("planner", [valid_proposal], forged, ["g1"])
    forged = copy.deepcopy(bundle)
    forged["target"]["kind"] = "uploaded_program"
    with pytest.raises(ValueError):
        contracts.approve_plan("planner", [valid_proposal], forged, ["g1"])


def test_all_six_registered_tests_can_be_approved_once_and_stop_can_be_empty():
    bundle = contracts.make_bundle(SAMPLE)
    tests = ["healthy_resume", "ttl_gap", "graph_change", "policy_change", "epoch_change", "proof_replay"]
    approved = contracts.approve_plan("planner", [proposal(bundle, test) for test in tests], bundle, ["g1"])
    assert {intent["test_id"] for intent in approved} == set(tests)
    assert len({intent["intent_id"] for intent in approved}) == 6
    assert contracts.approve_plan("planner", [], bundle, ["g1"], seen=tests) == []
