"""Real registered execution, trigger witnesses, and process lifecycle checks."""
import importlib
import importlib.util
import inspect
import os
import shutil
import subprocess
import sys
import threading
import time
import venv

import pytest


IDS = ("healthy_resume", "ttl_gap", "graph_change", "policy_change", "epoch_change", "proof_replay")


def catalog_module():
    return importlib.import_module("experiments.agent_review.catalog")


def runner_module():
    return importlib.import_module("experiments.agent_review.runner")


@pytest.mark.parametrize("test_id", IDS)
def test_registered_case_executes_real_production_core(test_id):
    result = catalog_module().run_case(test_id)
    assert result["test_id"] == test_id
    assert result["validity"] == "VALID"
    assert result["assertion_result"] == "PASS", result["assertion_failures"]
    assert len(result["frames"]) >= 10
    assert result["witnesses"]["candidate_frames"]
    assert result["witnesses"]["consumed_proof_frames"]
    assert result["witnesses"]["motion_frames"]
    if test_id == "proof_replay":
        assert result["witnesses"]["proof_replay_attempts"] == 1
        event = next(e for e in result["witnesses"]["events"] if e["kind"] == "proof_replay")
        assert event["previously_consumed"] is True
        assert event["allowed"] is False
        assert event["reason"] == "recovery proof replayed"


def test_missing_trigger_is_not_exercised():
    result = catalog_module().validate_case("proof_replay", [], [])
    assert result["validity"] == "NOT_EXERCISED"
    assert result["assertion_result"] == "NOT_EVALUATED"


def test_never_resume_is_valid_and_fails_normal_control():
    from guardian_core.bound_recovery import BoundRecoveryDecision, EvidenceBoundRecovery
    from guardian_core.recovery_protocol import RecoveryConfig
    from experiments.recovery_scenarios import Action, execute_scenario

    class NeverResume(EvidenceBoundRecovery):
        def update(self, **kwargs):
            return BoundRecoveryDecision("SAFE_STOP", False, 0., "test-only stalled controller")

    events = []
    frames = execute_scenario([Action("healthy", .5)], witnesses=events,
        gate_factory=lambda: NeverResume(RecoveryConfig(dwell_sec=.2, stable_window_sec=.1)))
    result = catalog_module().validate_case("healthy_resume", [f.to_dict() for f in frames], events)
    assert result["validity"] == "VALID"
    assert result["assertion_result"] == "FAIL"
    assert {f["code"] for f in result["assertion_failures"]} >= {
        "missing_candidate", "missing_proof_consumption", "missing_motion"}


def test_accepting_actually_replayed_proof_remains_valid_and_fails():
    from experiments.recovery_scenarios import Action, execute_scenario
    from experiments.recovery_mutations import make_gate
    events = []
    frames = execute_scenario([Action("healthy", .35), Action("replay_proof", .05), Action("healthy", .6)],
        gate_factory=lambda: make_gate("accept_proof_replay"), witnesses=events)
    result = catalog_module().validate_case("proof_replay", [f.to_dict() for f in frames], events)
    assert result["validity"] == "VALID"
    assert result["assertion_result"] == "FAIL"
    assert any(f["code"] == "replayed_proof_accepted" for f in result["assertion_failures"])
    replay = next(e for e in events if e["kind"] == "proof_replay")
    assert replay["previously_consumed"] and replay["allowed"]


def test_healthy_control_must_observe_motion_after_permission():
    catalog = catalog_module()
    original = catalog.run_case("healthy_resume")
    frames = [dict(frame, observed_speed=0.) for frame in original["frames"]]
    result = catalog.validate_case("healthy_resume", frames, original["witnesses"]["events"])
    assert result["validity"] == "VALID"
    assert result["assertion_result"] == "FAIL"
    assert any(f["code"] == "missing_motion" for f in result["assertion_failures"])


def test_wrong_ttl_acceptance_is_valid_and_fails_old_candidate_check():
    from experiments.recovery_scenarios import Action, execute_scenario
    from experiments.recovery_mutations import make_gate
    events = []
    frames = execute_scenario([Action("healthy", .25), Action("gap", .51), Action("wait", .5)],
        gate_factory=lambda: make_gate("no_proof_ttl"), witnesses=events)
    result = catalog_module().validate_case("ttl_gap", [f.to_dict() for f in frames], events)
    assert result["validity"] == "VALID"
    assert result["assertion_result"] == "FAIL"
    assert any(f["code"] == "old_candidate_consumed" for f in result["assertion_failures"])


def test_execution_interface_rejects_unknown_ids_and_code_parameters():
    runner = runner_module()
    with pytest.raises(ValueError):
        runner.run_registered_test("../worker")
    for name in ("source", "module", "path", "variant", "hook", "gate_factory"):
        with pytest.raises(TypeError):
            runner.run_registered_test("healthy_resume", **{name: "untrusted"})
    assert tuple(inspect.signature(runner.run_registered_test).parameters) == (
        "test_id", "timeout_sec", "cancel")


@pytest.mark.skipif(sys.platform != "linux" or importlib.util.find_spec("pyseccomp") is None,
    reason="optional worker requires Linux and pyseccomp")
@pytest.mark.parametrize("test_id", IDS)
def test_real_subprocess_has_frames_network_denial_and_clean_environment(test_id, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "agent-review-test-canary")
    monkeypatch.setenv("DASHBOARD_SESSION_SECRET", "agent-review-test-canary")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "agent-review-test-canary")
    result = runner_module().run_registered_test(test_id)
    assert result["status"] == "COMPLETE", result
    assert result["validity"] == "VALID"
    assert result["assertion_result"] == "PASS"
    assert result["frames"]
    assert result["isolation"]["network_denied"] is True
    assert result["isolation"]["socket_errno"] in (1, 13)
    assert result["isolation"]["credentials_absent"] is True
    assert result["isolation"]["cwd_is_temporary"] is True
    assert result["isolation"]["limits_applied"] is True
    assert result["source_manifest"]
    assert result["worker_pid"] != os.getpid()


@pytest.mark.skipif(sys.platform != "linux", reason="process-group lifecycle uses Linux")
def test_real_runner_deadline_and_preexisting_cancellation():
    runner = runner_module()
    started = time.monotonic()
    result = runner.run_registered_test("healthy_resume", timeout_sec=.000001)
    assert result["status"] == "TIMEOUT"
    assert time.monotonic() - started < 1.
    cancelled = threading.Event()
    cancelled.set()
    assert runner.run_registered_test("healthy_resume", cancel=cancelled)["status"] == "CANCELLED"


def _test_process(source):
    return subprocess.Popen([sys.executable, "-I", "-c", source], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)


@pytest.mark.skipif(sys.platform != "linux", reason="process-group lifecycle uses Linux")
def test_bounded_reader_terminates_real_excessive_output_and_reaps_process():
    proc = _test_process("import os\nwhile True: os.write(1, b'x' * 65536)")
    result = runner_module()._collect_process(proc, timeout_sec=2., cancel=None)
    assert result["status"] == "OUTPUT_LIMIT"
    assert len(result["stdout"]) <= 2 * 1024 * 1024
    assert proc.poll() is not None
    with pytest.raises(ProcessLookupError):
        os.kill(proc.pid, 0)


@pytest.mark.skipif(sys.platform != "linux", reason="process-group lifecycle uses Linux")
def test_cancellation_kills_running_process_group():
    proc = _test_process("import time\ntime.sleep(10)")
    cancelled = threading.Event()
    timer = threading.Timer(.05, cancelled.set)
    timer.start()
    try:
        result = runner_module()._collect_process(proc, timeout_sec=2., cancel=cancelled)
    finally:
        timer.cancel()
    assert result["status"] == "CANCELLED"
    assert proc.poll() is not None


def test_invalid_timeout_is_rejected():
    for value in (True, 0, -1, float("nan"), 2.1):
        with pytest.raises(ValueError):
            runner_module().run_registered_test("healthy_resume", timeout_sec=value)


@pytest.mark.skipif(sys.platform != "linux", reason="worker requires Linux seccomp")
def test_missing_seccomp_dependency_fails_closed_in_real_worker(tmp_path, monkeypatch):
    runner = runner_module()
    empty_env = tmp_path / "without-seccomp"
    venv.EnvBuilder(with_pip=False).create(empty_env)
    monkeypatch.setattr(runner.sys, "executable", str(empty_env / "bin/python"))
    result = runner.run_registered_test("healthy_resume")
    assert result["status"] == "UNAVAILABLE"
    assert result["frames"] == []
    assert result["assertion_result"] == "NOT_EVALUATED"
    assert result["isolation"]["mode"] == "unavailable"


@pytest.mark.skipif(sys.platform != "linux" or importlib.util.find_spec("pyseccomp") is None,
    reason="optional worker requires Linux and pyseccomp")
@pytest.mark.parametrize("removed", (False, True))
def test_real_source_byte_change_before_result_acceptance_is_stale(tmp_path, monkeypatch, removed):
    runner = runner_module()
    copy_root = tmp_path / "review-copy"
    for relative in runner._SOURCES:
        destination = copy_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(runner.ROOT / relative, destination)
    original_collector = runner._collect_process

    def collect_then_change_source(proc, **kwargs):
        collected = original_collector(proc, **kwargs)
        assert collected["returncode"] == 0
        changed = copy_root / "experiments/agent_review/catalog.py"
        if removed:
            changed.unlink()
        else:
            changed.write_bytes(changed.read_bytes() + b"\n# test-only drift\n")
        return collected

    monkeypatch.setattr(runner, "ROOT", copy_root)
    monkeypatch.setattr(runner, "_collect_process", collect_then_change_source)
    result = runner.run_registered_test("healthy_resume")
    assert result["status"] == "STALE_CONTEXT"
    assert result["frames"] == []
