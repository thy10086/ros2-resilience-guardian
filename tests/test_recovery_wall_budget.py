"""Wall-budget contract: stop at case boundaries without Hypothesis retries."""
from pathlib import Path
import sys
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))
from run_recovery_feedback_fuzzing import replay_corpus, run_campaign


def test_wall_budget_finishes_inflight_case_once_and_replays_corpus(tmp_path):
    calls = []

    def slow_probe(actions, trace, origin, index, elapsed):
        calls.append(index)
        time.sleep(.06)

    report = run_campaign(seed_value=20, budget=10000, mode="boundary",
        corpus_path=tmp_path / "corpus.json", include_seeds=False,
        shrink_failures=False, evaluation_hook=slow_probe, wall_time_sec=.05)
    assert calls == [1]  # No failing-example retry by Hypothesis.
    assert report["generated_executions"] == 1
    assert report["stop_reason"] == "wall_time"
    assert report["search_elapsed_sec"] >= .06
    assert report["deadline_overrun_sec"] >= .01
    replay = replay_corpus(tmp_path / "corpus.json")
    assert replay["coverage"] == report["coverage"]
    assert not report["violations"] and not replay["violations"]


def test_execution_cap_is_distinct_from_time_exhaustion(tmp_path):
    report = run_campaign(seed_value=20, budget=2, mode="unguided",
        corpus_path=tmp_path / "corpus.json", include_seeds=False,
        shrink_failures=False, wall_time_sec=5)
    assert report["generated_executions"] == 2
    assert report["stop_reason"] == "execution_cap"
    assert report["deadline_overrun_sec"] == 0


@pytest.mark.parametrize("limit", [0, -1, True, float("nan"), float("inf"), "5"])
def test_invalid_wall_budget_does_not_write_a_corpus(tmp_path, limit):
    path = tmp_path / "corpus.json"
    with pytest.raises(ValueError):
        run_campaign(seed_value=20, budget=2, mode="unguided", corpus_path=path,
            include_seeds=False, shrink_failures=False, wall_time_sec=limit)
    assert not path.exists()


def test_wall_budget_rejects_warmup_and_shrinking(tmp_path):
    with pytest.raises(ValueError):
        run_campaign(seed_value=20, budget=2, mode="guided",
            corpus_path=tmp_path / "corpus.json", wall_time_sec=1)
