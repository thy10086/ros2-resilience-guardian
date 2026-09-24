"""Research UI evidence must be recomputed by the real local engines."""
from guardian_core.dashboard_research import run_research_suite


def test_research_comparison_reduces_calls_and_preserves_boundaries():
    report = run_research_suite()
    assert report["mode"] == "offline_stub"
    assert report["real_api_calls"] == 0
    assert report["actuation"] == "none"
    cases = {case["id"]: case for case in report["cases"]}
    assert all(case["passed"] for case in cases.values())
    assert cases["duplicates"]["baseline_calls"] == 12
    assert cases["duplicates"]["efficient_calls"] == 1
    assert cases["duplicates"]["routes"] == ["REMOTE"] + ["CACHE"] * 11
    assert cases["low_risk"]["routes"] == ["LOCAL_SAFE"]
    assert cases["unverified"]["routes"] == ["SKIPPED_UNVERIFIED"]
    assert cases["critical"]["routes"] == ["LOCAL_ENFORCED"]
    assert cases["timeout"]["routes"] == ["UNAVAILABLE"]
    assert cases["session"]["efficient_calls"] == 1
    assert cases["session"]["routes"] == ["QUERIED"] + ["SESSION_REUSE"] * 9
    assert cases["expired_parent"]["routes"] == ["LEDGER_BLOCKED"]
    assert cases["expired_parent"]["efficient_calls"] == 0
    assert all(case["passed"] for case in report["protection_cases"])
    assert report["protection_cases"][-1]["state"] == "SAFE_STOP"


def test_research_runs_are_isolated_and_deterministic():
    first = run_research_suite()
    second = run_research_suite()
    assert first == second
