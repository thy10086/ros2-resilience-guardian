from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))
from recovery_mutations import VARIANTS, challenge_scenarios, make_gate, mutation_manifest
from recovery_scenarios import execute_scenario
from guardian_core.bound_recovery import EvidenceBoundRecovery
from guardian_core.recovery_feedback import SafetyOracle


@pytest.mark.parametrize("variant", VARIANTS)
def test_actual_mutant_is_detected_but_paired_full_control_is_safe(variant):
    actions = challenge_scenarios()[variant]
    full = execute_scenario(actions)
    changed = execute_scenario(actions, variant=variant)
    assert not SafetyOracle().check_trace(full)
    assert SafetyOracle().check_trace(changed), variant
    assert any(f.mission_allowed for f in changed)
    repeated = execute_scenario(actions, variant=variant)
    assert [(v.code, v.frame_index) for v in SafetyOracle().check_trace(changed)] == [
        (v.code, v.frame_index) for v in SafetyOracle().check_trace(repeated)]


def test_mutants_cannot_replace_production_class():
    mutant = make_gate("no_context_binding")
    assert type(mutant) is not EvidenceBoundRecovery
    assert type(make_gate("full")) is EvidenceBoundRecovery
    assert len(mutation_manifest()["sources"]["bound_recovery_sha256"]) == 64


def test_mutation_rejects_unknown_variant_and_source_drift():
    with pytest.raises(ValueError):
        make_gate("unknown")
    from recovery_mutations import mutate_protocol
    with pytest.raises(ValueError, match="site"):
        mutate_protocol("class RecoveryProtocol: pass", "no_proof_ttl")
