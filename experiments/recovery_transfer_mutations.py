"""Independent post-freeze safety-contract mutations; offline classes only."""
import ast
from functools import lru_cache
import inspect

from guardian_core import bound_recovery
from guardian_core.recovery_protocol import RecoveryConfig
from recovery_scenarios import Action, execute_scenario

FAMILIES = ("no_motion_envelope", "nonzero_safe_stop_limit")
EXPECTED_CODES = {"no_motion_envelope": {"unsafe_candidate", "unsafe_motion"},
    "nonzero_safe_stop_limit": {"invalid_speed_limit"}}


class TransferMutation(ast.NodeTransformer):
    def __init__(self, family):
        self.family, self.matched = family, 0

    def visit_If(self, node):
        expected = ast.parse("if not motion.mission_allowed:\n return self._stop(motion.reason)").body[0]
        if self.family == "no_motion_envelope" and ast.dump(node) == ast.dump(expected):
            self.matched += 1
            return None
        return self.generic_visit(node)

    def visit_Call(self, node):
        expected = ast.parse('BoundRecoveryDecision("SAFE_STOP", False, 0.0, reason)', mode="eval").body
        if self.family == "nonzero_safe_stop_limit" and ast.dump(node) == ast.dump(expected):
            self.matched += 1
            node.args[2] = ast.Constant(.2)
        return self.generic_visit(node)


def mutate_gate(source, family):
    if family not in FAMILIES:
        raise ValueError("unknown transfer defect family")
    transformer = TransferMutation(family)
    tree = transformer.visit(ast.parse(source))
    if transformer.matched != 1:
        raise ValueError(f"transfer mutation site mismatch: {family}, expected 1, got {transformer.matched}")
    return ast.fix_missing_locations(tree)


@lru_cache(maxsize=2)
def gate_class(family):
    namespace = dict(vars(bound_recovery))
    tree = mutate_gate(inspect.getsource(bound_recovery.EvidenceBoundRecovery), family)
    exec(compile(tree, "<offline-transfer-mutation>", "exec"), namespace)
    return namespace["EvidenceBoundRecovery"]


def execute_transfer(actions, family):
    return execute_scenario(actions, gate_factory=lambda: gate_class(family)(
        RecoveryConfig(dwell_sec=.2, stable_window_sec=.1, proof_ttl_sec=.5)))


def challenge_scenarios():
    return {"no_motion_envelope": [Action("near_obstacle", .3)],
        "nonzero_safe_stop_limit": [Action("graph_missing", .01)]}
