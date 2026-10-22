"""New offline defects; original production classes and search targets stay intact."""
import ast
from functools import lru_cache
import inspect

from guardian_core import bound_recovery
from guardian_core.recovery_protocol import RecoveryConfig
from recovery_scenarios import Action, execute_scenario

FAMILIES = ("ignore_stop_ack", "wrong_next_epoch", "never_resume")
EXPECTED_CODES = {
    "ignore_stop_ack": {"unsafe_candidate", "unsafe_resume"},
    "wrong_next_epoch": {"candidate_binding_mismatch", "context_mismatch"},
    "never_resume": {"recovery_stalled"},
}


class HoldoutMutation(ast.NodeTransformer):
    def __init__(self, family):
        self.family, self.matched = family, 0

    def visit_If(self, node):
        guard = ast.parse("not stopped_ack or telemetry.speed > 1e-6", mode="eval").body
        if self.family == "ignore_stop_ack" and ast.dump(node.test) == ast.dump(guard):
            self.matched += 1
            node.test = node.test.values[1]
        return self.generic_visit(node)

    def visit_Call(self, node):
        if (self.family == "wrong_next_epoch" and isinstance(node.func, ast.Name)
                and node.func.id == "RecoveryObservation" and len(node.args) == 11
                and ast.dump(node.args[9]) == ast.dump(ast.parse("command_epoch + 1", mode="eval").body)):
            self.matched += 1
            node.args[9].right = ast.Constant(2)
        return self.generic_visit(node)

    def visit_Return(self, node):
        call = node.value
        if (self.family == "never_resume" and isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name) and call.func.id == "BoundRecoveryDecision"
                and len(call.args) >= 2 and isinstance(call.args[0], ast.Constant)
                and call.args[0].value == "RESUMABLE"
                and isinstance(call.args[1], ast.Constant) and call.args[1].value is True):
            self.matched += 1
            node.value = ast.parse('self._stop("offline defect: valid recovery rejected")', mode="eval").body
        return self.generic_visit(node)


def mutate_gate(source, family):
    if family not in FAMILIES:
        raise ValueError("unknown holdout defect family")
    transformer = HoldoutMutation(family)
    tree = transformer.visit(ast.parse(source))
    if transformer.matched != 1:
        raise ValueError(f"holdout mutation site mismatch: {family}, expected 1, got {transformer.matched}")
    return ast.fix_missing_locations(tree)


@lru_cache(maxsize=3)
def gate_class(family):
    namespace = dict(vars(bound_recovery))
    tree = mutate_gate(inspect.getsource(bound_recovery.EvidenceBoundRecovery), family)
    exec(compile(tree, "<offline-holdout-mutation>", "exec"), namespace)
    return namespace["EvidenceBoundRecovery"]


def execute_holdout(actions, family):
    return execute_scenario(actions, gate_factory=lambda: gate_class(family)(
        RecoveryConfig(dwell_sec=.2, stable_window_sec=.1, proof_ttl_sec=.5)))


def challenge_scenarios():
    return {
        "ignore_stop_ack": [Action("ack_missing", .6)],
        "wrong_next_epoch": [Action("healthy", .6)],
        "never_resume": [Action("healthy", 1), Action("wait", 1),
            Action("wait", 1), Action("wait", 1)],
    }
