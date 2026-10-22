"""Predefined offline defects in repository-owned code; never change ROS classes.

AST mutations retain the real implementation and cryptographic checks. No
source supplied by a CLI/user is evaluated. Expected mutation-site counts
protect against silently changing a different branch after source evolution.
"""
import ast
from functools import lru_cache
import hashlib
import inspect

from guardian_core import bound_recovery, recovery_protocol
from guardian_core.recovery_protocol import RecoveryConfig

VARIANTS = ("no_proof_ttl", "no_context_binding", "accept_proof_replay", "no_independent_observation")
DISABLED_CHECKS = {
    "no_proof_ttl": ["authorize_command proof time interval"],
    "no_context_binding": ["observe context stability", "latest candidate context binding",
        "consume observation context binding", "running context binding"],
    "accept_proof_replay": ["used-proof branch returns allowed instead of rejecting"],
    "no_independent_observation": ["offline controller receives adapter telemetry instead of fused telemetry"],
}


class RemoveChecks(ast.NodeTransformer):
    def __init__(self, reasons, *, replay=False):
        self.reasons, self.replay, self.matched = set(reasons), replay, 0

    def visit_If(self, node):
        # Match only direct return statements, never enclosing control blocks.
        strings = {argument.value for statement in node.body if isinstance(statement, ast.Return)
            and isinstance(statement.value, ast.Call) for argument in statement.value.args
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str)}
        if self.reasons & strings:
            self.matched += 1
            if self.replay:
                node.body = ast.parse('return RecoveryDecision("RESUMABLE", True, "offline replay defect")').body
                return node
            return None
        return self.generic_visit(node)


def mutate_protocol(source, variant):
    tree = ast.parse(source)
    reasons = {
        "no_proof_ttl": ("recovery proof expired",),
        "no_context_binding": ("recovery context changed", "latest recovery context changed"),
        "accept_proof_replay": ("recovery proof replayed",),
    }
    if variant not in reasons:
        raise ValueError("unsupported protocol variant")
    transformer = RemoveChecks(reasons[variant], replay=variant == "accept_proof_replay")
    tree = transformer.visit(tree)
    expected = 3 if variant == "no_context_binding" else 1
    if transformer.matched != expected:
        raise ValueError(f"mutation site mismatch: {variant} expected {expected}, got {transformer.matched}")
    return ast.fix_missing_locations(tree)


@lru_cache(maxsize=8)
def gate_class(variant):
    if variant in ("full", "no_independent_observation"):
        return bound_recovery.EvidenceBoundRecovery
    if variant not in VARIANTS:
        raise ValueError("unknown recovery variant")
    protocol_namespace = dict(vars(recovery_protocol))
    protocol_tree = mutate_protocol(inspect.getsource(recovery_protocol.RecoveryProtocol), variant)
    exec(compile(protocol_tree, "<offline-recovery-protocol-mutation>", "exec"), protocol_namespace)
    gate_namespace = dict(vars(bound_recovery))
    gate_namespace["RecoveryProtocol"] = protocol_namespace["RecoveryProtocol"]
    gate_tree = ast.parse(inspect.getsource(bound_recovery.EvidenceBoundRecovery))
    if variant == "no_context_binding":
        transformer = RemoveChecks(("authorized recovery context changed",))
        gate_tree = transformer.visit(gate_tree)
        if transformer.matched != 1:
            raise ValueError("coordinator mutation site mismatch")
    exec(compile(ast.fix_missing_locations(gate_tree), "<offline-bound-recovery-mutation>", "exec"), gate_namespace)
    return gate_namespace["EvidenceBoundRecovery"]


def make_gate(variant):
    return gate_class(variant)(RecoveryConfig(dwell_sec=.2, stable_window_sec=.1, proof_ttl_sec=.5))


def mutation_manifest():
    return {"variants": DISABLED_CHECKS, "sources": {
        "bound_recovery_sha256": hashlib.sha256(inspect.getsource(bound_recovery).encode()).hexdigest(),
        "recovery_protocol_sha256": hashlib.sha256(inspect.getsource(recovery_protocol).encode()).hexdigest()}}


def challenge_scenarios():
    from recovery_scenarios import Action
    return {
        "no_proof_ttl": [Action("healthy", .25), Action("gap", .51), Action("wait", .6)],
        "no_context_binding": [Action("healthy", .25), Action("graph_change", .05), Action("wait", .6)],
        "accept_proof_replay": [Action("healthy", .35), Action("replay_proof", .05), Action("healthy", .6)],
        "no_independent_observation": [Action("healthy", .5), Action("speed_mismatch", .2), Action("healthy", .6)],
    }
