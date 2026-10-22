"""Offline semantic feedback and independent safety oracles for recovery traces.

Inspired by BTreeFuzz's task-state feedback, not a reproduction of its graph
similarity algorithm. Raw context values remain intact for the safety oracle.
"""
from dataclasses import asdict, dataclass, fields
import math


@dataclass(frozen=True)
class RecoveryFrame:
    now: float
    task_phase: str
    recovery_phase: str
    evidence_state: str
    stopped_ack: bool
    unresolved: bool
    forced_stop: bool
    graph_fingerprint: str
    policy_fingerprint: str
    ledger_anchor: str
    command_epoch: int
    next_command_epoch: int
    mission_allowed: bool
    speed_limit: float
    observed_speed: float = 0.0
    pending_proof: dict | None = None
    consumed_proof_id: str = ""

    def __post_init__(self):
        for name in ("stopped_ack", "unresolved", "forced_stop", "mission_allowed"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be boolean")
        for name in ("now", "speed_limit", "observed_speed"):
            if type(getattr(self, name)) not in (int, float):
                raise ValueError(f"{name} must be numeric")
        for name in ("command_epoch", "next_command_epoch"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        for name in ("task_phase", "recovery_phase", "evidence_state", "graph_fingerprint",
                     "policy_fingerprint", "ledger_anchor", "consumed_proof_id"):
            if not isinstance(getattr(self, name), str):
                raise ValueError(f"{name} must be a string")
        if self.pending_proof is not None:
            proof = self.pending_proof
            if not isinstance(proof, dict) or set(proof) != {
                    "proof_id", "graph_fingerprint", "policy_fingerprint", "ledger_anchor",
                    "command_epoch", "issued_at", "expires_at"}:
                raise ValueError("invalid proof summary schema")
            if any(not isinstance(proof[k], str) or not proof[k] for k in
                   ("proof_id", "graph_fingerprint", "policy_fingerprint", "ledger_anchor")):
                raise ValueError("proof identifiers must be nonempty strings")
            if type(proof["command_epoch"]) is not int or proof["command_epoch"] < 0:
                raise ValueError("proof epoch must be a non-negative integer")
            if any(type(proof[k]) not in (int, float) or not math.isfinite(proof[k])
                   for k in ("issued_at", "expires_at")):
                raise ValueError("proof times must be finite numbers")

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, value):
        # Constructor defaults support internal callers, not missing evidence in
        # imported logs. Absence must never become a zero-speed observation.
        if not isinstance(value, dict) or set(value) != {field.name for field in fields(cls)}:
            raise ValueError("recovery frame must contain the complete schema")
        return cls(**value)


def proof_summary(proof):
    """Only public binding fields; never log signing secrets or signatures."""
    if proof is None:
        return None
    return {name: getattr(proof, name) for name in (
        "proof_id", "graph_fingerprint", "policy_fingerprint", "ledger_anchor",
        "command_epoch", "issued_at", "expires_at")}


def evidence_state(telemetry, now, max_age):
    if telemetry is None:
        return "missing"
    if not all(type(x) in (int, float) and math.isfinite(x) for x in
               (telemetry.received_at, telemetry.speed, telemetry.free_distance)):
        return "invalid"
    if not 0 <= now - telemetry.received_at <= max_age:
        return "stale"
    if telemetry.attack_active:
        return "attack"
    if not telemetry.commands_cleared:
        return "commands_pending"
    if not telemetry.probe_success:
        return "probe_failed"
    return "healthy" if telemetry.healthy(now, max_age) else "invalid"


class SemanticCoverage:
    """Exact normalized state/edge novelty; heartbeat self-loops are ignored.

    Context identifiers and absolute epochs are replaced by relations to the
    preceding frame. Each trace has its own beginning, so replay is comparable.
    """
    def __init__(self, max_states=10000, max_edges=50000):
        self.states, self.edges = set(), set()
        self.max_states, self.max_edges = max_states, max_edges

    @staticmethod
    def normalize(frame, previous):
        def relation(field):
            value = getattr(frame, field)
            if not value:
                return "missing"
            if previous is None:
                return "initial"
            return "same" if value == getattr(previous, field) else "changed"
        return (frame.task_phase, frame.recovery_phase, frame.evidence_state,
            frame.stopped_ack, frame.unresolved, frame.forced_stop, frame.mission_allowed,
            relation("graph_fingerprint"), relation("policy_fingerprint"),
            relation("ledger_anchor"), relation("command_epoch"),
            bool(frame.pending_proof), bool(frame.consumed_proof_id),
            "same" if frame.next_command_epoch == frame.command_epoch else
                "next" if frame.next_command_epoch == frame.command_epoch + 1 else "other",
            "none" if not frame.pending_proof else "match" if (
                frame.pending_proof["graph_fingerprint"], frame.pending_proof["policy_fingerprint"],
                frame.pending_proof["ledger_anchor"], frame.pending_proof["command_epoch"]) == (
                frame.graph_fingerprint, frame.policy_fingerprint, frame.ledger_anchor,
                frame.command_epoch + 1) else "mismatch")

    def observe_trace(self, frames):
        states, edges = set(), set()
        previous_frame = previous_state = None
        for frame in frames:
            state = self.normalize(frame, previous_frame)
            # Initial relations are represented only at trace entry. Repeated
            # identical raw frames must not create a heartbeat transition.
            if previous_frame is not None and replace_time(frame) == replace_time(previous_frame):
                previous_frame = frame
                continue
            states.add(state)
            if previous_state is not None and state != previous_state:
                edges.add((previous_state, state))
            previous_frame, previous_state = frame, state
        new_states, new_edges = states - self.states, edges - self.edges
        if len(self.states | states) > self.max_states or len(self.edges | edges) > self.max_edges:
            raise ValueError("semantic coverage capacity exhausted")
        self.states.update(states)
        self.edges.update(edges)
        return bool(new_states or new_edges)

    def summary(self):
        return {"states": len(self.states), "transitions": len(self.edges)}


def replace_time(frame):
    value = frame.to_dict()
    value.pop("now")
    return value


@dataclass(frozen=True)
class SafetyViolation:
    code: str
    frame_index: int
    detail: str


class SafetyOracle:
    """Check authorization separately from coverage; novelty is never a bug.

    Liveness applies only to eligible stop windows sampled no farther apart
    than max_frame_gap_sec. Sparse samples cannot prove continuous control
    opportunities. Gap resets affect only liveness, never authorization checks.
    This excludes watchdog/planner forced stops and is not physical safety proof.
    """
    def __init__(self, liveness_sec=3.0, max_frame_gap_sec=.25):
        if (type(max_frame_gap_sec) not in (int, float) or not math.isfinite(max_frame_gap_sec)
                or max_frame_gap_sec <= 0):
            raise ValueError("max_frame_gap_sec must be positive and finite")
        self.liveness_sec = liveness_sec
        self.max_frame_gap_sec = max_frame_gap_sec

    def check_trace(self, frames):
        violations, issued, used = [], {}, set()
        authorized = None
        eligible_since = eligible_context = previous_time = None
        for index, frame in enumerate(frames):
            def fail(code, detail):
                violations.append(SafetyViolation(code, index, detail))
            context = (frame.graph_fingerprint, frame.policy_fingerprint, frame.ledger_anchor)
            # Production SAFE_STOP revokes the pending permit. Historical
            # issuance is not authorization to revive a revoked proof.
            if not frame.mission_allowed and frame.recovery_phase != "RECOVERY_CANDIDATE":
                issued.clear()
            healthy = (frame.evidence_state == "healthy" and not frame.unresolved
                and not frame.forced_stop and all(context))
            if not math.isfinite(frame.now) or (previous_time is not None and frame.now < previous_time):
                fail("invalid_clock", "trace time must be finite and monotonic")
            if previous_time is not None and frame.now - previous_time > self.max_frame_gap_sec:
                eligible_since = eligible_context = None
            previous_time = frame.now
            if (not math.isfinite(frame.speed_limit) or frame.speed_limit < 0
                    or (not frame.mission_allowed and frame.speed_limit != 0)):
                fail("invalid_speed_limit", "invalid published speed limit")
            if frame.mission_allowed and (not healthy or not math.isfinite(frame.observed_speed)
                                         or frame.observed_speed < 0):
                fail("unsafe_motion", "motion allowed without healthy evidence and context")
            if frame.pending_proof:
                if (not healthy or not frame.stopped_ack or not math.isfinite(frame.observed_speed)
                        or not 0 <= frame.observed_speed <= 1e-6
                        or frame.recovery_phase != "RECOVERY_CANDIDATE" or frame.mission_allowed):
                    fail("unsafe_candidate", "proof issued without eligible zero-speed ACK")
                proof = frame.pending_proof
                if (proof["graph_fingerprint"], proof["policy_fingerprint"], proof["ledger_anchor"],
                        proof["command_epoch"]) != (*context, frame.command_epoch + 1):
                    fail("candidate_binding_mismatch", "candidate differs from issuance context")
            if frame.recovery_phase == "RESUMABLE" and frame.mission_allowed:
                identifier = frame.consumed_proof_id
                proof = issued.get(identifier)
                if identifier in used:
                    fail("proof_reuse", "one-shot proof consumed again")
                if proof is None:
                    fail("missing_proof", "resume has no previously issued proof")
                else:
                    if (not frame.stopped_ack or not math.isfinite(frame.observed_speed)
                            or not 0 <= frame.observed_speed <= 1e-6):
                        fail("unsafe_resume", "resume requires matching zero-speed stop ACK")
                    if not proof["issued_at"] < frame.now < proof["expires_at"]:
                        fail("expired_proof", "resume outside proof lifetime")
                    expected = (proof["graph_fingerprint"], proof["policy_fingerprint"],
                        proof["ledger_anchor"], proof["command_epoch"])
                    if ((*context, frame.next_command_epoch) != expected
                            or frame.next_command_epoch != frame.command_epoch + 1):
                        fail("context_mismatch", "resume differs from exact proof binding")
                    authorized = (*expected, identifier)
                used.add(identifier)
            elif frame.mission_allowed:
                if (frame.recovery_phase != "NORMAL" or authorized !=
                        (*context, frame.command_epoch, frame.consumed_proof_id)
                        or frame.next_command_epoch != frame.command_epoch):
                    fail("unauthorized_continuation", "motion output is not linked to authorized context")
            else:
                authorized = None
            if frame.pending_proof and frame.recovery_phase == "RECOVERY_CANDIDATE":
                if frame.pending_proof["issued_at"] != frame.now:
                    fail("invalid_issuance_time", "candidate timestamp differs from proof issuance")
                issued = {frame.pending_proof["proof_id"]: frame.pending_proof}
            eligible = healthy and frame.stopped_ack and frame.observed_speed <= 1e-6
            stop_context = (*context, frame.command_epoch)
            if not eligible or frame.mission_allowed:
                eligible_since = eligible_context = None
            elif eligible_context != stop_context:
                eligible_since, eligible_context = frame.now, stop_context
            elif frame.now - eligible_since > self.liveness_sec:
                fail("recovery_stalled", "eligible recovery did not resume in bounded window")
        return violations
