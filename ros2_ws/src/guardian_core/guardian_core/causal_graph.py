"""Deterministic, provenance-carrying risk propagation over a ROS 2 data path."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Mapping


def _finite(value: float, name: str) -> float:
    value = float(value)
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    return value


def _bounded(value: float, name: str) -> float:
    value = _finite(value, name)
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be in [0, 1]")
    return value


@dataclass(frozen=True)
class CausalNode:
    name: str
    kind: str
    trust_domain: str
    criticality: float = 0.0

    def __post_init__(self) -> None:
        if not self.name or not self.kind or not self.trust_domain:
            raise ValueError("causal node fields cannot be empty")
        _bounded(self.criticality, "criticality")


@dataclass(frozen=True)
class CausalEdge:
    source: str
    target: str
    weight: float
    relation: str

    def __post_init__(self) -> None:
        if not self.source or not self.target or not self.relation:
            raise ValueError("causal edge fields cannot be empty")
        _bounded(self.weight, "edge weight")

    @property
    def key(self) -> str:
        return f"{self.source}->{self.target}"


@dataclass(frozen=True)
class GraphSnapshot:
    nodes: tuple[CausalNode, ...]
    edges: tuple[CausalEdge, ...]
    observed_at: float

    def __post_init__(self) -> None:
        _finite(self.observed_at, "observed_at")
        names = [node.name for node in self.nodes]
        if len(names) != len(set(names)):
            raise ValueError("causal node names must be unique")
        known = set(names)
        for edge in self.edges:
            if edge.source not in known or edge.target not in known:
                raise ValueError("causal edge endpoints require registered nodes")
        edge_keys = [edge.key for edge in self.edges]
        if len(edge_keys) != len(set(edge_keys)):
            raise ValueError("duplicate causal edge")

    @property
    def fingerprint(self) -> str:
        payload = {
            "nodes": [
                {
                    "criticality": node.criticality,
                    "kind": node.kind,
                    "name": node.name,
                    "trust_domain": node.trust_domain,
                }
                for node in sorted(self.nodes, key=lambda item: item.name)
            ],
            "edges": [
                {
                    "relation": edge.relation,
                    "source": edge.source,
                    "target": edge.target,
                    "weight": edge.weight,
                }
                for edge in sorted(self.edges, key=lambda item: (item.source, item.target, item.relation))
            ],
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class RiskTrace:
    risk_by_node: Mapping[str, float]
    paths_by_node: Mapping[str, tuple[str, ...]]
    critical_nodes: frozenset[str]
    traversed_edges: tuple[str, ...]
    cross_domain_edges: tuple[str, ...]
    snapshot_fingerprint: str


@dataclass(frozen=True)
class GraphChange:
    changed_nodes: tuple[str, ...]
    changed_edges: tuple[str, ...]
    before_fingerprint: str
    after_fingerprint: str

    @property
    def changed(self) -> bool:
        return bool(self.changed_nodes or self.changed_edges)


def trace_risk(
    snapshot: GraphSnapshot,
    seeds: Mapping[str, float],
    *,
    now: float,
    max_age_sec: float,
) -> RiskTrace:
    now = _finite(now, "now")
    max_age_sec = _finite(max_age_sec, "max_age_sec")
    if max_age_sec < 0:
        raise ValueError("max_age_sec must be non-negative")
    age = now - snapshot.observed_at
    if age < 0 or age > max_age_sec:
        raise ValueError("graph snapshot is stale")
    nodes = {node.name: node for node in snapshot.nodes}
    for name, value in seeds.items():
        if name not in nodes:
            raise ValueError(f"unknown seed: {name}")
        _bounded(value, f"seed {name}")

    risk = {name: _bounded(seeds.get(name, 0.0), f"risk {name}") for name in nodes}
    paths = {name: ((name,) if risk[name] > 0 else ()) for name in nodes}
    edges = tuple(sorted(snapshot.edges, key=lambda item: (item.source, item.target, item.relation)))
    for _ in range(max(1, len(nodes))):
        changed = False
        for edge in edges:
            candidate = risk[edge.source] * edge.weight
            candidate_path = paths[edge.source] + (edge.target,) if paths[edge.source] else ()
            if candidate > risk[edge.target] + 1e-12 or (
                candidate > 0 and abs(candidate - risk[edge.target]) <= 1e-12
                and candidate_path and (not paths[edge.target] or candidate_path < paths[edge.target])
            ):
                risk[edge.target] = candidate
                paths[edge.target] = candidate_path
                changed = True
        if not changed:
            break
    affected = {name for name, value in risk.items() if value > 0.0}
    critical = frozenset(
        name for name in affected if nodes[name].criticality >= 0.8
    )
    traversed = tuple(
        f"{path[index]}->{path[index + 1]}"
        for path in paths.values()
        for index in range(len(path) - 1)
    )
    by_name = {node.name: node for node in snapshot.nodes}
    cross_domain = tuple(sorted(
        edge.key for edge in edges
        if edge.key in traversed
        and by_name[edge.source].trust_domain != by_name[edge.target].trust_domain
    ))
    return RiskTrace(
        risk_by_node=risk,
        paths_by_node=paths,
        critical_nodes=critical,
        traversed_edges=tuple(sorted(set(traversed))),
        cross_domain_edges=cross_domain,
        snapshot_fingerprint=snapshot.fingerprint,
    )


def compare_graphs(before: GraphSnapshot, after: GraphSnapshot) -> GraphChange:
    before_nodes = {node.name: node for node in before.nodes}
    after_nodes = {node.name: node for node in after.nodes}
    changed_nodes = tuple(sorted(
        name for name in set(before_nodes) | set(after_nodes)
        if before_nodes.get(name) != after_nodes.get(name)
    ))
    before_edges = {edge.key: edge for edge in before.edges}
    after_edges = {edge.key: edge for edge in after.edges}
    changed_edges = tuple(sorted(
        key for key in set(before_edges) | set(after_edges)
        if before_edges.get(key) != after_edges.get(key)
    ))
    return GraphChange(
        changed_nodes=changed_nodes,
        changed_edges=changed_edges,
        before_fingerprint=before.fingerprint,
        after_fingerprint=after.fingerprint,
    )


__all__ = [
    "CausalEdge", "CausalNode", "GraphChange", "GraphSnapshot", "RiskTrace",
    "compare_graphs", "trace_risk",
]
