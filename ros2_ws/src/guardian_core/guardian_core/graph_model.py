"""Small, deterministic ROS 2 dependency graph and risk propagation model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping


def _bounded(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


@dataclass(frozen=True)
class GraphNode:
    name: str
    kind: str
    criticality: float = 0.0

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("graph node name cannot be empty")
        if not 0.0 <= self.criticality <= 1.0:
            raise ValueError("graph node criticality must be in [0, 1]")


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    weight: float = 1.0

    def __post_init__(self) -> None:
        if not self.source or not self.target:
            raise ValueError("graph edge endpoints cannot be empty")
        if not 0.0 <= self.weight <= 1.0:
            raise ValueError("graph edge weight must be in [0, 1]")


@dataclass(frozen=True)
class GraphRiskAssessment:
    risk_by_node: Mapping[str, float]
    affected_nodes: frozenset[str]
    critical_nodes: frozenset[str]

    @property
    def max_risk(self) -> float:
        return max(self.risk_by_node.values(), default=0.0)

    @property
    def blast_radius(self) -> float:
        if not self.risk_by_node:
            return 0.0
        return len(self.affected_nodes) / len(self.risk_by_node)


class SecurityGraph:
    """Propagate a bounded risk score through a directed ROS 2 data path."""

    def __init__(self, nodes: Iterable[GraphNode] = (), edges: Iterable[GraphEdge] = ()) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []
        for node in nodes:
            self.add_node(node)
        for edge in edges:
            self.add_edge(edge)

    def add_node(self, node: GraphNode) -> None:
        self._nodes[node.name] = node

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.source not in self._nodes or edge.target not in self._nodes:
            raise ValueError("graph edges require registered source and target nodes")
        self._edges.append(edge)

    @property
    def nodes(self) -> tuple[GraphNode, ...]:
        return tuple(self._nodes.values())

    @property
    def edges(self) -> tuple[GraphEdge, ...]:
        return tuple(self._edges)

    def propagate(self, base_risk: Mapping[str, float]) -> GraphRiskAssessment:
        risk = {name: _bounded(base_risk.get(name, 0.0)) for name in self._nodes}
        # A bounded fixed-point pass handles chains and cycles without allowing
        # risk to grow beyond one. The graph is intentionally small and local.
        for _ in range(max(1, len(self._nodes))):
            changed = False
            for edge in self._edges:
                propagated = _bounded(risk[edge.source] * edge.weight)
                if propagated > risk[edge.target]:
                    risk[edge.target] = propagated
                    changed = True
            if not changed:
                break
        affected = frozenset(name for name, value in risk.items() if value > 0.0)
        critical = frozenset(
            name for name in affected if self._nodes[name].criticality >= 0.8
        )
        return GraphRiskAssessment(risk, affected, critical)
