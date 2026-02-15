"""Model lineage tracking.

Provides ``LineageNode`` and ``ModelLineage`` for representing
the derivation chain of a model (e.g. base → fine-tuned → quantized).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class LineageNode:
    """A single node in a model lineage chain.

    Attributes:
        model_id: Identifier for this model.
        relation: Relationship to parent (e.g. ``"fine_tuned"``).
            Empty string for root nodes.
        parent_id: Identifier of the parent model.
            Empty string for root nodes.
        metadata: Optional extra metadata for this node.
    """

    model_id: str
    relation: str = ""
    parent_id: str = ""
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict, omitting empty fields."""
        result: dict[str, Any] = {"model_id": self.model_id}
        if self.relation:
            result["relation"] = self.relation
        if self.parent_id:
            result["parent_id"] = self.parent_id
        if self.metadata:
            result["metadata"] = dict(self.metadata)
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LineageNode:
        """Construct from a dict."""
        return cls(
            model_id=str(data["model_id"]),
            relation=str(data.get("relation", "")),
            parent_id=str(data.get("parent_id", "")),
            metadata=dict(data.get("metadata", {})),
        )


class ModelLineage:
    """Ordered chain of lineage nodes (root-first).

    Represents the derivation history of a model, from the
    original base model to the current derived version.
    """

    def __init__(self) -> None:
        self._nodes: list[LineageNode] = []

    @property
    def nodes(self) -> list[LineageNode]:
        """Return a copy of the lineage nodes."""
        return list(self._nodes)

    @property
    def depth(self) -> int:
        """Return the number of nodes in the chain."""
        return len(self._nodes)

    @property
    def root(self) -> LineageNode | None:
        """Return the root node, or None if empty."""
        return self._nodes[0] if self._nodes else None

    @property
    def leaf(self) -> LineageNode | None:
        """Return the most-derived node, or None if empty."""
        return self._nodes[-1] if self._nodes else None

    def add(self, node: LineageNode) -> None:
        """Append a node to the lineage chain."""
        self._nodes.append(node)

    def ancestors(self, model_id: str) -> list[LineageNode]:
        """Return all ancestors of *model_id* (not including itself).

        Walks backward from the node matching *model_id* to the root.

        Args:
            model_id: The model to find ancestors for.

        Returns:
            List of ancestor nodes (root-first), or empty if not found.
        """
        idx = None
        for i, node in enumerate(self._nodes):
            if node.model_id == model_id:
                idx = i
                break
        if idx is None or idx == 0:
            return []
        return list(self._nodes[:idx])

    @classmethod
    def from_provenance(cls, provenance: object) -> ModelLineage:
        """Build a lineage chain from a provenance object.

        Creates a 1-node chain if only ``model_id`` is present, or
        a 2-node chain if ``base_model`` is also set.

        Args:
            provenance: Object with ``model_id``, ``base_model``, and
                optionally ``model_type`` attributes.

        Returns:
            New ``ModelLineage`` with 1-2 nodes.
        """
        lineage = cls()

        model_id: str = getattr(provenance, "model_id", "")
        base_model: str = getattr(provenance, "base_model", "")
        model_type: str = getattr(provenance, "model_type", "")

        if base_model and base_model != model_id:
            lineage.add(LineageNode(model_id=base_model))
            relation = model_type if model_type else "fine_tuned"
            lineage.add(
                LineageNode(
                    model_id=model_id,
                    relation=relation,
                    parent_id=base_model,
                )
            )
        else:
            lineage.add(LineageNode(model_id=model_id))

        return lineage

    def to_dict(self) -> list[dict[str, Any]]:
        """Serialize the lineage chain to a list of dicts."""
        return [node.to_dict() for node in self._nodes]

    @classmethod
    def from_dict(cls, data: list[dict[str, Any]]) -> ModelLineage:
        """Construct from a list of dicts."""
        lineage = cls()
        for item in data:
            lineage.add(LineageNode.from_dict(item))
        return lineage

    def to_agentfacts_extension(
        self,
        key: str = "x_model_lineage",
    ) -> dict[str, list[dict[str, Any]]]:
        """Produce a NANDA AgentFacts extension block.

        Args:
            key: Extension key name.

        Returns:
            Dict suitable for merging into AgentFacts metadata.
        """
        return {key: self.to_dict()}
