"""Tests for lineage module — model derivation tracking.

# Step 1 — Assumption Audit
# - LineageNode has model_id, optional relation/parent_id/metadata
# - ModelLineage supports add(), depth, root, leaf, ancestors(), to_dict()
# - Empty lineage has depth=0, root=None, leaf=None
# - from_provenance() builds lineage from ModelProvenance (1 or 2 nodes)
# - ancestors() returns empty list for root or unknown nodes

# Step 2 — Gap Analysis
# - Empty lineage test exists but no test for to_dict() on empty lineage
# - No circular lineage detection test (ancestors with circular parent_id)

# Step 3 — Break It List
# - Empty lineage to_dict should return []
# - Circular parent_id chain could infinite loop in ancestors()
"""

from __future__ import annotations

from nanda_integrity import ModelProvenance
from nanda_integrity.lineage import LineageNode, ModelLineage

# -- LineageNode ------------------------------------------------------


class TestLineageNode:
    """LineageNode serialization and construction."""

    def test_minimal_node(self):
        node = LineageNode(model_id="llama-3.1-8b")
        d = node.to_dict()
        assert d == {"model_id": "llama-3.1-8b"}
        assert "relation" not in d
        assert "parent_id" not in d

    def test_full_node(self):
        node = LineageNode(
            model_id="my-adapter",
            relation="fine_tuned",
            parent_id="llama-3.1-8b",
            metadata={"framework": "pytorch"},
        )
        d = node.to_dict()
        assert d == {
            "model_id": "my-adapter",
            "relation": "fine_tuned",
            "parent_id": "llama-3.1-8b",
            "metadata": {"framework": "pytorch"},
        }

    def test_round_trip(self):
        node = LineageNode(
            model_id="test",
            relation="quantized",
            parent_id="base",
        )
        rebuilt = LineageNode.from_dict(node.to_dict())
        assert rebuilt.model_id == node.model_id
        assert rebuilt.relation == node.relation
        assert rebuilt.parent_id == node.parent_id


# -- ModelLineage -----------------------------------------------------


class TestModelLineage:
    """ModelLineage chain operations."""

    def test_empty_lineage(self):
        lineage = ModelLineage()
        assert lineage.depth == 0
        assert lineage.root is None
        assert lineage.leaf is None
        assert lineage.nodes == []

    def test_add_and_depth(self):
        lineage = ModelLineage()
        lineage.add(LineageNode(model_id="base"))
        lineage.add(LineageNode(model_id="child", parent_id="base"))
        assert lineage.depth == 2

    def test_root_and_leaf(self):
        lineage = ModelLineage()
        lineage.add(LineageNode(model_id="root"))
        lineage.add(LineageNode(model_id="leaf", parent_id="root"))
        assert lineage.root is not None
        assert lineage.root.model_id == "root"
        assert lineage.leaf is not None
        assert lineage.leaf.model_id == "leaf"

    def test_ancestors(self):
        lineage = ModelLineage()
        lineage.add(LineageNode(model_id="A"))
        lineage.add(LineageNode(model_id="B", parent_id="A"))
        lineage.add(LineageNode(model_id="C", parent_id="B"))

        ancestors = lineage.ancestors("C")
        assert len(ancestors) == 2
        assert ancestors[0].model_id == "A"
        assert ancestors[1].model_id == "B"

    def test_ancestors_of_root(self):
        lineage = ModelLineage()
        lineage.add(LineageNode(model_id="root"))
        assert lineage.ancestors("root") == []

    def test_ancestors_of_unknown(self):
        lineage = ModelLineage()
        lineage.add(LineageNode(model_id="A"))
        assert lineage.ancestors("unknown") == []

    def test_nodes_returns_copy(self):
        lineage = ModelLineage()
        lineage.add(LineageNode(model_id="A"))
        nodes = lineage.nodes
        nodes.append(LineageNode(model_id="B"))
        assert lineage.depth == 1  # original unmodified

    def test_to_dict(self):
        lineage = ModelLineage()
        lineage.add(LineageNode(model_id="base"))
        lineage.add(
            LineageNode(model_id="child", relation="fine_tuned", parent_id="base")
        )
        d = lineage.to_dict()
        assert len(d) == 2
        assert d[0] == {"model_id": "base"}
        assert d[1]["relation"] == "fine_tuned"

    def test_round_trip(self):
        lineage = ModelLineage()
        lineage.add(LineageNode(model_id="A"))
        lineage.add(LineageNode(model_id="B", relation="adapter", parent_id="A"))
        rebuilt = ModelLineage.from_dict(lineage.to_dict())
        assert rebuilt.depth == 2
        assert rebuilt.root is not None
        assert rebuilt.root.model_id == "A"

    def test_agentfacts_extension(self):
        lineage = ModelLineage()
        lineage.add(LineageNode(model_id="base"))
        ext = lineage.to_agentfacts_extension()
        assert "x_model_lineage" in ext
        assert len(ext["x_model_lineage"]) == 1

    def test_agentfacts_custom_key(self):
        lineage = ModelLineage()
        lineage.add(LineageNode(model_id="test"))
        ext = lineage.to_agentfacts_extension(key="x_custom")
        assert "x_custom" in ext
        assert "x_model_lineage" not in ext


# -- ModelLineage.from_provenance() -----------------------------------


class TestFromProvenance:
    """from_provenance() builds lineage from a provenance object."""

    def test_base_model_only(self):
        prov = ModelProvenance(model_id="llama-3.1-8b")
        lineage = ModelLineage.from_provenance(prov)
        assert lineage.depth == 1
        assert lineage.root is not None
        assert lineage.root.model_id == "llama-3.1-8b"

    def test_with_base_model(self):
        prov = ModelProvenance(
            model_id="my-adapter",
            base_model="llama-3.1-8b",
            model_type="lora_adapter",
        )
        lineage = ModelLineage.from_provenance(prov)
        assert lineage.depth == 2
        assert lineage.root is not None
        assert lineage.root.model_id == "llama-3.1-8b"
        assert lineage.leaf is not None
        assert lineage.leaf.model_id == "my-adapter"
        assert lineage.leaf.relation == "lora_adapter"
        assert lineage.leaf.parent_id == "llama-3.1-8b"

    def test_base_model_same_as_model_id(self):
        """When base_model == model_id, treat as single-node."""
        prov = ModelProvenance(
            model_id="llama-3.1-8b",
            base_model="llama-3.1-8b",
        )
        lineage = ModelLineage.from_provenance(prov)
        assert lineage.depth == 1

    def test_default_relation(self):
        """When model_type is empty, defaults to fine_tuned."""
        prov = ModelProvenance(
            model_id="child",
            base_model="parent",
        )
        lineage = ModelLineage.from_provenance(prov)
        assert lineage.leaf is not None
        assert lineage.leaf.relation == "fine_tuned"


# -- Adversarial lineage tests ----------------------------------------


class TestLineageAdversarial:
    """R2: adversarial edge cases for lineage."""

    def test_lineage_with_no_nodes_to_dict(self):
        """Empty lineage to_dict returns empty list."""
        lineage = ModelLineage()
        assert lineage.to_dict() == []
        assert lineage.depth == 0
        assert lineage.root is None
        assert lineage.leaf is None

    def test_circular_lineage_ancestors_terminates(self):
        """If parent_id creates a cycle, ancestors() must not infinite loop."""
        lineage = ModelLineage()
        lineage.add(LineageNode(model_id="A", parent_id="B"))
        lineage.add(LineageNode(model_id="B", parent_id="A"))
        # ancestors() may return partial results but must terminate
        ancestors = lineage.ancestors("A")
        # Should not hang; length is bounded by number of nodes
        assert len(ancestors) <= 2
