"""Tests for nanda module — NANDA protocol integration."""

from __future__ import annotations

from nanda_integrity import (
    Attestation,
    GovernanceReport,
    ModelLineage,
    ModelProvenance,
    PolicyResult,
    check_governance,
)
from nanda_integrity.lineage import LineageNode
from nanda_integrity.nanda import (
    IntegrityExtension,
    attach_to_agent_facts,
    extract_from_agent_facts,
)


# -- IntegrityExtension -----------------------------------------------


class TestIntegrityExtension:
    """IntegrityExtension combines all layers."""

    def test_minimal(self):
        prov = ModelProvenance(model_id="test")
        ext = IntegrityExtension(provenance=prov)
        d = ext.to_dict()
        assert "provenance" in d
        assert d["provenance"]["model_id"] == "test"
        assert "lineage" not in d
        assert "attestation" not in d
        assert "governance" not in d

    def test_with_lineage(self):
        prov = ModelProvenance(model_id="child", base_model="parent")
        lineage = ModelLineage.from_provenance(prov)
        ext = IntegrityExtension(provenance=prov, lineage=lineage)
        d = ext.to_dict()
        assert "lineage" in d
        assert len(d["lineage"]) == 2

    def test_with_attestation(self):
        prov = ModelProvenance(model_id="test")
        att = Attestation(
            provenance_digest="abc",
            method="hmac-sha256",
            signature="sig",
            signer_id="org",
            timestamp="2026-01-01T00:00:00Z",
        )
        ext = IntegrityExtension(provenance=prov, attestation=att)
        d = ext.to_dict()
        assert "attestation" in d
        assert d["attestation"]["method"] == "hmac-sha256"

    def test_with_governance(self):
        prov = ModelProvenance(
            model_id="test",
            weights_hash="abc",
            governance_tier="standard",
        )
        report = check_governance(prov)
        ext = IntegrityExtension(provenance=prov, governance_report=report)
        d = ext.to_dict()
        assert "governance" in d
        assert d["governance"]["passed"] is True

    def test_agentfacts_extension(self):
        prov = ModelProvenance(model_id="test")
        ext = IntegrityExtension(provenance=prov)
        result = ext.to_agentfacts_extension()
        assert "x_model_integrity" in result

    def test_custom_key(self):
        prov = ModelProvenance(model_id="test")
        ext = IntegrityExtension(provenance=prov)
        result = ext.to_agentfacts_extension(key="x_custom")
        assert "x_custom" in result
        assert "x_model_integrity" not in result

    def test_legacy_extension(self):
        prov = ModelProvenance(model_id="test", provider_id="local")
        ext = IntegrityExtension(provenance=prov)
        legacy = ext.to_legacy_extension()
        assert "x_model_provenance" in legacy
        assert legacy["x_model_provenance"]["model_id"] == "test"


# -- attach_to_agent_facts() -----------------------------------------


class TestAttachToAgentFacts:
    """attach_to_agent_facts() merges non-destructively."""

    def test_adds_extension(self):
        metadata: dict = {"name": "test-agent"}
        ext = IntegrityExtension(
            provenance=ModelProvenance(model_id="test")
        )
        result = attach_to_agent_facts(metadata, ext)
        assert "name" in result
        assert "x_model_integrity" in result

    def test_preserves_existing(self):
        metadata: dict = {"existing": "value", "x_other": {"data": True}}
        ext = IntegrityExtension(
            provenance=ModelProvenance(model_id="test")
        )
        result = attach_to_agent_facts(metadata, ext)
        assert result["existing"] == "value"
        assert result["x_other"] == {"data": True}

    def test_does_not_mutate_original(self):
        metadata: dict = {"name": "agent"}
        ext = IntegrityExtension(
            provenance=ModelProvenance(model_id="test")
        )
        result = attach_to_agent_facts(metadata, ext)
        assert "x_model_integrity" not in metadata
        assert "x_model_integrity" in result

    def test_include_legacy(self):
        metadata: dict = {}
        ext = IntegrityExtension(
            provenance=ModelProvenance(model_id="test")
        )
        result = attach_to_agent_facts(metadata, ext, include_legacy=True)
        assert "x_model_integrity" in result
        assert "x_model_provenance" in result

    def test_custom_key(self):
        metadata: dict = {}
        ext = IntegrityExtension(
            provenance=ModelProvenance(model_id="test")
        )
        result = attach_to_agent_facts(metadata, ext, key="x_vendor")
        assert "x_vendor" in result
        assert "x_model_integrity" not in result


# -- extract_from_agent_facts() ---------------------------------------


class TestExtractFromAgentFacts:
    """extract_from_agent_facts() reconstructs IntegrityExtension."""

    def test_round_trip(self):
        prov = ModelProvenance(model_id="test", provider_id="local")
        lineage = ModelLineage.from_provenance(prov)
        ext = IntegrityExtension(provenance=prov, lineage=lineage)
        metadata = attach_to_agent_facts({}, ext)

        extracted = extract_from_agent_facts(metadata)
        assert extracted is not None
        assert extracted.provenance.model_id == "test"
        assert extracted.provenance.provider_id == "local"

    def test_missing_returns_none(self):
        assert extract_from_agent_facts({}) is None
        assert extract_from_agent_facts({"other": "data"}) is None

    def test_missing_provenance_returns_none(self):
        metadata = {"x_model_integrity": {"lineage": []}}
        assert extract_from_agent_facts(metadata) is None

    def test_with_attestation(self):
        prov = ModelProvenance(model_id="test")
        att = Attestation(
            provenance_digest="abc",
            method="hmac-sha256",
            signature="sig",
            signer_id="org",
            timestamp="2026-01-01T00:00:00Z",
        )
        ext = IntegrityExtension(provenance=prov, attestation=att)
        metadata = attach_to_agent_facts({}, ext)

        extracted = extract_from_agent_facts(metadata)
        assert extracted is not None
        assert extracted.attestation is not None
        assert extracted.attestation.method == "hmac-sha256"

    def test_with_lineage(self):
        prov = ModelProvenance(
            model_id="child",
            base_model="parent",
            model_type="lora_adapter",
        )
        lineage = ModelLineage.from_provenance(prov)
        ext = IntegrityExtension(provenance=prov, lineage=lineage)
        metadata = attach_to_agent_facts({}, ext)

        extracted = extract_from_agent_facts(metadata)
        assert extracted is not None
        assert extracted.lineage is not None
        assert extracted.lineage.depth == 2

    def test_custom_key(self):
        prov = ModelProvenance(model_id="test")
        ext = IntegrityExtension(provenance=prov)
        metadata = attach_to_agent_facts({}, ext, key="x_vendor")

        assert extract_from_agent_facts(metadata) is None
        extracted = extract_from_agent_facts(metadata, key="x_vendor")
        assert extracted is not None
        assert extracted.provenance.model_id == "test"
