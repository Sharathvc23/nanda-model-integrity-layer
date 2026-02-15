"""Golden-file tests verifying JSON shapes match NANDA protocol patterns.

These tests encode the exact JSON structures expected by NANDA-compatible
agent registries, ensuring the library stays aligned with the protocol.
"""

from __future__ import annotations

from nanda_integrity import ModelProvenance


# -- AgentFacts extension shape ---------------------------------------


class TestAgentFactsShape:
    """AgentFacts extension matches the NANDA x_ vendor extension pattern."""

    def test_agentfacts_extension_shape(self):
        """The inner dict contains only non-empty provenance fields."""
        p = ModelProvenance(
            model_id="phi3-mini",
            provider_id="local",
            governance_tier="standard",
        )
        ext = p.to_agentfacts_extension()
        inner = ext["x_model_provenance"]
        assert inner == {
            "model_id": "phi3-mini",
            "provider_id": "local",
            "governance_tier": "standard",
        }

    def test_default_extension_key(self):
        """Library uses x_model_provenance as the default extension key."""
        p = ModelProvenance(model_id="test")
        ext = p.to_agentfacts_extension()
        assert "x_model_provenance" in ext

    def test_vendor_extension_key(self):
        """Vendors can use their own namespace via extension_key arg."""
        p = ModelProvenance(model_id="test")
        ext = p.to_agentfacts_extension(extension_key="x_my_vendor")
        assert "x_my_vendor" in ext
        assert "x_model_provenance" not in ext


# -- AgentCard metadata shape -----------------------------------------


class TestAgentCardShape:
    """AgentCard metadata matches the model_info pattern."""

    def test_agent_card_model_info_shape(self):
        """model_info key with inner dict matching the NANDA AgentCard schema."""
        p = ModelProvenance(
            model_id="llama-3.1-8b",
            provider_id="ollama",
        )
        card_meta = p.to_agent_card_metadata()
        assert card_meta == {
            "model_info": {
                "model_id": "llama-3.1-8b",
                "provider_id": "ollama",
            }
        }

    def test_minimal_agent_card(self):
        """Minimal provenance produces minimal model_info."""
        p = ModelProvenance(model_id="test-model")
        card_meta = p.to_agent_card_metadata()
        assert card_meta == {"model_info": {"model_id": "test-model"}}


# -- Decision envelope shape ------------------------------------------


class TestDecisionFieldsShape:
    """Decision fields match the NANDA decision-envelope provenance block."""

    def test_full_decision_fields_shape(self):
        """Top-level model_id/model_version/provider_id — omit-when-falsy."""
        p = ModelProvenance(
            model_id="phi3-mini",
            model_version="3.8b",
            provider_id="local",
        )
        fields = p.to_decision_fields()
        assert fields == {
            "model_id": "phi3-mini",
            "model_version": "3.8b",
            "provider_id": "local",
        }

    def test_partial_decision_fields(self):
        """When model_version is absent, it is omitted from output."""
        p = ModelProvenance(model_id="phi3-mini", provider_id="local")
        fields = p.to_decision_fields()
        assert fields == {"model_id": "phi3-mini", "provider_id": "local"}
        assert "model_version" not in fields


# -- Omit-when-empty filter pattern -----------------------------------


class TestOmitWhenEmptyPattern:
    """to_dict() uses the {if v} filter pattern for clean serialization."""

    def test_core_fields_shape(self):
        """Core fields are present when set, absent when empty."""
        p = ModelProvenance(
            model_id="phi3-mini",
            model_version="3.8b",
            provider_id="local",
            model_type="lora_adapter",
            base_model="llama-3.1-8b",
            governance_tier="standard",
        )
        d = p.to_dict()
        assert set(d.keys()) == {
            "model_id",
            "model_version",
            "provider_id",
            "model_type",
            "base_model",
            "governance_tier",
        }

    def test_extended_fields_shape(self):
        """Extended fields (weights_hash, risk_level) serialize correctly."""
        p = ModelProvenance(
            model_id="test",
            weights_hash="abc123",
            risk_level="high",
        )
        d = p.to_dict()
        assert "weights_hash" in d
        assert "risk_level" in d
        assert d["model_id"] == "test"
