"""Unit tests for ModelProvenance dataclass and serialization methods."""

from __future__ import annotations

import pytest

from nanda_integrity import ModelProvenance


# -- to_dict() --------------------------------------------------------


class TestToDict:
    """to_dict() serializes fields and omits empty strings."""

    def test_minimal_only_model_id(self):
        p = ModelProvenance(model_id="phi3-mini")
        assert p.to_dict() == {"model_id": "phi3-mini"}

    def test_maximal_all_fields(self):
        p = ModelProvenance(
            model_id="llama-3.1-8b",
            model_version="1.0.0",
            provider_id="ollama",
            model_type="base",
            base_model="llama-3.1-8b",
            governance_tier="standard",
            weights_hash="abc123",
            risk_level="low",
        )
        d = p.to_dict()
        assert d["model_id"] == "llama-3.1-8b"
        assert d["model_version"] == "1.0.0"
        assert d["provider_id"] == "ollama"
        assert d["model_type"] == "base"
        assert d["base_model"] == "llama-3.1-8b"
        assert d["governance_tier"] == "standard"
        assert d["weights_hash"] == "abc123"
        assert d["risk_level"] == "low"

    def test_omits_empty_strings(self):
        p = ModelProvenance(
            model_id="phi3-mini",
            model_version="3.8b",
            provider_id="",
            model_type="lora_adapter",
        )
        d = p.to_dict()
        assert "provider_id" not in d
        assert d == {
            "model_id": "phi3-mini",
            "model_version": "3.8b",
            "model_type": "lora_adapter",
        }

    def test_empty_model_id_omitted(self):
        """model_id="" is technically allowed at dataclass level but omitted."""
        p = ModelProvenance(model_id="")
        assert p.to_dict() == {}

    def test_new_fields_included(self):
        """New fields (hash_algorithm, created_at, attestation_method) serialize."""
        p = ModelProvenance(
            model_id="test",
            hash_algorithm="sha256",
            created_at="2026-01-15T10:30:00Z",
            attestation_method="hmac-sha256",
        )
        d = p.to_dict()
        assert d["hash_algorithm"] == "sha256"
        assert d["created_at"] == "2026-01-15T10:30:00Z"
        assert d["attestation_method"] == "hmac-sha256"

    def test_new_fields_omitted_when_empty(self):
        """New fields follow the same omit-when-empty pattern."""
        p = ModelProvenance(model_id="test")
        d = p.to_dict()
        assert "hash_algorithm" not in d
        assert "created_at" not in d
        assert "attestation_method" not in d


# -- to_agentfacts_extension() ----------------------------------------


class TestAgentFactsExtension:
    """to_agentfacts_extension() wraps under an extension key."""

    def test_default_key(self):
        p = ModelProvenance(model_id="phi3-mini", provider_id="local")
        result = p.to_agentfacts_extension()
        assert "x_model_provenance" in result
        assert result["x_model_provenance"]["model_id"] == "phi3-mini"
        assert result["x_model_provenance"]["provider_id"] == "local"

    def test_custom_key(self):
        p = ModelProvenance(model_id="test")
        result = p.to_agentfacts_extension(extension_key="x_custom")
        assert "x_custom" in result
        assert "x_model_provenance" not in result
        assert result["x_custom"]["model_id"] == "test"


# -- to_agent_card_metadata() ----------------------------------------


class TestAgentCardMetadata:
    """to_agent_card_metadata() wraps under 'model_info'."""

    def test_shape(self):
        p = ModelProvenance(model_id="llama-3.1-8b", provider_id="ollama")
        result = p.to_agent_card_metadata()
        assert "model_info" in result
        assert result["model_info"] == {
            "model_id": "llama-3.1-8b",
            "provider_id": "ollama",
        }

    def test_minimal(self):
        p = ModelProvenance(model_id="test")
        result = p.to_agent_card_metadata()
        assert result == {"model_info": {"model_id": "test"}}


# -- to_decision_fields() --------------------------------------------


class TestDecisionFields:
    """to_decision_fields() emits flat top-level fields."""

    def test_all_three_present(self):
        p = ModelProvenance(
            model_id="phi3-mini",
            model_version="3.8b",
            provider_id="local",
        )
        assert p.to_decision_fields() == {
            "model_id": "phi3-mini",
            "model_version": "3.8b",
            "provider_id": "local",
        }

    def test_omits_empty(self):
        p = ModelProvenance(model_id="phi3-mini")
        result = p.to_decision_fields()
        assert result == {"model_id": "phi3-mini"}
        assert "model_version" not in result
        assert "provider_id" not in result

    def test_ignores_other_fields(self):
        """Decision fields only contain model_id/version/provider_id."""
        p = ModelProvenance(
            model_id="llama",
            model_type="base",
            governance_tier="regulated",
            weights_hash="abc",
            risk_level="high",
        )
        result = p.to_decision_fields()
        assert result == {"model_id": "llama"}

    def test_empty_model_id(self):
        p = ModelProvenance(model_id="", provider_id="ollama")
        result = p.to_decision_fields()
        assert "model_id" not in result
        assert result == {"provider_id": "ollama"}


# -- from_dict() ------------------------------------------------------


class TestFromDict:
    """from_dict() deserializes and round-trips."""

    def test_minimal(self):
        p = ModelProvenance.from_dict({"model_id": "test"})
        assert p.model_id == "test"
        assert p.model_version == ""
        assert p.provider_id == ""

    def test_full_round_trip(self):
        original = ModelProvenance(
            model_id="llama-3.1-8b",
            model_version="1.0.0",
            provider_id="ollama",
            model_type="base",
            base_model="llama-3.1-8b",
            governance_tier="standard",
            weights_hash="deadbeef",
            risk_level="low",
            hash_algorithm="sha256",
            created_at="2026-01-15T10:30:00Z",
            attestation_method="hmac-sha256",
        )
        rebuilt = ModelProvenance.from_dict(original.to_dict())
        assert rebuilt == original

    def test_ignores_unknown_keys(self):
        data = {"model_id": "test", "unknown_field": "ignored", "extra": 42}
        p = ModelProvenance.from_dict(data)
        assert p.model_id == "test"

    def test_missing_model_id_raises(self):
        with pytest.raises(TypeError, match="model_id is required"):
            ModelProvenance.from_dict({"provider_id": "ollama"})

    def test_round_trip_via_agentfacts(self):
        """from_dict can rebuild from to_agentfacts_extension inner dict."""
        original = ModelProvenance(model_id="phi3", provider_id="local")
        ext = original.to_agentfacts_extension()
        inner = ext["x_model_provenance"]
        rebuilt = ModelProvenance.from_dict(inner)
        assert rebuilt.model_id == "phi3"
        assert rebuilt.provider_id == "local"

    def test_new_fields_round_trip(self):
        """New fields survive a from_dict → to_dict round trip."""
        original = ModelProvenance(
            model_id="test",
            hash_algorithm="blake2b",
            created_at="2026-02-01T00:00:00Z",
            attestation_method="self-declared",
        )
        rebuilt = ModelProvenance.from_dict(original.to_dict())
        assert rebuilt == original
