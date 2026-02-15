"""Shared fixtures for nanda_integrity tests."""

from __future__ import annotations

import pytest

from nanda_integrity import ModelProvenance


@pytest.fixture()
def minimal_provenance() -> ModelProvenance:
    """Provenance with only model_id set."""
    return ModelProvenance(model_id="test-model")


@pytest.fixture()
def full_provenance() -> ModelProvenance:
    """Provenance with all fields populated."""
    return ModelProvenance(
        model_id="llama-3.1-8b",
        model_version="1.0.0",
        provider_id="ollama",
        model_type="base",
        base_model="llama-3.1-8b",
        governance_tier="standard",
        weights_hash="abc123def456",
        risk_level="low",
        hash_algorithm="sha256",
        created_at="2026-01-15T10:30:00Z",
        attestation_method="hmac-sha256",
    )
