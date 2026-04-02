"""Tests for attestation module — signing and verification.

# Step 1 — Assumption Audit
# - HMACSigner/HMACVerifier use HMAC-SHA256
# - canonicalize() produces sorted-key, no-whitespace JSON
# - Attestation is frozen and round-trips via to_dict/from_dict
# - create_attestation hashes the canonical provenance and signs it
# - verify_attestation re-canonicalizes and verifies the signature
# - Wrong key -> verification fails; tampered provenance -> verification fails

# Step 2 — Gap Analysis
# - No test for tampered single field after signing (not entire provenance swap)
# - No test for empty/minimal provenance attestation
# - Wrong key test exists at HMAC level but worth explicit attestation-level test

# Step 3 — Break It List
# - Change one field (e.g. provider_id) after signing, verify must fail
# - Minimal provenance with only model_id should still sign/verify
# - Sign with key A, verify with key B at full attestation workflow level
"""

from __future__ import annotations

import hashlib
import json

import pytest

from nanda_integrity import ModelProvenance
from nanda_integrity.attestation import (
    Attestation,
    HMACSigner,
    HMACVerifier,
    Signer,
    Verifier,
    canonicalize,
    create_attestation,
    verify_attestation,
)

# -- Protocols --------------------------------------------------------


class TestProtocols:
    """Signer and Verifier satisfy runtime-checkable protocols."""

    def test_hmac_signer_satisfies_protocol(self):
        assert isinstance(HMACSigner(b"key"), Signer)

    def test_hmac_verifier_satisfies_protocol(self):
        assert isinstance(HMACVerifier(b"key"), Verifier)


# -- HMACSigner / HMACVerifier ---------------------------------------


class TestHMAC:
    """HMAC signing and verification."""

    def test_sign_produces_hex(self):
        signer = HMACSigner(b"secret", signer_id="test-org")
        sig = signer.sign(b"hello")
        assert isinstance(sig, str)
        assert len(sig) == 64  # sha256 hex length

    def test_method_is_hmac_sha256(self):
        signer = HMACSigner(b"key")
        assert signer.method == "hmac-sha256"

    def test_signer_id_default(self):
        signer = HMACSigner(b"key")
        assert signer.signer_id == "self"

    def test_signer_id_custom(self):
        signer = HMACSigner(b"key", signer_id="org-123")
        assert signer.signer_id == "org-123"

    def test_sign_verify_round_trip(self):
        secret = b"shared-secret"
        signer = HMACSigner(secret)
        verifier = HMACVerifier(secret)

        data = b"test data"
        sig = signer.sign(data)
        assert verifier.verify(data, sig) is True

    def test_wrong_key_fails(self):
        signer = HMACSigner(b"key-A")
        verifier = HMACVerifier(b"key-B")

        data = b"test data"
        sig = signer.sign(data)
        assert verifier.verify(data, sig) is False

    def test_tampered_data_fails(self):
        secret = b"key"
        signer = HMACSigner(secret)
        verifier = HMACVerifier(secret)

        sig = signer.sign(b"original")
        assert verifier.verify(b"tampered", sig) is False


# -- canonicalize() ---------------------------------------------------


class TestCanonicalize:
    """canonicalize() produces deterministic bytes."""

    def test_deterministic(self):
        p = ModelProvenance(model_id="test", provider_id="local")
        assert canonicalize(p) == canonicalize(p)

    def test_sorted_keys(self):
        p = ModelProvenance(model_id="b", provider_id="a")
        result = json.loads(canonicalize(p))
        keys = list(result.keys())
        assert keys == sorted(keys)

    def test_no_whitespace(self):
        p = ModelProvenance(model_id="test")
        raw = canonicalize(p).decode()
        assert " " not in raw
        assert "\n" not in raw

    def test_omits_empty_fields(self):
        p = ModelProvenance(model_id="test")
        result = json.loads(canonicalize(p))
        assert result == {"model_id": "test"}


# -- Attestation dataclass -------------------------------------------


class TestAttestation:
    """Attestation serialization."""

    def test_to_dict(self):
        a = Attestation(
            provenance_digest="abc123",
            method="hmac-sha256",
            signature="sig",
            signer_id="org",
            timestamp="2026-01-01T00:00:00Z",
        )
        d = a.to_dict()
        assert d["method"] == "hmac-sha256"
        assert d["signer_id"] == "org"

    def test_round_trip(self):
        a = Attestation(
            provenance_digest="abc",
            method="hmac-sha256",
            signature="sig",
            signer_id="self",
            timestamp="2026-01-01T00:00:00Z",
        )
        rebuilt = Attestation.from_dict(a.to_dict())
        assert rebuilt == a

    def test_frozen(self):
        a = Attestation(
            provenance_digest="x",
            method="m",
            signature="s",
            signer_id="i",
            timestamp="t",
        )
        with pytest.raises(AttributeError):
            a.method = "other"  # type: ignore[misc]


# -- create_attestation() / verify_attestation() ----------------------


class TestCreateVerifyAttestation:
    """End-to-end attestation creation and verification."""

    def test_create_and_verify(self):
        secret = b"test-secret"
        signer = HMACSigner(secret, signer_id="test-org")
        verifier = HMACVerifier(secret)

        prov = ModelProvenance(
            model_id="llama-3.1-8b",
            provider_id="ollama",
            governance_tier="standard",
        )

        attestation = create_attestation(prov, signer, timestamp="2026-01-15T10:00:00Z")
        assert attestation.method == "hmac-sha256"
        assert attestation.signer_id == "test-org"
        assert attestation.timestamp == "2026-01-15T10:00:00Z"

        assert verify_attestation(prov, attestation, verifier) is True

    def test_tampered_provenance_fails(self):
        secret = b"key"
        signer = HMACSigner(secret)
        verifier = HMACVerifier(secret)

        prov = ModelProvenance(model_id="original")
        attestation = create_attestation(prov, signer)

        tampered = ModelProvenance(model_id="tampered")
        assert verify_attestation(tampered, attestation, verifier) is False

    def test_wrong_key_fails(self):
        prov = ModelProvenance(model_id="test")
        attestation = create_attestation(prov, HMACSigner(b"key-A"))
        assert verify_attestation(prov, attestation, HMACVerifier(b"key-B")) is False

    def test_auto_timestamp(self):
        signer = HMACSigner(b"key")
        prov = ModelProvenance(model_id="test")
        attestation = create_attestation(prov, signer)
        assert attestation.timestamp  # non-empty
        assert "T" in attestation.timestamp  # ISO format

    def test_digest_matches_canonical(self):
        signer = HMACSigner(b"key")
        prov = ModelProvenance(model_id="test", provider_id="local")
        attestation = create_attestation(prov, signer)

        canonical = canonicalize(prov)
        expected_digest = hashlib.sha256(canonical).hexdigest()
        assert attestation.provenance_digest == expected_digest

    def test_tampered_single_field_detected(self):
        """R7: changing one field after signing must fail verification."""
        secret = b"shared-secret"
        signer = HMACSigner(secret, signer_id="org")
        verifier = HMACVerifier(secret)

        prov = ModelProvenance(
            model_id="model-x",
            provider_id="ollama",
            governance_tier="standard",
        )
        attestation = create_attestation(prov, signer)
        assert verify_attestation(prov, attestation, verifier) is True

        # Tamper a single field
        tampered = ModelProvenance(
            model_id="model-x",
            provider_id="ollama",
            governance_tier="regulated",  # changed from "standard"
        )
        assert verify_attestation(tampered, attestation, verifier) is False

    def test_empty_provenance_attestation(self):
        """Minimal provenance (only model_id) can be signed and verified."""
        secret = b"key"
        signer = HMACSigner(secret)
        verifier = HMACVerifier(secret)

        prov = ModelProvenance(model_id="minimal-model")
        attestation = create_attestation(prov, signer)
        assert verify_attestation(prov, attestation, verifier) is True

    def test_wrong_key_verification_fails(self):
        """R7: sign with key A, verify with key B -> must fail."""
        prov = ModelProvenance(
            model_id="test",
            provider_id="local",
            risk_level="low",
        )
        attestation = create_attestation(prov, HMACSigner(b"key-A", signer_id="org-A"))
        assert verify_attestation(prov, attestation, HMACVerifier(b"key-B")) is False
