"""Tests for hashing module — integrity verification."""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import pytest

from nanda_integrity import (
    IntegrityResult,
    ModelProvenance,
    StdlibHashProvider,
    compute_weights_hash,
    verify_integrity,
    verify_provenance_integrity,
)
from nanda_integrity.hashing import HashProvider


# -- StdlibHashProvider -----------------------------------------------


class TestStdlibHashProvider:
    """StdlibHashProvider computes correct hashes."""

    def test_satisfies_protocol(self):
        assert isinstance(StdlibHashProvider(), HashProvider)

    def test_supported_algorithms(self):
        p = StdlibHashProvider()
        assert "sha256" in p.supported_algorithms
        assert "sha384" in p.supported_algorithms
        assert "sha512" in p.supported_algorithms
        assert "blake2b" in p.supported_algorithms

    def test_hash_bytes_sha256(self):
        p = StdlibHashProvider()
        expected = hashlib.sha256(b"hello world").hexdigest()
        assert p.hash_bytes(b"hello world", "sha256") == expected

    def test_hash_bytes_blake2b(self):
        p = StdlibHashProvider()
        expected = hashlib.blake2b(b"test data").hexdigest()
        assert p.hash_bytes(b"test data", "blake2b") == expected

    def test_hash_file(self, tmp_path: Path):
        p = StdlibHashProvider()
        f = tmp_path / "weights.bin"
        f.write_bytes(b"model weights data")
        expected = hashlib.sha256(b"model weights data").hexdigest()
        assert p.hash_file(f, "sha256") == expected

    def test_unsupported_algorithm_raises(self):
        p = StdlibHashProvider()
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            p.hash_bytes(b"data", "md5")


# -- compute_weights_hash() ------------------------------------------


class TestComputeWeightsHash:
    """compute_weights_hash() convenience function."""

    def test_default_sha256(self, tmp_path: Path):
        f = tmp_path / "model.bin"
        f.write_bytes(b"weights")
        expected = hashlib.sha256(b"weights").hexdigest()
        assert compute_weights_hash(f) == expected

    def test_explicit_algorithm(self, tmp_path: Path):
        f = tmp_path / "model.bin"
        f.write_bytes(b"weights")
        expected = hashlib.sha512(b"weights").hexdigest()
        assert compute_weights_hash(f, "sha512") == expected

    def test_string_path(self, tmp_path: Path):
        f = tmp_path / "model.bin"
        f.write_bytes(b"data")
        expected = hashlib.sha256(b"data").hexdigest()
        assert compute_weights_hash(str(f)) == expected


# -- verify_integrity() -----------------------------------------------


class TestVerifyIntegrity:
    """verify_integrity() checks file hash against expected value."""

    def test_valid_file(self, tmp_path: Path):
        f = tmp_path / "model.bin"
        f.write_bytes(b"correct data")
        expected = hashlib.sha256(b"correct data").hexdigest()
        result = verify_integrity(f, expected)
        assert isinstance(result, IntegrityResult)
        assert result.valid is True
        assert result.computed_hash == expected
        assert result.algorithm == "sha256"

    def test_invalid_file(self, tmp_path: Path):
        f = tmp_path / "model.bin"
        f.write_bytes(b"tampered data")
        result = verify_integrity(f, "wrong_hash")
        assert result.valid is False
        assert result.expected_hash == "wrong_hash"

    def test_integrity_result_is_frozen(self, tmp_path: Path):
        f = tmp_path / "model.bin"
        f.write_bytes(b"data")
        result = verify_integrity(f, "abc")
        with pytest.raises(AttributeError):
            result.valid = True  # type: ignore[misc]


# -- verify_provenance_integrity() ------------------------------------


class TestVerifyProvenanceIntegrity:
    """verify_provenance_integrity() reads hash info from provenance."""

    def test_valid_provenance(self, tmp_path: Path):
        f = tmp_path / "model.bin"
        f.write_bytes(b"model data")
        expected = hashlib.sha256(b"model data").hexdigest()
        prov = ModelProvenance(
            model_id="test",
            weights_hash=expected,
            hash_algorithm="sha256",
        )
        result = verify_provenance_integrity(prov, f)
        assert result.valid is True

    def test_defaults_to_sha256(self, tmp_path: Path):
        f = tmp_path / "model.bin"
        f.write_bytes(b"data")
        expected = hashlib.sha256(b"data").hexdigest()
        prov = ModelProvenance(model_id="test", weights_hash=expected)
        result = verify_provenance_integrity(prov, f)
        assert result.valid is True
        assert result.algorithm == "sha256"

    def test_empty_weights_hash_raises(self, tmp_path: Path):
        f = tmp_path / "model.bin"
        f.write_bytes(b"data")
        prov = ModelProvenance(model_id="test")
        with pytest.raises(ValueError, match="no weights_hash"):
            verify_provenance_integrity(prov, f)

    def test_tampered_file_fails(self, tmp_path: Path):
        f = tmp_path / "model.bin"
        f.write_bytes(b"original")
        original_hash = hashlib.sha256(b"original").hexdigest()
        prov = ModelProvenance(
            model_id="test",
            weights_hash=original_hash,
            hash_algorithm="sha256",
        )
        # Tamper with the file
        f.write_bytes(b"tampered")
        result = verify_provenance_integrity(prov, f)
        assert result.valid is False
