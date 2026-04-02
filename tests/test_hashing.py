"""Tests for hashing module — integrity verification.

# Step 1 — Assumption Audit
# - StdlibHashProvider supports sha256/sha384/sha512/blake2b only
# - md5 is explicitly unsupported and raises ValueError
# - hash_file streams via 64 KiB chunks; empty files should still return valid hash
# - compute_weights_hash accepts str or Path
# - verify_integrity returns frozen IntegrityResult
# - verify_provenance_integrity reads hash info from ModelProvenance

# Step 2 — Gap Analysis
# - No test for hashing an empty file (0 bytes)
# - No test for hash_file on a nonexistent path
# - Unsupported algorithm test only on hash_bytes, not hash_file

# Step 3 — Break It List
# - Empty file edge case
# - Nonexistent file path should raise FileNotFoundError
# - md5 (unsupported) via hash_file path
"""

from __future__ import annotations

import hashlib
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

    def test_hash_empty_file(self, tmp_path: Path):
        """R5: empty file (0 bytes) returns a valid hash, not an error."""
        p = StdlibHashProvider()
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        expected = hashlib.sha256(b"").hexdigest()
        assert p.hash_file(f, "sha256") == expected

    def test_hash_nonexistent_file_raises(self, tmp_path: Path):
        """R2: hashing a path that does not exist must raise FileNotFoundError."""
        p = StdlibHashProvider()
        missing = tmp_path / "does_not_exist.bin"
        with pytest.raises(FileNotFoundError):
            p.hash_file(missing, "sha256")

    def test_unsupported_algorithm_raises_hash_file(self, tmp_path: Path):
        """R2: md5 via hash_file raises ValueError, same as hash_bytes."""
        p = StdlibHashProvider()
        f = tmp_path / "data.bin"
        f.write_bytes(b"data")
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            p.hash_file(f, "md5")


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
