"""Integrity verification via cryptographic hashing.

Provides pluggable hash providers using a ``HashProvider`` protocol,
a stdlib-based default implementation, and convenience functions for
verifying model weight integrity against provenance metadata.

Zero runtime dependencies — uses only stdlib ``hashlib``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

_SUPPORTED_ALGORITHMS = frozenset({"sha256", "sha384", "sha512", "blake2b"})

_CHUNK_SIZE = 1 << 16  # 64 KiB


@runtime_checkable
class HashProvider(Protocol):
    """Protocol for pluggable hash providers."""

    def hash_bytes(self, data: bytes, algorithm: str) -> str:
        """Compute hex digest of *data* using *algorithm*."""
        ...  # pragma: no cover

    def hash_file(self, path: Path, algorithm: str) -> str:
        """Compute hex digest of file at *path* using *algorithm*."""
        ...  # pragma: no cover

    @property
    def supported_algorithms(self) -> frozenset[str]:
        """Return set of supported algorithm names."""
        ...  # pragma: no cover


class StdlibHashProvider:
    """Hash provider using Python stdlib ``hashlib``."""

    @property
    def supported_algorithms(self) -> frozenset[str]:
        return _SUPPORTED_ALGORITHMS

    def hash_bytes(self, data: bytes, algorithm: str) -> str:
        """Compute hex digest of *data*."""
        self._check_algorithm(algorithm)
        h = hashlib.new(algorithm)
        h.update(data)
        return h.hexdigest()

    def hash_file(self, path: Path, algorithm: str) -> str:
        """Compute hex digest of file at *path* by streaming chunks."""
        self._check_algorithm(algorithm)
        h = hashlib.new(algorithm)
        with open(path, "rb") as f:
            while chunk := f.read(_CHUNK_SIZE):
                h.update(chunk)
        return h.hexdigest()

    def _check_algorithm(self, algorithm: str) -> None:
        if algorithm not in _SUPPORTED_ALGORITHMS:
            msg = (
                f"Unsupported algorithm {algorithm!r}. "
                f"Supported: {sorted(_SUPPORTED_ALGORITHMS)}"
            )
            raise ValueError(msg)


@dataclass(frozen=True)
class IntegrityResult:
    """Result of an integrity verification check.

    Attributes:
        valid: Whether the computed hash matches the expected hash.
        expected_hash: The expected hex digest.
        computed_hash: The computed hex digest.
        algorithm: The hash algorithm used.
    """

    valid: bool
    expected_hash: str
    computed_hash: str
    algorithm: str


_default_provider = StdlibHashProvider()


def compute_weights_hash(
    path: str | Path,
    algorithm: str = "sha256",
    *,
    provider: HashProvider | None = None,
) -> str:
    """Compute hex digest of a model weights file.

    Args:
        path: Path to the weights file.
        algorithm: Hash algorithm name (default ``"sha256"``).
        provider: Optional custom hash provider.

    Returns:
        Hex digest string.
    """
    p = provider or _default_provider
    return p.hash_file(Path(path), algorithm)


def verify_integrity(
    path: str | Path,
    expected_hash: str,
    algorithm: str = "sha256",
    *,
    provider: HashProvider | None = None,
) -> IntegrityResult:
    """Verify a file's integrity against an expected hash.

    Args:
        path: Path to the file to verify.
        expected_hash: Expected hex digest.
        algorithm: Hash algorithm name (default ``"sha256"``).
        provider: Optional custom hash provider.

    Returns:
        ``IntegrityResult`` with ``valid=True`` if hashes match.
    """
    p = provider or _default_provider
    computed = p.hash_file(Path(path), algorithm)
    return IntegrityResult(
        valid=computed == expected_hash,
        expected_hash=expected_hash,
        computed_hash=computed,
        algorithm=algorithm,
    )


def verify_provenance_integrity(
    provenance: object,
    path: str | Path,
    *,
    provider: HashProvider | None = None,
) -> IntegrityResult:
    """Verify file integrity using hash info from a provenance object.

    Reads ``weights_hash`` and ``hash_algorithm`` from the provenance
    object.  If ``hash_algorithm`` is empty, defaults to ``"sha256"``.

    Args:
        provenance: Object with ``weights_hash`` and ``hash_algorithm``
            attributes (e.g. ``ModelProvenance``).
        path: Path to the file to verify.
        provider: Optional custom hash provider.

    Returns:
        ``IntegrityResult`` with ``valid=True`` if hashes match.

    Raises:
        ValueError: If ``weights_hash`` is empty on the provenance.
    """
    weights_hash: str = getattr(provenance, "weights_hash", "")
    hash_algorithm: str = getattr(provenance, "hash_algorithm", "") or "sha256"

    if not weights_hash:
        msg = "Provenance has no weights_hash to verify against"
        raise ValueError(msg)

    return verify_integrity(
        path,
        weights_hash,
        hash_algorithm,
        provider=provider,
    )
