"""Trust attestation via signing and verification.

Provides protocols for pluggable signing/verification, an HMAC-based
implementation using stdlib, and convenience functions for creating
and verifying attestations over provenance data.

Zero runtime dependencies — uses only stdlib ``hmac`` and ``json``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from nanda_integrity.provenance import ModelProvenance


@runtime_checkable
class Signer(Protocol):
    """Protocol for attestation signers."""

    @property
    def method(self) -> str:
        """Return the attestation method name (e.g. ``"hmac-sha256"``)."""
        ...  # pragma: no cover

    @property
    def signer_id(self) -> str:
        """Return an identifier for this signer."""
        ...  # pragma: no cover

    def sign(self, data: bytes) -> str:
        """Produce a signature (hex string) over *data*."""
        ...  # pragma: no cover


@runtime_checkable
class Verifier(Protocol):
    """Protocol for attestation verifiers."""

    def verify(self, data: bytes, signature: str) -> bool:
        """Return True if *signature* is valid for *data*."""
        ...  # pragma: no cover


@dataclass(frozen=True)
class Attestation:
    """A signed attestation over provenance data.

    Attributes:
        provenance_digest: Hex digest of the canonical provenance bytes.
        method: Signing method used (e.g. ``"hmac-sha256"``).
        signature: Hex-encoded signature.
        signer_id: Identifier for the signer.
        timestamp: ISO 8601 timestamp of when the attestation was created.
    """

    provenance_digest: str
    method: str
    signature: str
    signer_id: str
    timestamp: str

    def to_dict(self) -> dict[str, str]:
        """Serialize to dict."""
        return {
            "provenance_digest": self.provenance_digest,
            "method": self.method,
            "signature": self.signature,
            "signer_id": self.signer_id,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Attestation:
        """Construct from a dict (e.g. parsed JSON)."""
        return cls(
            provenance_digest=str(data["provenance_digest"]),
            method=str(data["method"]),
            signature=str(data["signature"]),
            signer_id=str(data["signer_id"]),
            timestamp=str(data["timestamp"]),
        )


class HMACSigner:
    """HMAC-SHA256 signer using stdlib ``hmac``.

    Args:
        secret: Shared secret key (bytes).
        signer_id: Identifier for this signer.
    """

    def __init__(self, secret: bytes, signer_id: str = "self") -> None:
        self._secret = secret
        self._signer_id = signer_id

    @property
    def method(self) -> str:
        return "hmac-sha256"

    @property
    def signer_id(self) -> str:
        return self._signer_id

    def sign(self, data: bytes) -> str:
        return hmac.new(self._secret, data, hashlib.sha256).hexdigest()


class HMACVerifier:
    """HMAC-SHA256 verifier using stdlib ``hmac``.

    Args:
        secret: Shared secret key (bytes) — must match the signer's.
    """

    def __init__(self, secret: bytes) -> None:
        self._secret = secret

    def verify(self, data: bytes, signature: str) -> bool:
        expected = hmac.new(self._secret, data, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)


def canonicalize(provenance: ModelProvenance) -> bytes:
    """Produce deterministic JSON bytes from a provenance object.

    Uses sorted keys and no whitespace to ensure identical output
    for identical logical content.

    Args:
        provenance: The provenance to canonicalize.

    Returns:
        UTF-8 encoded JSON bytes.
    """
    return json.dumps(
        provenance.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def create_attestation(
    provenance: ModelProvenance,
    signer: Signer,
    *,
    timestamp: str | None = None,
) -> Attestation:
    """Create a signed attestation over provenance data.

    Args:
        provenance: The provenance to attest.
        signer: A ``Signer`` implementation.
        timestamp: Optional ISO 8601 timestamp (defaults to now).

    Returns:
        A new ``Attestation`` with the signature.
    """
    canonical = canonicalize(provenance)
    digest = hashlib.sha256(canonical).hexdigest()
    signature = signer.sign(canonical)
    ts = timestamp or datetime.now(timezone.utc).isoformat()

    return Attestation(
        provenance_digest=digest,
        method=signer.method,
        signature=signature,
        signer_id=signer.signer_id,
        timestamp=ts,
    )


def verify_attestation(
    provenance: ModelProvenance,
    attestation: Attestation,
    verifier: Verifier,
) -> bool:
    """Verify an attestation against provenance data.

    Checks both the provenance digest and the signature.

    Args:
        provenance: The provenance the attestation claims to cover.
        attestation: The attestation to verify.
        verifier: A ``Verifier`` implementation.

    Returns:
        ``True`` if the digest matches and signature is valid.
    """
    canonical = canonicalize(provenance)
    digest = hashlib.sha256(canonical).hexdigest()

    if not hmac.compare_digest(digest, attestation.provenance_digest):
        return False

    return verifier.verify(canonical, attestation.signature)
