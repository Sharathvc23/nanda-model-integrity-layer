"""Shared enums for the nanda_integrity package."""

from __future__ import annotations

from enum import Enum


class ModelType(str, Enum):
    """Model category classification."""

    BASE = "base"
    LORA_ADAPTER = "lora_adapter"
    ONNX_EDGE = "onnx_edge"
    FEDERATED = "federated"
    HEURISTIC = "heuristic"
    QUANTIZED = "quantized"
    DISTILLED = "distilled"
    MERGED = "merged"


class GovernanceTier(str, Enum):
    """Governance classification level."""

    STANDARD = "standard"
    REGULATED = "regulated"
    RESTRICTED = "restricted"


class RiskLevel(str, Enum):
    """Risk assessment level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HashAlgorithm(str, Enum):
    """Supported hash algorithms."""

    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    BLAKE2B = "blake2b"


class AttestationMethod(str, Enum):
    """Supported attestation methods."""

    SELF_DECLARED = "self-declared"
    HMAC_SHA256 = "hmac-sha256"
    ED25519 = "ed25519"
    ECDSA_P256 = "ecdsa-p256"


class LineageRelation(str, Enum):
    """Relationship between a derived model and its parent."""

    FINE_TUNED = "fine_tuned"
    ADAPTER = "adapter"
    QUANTIZED = "quantized"
    DISTILLED = "distilled"
    MERGED = "merged"
