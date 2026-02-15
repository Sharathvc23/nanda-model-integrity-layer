"""Model provenance metadata for NANDA agent discovery.

Provides a single ``ModelProvenance`` dataclass that encapsulates
model-related metadata for surfacing in NANDA AgentFacts and AgentCard
outputs.  Zero runtime dependencies — works with any NANDA-compatible
agent framework.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ModelProvenance:
    """Model provenance metadata for NANDA agent discovery.

    Aligns with the ``model_info`` schema used by NANDA-compatible
    agent registries for surfacing AI model details in AgentFacts
    and AgentCard metadata.

    Only ``model_id`` is required.  All other fields default to empty
    strings and are omitted from serialized output when empty.

    Attributes:
        model_id: Model identifier (e.g. ``"llama-3.1-8b"``).
        model_version: Semantic or arbitrary version string.
        provider_id: Inference provider (e.g. ``"openai"``, ``"ollama"``,
            ``"local"``).
        model_type: Model category — ``"base"``, ``"lora_adapter"``,
            ``"onnx_edge"``, ``"federated"``, or ``"heuristic"``.
        base_model: Foundation model name when ``model_type`` is an adapter.
        governance_tier: Governance classification — ``"standard"``,
            ``"regulated"``, or ``"restricted"``.
        weights_hash: Hex digest of model weights (optional).
        risk_level: Risk assessment — ``"low"``, ``"medium"``, ``"high"``,
            or ``"critical"`` (optional).
        hash_algorithm: Algorithm used for weights_hash (e.g. ``"sha256"``,
            ``"blake2b"``).
        created_at: ISO 8601 timestamp of provenance creation.
        attestation_method: How provenance was attested (e.g.
            ``"self-declared"``, ``"hmac-sha256"``).
    """

    model_id: str
    model_version: str = ""
    provider_id: str = ""
    model_type: str = ""
    base_model: str = ""
    governance_tier: str = ""
    weights_hash: str = ""
    risk_level: str = ""
    hash_algorithm: str = ""
    created_at: str = ""
    attestation_method: str = ""

    # -- Serialization ------------------------------------------------

    def to_dict(self) -> dict[str, str]:
        """Serialize to dict, omitting empty-string fields.

        Returns:
            Dict with only non-empty field values.
        """
        return {
            k: v
            for k, v in {
                "model_id": self.model_id,
                "model_version": self.model_version,
                "provider_id": self.provider_id,
                "model_type": self.model_type,
                "base_model": self.base_model,
                "governance_tier": self.governance_tier,
                "weights_hash": self.weights_hash,
                "risk_level": self.risk_level,
                "hash_algorithm": self.hash_algorithm,
                "created_at": self.created_at,
                "attestation_method": self.attestation_method,
            }.items()
            if v
        }

    def to_agentfacts_extension(
        self,
        extension_key: str = "x_model_provenance",
    ) -> dict[str, dict[str, str]]:
        """Produce metadata extension for NANDA AgentFacts.

        The default key ``x_model_provenance`` follows the NANDA ``x_``
        prefix convention for vendor extensions.

        Args:
            extension_key: Top-level key in AgentFacts metadata.

        Returns:
            Dict suitable for merging into ``AgentFacts.metadata``.
        """
        return {extension_key: self.to_dict()}

    def to_agent_card_metadata(self) -> dict[str, dict[str, str]]:
        """Produce ``model_info`` for NANDA AgentCard metadata.

        Returns:
            Dict with ``"model_info"`` key containing provenance fields.
        """
        return {"model_info": self.to_dict()}

    def to_decision_fields(self) -> dict[str, str]:
        """Produce flat fields for decision-envelope style records.

        Only emits ``model_id``, ``model_version``, and ``provider_id``
        — matching the top-level provenance fields used in decision
        envelopes (omit-when-falsy).

        Returns:
            Dict with top-level provenance fields.
        """
        result: dict[str, str] = {}
        if self.model_id:
            result["model_id"] = self.model_id
        if self.model_version:
            result["model_version"] = self.model_version
        if self.provider_id:
            result["provider_id"] = self.provider_id
        return result

    # -- Deserialization ----------------------------------------------

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> ModelProvenance:
        """Construct from a dict (e.g. parsed JSON).

        Unknown keys are silently ignored so the library is
        forward-compatible with future field additions.

        Args:
            data: Dict with provenance fields.

        Returns:
            New ``ModelProvenance`` instance.

        Raises:
            TypeError: If ``model_id`` is missing from *data*.
        """
        if "model_id" not in data:
            msg = "model_id is required"
            raise TypeError(msg)
        return cls(
            model_id=data["model_id"],
            model_version=data.get("model_version", ""),
            provider_id=data.get("provider_id", ""),
            model_type=data.get("model_type", ""),
            base_model=data.get("base_model", ""),
            governance_tier=data.get("governance_tier", ""),
            weights_hash=data.get("weights_hash", ""),
            risk_level=data.get("risk_level", ""),
            hash_algorithm=data.get("hash_algorithm", ""),
            created_at=data.get("created_at", ""),
            attestation_method=data.get("attestation_method", ""),
        )
