"""NANDA protocol integration.

Provides ``IntegrityExtension`` — a composite that combines provenance,
lineage, attestation, and governance into a single NANDA AgentFacts
extension block.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from nanda_integrity.attestation import Attestation
from nanda_integrity.governance import GovernanceReport
from nanda_integrity.lineage import ModelLineage
from nanda_integrity.provenance import ModelProvenance


@dataclass
class IntegrityExtension:
    """Complete model integrity block for NANDA AgentFacts.

    Combines provenance, lineage, attestation, and governance
    into a single extension that can be attached to AgentFacts
    metadata.

    Attributes:
        provenance: Model provenance metadata.
        lineage: Optional model lineage chain.
        attestation: Optional signed attestation.
        governance_report: Optional governance check results.
    """

    provenance: ModelProvenance
    lineage: ModelLineage | None = None
    attestation: Attestation | None = None
    governance_report: GovernanceReport | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        result: dict[str, Any] = {
            "provenance": self.provenance.to_dict(),
        }
        if self.lineage is not None:
            result["lineage"] = self.lineage.to_dict()
        if self.attestation is not None:
            result["attestation"] = self.attestation.to_dict()
        if self.governance_report is not None:
            result["governance"] = self.governance_report.to_dict()
        return result

    def to_agentfacts_extension(
        self,
        key: str = "x_model_integrity",
    ) -> dict[str, Any]:
        """Produce a complete integrity block for NANDA AgentFacts.

        Args:
            key: Extension key name.

        Returns:
            Dict suitable for merging into AgentFacts metadata.
        """
        return {key: self.to_dict()}

    def to_legacy_extension(self) -> dict[str, dict[str, str]]:
        """Produce a backward-compatible ``x_model_provenance`` block.

        Returns:
            Dict with ``x_model_provenance`` key for legacy consumers.
        """
        return self.provenance.to_agentfacts_extension("x_model_provenance")


def attach_to_agent_facts(
    metadata: dict[str, Any],
    extension: IntegrityExtension,
    *,
    key: str = "x_model_integrity",
    include_legacy: bool = False,
) -> dict[str, Any]:
    """Attach an integrity extension to AgentFacts metadata.

    Non-destructive merge — existing keys in *metadata* are preserved.

    Args:
        metadata: Existing AgentFacts metadata dict.
        extension: The integrity extension to attach.
        key: Extension key name.
        include_legacy: If True, also add ``x_model_provenance``.

    Returns:
        New dict with integrity extension merged in.
    """
    result = dict(metadata)
    result.update(extension.to_agentfacts_extension(key))
    if include_legacy:
        result.update(extension.to_legacy_extension())
    return result


def extract_from_agent_facts(
    metadata: dict[str, Any],
    *,
    key: str = "x_model_integrity",
) -> IntegrityExtension | None:
    """Extract an integrity extension from AgentFacts metadata.

    Args:
        metadata: AgentFacts metadata dict.
        key: Extension key to look for.

    Returns:
        ``IntegrityExtension`` if found, or ``None``.
    """
    block = metadata.get(key)
    if block is None:
        return None

    prov_data = block.get("provenance")
    if prov_data is None:
        return None

    provenance = ModelProvenance.from_dict(prov_data)

    lineage = None
    lineage_data = block.get("lineage")
    if lineage_data is not None:
        lineage = ModelLineage.from_dict(lineage_data)

    attestation = None
    att_data = block.get("attestation")
    if att_data is not None:
        attestation = Attestation.from_dict(att_data)

    return IntegrityExtension(
        provenance=provenance,
        lineage=lineage,
        attestation=attestation,
    )
