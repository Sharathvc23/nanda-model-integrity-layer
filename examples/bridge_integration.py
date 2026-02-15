"""NANDA bridge integration example.

Demonstrates using IntegrityExtension with AgentFacts metadata,
including lineage tracking and governance checks.
"""

from nanda_integrity import (
    HMACSigner,
    IntegrityExtension,
    ModelLineage,
    ModelProvenance,
    attach_to_agent_facts,
    check_governance,
    create_attestation,
    extract_from_agent_facts,
)

# 1. Create provenance for a fine-tuned model
provenance = ModelProvenance(
    model_id="my-legal-advisor-v2",
    model_version="2.1.0",
    provider_id="local",
    model_type="lora_adapter",
    base_model="llama-3.1-8b",
    governance_tier="regulated",
    risk_level="medium",
    hash_algorithm="sha256",
    weights_hash="a1b2c3d4e5f6",
    attestation_method="hmac-sha256",
)

# 2. Build lineage
lineage = ModelLineage.from_provenance(provenance)
print(f"Lineage depth: {lineage.depth}")
for node in lineage.nodes:
    print(f"  {node.model_id} (relation={node.relation or 'root'})")

# 3. Sign an attestation
signer = HMACSigner(b"org-secret", signer_id="legal-team")
attestation = create_attestation(provenance, signer)

# 4. Run governance checks
report = check_governance(provenance)
print(f"\nGovernance: {'PASS' if report.passed else 'FAIL'}")
for r in report.results:
    print(f"  {r.policy_name}: {'PASS' if r.passed else 'FAIL'} - {r.message}")

# 5. Build the complete integrity extension
extension = IntegrityExtension(
    provenance=provenance,
    lineage=lineage,
    attestation=attestation,
    governance_report=report,
)

# 6. Attach to AgentFacts metadata (simulating nanda_bridge usage)
agent_metadata = {
    "name": "Legal Advisor Agent",
    "version": "2.1.0",
}
enriched = attach_to_agent_facts(
    agent_metadata, extension, include_legacy=True
)

print("\nEnriched metadata keys:", list(enriched.keys()))
print("Has x_model_integrity:", "x_model_integrity" in enriched)
print("Has x_model_provenance:", "x_model_provenance" in enriched)

# 7. Extract back (simulating a consumer)
extracted = extract_from_agent_facts(enriched)
if extracted:
    print(f"\nExtracted model: {extracted.provenance.model_id}")
    print(f"Has lineage: {extracted.lineage is not None}")
    print(f"Has attestation: {extracted.attestation is not None}")
