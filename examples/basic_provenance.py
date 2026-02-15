"""Basic provenance metadata example.

Demonstrates creating, serializing, and deserializing ModelProvenance.
"""

from nanda_integrity import ModelProvenance

# Create provenance with model details
provenance = ModelProvenance(
    model_id="llama-3.1-8b",
    model_version="1.0.0",
    provider_id="ollama",
    model_type="base",
    governance_tier="standard",
    risk_level="low",
)

# Serialize to dict (omits empty fields)
print("Provenance dict:")
print(provenance.to_dict())

# Produce NANDA AgentFacts extension
print("\nAgentFacts extension:")
print(provenance.to_agentfacts_extension())

# Produce AgentCard metadata
print("\nAgentCard metadata:")
print(provenance.to_agent_card_metadata())

# Round-trip via from_dict
rebuilt = ModelProvenance.from_dict(provenance.to_dict())
assert rebuilt == provenance
print("\nRound-trip: OK")
