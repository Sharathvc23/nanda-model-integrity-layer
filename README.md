# NANDA Model Integrity Layer

A Python library for model integrity and trust in NANDA-compatible agent registries.

**[NANDA](https://projectnanda.org)** (Networked AI Agents in Decentralized Architecture) is the protocol for federated AI agent discovery and communication. This library provides the model integrity primitives — provenance tracking, weight hashing, signed attestations, lineage chains, and governance policy enforcement — for agents participating in the NANDA ecosystem.

## Features

- **Model Provenance** - Structured metadata for AI models (identity, versioning, provider, governance tier)
- **Integrity Hashing** - Cryptographic verification of model weights (SHA-256, SHA-384, SHA-512, BLAKE2b)
- **Signed Attestations** - HMAC-SHA256 signing and verification of provenance data
- **Lineage Tracking** - Derivation chains from base model to fine-tuned/quantized variants
- **Governance Policies** - Configurable policy engine with 6 built-in checks and preset rule sets
- **NANDA Integration** - First-class support for AgentFacts and AgentCard metadata extensions

## Installation

```bash
pip install nanda-model-integrity-layer
```

Or install from source:

```bash
git clone https://github.com/Sharathvc23/nanda-model-integrity-layer
cd nanda-model-integrity-layer
pip install -e .
```

## Quick Start

### Model Provenance

```python
from nanda_integrity import ModelProvenance

provenance = ModelProvenance(
    model_id="llama-3.1-8b",
    model_version="1.0.0",
    provider_id="ollama",
    model_type="base",
    governance_tier="standard",
    risk_level="low",
)

# Serialize (empty fields omitted)
provenance.to_dict()
# {'model_id': 'llama-3.1-8b', 'model_version': '1.0.0', ...}

# NANDA AgentFacts extension
provenance.to_agentfacts_extension()
# {'x_model_provenance': {'model_id': 'llama-3.1-8b', ...}}

# Round-trip
rebuilt = ModelProvenance.from_dict(provenance.to_dict())
assert rebuilt == provenance
```

### Integrity Verification

```python
from nanda_integrity import ModelProvenance, compute_weights_hash, verify_provenance_integrity

# Hash model weights
digest = compute_weights_hash("model.bin", "sha256")

# Create provenance with hash
provenance = ModelProvenance(
    model_id="my-model",
    weights_hash=digest,
    hash_algorithm="sha256",
)

# Verify later
result = verify_provenance_integrity(provenance, "model.bin")
print(result.valid)    # True
print(result.algorithm)  # "sha256"
```

### Signed Attestations

```python
from nanda_integrity import (
    ModelProvenance, HMACSigner, HMACVerifier,
    create_attestation, verify_attestation,
)

provenance = ModelProvenance(model_id="llama-3.1-8b", provider_id="ollama")

# Sign
signer = HMACSigner(b"shared-secret", signer_id="my-org")
attestation = create_attestation(provenance, signer)

# Verify
verifier = HMACVerifier(b"shared-secret")
assert verify_attestation(provenance, attestation, verifier)
```

### Lineage Tracking

```python
from nanda_integrity import ModelProvenance, ModelLineage

provenance = ModelProvenance(
    model_id="my-adapter",
    base_model="llama-3.1-8b",
    model_type="lora_adapter",
)

lineage = ModelLineage.from_provenance(provenance)
print(lineage.depth)              # 2
print(lineage.root.model_id)      # "llama-3.1-8b"
print(lineage.leaf.model_id)      # "my-adapter"
print(lineage.leaf.relation)      # "lora_adapter"
```

### Governance Checks

```python
from nanda_integrity import ModelProvenance, check_governance, REGULATED_POLICIES

provenance = ModelProvenance(
    model_id="test-model",
    weights_hash="abc123",
    governance_tier="regulated",
    risk_level="low",
    attestation_method="hmac-sha256",
)

# Standard policies (default)
report = check_governance(provenance)
print(report.passed)  # True

# Regulated policies (stricter)
report = check_governance(provenance, policies=list(REGULATED_POLICIES))
print(report.passed)       # True
print(len(report.results)) # 6
```

### NANDA Integration

```python
from nanda_integrity import (
    ModelProvenance, IntegrityExtension, ModelLineage,
    attach_to_agent_facts, extract_from_agent_facts,
)

provenance = ModelProvenance(model_id="my-model", provider_id="local")
lineage = ModelLineage.from_provenance(provenance)

extension = IntegrityExtension(provenance=provenance, lineage=lineage)

# Attach to agent metadata
metadata = {"name": "My Agent"}
enriched = attach_to_agent_facts(metadata, extension, include_legacy=True)
# enriched now has x_model_integrity and x_model_provenance keys

# Extract from metadata
extracted = extract_from_agent_facts(enriched)
assert extracted.provenance.model_id == "my-model"
```

## Module Reference

### `ModelProvenance` Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `model_id` | `str` | *(required)* | Model identifier |
| `model_version` | `str` | `""` | Version string |
| `provider_id` | `str` | `""` | Inference provider |
| `model_type` | `str` | `""` | Model category |
| `base_model` | `str` | `""` | Foundation model name |
| `governance_tier` | `str` | `""` | Governance classification |
| `weights_hash` | `str` | `""` | Hex digest of model weights |
| `risk_level` | `str` | `""` | Risk assessment |
| `hash_algorithm` | `str` | `""` | Algorithm for weights_hash |
| `created_at` | `str` | `""` | ISO 8601 timestamp |
| `attestation_method` | `str` | `""` | How provenance was attested |

### Enums

- `ModelType`: `base`, `lora_adapter`, `onnx_edge`, `federated`, `heuristic`, `quantized`, `distilled`, `merged`
- `GovernanceTier`: `standard`, `regulated`, `restricted`
- `RiskLevel`: `low`, `medium`, `high`, `critical`
- `HashAlgorithm`: `sha256`, `sha384`, `sha512`, `blake2b`
- `AttestationMethod`: `self-declared`, `hmac-sha256`, `ed25519`, `ecdsa-p256`
- `LineageRelation`: `fine_tuned`, `adapter`, `quantized`, `distilled`, `merged`

All enums are `str, Enum` subclasses — they compare equal to their string values.

### Built-in Governance Policies

| Policy | Description |
|--------|-------------|
| `RequireWeightsHash` | Provenance must include `weights_hash` |
| `RequireGovernanceTier` | Provenance must include `governance_tier` |
| `RequireRiskLevel` | Provenance must include `risk_level` |
| `MaxRiskLevel(level)` | `risk_level` must not exceed threshold |
| `RequireAttestation` | Provenance must include `attestation_method` |
| `RequireBaseModel` | Adapter types must include `base_model` |

Presets: `STANDARD_POLICIES` (3 policies), `REGULATED_POLICIES` (6 policies).

## Integration with nanda_bridge

```python
from nanda_integrity import (
    IntegrityExtension, ModelProvenance, ModelLineage,
    HMACSigner, create_attestation, check_governance,
    attach_to_agent_facts,
)

# Build integrity extension
provenance = ModelProvenance(
    model_id="my-agent-model",
    provider_id="local",
    governance_tier="standard",
    weights_hash="abc123",
)
lineage = ModelLineage.from_provenance(provenance)
attestation = create_attestation(provenance, HMACSigner(b"secret"))
report = check_governance(provenance)

extension = IntegrityExtension(
    provenance=provenance,
    lineage=lineage,
    attestation=attestation,
    governance_report=report,
)

# Attach to your agent's metadata
agent_metadata = attach_to_agent_facts(
    {"name": "My NANDA Agent"},
    extension,
    include_legacy=True,
)
# agent_metadata now includes x_model_integrity and x_model_provenance
```

## Related Packages

| Package | Question it answers |
|---------|-------------------|
| [`nanda-model-provenance`](https://github.com/Sharathvc23/nanda-model-provenance) | "Where did this model come from?" (identity, versioning, provider, NANDA serialization) |
| [`nanda-model-card`](https://github.com/Sharathvc23/model-card) | "What is this model?" (unified metadata schema — type, status, risk level, metrics, weights hash) |
| `nanda-model-integrity-layer` (this package) | "Does this model's metadata meet policy?" (rule-based checks) |
| [`nanda-model-governance`](https://github.com/Sharathvc23/nanda-governance) | "Has this model been cryptographically approved for deployment?" (approval flow with signatures, quorum, scoping, revocation) |
| [`nanda-bridge`](https://github.com/Sharathvc23/nanda-bridge) | "How do I expose this to the NANDA network?" (FastAPI router, AgentFacts models, delta sync) |

## Related Projects

- [Project NANDA](https://github.com/projnanda) - ProjectNANDA.org
- [NANDA Adapter](https://github.com/projnanda/adapter) - Official NANDA SDK
- [NANDA Quilt](https://github.com/aidecentralized/NANDA-Quilt-of-Registries-and-Verified-AgentFacts) - Federated registry specification

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

Contributions welcome! Please read our contributing guidelines and submit pull requests.

## Credits

Developed by [stellarminds.ai](https://stellarminds.ai) 
