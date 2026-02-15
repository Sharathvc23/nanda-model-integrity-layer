# A Modular Integrity Stack for Decentralized AI Agent Registries

**Authors:** StellarMinds ([stellarminds.ai](https://stellarminds.ai))
**Date:** February 2026
**Version:** 1.0

## Abstract

As AI agents proliferate across decentralized registries, verifying the integrity of model metadata — weights hashes, provenance claims, and governance attestations — becomes an increasingly important infrastructure concern. Existing supply-chain security frameworks primarily target build artifacts and container images, leaving a potential gap for ML-specific metadata integrity. This paper presents `nanda-model-integrity-layer`, a zero-dependency, protocol-based integrity verification stack for the NANDA agent ecosystem. The library provides pluggable hash providers supporting SHA-256, SHA-384, SHA-512, and BLAKE2b; HMAC-SHA256 attestation with canonical JSON serialization and timing-safe verification; model lineage chain reconstruction from provenance records; a configurable governance policy engine with six built-in rules and two preset policy sets; and a composite `IntegrityExtension` type for embedding integrity metadata into NANDA AgentFacts. All extension points are defined as `@runtime_checkable` protocols, enabling structural subtyping without inheritance. The implementation uses only the Python standard library, ships with 75+ tests across seven modules, and integrates with both the `nanda-model-card` metadata schema and the `nanda-model-governance` cryptographic approval layer.

## 1. Introduction

### 1.1 Problem Statement

Decentralized AI agent registries face a trust problem: when an agent advertises model capabilities — accuracy metrics, training provenance, governance tier — how can a consuming agent or orchestrator verify these claims? Without integrity verification, a registry may become vulnerable to:

- **Metadata tampering** — an attacker modifies the `weights_hash` after training to substitute a different model.
- **Provenance forgery** — false claims about training data, base models, or governance approval status.
- **Policy non-compliance** — models that lack required attestations or exceed risk thresholds entering production undetected.

### 1.2 Motivation

The NANDA ecosystem requires an integrity layer that is:

1. **Modular** — each concern (hashing, attestation, lineage, governance) can be used independently or composed.
2. **Protocol-based** — extension points use structural subtyping, allowing custom implementations without inheriting from framework classes.
3. **Zero-dependency** — the core library must function in constrained environments (edge devices, CI pipelines, serverless functions) without pulling in heavy cryptographic dependencies.
4. **Standard-aligned** — compatible with established supply-chain security concepts from SLSA, in-toto, and NIST frameworks.

### 1.3 Contributions

This paper makes the following contributions:

- A **pluggable hash provider architecture** with a `HashProvider` protocol supporting four algorithms and streaming file hashing with configurable chunk sizes.
- An **HMAC-SHA256 attestation system** using canonical JSON serialization for deterministic signing and timing-safe verification to prevent side-channel attacks.
- A **lineage chain data structure** that reconstructs model derivation histories from provenance records, supporting fine-tuned, adapter, quantized, distilled, and merged relationships.
- A **governance policy engine** with six built-in policies, two preset rule sets (standard and regulated), and a `GovernancePolicy` protocol for custom extensions.
- A **composite integration type** (`IntegrityExtension`) that bundles provenance, lineage, attestation, and governance into NANDA-compatible agent metadata.

## 2. Related Work

### 2.1 SLSA (Supply-chain Levels for Software Artifacts)

The SLSA framework defines four levels of supply-chain security, from basic provenance logging (L1) to hermetic builds with two-party review (L4). SLSA targets software build artifacts — source code, build configurations, container images — rather than ML model metadata. While SLSA's provenance model informs this work's attestation design, ML models benefit from domain-specific integrity checks (weight hash verification, governance tier enforcement, lineage tracking) that are not currently addressed by SLSA.

### 2.2 in-toto

in-toto provides a framework for securing the entire software supply chain by defining expected steps and their functionaries. Each step produces a signed link metadata file. The framework is powerful for multi-step build pipelines but requires a predefined supply chain layout. ML model lifecycles tend to be more fluid — a model may be fine-tuned, quantized, and merged in various orders — making rigid step definitions less practical in some workflows.

### 2.3 Sigstore

Sigstore provides keyless signing and transparency logging for software artifacts. Its cosign tool signs container images, and Rekor provides an immutable transparency log. While Sigstore's approach to transparent attestation is influential, it is primarily designed around OCI (Open Container Initiative) artifacts and PKI infrastructure that may not be available in all agent deployment environments.

### 2.4 NIST AI Risk Management Framework (AI RMF)

NIST AI RMF 1.0 (2023) provides a voluntary framework for managing AI risks, organized around Govern, Map, Measure, and Manage functions. The framework emphasizes documentation, transparency, and accountability but does not currently prescribe specific technical mechanisms for integrity verification at the implementation level. This work aims to provide concrete tooling that can support NIST AI RMF's Govern and Measure functions through automated policy checks and provenance attestation.

### 2.5 Gaps Addressed

This work addresses three gaps in the existing landscape:

1. **ML-specific integrity primitives** — weight hash verification, model lineage chains, and governance tier enforcement as first-class operations.
2. **Protocol-based extensibility** — allowing custom hash providers, signers, verifiers, and policies without framework lock-in.
3. **Zero-dependency composability** — enabling deployment in environments where SLSA, in-toto, or Sigstore toolchains cannot be installed.

## 3. Design / Architecture

### 3.1 Layered Architecture

The library is organized into five composable layers, each independent but designed for composition:

```
┌─────────────────────────────────────────────┐
│          NANDA Integration (nanda.py)        │  AgentFacts, IntegrityExtension
├─────────────────────────────────────────────┤
│        Governance Policies (governance.py)   │  6 built-in, 2 presets
├─────────────────────────────────────────────┤
│       Lineage Tracking (lineage.py)          │  LineageNode, ModelLineage
├─────────────────────────────────────────────┤
│     Attestation (attestation.py)             │  HMAC-SHA256, canonical JSON
├─────────────────────────────────────────────┤
│       Hashing (hashing.py)                   │  SHA-256/384/512, BLAKE2b
├─────────────────────────────────────────────┤
│     Provenance (provenance.py)               │  ModelProvenance dataclass
├─────────────────────────────────────────────┤
│        Types & Compatibility                 │  Enums, optional dep detection
└─────────────────────────────────────────────┘
```

Each layer depends only on layers below it. The hashing layer has no internal dependencies beyond Python's `hashlib`; the attestation layer depends on hashing and provenance; the governance layer depends on provenance; and the NANDA integration layer composes all of the above.

### 3.2 Protocol-Based Extensibility

All extension points are defined as `@runtime_checkable` Python protocols, enabling structural subtyping (duck typing with static analysis support):

| Protocol | Methods | Purpose |
|----------|---------|---------|
| `HashProvider` | `hash_bytes()`, `hash_file()`, `supported_algorithms` | Pluggable hash computation |
| `Signer` | `sign()`, `method`, `signer_id` | Pluggable attestation signing |
| `Verifier` | `verify()` | Pluggable signature verification |
| `GovernancePolicy` | `check()`, `name` | Custom governance rules |

This design allows users to inject custom implementations (e.g., HSM-backed signers, cloud KMS hash providers) without subclassing any library type. A class that implements the required methods satisfies the protocol, verified at runtime via `isinstance()`.

### 3.3 Provenance Data Model

The `ModelProvenance` dataclass captures 11 metadata fields:

| Field | Type | Description |
|-------|------|-------------|
| `model_id` | `str` | Model identifier (required) |
| `model_version` | `str` | Semantic or arbitrary version string |
| `provider_id` | `str` | Inference provider (e.g., openai, ollama, local) |
| `model_type` | `str` | Category (base, lora_adapter, quantized, etc.) |
| `base_model` | `str` | Foundation model for derived models |
| `governance_tier` | `str` | Governance level (standard, regulated, restricted) |
| `weights_hash` | `str` | Hex digest of model weights |
| `risk_level` | `str` | Risk assessment (low, medium, high, critical) |
| `hash_algorithm` | `str` | Algorithm for weights_hash |
| `created_at` | `str` | ISO 8601 creation timestamp |
| `attestation_method` | `str` | How provenance was attested |

Empty-string fields are omitted during serialization (`to_dict()`), producing compact representations suitable for network transmission.

### 3.4 Type System

The library defines six string enumerations for type-safe field values:

- **`ModelType`** — base, lora_adapter, onnx_edge, federated, heuristic, quantized, distilled, merged
- **`GovernanceTier`** — standard, regulated, restricted
- **`RiskLevel`** — low, medium, high, critical
- **`HashAlgorithm`** — sha256, sha384, sha512, blake2b
- **`AttestationMethod`** — self-declared, hmac-sha256, ed25519, ecdsa-p256
- **`LineageRelation`** — fine_tuned, adapter, quantized, distilled, merged

All enums inherit from `(str, Enum)`, ensuring they compare equal to their string values and serialize naturally to JSON.

## 4. Implementation

### 4.1 Hash Provider

The `HashProvider` protocol defines three methods:

```python
@runtime_checkable
class HashProvider(Protocol):
    def hash_bytes(self, data: bytes, algorithm: str) -> str: ...
    def hash_file(self, path: Path, algorithm: str) -> str: ...
    @property
    def supported_algorithms(self) -> frozenset[str]: ...
```

The `StdlibHashProvider` implementation supports four algorithms: `sha256`, `sha384`, `sha512`, and `blake2b`. File hashing uses **64 KiB streaming chunks** (`_CHUNK_SIZE = 1 << 16`) to maintain constant memory usage regardless of model file size — an important property when verifying multi-gigabyte weight files.

Three convenience functions wrap the provider for common operations:

- `compute_weights_hash(path, algorithm="sha256")` — computes a model file's hash digest.
- `verify_integrity(path, expected_hash, algorithm="sha256")` — compares a file's computed hash against an expected value, returning an `IntegrityResult`.
- `verify_provenance_integrity(provenance, path)` — reads the hash algorithm and expected hash from a `ModelProvenance` record and verifies the corresponding file.

The `IntegrityResult` is a frozen dataclass capturing the verification outcome (`valid`, `expected_hash`, `computed_hash`, `algorithm`), providing a structured record for audit logging.

### 4.2 HMAC-SHA256 Attestation

#### 4.2.1 Canonical Serialization

Attestation signing requires a deterministic byte representation of provenance metadata. The `canonicalize()` function produces this:

```python
def canonicalize(provenance: ModelProvenance) -> bytes:
    return json.dumps(
        provenance.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
```

Three properties ensure determinism: `sort_keys=True` normalizes key order; compact `separators` eliminate whitespace; and `ensure_ascii=True` prevents encoding-dependent variation. The `to_dict()` method's omit-when-empty behavior means the canonical form includes only populated fields.

#### 4.2.2 Signing and Verification

The `Signer` and `Verifier` protocols decouple signing from specific cryptographic backends:

```python
@runtime_checkable
class Signer(Protocol):
    @property
    def method(self) -> str: ...
    @property
    def signer_id(self) -> str: ...
    def sign(self, data: bytes) -> str: ...
```

The `HMACSigner` implementation uses `hmac.new(secret, data, hashlib.sha256).hexdigest()`, while `HMACVerifier` uses `hmac.compare_digest()` for **timing-safe comparison**, preventing side-channel attacks that could leak information about valid signatures through response time analysis.

#### 4.2.3 Attestation Record

The `create_attestation()` function orchestrates the signing workflow:

1. Canonicalize the provenance to bytes.
2. Compute the SHA-256 digest of the canonical representation.
3. Sign the canonical bytes using the provided `Signer`.
4. Package the digest, signature, signer identity, and timestamp into a frozen `Attestation` dataclass.

The `verify_attestation()` function reverses this process, recomputing the canonical bytes and digest, then checking both the digest match (via `hmac.compare_digest`) and the signature validity.

### 4.3 Lineage Chain Reconstruction

The `ModelLineage` class maintains an ordered list of `LineageNode` objects representing a model's derivation history:

```python
@dataclass
class LineageNode:
    model_id: str
    relation: str = ""       # fine_tuned, adapter, quantized, etc.
    parent_id: str = ""      # Parent model identifier
    metadata: dict[str, str] = field(default_factory=dict)
```

The `ModelLineage` class provides:

- **`add(node)`** — appends a node to the chain.
- **`ancestors(model_id)`** — walks backward through `parent_id` references to reconstruct the derivation path from root to the specified node.
- **`root` / `leaf`** — properties returning the first and last nodes.
- **`depth`** — the number of nodes in the chain.

The `from_provenance()` class method automatically constructs a lineage from a provenance record: if only `model_id` is set, a single root node is created; if `base_model` is also set, a two-node chain is created with the appropriate `relation` derived from the `model_type` field.

The `to_agentfacts_extension()` method serializes the lineage under the `x_model_lineage` key for embedding in NANDA agent metadata.

### 4.4 Governance Policy Engine

#### 4.4.1 Policy Protocol

The `GovernancePolicy` protocol requires two members:

```python
@runtime_checkable
class GovernancePolicy(Protocol):
    @property
    def name(self) -> str: ...
    def check(self, provenance: ModelProvenance) -> PolicyResult: ...
```

Each policy's `check()` method returns a frozen `PolicyResult(passed, policy_name, message)`.

#### 4.4.2 Built-in Policies

Six policies ship with the library:

| Policy | Rule | Failure Condition |
|--------|------|-------------------|
| `RequireWeightsHash` | Weights hash must be non-empty | `provenance.weights_hash == ""` |
| `RequireGovernanceTier` | Governance tier must be set | `provenance.governance_tier == ""` |
| `RequireRiskLevel` | Risk level must be set | `provenance.risk_level == ""` |
| `MaxRiskLevel(max)` | Risk must not exceed ceiling | `risk_order[level] > risk_order[max]` |
| `RequireAttestation` | Attestation method must be set | `provenance.attestation_method == ""` |
| `RequireBaseModel` | Adapter types need a base model | `type ∈ {adapter, lora_adapter, fine_tuned}` and `base_model == ""` |

The `MaxRiskLevel` policy uses an ordinal mapping (`low=0, medium=1, high=2, critical=3`) to enforce risk ceilings without string comparison.

#### 4.4.3 Preset Policy Sets

Two preset configurations provide common compliance profiles:

- **`STANDARD_POLICIES`** — `RequireWeightsHash`, `RequireGovernanceTier`, `RequireBaseModel`. Suitable for internal registries with moderate trust requirements.
- **`REGULATED_POLICIES`** — All six policies. Suitable for regulated environments requiring full attestation, risk assessment, and governance classification.

#### 4.4.4 Policy Execution

The `check_governance()` function executes a policy set against a provenance record and returns a `GovernanceReport`:

```python
def check_governance(provenance, policies=None) -> GovernanceReport:
```

The report aggregates all `PolicyResult` objects, exposes a `passed` boolean (True only if all policies pass), and provides a `failures` tuple for targeted remediation.

### 4.5 NANDA Integration

The `IntegrityExtension` dataclass composes all integrity components:

```python
@dataclass
class IntegrityExtension:
    provenance: ModelProvenance
    lineage: ModelLineage | None = None
    attestation: Attestation | None = None
    governance_report: GovernanceReport | None = None
```

Two functions manage the attachment lifecycle:

- **`attach_to_agent_facts(metadata, extension)`** — non-destructive merge into an agent's metadata dictionary, preserving existing keys. Supports both the modern `x_model_integrity` key and a legacy `x_model_provenance` key for backward compatibility.
- **`extract_from_agent_facts(metadata)`** — reconstructs an `IntegrityExtension` from agent metadata, handling optional lineage and attestation components gracefully.

The `ModelProvenance` class provides additional serialization methods for NANDA integration:

- `to_agentfacts_extension()` — wraps under `x_model_provenance`.
- `to_agent_card_metadata()` — wraps under `model_info`.
- `to_decision_fields()` — extracts only `model_id`, `model_version`, and `provider_id` for decision-envelope records.

## 5. Integration

### 5.1 NANDA Ecosystem Context

The `nanda-model-integrity-layer` occupies the **verification layer** in the NANDA ecosystem, answering the question: *"Does this model's metadata meet policy?"*

| Package | Role | Question Answered |
|---------|------|-------------------|
| `nanda-model-card` | Metadata schema | What is this model? |
| `nanda-model-integrity-layer` | Integrity verification | Does this model's metadata meet policy? |
| `nanda-model-governance` | Cryptographic governance | Has this model been approved? |

### 5.2 Integration with the Model Card Schema

The `nanda-model-card` package defines the `ModelCard` dataclass — the upstream metadata source. The integrity layer consumes model card fields through its `ModelProvenance` type:

- **`ModelCard.weights_hash`** maps to **`ModelProvenance.weights_hash`**, enabling hash verification through `verify_provenance_integrity()`.
- **`ModelCard.model_type`** maps to **`ModelProvenance.model_type`**, driving governance policies like `RequireBaseModel` that enforce paradigm-specific invariants.
- **`ModelCard.risk_level`** maps to **`ModelProvenance.risk_level`**, enabling the `MaxRiskLevel` policy to enforce risk ceilings.
- **`ModelCard.dataset_hash`** (produced by `compute_dataset_hash()`) provides a training data fingerprint that can be cross-referenced in lineage metadata.

The integrity layer's `ModelLineage.from_provenance()` mirrors the model card's `base_model` and `model_type` fields to construct derivation chains automatically.

### 5.3 Integration with the Governance Layer

The `nanda-model-governance` package consumes integrity verification results at several points:

- **Pre-governance checks** — Before a model enters the governance pipeline, the integrity layer's `check_governance()` can validate that required metadata fields are present and within policy bounds.
- **Attestation bridging** — The governance layer's `approval_to_integrity_facts()` function converts a `ModelApproval` record into integrity-layer-compatible metadata, creating a verifiable link between cryptographic approval and provenance claims.
- **Composite extension** — The `IntegrityExtension` type can carry both an `attestation` (from the integrity layer's HMAC signing) and a `governance_report`, bundling multi-layer verification results into a single agent metadata payload.

### 5.4 Agent Discovery Workflow

In a typical NANDA agent discovery flow, the integrity layer participates as follows:

1. **Model registration** — A model's `ModelProvenance` is created, attested via HMAC-SHA256, and attached to the agent's metadata using `attach_to_agent_facts()`.
2. **Policy verification** — A discovering agent extracts the integrity extension via `extract_from_agent_facts()` and runs `check_governance()` against its local policy set.
3. **Weight verification** — If the discovering agent has access to the model file, `verify_provenance_integrity()` confirms the weights match the advertised hash.
4. **Lineage inspection** — The discovering agent can traverse the lineage chain to verify the model's derivation history.

## 6. Evaluation

### 6.1 Test Coverage

The test suite contains **75+ test methods** across seven test modules:

| Test Module | Tests | Coverage Area |
|-------------|:-----:|---------------|
| `test_provenance.py` | 14 | Serialization, AgentFacts, decision fields, round-trip |
| `test_hashing.py` | ~12 | All 4 algorithms, file integrity, provenance verification |
| `test_attestation.py` | 16 | Protocols, HMAC, canonicalization, tamper detection |
| `test_lineage.py` | 20 | Node operations, chain traversal, provenance reconstruction |
| `test_governance.py` | 28 | All 6 policies, presets, report aggregation |
| `test_nanda.py` | 16 | IntegrityExtension, attach/extract round-trip |
| `test_json_shapes.py` | 11 | Golden-file protocol validation |

Test types include unit tests, integration tests (round-trip serialization), protocol conformance tests (`isinstance` checks against `@runtime_checkable` protocols), golden-file tests (JSON shape validation), and tamper detection tests (verifying that modified provenance records fail attestation).

### 6.2 Example: End-to-End Integrity Verification

```python
from nanda_integrity import (
    ModelProvenance, StdlibHashProvider,
    compute_weights_hash, verify_provenance_integrity,
    HMACSigner, HMACVerifier,
    create_attestation, verify_attestation,
    ModelLineage,
    check_governance, REGULATED_POLICIES,
    IntegrityExtension, attach_to_agent_facts,
)

# 1. Compute weights hash
provider = StdlibHashProvider()
weights_hash = compute_weights_hash("model.bin", provider=provider)

# 2. Create provenance
provenance = ModelProvenance(
    model_id="sentiment-v3",
    model_version="3.0.0",
    model_type="lora_adapter",
    base_model="llama-3.1-8b",
    governance_tier="regulated",
    weights_hash=weights_hash,
    risk_level="low",
    hash_algorithm="sha256",
    attestation_method="hmac-sha256",
)

# 3. Sign attestation
signer = HMACSigner(secret=b"shared-secret", signer_id="ci-pipeline")
attestation = create_attestation(provenance, signer)

# 4. Verify attestation
verifier = HMACVerifier(secret=b"shared-secret")
assert verify_attestation(provenance, attestation, verifier)

# 5. Build lineage
lineage = ModelLineage.from_provenance(provenance)
assert lineage.depth == 2  # base → fine-tuned

# 6. Check governance policies
report = check_governance(provenance, REGULATED_POLICIES)
assert report.passed

# 7. Bundle and attach to agent metadata
extension = IntegrityExtension(
    provenance=provenance,
    lineage=lineage,
    attestation=attestation,
    governance_report=report,
)
agent_metadata = attach_to_agent_facts({}, extension)
```

### 6.3 Performance Characteristics

- **File hashing** — Streams in 64 KiB chunks; memory usage is O(1) regardless of file size.
- **Canonicalization** — O(n log n) due to JSON key sorting, where n is the number of provenance fields (constant at 11).
- **HMAC signing/verification** — O(m) where m is the canonical byte length (typically < 1 KiB).
- **Policy execution** — O(p) where p is the number of policies (6 for regulated, 3 for standard).

## 7. Conclusion

### 7.1 Summary

This paper presented `nanda-model-integrity-layer`, a modular integrity verification stack designed for the specific needs of AI agent registries. By implementing hashing, attestation, lineage tracking, and governance policy checking as composable, protocol-based layers, the library provides ML-specific integrity primitives without imposing heavyweight dependencies or framework lock-in. The protocol-based design is intended to allow each component to be extended or replaced independently, while the zero-dependency core enables deployment across the full spectrum of environments from edge devices to cloud orchestrators.

### 7.2 Future Work

Several extensions are under consideration:

- **Ed25519 and ECDSA attestation** — The `AttestationMethod` enum already includes `ed25519` and `ecdsa-p256` values; implementing corresponding `Signer` and `Verifier` types would provide asymmetric signing for environments where shared secrets are impractical.
- **Transparency logging** — Integrating with append-only transparency logs (inspired by Sigstore's Rekor) to provide tamper-evident provenance records.
- **Multi-model lineage** — Extending the `ModelLineage` structure to support directed acyclic graphs (DAGs) for merged models with multiple parents.
- **Policy composition operators** — Adding AND/OR/NOT combinators for governance policies, enabling complex compliance rules from simple primitives.
- **Streaming attestation** — Signing provenance updates incrementally as model metadata evolves through the lifecycle, rather than attesting only at a single point in time.

## References

1. SLSA. "Supply-chain Levels for Software Artifacts." https://slsa.dev

2. Torres-Arias, S., Afzali, H., Kuppusamy, T.K., Curtmola, R., and Cappos, J. (2019). "in-toto: Providing farm-to-table guarantees for bits and bytes." *Proceedings of the 28th USENIX Security Symposium*, pp. 1393–1410.

3. Sigstore. "Software Signing for Everyone." https://sigstore.dev

4. National Institute of Standards and Technology. (2023). "Artificial Intelligence Risk Management Framework (AI RMF 1.0)." NIST AI 100-1.

5. Mitchell, M., Wu, S., Zaldivar, A., Barnes, P., Vasserman, L., Hutchinson, B., Spitzer, E., Raji, I.D., and Gebru, T. (2019). "Model Cards for Model Reporting." *Proceedings of the Conference on Fairness, Accountability, and Transparency (FAT\*)*, pp. 220–229.

6. NANDA Protocol. "Network for Agent Discovery and Attestation." https://projectnanda.org

7. Krawczyk, H., Bellare, M., and Canetti, R. (1997). "HMAC: Keyed-Hashing for Message Authentication." RFC 2104. Internet Engineering Task Force.
