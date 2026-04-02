# Model Integrity Verification for Decentralized Agent Registries

**Authors:** StellarMinds ([stellarminds.ai](https://stellarminds.ai))
**Date:** April 2026
**Version:** 0.2.0

## Abstract

`nanda-model-integrity-layer` is a zero-dependency, protocol-based integrity verification stack for the NANDA agent ecosystem. It solves the problem of verifying model metadata claims (weights hashes, provenance, governance attestations) in decentralized registries where no single authority controls trust. The library provides 5 composable layers spanning hashing, attestation, lineage tracking, and governance policy enforcement, with all extension points defined as `@runtime_checkable` protocols. The implementation uses only the Python standard library.

## Problem

Decentralized AI agent registries face a trust problem: when an agent advertises model capabilities, consuming agents have no way to verify claims about accuracy metrics, training provenance, or governance status. Without integrity verification primitives, registries become vulnerable to metadata tampering, provenance forgery, and policy non-compliance. Existing supply-chain security frameworks (SLSA, in-toto, Sigstore) target build artifacts and container images, leaving a gap for ML-specific metadata integrity.

## What It Does

- Provides pluggable hash providers supporting SHA-256, SHA-384, SHA-512, and BLAKE2b with streaming file hashing in 64 KiB chunks for O(1) memory
- Implements HMAC-SHA256 attestation with canonical JSON serialization (sorted keys, compact separators, ASCII-safe) and timing-safe verification via `hmac.compare_digest()`
- Reconstructs model lineage chains from provenance records with support for fine-tuned, adapter, quantized, distilled, and merged relationships
- Enforces 6 governance policies: RequireWeightsHash, RequireGovernanceTier, RequireRiskLevel, MaxRiskLevel (ordinal comparison), RequireAttestation, RequireBaseModel (adapter-type check)
- Ships 2 preset policy sets: standard (3 rules for internal registries) and regulated (all 6 rules for compliance environments)
- Bundles all components into an `IntegrityExtension` composite type for embedding in NANDA AgentFacts metadata via `attach_to_agent_facts()` and `extract_from_agent_facts()`
- Defines 4 protocol extension points: `HashProvider`, `Signer`, `Verifier`, `GovernancePolicy`
- Requires zero external dependencies

## Architecture

The library is organized into 5 composable layers, each depending only on layers below it:

```
┌─────────────────────────────────────────────┐
│     NANDA Integration (nanda.py)            │  IntegrityExtension, attach/extract
├─────────────────────────────────────────────┤
│     Governance Policies (governance.py)     │  6 built-in rules, 2 presets
├─────────────────────────────────────────────┤
│     Lineage Tracking (lineage.py)           │  LineageNode, ModelLineage, ancestors
├─────────────────────────────────────────────┤
│     Attestation (attestation.py)            │  HMAC-SHA256, canonical JSON, Signer/Verifier
├─────────────────────────────────────────────┤
│     Hashing (hashing.py)                    │  SHA-256/384/512, BLAKE2b, streaming
├─────────────────────────────────────────────┤
│     Provenance (provenance.py)              │  ModelProvenance (11 fields), serialization
└─────────────────────────────────────────────┘
```

The hashing layer has no internal dependencies beyond `hashlib`. The attestation layer depends on hashing and provenance. The governance layer depends on provenance only. The NANDA integration layer composes all layers into a single `IntegrityExtension` that carries provenance, lineage, attestation, and governance report as a unified agent metadata payload.

The `IntegrityExtension` dataclass bundles all components for agent metadata embedding:

| Component | Type | Optional | Purpose |
|-----------|------|:--------:|---------|
| `provenance` | `ModelProvenance` | No | 11-field identity and integrity metadata |
| `lineage` | `ModelLineage` | Yes | Derivation chain (root to leaf) |
| `attestation` | `Attestation` | Yes | HMAC-SHA256 signature record |
| `governance_report` | `GovernanceReport` | Yes | Policy compliance results |

Two functions manage the attachment lifecycle: `attach_to_agent_facts()` performs non-destructive merge into agent metadata under the `x_model_integrity` key (with backward-compatible `x_model_provenance` support), and `extract_from_agent_facts()` reconstructs the extension from agent metadata.

All extension points are `@runtime_checkable` protocols enabling structural subtyping:

| Protocol | Methods | Purpose |
|----------|---------|---------|
| `HashProvider` | `hash_bytes()`, `hash_file()`, `supported_algorithms` | Pluggable hash computation |
| `Signer` | `sign()`, `method`, `signer_id` | Pluggable attestation signing |
| `Verifier` | `verify()` | Pluggable signature verification |
| `GovernancePolicy` | `check()`, `name` | Custom governance rules |

## Key Design Decisions

- **Protocol-based extensibility (no vendor lock-in):** All extension points are `@runtime_checkable` protocols rather than abstract base classes. Custom implementations (HSM-backed signers, cloud KMS hash providers) satisfy the protocol by implementing the required methods, with no subclassing or library imports needed. This is verified at runtime via `isinstance()`, providing both static analysis support and duck-typing flexibility.

- **Frozen dataclasses for immutable audit:** `Attestation`, `IntegrityResult`, and `PolicyResult` are frozen dataclasses. Once a verification record is created, it cannot be mutated after the fact, providing a reliable foundation for audit logging and evidence chains. This immutability guarantee is enforced by the Python runtime, not just by convention.

- **64 KiB streaming chunks for file hashing:** The `StdlibHashProvider` uses `_CHUNK_SIZE = 1 << 16` for file hashing, maintaining O(1) memory usage regardless of model file size. This is critical when verifying multi-gigabyte weight files in memory-constrained environments such as CI pipelines, edge devices, and serverless functions.

- **HMAC-SHA256 in core, not Ed25519:** The zero-dependency constraint means the core ships with HMAC-based attestation using stdlib `hmac` and `hashlib` modules. Asymmetric signing (Ed25519) lives in the governance layer (`nanda-model-governance`) which manages the optional `cryptography` dependency. This separation keeps the integrity layer deployable in every environment where Python runs, from edge devices to cloud orchestrators.

- **Canonical JSON for deterministic signing:** The `canonicalize()` function uses `sort_keys=True`, compact separators, and `ensure_ascii=True` to produce a deterministic byte representation of provenance metadata. This ensures that the same provenance data produces the same bytes regardless of Python dictionary ordering, JSON formatter configuration, or encoding variation.

## Ecosystem Integration

The `nanda-model-integrity-layer` occupies the verification layer in the NANDA ecosystem, answering whether a model's advertised metadata actually meets policy requirements.

| Package | Role | Question Answered |
|---------|------|-------------------|
| `nanda-model-provenance` | Identity metadata | Where did this model come from? |
| `nanda-model-card` | Metadata schema | What is this model? |
| **`nanda-model-integrity-layer`** | **Integrity verification** | **Does metadata meet policy?** |
| `nanda-model-governance` | Cryptographic governance | Has this model been approved? |
| `nanda-bridge` | Transport layer | How is it exposed to the network? |

The model card's `weights_hash`, `model_type`, `risk_level`, and `base_model` fields drive integrity verification, governance policy enforcement, and lineage chain reconstruction. The `ModelLineage.from_provenance()` method mirrors model card fields to construct derivation chains automatically: if only `model_id` is set, a single root node is created; if `base_model` is also set, a two-node chain is created with the relationship derived from `model_type`.

The governance layer's `approval_to_integrity_facts()` function converts cryptographic approvals into integrity-layer-compatible metadata, creating a verifiable link between approval and provenance. The `IntegrityExtension` can carry both an HMAC attestation and a governance report, bundling multi-layer verification results into a single agent metadata payload.

In a typical NANDA agent discovery flow, the integrity layer participates as follows: a model's provenance is attested via HMAC-SHA256 and attached to agent metadata during registration; a discovering agent extracts the integrity extension and runs governance policies against its local policy set; if the agent has access to the model file, `verify_provenance_integrity()` confirms the weights match the advertised hash; lineage chains can be traversed to verify the model's derivation history.

The library defines six string enumerations for type-safe field values: `ModelType` (8 values including base, lora_adapter, quantized, distilled, merged), `GovernanceTier` (standard, regulated, restricted), `RiskLevel` (low, medium, high, critical), `HashAlgorithm` (sha256, sha384, sha512, blake2b), `AttestationMethod` (self-declared, hmac-sha256, ed25519, ecdsa-p256), and `LineageRelation` (fine_tuned, adapter, quantized, distilled, merged). All enums inherit from `(str, Enum)`, ensuring they compare equal to their string values and serialize naturally to JSON.

The `ModelProvenance` dataclass in the integrity layer extends the identity-layer provenance with 3 additional fields: `hash_algorithm` (which algorithm was used for `weights_hash`), `created_at` (ISO 8601 creation timestamp), and `attestation_method` (how provenance was attested). These fields capture the verification-specific metadata that belongs at the integrity layer rather than the identity layer.

## Future Work

- Ed25519 and ECDSA attestation signers for environments where shared HMAC secrets are impractical
- Transparency logging integration inspired by Sigstore's Rekor for tamper-evident provenance records
- DAG-based multi-model lineage supporting merged models with multiple parents
- Policy composition operators (AND/OR/NOT) enabling complex compliance rules from simple primitives
- Streaming attestation for signing provenance updates incrementally as model metadata evolves through the lifecycle

## References

1. SLSA. "Supply-chain Levels for Software Artifacts." https://slsa.dev
2. Krawczyk, H., Bellare, M., and Canetti, R. (1997). "HMAC: Keyed-Hashing for Message Authentication." RFC 2104.
3. NANDA Protocol. "Network of AI Agents in Decentralized Architecture." https://projectnanda.org
