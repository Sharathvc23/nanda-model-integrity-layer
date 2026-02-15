"""Signed attestation example.

Demonstrates creating and verifying HMAC-signed attestations.
"""

from nanda_integrity import (
    HMACSigner,
    HMACVerifier,
    ModelProvenance,
    create_attestation,
    verify_attestation,
)

# Create provenance
provenance = ModelProvenance(
    model_id="llama-3.1-8b",
    model_version="1.0.0",
    provider_id="ollama",
    governance_tier="standard",
)

# Sign with HMAC-SHA256
secret = b"organization-shared-secret"
signer = HMACSigner(secret, signer_id="my-org")

attestation = create_attestation(provenance, signer)
print(f"Attestation method: {attestation.method}")
print(f"Signer: {attestation.signer_id}")
print(f"Digest: {attestation.provenance_digest[:16]}...")
print(f"Signature: {attestation.signature[:16]}...")

# Verify with matching key
verifier = HMACVerifier(secret)
valid = verify_attestation(provenance, attestation, verifier)
print(f"\nVerification: {'PASS' if valid else 'FAIL'}")

# Tamper detection — modified provenance fails verification
tampered = ModelProvenance(
    model_id="llama-3.1-8b",
    model_version="1.0.0",
    provider_id="ollama",
    governance_tier="regulated",  # changed!
)
valid = verify_attestation(tampered, attestation, verifier)
print(f"Tampered verification: {'PASS' if valid else 'FAIL'}")
