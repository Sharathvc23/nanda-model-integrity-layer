"""Integrity verification example.

Demonstrates computing and verifying model weight hashes.
"""

import tempfile
from pathlib import Path

from nanda_integrity import (
    ModelProvenance,
    compute_weights_hash,
    verify_integrity,
    verify_provenance_integrity,
)

# Create a temporary file to simulate model weights
with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
    f.write(b"simulated model weights data")
    weights_path = Path(f.name)

# Compute the hash
digest = compute_weights_hash(weights_path, "sha256")
print(f"SHA-256 hash: {digest}")

# Verify directly
result = verify_integrity(weights_path, digest, "sha256")
print(f"Direct verify: valid={result.valid}")

# Create provenance with the hash, then verify via provenance
provenance = ModelProvenance(
    model_id="test-model",
    weights_hash=digest,
    hash_algorithm="sha256",
)

result = verify_provenance_integrity(provenance, weights_path)
print(f"Provenance verify: valid={result.valid}")

# Simulate tampering
weights_path.write_bytes(b"tampered data")
result = verify_provenance_integrity(provenance, weights_path)
print(f"After tampering: valid={result.valid}")

# Cleanup
weights_path.unlink()
