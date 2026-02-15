"""Optional dependency detection."""

from __future__ import annotations


def has_cryptography() -> bool:
    """Check if the cryptography package is available."""
    try:
        import cryptography  # noqa: F401

        return True
    except ImportError:
        return False


def has_nanda_bridge() -> bool:
    """Check if the nanda_bridge package is available."""
    try:
        import nanda_bridge  # type: ignore[import-not-found]  # noqa: F401

        return True
    except ImportError:
        return False
