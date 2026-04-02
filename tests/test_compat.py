"""Tests for _compat optional dependency detection.

# Step 1 — Assumption Audit
# - has_cryptography() returns bool based on importability of cryptography
# - has_nanda_bridge() returns bool based on importability of nanda_bridge
# - Both return False when import fails, True when available

# Step 2 — Gap Analysis
# - Coverage is complete for True/False cases with mocked imports
# - No additional adversarial tests needed

# Step 3 — Break It List
# - Import failures properly caught (already covered)
"""

from __future__ import annotations

import types
from unittest.mock import patch

from nanda_integrity._compat import has_cryptography, has_nanda_bridge


def test_has_cryptography_returns_bool() -> None:
    result = has_cryptography()
    assert isinstance(result, bool)


def test_has_nanda_bridge_returns_bool() -> None:
    result = has_nanda_bridge()
    assert isinstance(result, bool)


def test_has_cryptography_false_when_missing() -> None:
    with patch("builtins.__import__", side_effect=ImportError("mocked")):
        assert has_cryptography() is False


def test_has_cryptography_true_when_available() -> None:
    fake_module = types.ModuleType("cryptography")
    original_import = __import__

    def mock_import(name, *args, **kwargs):
        if name == "cryptography":
            return fake_module
        return original_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        assert has_cryptography() is True


def test_has_nanda_bridge_false_when_missing() -> None:
    with patch("builtins.__import__", side_effect=ImportError("mocked")):
        assert has_nanda_bridge() is False


def test_has_nanda_bridge_true_when_available() -> None:
    fake_module = types.ModuleType("nanda_bridge")
    original_import = __import__

    def mock_import(name, *args, **kwargs):
        if name == "nanda_bridge":
            return fake_module
        return original_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        assert has_nanda_bridge() is True
