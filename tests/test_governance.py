"""Tests for governance module — policy engine and built-in policies.

# Step 1 — Assumption Audit
# - MaxRiskLevel uses ordered levels: low=0, medium=1, high=2, critical=3
# - Threshold check is <= (inclusive): risk at max level passes
# - STANDARD_POLICIES has 3 policies; REGULATED_POLICIES has 6
# - check_governance defaults to STANDARD_POLICIES when none given
# - Missing risk_level always fails MaxRiskLevel; unknown level also fails

# Step 2 — Gap Analysis
# - No explicit boundary test at exact threshold for MaxRiskLevel
# - No test for fully populated provenance passing STANDARD policies
# - No test for minimal provenance (only model_id) failing REGULATED

# Step 3 — Break It List
# - MaxRiskLevel boundary: risk exactly at max -> passes; one above -> fails
# - Full provenance through STANDARD (should pass all 3)
# - Minimal provenance through REGULATED (should fail most of 6)
"""

from __future__ import annotations

import pytest

from nanda_integrity import ModelProvenance
from nanda_integrity.governance import (
    REGULATED_POLICIES,
    STANDARD_POLICIES,
    GovernancePolicy,
    GovernanceReport,
    MaxRiskLevel,
    PolicyResult,
    RequireAttestation,
    RequireBaseModel,
    RequireGovernanceTier,
    RequireRiskLevel,
    RequireWeightsHash,
    check_governance,
)

# -- PolicyResult -----------------------------------------------------


class TestPolicyResult:
    """PolicyResult is frozen and has expected fields."""

    def test_frozen(self):
        r = PolicyResult(True, "test", "ok")
        with pytest.raises(AttributeError):
            r.passed = False  # type: ignore[misc]


# -- GovernanceReport -------------------------------------------------


class TestGovernanceReport:
    """GovernanceReport aggregation and serialization."""

    def test_to_dict(self):
        r = GovernanceReport(
            provenance_id="test",
            results=(PolicyResult(True, "p1", "ok"),),
            passed=True,
            failures=(),
        )
        d = r.to_dict()
        assert d["provenance_id"] == "test"
        assert d["passed"] is True
        assert len(d["results"]) == 1
        assert len(d["failures"]) == 0


# -- RequireWeightsHash -----------------------------------------------


class TestRequireWeightsHash:
    """RequireWeightsHash checks for weights_hash presence."""

    def test_satisfies_protocol(self):
        assert isinstance(RequireWeightsHash(), GovernancePolicy)

    def test_passes_with_hash(self):
        prov = ModelProvenance(model_id="test", weights_hash="abc")
        result = RequireWeightsHash().check(prov)
        assert result.passed is True

    def test_fails_without_hash(self):
        prov = ModelProvenance(model_id="test")
        result = RequireWeightsHash().check(prov)
        assert result.passed is False


# -- RequireGovernanceTier --------------------------------------------


class TestRequireGovernanceTier:
    def test_passes(self):
        prov = ModelProvenance(model_id="test", governance_tier="standard")
        assert RequireGovernanceTier().check(prov).passed is True

    def test_fails(self):
        prov = ModelProvenance(model_id="test")
        assert RequireGovernanceTier().check(prov).passed is False


# -- RequireRiskLevel -------------------------------------------------


class TestRequireRiskLevel:
    def test_passes(self):
        prov = ModelProvenance(model_id="test", risk_level="low")
        assert RequireRiskLevel().check(prov).passed is True

    def test_fails(self):
        prov = ModelProvenance(model_id="test")
        assert RequireRiskLevel().check(prov).passed is False


# -- MaxRiskLevel -----------------------------------------------------


class TestMaxRiskLevel:
    """MaxRiskLevel enforces a ceiling on risk_level."""

    def test_low_within_medium(self):
        prov = ModelProvenance(model_id="test", risk_level="low")
        assert MaxRiskLevel("medium").check(prov).passed is True

    def test_medium_within_medium(self):
        prov = ModelProvenance(model_id="test", risk_level="medium")
        assert MaxRiskLevel("medium").check(prov).passed is True

    def test_high_exceeds_medium(self):
        prov = ModelProvenance(model_id="test", risk_level="high")
        assert MaxRiskLevel("medium").check(prov).passed is False

    def test_critical_exceeds_medium(self):
        prov = ModelProvenance(model_id="test", risk_level="critical")
        assert MaxRiskLevel("medium").check(prov).passed is False

    def test_missing_risk_fails(self):
        prov = ModelProvenance(model_id="test")
        assert MaxRiskLevel("medium").check(prov).passed is False

    def test_unknown_risk_fails(self):
        prov = ModelProvenance(model_id="test", risk_level="unknown")
        assert MaxRiskLevel("medium").check(prov).passed is False

    def test_invalid_max_level_raises(self):
        with pytest.raises(ValueError, match="Invalid risk level"):
            MaxRiskLevel("invalid")

    def test_high_within_high(self):
        prov = ModelProvenance(model_id="test", risk_level="high")
        assert MaxRiskLevel("high").check(prov).passed is True


# -- RequireAttestation -----------------------------------------------


class TestRequireAttestation:
    def test_passes(self):
        prov = ModelProvenance(model_id="test", attestation_method="hmac-sha256")
        assert RequireAttestation().check(prov).passed is True

    def test_fails(self):
        prov = ModelProvenance(model_id="test")
        assert RequireAttestation().check(prov).passed is False


# -- RequireBaseModel -------------------------------------------------


class TestRequireBaseModel:
    """RequireBaseModel only enforces for adapter types."""

    def test_adapter_with_base_passes(self):
        prov = ModelProvenance(
            model_id="test",
            model_type="lora_adapter",
            base_model="llama-3.1-8b",
        )
        assert RequireBaseModel().check(prov).passed is True

    def test_adapter_without_base_fails(self):
        prov = ModelProvenance(model_id="test", model_type="lora_adapter")
        assert RequireBaseModel().check(prov).passed is False

    def test_non_adapter_always_passes(self):
        prov = ModelProvenance(model_id="test", model_type="base")
        assert RequireBaseModel().check(prov).passed is True

    def test_empty_type_passes(self):
        prov = ModelProvenance(model_id="test")
        assert RequireBaseModel().check(prov).passed is True


# -- check_governance() -----------------------------------------------


class TestCheckGovernance:
    """check_governance() aggregates policy results."""

    def test_all_pass(self):
        prov = ModelProvenance(
            model_id="test",
            weights_hash="abc",
            governance_tier="standard",
        )
        report = check_governance(prov)
        assert isinstance(report, GovernanceReport)
        assert report.passed is True
        assert len(report.failures) == 0

    def test_some_fail(self):
        prov = ModelProvenance(model_id="test")
        report = check_governance(prov)
        assert report.passed is False
        assert len(report.failures) > 0

    def test_custom_policies(self):
        prov = ModelProvenance(model_id="test", risk_level="low")
        report = check_governance(prov, policies=[RequireRiskLevel()])
        assert report.passed is True
        assert len(report.results) == 1

    def test_default_is_standard(self):
        prov = ModelProvenance(model_id="test")
        report = check_governance(prov)
        assert len(report.results) == len(STANDARD_POLICIES)

    def test_provenance_id_in_report(self):
        prov = ModelProvenance(model_id="my-model")
        report = check_governance(prov)
        assert report.provenance_id == "my-model"


# -- Presets ----------------------------------------------------------


class TestPresets:
    """Preset policy sets contain expected policies."""

    def test_standard_count(self):
        assert len(STANDARD_POLICIES) == 3

    def test_regulated_count(self):
        assert len(REGULATED_POLICIES) == 6

    def test_regulated_is_superset(self):
        standard_names = {p.name for p in STANDARD_POLICIES}
        regulated_names = {p.name for p in REGULATED_POLICIES}
        assert standard_names.issubset(regulated_names)

    def test_compliant_provenance_passes_regulated(self):
        prov = ModelProvenance(
            model_id="test",
            weights_hash="abc",
            governance_tier="regulated",
            risk_level="low",
            attestation_method="hmac-sha256",
            model_type="base",
        )
        report = check_governance(prov, policies=list(REGULATED_POLICIES))
        assert report.passed is True


# -- R5 Boundary & adversarial tests ---------------------------------


class TestMaxRiskLevelBoundary:
    """R5: boundary tests for MaxRiskLevel at/below/above threshold."""

    def test_max_risk_level_boundary_at_exactly_threshold(self):
        """Risk exactly at max_level passes (<=)."""
        prov = ModelProvenance(model_id="test", risk_level="high")
        assert MaxRiskLevel("high").check(prov).passed is True

    def test_max_risk_level_boundary_above_threshold(self):
        """Risk one level above max_level fails (>)."""
        prov = ModelProvenance(model_id="test", risk_level="critical")
        assert MaxRiskLevel("high").check(prov).passed is False

    def test_max_risk_level_boundary_below_threshold(self):
        """Risk one level below max_level passes."""
        prov = ModelProvenance(model_id="test", risk_level="medium")
        assert MaxRiskLevel("high").check(prov).passed is True


class TestGovernanceAdversarial:
    """Adversarial tests for governance check with preset policies."""

    def test_all_standard_policies_pass_full_provenance(self):
        """Fully populated provenance passes all STANDARD policies."""
        prov = ModelProvenance(
            model_id="llama-3.1-8b",
            model_version="1.0.0",
            provider_id="ollama",
            model_type="base",
            base_model="llama-3.1-8b",
            governance_tier="standard",
            weights_hash="abc123def456",
            risk_level="low",
        )
        report = check_governance(prov, policies=list(STANDARD_POLICIES))
        assert report.passed is True
        assert len(report.failures) == 0

    def test_regulated_policies_fail_minimal_provenance(self):
        """Provenance with only model_id fails REGULATED policies."""
        prov = ModelProvenance(model_id="bare-minimum")
        report = check_governance(prov, policies=list(REGULATED_POLICIES))
        assert report.passed is False
        # At least weights_hash, tier, risk_level, attestation
        assert len(report.failures) >= 3
