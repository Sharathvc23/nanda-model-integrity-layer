"""Governance policy engine for model provenance.

Provides a ``GovernancePolicy`` protocol for defining governance
checks, six built-in policies, and a ``check_governance()`` function
that aggregates policy results into a ``GovernanceReport``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, ClassVar, Protocol, runtime_checkable

from nanda_integrity.provenance import ModelProvenance


@runtime_checkable
class GovernancePolicy(Protocol):
    """Protocol for governance policies."""

    @property
    def name(self) -> str:
        """Human-readable policy name."""
        ...  # pragma: no cover

    def check(self, provenance: ModelProvenance) -> PolicyResult:
        """Evaluate the policy against a provenance object."""
        ...  # pragma: no cover


@dataclass(frozen=True)
class PolicyResult:
    """Result of a single policy check.

    Attributes:
        passed: Whether the policy check passed.
        policy_name: Name of the policy that was checked.
        message: Human-readable result message.
    """

    passed: bool
    policy_name: str
    message: str


@dataclass(frozen=True)
class GovernanceReport:
    """Aggregated governance check results.

    Attributes:
        provenance_id: The model_id from the checked provenance.
        results: All individual policy results.
        passed: Whether all policies passed.
        failures: List of failed policy results.
    """

    provenance_id: str
    results: tuple[PolicyResult, ...]
    passed: bool
    failures: tuple[PolicyResult, ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "provenance_id": self.provenance_id,
            "passed": self.passed,
            "results": [
                {
                    "policy_name": r.policy_name,
                    "passed": r.passed,
                    "message": r.message,
                }
                for r in self.results
            ],
            "failures": [
                {
                    "policy_name": f.policy_name,
                    "passed": f.passed,
                    "message": f.message,
                }
                for f in self.failures
            ],
        }


# -- Built-in policies ------------------------------------------------


class RequireWeightsHash:
    """Policy: provenance must include a weights_hash."""

    @property
    def name(self) -> str:
        return "require_weights_hash"

    def check(self, provenance: ModelProvenance) -> PolicyResult:
        if provenance.weights_hash:
            return PolicyResult(True, self.name, "weights_hash is present")
        return PolicyResult(False, self.name, "weights_hash is missing")


class RequireGovernanceTier:
    """Policy: provenance must include a governance_tier."""

    @property
    def name(self) -> str:
        return "require_governance_tier"

    def check(self, provenance: ModelProvenance) -> PolicyResult:
        if provenance.governance_tier:
            return PolicyResult(True, self.name, "governance_tier is present")
        return PolicyResult(False, self.name, "governance_tier is missing")


class RequireRiskLevel:
    """Policy: provenance must include a risk_level."""

    @property
    def name(self) -> str:
        return "require_risk_level"

    def check(self, provenance: ModelProvenance) -> PolicyResult:
        if provenance.risk_level:
            return PolicyResult(True, self.name, "risk_level is present")
        return PolicyResult(False, self.name, "risk_level is missing")


class MaxRiskLevel:
    """Policy: risk_level must not exceed a maximum.

    Args:
        max_level: Maximum allowed risk level (inclusive).
    """

    _RISK_ORDER: ClassVar[dict[str, int]] = {
        "low": 0, "medium": 1, "high": 2, "critical": 3,
    }

    def __init__(self, max_level: str = "medium") -> None:
        if max_level not in self._RISK_ORDER:
            msg = f"Invalid risk level: {max_level!r}"
            raise ValueError(msg)
        self._max_level = max_level

    @property
    def name(self) -> str:
        return "max_risk_level"

    def check(self, provenance: ModelProvenance) -> PolicyResult:
        if not provenance.risk_level:
            return PolicyResult(
                False, self.name, "risk_level is missing (cannot evaluate)"
            )

        actual = self._RISK_ORDER.get(provenance.risk_level.lower())
        if actual is None:
            return PolicyResult(
                False, self.name, f"Unknown risk level: {provenance.risk_level!r}"
            )

        threshold = self._RISK_ORDER[self._max_level]
        if actual <= threshold:
            return PolicyResult(
                True,
                self.name,
                f"risk_level {provenance.risk_level!r} <= {self._max_level!r}",
            )
        return PolicyResult(
            False,
            self.name,
            f"risk_level {provenance.risk_level!r} exceeds {self._max_level!r}",
        )


class RequireAttestation:
    """Policy: provenance must include an attestation_method."""

    @property
    def name(self) -> str:
        return "require_attestation"

    def check(self, provenance: ModelProvenance) -> PolicyResult:
        if provenance.attestation_method:
            return PolicyResult(True, self.name, "attestation_method is present")
        return PolicyResult(False, self.name, "attestation_method is missing")


class RequireBaseModel:
    """Policy: provenance must include a base_model when model_type is an adapter."""

    @property
    def name(self) -> str:
        return "require_base_model"

    def check(self, provenance: ModelProvenance) -> PolicyResult:
        adapter_types = {"lora_adapter", "adapter", "fine_tuned"}
        if provenance.model_type in adapter_types:
            if provenance.base_model:
                return PolicyResult(
                    True, self.name, "base_model is present for adapter type"
                )
            return PolicyResult(
                False, self.name, "base_model is required for adapter types"
            )
        return PolicyResult(True, self.name, "base_model not required for this type")


# -- Presets ----------------------------------------------------------

STANDARD_POLICIES: tuple[GovernancePolicy, ...] = (
    RequireWeightsHash(),
    RequireGovernanceTier(),
    RequireBaseModel(),
)

REGULATED_POLICIES: tuple[GovernancePolicy, ...] = (
    RequireWeightsHash(),
    RequireGovernanceTier(),
    RequireRiskLevel(),
    MaxRiskLevel("medium"),
    RequireAttestation(),
    RequireBaseModel(),
)


# -- check_governance() -----------------------------------------------


def check_governance(
    provenance: ModelProvenance,
    policies: Sequence[GovernancePolicy] | None = None,
) -> GovernanceReport:
    """Run governance policies against a provenance object.

    Args:
        provenance: The provenance to check.
        policies: Policies to apply. Defaults to ``STANDARD_POLICIES``.

    Returns:
        ``GovernanceReport`` with all results.
    """
    active_policies = policies if policies is not None else STANDARD_POLICIES
    results: list[PolicyResult] = []
    failures: list[PolicyResult] = []

    for policy in active_policies:
        result = policy.check(provenance)
        results.append(result)
        if not result.passed:
            failures.append(result)

    return GovernanceReport(
        provenance_id=provenance.model_id,
        results=tuple(results),
        passed=len(failures) == 0,
        failures=tuple(failures),
    )
