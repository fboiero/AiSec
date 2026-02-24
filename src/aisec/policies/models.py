"""Data models for the policy engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class GateVerdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"


@dataclass
class PolicyRule:
    """A single rule within a policy."""

    severity: str = ""          # critical, high, medium, low
    count: str = ">0"           # e.g. ">0", ">5", ">=10"
    agent: str = ""             # optional: restrict to specific agent
    description: str = ""


@dataclass
class PolicyGate:
    """Gate configuration defining block and warn conditions."""

    block_on: list[PolicyRule] = field(default_factory=list)
    warn_on: list[PolicyRule] = field(default_factory=list)


@dataclass
class PolicyCompliance:
    """Compliance requirements within a policy."""

    required_frameworks: list[str] = field(default_factory=list)
    minimum_pass_rate: float = 0.0  # percentage


@dataclass
class PolicyThresholds:
    """Numeric thresholds for the policy."""

    max_critical: int = -1      # -1 = unlimited
    max_high: int = -1
    max_medium: int = -1
    min_agents_passed: int = 0


@dataclass
class Policy:
    """A complete security policy definition."""

    name: str = ""
    version: str = "1.0"
    description: str = ""
    gate: PolicyGate = field(default_factory=PolicyGate)
    required_agents: list[str] = field(default_factory=list)
    compliance: PolicyCompliance = field(default_factory=PolicyCompliance)
    thresholds: PolicyThresholds = field(default_factory=PolicyThresholds)


@dataclass
class RuleViolation:
    """A single rule violation detected during policy evaluation."""

    rule: PolicyRule
    actual_count: int = 0
    is_blocking: bool = True
    message: str = ""


@dataclass
class GateDecision:
    """The result of evaluating a scan against a policy."""

    verdict: GateVerdict = GateVerdict.PASS
    policy_name: str = ""
    violations: list[RuleViolation] = field(default_factory=list)
    warnings: list[RuleViolation] = field(default_factory=list)
    missing_agents: list[str] = field(default_factory=list)
    summary: str = ""
    exit_code: int = 0  # 0=pass, 1=fail, 2=warn
