"""YAML policy loader."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from aisec.policies.models import (
    Policy,
    PolicyCompliance,
    PolicyGate,
    PolicyRule,
    PolicyThresholds,
)

logger = logging.getLogger(__name__)

_BUILTIN_DIR = Path(__file__).parent / "builtin"


def load_policy(source: str) -> Policy:
    """Load a policy from a built-in name or a file path.

    Args:
        source: Either a built-in policy name (strict, moderate, permissive)
                or a path to a YAML policy file.

    Returns:
        A parsed Policy object.
    """
    # Check built-in policies first
    builtin_path = _BUILTIN_DIR / f"{source}.yaml"
    if builtin_path.exists():
        path = builtin_path
    else:
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"Policy not found: {source}")

    logger.info("Loading policy from %s", path)
    with open(path) as f:
        raw = yaml.safe_load(f)

    return _parse_policy(raw)


def _parse_policy(raw: dict) -> Policy:
    """Parse a raw YAML dict into a Policy object."""
    policy = Policy(
        name=raw.get("name", ""),
        version=str(raw.get("version", "1.0")),
        description=raw.get("description", ""),
    )

    # Gate rules
    gate_raw = raw.get("gate", {})
    policy.gate = PolicyGate(
        block_on=[_parse_rule(r) for r in gate_raw.get("block_on", [])],
        warn_on=[_parse_rule(r) for r in gate_raw.get("warn_on", [])],
    )

    # Required agents
    policy.required_agents = raw.get("required_agents", [])

    # Compliance
    comp_raw = raw.get("compliance", {})
    if comp_raw:
        policy.compliance = PolicyCompliance(
            required_frameworks=comp_raw.get("required_frameworks", []),
            minimum_pass_rate=float(comp_raw.get("minimum_pass_rate", 0)),
        )

    # Thresholds
    thresh_raw = raw.get("thresholds", {})
    if thresh_raw:
        policy.thresholds = PolicyThresholds(
            max_critical=int(thresh_raw.get("max_critical", -1)),
            max_high=int(thresh_raw.get("max_high", -1)),
            max_medium=int(thresh_raw.get("max_medium", -1)),
            min_agents_passed=int(thresh_raw.get("min_agents_passed", 0)),
        )

    return policy


def _parse_rule(raw: dict) -> PolicyRule:
    """Parse a single rule from YAML."""
    return PolicyRule(
        severity=raw.get("severity", ""),
        count=str(raw.get("count", ">0")),
        agent=raw.get("agent", ""),
        description=raw.get("description", ""),
    )
