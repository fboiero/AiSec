"""Tests for security framework mappings."""

from aisec.core.enums import Severity
from aisec.core.models import Finding
from aisec.frameworks.owasp_llm import OWASP_LLM_TOP_10, get_category, map_findings
from aisec.frameworks.owasp_agentic import (
    OWASP_AGENTIC_TOP_10,
    get_category as get_agentic_category,
)
from aisec.frameworks.nist_ai_rmf import NIST_AI_RMF_FUNCTIONS


def test_owasp_llm_has_10_items():
    assert len(OWASP_LLM_TOP_10) == 10


def test_owasp_llm_get_category():
    item = get_category("LLM01")
    assert item is not None
    assert "injection" in item.name.lower() or "prompt" in item.name.lower()


def test_owasp_llm_get_category_invalid():
    item = get_category("INVALID")
    assert item is None


def test_owasp_llm_map_findings():
    findings = [
        Finding(
            title="Injection", severity=Severity.HIGH, owasp_llm=["LLM01", "LLM05"]
        ),
        Finding(title="Leak", severity=Severity.MEDIUM, owasp_llm=["LLM02"]),
    ]
    mapping = map_findings(findings)
    assert "LLM01" in mapping
    assert len(mapping["LLM01"]) == 1
    assert "LLM02" in mapping
    assert "LLM05" in mapping


def test_owasp_llm_map_findings_empty():
    mapping = map_findings([])
    assert mapping == {}


def test_owasp_agentic_has_10_items():
    assert len(OWASP_AGENTIC_TOP_10) == 10


def test_owasp_agentic_get_category():
    item = get_agentic_category("ASI01")
    assert item is not None


def test_owasp_agentic_get_category_invalid():
    item = get_agentic_category("INVALID")
    assert item is None


def test_nist_ai_rmf_has_4_functions():
    assert len(NIST_AI_RMF_FUNCTIONS) == 4


def test_nist_ai_rmf_core_functions():
    ids = set(NIST_AI_RMF_FUNCTIONS.keys())
    assert "GOVERN" in ids
    assert "MAP" in ids
    assert "MEASURE" in ids
    assert "MANAGE" in ids
