"""Shared test fixtures for AiSec."""

from __future__ import annotations

import pytest

from aisec.core.config import AiSecConfig
from aisec.core.context import ScanContext
from aisec.core.enums import Severity
from aisec.core.events import EventBus
from aisec.core.models import AgentResult, Evidence, Finding


@pytest.fixture
def config() -> AiSecConfig:
    """Default test configuration."""
    return AiSecConfig(
        target_image="test-agent:latest",
        target_name="TestAgent",
        target_type="generic",
        scan_timeout=60,
    )


@pytest.fixture
def event_bus() -> EventBus:
    """Fresh event bus."""
    return EventBus()


@pytest.fixture
def scan_context(config: AiSecConfig, event_bus: EventBus) -> ScanContext:
    """Scan context for testing (no Docker)."""
    return ScanContext(
        target_image=config.target_image,
        target_name=config.target_name,
        config=config,
        event_bus=event_bus,
    )


@pytest.fixture
def sample_finding() -> Finding:
    """A sample finding for testing."""
    return Finding(
        title="Test Finding",
        description="This is a test finding.",
        severity=Severity.MEDIUM,
        agent="test_agent",
        owasp_llm=["LLM01"],
        owasp_agentic=["ASI01"],
        nist_ai_rmf=["MEASURE.2.1"],
        evidence=[
            Evidence(
                type="config",
                summary="Test evidence",
                raw_data="example data",
                location="/etc/config",
            )
        ],
        remediation="Fix the issue.",
        references=["https://example.com"],
    )


@pytest.fixture
def sample_findings() -> list[Finding]:
    """Multiple sample findings across severities."""
    return [
        Finding(
            title="Critical: Prompt Injection Vulnerability",
            description="Direct prompt injection via API endpoint.",
            severity=Severity.CRITICAL,
            agent="prompt_security",
            owasp_llm=["LLM01"],
            owasp_agentic=["ASI01"],
        ),
        Finding(
            title="High: Excessive Agency - Root Container",
            description="Container runs as root user.",
            severity=Severity.HIGH,
            agent="permission",
            owasp_llm=["LLM06"],
            owasp_agentic=["ASI02", "ASI03"],
        ),
        Finding(
            title="Medium: PII in Log Files",
            description="Email addresses found in application logs.",
            severity=Severity.MEDIUM,
            agent="dataflow",
            owasp_llm=["LLM02"],
            owasp_agentic=["ASI06"],
        ),
        Finding(
            title="Low: Unpinned Dependencies",
            description="requirements.txt has unpinned dependencies.",
            severity=Severity.LOW,
            agent="supply_chain",
            owasp_llm=["LLM03"],
            owasp_agentic=["ASI04"],
        ),
        Finding(
            title="Info: Server Header Exposed",
            description="HTTP server header reveals software version.",
            severity=Severity.INFO,
            agent="network",
            owasp_llm=["LLM09"],
        ),
    ]


@pytest.fixture
def sample_agent_result(sample_findings: list[Finding]) -> AgentResult:
    """A sample agent result."""
    return AgentResult(
        agent="test_agent",
        findings=sample_findings,
        duration_seconds=12.5,
    )
