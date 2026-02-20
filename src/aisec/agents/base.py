"""Base agent abstract class defining the analysis lifecycle."""

from __future__ import annotations

import time
import logging
from abc import ABC, abstractmethod
from typing import ClassVar

from aisec.core.context import ScanContext
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import AgentResult, Evidence, Finding

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base for all security analysis agents."""

    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    phase: ClassVar[AgentPhase] = AgentPhase.DYNAMIC
    frameworks: ClassVar[list[str]] = []
    depends_on: ClassVar[list[str]] = []

    def __init__(self, context: ScanContext) -> None:
        self.context = context
        self.findings: list[Finding] = []
        self._start_time: float = 0.0

    async def run(self) -> AgentResult:
        """Template method: setup -> analyze -> teardown."""
        self._start_time = time.monotonic()
        logger.info("Agent %s starting", self.name)
        await self.setup()
        try:
            await self.analyze()
        except Exception as exc:
            logger.exception("Agent %s failed", self.name)
            duration = time.monotonic() - self._start_time
            return AgentResult(
                agent=self.name,
                findings=self.findings,
                duration_seconds=duration,
                error=str(exc),
            )
        finally:
            await self.teardown()
        duration = time.monotonic() - self._start_time
        logger.info("Agent %s completed with %d findings in %.1fs", self.name, len(self.findings), duration)
        return AgentResult(
            agent=self.name,
            findings=self.findings,
            duration_seconds=duration,
        )

    async def setup(self) -> None:
        """Optional setup hook."""

    @abstractmethod
    async def analyze(self) -> None:
        """Core analysis logic. Must populate self.findings."""
        ...

    async def teardown(self) -> None:
        """Optional cleanup hook."""

    def add_finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        *,
        owasp_llm: list[str] | None = None,
        owasp_agentic: list[str] | None = None,
        nist_ai_rmf: list[str] | None = None,
        evidence: list[Evidence] | None = None,
        remediation: str = "",
        references: list[str] | None = None,
        cvss_score: float | None = None,
        ai_risk_score: float | None = None,
    ) -> Finding:
        """Create and register a new finding."""
        finding = Finding(
            title=title,
            description=description,
            severity=severity,
            agent=self.name,
            owasp_llm=owasp_llm or [],
            owasp_agentic=owasp_agentic or [],
            nist_ai_rmf=nist_ai_rmf or [],
            evidence=evidence or [],
            remediation=remediation,
            references=references or [],
            cvss_score=cvss_score,
            ai_risk_score=ai_risk_score,
        )
        self.findings.append(finding)
        self.context.event_bus.emit("finding.new", finding)
        return finding
