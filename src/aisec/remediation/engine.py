"""Auto-remediation engine that generates fix suggestions for findings."""

from __future__ import annotations

import logging
from uuid import UUID

from aisec.core.enums import Severity
from aisec.core.models import Finding
from aisec.remediation.models import FixSuggestion, RemediationPlan
from aisec.remediation.strategies import generate_fix

logger = logging.getLogger(__name__)

# Effort weights for estimation (in hours)
_EFFORT_HOURS = {"low": 0.5, "medium": 2.0, "high": 6.0}


class RemediationEngine:
    """Generates prioritized remediation plans from scan findings."""

    def generate_plan(self, findings: list[Finding], scan_id: UUID | None = None) -> RemediationPlan:
        """Generate a complete remediation plan for a list of findings.

        Args:
            findings: All findings from a scan.
            scan_id: Optional scan identifier.

        Returns:
            A prioritized RemediationPlan with fix suggestions.
        """
        from uuid import uuid4

        plan = RemediationPlan(scan_id=scan_id or uuid4())
        plan.total_findings = len(findings)

        for finding in findings:
            fix = generate_fix(
                title=finding.title,
                description=finding.description,
                agent=finding.agent,
                severity=finding.severity.value if isinstance(finding.severity, Severity) else str(finding.severity),
            )
            if fix is None:
                continue

            fix.finding_id = finding.id
            plan.total_suggestions += 1

            # Bucket by severity
            sev = finding.severity if isinstance(finding.severity, Severity) else Severity(finding.severity)
            if sev == Severity.CRITICAL:
                fix.priority = 1
                plan.critical_fixes.append(fix)
            elif sev == Severity.HIGH:
                fix.priority = 2
                plan.high_fixes.append(fix)
            elif sev == Severity.MEDIUM:
                fix.priority = 3
                plan.medium_fixes.append(fix)
            else:
                fix.priority = 4
                plan.low_fixes.append(fix)

            # Quick wins: low effort + high/critical severity
            if fix.effort == "low" and sev in (Severity.CRITICAL, Severity.HIGH):
                plan.quick_wins.append(fix)

        plan.estimated_effort = self._estimate_effort(plan)

        logger.info(
            "Remediation plan generated: %d suggestions (%d quick wins) for %d findings",
            plan.total_suggestions,
            len(plan.quick_wins),
            plan.total_findings,
        )
        return plan

    def _estimate_effort(self, plan: RemediationPlan) -> str:
        """Estimate total effort for the remediation plan."""
        total_hours = 0.0
        for fixes in (plan.critical_fixes, plan.high_fixes, plan.medium_fixes, plan.low_fixes):
            for fix in fixes:
                total_hours += _EFFORT_HOURS.get(fix.effort, 2.0)

        if total_hours <= 1:
            return "~1 hour"
        elif total_hours <= 8:
            return f"~{int(total_hours)} hours"
        else:
            days = total_hours / 8
            if days <= 1:
                return "~1 day"
            return f"~{days:.1f} days"

    def to_markdown(self, plan: RemediationPlan) -> str:
        """Render a remediation plan as markdown."""
        lines: list[str] = []
        lines.append("# Remediation Plan\n")
        lines.append(f"**Findings:** {plan.total_findings} | "
                      f"**Suggestions:** {plan.total_suggestions} | "
                      f"**Estimated effort:** {plan.estimated_effort}\n")

        if plan.quick_wins:
            lines.append("## Quick Wins (Low Effort, High Impact)\n")
            for fix in plan.quick_wins:
                lines.append(f"### {fix.title}\n")
                lines.append(f"{fix.description}\n")
                self._render_patches(fix, lines)
                self._render_commands(fix, lines)

        for label, fixes in [
            ("Critical", plan.critical_fixes),
            ("High", plan.high_fixes),
            ("Medium", plan.medium_fixes),
            ("Low", plan.low_fixes),
        ]:
            # Exclude quick wins already shown
            remaining = [f for f in fixes if f not in plan.quick_wins]
            if not remaining:
                continue
            lines.append(f"## {label} Priority\n")
            for fix in remaining:
                lines.append(f"### {fix.title}\n")
                lines.append(f"{fix.description}\n")
                lines.append(f"**Effort:** {fix.effort}\n")
                self._render_patches(fix, lines)
                self._render_commands(fix, lines)
                self._render_references(fix, lines)
                if fix.framework_guidance:
                    lines.append("**Framework-specific guidance:**\n")
                    for fw, guidance in fix.framework_guidance.items():
                        lines.append(f"- **{fw}:** {guidance}")
                    lines.append("")

        return "\n".join(lines)

    def _render_patches(self, fix: FixSuggestion, lines: list[str]) -> None:
        for patch in fix.code_patches:
            lines.append(f"**{patch.explanation}**\n")
            if patch.before:
                lines.append(f"```{patch.language}")
                lines.append(f"# Before:")
                lines.append(patch.before)
                lines.append(f"# After:")
                lines.append(patch.after)
                lines.append("```\n")

    def _render_commands(self, fix: FixSuggestion, lines: list[str]) -> None:
        if fix.commands:
            lines.append("**Commands:**\n")
            lines.append("```bash")
            for cmd in fix.commands:
                lines.append(cmd)
            lines.append("```\n")

    def _render_references(self, fix: FixSuggestion, lines: list[str]) -> None:
        if fix.references:
            lines.append("**References:**\n")
            for ref in fix.references:
                lines.append(f"- {ref}")
            lines.append("")
