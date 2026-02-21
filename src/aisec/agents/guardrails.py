"""AI safety guardrail analysis agent."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Guardrail framework detection patterns
# ---------------------------------------------------------------------------

GUARDRAIL_FRAMEWORKS: list[tuple[str, list[re.Pattern[str]]]] = [
    (
        "NeMo Guardrails",
        [
            re.compile(r"(?i)nemoguardrails"),
            re.compile(r"(?i)from\s+nemoguardrails\s+import"),
            re.compile(r"(?i)import\s+nemoguardrails"),
            re.compile(r"(?i)rails[_\s]?config"),
            re.compile(r"\.co$|\.co\b"),  # Colang files
        ],
    ),
    (
        "Guardrails AI",
        [
            re.compile(r"(?i)guardrails[\-_]ai"),
            re.compile(r"(?i)from\s+guardrails\s+import"),
            re.compile(r"(?i)import\s+guardrails"),
            re.compile(r"\.rail\b"),
        ],
    ),
    (
        "LLM Guard",
        [
            re.compile(r"(?i)llm[\-_]guard"),
            re.compile(r"(?i)from\s+llm_guard\s+import"),
            re.compile(r"(?i)import\s+llm_guard"),
        ],
    ),
]

CUSTOM_GUARDRAIL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(class|def)\s+\w*(guardrail|guard_rail)\w*"),
    re.compile(r"(?i)(class|def)\s+\w*(safety[_\s]?filter|safety[_\s]?check)\w*"),
    re.compile(r"(?i)(class|def)\s+\w*(content[_\s]?filter|input[_\s]?filter|output[_\s]?filter)\w*"),
    re.compile(r"(?i)(class|def)\s+\w*(moderation[_\s]?layer|moderation[_\s]?check)\w*"),
]

# ---------------------------------------------------------------------------
# Input validation patterns
# ---------------------------------------------------------------------------

INPUT_VALIDATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Input length limit", re.compile(
        r"(?i)(max[_\s]?(len|length|size|chars|tokens)|len\s*\(\s*\w+\s*\)\s*[<>]|"
        r"truncat|\.[:]{0}maxlen|input.{0,30}limit)"
    )),
    ("Content type validation", re.compile(
        r"(?i)(content[_\s]?type|mime[_\s]?type|allowed[_\s]?types|"
        r"accept[_\s]?header|validate[_\s]?content)"
    )),
    ("Encoding validation", re.compile(
        r"(?i)(encoding[_\s]?valid|charset[_\s]?valid|utf[_\s]?8[_\s]?valid|"
        r"decode[_\s]?strict|chardet|ftfy)"
    )),
    ("Injection pattern filtering", re.compile(
        r"(?i)(injection[_\s]?filter|injection[_\s]?detect|prompt[_\s]?guard|"
        r"sanitiz|strip[_\s]?tag|escape[_\s]?input|clean[_\s]?input|"
        r"block[_\s]?pattern|deny[_\s]?pattern)"
    )),
]

# ---------------------------------------------------------------------------
# Output filtering patterns
# ---------------------------------------------------------------------------

OUTPUT_FILTERING_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("PII redaction", re.compile(
        r"(?i)(pii[_\s]?redact|pii[_\s]?mask|pii[_\s]?filter|pii[_\s]?detect|"
        r"redact[_\s]?pii|mask[_\s]?pii|anonymiz|de[_\s]?identif|scrub[_\s]?pii|"
        r"presidio|microsoft[_\s]?presidio)"
    )),
    ("HTML/XSS sanitization", re.compile(
        r"(?i)(html[_\s]?sanitiz|xss[_\s]?filter|escape[_\s]?html|bleach|"
        r"markupsafe|html\.escape|cgi\.escape|strip[_\s]?tags|sanitize[_\s]?html|"
        r"dompurify)"
    )),
    ("Profanity/toxicity filtering", re.compile(
        r"(?i)(profanity|toxicity|toxic[_\s]?filter|profanity[_\s]?filter|"
        r"bad[_\s]?word|offensive[_\s]?content|hate[_\s]?speech|"
        r"detoxify|perspective[_\s]?api|alt[_\s]?text)"
    )),
    ("Confidence threshold", re.compile(
        r"(?i)(confidence[_\s]?threshold|min[_\s]?confidence|score[_\s]?threshold|"
        r"uncertainty[_\s]?threshold|confidence[_\s]?score\s*[<>]|"
        r"hallucination[_\s]?detect|factual[_\s]?check)"
    )),
    ("Response length limit", re.compile(
        r"(?i)(max[_\s]?output|max[_\s]?response|max[_\s]?tokens|"
        r"response[_\s]?limit|output[_\s]?limit|truncat[_\s]?output|"
        r"max[_\s]?new[_\s]?tokens)"
    )),
]

# ---------------------------------------------------------------------------
# Content moderation patterns
# ---------------------------------------------------------------------------

CONTENT_MODERATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OpenAI Moderation API", re.compile(
        r"(?i)(openai\.Moderation|openai.*moderat|client\.moderations|"
        r"moderations\.create|/v1/moderations)"
    )),
    ("Anthropic content filtering", re.compile(
        r"(?i)(anthropic.*content[_\s]?polic|anthropic.*safety|"
        r"content[_\s]?policy[_\s]?violation)"
    )),
    ("Custom moderation classifier", re.compile(
        r"(?i)(moderation[_\s]?model|moderation[_\s]?classif|"
        r"content[_\s]?classif|safety[_\s]?classif|"
        r"classify[_\s]?content|moderate[_\s]?content)"
    )),
    ("Blocklist/allowlist", re.compile(
        r"(?i)(block[_\s]?list|deny[_\s]?list|blacklist|banned[_\s]?words|"
        r"allow[_\s]?list|whitelist|approved[_\s]?topics|"
        r"forbidden[_\s]?topics|topic[_\s]?filter)"
    )),
    ("NSFW detection", re.compile(
        r"(?i)(nsfw|not[_\s]?safe[_\s]?for[_\s]?work|adult[_\s]?content|"
        r"explicit[_\s]?content|nudity[_\s]?detect|"
        r"safety[_\s]?classifier|opennsfw)"
    )),
]

# ---------------------------------------------------------------------------
# Rate limiting patterns
# ---------------------------------------------------------------------------

RATE_LIMIT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Redis-based rate limiting", re.compile(
        r"(?i)(redis.*rate[_\s]?limit|rate[_\s]?limit.*redis|"
        r"redis.*throttl|sliding[_\s]?window.*redis)"
    )),
    ("In-memory rate limiting", re.compile(
        r"(?i)(rate[_\s]?limit|throttl|RateLimiter|Throttle|"
        r"slowapi|flask[_\s]?limiter|ratelimit|"
        r"token[_\s]?bucket|leaky[_\s]?bucket|sliding[_\s]?window)"
    )),
    ("Token/cost limiting", re.compile(
        r"(?i)(token[_\s]?limit|token[_\s]?budget|cost[_\s]?limit|"
        r"usage[_\s]?limit|spending[_\s]?limit|max[_\s]?cost|"
        r"token[_\s]?quota|api[_\s]?quota)"
    )),
    ("Concurrent request limiting", re.compile(
        r"(?i)(concurrent[_\s]?limit|max[_\s]?concurrent|"
        r"semaphore|connection[_\s]?pool|max[_\s]?connections|"
        r"asyncio\.Semaphore|threading\.Semaphore)"
    )),
]

# ---------------------------------------------------------------------------
# System prompt protection patterns
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'(?i)system[_\s]?prompt\s*[:=]\s*["\']'),
    re.compile(r'(?i)system[_\s]?message\s*[:=]\s*["\']'),
    re.compile(r'(?i)SYSTEM_PROMPT\s*=\s*["\']'),
    re.compile(r'(?i)\{["\']role["\']\s*:\s*["\']system["\']'),
    re.compile(r'(?i)instructions?\s*[:=]\s*"""'),
]

PROMPT_ENV_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)os\.environ.*(?:system[_\s]?prompt|instructions)"),
    re.compile(r"(?i)os\.getenv\s*\(\s*['\"].*(?:SYSTEM|PROMPT|INSTRUCTION)"),
    re.compile(r"(?i)environ\[.*(?:SYSTEM|PROMPT|INSTRUCTION)"),
    re.compile(r"(?i)config\.get\s*\(\s*['\"].*(?:system|prompt|instruction)"),
    re.compile(r"(?i)settings\.(?:SYSTEM|PROMPT|INSTRUCTION)"),
]

ANTI_EXTRACTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(do\s+not|never|don't|must\s+not)\s+(reveal|share|disclose|show|output|repeat)\s+(your\s+)?(system|instruction|prompt)"),
    re.compile(r"(?i)(keep|maintain)\s+(your\s+)?(system\s+prompt|instructions?)\s+(secret|private|confidential)"),
    re.compile(r"(?i)if\s+(asked|someone\s+asks)\s+(about|for)\s+(your\s+)?(system|instruction|prompt)"),
    re.compile(r"(?i)(refuse|decline|ignore)\s+.{0,40}(reveal|extract|leak)\s+.{0,20}(prompt|instruction)"),
]

# ---------------------------------------------------------------------------
# Tool authorization patterns
# ---------------------------------------------------------------------------

TOOL_DEFINITION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)@tool\b"),
    re.compile(r"(?i)tools?\s*[:=]\s*\["),
    re.compile(r"(?i)function[_\s]?calling"),
    re.compile(r"(?i)(tool|function)[_\s]?(call|invoke|execute|run)"),
    re.compile(r"(?i)(langchain|autogen|crewai|openai).*tool"),
]

TOOL_WHITELIST_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(allowed[_\s]?tools|tool[_\s]?whitelist|permitted[_\s]?tools|enabled[_\s]?tools|available[_\s]?tools)"),
    re.compile(r"(?i)(tool[_\s]?registry|registered[_\s]?tools|tool[_\s]?manifest)"),
]

TOOL_AUTH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(authorize|authoriz|permission[_\s]?check|access[_\s]?control)\s*.*tool"),
    re.compile(r"(?i)tool.*\b(authorize|authoriz|permission|access[_\s]?control)\b"),
    re.compile(r"(?i)(require[_\s]?auth|check[_\s]?permission|verify[_\s]?access)\s*.*tool"),
]

DANGEROUS_TOOL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(subprocess|os\.system|os\.popen|exec\s*\(|eval\s*\(|shell[_\s]?exec)"),
    re.compile(r"(?i)(file\.write|open\s*\(.*['\"]w['\"]|write[_\s]?file|delete[_\s]?file|remove[_\s]?file|os\.remove|os\.unlink|shutil\.rmtree)"),
    re.compile(r"(?i)(requests\.(get|post|put|delete|patch)|urllib|httpx|aiohttp)"),
    re.compile(r"(?i)(sql[_\s]?exec|execute[_\s]?query|raw[_\s]?sql|cursor\.execute)"),
]

CONFIRMATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(confirm|confirmation|user[_\s]?confirm|ask[_\s]?confirm)"),
    re.compile(r"(?i)(human[_\s]?in[_\s]?the[_\s]?loop|hitl|human[_\s]?approval|human[_\s]?review)"),
    re.compile(r"(?i)(require[_\s]?approval|approval[_\s]?required|must[_\s]?approve)"),
    re.compile(r"(?i)(destructive|dangerous|irreversible)\s*.{0,30}(check|guard|gate|confirm)"),
]


class GuardrailAgent(BaseAgent):
    """Evaluate AI safety guardrail presence, configuration, and bypass resistance."""

    name: ClassVar[str] = "guardrails"
    description: ClassVar[str] = (
        "Evaluates AI safety guardrail presence, configuration, and bypass "
        "resistance across input/output channels."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.DYNAMIC
    frameworks: ClassVar[list[str]] = ["LLM01", "LLM05", "LLM09", "ASI01", "ASI09"]
    depends_on: ClassVar[list[str]] = ["prompt_security"]

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def analyze(self) -> None:
        """Run all guardrail security checks."""
        source_files = await self._collect_source_files()

        await self._check_guardrail_frameworks(source_files)
        await self._check_input_validation(source_files)
        await self._check_output_filtering(source_files)
        await self._check_content_moderation(source_files)
        await self._check_rate_limiting(source_files)
        await self._check_system_prompt_protection(source_files)
        await self._check_tool_authorization(source_files)

    # ------------------------------------------------------------------
    # Container introspection helpers
    # ------------------------------------------------------------------

    async def _exec_in_container(self, command: str) -> str:
        """Run a shell command inside the target container and return stdout."""
        cid = self.context.container_id
        if not cid:
            return ""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c", command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode(errors="replace").strip() if proc.returncode == 0 else ""
        except Exception:
            return ""

    async def _collect_source_files(self) -> dict[str, str]:
        """Gather source code and configuration files from the container."""
        cid = self.context.container_id
        if not cid:
            return {}

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid,
                "sh", "-c",
                "find /app /src /opt -maxdepth 5 -type f "
                "\\( -name '*.py' -o -name '*.js' -o -name '*.ts' "
                "-o -name '*.yaml' -o -name '*.yml' -o -name '*.json' "
                "-o -name '*.toml' -o -name '*.rail' -o -name '*.co' \\) "
                "-size -512k 2>/dev/null | head -100",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return {}
            file_list = stdout.decode(errors="replace").strip().splitlines()
        except Exception:
            return {}

        contents: dict[str, str] = {}
        for fpath in file_list:
            fpath = fpath.strip()
            if not fpath:
                continue
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", cid, "head", "-c", "65536", fpath,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    contents[fpath] = stdout.decode(errors="replace")
            except Exception:
                continue
        return contents

    # ------------------------------------------------------------------
    # 1. Guardrail framework detection
    # ------------------------------------------------------------------

    async def _check_guardrail_frameworks(self, source_files: dict[str, str]) -> None:
        """Search the container for installed guardrail frameworks."""
        cid = self.context.container_id

        detected_frameworks: dict[str, list[str]] = {}

        # Check installed Python packages via pip
        pip_list = await self._exec_in_container(
            "pip list 2>/dev/null || pip3 list 2>/dev/null"
        )
        pip_packages = pip_list.lower() if pip_list else ""

        for framework_name, patterns in GUARDRAIL_FRAMEWORKS:
            locations: list[str] = []

            # Check pip output for known package names
            package_key = framework_name.lower().replace(" ", "")
            if package_key in pip_packages.replace("-", "").replace("_", ""):
                locations.append("pip package installed")

            # Search source files for import and usage patterns
            for fpath, content in source_files.items():
                for pattern in patterns:
                    if pattern.search(content):
                        locations.append(fpath)
                        break

            if locations:
                detected_frameworks[framework_name] = list(set(locations))

        # Check for framework-specific config files
        rails_config = await self._exec_in_container(
            "find /app /src /opt -maxdepth 5 -type f "
            "\\( -name 'config.yml' -o -name 'rails_config.yml' "
            "-o -name '*.rail' -o -name '*.co' \\) "
            "2>/dev/null | head -20"
        )
        if rails_config:
            for cfg_path in rails_config.strip().splitlines():
                cfg_path = cfg_path.strip()
                if cfg_path.endswith(".rail"):
                    detected_frameworks.setdefault("Guardrails AI", []).append(cfg_path)
                elif cfg_path.endswith(".co"):
                    detected_frameworks.setdefault("NeMo Guardrails", []).append(cfg_path)
                elif "rails" in cfg_path.lower():
                    detected_frameworks.setdefault("NeMo Guardrails", []).append(cfg_path)

        # Search for custom guardrail implementations
        custom_hits: list[str] = []
        for fpath, content in source_files.items():
            for pattern in CUSTOM_GUARDRAIL_PATTERNS:
                match = pattern.search(content)
                if match:
                    custom_hits.append(f"{fpath}: {match.group(0)}")
                    break

        if custom_hits:
            detected_frameworks["Custom guardrails"] = custom_hits

        if detected_frameworks:
            details_lines: list[str] = []
            for fw_name, locations in detected_frameworks.items():
                details_lines.append(f"  [{fw_name}]")
                for loc in locations[:5]:
                    details_lines.append(f"    - {loc}")

            self.add_finding(
                title=f"Guardrail frameworks detected ({len(detected_frameworks)} framework(s))",
                description=(
                    f"Detected {len(detected_frameworks)} guardrail framework(s): "
                    f"{', '.join(detected_frameworks.keys())}. The presence of guardrail "
                    "frameworks is a positive security indicator. Verify that they are "
                    "properly configured and cover all input/output channels."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM01", "LLM05"],
                owasp_agentic=["ASI01", "ASI09"],
                nist_ai_rmf=["GOVERN", "MEASURE"],
                evidence=[
                    Evidence(
                        type="config",
                        summary=f"Guardrail frameworks: {', '.join(detected_frameworks.keys())}",
                        raw_data="\n".join(details_lines),
                        location=f"container:{cid}" if cid else "unknown",
                    )
                ],
                remediation=(
                    "Continue maintaining and updating guardrail configurations. "
                    "Ensure all user-facing input and LLM output channels are covered. "
                    "Regularly test guardrail bypass resistance with adversarial inputs."
                ),
            )
        else:
            self.add_finding(
                title="No guardrail frameworks detected",
                description=(
                    "No established guardrail frameworks (NeMo Guardrails, "
                    "Guardrails AI, LLM Guard) or custom guardrail implementations "
                    "were detected in the container. Without guardrails, the AI "
                    "system lacks structured defenses against prompt injection, "
                    "harmful output generation, and policy violations."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM01", "LLM05"],
                owasp_agentic=["ASI01", "ASI09"],
                nist_ai_rmf=["GOVERN", "MEASURE"],
                evidence=[
                    Evidence(
                        type="config",
                        summary="No guardrail frameworks found",
                        raw_data=(
                            f"Searched {len(source_files)} source files and pip packages. "
                            "No known guardrail frameworks or custom implementations detected."
                        ),
                        location=f"container:{cid}" if cid else "unknown",
                    )
                ],
                remediation=(
                    "Implement a guardrail framework to protect AI input/output channels. "
                    "Consider: (1) NVIDIA NeMo Guardrails for conversational AI, "
                    "(2) Guardrails AI for structured validation, (3) LLM Guard for "
                    "input/output scanning, or (4) a custom guardrail layer with "
                    "content moderation, input validation, and output filtering."
                ),
                references=[
                    "https://github.com/NVIDIA/NeMo-Guardrails",
                    "https://github.com/guardrails-ai/guardrails",
                    "https://github.com/protectai/llm-guard",
                ],
                cvss_score=7.0,
                ai_risk_score=8.0,
            )

    # ------------------------------------------------------------------
    # 2. Input validation
    # ------------------------------------------------------------------

    async def _check_input_validation(self, source_files: dict[str, str]) -> None:
        """Search for input validation and sanitization patterns."""
        detected: dict[str, list[str]] = {}

        for fpath, content in source_files.items():
            for category, pattern in INPUT_VALIDATION_PATTERNS:
                match = pattern.search(content)
                if match:
                    start = max(0, match.start() - 30)
                    end = min(len(content), match.end() + 80)
                    snippet = content[start:end].strip().replace("\n", " ")
                    detected.setdefault(category, []).append(
                        f"{fpath}: {snippet[:120]}"
                    )

        if detected:
            details_lines: list[str] = []
            for category, hits in detected.items():
                details_lines.append(f"  [{category}] ({len(hits)} occurrence(s))")
                for hit in hits[:3]:
                    details_lines.append(f"    - {hit}")

            total_categories = len(detected)
            total_expected = len(INPUT_VALIDATION_PATTERNS)
            missing = [
                cat for cat, _ in INPUT_VALIDATION_PATTERNS if cat not in detected
            ]

            severity = Severity.INFO if not missing else Severity.LOW
            self.add_finding(
                title=f"Input validation detected ({total_categories}/{total_expected} categories)",
                description=(
                    f"Found input validation patterns in {total_categories} of "
                    f"{total_expected} categories: {', '.join(detected.keys())}."
                    + (
                        f" Missing categories: {', '.join(missing)}. "
                        "Consider adding validation for these areas."
                        if missing else
                        " All major input validation categories are covered."
                    )
                ),
                severity=severity,
                owasp_llm=["LLM01"],
                owasp_agentic=["ASI01"],
                nist_ai_rmf=["MEASURE"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"Input validation: {', '.join(detected.keys())}",
                        raw_data="\n".join(details_lines),
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Ensure input validation covers all categories: length limits, "
                    "content type checking, encoding validation, and injection "
                    "pattern filtering. Apply validation consistently across all "
                    "user-facing input paths."
                    + (f" Missing: {', '.join(missing)}." if missing else "")
                ),
            )
        else:
            self.add_finding(
                title="No input validation or sanitization detected",
                description=(
                    "No input validation patterns (length limits, content type "
                    "validation, encoding checks, injection filtering) were found "
                    "in the source code. Without input validation, the AI system "
                    "is vulnerable to oversized inputs, encoding attacks, prompt "
                    "injection, and other input manipulation techniques."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM01"],
                owasp_agentic=["ASI01", "ASI09"],
                nist_ai_rmf=["GOVERN", "MEASURE"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="No input validation found",
                        raw_data=f"Searched {len(source_files)} source files for validation patterns.",
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Implement input validation covering: (1) input length limits to "
                    "prevent resource exhaustion, (2) content type validation to reject "
                    "unexpected formats, (3) encoding validation to block encoding-based "
                    "attacks, and (4) injection pattern filtering to detect known prompt "
                    "injection payloads. Use a defense-in-depth approach with multiple layers."
                ),
                cvss_score=7.5,
                ai_risk_score=8.0,
            )

    # ------------------------------------------------------------------
    # 3. Output filtering
    # ------------------------------------------------------------------

    async def _check_output_filtering(self, source_files: dict[str, str]) -> None:
        """Check for output sanitization and filtering mechanisms."""
        detected: dict[str, list[str]] = {}

        for fpath, content in source_files.items():
            for category, pattern in OUTPUT_FILTERING_PATTERNS:
                match = pattern.search(content)
                if match:
                    start = max(0, match.start() - 30)
                    end = min(len(content), match.end() + 80)
                    snippet = content[start:end].strip().replace("\n", " ")
                    detected.setdefault(category, []).append(
                        f"{fpath}: {snippet[:120]}"
                    )

        if detected:
            details_lines: list[str] = []
            for category, hits in detected.items():
                details_lines.append(f"  [{category}] ({len(hits)} occurrence(s))")
                for hit in hits[:3]:
                    details_lines.append(f"    - {hit}")

            total_categories = len(detected)
            total_expected = len(OUTPUT_FILTERING_PATTERNS)
            missing = [
                cat for cat, _ in OUTPUT_FILTERING_PATTERNS if cat not in detected
            ]

            severity = Severity.INFO if not missing else Severity.LOW
            self.add_finding(
                title=f"Output filtering detected ({total_categories}/{total_expected} categories)",
                description=(
                    f"Found output filtering patterns in {total_categories} of "
                    f"{total_expected} categories: {', '.join(detected.keys())}."
                    + (
                        f" Missing categories: {', '.join(missing)}. "
                        "Consider adding output filtering for these areas."
                        if missing else
                        " All major output filtering categories are covered."
                    )
                ),
                severity=severity,
                owasp_llm=["LLM05"],
                owasp_agentic=["ASI09"],
                nist_ai_rmf=["MEASURE"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"Output filtering: {', '.join(detected.keys())}",
                        raw_data="\n".join(details_lines),
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Ensure output filtering covers all categories: PII redaction, "
                    "HTML/XSS sanitization, profanity/toxicity filtering, confidence "
                    "thresholds, and response length limits."
                    + (f" Missing: {', '.join(missing)}." if missing else "")
                ),
            )
        else:
            self.add_finding(
                title="No output filtering or sanitization detected",
                description=(
                    "No output filtering patterns (PII redaction, HTML/XSS "
                    "sanitization, profanity filtering, confidence thresholds, "
                    "response length limits) were found in the source code. "
                    "Without output filtering, the AI system may leak sensitive "
                    "information, produce harmful content, or generate responses "
                    "that introduce downstream vulnerabilities such as XSS."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM05"],
                owasp_agentic=["ASI09"],
                nist_ai_rmf=["GOVERN", "MEASURE"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="No output filtering found",
                        raw_data=f"Searched {len(source_files)} source files for output filtering patterns.",
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Implement output filtering covering: (1) PII redaction to prevent "
                    "sensitive data leakage (consider Microsoft Presidio), (2) HTML/XSS "
                    "sanitization for web-facing outputs, (3) profanity/toxicity filtering "
                    "to block harmful content, (4) confidence thresholds to suppress "
                    "low-confidence or hallucinated responses, and (5) response length "
                    "limits to prevent resource exhaustion."
                ),
                references=[
                    "https://microsoft.github.io/presidio/",
                ],
                cvss_score=6.5,
                ai_risk_score=7.5,
            )

    # ------------------------------------------------------------------
    # 4. Content moderation
    # ------------------------------------------------------------------

    async def _check_content_moderation(self, source_files: dict[str, str]) -> None:
        """Look for content moderation mechanisms."""
        detected: dict[str, list[str]] = {}

        for fpath, content in source_files.items():
            for category, pattern in CONTENT_MODERATION_PATTERNS:
                match = pattern.search(content)
                if match:
                    start = max(0, match.start() - 30)
                    end = min(len(content), match.end() + 80)
                    snippet = content[start:end].strip().replace("\n", " ")
                    detected.setdefault(category, []).append(
                        f"{fpath}: {snippet[:120]}"
                    )

        if detected:
            details_lines: list[str] = []
            for category, hits in detected.items():
                details_lines.append(f"  [{category}] ({len(hits)} occurrence(s))")
                for hit in hits[:3]:
                    details_lines.append(f"    - {hit}")

            self.add_finding(
                title=f"Content moderation detected ({len(detected)} mechanism(s))",
                description=(
                    f"Found content moderation mechanisms: {', '.join(detected.keys())}. "
                    "Content moderation helps prevent harmful, offensive, or "
                    "policy-violating content from being generated or processed. "
                    "Verify that moderation is applied consistently to both inputs "
                    "and outputs."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM05", "LLM09"],
                owasp_agentic=["ASI09"],
                nist_ai_rmf=["GOVERN", "MEASURE"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"Content moderation: {', '.join(detected.keys())}",
                        raw_data="\n".join(details_lines),
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Continue maintaining content moderation. Ensure moderation "
                    "covers both user inputs and model outputs. Regularly update "
                    "blocklists and moderation classifiers to address emerging threats."
                ),
            )
        else:
            self.add_finding(
                title="No content moderation detected",
                description=(
                    "No content moderation mechanisms (moderation APIs, custom "
                    "classifiers, blocklists/allowlists, NSFW detection) were found "
                    "in the source code. Without content moderation, the AI system "
                    "may generate harmful, offensive, or policy-violating content "
                    "that damages user trust and creates legal or reputational risk."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM05", "LLM09"],
                owasp_agentic=["ASI09"],
                nist_ai_rmf=["GOVERN", "MEASURE"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="No content moderation found",
                        raw_data=f"Searched {len(source_files)} source files for moderation patterns.",
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Implement content moderation: (1) use provider moderation APIs "
                    "(OpenAI Moderation, Anthropic content filtering) for baseline "
                    "safety, (2) add custom classifiers for domain-specific content "
                    "policies, (3) maintain blocklists for forbidden topics and "
                    "allowlists for approved topics, (4) implement NSFW detection "
                    "if the system handles image or multimedia content."
                ),
                cvss_score=5.0,
                ai_risk_score=6.5,
            )

    # ------------------------------------------------------------------
    # 5. Rate limiting
    # ------------------------------------------------------------------

    async def _check_rate_limiting(self, source_files: dict[str, str]) -> None:
        """Detect rate limiting and request throttling mechanisms."""
        detected: dict[str, list[str]] = {}

        for fpath, content in source_files.items():
            for category, pattern in RATE_LIMIT_PATTERNS:
                match = pattern.search(content)
                if match:
                    start = max(0, match.start() - 30)
                    end = min(len(content), match.end() + 80)
                    snippet = content[start:end].strip().replace("\n", " ")
                    detected.setdefault(category, []).append(
                        f"{fpath}: {snippet[:120]}"
                    )

        # Also check pip packages for rate limiting libraries
        pip_list = await self._exec_in_container(
            "pip list 2>/dev/null || pip3 list 2>/dev/null"
        )
        if pip_list:
            pip_lower = pip_list.lower()
            rate_limit_packages = [
                ("slowapi", "In-memory rate limiting"),
                ("flask-limiter", "In-memory rate limiting"),
                ("django-ratelimit", "In-memory rate limiting"),
                ("ratelimit", "In-memory rate limiting"),
                ("aiohttp-ratelimiter", "In-memory rate limiting"),
            ]
            for pkg_name, category in rate_limit_packages:
                if pkg_name in pip_lower:
                    detected.setdefault(category, []).append(
                        f"pip package: {pkg_name}"
                    )

        if detected:
            details_lines: list[str] = []
            for category, hits in detected.items():
                details_lines.append(f"  [{category}] ({len(hits)} occurrence(s))")
                for hit in hits[:3]:
                    details_lines.append(f"    - {hit}")

            self.add_finding(
                title=f"Rate limiting detected ({len(detected)} mechanism(s))",
                description=(
                    f"Found rate limiting mechanisms: {', '.join(detected.keys())}. "
                    "Rate limiting helps prevent resource exhaustion, denial-of-service "
                    "attacks, and cost overruns from excessive API usage. Verify that "
                    "limits are configured appropriately and cannot be bypassed."
                ),
                severity=Severity.INFO,
                owasp_llm=["LLM09"],
                owasp_agentic=["ASI01"],
                nist_ai_rmf=["MEASURE"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary=f"Rate limiting: {', '.join(detected.keys())}",
                        raw_data="\n".join(details_lines),
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Continue maintaining rate limiting. Ensure limits cover all "
                    "user-facing endpoints. Consider implementing per-user, per-IP, "
                    "and global rate limits. Add token/cost budgets to prevent "
                    "unexpected spending on LLM API calls."
                ),
            )
        else:
            self.add_finding(
                title="No rate limiting detected",
                description=(
                    "No rate limiting mechanisms (API rate limiters, request "
                    "throttling, token/cost limits, concurrent request limits) "
                    "were found in the source code or installed packages. Without "
                    "rate limiting, the AI system is vulnerable to denial-of-service "
                    "attacks, resource exhaustion, and unbounded cost accumulation "
                    "from excessive LLM API calls."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM09"],
                owasp_agentic=["ASI01"],
                nist_ai_rmf=["GOVERN", "MEASURE"],
                evidence=[
                    Evidence(
                        type="file_content",
                        summary="No rate limiting found",
                        raw_data=f"Searched {len(source_files)} source files and pip packages.",
                        location=f"container:{self.context.container_id}",
                    )
                ],
                remediation=(
                    "Implement rate limiting: (1) add API rate limiters using Redis "
                    "or in-memory backends (e.g., slowapi, flask-limiter), "
                    "(2) implement request throttling with token bucket or sliding "
                    "window algorithms, (3) set token/cost budgets per user and "
                    "globally to prevent cost overruns, (4) limit concurrent "
                    "requests using semaphores or connection pools."
                ),
                cvss_score=5.5,
                ai_risk_score=6.0,
            )

    # ------------------------------------------------------------------
    # 6. System prompt protection
    # ------------------------------------------------------------------

    async def _check_system_prompt_protection(self, source_files: dict[str, str]) -> None:
        """Analyze system prompt security posture."""
        cid = self.context.container_id

        # Detect hardcoded system prompts
        hardcoded_prompts: list[tuple[str, str]] = []
        for fpath, content in source_files.items():
            for pattern in SYSTEM_PROMPT_PATTERNS:
                match = pattern.search(content)
                if match:
                    start = max(0, match.start() - 10)
                    end = min(len(content), match.end() + 150)
                    snippet = content[start:end].strip().replace("\n", " ")
                    hardcoded_prompts.append((fpath, snippet[:150]))
                    break

        # Detect environment variable / config-based prompt loading
        env_loaded_prompts: list[str] = []
        for fpath, content in source_files.items():
            for pattern in PROMPT_ENV_PATTERNS:
                if pattern.search(content):
                    env_loaded_prompts.append(fpath)
                    break

        # Detect anti-extraction instructions
        has_anti_extraction = False
        anti_extraction_files: list[str] = []
        for fpath, content in source_files.items():
            for pattern in ANTI_EXTRACTION_PATTERNS:
                if pattern.search(content):
                    has_anti_extraction = True
                    anti_extraction_files.append(fpath)
                    break

        # Detect prompt/user input separation
        separation_patterns = [
            re.compile(r"(?i)(system[_\s]?message|system[_\s]?prompt)\s*.{0,30}(user[_\s]?message|user[_\s]?input|user[_\s]?prompt)"),
            re.compile(r'(?i)\[\s*\{["\']role["\']\s*:\s*["\']system["\'].*\{["\']role["\']\s*:\s*["\']user["\']', re.DOTALL),
            re.compile(r"(?i)(ChatPromptTemplate|SystemMessage|HumanMessage)"),
            re.compile(r"(?i)(messages\s*[:=]\s*\[|messages\.append)"),
        ]
        has_separation = False
        for fpath, content in source_files.items():
            for pattern in separation_patterns:
                if pattern.search(content):
                    has_separation = True
                    break
            if has_separation:
                break

        # No system prompts found at all -- nothing to protect
        if not hardcoded_prompts and not env_loaded_prompts:
            return

        # Build assessment
        issues: list[str] = []
        strengths: list[str] = []

        if hardcoded_prompts and not env_loaded_prompts:
            issues.append(
                f"System prompt hardcoded in {len(hardcoded_prompts)} file(s) "
                "with no environment variable or config file loading detected"
            )
        elif hardcoded_prompts and env_loaded_prompts:
            issues.append(
                f"System prompt hardcoded in {len(hardcoded_prompts)} file(s), "
                f"though env/config loading also found in {len(env_loaded_prompts)} file(s)"
            )
        if env_loaded_prompts:
            strengths.append(
                f"System prompt loaded from environment/config in {len(env_loaded_prompts)} file(s)"
            )

        if has_anti_extraction:
            strengths.append(
                f"Anti-extraction instructions found in {len(anti_extraction_files)} file(s)"
            )
        else:
            issues.append("No anti-extraction instructions detected in system prompts")

        if has_separation:
            strengths.append("System and user message separation detected")
        else:
            issues.append("No clear system/user prompt separation detected")

        evidence_lines: list[str] = []
        if issues:
            evidence_lines.append("Issues:")
            for issue in issues:
                evidence_lines.append(f"  - {issue}")
        if strengths:
            evidence_lines.append("Strengths:")
            for strength in strengths:
                evidence_lines.append(f"  + {strength}")
        if hardcoded_prompts:
            evidence_lines.append("Hardcoded prompt locations:")
            for fpath, snippet in hardcoded_prompts[:5]:
                evidence_lines.append(f"  {fpath}: {snippet[:80]}...")

        # Determine severity
        if hardcoded_prompts and not has_anti_extraction and not has_separation:
            severity = Severity.HIGH
        elif hardcoded_prompts and (not has_anti_extraction or not has_separation):
            severity = Severity.MEDIUM
        elif issues:
            severity = Severity.LOW
        else:
            severity = Severity.INFO

        self.add_finding(
            title=f"System prompt security assessment ({len(issues)} issue(s), {len(strengths)} strength(s))",
            description=(
                "Evaluated system prompt security across four dimensions: "
                "storage method (hardcoded vs. externalized), anti-extraction "
                "instructions, prompt/user input separation, and configuration "
                "security. "
                + (
                    f"Found {len(issues)} issue(s): {'; '.join(issues)}. "
                    if issues else "No issues found. "
                )
                + (
                    f"Positive controls: {'; '.join(strengths)}."
                    if strengths else ""
                )
            ),
            severity=severity,
            owasp_llm=["LLM01", "LLM09"],
            owasp_agentic=["ASI01"],
            nist_ai_rmf=["GOVERN", "MEASURE"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary="System prompt security assessment",
                    raw_data="\n".join(evidence_lines),
                    location=f"container:{cid}" if cid else "unknown",
                )
            ],
            remediation=(
                "Secure system prompts by: (1) loading prompts from environment "
                "variables or a secrets manager instead of hardcoding, (2) adding "
                "anti-extraction instructions that direct the model to refuse "
                "revealing its system prompt, (3) maintaining clear separation "
                "between system instructions and user inputs using the provider's "
                "message role API, (4) implementing error handling that does not "
                "expose prompts in stack traces or error messages."
            ),
            references=[
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            ],
            cvss_score=6.5 if severity in (Severity.HIGH, Severity.MEDIUM) else None,
            ai_risk_score=7.0 if severity in (Severity.HIGH, Severity.MEDIUM) else None,
        )

    # ------------------------------------------------------------------
    # 7. Tool authorization
    # ------------------------------------------------------------------

    async def _check_tool_authorization(self, source_files: dict[str, str]) -> None:
        """Check tool/function calling security controls."""
        # Detect tool usage
        tool_files: list[tuple[str, str]] = []
        for fpath, content in source_files.items():
            for pattern in TOOL_DEFINITION_PATTERNS:
                match = pattern.search(content)
                if match:
                    start = max(0, match.start() - 40)
                    end = min(len(content), match.end() + 120)
                    snippet = content[start:end].strip().replace("\n", " ")
                    tool_files.append((fpath, snippet[:150]))
                    break

        if not tool_files:
            return  # No tool usage, nothing to check

        # Check for tool whitelisting
        has_whitelist = False
        whitelist_locations: list[str] = []
        for fpath, content in source_files.items():
            for pattern in TOOL_WHITELIST_PATTERNS:
                if pattern.search(content):
                    has_whitelist = True
                    whitelist_locations.append(fpath)
                    break

        # Check for authorization before tool execution
        has_auth = False
        auth_locations: list[str] = []
        for fpath, content in source_files.items():
            for pattern in TOOL_AUTH_PATTERNS:
                if pattern.search(content):
                    has_auth = True
                    auth_locations.append(fpath)
                    break

        # Check for dangerous tool capabilities
        dangerous_tools: dict[str, list[str]] = {}
        capability_labels = {
            0: "Shell/code execution",
            1: "Filesystem write/delete",
            2: "Network requests",
            3: "Database queries",
        }
        for fpath, content in source_files.items():
            for idx, pattern in enumerate(DANGEROUS_TOOL_PATTERNS):
                match = pattern.search(content)
                if match:
                    label = capability_labels[idx]
                    dangerous_tools.setdefault(label, []).append(fpath)

        # Check for confirmation on destructive actions
        has_confirmation = False
        confirmation_locations: list[str] = []
        for fpath, content in source_files.items():
            for pattern in CONFIRMATION_PATTERNS:
                if pattern.search(content):
                    has_confirmation = True
                    confirmation_locations.append(fpath)
                    break

        # Build assessment
        issues: list[str] = []
        strengths: list[str] = []

        if has_whitelist:
            strengths.append(
                f"Tool whitelisting found in {len(whitelist_locations)} file(s)"
            )
        else:
            issues.append("No tool whitelisting detected")

        if has_auth:
            strengths.append(
                f"Tool authorization checks found in {len(auth_locations)} file(s)"
            )
        else:
            issues.append("No authorization checks before tool execution")

        if dangerous_tools:
            ungated_dangerous = []
            for label, files in dangerous_tools.items():
                gated = any(
                    f in whitelist_locations or f in auth_locations or f in confirmation_locations
                    for f in files
                )
                if not gated:
                    ungated_dangerous.append(label)
            if ungated_dangerous:
                issues.append(
                    f"Dangerous tool capabilities without apparent gating: "
                    f"{', '.join(ungated_dangerous)}"
                )
            else:
                strengths.append("Dangerous tool capabilities appear to be gated")

        if has_confirmation:
            strengths.append(
                f"Destructive action confirmation found in {len(confirmation_locations)} file(s)"
            )
        elif dangerous_tools:
            issues.append("No confirmation required for destructive actions")

        # Build evidence
        evidence_lines: list[str] = []
        evidence_lines.append(f"Tool usage in {len(tool_files)} file(s):")
        for fpath, snippet in tool_files[:5]:
            evidence_lines.append(f"  - {fpath}: {snippet[:80]}...")
        if issues:
            evidence_lines.append("Issues:")
            for issue in issues:
                evidence_lines.append(f"  - {issue}")
        if strengths:
            evidence_lines.append("Strengths:")
            for strength in strengths:
                evidence_lines.append(f"  + {strength}")
        if dangerous_tools:
            evidence_lines.append("Dangerous capabilities:")
            for label, files in dangerous_tools.items():
                evidence_lines.append(f"  [{label}] in {len(files)} file(s)")

        # Determine severity
        if not has_whitelist and not has_auth and dangerous_tools:
            severity = Severity.CRITICAL
        elif not has_whitelist and not has_auth:
            severity = Severity.HIGH
        elif issues:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        self.add_finding(
            title=f"Tool authorization assessment ({len(issues)} issue(s), {len(strengths)} strength(s))",
            description=(
                f"The agent uses tool/function calling in {len(tool_files)} file(s). "
                "Evaluated tool security across four dimensions: whitelisting, "
                "authorization, dangerous capability gating, and destructive action "
                "confirmation. "
                + (
                    f"Found {len(issues)} issue(s): {'; '.join(issues)}. "
                    if issues else "No issues found. "
                )
                + (
                    f"Positive controls: {'; '.join(strengths)}."
                    if strengths else ""
                )
            ),
            severity=severity,
            owasp_llm=["LLM01", "LLM05"],
            owasp_agentic=["ASI01", "ASI09"],
            nist_ai_rmf=["GOVERN", "MANAGE"],
            evidence=[
                Evidence(
                    type="file_content",
                    summary="Tool authorization assessment",
                    raw_data="\n".join(evidence_lines),
                    location=f"container:{self.context.container_id}",
                )
            ],
            remediation=(
                "Secure tool/function calling by: (1) maintaining an explicit "
                "whitelist of permitted tools and rejecting unlisted invocations, "
                "(2) implementing authorization checks that verify the caller has "
                "permission before tool execution, (3) gating dangerous capabilities "
                "(shell execution, filesystem writes, network requests, database "
                "queries) behind additional safeguards, (4) requiring user "
                "confirmation or human-in-the-loop approval for destructive or "
                "irreversible actions."
            ),
            references=[
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            ],
            cvss_score=9.0 if severity == Severity.CRITICAL else (
                7.0 if severity == Severity.HIGH else None
            ),
            ai_risk_score=9.5 if severity == Severity.CRITICAL else (
                7.5 if severity == Severity.HIGH else None
            ),
        )
