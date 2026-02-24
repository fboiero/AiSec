"""Agent memory store security agent."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# Memory store instantiation patterns
MEMORY_STORE_PATTERNS = re.compile(
    r'(?:ConversationBufferMemory|ConversationBufferWindowMemory|'
    r'ConversationSummaryMemory|ConversationSummaryBufferMemory|'
    r'ConversationTokenBufferMemory|ConversationEntityMemory|'
    r'FileChatMessageHistory|SQLChatMessageHistory|'
    r'RedisChatMessageHistory|MongoDBChatMessageHistory|'
    r'DynamoDBChatMessageHistory|PostgresChatMessageHistory|'
    r'ChatMessageHistory|InMemoryChatMessageHistory|'
    r'VectorStoreRetrieverMemory|ConversationKGMemory)\s*\(',
)

# Memory write / save operations
MEMORY_WRITE_PATTERNS = re.compile(
    r'(?:save_context|add_user_message|add_ai_message|'
    r'add_message|memory\.save|chat_memory\.add|'
    r'memory\.chat_memory\.add|save_memory|'
    r'memory_store\.put|memory\.put|store_memory)',
)

# Unbounded memory patterns (no window, no limit)
UNBOUNDED_MEMORY_PATTERNS = re.compile(
    r'ConversationBufferMemory\s*\(',
)

# Bounded memory indicators
BOUNDED_MEMORY_PATTERNS = re.compile(
    r'(?:ConversationBufferWindowMemory|ConversationSummaryMemory|'
    r'ConversationSummaryBufferMemory|ConversationTokenBufferMemory|'
    r'max_token_limit|k\s*=\s*\d+|max_history|max_messages|'
    r'window_size|token_limit|max_turns)',
    re.IGNORECASE,
)

# Encryption patterns
ENCRYPTION_PATTERNS = re.compile(
    r'(?:encrypt|decrypt|Fernet|AES|cipher|kms|vault|'
    r'cryptography|nacl|chacha|sealed_box|secret_box|'
    r'encrypted_field|encrypt_at_rest|aws_encryption)',
    re.IGNORECASE,
)

# Access control / user isolation patterns
MEMORY_ACCESS_CONTROL_PATTERNS = re.compile(
    r'(?:user_id|session_id|tenant_id|org_id|'
    r'conversation_id.*user|user.*conversation_id|'
    r'memory_key.*user|per_user|user_memory|'
    r'get_session_history|session_factory)',
    re.IGNORECASE,
)

# Global / shared memory indicators
SHARED_MEMORY_PATTERNS = re.compile(
    r'(?:memory\s*=\s*(?:ConversationBufferMemory|ChatMessageHistory)\s*\(\s*\)|'
    r'global_memory|shared_memory|app\.state\.memory|'
    r'memory\s*=\s*\{\}|memory_store\s*=\s*\{\})',
)

# PII detection / scrubbing patterns
PII_SCRUB_PATTERNS = re.compile(
    r'(?:scrub_pii|anonymize|presidio|redact|mask_pii|'
    r'pii_filter|remove_pii|sanitize_pii|'
    r'AnalyzerEngine|AnonymizerEngine|'
    r'pii_detect|strip_pii|clean_pii)',
    re.IGNORECASE,
)

# Tool output to memory patterns
TOOL_TO_MEMORY_PATTERNS = re.compile(
    r'(?:tool_result.*memory|tool_output.*save|'
    r'add_message.*tool|memory.*tool_result|'
    r'save_context.*tool|tool.*add_message)',
    re.IGNORECASE,
)

# Tool output sanitization before memory
TOOL_SANITIZE_PATTERNS = re.compile(
    r'(?:sanitize.*tool|validate.*tool.*output|'
    r'clean.*tool.*result|filter.*tool.*output|'
    r'tool.*sanitize|tool.*validate)',
    re.IGNORECASE,
)

# Unsafe serialization patterns
UNSAFE_SERIAL_PATTERNS = re.compile(
    r'(?:pickle\.dump|pickle\.load|pickle\.dumps|pickle\.loads|'
    r'shelve\.open|marshal\.dump|marshal\.load|'
    r'cloudpickle|dill\.dump|dill\.load)',
)

# Safe serialization patterns
SAFE_SERIAL_PATTERNS = re.compile(
    r'(?:json\.dump|json\.load|orjson|msgpack|protobuf|'
    r'pydantic.*model_dump|to_json|from_json)',
    re.IGNORECASE,
)

# Memory audit / logging patterns
MEMORY_AUDIT_PATTERNS = re.compile(
    r'(?:logger.*memory|log.*memory|audit.*memory|'
    r'memory.*log|memory.*audit|track.*memory|'
    r'memory_event|on_memory_write|memory.*telemetry)',
    re.IGNORECASE,
)

# User input to long-term memory without validation
USER_INPUT_TO_MEMORY = re.compile(
    r'(?:user_input.*save_context|input.*memory\.save|'
    r'request\..*memory|user_message.*long_term|'
    r'add_user_message\s*\(\s*(?:user_input|message|text|query|request))',
    re.IGNORECASE,
)

# Memory validation / filtering
MEMORY_VALIDATION_PATTERNS = re.compile(
    r'(?:validate.*memory|filter.*memory|check.*memory|'
    r'memory.*validate|memory.*filter|content_filter|'
    r'input_guard|guardrail.*memory)',
    re.IGNORECASE,
)


class AgentMemorySecurityAgent(BaseAgent):
    """Secures agent memory stores and conversation persistence."""

    name: ClassVar[str] = "agent_memory"
    description: ClassVar[str] = (
        "Secures agent memory stores and conversation persistence: "
        "unencrypted stores, access controls, memory poisoning, "
        "unbounded growth, cross-session leakage, PII in memory, "
        "and unsafe serialization."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["ASI06", "LLM02", "LLM01"]
    depends_on: ClassVar[list[str]] = []

    async def analyze(self) -> None:
        """Analyze agent memory security."""
        source_files = await self._collect_source_files()
        if not source_files:
            self.add_finding(
                title="No source files for memory analysis",
                description="No Python source files found in the container.",
                severity=Severity.INFO,
                owasp_agentic=["ASI06"],
            )
            return

        all_content: dict[str, str] = {}
        for fpath in source_files[:100]:
            content = await self._read_file(fpath)
            if content:
                all_content[fpath] = content

        if not all_content:
            return

        combined = "\n".join(all_content.values())

        # Only run checks if memory patterns are detected
        has_memory = bool(MEMORY_STORE_PATTERNS.search(combined))
        if not has_memory:
            return

        self._check_unencrypted_stores(all_content, combined)
        self._check_no_access_controls(all_content, combined)
        self._check_memory_poisoning(all_content, combined)
        self._check_unbounded_growth(all_content, combined)
        self._check_cross_session_leakage(all_content, combined)
        self._check_pii_in_memory(all_content, combined)
        self._check_memory_injection_via_tools(combined)
        self._check_unsafe_serialization(all_content)
        self._check_no_audit_trail(combined)

    def _check_unencrypted_stores(self, files: dict[str, str], combined: str) -> None:
        """Check for persistent memory stores without encryption."""
        # Persistent store patterns (file, SQL, Redis, Mongo — not in-memory)
        persistent_store = re.compile(
            r'(?:FileChatMessageHistory|SQLChatMessageHistory|'
            r'RedisChatMessageHistory|MongoDBChatMessageHistory|'
            r'DynamoDBChatMessageHistory|PostgresChatMessageHistory)\s*\(',
        )
        for fpath, content in files.items():
            store_matches = list(persistent_store.finditer(content))
            if not store_matches:
                continue

            has_encryption = bool(ENCRYPTION_PATTERNS.search(content))
            if not has_encryption:
                lines = [str(content[:m.start()].count("\n") + 1) for m in store_matches]
                self.add_finding(
                    title="Unencrypted persistent memory store",
                    description=(
                        f"Persistent memory store(s) at {fpath} (lines: "
                        f"{', '.join(lines)}) store conversation history without "
                        "encryption. Chat messages may contain sensitive data, "
                        "credentials, or PII that would be exposed if the store "
                        "is compromised."
                    ),
                    severity=Severity.HIGH,
                    owasp_llm=["LLM02"],
                    owasp_agentic=["ASI06"],
                    nist_ai_rmf=["GOVERN"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Unencrypted memory store at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Encrypt memory stores at rest. Use database-level encryption "
                        "(e.g., TDE) or application-level encryption with Fernet/AES "
                        "before persisting chat messages."
                    ),
                    cvss_score=7.0,
                    ai_risk_score=7.0,
                )

    def _check_no_access_controls(self, files: dict[str, str], combined: str) -> None:
        """Check for global memory dictionaries without user-scoped access."""
        for fpath, content in files.items():
            shared_matches = list(SHARED_MEMORY_PATTERNS.finditer(content))
            if not shared_matches:
                continue

            has_access_control = bool(MEMORY_ACCESS_CONTROL_PATTERNS.search(content))
            if not has_access_control:
                lines = [str(content[:m.start()].count("\n") + 1) for m in shared_matches]
                self.add_finding(
                    title="No memory access controls",
                    description=(
                        f"Shared/global memory at {fpath} (lines: {', '.join(lines)}) "
                        "lacks user_id or session scoping. All users share the same "
                        "memory store, enabling cross-user data leakage."
                    ),
                    severity=Severity.HIGH,
                    owasp_llm=["LLM02"],
                    owasp_agentic=["ASI06"],
                    nist_ai_rmf=["GOVERN"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Shared memory without access control at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Scope memory by user_id/session_id: use "
                        "get_session_history(session_id) or pass user_id to memory "
                        "constructors. Never share memory across users."
                    ),
                    cvss_score=7.5,
                    ai_risk_score=7.5,
                )

    def _check_memory_poisoning(self, files: dict[str, str], combined: str) -> None:
        """Check for user input written to long-term memory without validation."""
        has_user_to_memory = bool(USER_INPUT_TO_MEMORY.search(combined))
        has_validation = bool(MEMORY_VALIDATION_PATTERNS.search(combined))

        if has_user_to_memory and not has_validation:
            self.add_finding(
                title="Memory poisoning: user input to long-term memory without validation",
                description=(
                    "User input is saved to long-term memory without validation "
                    "or content filtering. An attacker can inject adversarial content "
                    "into memory that persists across conversations, poisoning future "
                    "agent responses and enabling persistent prompt injection."
                ),
                severity=Severity.CRITICAL,
                owasp_llm=["LLM01"],
                owasp_agentic=["ASI06"],
                nist_ai_rmf=["GOVERN", "MEASURE"],
                remediation=(
                    "Validate and filter user input before writing to long-term memory. "
                    "Use content filters to block injection payloads. Consider a review "
                    "step for long-term memory writes."
                ),
                cvss_score=9.0,
                ai_risk_score=9.0,
            )

    def _check_unbounded_growth(self, files: dict[str, str], combined: str) -> None:
        """Check for unbounded conversation memory without limits."""
        for fpath, content in files.items():
            unbounded_matches = list(UNBOUNDED_MEMORY_PATTERNS.finditer(content))
            if not unbounded_matches:
                continue

            # Check if bounded patterns exist in the same file
            has_bounds = bool(BOUNDED_MEMORY_PATTERNS.search(content))
            if not has_bounds:
                lines = [str(content[:m.start()].count("\n") + 1) for m in unbounded_matches]
                self.add_finding(
                    title="Unbounded memory growth",
                    description=(
                        f"ConversationBufferMemory at {fpath} (lines: "
                        f"{', '.join(lines)}) stores all messages without limits. "
                        "This can cause token budget exhaustion, increased latency, "
                        "and out-of-memory errors in long conversations."
                    ),
                    severity=Severity.MEDIUM,
                    owasp_llm=["LLM10"],
                    owasp_agentic=["ASI06"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Unbounded memory at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Use bounded memory: ConversationBufferWindowMemory(k=10), "
                        "ConversationSummaryMemory, or set max_token_limit. "
                        "Implement periodic memory pruning."
                    ),
                    cvss_score=5.0,
                    ai_risk_score=5.0,
                )

    def _check_cross_session_leakage(self, files: dict[str, str], combined: str) -> None:
        """Check for shared memory across users or sessions."""
        has_memory_store = bool(MEMORY_STORE_PATTERNS.search(combined))
        has_access_control = bool(MEMORY_ACCESS_CONTROL_PATTERNS.search(combined))

        # Detect module-level / global memory singletons
        module_level_memory = re.compile(
            r'^(?:memory|chat_memory|store)\s*=\s*(?:Conversation|Chat|Redis|SQL)',
            re.MULTILINE,
        )
        has_global_singleton = bool(module_level_memory.search(combined))

        if has_memory_store and has_global_singleton and not has_access_control:
            self.add_finding(
                title="Cross-session data leakage via shared memory",
                description=(
                    "A global/module-level memory instance is shared across "
                    "sessions without user or session isolation. Conversation "
                    "data from one user can leak into another user's context, "
                    "exposing sensitive information."
                ),
                severity=Severity.CRITICAL,
                owasp_llm=["LLM02"],
                owasp_agentic=["ASI06"],
                nist_ai_rmf=["GOVERN", "MEASURE"],
                remediation=(
                    "Create per-session memory instances scoped by session_id/user_id. "
                    "Use a session factory: get_session_history(session_id) to ensure "
                    "isolation. Never share memory objects across requests."
                ),
                cvss_score=9.0,
                ai_risk_score=9.0,
            )

    def _check_pii_in_memory(self, files: dict[str, str], combined: str) -> None:
        """Check for missing PII scrubbing before memory storage."""
        has_memory_write = bool(MEMORY_WRITE_PATTERNS.search(combined))
        has_pii_scrub = bool(PII_SCRUB_PATTERNS.search(combined))

        if has_memory_write and not has_pii_scrub:
            self.add_finding(
                title="PII in persistent memory without scrubbing",
                description=(
                    "Conversation messages are persisted to memory without PII "
                    "detection or scrubbing. Users may share personal information "
                    "(names, emails, SSNs, addresses) in conversations that gets "
                    "stored indefinitely."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM02"],
                owasp_agentic=["ASI06"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                remediation=(
                    "Add PII scrubbing before memory storage using Presidio, "
                    "spaCy NER, or regex-based PII detection. Implement data "
                    "retention policies with automatic memory expiration."
                ),
                cvss_score=7.0,
                ai_risk_score=7.5,
            )

    def _check_memory_injection_via_tools(self, combined: str) -> None:
        """Check for tool outputs written to memory without sanitization."""
        has_tool_to_memory = bool(TOOL_TO_MEMORY_PATTERNS.search(combined))
        has_sanitization = bool(TOOL_SANITIZE_PATTERNS.search(combined))

        if has_tool_to_memory and not has_sanitization:
            self.add_finding(
                title="Memory injection via unsanitized tool outputs",
                description=(
                    "Tool outputs are stored in agent memory without sanitization. "
                    "A compromised or manipulated tool could inject adversarial "
                    "content into memory that persists across turns, enabling "
                    "indirect prompt injection through memory recall."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM01"],
                owasp_agentic=["ASI06"],
                nist_ai_rmf=["MEASURE"],
                remediation=(
                    "Sanitize and validate tool outputs before writing to memory. "
                    "Apply content filters, length limits, and injection detection "
                    "to tool results before memory storage."
                ),
                cvss_score=7.5,
                ai_risk_score=8.0,
            )

    def _check_unsafe_serialization(self, files: dict[str, str]) -> None:
        """Check for pickle or unsafe serialization of memory."""
        for fpath, content in files.items():
            has_memory = bool(MEMORY_STORE_PATTERNS.search(content))
            if not has_memory:
                continue

            unsafe_matches = list(UNSAFE_SERIAL_PATTERNS.finditer(content))
            if not unsafe_matches:
                continue

            lines = [str(content[:m.start()].count("\n") + 1) for m in unsafe_matches]
            self.add_finding(
                title="Unsafe memory serialization with pickle",
                description=(
                    f"Memory at {fpath} (lines: {', '.join(lines)}) uses pickle "
                    "or similar unsafe serialization. Pickle deserialization can "
                    "execute arbitrary code, allowing an attacker who controls "
                    "the memory store to achieve remote code execution."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM02"],
                owasp_agentic=["ASI06"],
                nist_ai_rmf=["GOVERN"],
                evidence=[Evidence(
                    type="file_content",
                    summary=f"Unsafe pickle serialization at {fpath}",
                    raw_data=f"Lines: {', '.join(lines)}",
                    location=fpath,
                )],
                remediation=(
                    "Replace pickle with JSON or msgpack for memory serialization. "
                    "Never deserialize untrusted data with pickle. Use "
                    "json.dumps/json.loads or Pydantic model_dump/model_validate."
                ),
                cvss_score=8.0,
                ai_risk_score=8.0,
            )

    def _check_no_audit_trail(self, combined: str) -> None:
        """Check for absence of memory write logging."""
        has_memory_write = bool(MEMORY_WRITE_PATTERNS.search(combined))
        has_audit = bool(MEMORY_AUDIT_PATTERNS.search(combined))

        if has_memory_write and not has_audit:
            self.add_finding(
                title="No memory audit trail",
                description=(
                    "Memory write operations are not logged or audited. Without "
                    "an audit trail, memory poisoning attacks cannot be detected, "
                    "investigated, or rolled back."
                ),
                severity=Severity.MEDIUM,
                owasp_agentic=["ASI06"],
                nist_ai_rmf=["GOVERN", "MANAGE"],
                remediation=(
                    "Log all memory write operations including timestamp, user_id, "
                    "operation type, and content hash. Implement memory change "
                    "tracking for forensic analysis."
                ),
                cvss_score=4.0,
                ai_risk_score=5.0,
            )

    async def _collect_source_files(self) -> list[str]:
        """Collect Python source files from the container."""
        cid = self.context.container_id
        if not cid:
            return []

        cmd = (
            "find /app /src /opt -maxdepth 6 -type f -name '*.py' "
            "-size -1M 2>/dev/null | head -200"
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "sh", "-c", cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return []
            return [f.strip() for f in stdout.decode(errors="replace").splitlines() if f.strip()]
        except Exception:
            return []

    async def _read_file(self, fpath: str) -> str:
        """Read a file from the container."""
        cid = self.context.container_id
        if not cid:
            return ""

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", cid, "head", "-c", "65536", fpath,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                return ""
            return stdout.decode(errors="replace")
        except Exception:
            return ""
