"""Framework enums and category definitions."""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OPEN = "open"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


class AgentPhase(str, Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"
    POST = "post"


class OwaspLlmCategory(str, Enum):
    LLM01 = "LLM01 - Prompt Injection"
    LLM02 = "LLM02 - Sensitive Information Disclosure"
    LLM03 = "LLM03 - Supply Chain"
    LLM04 = "LLM04 - Data and Model Poisoning"
    LLM05 = "LLM05 - Improper Output Handling"
    LLM06 = "LLM06 - Excessive Agency"
    LLM07 = "LLM07 - System Prompt Leakage"
    LLM08 = "LLM08 - Vector and Embedding Weaknesses"
    LLM09 = "LLM09 - Misinformation"
    LLM10 = "LLM10 - Unbounded Consumption"


class OwaspAgenticCategory(str, Enum):
    ASI01 = "ASI01 - Agent Goal Hijacking"
    ASI02 = "ASI02 - Tool Misuse"
    ASI03 = "ASI03 - Identity and Privilege Abuse"
    ASI04 = "ASI04 - Supply Chain Vulnerabilities"
    ASI05 = "ASI05 - Unexpected Code Execution"
    ASI06 = "ASI06 - Memory and Context Poisoning"
    ASI07 = "ASI07 - Insecure Inter-Agent Communication"
    ASI08 = "ASI08 - Cascading Failures"
    ASI09 = "ASI09 - Human-Agent Trust Exploitation"
    ASI10 = "ASI10 - Rogue Agents"


class NistAiRmfFunction(str, Enum):
    GOVERN = "GOVERN"
    MAP = "MAP"
    MEASURE = "MEASURE"
    MANAGE = "MANAGE"


class ComplianceFramework(str, Enum):
    GDPR = "gdpr"
    CCPA = "ccpa"
    HABEAS_DATA = "habeas_data"
    EU_AI_ACT = "eu_ai_act"
    ISO_42001 = "iso_42001"
    NIST_AI_600_1 = "nist_ai_600_1"
    ARGENTINA_AI = "argentina_ai"


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_APPLICABLE = "n/a"
