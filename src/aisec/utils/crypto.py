"""Secret detection and hashing utilities."""

from __future__ import annotations

import hashlib
import re

# Common secret patterns
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}"),
    "github_token": re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}"),
    "generic_api_key": re.compile(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}"),
    "generic_secret": re.compile(r"(?i)(secret|password|passwd|token)\s*[=:]\s*['\"]?[^\s'\"]{8,}"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),
    "jwt_token": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
    "openai_key": re.compile(r"sk-[A-Za-z0-9]{32,}"),
    "anthropic_key": re.compile(r"sk-ant-[A-Za-z0-9_-]{32,}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9\-]+"),
    "azure_key": re.compile(
        r"(?i)(?:AccountKey|azure[_\-]?(?:storage|subscription)[_\-]?key)\s*[=:]\s*['\"]?[A-Za-z0-9+/=]{40,}"
    ),
    "gcp_key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "stripe_key": re.compile(r"(?:sk|pk)_live_[0-9a-zA-Z]{24,}"),
    "sendgrid_key": re.compile(r"SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,}"),
    "database_url": re.compile(
        r"(?i)(?:postgres(?:ql)?|mysql|mongodb)://[^\s'\"]{10,}"
    ),
}

# PII patterns
PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "phone_international": re.compile(r"\+?[1-9]\d{1,14}"),
    "ssn_us": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
    "dni_argentina": re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}\b"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "passport": re.compile(
        r"\b(?:[A-Z]{1,3})?[0-9]{6,9}\b"
    ),
    "iban": re.compile(
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]{0,18})\b"
    ),
    "mac_address": re.compile(
        r"\b[0-9A-Fa-f]{2}([-:])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}\b"
    ),
    "phone_argentina": re.compile(
        r"\+54\s?(?:9\s?)?(?:11|[2-3]\d{2,3})\s?\d{4}[\s-]?\d{4}\b"
    ),
    "cuit_argentina": re.compile(
        r"\b(?:20|23|24|27|30|33|34)\-?\d{8}\-?\d\b"
    ),
}


def detect_secrets(text: str) -> list[dict[str, str]]:
    """Scan text for potential secrets."""
    results = []
    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            results.append({
                "type": name,
                "match": match.group()[:20] + "..." if len(match.group()) > 20 else match.group(),
                "position": str(match.start()),
            })
    return results


def detect_pii(text: str) -> list[dict[str, str]]:
    """Scan text for potential PII."""
    results = []
    for name, pattern in PII_PATTERNS.items():
        for match in pattern.finditer(text):
            results.append({
                "type": name,
                "match": match.group(),
                "position": str(match.start()),
            })
    return results


def sha256_hash(data: str | bytes) -> str:
    """Compute SHA-256 hash."""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()
