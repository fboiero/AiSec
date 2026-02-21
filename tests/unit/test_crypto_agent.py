"""Tests for CryptoAuditAgent."""

import pytest

from aisec.agents.crypto import (
    WEAK_CIPHERS,
    WEAK_CIPHER_PATTERNS,
    WEAK_ALGORITHM_PATTERNS,
    SECRET_PATTERNS,
    WEAK_PRNG_PATTERNS,
    PQC_VULNERABLE_ALGORITHMS,
    CryptoAuditAgent,
)
from aisec.core.context import ScanContext
from aisec.core.enums import AgentPhase


# ── Agent metadata ──────────────────────────────────────────────────

def test_crypto_agent_name():
    assert CryptoAuditAgent.name == "crypto"


def test_crypto_agent_phase():
    assert CryptoAuditAgent.phase == AgentPhase.DYNAMIC


def test_crypto_agent_depends_on_network():
    assert "network" in CryptoAuditAgent.depends_on


def test_crypto_agent_frameworks():
    assert "LLM02" in CryptoAuditAgent.frameworks or "LLM09" in CryptoAuditAgent.frameworks


# ── Weak cipher constants ──────────────────────────────────────────

def test_weak_ciphers_include_rc4():
    assert "RC4" in WEAK_CIPHERS


def test_weak_ciphers_include_des():
    assert "DES" in WEAK_CIPHERS


def test_weak_ciphers_include_null():
    assert "NULL" in WEAK_CIPHERS


# ── Weak cipher patterns ──────────────────────────────────────────

def test_weak_cipher_pattern_detects_rc4():
    assert any(p.search("ssl_ciphers RC4:HIGH") for p in WEAK_CIPHER_PATTERNS)


def test_weak_cipher_pattern_detects_sslv3():
    assert any(p.search("SSLv3") for p in WEAK_CIPHER_PATTERNS)


def test_weak_cipher_pattern_detects_tlsv1():
    assert any(p.search("TLSv1.0") for p in WEAK_CIPHER_PATTERNS)


# ── Weak algorithm patterns ───────────────────────────────────────

def test_weak_algo_detects_md5():
    found = [name for pattern, name, _ in WEAK_ALGORITHM_PATTERNS if pattern.search("hashlib.md5(data)")]
    assert "MD5" in found


def test_weak_algo_detects_sha1():
    found = [name for pattern, name, _ in WEAK_ALGORITHM_PATTERNS if pattern.search("sha-1 digest")]
    assert "SHA-1" in found


def test_weak_algo_detects_ecb():
    found = [name for pattern, name, _ in WEAK_ALGORITHM_PATTERNS if pattern.search("AES/ECB/PKCS5Padding")]
    assert "ECB mode" in found


# ── Secret patterns ───────────────────────────────────────────────

def test_secret_pattern_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----"
    assert any(p.search(text) for p, _ in SECRET_PATTERNS)


def test_secret_pattern_aws_key():
    text = "AKIAIOSFODNN7EXAMPLE"
    assert any(p.search(text) for p, _ in SECRET_PATTERNS)


def test_secret_pattern_openai_key():
    text = "sk-abcdefghijklmnopqrstuvwxyz123456"
    assert any(p.search(text) for p, _ in SECRET_PATTERNS)


# ── Weak PRNG patterns ────────────────────────────────────────────

def test_prng_detects_random_random():
    assert any(p.search("x = random.random()") for p, _ in WEAK_PRNG_PATTERNS)


def test_prng_detects_random_randint():
    assert any(p.search("random.randint(0, 100)") for p, _ in WEAK_PRNG_PATTERNS)


def test_prng_no_false_positive_on_secrets():
    text = "secrets.token_hex(32)"
    assert not any(p.search(text) for p, _ in WEAK_PRNG_PATTERNS)


# ── PQC vulnerable algorithms ─────────────────────────────────────

def test_pqc_detects_rsa():
    found = [name for pattern, name, _ in PQC_VULNERABLE_ALGORITHMS if pattern.search("RSA-2048")]
    assert "RSA" in found


def test_pqc_detects_ecdsa():
    found = [name for pattern, name, _ in PQC_VULNERABLE_ALGORITHMS if pattern.search("ECDSA signing")]
    assert "ECC" in found


def test_pqc_detects_diffie_hellman():
    found = [name for pattern, name, _ in PQC_VULNERABLE_ALGORITHMS if pattern.search("DHE key exchange")]
    assert "Diffie-Hellman" in found


# ── Agent instantiation ───────────────────────────────────────────

def test_crypto_agent_creates_no_findings_without_container():
    """Agent should produce no findings when no container_id is set."""
    ctx = ScanContext(target_image="test:latest")
    agent = CryptoAuditAgent(ctx)
    assert agent.findings == []


@pytest.mark.asyncio
async def test_crypto_agent_run_returns_result():
    """Agent.run() should return an AgentResult even without Docker."""
    ctx = ScanContext(target_image="test:latest")
    agent = CryptoAuditAgent(ctx)
    result = await agent.run()
    assert result.agent == "crypto"
    assert result.error is None
