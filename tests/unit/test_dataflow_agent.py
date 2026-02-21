"""Tests for DataFlowAgent."""

import pytest

from aisec.agents.dataflow import (
    DataFlowAgent,
    PII_PATTERNS,
    SECRET_PATTERNS,
)
from aisec.core.context import ScanContext
from aisec.core.enums import AgentPhase


# ── Agent metadata ──────────────────────────────────────────────────

def test_dataflow_agent_name():
    assert DataFlowAgent.name == "dataflow"


def test_dataflow_agent_phase():
    assert DataFlowAgent.phase == AgentPhase.DYNAMIC


def test_dataflow_agent_frameworks():
    assert "LLM02" in DataFlowAgent.frameworks


# ── PII patterns ────────────────────────────────────────────────────

def test_pii_pattern_email():
    assert PII_PATTERNS["email"].search("user@example.com")


def test_pii_pattern_ssn():
    assert PII_PATTERNS["ssn"].search("123-45-6789")


def test_pii_pattern_credit_card():
    assert PII_PATTERNS["credit_card"].search("4111111111111111")


def test_pii_pattern_argentine_dni():
    assert PII_PATTERNS["argentine_dni"].search("30.123.456")


def test_pii_pattern_phone_international():
    assert PII_PATTERNS["phone_international"].search("+14155551234")


# ── Secret patterns ─────────────────────────────────────────────────

def test_secret_pattern_aws_key():
    assert SECRET_PATTERNS["aws_access_key"].search("AKIAIOSFODNN7EXAMPLE")


def test_secret_pattern_private_key():
    assert SECRET_PATTERNS["private_key_header"].search("-----BEGIN RSA PRIVATE KEY-----")


def test_secret_pattern_github_token():
    text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
    assert SECRET_PATTERNS["github_token"].search(text)


def test_secret_pattern_openai_key():
    assert SECRET_PATTERNS["openai_key"].search("sk-abcdefghijklmnopqrstuvwxyz123456")


def test_secret_pattern_connection_string():
    text = "postgres://user:pass@localhost:5432/mydb"
    assert SECRET_PATTERNS["connection_string"].search(text)


def test_secret_pattern_bearer_token():
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"
    assert SECRET_PATTERNS["bearer_token"].search(text)


# ── Agent instantiation ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dataflow_agent_run_no_container():
    """Agent.run() should return without error when no container is set."""
    ctx = ScanContext(target_image="test:latest")
    agent = DataFlowAgent(ctx)
    result = await agent.run()
    assert result.agent == "dataflow"
    assert result.error is None
