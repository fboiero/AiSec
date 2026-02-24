"""Tests for AgentMemorySecurityAgent."""

from __future__ import annotations

import pytest

from aisec.agents.agent_memory import (
    BOUNDED_MEMORY_PATTERNS,
    ENCRYPTION_PATTERNS,
    MEMORY_ACCESS_CONTROL_PATTERNS,
    MEMORY_AUDIT_PATTERNS,
    MEMORY_STORE_PATTERNS,
    MEMORY_VALIDATION_PATTERNS,
    MEMORY_WRITE_PATTERNS,
    PII_SCRUB_PATTERNS,
    SHARED_MEMORY_PATTERNS,
    UNBOUNDED_MEMORY_PATTERNS,
    UNSAFE_SERIAL_PATTERNS,
    USER_INPUT_TO_MEMORY,
    AgentMemorySecurityAgent,
)
from aisec.core.enums import AgentPhase, Severity


class TestAgentMemoryMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert AgentMemorySecurityAgent.name == "agent_memory"

    def test_phase(self):
        assert AgentMemorySecurityAgent.phase == AgentPhase.STATIC

    def test_frameworks(self):
        assert "ASI06" in AgentMemorySecurityAgent.frameworks

    def test_no_dependencies(self):
        assert AgentMemorySecurityAgent.depends_on == []


class TestAgentMemoryPatterns:
    """Test regex pattern matching."""

    def test_memory_store_patterns_match(self):
        assert MEMORY_STORE_PATTERNS.search("ConversationBufferMemory()")
        assert MEMORY_STORE_PATTERNS.search("FileChatMessageHistory(file_path)")

    def test_unbounded_memory_matches(self):
        assert UNBOUNDED_MEMORY_PATTERNS.search("ConversationBufferMemory(")

    def test_bounded_memory_matches(self):
        assert BOUNDED_MEMORY_PATTERNS.search("ConversationBufferWindowMemory")
        assert BOUNDED_MEMORY_PATTERNS.search("k=10")


class TestAgentMemoryNoContainer:
    """Test agent without container."""

    @pytest.mark.asyncio
    async def test_no_container_returns_info(self, scan_context):
        agent = AgentMemorySecurityAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 1
        assert agent.findings[0].severity == Severity.INFO


class TestUnencryptedMemoryStore:
    """Test unencrypted persistent memory store detection."""

    def test_detects_unencrypted_store(self, scan_context):
        agent = AgentMemorySecurityAgent(scan_context)
        files = {
            "/app/memory.py": (
                'from langchain.memory import FileChatMessageHistory\n'
                'history = FileChatMessageHistory(file_path="/data/chat.json")\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_unencrypted_stores(files, combined)
        findings = [f for f in agent.findings if "Unencrypted" in f.title]
        assert len(findings) >= 1

    def test_encrypted_store_passes(self, scan_context):
        agent = AgentMemorySecurityAgent(scan_context)
        files = {
            "/app/memory.py": (
                'from langchain.memory import FileChatMessageHistory\n'
                'from cryptography.fernet import Fernet\n'
                'cipher = Fernet(key)\n'
                'history = FileChatMessageHistory(file_path="/data/chat.json")\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_unencrypted_stores(files, combined)
        findings = [f for f in agent.findings if "Unencrypted" in f.title]
        assert len(findings) == 0


class TestNoAccessControls:
    """Test global memory without access controls."""

    def test_detects_no_access_controls(self, scan_context):
        agent = AgentMemorySecurityAgent(scan_context)
        files = {
            "/app/memory.py": (
                'from langchain.memory import ConversationBufferMemory\n'
                'memory = {}\n'
                'chat_memory = ConversationBufferMemory()\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_no_access_controls(files, combined)
        findings = [f for f in agent.findings if "access control" in f.title.lower()]
        assert len(findings) >= 1


class TestMemoryPoisoning:
    """Test memory poisoning via user input detection."""

    def test_detects_memory_poisoning(self, scan_context):
        agent = AgentMemorySecurityAgent(scan_context)
        files = {
            "/app/chat.py": (
                'from langchain.memory import ConversationBufferMemory\n'
                'memory = ConversationBufferMemory()\n'
                'memory.chat_memory.add_user_message(user_input)\n'
                'memory.chat_memory.add_ai_message(response)\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_memory_poisoning(files, combined)
        findings = [f for f in agent.findings if "poisoning" in f.title.lower()]
        assert len(findings) >= 1


class TestUnboundedMemory:
    """Test unbounded memory growth detection."""

    def test_detects_unbounded_memory(self, scan_context):
        agent = AgentMemorySecurityAgent(scan_context)
        files = {
            "/app/chat.py": (
                'from langchain.memory import ConversationBufferMemory\n'
                'memory = ConversationBufferMemory()\n'
                'chain = ConversationChain(llm=llm, memory=memory)\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_unbounded_growth(files, combined)
        findings = [f for f in agent.findings if "Unbounded" in f.title]
        assert len(findings) >= 1

    def test_bounded_memory_passes(self, scan_context):
        agent = AgentMemorySecurityAgent(scan_context)
        files = {
            "/app/chat.py": (
                'from langchain.memory import ConversationBufferWindowMemory\n'
                'memory = ConversationBufferWindowMemory(k=10)\n'
                'chain = ConversationChain(llm=llm, memory=memory)\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_unbounded_growth(files, combined)
        findings = [f for f in agent.findings if "Unbounded" in f.title]
        assert len(findings) == 0


class TestCrossSessionLeakage:
    """Test cross-session data leakage detection."""

    def test_detects_global_memory_singleton(self, scan_context):
        agent = AgentMemorySecurityAgent(scan_context)
        files = {
            "/app/chat.py": (
                'from langchain.memory import ConversationBufferMemory\n'
                'memory = ConversationBufferMemory()\n'
                '\n'
                'def handle_request(request):\n'
                '    chain = ConversationChain(llm=llm, memory=memory)\n'
                '    return chain.run(request.input)\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_cross_session_leakage(files, combined)
        findings = [f for f in agent.findings if "Cross-session" in f.title]
        assert len(findings) >= 1


class TestPIIInMemory:
    """Test PII in memory without scrubbing detection."""

    def test_detects_pii_no_scrub(self, scan_context):
        agent = AgentMemorySecurityAgent(scan_context)
        files = {
            "/app/chat.py": (
                'from langchain.memory import ConversationBufferMemory\n'
                'memory = ConversationBufferMemory()\n'
                'memory.save_context({"input": msg}, {"output": resp})\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_pii_in_memory(files, combined)
        findings = [f for f in agent.findings if "PII" in f.title]
        assert len(findings) >= 1


class TestUnsafeSerialization:
    """Test unsafe memory serialization detection."""

    def test_detects_pickle_serialization(self, scan_context):
        agent = AgentMemorySecurityAgent(scan_context)
        files = {
            "/app/memory.py": (
                'import pickle\n'
                'from langchain.memory import ConversationBufferMemory\n'
                'memory = ConversationBufferMemory()\n'
                'with open("memory.pkl", "wb") as f:\n'
                '    pickle.dump(memory, f)\n'
            )
        }
        agent._check_unsafe_serialization(files)
        findings = [f for f in agent.findings if "pickle" in f.title.lower() or "serialization" in f.title.lower()]
        assert len(findings) >= 1


class TestNoAuditTrail:
    """Test absence of memory audit trail detection."""

    def test_detects_no_audit_trail(self, scan_context):
        agent = AgentMemorySecurityAgent(scan_context)
        combined = (
            'from langchain.memory import ConversationBufferMemory\n'
            'memory = ConversationBufferMemory()\n'
            'memory.save_context({"input": msg}, {"output": resp})\n'
        )
        agent._check_no_audit_trail(combined)
        findings = [f for f in agent.findings if "audit" in f.title.lower()]
        assert len(findings) >= 1
