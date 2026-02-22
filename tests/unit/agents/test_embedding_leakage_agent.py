"""Tests for EmbeddingLeakageAgent."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from aisec.agents.embedding_leakage import (
    EMBEDDING_CACHE_PATTERNS,
    EMBEDDING_PATTERNS,
    FINETUNING_PATTERNS,
    VECTOR_DB_PATTERNS,
    EmbeddingLeakageAgent,
)
from aisec.core.enums import AgentPhase, Severity


class TestEmbeddingLeakageMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert EmbeddingLeakageAgent.name == "embedding_leakage"

    def test_phase(self):
        assert EmbeddingLeakageAgent.phase == AgentPhase.STATIC

    def test_frameworks(self):
        assert "LLM06" in EmbeddingLeakageAgent.frameworks
        assert "ASI06" in EmbeddingLeakageAgent.frameworks

    def test_no_dependencies(self):
        assert EmbeddingLeakageAgent.depends_on == []


class TestVectorDBPatterns:
    """Test vector DB detection patterns."""

    def test_vector_db_patterns_defined(self):
        assert len(VECTOR_DB_PATTERNS) >= 5

    def test_chromadb_pattern(self):
        name, init_pat, auth_pat, _ = VECTOR_DB_PATTERNS[0]
        assert name == "ChromaDB"
        assert init_pat.search("chromadb.Client()")
        assert init_pat.search("chromadb.HttpClient(host='localhost')")

    def test_pinecone_pattern(self):
        name, init_pat, _, _ = VECTOR_DB_PATTERNS[1]
        assert name == "Pinecone"
        assert init_pat.search("pinecone.Pinecone()")

    def test_faiss_pattern(self):
        name, init_pat, _, _ = VECTOR_DB_PATTERNS[5]
        assert name == "FAISS"
        assert init_pat.search("faiss.IndexFlatL2(768)")


class TestEmbeddingPatterns:
    """Test embedding API patterns."""

    def test_embedding_patterns_match(self):
        assert EMBEDDING_PATTERNS.search("openai.embedding.create()")
        assert EMBEDDING_PATTERNS.search("sentence_transformers.encode(text)")
        assert EMBEDDING_PATTERNS.search("embed_query(text)")

    def test_finetuning_patterns_match(self):
        assert FINETUNING_PATTERNS.search("TrainingArguments(output_dir='./results')")
        assert FINETUNING_PATTERNS.search("openai.FineTuningJob.create()")

    def test_cache_patterns_match(self):
        assert EMBEDDING_CACHE_PATTERNS.search("CacheBackedEmbeddings()")
        assert EMBEDDING_CACHE_PATTERNS.search("embedding_cache.get(key)")


class TestEmbeddingLeakageNoContainer:
    """Test agent without container."""

    @pytest.mark.asyncio
    async def test_no_container_returns_info(self, scan_context):
        agent = EmbeddingLeakageAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 1
        assert agent.findings[0].severity == Severity.INFO


class TestVectorDBAuth:
    """Test vector DB authentication checking."""

    def test_detects_chromadb_without_auth(self, scan_context):
        agent = EmbeddingLeakageAgent(scan_context)
        files = {
            "/app/vectordb.py": (
                'import chromadb\n'
                'client = chromadb.Client()\n'
                'collection = client.get_collection("my_data")\n'
            )
        }
        agent._check_vector_db_auth(files)
        auth_findings = [f for f in agent.findings if "auth" in f.title.lower()]
        assert len(auth_findings) >= 1

    def test_chromadb_with_auth_ok(self, scan_context):
        agent = EmbeddingLeakageAgent(scan_context)
        files = {
            "/app/vectordb.py": (
                'import chromadb\n'
                'client = chromadb.HttpClient(\n'
                '    host="localhost",\n'
                '    auth=chromadb.auth.TokenAuth(token=secret)\n'
                ')\n'
            )
        }
        agent._check_vector_db_auth(files)
        auth_findings = [f for f in agent.findings if "ChromaDB" in f.title and "auth" in f.title.lower()]
        assert len(auth_findings) == 0


class TestNamespaceIsolation:
    """Test multi-tenant namespace isolation."""

    def test_detects_multi_tenant_without_isolation(self, scan_context):
        agent = EmbeddingLeakageAgent(scan_context)
        files = {
            "/app/search.py": (
                'from chromadb import Client\n'
                'client = chromadb.Client()\n'
                'tenant = request.tenant_id\n'
                'results = collection.query(query_texts=["hello"])\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_namespace_isolation(files, combined)
        namespace_findings = [f for f in agent.findings if "namespace" in f.title.lower()]
        assert len(namespace_findings) >= 1


class TestTrainingMemorization:
    """Test training data memorization detection."""

    def test_finetuning_without_dp(self, scan_context):
        agent = EmbeddingLeakageAgent(scan_context)
        code = (
            'from transformers import TrainingArguments, Trainer\n'
            'args = TrainingArguments(output_dir="./results")\n'
            'trainer = Trainer(model=model, args=args)\n'
        )
        agent._check_training_memorization(code)
        dp_findings = [f for f in agent.findings if "differential" in f.title.lower() or "privacy" in f.title.lower()]
        assert len(dp_findings) >= 1

    def test_finetuning_with_dp_ok(self, scan_context):
        agent = EmbeddingLeakageAgent(scan_context)
        code = (
            'from transformers import TrainingArguments\n'
            'from opacus import PrivateEngine\n'
            'differential_privacy = True\n'
        )
        agent._check_training_memorization(code)
        dp_findings = [f for f in agent.findings if "differential" in f.title.lower() or "privacy" in f.title.lower()]
        assert len(dp_findings) == 0


class TestEmbeddingCache:
    """Test embedding cache integrity."""

    def test_cache_without_integrity(self, scan_context):
        agent = EmbeddingLeakageAgent(scan_context)
        files = {
            "/app/embeddings.py": (
                'from langchain.embeddings import CacheBackedEmbeddings\n'
                'embeddings = CacheBackedEmbeddings(embedding_model, cache)\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_embedding_cache(files, combined)
        cache_findings = [f for f in agent.findings if "cache" in f.title.lower()]
        assert len(cache_findings) >= 1
