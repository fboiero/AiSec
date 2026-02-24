"""Tests for RAGSecurityAgent."""

from __future__ import annotations

import pytest

from aisec.agents.rag_security import (
    CONTEXT_ASSEMBLY_PATTERNS,
    EMBEDDING_KEY_PATTERNS,
    GROUNDING_PATTERNS,
    LOADER_PATTERNS,
    LOADER_VALIDATION_PATTERNS,
    RAG_CHAIN_PATTERNS,
    RETRIEVAL_FILTER_PATTERNS,
    RETRIEVAL_PATTERNS,
    SHARED_COLLECTION_PATTERNS,
    SOURCE_ATTRIBUTION_PATTERNS,
    USER_INPUT_IN_LOADER,
    RAGSecurityAgent,
)
from aisec.core.enums import AgentPhase, Severity


class TestRAGSecurityMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert RAGSecurityAgent.name == "rag_security"

    def test_phase(self):
        assert RAGSecurityAgent.phase == AgentPhase.STATIC

    def test_frameworks(self):
        assert "LLM01" in RAGSecurityAgent.frameworks
        assert "LLM08" in RAGSecurityAgent.frameworks

    def test_no_dependencies(self):
        assert RAGSecurityAgent.depends_on == []


class TestRAGPatterns:
    """Test regex pattern matching."""

    def test_loader_patterns_match(self):
        assert LOADER_PATTERNS.search("DirectoryLoader(path)")
        assert LOADER_PATTERNS.search("WebBaseLoader(url)")
        assert LOADER_PATTERNS.search("SimpleDirectoryReader(input_dir)")

    def test_loader_validation_matches(self):
        assert LOADER_VALIDATION_PATTERNS.search("glob='*.pdf'")
        assert LOADER_VALIDATION_PATTERNS.search("allowed_types=['pdf']")

    def test_retrieval_patterns_match(self):
        assert RETRIEVAL_PATTERNS.search(".similarity_search(query)")
        assert RETRIEVAL_PATTERNS.search(".as_retriever()")

    def test_retrieval_filter_matches(self):
        assert RETRIEVAL_FILTER_PATTERNS.search("score_threshold=0.7")
        assert RETRIEVAL_FILTER_PATTERNS.search("top_k=5")


class TestRAGSecurityNoContainer:
    """Test agent without container."""

    @pytest.mark.asyncio
    async def test_no_container_returns_info(self, scan_context):
        agent = RAGSecurityAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 1
        assert agent.findings[0].severity == Severity.INFO


class TestUnvalidatedLoaders:
    """Test unvalidated document loader detection."""

    def test_detects_unvalidated_loader(self, scan_context):
        agent = RAGSecurityAgent(scan_context)
        files = {
            "/app/loader.py": (
                'from langchain.document_loaders import DirectoryLoader\n'
                'loader = DirectoryLoader("/data/docs")\n'
                'docs = loader.load()\n'
            )
        }
        agent._check_unvalidated_loaders(files)
        findings = [f for f in agent.findings if "Unvalidated" in f.title]
        assert len(findings) >= 1

    def test_loader_with_glob_passes(self, scan_context):
        agent = RAGSecurityAgent(scan_context)
        files = {
            "/app/loader.py": (
                'from langchain.document_loaders import DirectoryLoader\n'
                "loader = DirectoryLoader('/data', glob='*.pdf')\n"
                'docs = loader.load()\n'
            )
        }
        agent._check_unvalidated_loaders(files)
        findings = [f for f in agent.findings if "Unvalidated" in f.title]
        assert len(findings) == 0


class TestRetrievalFiltering:
    """Test retrieval without filtering detection."""

    def test_detects_retrieval_without_filter(self, scan_context):
        agent = RAGSecurityAgent(scan_context)
        files = {
            "/app/search.py": (
                'results = vectorstore.similarity_search(query)\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_retrieval_filtering(files, combined)
        findings = [f for f in agent.findings if "filtering" in f.title.lower()]
        assert len(findings) >= 1

    def test_retrieval_with_score_threshold_passes(self, scan_context):
        agent = RAGSecurityAgent(scan_context)
        files = {
            "/app/search.py": (
                'results = vectorstore.similarity_search(\n'
                '    query, score_threshold=0.7, k=5\n'
                ')\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_retrieval_filtering(files, combined)
        findings = [f for f in agent.findings if "filtering" in f.title.lower()]
        assert len(findings) == 0


class TestContextStuffing:
    """Test context stuffing risk detection."""

    def test_detects_context_stuffing(self, scan_context):
        agent = RAGSecurityAgent(scan_context)
        code = (
            'context = "\\n".join([doc.page_content for doc in docs])\n'
            'prompt = f"Context: {context}\\nQuestion: {query}"\n'
        )
        agent._check_context_stuffing(code)
        findings = [f for f in agent.findings if "stuffing" in f.title.lower()]
        assert len(findings) >= 1

    def test_context_with_max_tokens_passes(self, scan_context):
        agent = RAGSecurityAgent(scan_context)
        code = (
            'context = "\\n".join([doc.page_content for doc in docs])\n'
            'max_tokens = 2000\n'
            'truncated = context[:max_tokens]\n'
        )
        agent._check_context_stuffing(code)
        findings = [f for f in agent.findings if "stuffing" in f.title.lower()]
        assert len(findings) == 0


class TestDocumentInjection:
    """Test user-controlled loader path detection."""

    def test_detects_document_injection(self, scan_context):
        agent = RAGSecurityAgent(scan_context)
        files = {
            "/app/upload.py": (
                'user_dir = request.args.get("dir")\n'
                'loader = DirectoryLoader(f"{user_dir}/docs")\n'
            )
        }
        agent._check_document_injection(files)
        findings = [f for f in agent.findings if "injection" in f.title.lower()]
        assert len(findings) >= 1


class TestHardcodedEmbeddingKey:
    """Test hardcoded embedding API key detection."""

    def test_detects_hardcoded_key(self, scan_context):
        agent = RAGSecurityAgent(scan_context)
        files = {
            "/app/embeddings.py": (
                'from langchain.embeddings import OpenAIEmbeddings\n'
                'embeddings = OpenAIEmbeddings(\n'
                '    openai_api_key="sk-abcdef1234567890abcdefgh"\n'
                ')\n'
            )
        }
        agent._check_hardcoded_embedding_keys(files)
        findings = [f for f in agent.findings if "Hardcoded" in f.title]
        assert len(findings) >= 1

    def test_key_from_env_passes(self, scan_context):
        agent = RAGSecurityAgent(scan_context)
        files = {
            "/app/embeddings.py": (
                'import os\n'
                'from langchain.embeddings import OpenAIEmbeddings\n'
                'embeddings = OpenAIEmbeddings(\n'
                '    openai_api_key=os.environ["OPENAI_API_KEY"]\n'
                ')\n'
            )
        }
        agent._check_hardcoded_embedding_keys(files)
        findings = [f for f in agent.findings if "Hardcoded" in f.title]
        assert len(findings) == 0


class TestRetrievalPoisoning:
    """Test retrieval poisoning detection."""

    def test_detects_shared_collection_no_attribution(self, scan_context):
        agent = RAGSecurityAgent(scan_context)
        files = {
            "/app/rag.py": (
                'collection = client.get_or_create_collection(\n'
                '    collection_name="shared_knowledge"\n'
                ')\n'
                'results = collection.query(query_texts=["hello"])\n'
            )
        }
        combined = "\n".join(files.values())
        agent._check_retrieval_poisoning(files, combined)
        findings = [f for f in agent.findings if "poisoning" in f.title.lower()]
        assert len(findings) >= 1


class TestOutputGrounding:
    """Test RAG output grounding detection."""

    def test_detects_no_grounding(self, scan_context):
        agent = RAGSecurityAgent(scan_context)
        code = (
            'from langchain.chains import RetrievalQA\n'
            'chain = RetrievalQA.from_chain_type(llm=llm, retriever=retriever)\n'
            'result = chain.run(query)\n'
        )
        agent._check_output_grounding(code)
        findings = [f for f in agent.findings if "grounding" in f.title.lower()]
        assert len(findings) >= 1

    def test_no_rag_patterns_no_findings(self, scan_context):
        agent = RAGSecurityAgent(scan_context)
        code = (
            'import json\n'
            'data = json.loads(response)\n'
            'print(data)\n'
        )
        agent._check_output_grounding(code)
        assert len(agent.findings) == 0
