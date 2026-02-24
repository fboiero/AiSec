"""RAG pipeline security agent."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# Document loader patterns (LangChain, LlamaIndex, generic)
LOADER_PATTERNS = re.compile(
    r'(?:DirectoryLoader|WebBaseLoader|UnstructuredFileLoader|'
    r'S3FileLoader|GCSFileLoader|CSVLoader|PyPDFLoader|TextLoader|'
    r'JSONLoader|SeleniumURLLoader|PlaywrightURLLoader|'
    r'RecursiveUrlLoader|UnstructuredURLLoader|BSHTMLLoader|'
    r'NotebookLoader|AzureBlobStorageFileLoader|SimpleDirectoryReader|'
    r'PDFReader|DocxReader|download_loader)\s*\(',
)

# Loader sanitization / validation patterns
LOADER_VALIDATION_PATTERNS = re.compile(
    r'(?:allowed_types|file_filter|glob=|required_exts|'
    r'exclude_hidden|input_files|file_extractor|'
    r'sanitize|validate.*path|allowlist)',
    re.IGNORECASE,
)

# Retrieval call patterns
RETRIEVAL_PATTERNS = re.compile(
    r'\.(?:similarity_search|similarity_search_with_score|'
    r'get_relevant_documents|as_retriever|max_marginal_relevance_search|'
    r'invoke|retrieve)\s*\(',
)

# Retrieval filtering indicators
RETRIEVAL_FILTER_PATTERNS = re.compile(
    r'(?:score_threshold|k\s*=\s*\d+|top_k|search_kwargs|'
    r'fetch_k|lambda_mult|filter=|where=|rerank|'
    r'CrossEncoderReranker|CohereRerank|FlashrankRerank)',
    re.IGNORECASE,
)

# Context assembly without limits
CONTEXT_ASSEMBLY_PATTERNS = re.compile(
    r'(?:"\s*\\n\s*"\s*\.join|"\s*"\s*\.join|format_docs|'
    r'combine_documents|stuff_documents|StuffDocumentsChain)',
)

MAX_CONTEXT_PATTERNS = re.compile(
    r'(?:max_tokens|max_context|token_limit|max_length|'
    r'truncate|chunk_size.*prompt|max_doc)',
    re.IGNORECASE,
)

# User-controlled paths in loaders
USER_INPUT_IN_LOADER = re.compile(
    r'(?:DirectoryLoader|WebBaseLoader|SimpleDirectoryReader|'
    r'TextLoader|S3FileLoader)\s*\(\s*(?:f["\']|.*\.format|.*\+\s*(?:user|input|request|query|param))',
    re.IGNORECASE,
)

# Hardcoded embedding API keys
EMBEDDING_KEY_PATTERNS = re.compile(
    r'''(?:openai_api_key|cohere_api_key|voyage_api_key|'''
    r'''huggingfacehub_api_token|api_key)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]''',
)

# Embedding key env vars (safe pattern)
EMBEDDING_KEY_ENV_PATTERNS = re.compile(
    r'(?:os\.environ|os\.getenv|settings\.|config\.)',
)

# Vector store shared collection patterns
SHARED_COLLECTION_PATTERNS = re.compile(
    r'(?:collection_name\s*=\s*["\'][^"\']+["\']|'
    r'index_name\s*=\s*["\'][^"\']+["\'])',
)

# Source attribution patterns
SOURCE_ATTRIBUTION_PATTERNS = re.compile(
    r'(?:metadata.*source|source.*metadata|page_content.*source|'
    r'document\.metadata|\.metadata\[.source.\])',
    re.IGNORECASE,
)

# Metadata filtering on retrieval
METADATA_FILTER_PATTERNS = re.compile(
    r'(?:filter\s*=|where\s*=|metadata_filter|search_filter|'
    r'user_id.*filter|tenant.*filter|source_filter)',
    re.IGNORECASE,
)

# Output grounding / citation patterns
GROUNDING_PATTERNS = re.compile(
    r'(?:source_documents|citation|cite|grounding|fact.?check|'
    r'verify.*source|reference.*doc|attributed|provenance)',
    re.IGNORECASE,
)

# RAG chain indicators
RAG_CHAIN_PATTERNS = re.compile(
    r'(?:RetrievalQA|ConversationalRetrievalChain|'
    r'create_retrieval_chain|RAGChain|rag_chain|'
    r'retriever.*llm|vectorstore.*chain)',
    re.IGNORECASE,
)


class RAGSecurityAgent(BaseAgent):
    """Secures Retrieval-Augmented Generation pipelines."""

    name: ClassVar[str] = "rag_security"
    description: ClassVar[str] = (
        "Secures RAG pipelines: document injection, retrieval poisoning, "
        "context stuffing, unvalidated loaders, missing chunk validation, "
        "hardcoded embedding keys, and output grounding."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM01", "LLM08", "ASI06"]
    depends_on: ClassVar[list[str]] = []

    async def analyze(self) -> None:
        """Analyze RAG pipeline security."""
        source_files = await self._collect_source_files()
        if not source_files:
            self.add_finding(
                title="No source files for RAG analysis",
                description="No Python source files found in the container.",
                severity=Severity.INFO,
                owasp_llm=["LLM08"],
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

        # Only run checks if RAG patterns are detected
        has_rag = bool(
            RAG_CHAIN_PATTERNS.search(combined)
            or (LOADER_PATTERNS.search(combined) and RETRIEVAL_PATTERNS.search(combined))
        )
        if not has_rag:
            return

        self._check_unvalidated_loaders(all_content)
        self._check_retrieval_filtering(all_content, combined)
        self._check_context_stuffing(combined)
        self._check_document_injection(all_content)
        self._check_chunk_validation(combined)
        self._check_hardcoded_embedding_keys(all_content)
        self._check_retrieval_poisoning(all_content, combined)
        self._check_output_grounding(combined)

    def _check_unvalidated_loaders(self, files: dict[str, str]) -> None:
        """Check for document loaders without validation."""
        for fpath, content in files.items():
            loader_matches = list(LOADER_PATTERNS.finditer(content))
            if not loader_matches:
                continue

            has_validation = bool(LOADER_VALIDATION_PATTERNS.search(content))
            if not has_validation:
                lines = [str(content[:m.start()].count("\n") + 1) for m in loader_matches]
                self.add_finding(
                    title="Unvalidated document loader in RAG pipeline",
                    description=(
                        f"Document loader(s) at {fpath} (lines: {', '.join(lines)}) "
                        "lack file type validation or sanitization. Malicious documents "
                        "could inject prompts, execute code, or exfiltrate data."
                    ),
                    severity=Severity.HIGH,
                    owasp_llm=["LLM01", "LLM08"],
                    owasp_agentic=["ASI06"],
                    nist_ai_rmf=["MEASURE"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Unvalidated loader at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Add file type validation: DirectoryLoader(path, glob='*.pdf', "
                        "loader_cls=PyPDFLoader). Use allowed_types or file_filter parameters."
                    ),
                    cvss_score=7.0,
                    ai_risk_score=7.5,
                )

    def _check_retrieval_filtering(self, files: dict[str, str], combined: str) -> None:
        """Check for retrieval calls without score filtering."""
        for fpath, content in files.items():
            retrieval_matches = list(RETRIEVAL_PATTERNS.finditer(content))
            if not retrieval_matches:
                continue

            has_filter = bool(RETRIEVAL_FILTER_PATTERNS.search(content))
            if not has_filter:
                lines = [str(content[:m.start()].count("\n") + 1) for m in retrieval_matches]
                self.add_finding(
                    title="No retrieval result filtering in RAG pipeline",
                    description=(
                        f"Retrieval call(s) at {fpath} (lines: {', '.join(lines)}) "
                        "lack score thresholds, top-k limits, or re-ranking. "
                        "Low-relevance or poisoned documents may reach the LLM."
                    ),
                    severity=Severity.HIGH,
                    owasp_llm=["LLM08"],
                    owasp_agentic=["ASI06"],
                    nist_ai_rmf=["MEASURE"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Unfiltered retrieval at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Add score_threshold and k limits: "
                        "vectorstore.similarity_search(query, k=5, score_threshold=0.7). "
                        "Consider adding a re-ranker (CrossEncoder, Cohere Rerank)."
                    ),
                    cvss_score=6.5,
                    ai_risk_score=7.0,
                )

    def _check_context_stuffing(self, combined: str) -> None:
        """Check for context assembly without token limits."""
        has_assembly = bool(CONTEXT_ASSEMBLY_PATTERNS.search(combined))
        has_limits = bool(MAX_CONTEXT_PATTERNS.search(combined))

        if has_assembly and not has_limits:
            self.add_finding(
                title="Context window stuffing risk in RAG pipeline",
                description=(
                    "Retrieved documents are assembled into prompts without token "
                    "limits or truncation. Attackers can craft documents that fill "
                    "the context window, displacing system instructions."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM10"],
                owasp_agentic=["ASI06"],
                remediation=(
                    "Set max_tokens or max_context_length on document assembly. "
                    "Use token counting to truncate retrieved content before prompt insertion."
                ),
                cvss_score=5.0,
                ai_risk_score=6.0,
            )

    def _check_document_injection(self, files: dict[str, str]) -> None:
        """Check for user-controlled paths in document loaders."""
        for fpath, content in files.items():
            matches = list(USER_INPUT_IN_LOADER.finditer(content))
            if matches:
                lines = [str(content[:m.start()].count("\n") + 1) for m in matches]
                self.add_finding(
                    title="Document injection: user-controlled loader path",
                    description=(
                        f"Document loader at {fpath} (lines: {', '.join(lines)}) "
                        "uses user-controlled input in the file path or URL. "
                        "An attacker can load arbitrary documents to poison RAG context."
                    ),
                    severity=Severity.CRITICAL,
                    owasp_llm=["LLM01"],
                    owasp_agentic=["ASI06"],
                    nist_ai_rmf=["GOVERN", "MEASURE"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"User input in loader path at {fpath}",
                        raw_data=f"Lines: {', '.join(lines)}",
                        location=fpath,
                    )],
                    remediation=(
                        "Never use user input directly in document loader paths. "
                        "Use an allowlist of permitted directories and validate paths "
                        "against path traversal (resolve and check prefix)."
                    ),
                    cvss_score=9.0,
                    ai_risk_score=9.0,
                )

    def _check_chunk_validation(self, combined: str) -> None:
        """Check for missing content validation between retrieval and prompt."""
        has_retrieval = bool(RETRIEVAL_PATTERNS.search(combined))
        has_assembly = bool(CONTEXT_ASSEMBLY_PATTERNS.search(combined))

        if not (has_retrieval and has_assembly):
            return

        # Look for content sanitization between retrieval and prompt
        sanitization_patterns = re.compile(
            r'(?:sanitize.*chunk|filter.*content|clean.*text|'
            r'remove.*injection|strip.*html|escape.*content|'
            r'validate_chunk|content_filter)',
            re.IGNORECASE,
        )
        has_sanitization = bool(sanitization_patterns.search(combined))

        if not has_sanitization:
            self.add_finding(
                title="Missing chunk validation in RAG pipeline",
                description=(
                    "Retrieved chunks are passed to the LLM without content "
                    "validation or sanitization. Poisoned documents could contain "
                    "prompt injection payloads that execute when included in context."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM01"],
                owasp_agentic=["ASI06"],
                remediation=(
                    "Add content validation between retrieval and prompt assembly. "
                    "Filter chunks for injection patterns, HTML/script content, "
                    "and anomalous text before inserting into the prompt."
                ),
                cvss_score=5.5,
                ai_risk_score=6.5,
            )

    def _check_hardcoded_embedding_keys(self, files: dict[str, str]) -> None:
        """Check for hardcoded embedding API keys."""
        for fpath, content in files.items():
            key_matches = list(EMBEDDING_KEY_PATTERNS.finditer(content))
            if not key_matches:
                continue

            # Check if keys come from env vars (safe)
            for match in key_matches:
                context_start = max(0, match.start() - 100)
                context = content[context_start:match.end()]
                if EMBEDDING_KEY_ENV_PATTERNS.search(context):
                    continue

                line = content[:match.start()].count("\n") + 1
                self.add_finding(
                    title="Hardcoded embedding API key in RAG configuration",
                    description=(
                        f"Embedding API key hardcoded at {fpath} (line {line}). "
                        "Hardcoded keys in source code can be extracted from containers "
                        "and used to access paid embedding services."
                    ),
                    severity=Severity.CRITICAL,
                    owasp_llm=["LLM08"],
                    nist_ai_rmf=["GOVERN"],
                    evidence=[Evidence(
                        type="file_content",
                        summary=f"Hardcoded embedding key at {fpath}",
                        raw_data=f"Line: {line}",
                        location=fpath,
                    )],
                    remediation=(
                        "Use environment variables: os.environ['OPENAI_API_KEY']. "
                        "Never commit API keys to source code."
                    ),
                    cvss_score=8.0,
                    ai_risk_score=7.0,
                )

    def _check_retrieval_poisoning(self, files: dict[str, str], combined: str) -> None:
        """Check for shared collections without source attribution or filtering."""
        has_collection = bool(SHARED_COLLECTION_PATTERNS.search(combined))
        has_source_attr = bool(SOURCE_ATTRIBUTION_PATTERNS.search(combined))
        has_metadata_filter = bool(METADATA_FILTER_PATTERNS.search(combined))

        if has_collection and not has_source_attr and not has_metadata_filter:
            self.add_finding(
                title="Retrieval poisoning: shared collection without source filtering",
                description=(
                    "Vector store collections are shared without document source "
                    "attribution or metadata filtering. Any document ingested into "
                    "the shared collection will be returned in searches, enabling "
                    "poisoning by injecting malicious documents."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM08"],
                owasp_agentic=["ASI06"],
                nist_ai_rmf=["GOVERN", "MEASURE"],
                remediation=(
                    "Add metadata filtering: include source, user_id, or trust_level "
                    "in document metadata. Filter retrieval results by metadata to "
                    "ensure only trusted documents are returned."
                ),
                cvss_score=7.0,
                ai_risk_score=7.5,
            )

    def _check_output_grounding(self, combined: str) -> None:
        """Check for RAG output grounding / citation."""
        has_rag_chain = bool(RAG_CHAIN_PATTERNS.search(combined))
        has_grounding = bool(GROUNDING_PATTERNS.search(combined))

        if has_rag_chain and not has_grounding:
            self.add_finding(
                title="No output grounding in RAG pipeline",
                description=(
                    "RAG pipeline does not include source citation or grounding "
                    "verification. Without grounding, the LLM may hallucinate "
                    "information not present in retrieved documents."
                ),
                severity=Severity.LOW,
                owasp_llm=["LLM09"],
                remediation=(
                    "Include source_documents in RAG output. Add citation generation "
                    "to link responses back to specific retrieved documents."
                ),
                cvss_score=3.0,
                ai_risk_score=4.0,
            )

    async def _collect_source_files(self) -> list[str]:
        """Collect Python source files from the container."""
        cid = self.context.container_id
        if not cid:
            return []

        cmd = (
            "find /app /src /opt -maxdepth 6 -type f "
            "\\( -name '*.py' -o -name '*.yaml' -o -name '*.yml' -o -name '*.json' \\) "
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
