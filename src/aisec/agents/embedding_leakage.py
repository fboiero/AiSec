"""Embedding and vector DB security agent."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import ClassVar

from aisec.agents.base import BaseAgent
from aisec.core.enums import AgentPhase, Severity
from aisec.core.models import Evidence

logger = logging.getLogger(__name__)

# Vector DB client initialization patterns
VECTOR_DB_PATTERNS: list[tuple[str, re.Pattern[str], re.Pattern[str], str]] = [
    (
        "ChromaDB",
        re.compile(r'chromadb\.(?:Client|HttpClient|PersistentClient)\s*\('),
        re.compile(r'chromadb.*(?:auth|token|api_key|password|credentials)', re.IGNORECASE),
        "Configure ChromaDB authentication: Settings(chroma_client_auth_provider=...)",
    ),
    (
        "Pinecone",
        re.compile(r'pinecone\.(?:init|Pinecone|Index)\s*\('),
        re.compile(r'pinecone.*(?:api_key|environment)', re.IGNORECASE),
        "Always pass api_key to Pinecone: pinecone.Pinecone(api_key=secret)",
    ),
    (
        "Weaviate",
        re.compile(r'weaviate\.(?:Client|connect_to)\s*\('),
        re.compile(r'weaviate.*(?:auth|api_key|oidc)', re.IGNORECASE),
        "Configure Weaviate authentication: weaviate.AuthApiKey(api_key=secret)",
    ),
    (
        "Milvus",
        re.compile(r'(?:pymilvus\.)?connections\.connect\s*\('),
        re.compile(r'milvus.*(?:token|password|secure)', re.IGNORECASE),
        "Use authenticated Milvus: connections.connect(token=secret, secure=True)",
    ),
    (
        "Qdrant",
        re.compile(r'qdrant_client\.QdrantClient\s*\('),
        re.compile(r'qdrant.*(?:api_key|https)', re.IGNORECASE),
        "Configure Qdrant API key: QdrantClient(url=..., api_key=secret)",
    ),
    (
        "FAISS",
        re.compile(r'faiss\.(?:read_index|IndexFlatL2|IndexIVFFlat)\s*\('),
        re.compile(r'$^'),  # FAISS has no built-in auth; flag it
        "FAISS has no built-in auth. Wrap FAISS access behind an authenticated API.",
    ),
]

# Embedding API patterns
EMBEDDING_PATTERNS = re.compile(
    r'(?:openai.*embedding|sentence_transformers|'
    r'embed_query|embed_documents|get_embedding|encode\s*\(.*text)',
    re.IGNORECASE,
)

# Multi-tenant isolation patterns
NAMESPACE_PATTERNS = re.compile(
    r'(?:namespace|collection_name|tenant|partition|index_name)',
    re.IGNORECASE,
)

TENANT_ISOLATION_PATTERNS = re.compile(
    r'(?:tenant_id|org_id|user_id|workspace_id).*(?:namespace|collection|partition|filter)',
    re.IGNORECASE,
)

# Fine-tuning / training patterns
FINETUNING_PATTERNS = re.compile(
    r'(?:fine_tune|finetune|TrainingArguments|Trainer|'
    r'FineTuningJob|prepare_dataset|DPOTrainer|SFTTrainer)',
    re.IGNORECASE,
)

# Differential privacy patterns
DP_PATTERNS = re.compile(
    r'(?:differential_privacy|dp_sgd|opacus|tensorflow_privacy|'
    r'DPOptimizer|PrivateEngine|DP_SGDOptimizer|epsilon|privacy_budget)',
    re.IGNORECASE,
)

# Embedding cache patterns
EMBEDDING_CACHE_PATTERNS = re.compile(
    r'(?:cache.*embed|embed.*cache|CacheBackedEmbeddings|'
    r'embedding_cache|store.*embedding|redis.*embed)',
    re.IGNORECASE,
)


class EmbeddingLeakageAgent(BaseAgent):
    """Analyzes embedding and vector database security."""

    name: ClassVar[str] = "embedding_leakage"
    description: ClassVar[str] = (
        "Checks vector DB authentication, embedding access control, multi-tenant "
        "namespace isolation, training data memorization risks, embedding "
        "inversion risks, and cache integrity."
    )
    phase: ClassVar[AgentPhase] = AgentPhase.STATIC
    frameworks: ClassVar[list[str]] = ["LLM06", "LLM10", "ASI06", "ASI09"]
    depends_on: ClassVar[list[str]] = []

    async def analyze(self) -> None:
        """Analyze embedding and vector DB security."""
        source_files = await self._collect_source_files()
        if not source_files:
            self.add_finding(
                title="No source files for embedding analysis",
                description="No Python source files found in the container.",
                severity=Severity.INFO,
                owasp_llm=["LLM06"],
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

        self._check_vector_db_auth(all_content)
        self._check_namespace_isolation(all_content, combined)
        self._check_training_memorization(combined)
        self._check_embedding_cache(all_content, combined)
        self._check_embedding_api_exposure(all_content)

    def _check_vector_db_auth(self, files: dict[str, str]) -> None:
        """Check vector DB connections for authentication."""
        for fpath, content in files.items():
            for db_name, init_pattern, auth_pattern, remediation in VECTOR_DB_PATTERNS:
                init_matches = list(init_pattern.finditer(content))
                if not init_matches:
                    continue

                has_auth = bool(auth_pattern.search(content))

                if not has_auth:
                    lines = [str(content[:m.start()].count("\n") + 1) for m in init_matches]
                    self.add_finding(
                        title=f"Vector DB without authentication: {db_name}",
                        description=(
                            f"{db_name} client initialized at {fpath} (lines: "
                            f"{', '.join(lines)}) without authentication. "
                            "Unauthenticated vector databases can expose embeddings "
                            "and raw documents to unauthorized access."
                        ),
                        severity=Severity.HIGH,
                        owasp_llm=["LLM06", "LLM10"],
                        owasp_agentic=["ASI06"],
                        nist_ai_rmf=["MEASURE"],
                        evidence=[
                            Evidence(
                                type="file_content",
                                summary=f"{db_name} without auth at {fpath}",
                                raw_data=f"Lines: {', '.join(lines)}",
                                location=fpath,
                            )
                        ],
                        remediation=remediation,
                        cvss_score=7.0,
                        ai_risk_score=7.0,
                    )

    def _check_namespace_isolation(self, files: dict[str, str], combined: str) -> None:
        """Check for multi-tenant namespace/collection isolation."""
        has_vector_db = any(
            init_pat.search(combined)
            for _, init_pat, _, _ in VECTOR_DB_PATTERNS
        )
        has_embeddings = bool(EMBEDDING_PATTERNS.search(combined))

        if not has_vector_db and not has_embeddings:
            return

        has_namespace = bool(NAMESPACE_PATTERNS.search(combined))
        has_tenant_isolation = bool(TENANT_ISOLATION_PATTERNS.search(combined))

        # Check for multi-tenant indicators
        multi_tenant_indicators = re.compile(
            r'(?:tenant|multi_tenant|organization|workspace|team)',
            re.IGNORECASE,
        )
        is_multi_tenant = bool(multi_tenant_indicators.search(combined))

        if is_multi_tenant and not has_tenant_isolation:
            self.add_finding(
                title="Multi-tenant vector store without namespace isolation",
                description=(
                    "Multi-tenant patterns detected but vector store queries "
                    "don't appear to filter by tenant/namespace. This could allow "
                    "cross-tenant data leakage through similarity searches."
                ),
                severity=Severity.HIGH,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI06", "ASI09"],
                nist_ai_rmf=["GOVERN"],
                remediation=(
                    "Use separate namespaces/collections per tenant. Include "
                    "tenant_id in all vector store queries as a metadata filter."
                ),
                cvss_score=7.5,
                ai_risk_score=8.0,
            )

    def _check_training_memorization(self, combined: str) -> None:
        """Check fine-tuning code for privacy safeguards."""
        has_finetuning = bool(FINETUNING_PATTERNS.search(combined))
        has_dp = bool(DP_PATTERNS.search(combined))

        if has_finetuning and not has_dp:
            self.add_finding(
                title="Fine-tuning without differential privacy",
                description=(
                    "Model fine-tuning detected without differential privacy "
                    "mechanisms. Fine-tuned models can memorize training data, "
                    "potentially exposing sensitive information through inference."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM06", "LLM10"],
                owasp_agentic=["ASI06"],
                nist_ai_rmf=["GOVERN", "MEASURE"],
                remediation=(
                    "Implement differential privacy during fine-tuning using libraries "
                    "like Opacus (PyTorch) or TensorFlow Privacy. Deduplicate training "
                    "data and scrub PII before training."
                ),
                cvss_score=5.0,
                ai_risk_score=7.0,
            )

    def _check_embedding_cache(self, files: dict[str, str], combined: str) -> None:
        """Check embedding caches for integrity verification."""
        has_cache = bool(EMBEDDING_CACHE_PATTERNS.search(combined))

        if not has_cache:
            return

        # Check for hash/integrity verification
        integrity_patterns = re.compile(
            r'(?:hash.*embed|embed.*hash|verify.*cache|integrity|checksum|'
            r'hmac.*embed|embed.*hmac|cache.*validate)',
            re.IGNORECASE,
        )
        has_integrity = bool(integrity_patterns.search(combined))

        if not has_integrity:
            self.add_finding(
                title="Embedding cache without integrity verification",
                description=(
                    "Embedding cache detected without hash/integrity verification. "
                    "Cache poisoning could inject malicious embeddings that alter "
                    "similarity search results."
                ),
                severity=Severity.MEDIUM,
                owasp_llm=["LLM06"],
                owasp_agentic=["ASI06"],
                remediation=(
                    "Add HMAC or hash verification for cached embeddings. "
                    "Validate cache entries before use in similarity searches."
                ),
                cvss_score=5.0,
            )

    def _check_embedding_api_exposure(self, files: dict[str, str]) -> None:
        """Check for embeddings exposed via API without auth."""
        api_embed_pattern = re.compile(
            r'(?:@(?:app|router)\.(?:get|post)\s*\([^)]*(?:embed|vector|search|similar)[^)]*\))',
            re.IGNORECASE,
        )
        auth_pattern = re.compile(
            r'(?:Depends\s*\(.*auth|login_required|permission_required|'
            r'api_key|bearer|Authorization|authenticate)',
            re.IGNORECASE,
        )

        for fpath, content in files.items():
            api_matches = list(api_embed_pattern.finditer(content))
            if not api_matches:
                continue

            has_auth = bool(auth_pattern.search(content))

            if not has_auth:
                lines = [str(content[:m.start()].count("\n") + 1) for m in api_matches]
                self.add_finding(
                    title=f"Embedding API exposed without authentication",
                    description=(
                        f"Embedding/search API endpoint(s) at {fpath} (lines: "
                        f"{', '.join(lines)}) appear to lack authentication. "
                        "Unauthenticated embedding APIs can be used for model "
                        "inversion attacks to extract training data."
                    ),
                    severity=Severity.HIGH,
                    owasp_llm=["LLM06", "LLM10"],
                    owasp_agentic=["ASI09"],
                    evidence=[
                        Evidence(
                            type="file_content",
                            summary=f"Unauthenticated embedding API at {fpath}",
                            raw_data=f"Lines: {', '.join(lines)}",
                            location=fpath,
                        )
                    ],
                    remediation=(
                        "Add authentication to all embedding and search endpoints. "
                        "Implement rate limiting to prevent model inversion attacks."
                    ),
                    cvss_score=7.0,
                    ai_risk_score=8.0,
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
