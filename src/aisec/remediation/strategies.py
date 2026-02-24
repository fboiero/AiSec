"""Per-category remediation strategies with concrete fix suggestions."""

from __future__ import annotations

import re
from typing import Any

from aisec.remediation.models import CodePatch, FixSuggestion


# ---------------------------------------------------------------------------
# Strategy registry: maps finding title keywords to fix generators
# ---------------------------------------------------------------------------

def _match(title: str, *keywords: str) -> bool:
    """Check if any keyword appears in the finding title (case-insensitive)."""
    lower = title.lower()
    return any(k in lower for k in keywords)


def generate_fix(title: str, description: str, agent: str, severity: str) -> FixSuggestion | None:
    """Generate a fix suggestion for a finding based on its title/agent."""
    for matcher, generator in _STRATEGIES:
        if matcher(title, agent):
            return generator(title, description, severity)
    return _generic_fix(title, description, severity)


# ---------------------------------------------------------------------------
# Hardcoded secrets / API keys
# ---------------------------------------------------------------------------

def _fix_hardcoded_secret(title: str, description: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Replace hardcoded secret with environment variable",
        description="Move the secret to an environment variable or secrets manager.",
        effort="low",
        priority=1,
        code_patches=[
            CodePatch(
                language="python",
                before='api_key = "sk-aBcDeFgHiJkLmNoPqRsT"',
                after='api_key = os.environ["OPENAI_API_KEY"]',
                explanation="Read the API key from an environment variable instead of hardcoding it.",
            ),
        ],
        commands=[
            "export OPENAI_API_KEY='your-key-here'  # or use a .env file",
            "pip install python-dotenv  # for .env file support",
        ],
        references=[
            "https://12factor.net/config",
            "https://docs.github.com/en/actions/security-guides/encrypted-secrets",
        ],
        framework_guidance={
            "docker": "Use Docker secrets or --env-file instead of ENV in Dockerfile.",
            "kubernetes": "Use Kubernetes Secrets or external-secrets-operator.",
        },
    )


# ---------------------------------------------------------------------------
# Input validation / prompt injection
# ---------------------------------------------------------------------------

def _fix_input_validation(title: str, description: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Add input validation and sanitization",
        description="Implement input validation before passing data to the LLM.",
        effort="medium",
        priority=1,
        code_patches=[
            CodePatch(
                language="python",
                before='response = llm.invoke(user_input)',
                after=(
                    'from aisec_utils import validate_input\n'
                    'sanitized = validate_input(user_input, max_length=2000, block_injection=True)\n'
                    'response = llm.invoke(sanitized)'
                ),
                explanation="Validate and sanitize user input before passing to the LLM.",
            ),
        ],
        commands=["pip install guardrails-ai  # for structured validation"],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        ],
        framework_guidance={
            "langchain": "Use LangChain's InputValidator or custom RunnablePassthrough with validation.",
            "nemo": "Add input rails in NeMo Guardrails config.yml.",
        },
    )


# ---------------------------------------------------------------------------
# Missing guardrails
# ---------------------------------------------------------------------------

def _fix_missing_guardrails(title: str, description: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Add AI safety guardrails",
        description="Integrate a guardrail framework for input/output filtering.",
        effort="medium",
        priority=2,
        code_patches=[
            CodePatch(
                language="yaml",
                before="# No guardrails configuration",
                after=(
                    "# config.yml (NeMo Guardrails)\n"
                    "models:\n"
                    "  - type: main\n"
                    "    engine: openai\n"
                    "    model: gpt-4\n"
                    "rails:\n"
                    "  input:\n"
                    "    flows:\n"
                    "      - self check input\n"
                    "  output:\n"
                    "    flows:\n"
                    "      - self check output"
                ),
                explanation="Add NeMo Guardrails configuration for input/output safety.",
            ),
        ],
        commands=[
            "pip install nemoguardrails",
            "nemoguardrails init  # create config directory",
        ],
        references=[
            "https://github.com/NVIDIA/NeMo-Guardrails",
            "https://docs.guardrailsai.com/",
        ],
    )


# ---------------------------------------------------------------------------
# Unsafe deserialization
# ---------------------------------------------------------------------------

def _fix_unsafe_deserialization(title: str, description: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Replace unsafe deserialization with safe alternative",
        description="Use safe loading functions to prevent code execution via deserialization.",
        effort="low",
        priority=1,
        code_patches=[
            CodePatch(
                language="python",
                before="data = yaml.load(content)",
                after="data = yaml.safe_load(content)",
                explanation="Use safe_load to prevent arbitrary code execution.",
            ),
            CodePatch(
                language="python",
                before="obj = pickle.loads(data)",
                after=(
                    "import json\n"
                    "obj = json.loads(data)  # or use safetensors for model files"
                ),
                explanation="Replace pickle with a safe serialization format.",
            ),
        ],
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests",
        ],
    )


# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------

def _fix_sql_injection(title: str, description: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Use parameterized queries",
        description="Replace string formatting in SQL with parameterized queries.",
        effort="low",
        priority=1,
        code_patches=[
            CodePatch(
                language="python",
                before='cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")',
                after='cursor.execute("SELECT * FROM users WHERE name = %s", (name,))',
                explanation="Use parameterized queries to prevent SQL injection.",
            ),
        ],
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html"],
    )


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def _fix_rate_limiting(title: str, description: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Add rate limiting to endpoints",
        description="Implement rate limiting to prevent abuse and resource exhaustion.",
        effort="low",
        priority=2,
        code_patches=[
            CodePatch(
                language="python",
                before="@app.post('/api/chat')\nasync def chat(request):",
                after=(
                    "from slowapi import Limiter\n"
                    "limiter = Limiter(key_func=get_remote_address)\n\n"
                    "@app.post('/api/chat')\n"
                    "@limiter.limit('10/minute')\n"
                    "async def chat(request):"
                ),
                explanation="Add rate limiting to prevent abuse of AI endpoints.",
            ),
        ],
        commands=["pip install slowapi  # for FastAPI/Starlette"],
        references=["https://slowapi.readthedocs.io/"],
    )


# ---------------------------------------------------------------------------
# PII exposure
# ---------------------------------------------------------------------------

def _fix_pii_exposure(title: str, description: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Add PII detection and scrubbing",
        description="Implement PII scanning and anonymization before data processing.",
        effort="medium",
        priority=1,
        code_patches=[
            CodePatch(
                language="python",
                before="# No PII scrubbing\ndata = process(raw_input)",
                after=(
                    "from presidio_analyzer import AnalyzerEngine\n"
                    "from presidio_anonymizer import AnonymizerEngine\n\n"
                    "analyzer = AnalyzerEngine()\n"
                    "anonymizer = AnonymizerEngine()\n\n"
                    "results = analyzer.analyze(text=raw_input, language='en')\n"
                    "sanitized = anonymizer.anonymize(text=raw_input, analyzer_results=results)\n"
                    "data = process(sanitized.text)"
                ),
                explanation="Use Presidio to detect and anonymize PII before processing.",
            ),
        ],
        commands=["pip install presidio-analyzer presidio-anonymizer"],
        references=["https://microsoft.github.io/presidio/"],
    )


# ---------------------------------------------------------------------------
# Privileged container
# ---------------------------------------------------------------------------

def _fix_privileged_container(title: str, description: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Run container as non-root with minimal capabilities",
        description="Remove privileged mode and unnecessary capabilities.",
        effort="low",
        priority=1,
        code_patches=[
            CodePatch(
                language="dockerfile",
                before="FROM python:3.11\nRUN pip install app\nCMD [\"python\", \"app.py\"]",
                after=(
                    "FROM python:3.11-slim\n"
                    "RUN adduser --disabled-password --gecos '' appuser\n"
                    "RUN pip install app\n"
                    "USER appuser\n"
                    "CMD [\"python\", \"app.py\"]"
                ),
                explanation="Create a non-root user and switch to it.",
            ),
        ],
        references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"],
    )


# ---------------------------------------------------------------------------
# TLS / encryption
# ---------------------------------------------------------------------------

def _fix_missing_tls(title: str, description: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Enable TLS for transport encryption",
        description="Configure TLS to encrypt data in transit.",
        effort="medium",
        priority=1,
        code_patches=[
            CodePatch(
                language="python",
                before='app.run(host="0.0.0.0", port=8080)',
                after='app.run(host="0.0.0.0", port=8443, ssl_context=("cert.pem", "key.pem"))',
                explanation="Enable TLS on the server.",
            ),
        ],
        commands=["openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes"],
        references=["https://letsencrypt.org/getting-started/"],
    )


# ---------------------------------------------------------------------------
# MCP auth
# ---------------------------------------------------------------------------

def _fix_mcp_auth(title: str, description: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Add authentication to MCP server",
        description="Protect the MCP server with API key or token authentication.",
        effort="medium",
        priority=1,
        code_patches=[
            CodePatch(
                language="python",
                before='server = Server("my-server")\nserver.run(transport="http")',
                after=(
                    'import os\n'
                    'server = Server("my-server")\n\n'
                    '@server.auth\n'
                    'async def authenticate(request):\n'
                    '    token = request.headers.get("Authorization")\n'
                    '    if token != f"Bearer {os.environ[\'MCP_API_KEY\']}":\n'
                    '        raise PermissionError("Invalid token")\n\n'
                    'server.run(transport="http")'
                ),
                explanation="Add authentication middleware to the MCP server.",
            ),
        ],
        references=["https://modelcontextprotocol.io/docs/concepts/authentication"],
    )


# ---------------------------------------------------------------------------
# RAG security
# ---------------------------------------------------------------------------

def _fix_rag_no_filtering(title: str, description: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Add retrieval result filtering and validation",
        description="Limit and validate retrieval results before passing to the LLM.",
        effort="low",
        priority=1,
        code_patches=[
            CodePatch(
                language="python",
                before='results = vectorstore.similarity_search(query)',
                after='results = vectorstore.similarity_search(query, k=5, score_threshold=0.7)',
                explanation="Limit results with top-k and score threshold.",
            ),
        ],
        references=["https://python.langchain.com/docs/modules/data_connection/retrievers/"],
    )


# ---------------------------------------------------------------------------
# Memory security
# ---------------------------------------------------------------------------

def _fix_memory_security(title: str, description: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Secure agent memory with scoping and bounds",
        description="Add user scoping, encryption, and size limits to memory stores.",
        effort="medium",
        priority=2,
        code_patches=[
            CodePatch(
                language="python",
                before='memory = ConversationBufferMemory()',
                after=(
                    'memory = ConversationBufferWindowMemory(\n'
                    '    k=20,  # keep last 20 exchanges\n'
                    '    memory_key="chat_history",\n'
                    '    return_messages=True,\n'
                    ')'
                ),
                explanation="Use windowed memory to prevent unbounded growth.",
            ),
        ],
        references=["https://python.langchain.com/docs/modules/memory/types/buffer_window"],
    )


# ---------------------------------------------------------------------------
# CI/CD security
# ---------------------------------------------------------------------------

def _fix_cicd_secrets(title: str, description: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Use CI/CD secrets management instead of hardcoded values",
        description="Move secrets to the CI/CD platform's secret store.",
        effort="low",
        priority=1,
        code_patches=[
            CodePatch(
                language="yaml",
                before='env:\n  OPENAI_API_KEY: sk-abc123...',
                after='env:\n  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}',
                explanation="Reference secrets from the CI/CD platform's secret store.",
            ),
        ],
        references=[
            "https://docs.github.com/en/actions/security-guides/encrypted-secrets",
            "https://docs.gitlab.com/ee/ci/variables/#protected-cicd-variables",
        ],
    )


def _fix_unsafe_download(title: str, description: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Verify checksums for model downloads",
        description="Add checksum verification after downloading model artifacts.",
        effort="low",
        priority=1,
        code_patches=[
            CodePatch(
                language="yaml",
                before='- run: wget https://example.com/model.bin',
                after=(
                    '- run: |\n'
                    '    wget https://example.com/model.bin\n'
                    '    echo "expected_sha256  model.bin" | sha256sum -c -'
                ),
                explanation="Verify the downloaded file against a known checksum.",
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Tool chain security
# ---------------------------------------------------------------------------

def _fix_tool_no_sandbox(title: str, description: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Sandbox code execution tools",
        description="Run code execution tools in an isolated sandbox.",
        effort="high",
        priority=1,
        code_patches=[
            CodePatch(
                language="python",
                before='@tool\ndef run_code(code: str) -> str:\n    exec(code)',
                after=(
                    '@tool\n'
                    'def run_code(code: str) -> str:\n'
                    '    """Execute code in a sandboxed container."""\n'
                    '    import docker\n'
                    '    client = docker.from_env()\n'
                    '    result = client.containers.run(\n'
                    '        "python:3.11-slim",\n'
                    '        command=["python", "-c", code],\n'
                    '        mem_limit="256m",\n'
                    '        network_disabled=True,\n'
                    '        remove=True,\n'
                    '    )\n'
                    '    return result.decode()'
                ),
                explanation="Run untrusted code in a Docker container with resource limits.",
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Fine-tuning security
# ---------------------------------------------------------------------------

def _fix_training_data(title: str, description: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Add training data validation pipeline",
        description="Validate, deduplicate, and scrub training data before fine-tuning.",
        effort="medium",
        priority=1,
        code_patches=[
            CodePatch(
                language="python",
                before='dataset = load_dataset("org/data")\ntrainer.train()',
                after=(
                    'dataset = load_dataset("org/data", revision="v2.1")  # pin version\n'
                    'dataset = dataset.filter(quality_gate)\n'
                    'dataset = dataset.map(scrub_pii)\n'
                    'dataset = deduplicate(dataset)\n'
                    'trainer.train()'
                ),
                explanation="Add validation, PII scrubbing, and deduplication before training.",
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Generic fallback
# ---------------------------------------------------------------------------

def _generic_fix(title: str, description: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title=f"Remediate: {title}",
        description=f"Review and address this finding. {description[:200]}",
        effort="medium",
        priority=3 if severity in ("low", "info") else 2,
    )


# ---------------------------------------------------------------------------
# Strategy dispatch table
# ---------------------------------------------------------------------------

def _match_fn(*keywords: str):
    """Create a matcher function for a set of keywords."""
    def matcher(title: str, agent: str) -> bool:
        lower = title.lower()
        return any(k in lower for k in keywords)
    return matcher


def _match_agent(*agents: str):
    """Create a matcher that checks agent name."""
    def matcher(title: str, agent: str) -> bool:
        return agent in agents
    return matcher


_STRATEGIES: list[tuple[Any, Any]] = [
    # Secrets (highest priority — match first)
    (_match_fn("hardcoded", "secret", "credential", "api key", "api_key", "token exposed"),
     _fix_hardcoded_secret),
    # Deserialization
    (_match_fn("deserialization", "pickle", "yaml.load", "unsafe load", "serialization"),
     _fix_unsafe_deserialization),
    # SQL injection
    (_match_fn("sql injection", "query construction", "sql concat"),
     _fix_sql_injection),
    # Input validation / prompt injection
    (_match_fn("input validation", "prompt injection", "injection"),
     _fix_input_validation),
    # Guardrails
    (_match_fn("guardrail", "no guardrail", "missing guardrail"),
     _fix_missing_guardrails),
    # Rate limiting
    (_match_fn("rate limit", "rate-limit", "no rate"),
     _fix_rate_limiting),
    # PII
    (_match_fn("pii", "personal data", "sensitive data", "data exposure"),
     _fix_pii_exposure),
    # Privileged / container
    (_match_fn("privileged", "root container", "root user", "capabilities"),
     _fix_privileged_container),
    # TLS / encryption
    (_match_fn("tls", "ssl", "unencrypted", "http transport", "insecure transport"),
     _fix_missing_tls),
    # MCP
    (_match_fn("mcp", "unauthenticated mcp", "mcp server"),
     _fix_mcp_auth),
    # RAG
    (_match_fn("retrieval", "rag", "document loader", "context stuffing"),
     _fix_rag_no_filtering),
    # Memory
    (_match_fn("memory", "conversation buffer", "unbounded memory", "memory poisoning"),
     _fix_memory_security),
    # CI/CD secrets
    (_match_fn("ci config", "ci/cd", "pipeline secret", "secrets in ci"),
     _fix_cicd_secrets),
    # Download verification
    (_match_fn("insecure download", "model download", "unverified download", "checksum"),
     _fix_unsafe_download),
    # Tool sandbox
    (_match_fn("sandbox", "code execution tool", "exec without", "tool.*sandbox"),
     _fix_tool_no_sandbox),
    # Training data
    (_match_fn("training data", "fine-tuning", "fine_tuning", "unvalidated data"),
     _fix_training_data),
]
