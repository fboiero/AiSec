"""Tests for CascadeAgent."""

import re

import pytest

from aisec.agents.cascade import (
    HEALTH_CHECK_PATTERNS,
    CIRCUIT_BREAKER_PATTERNS,
    RETRY_TIMEOUT_PATTERNS,
    FALLBACK_PATTERNS,
    AUTH_TOKEN_PATTERNS,
    MTLS_PATTERNS,
    MESSAGE_SIGNING_PATTERNS,
    INTER_SERVICE_CALL_PATTERNS,
    INPUT_VALIDATION_PATTERNS,
    OUTPUT_SANITIZATION_PATTERNS,
    CORRELATION_PATTERNS,
    HMAC_SIGNATURE_PATTERNS,
    PLAINTEXT_COMM_PATTERNS,
    CascadeAgent,
)
from aisec.core.context import ScanContext
from aisec.core.enums import AgentPhase


# -- Agent metadata ----------------------------------------------------------

def test_cascade_agent_name():
    assert CascadeAgent.name == "cascade"


def test_cascade_agent_phase():
    assert CascadeAgent.phase == AgentPhase.STATIC


def test_cascade_agent_frameworks():
    assert "ASI08" in CascadeAgent.frameworks
    assert "ASI07" in CascadeAgent.frameworks


def test_cascade_agent_depends_on():
    assert "permission" in CascadeAgent.depends_on
    assert "network" in CascadeAgent.depends_on


def test_cascade_agent_description_not_empty():
    assert len(CascadeAgent.description) > 0


# -- Pattern constants exist and are non-empty -------------------------------

def test_health_check_patterns_not_empty():
    assert len(HEALTH_CHECK_PATTERNS) > 0


def test_circuit_breaker_patterns_not_empty():
    assert len(CIRCUIT_BREAKER_PATTERNS) > 0


def test_retry_timeout_patterns_not_empty():
    assert len(RETRY_TIMEOUT_PATTERNS) > 0


def test_fallback_patterns_not_empty():
    assert len(FALLBACK_PATTERNS) > 0


def test_auth_token_patterns_not_empty():
    assert len(AUTH_TOKEN_PATTERNS) > 0


def test_mtls_patterns_not_empty():
    assert len(MTLS_PATTERNS) > 0


def test_message_signing_patterns_not_empty():
    assert len(MESSAGE_SIGNING_PATTERNS) > 0


def test_inter_service_call_patterns_not_empty():
    assert len(INTER_SERVICE_CALL_PATTERNS) > 0


def test_input_validation_patterns_not_empty():
    assert len(INPUT_VALIDATION_PATTERNS) > 0


def test_output_sanitization_patterns_not_empty():
    assert len(OUTPUT_SANITIZATION_PATTERNS) > 0


def test_correlation_patterns_not_empty():
    assert len(CORRELATION_PATTERNS) > 0


def test_hmac_signature_patterns_not_empty():
    assert len(HMAC_SIGNATURE_PATTERNS) > 0


def test_plaintext_comm_patterns_not_empty():
    assert len(PLAINTEXT_COMM_PATTERNS) > 0


# -- All pattern lists contain compiled regexes ------------------------------

def test_all_patterns_are_compiled_regexes():
    all_pattern_lists = [
        HEALTH_CHECK_PATTERNS,
        CIRCUIT_BREAKER_PATTERNS,
        RETRY_TIMEOUT_PATTERNS,
        FALLBACK_PATTERNS,
        AUTH_TOKEN_PATTERNS,
        MTLS_PATTERNS,
        MESSAGE_SIGNING_PATTERNS,
        INTER_SERVICE_CALL_PATTERNS,
        INPUT_VALIDATION_PATTERNS,
        OUTPUT_SANITIZATION_PATTERNS,
        CORRELATION_PATTERNS,
        HMAC_SIGNATURE_PATTERNS,
        PLAINTEXT_COMM_PATTERNS,
    ]
    for pattern_list in all_pattern_lists:
        for pat in pattern_list:
            assert isinstance(pat, re.Pattern), (
                f"Expected compiled regex, got {type(pat)}"
            )


# -- HEALTH_CHECK_PATTERNS matching ------------------------------------------

def test_health_check_detects_healthcheck():
    assert any(p.search("HEALTHCHECK CMD curl") for p in HEALTH_CHECK_PATTERNS)


def test_health_check_detects_health_check_underscore():
    assert any(p.search("health_check: true") for p in HEALTH_CHECK_PATTERNS)


def test_health_check_detects_health_hyphen_check():
    assert any(p.search("health-check endpoint") for p in HEALTH_CHECK_PATTERNS)


def test_health_check_detects_health_endpoint():
    assert any(p.search("GET /health") for p in HEALTH_CHECK_PATTERNS)


def test_health_check_detects_ready_endpoint():
    assert any(p.search("GET /ready") for p in HEALTH_CHECK_PATTERNS)


def test_health_check_detects_liveness_endpoint():
    assert any(p.search("GET /liveness") for p in HEALTH_CHECK_PATTERNS)


def test_health_check_detects_liveness_probe():
    assert any(p.search("livenessProbe:") for p in HEALTH_CHECK_PATTERNS)


def test_health_check_detects_readiness_probe():
    assert any(p.search("readinessProbe:") for p in HEALTH_CHECK_PATTERNS)


def test_health_check_no_false_positive():
    assert not any(p.search("print('hello world')") for p in HEALTH_CHECK_PATTERNS)


# -- CIRCUIT_BREAKER_PATTERNS matching ---------------------------------------

def test_circuit_breaker_detects_circuit_breaker():
    assert any(p.search("circuit_breaker = CircuitBreaker()") for p in CIRCUIT_BREAKER_PATTERNS)


def test_circuit_breaker_detects_circuit_space_breaker():
    assert any(p.search("circuit breaker pattern") for p in CIRCUIT_BREAKER_PATTERNS)


def test_circuit_breaker_detects_pybreaker():
    assert any(p.search("import pybreaker") for p in CIRCUIT_BREAKER_PATTERNS)


def test_circuit_breaker_detects_resilience4j():
    assert any(p.search("resilience4j.circuitbreaker") for p in CIRCUIT_BREAKER_PATTERNS)


def test_circuit_breaker_detects_hystrix():
    assert any(p.search("@HystrixCommand") for p in CIRCUIT_BREAKER_PATTERNS)


def test_circuit_breaker_detects_polly():
    assert any(p.search("Policy.Handle<Exception>().Polly()") for p in CIRCUIT_BREAKER_PATTERNS)


def test_circuit_breaker_detects_tenacity():
    assert any(p.search("from tenacity import retry") for p in CIRCUIT_BREAKER_PATTERNS)


def test_circuit_breaker_detects_backoff():
    assert any(p.search("backoff.on_exception(backoff.expo)") for p in CIRCUIT_BREAKER_PATTERNS)


def test_circuit_breaker_no_false_positive():
    assert not any(p.search("x = y + z") for p in CIRCUIT_BREAKER_PATTERNS)


# -- RETRY_TIMEOUT_PATTERNS matching -----------------------------------------

def test_retry_timeout_detects_retry():
    assert any(p.search("@retry(max_attempts=3)") for p in RETRY_TIMEOUT_PATTERNS)


def test_retry_timeout_detects_timeout():
    assert any(p.search("timeout=30") for p in RETRY_TIMEOUT_PATTERNS)


def test_retry_timeout_detects_max_retries():
    assert any(p.search("max_retries=5") for p in RETRY_TIMEOUT_PATTERNS)


def test_retry_timeout_detects_retry_policy():
    assert any(p.search("retry_policy: exponential") for p in RETRY_TIMEOUT_PATTERNS)


def test_retry_timeout_detects_connect_timeout():
    assert any(p.search("connect_timeout=5") for p in RETRY_TIMEOUT_PATTERNS)


def test_retry_timeout_detects_read_timeout():
    assert any(p.search("read_timeout=30") for p in RETRY_TIMEOUT_PATTERNS)


def test_retry_timeout_detects_deadline():
    assert any(p.search("deadline=60") for p in RETRY_TIMEOUT_PATTERNS)


def test_retry_timeout_no_false_positive():
    assert not any(p.search("import os") for p in RETRY_TIMEOUT_PATTERNS)


# -- FALLBACK_PATTERNS matching ----------------------------------------------

def test_fallback_detects_fallback():
    assert any(p.search("def fallback():") for p in FALLBACK_PATTERNS)


def test_fallback_detects_graceful_degradation():
    assert any(p.search("graceful_degradation enabled") for p in FALLBACK_PATTERNS)


def test_fallback_detects_default_response():
    assert any(p.search("default_response = {}") for p in FALLBACK_PATTERNS)


def test_fallback_detects_failover():
    assert any(p.search("failover to secondary") for p in FALLBACK_PATTERNS)


def test_fallback_detects_fail_safe():
    assert any(p.search("fail_safe mode") for p in FALLBACK_PATTERNS)


def test_fallback_detects_backup_service():
    assert any(p.search("backup_service_url") for p in FALLBACK_PATTERNS)


def test_fallback_no_false_positive():
    assert not any(p.search("return 42") for p in FALLBACK_PATTERNS)


# -- AUTH_TOKEN_PATTERNS matching --------------------------------------------

def test_auth_token_detects_authorization_header():
    assert any(p.search("Authorization: Bearer abc") for p in AUTH_TOKEN_PATTERNS)


def test_auth_token_detects_bearer():
    assert any(p.search("Bearer eyJhbGciOiJIUz") for p in AUTH_TOKEN_PATTERNS)


def test_auth_token_detects_x_api_key():
    assert any(p.search("x-api-key: secret123") for p in AUTH_TOKEN_PATTERNS)


def test_auth_token_detects_api_token():
    assert any(p.search("api_token = getenv('TOKEN')") for p in AUTH_TOKEN_PATTERNS)


def test_auth_token_detects_auth_header():
    assert any(p.search("auth_header = 'Bearer ...'") for p in AUTH_TOKEN_PATTERNS)


def test_auth_token_detects_jwt():
    assert any(p.search("jwt.decode(token)") for p in AUTH_TOKEN_PATTERNS)


def test_auth_token_detects_oauth():
    assert any(p.search("oauth = OAuth2Session()") for p in AUTH_TOKEN_PATTERNS)


def test_auth_token_no_false_positive():
    assert not any(p.search("x = 1 + 2") for p in AUTH_TOKEN_PATTERNS)


# -- MTLS_PATTERNS matching --------------------------------------------------

def test_mtls_detects_mutual_tls():
    assert any(p.search("mutual_tls: true") for p in MTLS_PATTERNS)


def test_mtls_detects_mtls():
    assert any(p.search("mtls enabled") for p in MTLS_PATTERNS)


def test_mtls_detects_client_cert():
    assert any(p.search("client_cert=/path/to/cert") for p in MTLS_PATTERNS)


def test_mtls_detects_tls_client_auth():
    assert any(p.search("tls_client_auth: require") for p in MTLS_PATTERNS)


def test_mtls_detects_verify_client():
    assert any(p.search("verify_client on") for p in MTLS_PATTERNS)


def test_mtls_no_false_positive():
    assert not any(p.search("print('hello')") for p in MTLS_PATTERNS)


# -- MESSAGE_SIGNING_PATTERNS matching ---------------------------------------

def test_message_signing_detects_hmac():
    assert any(p.search("hmac.new(key, msg)") for p in MESSAGE_SIGNING_PATTERNS)


def test_message_signing_detects_message_sign():
    assert any(p.search("message_sign(data, key)") for p in MESSAGE_SIGNING_PATTERNS)


def test_message_signing_detects_verify_signature():
    assert any(p.search("verify_signature(sig, data)") for p in MESSAGE_SIGNING_PATTERNS)


def test_message_signing_detects_digital_signature():
    assert any(p.search("digital_signature = sign(payload)") for p in MESSAGE_SIGNING_PATTERNS)


def test_message_signing_detects_content_hash():
    assert any(p.search("content_hash = sha256(body)") for p in MESSAGE_SIGNING_PATTERNS)


def test_message_signing_detects_request_signing():
    assert any(p.search("request_signing middleware") for p in MESSAGE_SIGNING_PATTERNS)


def test_message_signing_detects_webhook_secret():
    assert any(p.search("webhook_secret = 'abc'") for p in MESSAGE_SIGNING_PATTERNS)


def test_message_signing_no_false_positive():
    assert not any(p.search("x = list()") for p in MESSAGE_SIGNING_PATTERNS)


# -- INTER_SERVICE_CALL_PATTERNS matching ------------------------------------

def test_inter_service_detects_requests_get():
    assert any(p.search("requests.get('http://svc/api')") for p in INTER_SERVICE_CALL_PATTERNS)


def test_inter_service_detects_requests_post():
    assert any(p.search("requests.post(url, json=data)") for p in INTER_SERVICE_CALL_PATTERNS)


def test_inter_service_detects_httpx_get():
    assert any(p.search("httpx.get(url)") for p in INTER_SERVICE_CALL_PATTERNS)


def test_inter_service_detects_httpx_async_client():
    assert any(p.search("httpx.AsyncClient()") for p in INTER_SERVICE_CALL_PATTERNS)


def test_inter_service_detects_aiohttp():
    assert any(p.search("aiohttp.ClientSession()") for p in INTER_SERVICE_CALL_PATTERNS)


def test_inter_service_detects_grpc():
    assert any(p.search("grpc.insecure_channel('svc:50051')") for p in INTER_SERVICE_CALL_PATTERNS)


def test_inter_service_detects_urllib():
    assert any(p.search("urllib.request.urlopen(url)") for p in INTER_SERVICE_CALL_PATTERNS)


def test_inter_service_no_false_positive():
    assert not any(p.search("def add(a, b): return a + b") for p in INTER_SERVICE_CALL_PATTERNS)


# -- INPUT_VALIDATION_PATTERNS matching --------------------------------------

def test_input_validation_detects_validate():
    assert any(p.search("schema.validate(data)") for p in INPUT_VALIDATION_PATTERNS)


def test_input_validation_detects_pydantic():
    assert any(p.search("from pydantic import BaseModel") for p in INPUT_VALIDATION_PATTERNS)


def test_input_validation_detects_marshmallow():
    assert any(p.search("marshmallow.Schema()") for p in INPUT_VALIDATION_PATTERNS)


def test_input_validation_detects_cerberus():
    assert any(p.search("cerberus.Validator(schema)") for p in INPUT_VALIDATION_PATTERNS)


def test_input_validation_detects_json_schema():
    assert any(p.search("json_schema.validate(data)") for p in INPUT_VALIDATION_PATTERNS)


def test_input_validation_detects_sanitize():
    assert any(p.search("sanitize(user_input)") for p in INPUT_VALIDATION_PATTERNS)


def test_input_validation_detects_bleach():
    assert any(p.search("bleach.clean(html)") for p in INPUT_VALIDATION_PATTERNS)


def test_input_validation_no_false_positive():
    assert not any(p.search("total = sum(values)") for p in INPUT_VALIDATION_PATTERNS)


# -- OUTPUT_SANITIZATION_PATTERNS matching -----------------------------------

def test_output_sanitization_detects_sanitize_output():
    assert any(p.search("sanitize_output(response)") for p in OUTPUT_SANITIZATION_PATTERNS)


def test_output_sanitization_detects_output_filter():
    assert any(p.search("output_filter applied") for p in OUTPUT_SANITIZATION_PATTERNS)


def test_output_sanitization_detects_output_validation():
    assert any(p.search("output_validation(result)") for p in OUTPUT_SANITIZATION_PATTERNS)


def test_output_sanitization_detects_escape_output():
    assert any(p.search("escape_output(data)") for p in OUTPUT_SANITIZATION_PATTERNS)


def test_output_sanitization_detects_response_filter():
    assert any(p.search("response_filter middleware") for p in OUTPUT_SANITIZATION_PATTERNS)


def test_output_sanitization_no_false_positive():
    assert not any(p.search("return 'ok'") for p in OUTPUT_SANITIZATION_PATTERNS)


# -- CORRELATION_PATTERNS matching -------------------------------------------

def test_correlation_detects_request_id():
    assert any(p.search("request_id = uuid4()") for p in CORRELATION_PATTERNS)


def test_correlation_detects_correlation_id():
    assert any(p.search("correlation_id: str") for p in CORRELATION_PATTERNS)


def test_correlation_detects_trace_id():
    assert any(p.search("trace_id = ctx.trace_id") for p in CORRELATION_PATTERNS)


def test_correlation_detects_x_request_id():
    assert any(p.search("x-request-id header") for p in CORRELATION_PATTERNS)


def test_correlation_detects_span_id():
    assert any(p.search("span_id = generate_span()") for p in CORRELATION_PATTERNS)


def test_correlation_detects_opentelemetry():
    assert any(p.search("from opentelemetry import trace") for p in CORRELATION_PATTERNS)


def test_correlation_detects_jaeger():
    assert any(p.search("jaeger_endpoint = 'http://...'") for p in CORRELATION_PATTERNS)


def test_correlation_detects_zipkin():
    assert any(p.search("zipkin exporter") for p in CORRELATION_PATTERNS)


def test_correlation_no_false_positive():
    assert not any(p.search("count = len(items)") for p in CORRELATION_PATTERNS)


# -- HMAC_SIGNATURE_PATTERNS matching ----------------------------------------

def test_hmac_sig_detects_hmac_module():
    assert any(p.search("hmac.new(secret, msg)") for p in HMAC_SIGNATURE_PATTERNS)


def test_hmac_sig_detects_hashlib_sha256():
    assert any(p.search("hashlib.sha256(data)") for p in HMAC_SIGNATURE_PATTERNS)


def test_hmac_sig_detects_create_hmac():
    assert any(p.search("createHmac('sha256', key)") for p in HMAC_SIGNATURE_PATTERNS)


def test_hmac_sig_detects_sign():
    assert any(p.search("signer.sign(payload)") for p in HMAC_SIGNATURE_PATTERNS)


def test_hmac_sig_detects_verify():
    assert any(p.search("verifier.verify(signature)") for p in HMAC_SIGNATURE_PATTERNS)


def test_hmac_sig_detects_signature():
    assert any(p.search("signature = compute_signature(data)") for p in HMAC_SIGNATURE_PATTERNS)


def test_hmac_sig_detects_digest():
    assert any(p.search("h.digest()") for p in HMAC_SIGNATURE_PATTERNS)


def test_hmac_sig_no_false_positive():
    assert not any(p.search("name = 'Alice'") for p in HMAC_SIGNATURE_PATTERNS)


# -- PLAINTEXT_COMM_PATTERNS matching ----------------------------------------

def test_plaintext_detects_http_external():
    assert any(p.search("http://api.example.com/data") for p in PLAINTEXT_COMM_PATTERNS)


def test_plaintext_does_not_flag_localhost():
    """http://localhost should NOT be flagged as plaintext communication."""
    assert not any(p.search("http://localhost:8080/api") for p in PLAINTEXT_COMM_PATTERNS)


def test_plaintext_does_not_flag_127():
    """http://127.0.0.1 should NOT be flagged."""
    assert not any(p.search("http://127.0.0.1:5000/") for p in PLAINTEXT_COMM_PATTERNS)


def test_plaintext_does_not_flag_0000():
    """http://0.0.0.0 should NOT be flagged."""
    assert not any(p.search("http://0.0.0.0:8000/api") for p in PLAINTEXT_COMM_PATTERNS)


def test_plaintext_detects_grpc_insecure():
    assert any(p.search("grpc.insecure_channel('svc:50051')") for p in PLAINTEXT_COMM_PATTERNS)


def test_plaintext_detects_verify_false():
    assert any(p.search("requests.get(url, verify=False)") for p in PLAINTEXT_COMM_PATTERNS)


def test_plaintext_detects_ssl_false():
    assert any(p.search("ssl=False") for p in PLAINTEXT_COMM_PATTERNS)


def test_plaintext_detects_tls_false():
    assert any(p.search("tls=False") for p in PLAINTEXT_COMM_PATTERNS)


def test_plaintext_no_false_positive_on_https():
    """https:// should NOT be flagged as plaintext."""
    assert not any(p.search("https://api.example.com/data") for p in PLAINTEXT_COMM_PATTERNS)


# -- _search helper ----------------------------------------------------------

def test_search_returns_hits_for_matching_content():
    ctx = ScanContext(target_image="test:latest")
    agent = CascadeAgent(ctx)
    files = {
        "/app/main.py": "import tenacity\ncircuit_breaker = True",
        "/app/utils.py": "print('hello')",
    }
    hits = agent._search(files, CIRCUIT_BREAKER_PATTERNS)
    assert len(hits) > 0
    matched_files = {f for f, _ in hits}
    assert "/app/main.py" in matched_files


def test_search_returns_empty_for_no_match():
    ctx = ScanContext(target_image="test:latest")
    agent = CascadeAgent(ctx)
    files = {
        "/app/main.py": "print('hello world')",
    }
    hits = agent._search(files, CIRCUIT_BREAKER_PATTERNS)
    assert hits == []


def test_search_returns_context_snippet():
    ctx = ScanContext(target_image="test:latest")
    agent = CascadeAgent(ctx)
    files = {
        "/app/main.py": "some prefix text healthcheck some suffix text",
    }
    hits = agent._search(files, HEALTH_CHECK_PATTERNS)
    assert len(hits) > 0
    _, snippet = hits[0]
    assert "healthcheck" in snippet


def test_search_limits_to_three_matches_per_pattern():
    ctx = ScanContext(target_image="test:latest")
    agent = CascadeAgent(ctx)
    # Content with many matches of the same pattern
    content = "\n".join(f"healthcheck_{i}" for i in range(20))
    files = {"/app/main.py": content}
    hits = agent._search(files, [HEALTH_CHECK_PATTERNS[0]])
    # Should be capped at 3 per pattern per file
    assert len(hits) <= 3


def test_search_across_multiple_files():
    ctx = ScanContext(target_image="test:latest")
    agent = CascadeAgent(ctx)
    files = {
        "/app/a.py": "healthcheck endpoint here",
        "/app/b.py": "readinessProbe: http",
        "/app/c.py": "no match here",
    }
    hits = agent._search(files, HEALTH_CHECK_PATTERNS)
    matched_files = {f for f, _ in hits}
    assert "/app/a.py" in matched_files
    assert "/app/b.py" in matched_files
    assert "/app/c.py" not in matched_files


# -- _has helper --------------------------------------------------------------

def test_has_returns_true_when_pattern_matches():
    ctx = ScanContext(target_image="test:latest")
    agent = CascadeAgent(ctx)
    files = {"/app/main.py": "circuit_breaker = CircuitBreaker()"}
    assert agent._has(files, CIRCUIT_BREAKER_PATTERNS) is True


def test_has_returns_false_when_no_match():
    ctx = ScanContext(target_image="test:latest")
    agent = CascadeAgent(ctx)
    files = {"/app/main.py": "print('no patterns here')"}
    assert agent._has(files, CIRCUIT_BREAKER_PATTERNS) is False


def test_has_returns_false_for_empty_files():
    ctx = ScanContext(target_image="test:latest")
    agent = CascadeAgent(ctx)
    files: dict[str, str] = {}
    assert agent._has(files, HEALTH_CHECK_PATTERNS) is False


def test_has_returns_true_if_any_file_matches():
    ctx = ScanContext(target_image="test:latest")
    agent = CascadeAgent(ctx)
    files = {
        "/app/a.py": "nothing useful",
        "/app/b.py": "still nothing",
        "/app/c.py": "oauth token exchange",
    }
    assert agent._has(files, AUTH_TOKEN_PATTERNS) is True


def test_has_returns_true_if_any_pattern_matches():
    ctx = ScanContext(target_image="test:latest")
    agent = CascadeAgent(ctx)
    files = {"/app/main.py": "zipkin exporter configured"}
    assert agent._has(files, CORRELATION_PATTERNS) is True


# -- Agent instantiation -----------------------------------------------------

def test_cascade_agent_creates_no_findings_without_container():
    ctx = ScanContext(target_image="test:latest")
    agent = CascadeAgent(ctx)
    assert agent.findings == []


@pytest.mark.asyncio
async def test_cascade_agent_run_returns_result():
    """Agent.run() should return an AgentResult even without Docker."""
    ctx = ScanContext(target_image="test:latest")
    agent = CascadeAgent(ctx)
    result = await agent.run()
    assert result.agent == "cascade"
    assert result.error is None
