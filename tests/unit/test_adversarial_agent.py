"""Tests for AdversarialAgent."""

import pytest

from aisec.agents.adversarial import (
    DANGEROUS_CODE_PATTERNS,
    SANDBOX_ESCAPE_INDICATORS,
    ENCODING_BYPASS_PATTERNS,
    AdversarialAgent,
)
from aisec.core.context import ScanContext
from aisec.core.enums import AgentPhase, Severity


# -- Agent metadata ----------------------------------------------------------

def test_adversarial_agent_name():
    assert AdversarialAgent.name == "adversarial"


def test_adversarial_agent_phase():
    assert AdversarialAgent.phase == AgentPhase.DYNAMIC


def test_adversarial_agent_frameworks():
    assert "LLM01" in AdversarialAgent.frameworks
    assert "LLM05" in AdversarialAgent.frameworks
    assert "LLM06" in AdversarialAgent.frameworks
    assert "ASI01" in AdversarialAgent.frameworks
    assert "ASI02" in AdversarialAgent.frameworks


def test_adversarial_agent_depends_on():
    assert "permission" in AdversarialAgent.depends_on
    assert "prompt_security" in AdversarialAgent.depends_on


# -- DANGEROUS_CODE_PATTERNS matching ----------------------------------------

def test_dangerous_pattern_detects_eval():
    code = 'result = eval(user_input)'
    assert any(pat.search(code) for pat, _, _, _ in DANGEROUS_CODE_PATTERNS)


def test_dangerous_pattern_detects_exec():
    code = 'exec(code_string)'
    assert any(pat.search(code) for pat, _, _, _ in DANGEROUS_CODE_PATTERNS)


def test_dangerous_pattern_detects_os_system():
    code = 'os.system("ls -la")'
    assert any(pat.search(code) for pat, _, _, _ in DANGEROUS_CODE_PATTERNS)


def test_dangerous_pattern_detects_os_popen():
    code = 'os.popen("cat /etc/passwd")'
    assert any(pat.search(code) for pat, _, _, _ in DANGEROUS_CODE_PATTERNS)


def test_dangerous_pattern_detects_subprocess_shell_true():
    code = 'subprocess.run(cmd, shell=True)'
    assert any(pat.search(code) for pat, _, _, _ in DANGEROUS_CODE_PATTERNS)


def test_dangerous_pattern_detects_compile_exec():
    code = "compile(source, 'file', 'exec')"
    assert any(pat.search(code) for pat, _, _, _ in DANGEROUS_CODE_PATTERNS)


def test_dangerous_pattern_detects_dynamic_import():
    code = 'importlib.import_module(module_name)'
    assert any(pat.search(code) for pat, _, _, _ in DANGEROUS_CODE_PATTERNS)


def test_dangerous_pattern_detects_dunder_import():
    code = '__import__("os")'
    assert any(pat.search(code) for pat, _, _, _ in DANGEROUS_CODE_PATTERNS)


def test_dangerous_pattern_detects_jinja2_from_string():
    code = 'Template(user_input).render() or from_string(tpl)'
    assert any(pat.search(code) for pat, _, _, _ in DANGEROUS_CODE_PATTERNS)


# -- Safe code should NOT match DANGEROUS_CODE_PATTERNS ----------------------

def test_safe_def_eval_not_matched():
    """A function named 'def eval_something()' should NOT trigger the eval pattern."""
    code = 'def eval_metrics(predictions):'
    # The eval pattern uses (?<!def ) negative lookbehind
    eval_patterns = [(pat, name) for pat, name, _, _ in DANGEROUS_CODE_PATTERNS if name == "eval()"]
    assert len(eval_patterns) > 0
    for pat, _ in eval_patterns:
        assert not pat.search(code), "def eval_metrics should not match the eval() pattern"


def test_safe_def_exec_not_matched():
    """A function named 'def exec_query()' should NOT trigger the exec pattern."""
    code = 'def exec_query(sql):'
    exec_patterns = [(pat, name) for pat, name, _, _ in DANGEROUS_CODE_PATTERNS if name == "exec()"]
    assert len(exec_patterns) > 0
    for pat, _ in exec_patterns:
        assert not pat.search(code), "def exec_query should not match the exec() pattern"


def test_subprocess_shell_false_not_matched():
    """subprocess.run with shell=False should NOT match the shell=True pattern."""
    code = 'subprocess.run(["ls", "-la"], shell=False)'
    shell_patterns = [(pat, name) for pat, name, _, _ in DANGEROUS_CODE_PATTERNS
                      if "shell=True" in name]
    assert len(shell_patterns) > 0
    for pat, _ in shell_patterns:
        assert not pat.search(code), "subprocess with shell=False should not match"


def test_safe_print_not_matched():
    """A plain print statement should not match any dangerous pattern."""
    code = 'print("Hello world")'
    assert not any(pat.search(code) for pat, _, _, _ in DANGEROUS_CODE_PATTERNS)


# -- DANGEROUS_CODE_PATTERNS structure ---------------------------------------

def test_dangerous_code_patterns_tuple_format():
    """Each entry must be a 4-tuple (pattern, name, severity, remediation)."""
    for entry in DANGEROUS_CODE_PATTERNS:
        assert len(entry) == 4
        pat, name, severity, remediation = entry
        assert hasattr(pat, "search"), "First element must be a compiled regex"
        assert isinstance(name, str)
        assert isinstance(severity, Severity)
        assert isinstance(remediation, str)


def test_dangerous_code_patterns_have_critical_entries():
    severities = {sev for _, _, sev, _ in DANGEROUS_CODE_PATTERNS}
    assert Severity.CRITICAL in severities


def test_dangerous_code_patterns_have_high_entries():
    severities = {sev for _, _, sev, _ in DANGEROUS_CODE_PATTERNS}
    assert Severity.HIGH in severities


# -- SANDBOX_ESCAPE_INDICATORS structure -------------------------------------

def test_sandbox_escape_indicators_not_empty():
    assert len(SANDBOX_ESCAPE_INDICATORS) > 0


def test_sandbox_escape_indicators_tuple_format():
    """Each entry must be a 4-tuple (indicator, description, severity, remediation)."""
    for entry in SANDBOX_ESCAPE_INDICATORS:
        assert len(entry) == 4
        indicator, description, severity, remediation = entry
        assert isinstance(indicator, str)
        assert isinstance(description, str)
        assert isinstance(severity, Severity)
        assert isinstance(remediation, str)


def test_sandbox_escape_detects_docker_socket():
    indicators = [ind for ind, _, _, _ in SANDBOX_ESCAPE_INDICATORS]
    assert "/var/run/docker.sock" in indicators


def test_sandbox_escape_detects_privileged():
    indicators = [ind for ind, _, _, _ in SANDBOX_ESCAPE_INDICATORS]
    assert "Privileged" in indicators


def test_sandbox_escape_detects_sys_admin():
    indicators = [ind for ind, _, _, _ in SANDBOX_ESCAPE_INDICATORS]
    assert "SYS_ADMIN" in indicators


def test_sandbox_escape_detects_pid_mode():
    indicators = [ind for ind, _, _, _ in SANDBOX_ESCAPE_INDICATORS]
    assert "PidMode" in indicators


def test_sandbox_escape_detects_seccomp_unconfined():
    indicators = [ind for ind, _, _, _ in SANDBOX_ESCAPE_INDICATORS]
    assert "seccomp=unconfined" in indicators


# -- ENCODING_BYPASS_PATTERNS matching ---------------------------------------

def test_encoding_pattern_detects_base64_decode():
    code = 'decoded = base64.b64decode(encoded)'
    assert any(pat.search(code) for pat, _ in ENCODING_BYPASS_PATTERNS)


def test_encoding_pattern_detects_hex_decode():
    code = 'raw = bytes.fromhex(hex_str)'
    assert any(pat.search(code) for pat, _ in ENCODING_BYPASS_PATTERNS)


def test_encoding_pattern_detects_url_decode():
    code = 'text = urllib.parse.unquote(encoded_url)'
    assert any(pat.search(code) for pat, _ in ENCODING_BYPASS_PATTERNS)


def test_encoding_pattern_detects_codecs_decode():
    code = 'result = codecs.decode(data, "rot_13")'
    assert any(pat.search(code) for pat, _ in ENCODING_BYPASS_PATTERNS)


def test_encoding_pattern_detects_unicode_normalization():
    code = 'normalized = unicodedata.normalize("NFKC", text)'
    assert any(pat.search(code) for pat, _ in ENCODING_BYPASS_PATTERNS)


def test_encoding_pattern_detects_invisible_unicode():
    code = r'text = "hello\u200bworld"'
    assert any(pat.search(code) for pat, _ in ENCODING_BYPASS_PATTERNS)


def test_encoding_pattern_detects_double_url_encoding():
    code = 'payload = "%2527OR"'
    assert any(pat.search(code) for pat, _ in ENCODING_BYPASS_PATTERNS)


def test_encoding_pattern_detects_homoglyph():
    code = 'from homoglyph import detect'
    assert any(pat.search(code) for pat, _ in ENCODING_BYPASS_PATTERNS)


def test_safe_string_does_not_match_encoding():
    """Plain string manipulation should not match encoding patterns."""
    code = 'result = text.upper()'
    assert not any(pat.search(code) for pat, _ in ENCODING_BYPASS_PATTERNS)


# -- Agent instantiation -----------------------------------------------------

def test_adversarial_agent_creates_no_findings_without_container():
    ctx = ScanContext(target_image="test:latest")
    agent = AdversarialAgent(ctx)
    assert agent.findings == []


@pytest.mark.asyncio
async def test_adversarial_agent_run_returns_result():
    """Agent.run() should return an AgentResult even without Docker."""
    ctx = ScanContext(target_image="test:latest")
    agent = AdversarialAgent(ctx)
    result = await agent.run()
    assert result.agent == "adversarial"
    assert result.error is None
