"""Tests for StaticAnalysisAgent."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aisec.agents.static_analysis import (
    DANGEROUS_PATTERNS,
    StaticAnalysisAgent,
)
from aisec.core.context import ScanContext
from aisec.core.enums import AgentPhase, Severity


class TestStaticAnalysisAgentMetadata:
    """Test agent class attributes."""

    def test_name(self):
        assert StaticAnalysisAgent.name == "static_analysis"

    def test_phase(self):
        assert StaticAnalysisAgent.phase == AgentPhase.STATIC

    def test_frameworks(self):
        assert "LLM01" in StaticAnalysisAgent.frameworks
        assert "ASI05" in StaticAnalysisAgent.frameworks

    def test_no_dependencies(self):
        assert StaticAnalysisAgent.depends_on == []


class TestStaticAnalysisAgentNoContainer:
    """Test agent behavior without a container."""

    @pytest.mark.asyncio
    async def test_no_container_returns_info(self, scan_context):
        agent = StaticAnalysisAgent(scan_context)
        await agent.analyze()
        assert len(agent.findings) == 1
        assert agent.findings[0].severity == Severity.INFO
        assert "No source" in agent.findings[0].title

    @pytest.mark.asyncio
    async def test_no_files_found(self, scan_context):
        scan_context.container_id = "test-container"
        agent = StaticAnalysisAgent(scan_context)

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            proc = AsyncMock()
            proc.returncode = 1
            proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = proc

            await agent.analyze()

        assert len(agent.findings) == 1
        assert "No source" in agent.findings[0].title


class TestBuiltinPatterns:
    """Test built-in pattern detection."""

    def test_dangerous_patterns_defined(self):
        assert len(DANGEROUS_PATTERNS) >= 7

    def test_pattern_structure(self):
        for name, regex, severity, desc, remediation in DANGEROUS_PATTERNS:
            assert isinstance(name, str)
            assert hasattr(regex, "search")
            assert isinstance(severity, Severity)
            assert isinstance(desc, str)
            assert isinstance(remediation, str)

    def test_eval_pattern_matches(self):
        _, pattern, *_ = DANGEROUS_PATTERNS[0]  # eval/exec with dynamic input
        assert pattern.search("eval(user_input)")
        assert pattern.search("exec(llm_response)")
        assert pattern.search("eval(request.data)")

    def test_subprocess_shell_true_matches(self):
        _, pattern, *_ = DANGEROUS_PATTERNS[1]  # subprocess with shell=True
        assert pattern.search("subprocess.call('ls', shell=True)")
        assert pattern.search("subprocess.run(cmd, shell=True)")

    def test_pickle_load_matches(self):
        _, pattern, *_ = DANGEROUS_PATTERNS[2]  # pickle.load
        assert pattern.search("pickle.load(f)")
        assert pattern.search("pickle.loads(data)")

    def test_os_system_fstring_matches(self):
        _, pattern, *_ = DANGEROUS_PATTERNS[3]  # os.system with f-string
        assert pattern.search('os.system(f"ls {path}")')

    def test_yaml_load_matches(self):
        _, pattern, *_ = DANGEROUS_PATTERNS[4]  # yaml.load without SafeLoader
        assert pattern.search("yaml.load(data)")

    def test_hardcoded_key_matches(self):
        _, pattern, *_ = DANGEROUS_PATTERNS[5]  # Hardcoded API key
        assert pattern.search('api_key = "sk-1234567890abcdefghij"')
        assert pattern.search('SECRET_KEY = "abcdefghij1234567890"')

    def test_torch_load_matches(self):
        _, pattern, *_ = DANGEROUS_PATTERNS[6]  # torch.load
        assert pattern.search("torch.load('model.pt')")


class TestBuiltinPatternScanning:
    """Test the built-in pattern scanning functionality."""

    @pytest.mark.asyncio
    async def test_builtin_patterns_on_files(self, scan_context):
        scan_context.container_id = "test-container"
        agent = StaticAnalysisAgent(scan_context)

        # Mock file content with dangerous patterns
        dangerous_code = (
            'import pickle\n'
            'data = pickle.load(open("model.pkl", "rb"))\n'
            'result = eval(user_input)\n'
        ).encode()

        async def mock_exec(*args, **kwargs):
            proc = AsyncMock()
            cmd = " ".join(args)
            if "head" in cmd or "head" in str(args):
                proc.returncode = 0
                proc.communicate = AsyncMock(return_value=(dangerous_code, b""))
            else:
                proc.returncode = 0
                proc.communicate = AsyncMock(return_value=(b"/app/main.py\n", b""))
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            # Mock semgrep and bandit as unavailable
            with patch.object(agent, "_run_semgrep", return_value=False):
                with patch.object(agent, "_run_bandit", return_value=False):
                    await agent.analyze()

        # Should find builtin patterns + "tools unavailable" info
        pattern_findings = [f for f in agent.findings if "Static pattern" in f.title]
        assert len(pattern_findings) > 0


class TestSemgrepIntegration:
    """Test Semgrep integration."""

    @pytest.mark.asyncio
    async def test_semgrep_unavailable(self, scan_context):
        scan_context.container_id = "test-container"
        agent = StaticAnalysisAgent(scan_context)

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            proc = AsyncMock()
            proc.returncode = 1
            proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = proc

            result = await agent._run_semgrep(["/app/main.py"])

        assert result is False

    @pytest.mark.asyncio
    async def test_semgrep_available_with_results(self, scan_context):
        scan_context.container_id = "test-container"
        agent = StaticAnalysisAgent(scan_context)

        semgrep_output = json.dumps({
            "results": [
                {
                    "check_id": "eval-llm-output",
                    "path": "/app/main.py",
                    "start": {"line": 10},
                    "extra": {
                        "severity": "ERROR",
                        "message": "eval on LLM output",
                        "lines": "eval(response)",
                        "fix": "Use safe parsing",
                    },
                }
            ]
        })

        call_count = 0

        async def mock_exec(*args, **kwargs):
            nonlocal call_count
            proc = AsyncMock()
            call_count += 1
            if call_count == 1:  # version check
                proc.returncode = 0
                proc.communicate = AsyncMock(return_value=(b"1.0.0", b""))
            else:  # actual scan
                proc.returncode = 0
                proc.communicate = AsyncMock(
                    return_value=(semgrep_output.encode(), b"")
                )
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            result = await agent._run_semgrep(["/app/main.py"])

        assert result is True
        assert len(agent.findings) == 1
        assert "Semgrep" in agent.findings[0].title


class TestBanditIntegration:
    """Test Bandit integration."""

    @pytest.mark.asyncio
    async def test_bandit_unavailable(self, scan_context):
        scan_context.container_id = "test-container"
        agent = StaticAnalysisAgent(scan_context)

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            proc = AsyncMock()
            proc.returncode = 1
            proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = proc

            result = await agent._run_bandit(["/app/main.py"])

        assert result is False

    @pytest.mark.asyncio
    async def test_bandit_no_python_files(self, scan_context):
        agent = StaticAnalysisAgent(scan_context)
        result = await agent._run_bandit(["/app/main.js", "/app/index.ts"])
        assert result is False

    @pytest.mark.asyncio
    async def test_bandit_with_results(self, scan_context):
        scan_context.container_id = "test-container"
        agent = StaticAnalysisAgent(scan_context)

        bandit_output = json.dumps({
            "results": [
                {
                    "test_id": "B102",
                    "issue_text": "Use of exec detected",
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "filename": "/app/main.py",
                    "line_number": 5,
                    "code": "exec(user_data)",
                    "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b102_exec_used.html",
                }
            ]
        })

        call_count = 0

        async def mock_exec(*args, **kwargs):
            nonlocal call_count
            proc = AsyncMock()
            call_count += 1
            if call_count == 1:  # version check
                proc.returncode = 0
                proc.communicate = AsyncMock(return_value=(b"1.7.0", b""))
            else:  # actual scan
                proc.returncode = 0
                proc.communicate = AsyncMock(
                    return_value=(bandit_output.encode(), b"")
                )
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            result = await agent._run_bandit(["/app/main.py"])

        assert result is True
        assert len(agent.findings) == 1
        assert "Bandit" in agent.findings[0].title
        assert agent.findings[0].severity == Severity.HIGH
