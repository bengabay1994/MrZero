"""Integration tests for SAST runner with caching."""

import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from mrzero.core.sast_runner import SASTRunner, SASTFinding


class TestSASTRunnerCaching:
    """Test SAST runner caching functionality."""

    @pytest.fixture
    def temp_target(self):
        """Create a temporary target directory with vulnerable code."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)

            # Create a Python file
            vuln_py = target / "app.py"
            vuln_py.write_text("""
import sqlite3
import os

def get_user(user_id):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

def run_cmd(cmd):
    os.system(f"echo {cmd}")
""")

            yield target

    @pytest.fixture
    def temp_db(self):
        """Create a temporary database for caching."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir) / "test.db"

    def test_runner_initialization(self, temp_target):
        """Test SAST runner initializes correctly."""
        runner = SASTRunner(temp_target)

        assert runner.target_path == temp_target
        assert runner._cache_enabled is True
        assert runner._db_manager is None  # Lazy loaded

    def test_cache_key_generation(self, temp_target):
        """Test cache key generation includes all components."""
        runner = SASTRunner(temp_target)

        key1 = runner._get_cache_key("opengrep")
        key2 = runner._get_cache_key("opengrep", {"rules": "auto"})
        key3 = runner._get_cache_key("gitleaks")

        # Keys should be different for different tools/args
        assert key1 != key2
        assert key1 != key3

        # Same call should produce same key
        key1_again = runner._get_cache_key("opengrep")
        assert key1 == key1_again

    def test_cache_key_includes_file_hash(self, temp_target):
        """Test cache key changes when files change."""
        runner = SASTRunner(temp_target)

        key_before = runner._get_cache_key("opengrep")

        # Modify a file
        (temp_target / "app.py").write_text("# Modified content")

        key_after = runner._get_cache_key("opengrep")

        # Key should change after file modification
        assert key_before != key_after

    def test_target_hash_computation(self, temp_target):
        """Test target hash is computed correctly."""
        runner = SASTRunner(temp_target)

        hash1 = runner._compute_target_hash()

        # Hash should be consistent
        hash2 = runner._compute_target_hash()
        assert hash1 == hash2

        # Hash should be a string
        assert isinstance(hash1, str)
        assert len(hash1) == 16  # Truncated SHA256

    def test_sast_finding_serialization(self):
        """Test SASTFinding can be serialized and deserialized."""
        finding = SASTFinding(
            rule_id="sql-injection",
            message="SQL injection vulnerability",
            severity="HIGH",
            file_path="/app/db.py",
            line_start=10,
            line_end=12,
            code_snippet="query = f'SELECT * FROM users WHERE id = {user_id}'",
            tool="opengrep",
            metadata={"cwe": "CWE-89"},
        )

        # Serialize
        data = finding.to_dict()
        assert data["rule_id"] == "sql-injection"
        assert data["severity"] == "HIGH"

        # Deserialize
        restored = SASTFinding.from_dict(data)
        assert restored.rule_id == finding.rule_id
        assert restored.severity == finding.severity
        assert restored.metadata == finding.metadata

    def test_cache_ttl_settings(self, temp_target):
        """Test cache TTL settings are correct."""
        runner = SASTRunner(temp_target)

        assert runner.CACHE_TTL["opengrep"] == 24
        assert runner.CACHE_TTL["gitleaks"] == 24
        assert runner.CACHE_TTL["trivy"] == 12
        assert runner.CACHE_TTL["slither"] == 24
        assert runner.CACHE_TTL["codeql"] == 24
        assert runner.CACHE_TTL["default"] == 12

    def test_is_tool_available(self, temp_target):
        """Test tool availability check."""
        runner = SASTRunner(temp_target)

        # These should be deterministic based on system
        python_available = runner._is_tool_available("python")
        nonexistent = runner._is_tool_available("nonexistent_tool_xyz")

        assert python_available is True
        assert nonexistent is False

    def test_has_solidity_files_false(self, temp_target):
        """Test Solidity detection when no .sol files."""
        runner = SASTRunner(temp_target)
        assert runner._has_solidity_files() is False

    def test_has_solidity_files_true(self, temp_target):
        """Test Solidity detection when .sol files exist."""
        (temp_target / "Contract.sol").write_text("// SPDX-License-Identifier: MIT")
        runner = SASTRunner(temp_target)
        assert runner._has_solidity_files() is True

    def test_deduplicate_findings(self, temp_target):
        """Test finding deduplication."""
        runner = SASTRunner(temp_target)

        finding1 = SASTFinding(
            rule_id="sql-injection",
            message="SQL injection",
            severity="HIGH",
            file_path="app.py",
            line_start=10,
            line_end=10,
            code_snippet="code",
            tool="opengrep",
            metadata={},
        )

        finding2 = SASTFinding(
            rule_id="sql-injection",  # Same rule
            message="Different message",
            severity="HIGH",
            file_path="app.py",  # Same file
            line_start=10,  # Same line
            line_end=10,
            code_snippet="code",
            tool="gitleaks",  # Different tool
            metadata={},
        )

        finding3 = SASTFinding(
            rule_id="cmd-injection",  # Different rule
            message="Command injection",
            severity="CRITICAL",
            file_path="app.py",
            line_start=15,  # Different line
            line_end=15,
            code_snippet="code",
            tool="opengrep",
            metadata={},
        )

        deduped = runner._deduplicate_findings([finding1, finding2, finding3])

        # Should remove finding2 (same file:line:rule as finding1)
        assert len(deduped) == 2
        assert deduped[0].rule_id == "sql-injection"
        assert deduped[1].rule_id == "cmd-injection"


class TestSASTRunnerWithMockedTools:
    """Test SAST runner with mocked external tools."""

    @pytest.fixture
    def temp_target(self):
        """Create a temporary target directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            (target / "app.py").write_text("print('hello')")
            yield target

    @pytest.mark.asyncio
    async def test_run_opengrep_parses_output(self, temp_target):
        """Test opengrep output parsing."""
        runner = SASTRunner(temp_target)

        mock_output = json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.sql-injection",
                        "path": "app.py",
                        "start": {"line": 5},
                        "end": {"line": 5},
                        "extra": {
                            "message": "SQL injection vulnerability",
                            "severity": "ERROR",
                            "lines": "query = f'SELECT * FROM users WHERE id = {user_id}'",
                            "metadata": {"cwe": "CWE-89"},
                        },
                    }
                ]
            }
        )

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate.return_value = (mock_output.encode(), b"")
            mock_exec.return_value = mock_proc

            findings = await runner.run_opengrep()

        assert len(findings) == 1
        assert findings[0].rule_id == "python.sql-injection"
        assert findings[0].severity == "ERROR"
        assert findings[0].tool == "opengrep"

    @pytest.mark.asyncio
    async def test_run_gitleaks_parses_output(self, temp_target):
        """Test gitleaks output parsing."""
        runner = SASTRunner(temp_target)

        mock_output = json.dumps(
            [
                {
                    "RuleID": "aws-access-token",
                    "Description": "AWS Access Token",
                    "File": "config.py",
                    "StartLine": 3,
                    "EndLine": 3,
                    "Secret": "AKIAIOSFODNN7EXAMPLE",
                    "Entropy": 3.5,
                    "Match": "aws_access_key_id",
                }
            ]
        )

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate.return_value = (mock_output.encode(), b"")
            mock_exec.return_value = mock_proc

            findings = await runner.run_gitleaks()

        assert len(findings) == 1
        assert findings[0].rule_id == "aws-access-token"
        assert findings[0].severity == "HIGH"
        assert findings[0].tool == "gitleaks"
        # Secret should be truncated
        assert "..." in findings[0].code_snippet

    @pytest.mark.asyncio
    async def test_run_trivy_parses_vulnerabilities(self, temp_target):
        """Test trivy output parsing for vulnerabilities."""
        runner = SASTRunner(temp_target)

        mock_output = json.dumps(
            {
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2021-1234",
                                "PkgName": "flask",
                                "InstalledVersion": "1.0.0",
                                "FixedVersion": "2.0.0",
                                "Severity": "HIGH",
                                "Title": "RCE in Flask",
                                "References": ["https://nvd.nist.gov/vuln/detail/CVE-2021-1234"],
                            }
                        ],
                    }
                ]
            }
        )

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate.return_value = (mock_output.encode(), b"")
            mock_exec.return_value = mock_proc

            findings = await runner.run_trivy()

        assert len(findings) == 1
        assert findings[0].rule_id == "CVE-2021-1234"
        assert findings[0].severity == "HIGH"
        assert findings[0].tool == "trivy"
        assert "flask@1.0.0" in findings[0].code_snippet

    @pytest.mark.asyncio
    async def test_run_slither_parses_output(self, temp_target):
        """Test slither output parsing."""
        # Create a Solidity file
        (temp_target / "Contract.sol").write_text("contract Test {}")
        runner = SASTRunner(temp_target)

        mock_output = json.dumps(
            {
                "results": {
                    "detectors": [
                        {
                            "check": "reentrancy-eth",
                            "description": "Reentrancy vulnerability",
                            "impact": "High",
                            "confidence": "Medium",
                            "elements": [
                                {
                                    "source_mapping": {
                                        "filename_relative": "Contract.sol",
                                        "lines": [10, 11, 12],
                                    }
                                }
                            ],
                        }
                    ]
                }
            }
        )

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate.return_value = (mock_output.encode(), b"")
            mock_exec.return_value = mock_proc

            findings = await runner.run_slither()

        assert len(findings) == 1
        assert findings[0].rule_id == "reentrancy-eth"
        assert findings[0].severity == "HIGH"
        assert findings[0].tool == "slither"

    @pytest.mark.asyncio
    async def test_run_all_available_aggregates_results(self, temp_target):
        """Test run_all_available aggregates findings from multiple tools."""
        runner = SASTRunner(temp_target)

        # Mock tool availability - only opengrep available
        with patch.object(runner, "_is_tool_available") as mock_available:
            mock_available.side_effect = lambda tool: tool == "opengrep"

            with patch.object(runner, "_run_with_cache") as mock_run:
                mock_run.return_value = [
                    SASTFinding(
                        rule_id="test-rule",
                        message="Test",
                        severity="HIGH",
                        file_path="app.py",
                        line_start=1,
                        line_end=1,
                        code_snippet="code",
                        tool="opengrep",
                        metadata={},
                    )
                ]

                findings = await runner.run_all_available()

        assert len(findings) == 1
        assert findings[0].rule_id == "test-rule"

    @pytest.mark.asyncio
    async def test_run_with_cache_returns_cached_on_hit(self, temp_target):
        """Test _run_with_cache returns cached results on cache hit."""
        runner = SASTRunner(temp_target)

        cached_findings = [
            SASTFinding(
                rule_id="cached-finding",
                message="From cache",
                severity="MEDIUM",
                file_path="app.py",
                line_start=5,
                line_end=5,
                code_snippet="cached code",
                tool="opengrep",
                metadata={},
            )
        ]

        # Mock cache hit
        with patch.object(runner, "_get_cached_findings", return_value=cached_findings):
            # The actual run function should NOT be called
            mock_run = AsyncMock(return_value=[])

            result = await runner._run_with_cache("opengrep", mock_run, use_cache=True)

        assert result == cached_findings
        mock_run.assert_not_called()

    @pytest.mark.asyncio
    async def test_run_with_cache_runs_tool_on_miss(self, temp_target):
        """Test _run_with_cache runs tool on cache miss."""
        runner = SASTRunner(temp_target)

        fresh_findings = [
            SASTFinding(
                rule_id="fresh-finding",
                message="Fresh result",
                severity="HIGH",
                file_path="app.py",
                line_start=10,
                line_end=10,
                code_snippet="fresh code",
                tool="opengrep",
                metadata={},
            )
        ]

        # Mock cache miss
        with patch.object(runner, "_get_cached_findings", return_value=None):
            with patch.object(runner, "_cache_findings") as mock_cache:
                mock_run = AsyncMock(return_value=fresh_findings)

                result = await runner._run_with_cache("opengrep", mock_run, use_cache=True)

        assert result == fresh_findings
        mock_run.assert_called_once()
        mock_cache.assert_called_once_with("opengrep", fresh_findings)

    @pytest.mark.asyncio
    async def test_run_with_cache_skips_cache_when_disabled(self, temp_target):
        """Test _run_with_cache skips caching when use_cache=False."""
        runner = SASTRunner(temp_target)

        findings = [
            SASTFinding(
                rule_id="test",
                message="Test",
                severity="LOW",
                file_path="app.py",
                line_start=1,
                line_end=1,
                code_snippet="code",
                tool="opengrep",
                metadata={},
            )
        ]

        with patch.object(runner, "_get_cached_findings") as mock_get:
            with patch.object(runner, "_cache_findings") as mock_set:
                mock_run = AsyncMock(return_value=findings)

                result = await runner._run_with_cache("opengrep", mock_run, use_cache=False)

        # Cache should not be checked or set
        mock_get.assert_not_called()
        mock_set.assert_not_called()
        mock_run.assert_called_once()

    @pytest.mark.asyncio
    async def test_tool_timeout_handled_gracefully(self, temp_target):
        """Test that tool timeouts are handled gracefully."""
        runner = SASTRunner(temp_target)

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate.side_effect = asyncio.TimeoutError()
            mock_exec.return_value = mock_proc

            # Should not raise, just return empty
            findings = await runner.run_opengrep()

        assert findings == []

    @pytest.mark.asyncio
    async def test_tool_not_found_handled_gracefully(self, temp_target):
        """Test that missing tools are handled gracefully."""
        runner = SASTRunner(temp_target)

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_exec.side_effect = FileNotFoundError()

            # Should not raise, just return empty
            findings = await runner.run_opengrep()

        assert findings == []


class TestSeverityMapping:
    """Test severity score mapping."""

    def test_severity_to_score(self):
        """Test severity to score conversion."""
        from mrzero.core.sast_runner import severity_to_score

        assert severity_to_score("CRITICAL") == 95
        assert severity_to_score("HIGH") == 80
        assert severity_to_score("MEDIUM") == 55
        assert severity_to_score("LOW") == 30
        assert severity_to_score("INFO") == 15
        assert severity_to_score("WARNING") == 50
        assert severity_to_score("UNKNOWN") == 40

    def test_severity_to_score_case_insensitive(self):
        """Test severity mapping is case insensitive."""
        from mrzero.core.sast_runner import severity_to_score

        assert severity_to_score("critical") == 95
        assert severity_to_score("Critical") == 95
        assert severity_to_score("high") == 80

    def test_severity_to_score_unknown_value(self):
        """Test unknown severity returns default score."""
        from mrzero.core.sast_runner import severity_to_score

        assert severity_to_score("INVALID") == 40
        assert severity_to_score("") == 40
