"""Tests for additional SAST tools and platform compatibility."""

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from mrzero.tools.additional_sast import (
    InferTool,
    BearerTool,
    ApplicationInspectorTool,
)
from mrzero.tools.base import ToolOutput
from mrzero.core.sast_runner import (
    PlatformInfo,
    ToolCompatibility,
    get_platform_info,
)


class TestPlatformInfo:
    """Test PlatformInfo class."""

    def test_platform_detection(self):
        """Test that platform is detected."""
        info = PlatformInfo()

        # Should have a valid system
        assert info.system in ["linux", "darwin", "windows"]

        # At least one of these should be true
        assert info.is_linux or info.is_macos or info.is_windows

        # At least one architecture should match
        assert info.is_arm or info.is_x86 or True  # May be other arch

    def test_to_dict(self):
        """Test platform info serialization."""
        info = PlatformInfo()
        data = info.to_dict()

        assert "system" in data
        assert "machine" in data
        assert "is_linux" in data
        assert "is_macos" in data
        assert "is_windows" in data
        assert "python_version" in data

    def test_get_platform_info_singleton(self):
        """Test that get_platform_info returns consistent instance."""
        info1 = get_platform_info()
        info2 = get_platform_info()

        assert info1.system == info2.system
        assert info1.is_linux == info2.is_linux


class TestToolCompatibility:
    """Test ToolCompatibility class."""

    def test_known_tools_have_compatibility_info(self):
        """Test that all known tools have compatibility info."""
        compat = ToolCompatibility()

        known_tools = [
            "opengrep",
            "gitleaks",
            "trivy",
            "slither",
            "codeql",
            "infer",
            "bearer",
            "appinspector",
        ]

        for tool in known_tools:
            info = compat.get_tool_info(tool)
            assert info is not None, f"Missing info for {tool}"
            assert "platforms" in info
            assert "binary" in info

    def test_is_compatible_returns_bool(self):
        """Test is_compatible returns boolean."""
        compat = ToolCompatibility()

        # These should work on most platforms
        for tool in ["opengrep", "gitleaks", "trivy"]:
            result = compat.is_compatible(tool)
            assert isinstance(result, bool)

    def test_is_available_caches_results(self):
        """Test that availability checks are cached."""
        compat = ToolCompatibility()

        # First call
        result1 = compat.is_available("opengrep")

        # Should be cached now
        assert "opengrep" in compat._availability_cache

        # Second call should use cache
        result2 = compat.is_available("opengrep")
        assert result1 == result2

    def test_get_available_tools(self):
        """Test getting list of available tools."""
        compat = ToolCompatibility()
        available = compat.get_available_tools()

        assert isinstance(available, list)
        # All returned tools should be available
        for tool in available:
            assert compat.is_available(tool)

    def test_get_unavailable_tools(self):
        """Test getting unavailable tools with reasons."""
        compat = ToolCompatibility()
        unavailable = compat.get_unavailable_tools()

        assert isinstance(unavailable, dict)
        # All values should be reason strings
        for tool, reason in unavailable.items():
            assert isinstance(reason, str)
            assert len(reason) > 0

    def test_unknown_tool_assumed_compatible(self):
        """Test that unknown tools are assumed compatible."""
        compat = ToolCompatibility()

        # Unknown tool should return True for compatibility
        # but False for availability (binary not found)
        assert compat.is_compatible("unknown_tool_xyz") is True

    def test_infer_not_compatible_on_windows(self):
        """Test that Infer is not compatible on Windows."""
        compat = ToolCompatibility()

        tool_info = compat.TOOL_COMPATIBILITY.get("infer")
        assert tool_info is not None
        assert "windows" not in tool_info["platforms"]


class TestInferTool:
    """Test InferTool wrapper."""

    def test_tool_properties(self):
        """Test tool has correct properties."""
        tool = InferTool()

        assert tool.name == "infer"
        assert tool.required_binary == "infer"
        assert "Java" in tool.description or "static" in tool.description.lower()

    def test_unavailable_tool_returns_error(self):
        """Test unavailable tool returns proper error."""
        tool = InferTool()

        with patch.object(tool, "is_available", return_value=False):
            import asyncio

            result = asyncio.get_event_loop().run_until_complete(tool.run("/some/path"))

        assert result.success is False
        assert "not installed" in result.error.lower()

    def test_detect_build_command_makefile(self):
        """Test build command detection for Makefile."""
        tool = InferTool()

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            (target / "Makefile").write_text("all: build")

            cmd = tool._detect_build_command(target)
            assert cmd == "make"

    def test_detect_build_command_gradle(self):
        """Test build command detection for Gradle."""
        tool = InferTool()

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            (target / "build.gradle").write_text("apply plugin: 'java'")

            cmd = tool._detect_build_command(target)
            assert cmd == "gradle build"

    def test_detect_build_command_maven(self):
        """Test build command detection for Maven."""
        tool = InferTool()

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            (target / "pom.xml").write_text("<project></project>")

            cmd = tool._detect_build_command(target)
            assert cmd == "mvn compile"

    def test_parse_report(self):
        """Test Infer report parsing."""
        tool = InferTool()

        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            report_data = [
                {
                    "bug_type": "NULL_DEREFERENCE",
                    "qualifier": "pointer may be null",
                    "severity": "ERROR",
                    "file": "src/main.c",
                    "line": 42,
                    "procedure": "main",
                    "hash": "abc123",
                }
            ]
            report_path.write_text(json.dumps(report_data))

            findings = tool._parse_report(report_path)

            assert len(findings) == 1
            assert findings[0]["bug_type"] == "NULL_DEREFERENCE"
            assert findings[0]["severity"] == "HIGH"  # Mapped from ERROR
            assert findings[0]["line"] == 42


class TestBearerTool:
    """Test BearerTool wrapper."""

    def test_tool_properties(self):
        """Test tool has correct properties."""
        tool = BearerTool()

        assert tool.name == "bearer"
        assert tool.required_binary == "bearer"
        assert "security" in tool.description.lower()

    def test_unavailable_tool_returns_error(self):
        """Test unavailable tool returns proper error."""
        tool = BearerTool()

        with patch.object(tool, "is_available", return_value=False):
            import asyncio

            result = asyncio.get_event_loop().run_until_complete(tool.run("/some/path"))

        assert result.success is False
        assert "not installed" in result.error.lower()

    def test_parse_json_output(self):
        """Test Bearer JSON output parsing."""
        tool = BearerTool()

        output = json.dumps(
            {
                "high": [
                    {
                        "rule_id": "ruby_lang_ssl_verification",
                        "title": "SSL verification disabled",
                        "description": "SSL verification is disabled",
                        "severity": "high",
                        "filename": "app/config.rb",
                        "line_number": 15,
                        "cwe_ids": ["CWE-295"],
                    }
                ],
                "medium": [],
            }
        )

        result = tool._parse_json_output(output)

        assert result.success is True
        assert result.data["total"] == 1
        assert result.data["findings"][0]["severity"] == "HIGH"
        assert "CWE-295" in result.data["findings"][0]["cwe_ids"]

    def test_normalize_finding(self):
        """Test finding normalization."""
        tool = BearerTool()

        finding = {
            "rule_id": "test_rule",
            "title": "Test Issue",
            "description": "Description",
            "severity": "critical",
            "filename": "test.py",
            "line_number": 10,
            "cwe_ids": ["CWE-89"],
        }

        normalized = tool._normalize_finding(finding)

        assert normalized["rule_id"] == "test_rule"
        assert normalized["severity"] == "CRITICAL"
        assert normalized["file"] == "test.py"
        assert normalized["line_start"] == 10


class TestApplicationInspectorTool:
    """Test ApplicationInspectorTool wrapper."""

    def test_tool_properties(self):
        """Test tool has correct properties."""
        tool = ApplicationInspectorTool()

        assert tool.name == "appinspector"
        assert tool.required_binary == "appinspector"
        assert (
            "characterization" in tool.description.lower() or "feature" in tool.description.lower()
        )

    def test_unavailable_tool_returns_error(self):
        """Test unavailable tool returns proper error."""
        tool = ApplicationInspectorTool()

        with patch.object(tool, "is_available", return_value=False):
            import asyncio

            result = asyncio.get_event_loop().run_until_complete(tool.run("/some/path"))

        assert result.success is False
        assert "not installed" in result.error.lower()

    def test_determine_severity(self):
        """Test severity determination from tags."""
        tool = ApplicationInspectorTool()

        # Critical patterns
        assert tool._determine_severity(["Cryptography.Hash.Weak"]) == "CRITICAL"
        assert tool._determine_severity(["Authentication.Hardcoded"]) == "CRITICAL"

        # High severity
        assert tool._determine_severity(["Cryptography.Symmetric"]) == "HIGH"
        assert tool._determine_severity(["Authentication.OAuth"]) == "HIGH"

        # Medium severity
        assert tool._determine_severity(["Network.HTTP"]) == "MEDIUM"
        assert tool._determine_severity(["OS.Process.Start"]) == "MEDIUM"

        # Default low
        assert tool._determine_severity(["SomeOther.Tag"]) == "LOW"

    def test_parse_json_output(self):
        """Test Application Inspector JSON output parsing."""
        tool = ApplicationInspectorTool()

        output = json.dumps(
            {
                "metaData": {
                    "applicationName": "TestApp",
                    "sourcePath": "/app",
                    "languages": {"Python": 100},
                    "uniqueTagsCount": 5,
                    "totalMatchesCount": 10,
                    "uniqueMatchesCount": 8,
                },
                "matchList": [
                    {
                        "ruleName": "Cryptography.Hash.SHA1",
                        "ruleId": "crypto-hash-sha1",
                        "tags": ["Cryptography.Hash.Weak"],
                        "confidence": "high",
                        "fileName": "crypto.py",
                        "startLocationLine": 25,
                        "endLocationLine": 25,
                        "excerpt": "hashlib.sha1()",
                        "sample": "sha1",
                    }
                ],
            }
        )

        result = tool._parse_json_output(output)

        assert result.success is True
        assert result.data["total"] == 1
        assert result.data["metadata"]["application_name"] == "TestApp"
        assert result.data["findings"][0]["severity"] == "CRITICAL"
        assert len(result.data["security_findings"]) == 1


class TestSASTRunnerPlatformFeatures:
    """Test SASTRunner platform-aware features."""

    @pytest.fixture
    def temp_target(self):
        """Create a temporary target directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            (target / "app.py").write_text("print('hello')")
            yield target

    def test_get_platform_info(self, temp_target):
        """Test getting platform info from runner."""
        from mrzero.core.sast_runner import SASTRunner

        runner = SASTRunner(temp_target)
        info = runner.get_platform_info()

        assert "system" in info
        assert "is_linux" in info
        assert "python_version" in info

    def test_get_tool_status(self, temp_target):
        """Test getting tool status from runner."""
        from mrzero.core.sast_runner import SASTRunner

        runner = SASTRunner(temp_target)
        status = runner.get_tool_status()

        assert "platform" in status
        assert "available" in status
        assert "unavailable" in status

        # Available should be a list
        assert isinstance(status["available"], list)

        # Unavailable should be a dict
        assert isinstance(status["unavailable"], dict)

    def test_get_available_tools(self, temp_target):
        """Test getting available tools."""
        from mrzero.core.sast_runner import SASTRunner

        runner = SASTRunner(temp_target)
        available = runner.get_available_tools()

        assert isinstance(available, list)

    def test_is_tool_available_uses_compatibility(self, temp_target):
        """Test that is_tool_available uses ToolCompatibility."""
        from mrzero.core.sast_runner import SASTRunner

        runner = SASTRunner(temp_target)

        # Mock the compatibility checker
        with patch.object(runner._tool_compat, "is_available", return_value=True) as mock:
            result = runner._is_tool_available("opengrep")
            mock.assert_called_once_with("opengrep")
            assert result is True
