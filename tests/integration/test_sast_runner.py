"""Integration tests for SAST functionality.

Note: SASTRunner is deprecated. Use mrzero.core.tools_service.ToolsService instead.
These tests verify backward compatibility of the deprecated SASTRunner.
"""

import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from mrzero.core.sast_runner import SASTRunner, SASTFinding


class TestSASTFinding:
    """Test SASTFinding dataclass."""

    def test_sast_finding_serialization(self):
        """Test SASTFinding can be serialized and deserialized."""
        finding = SASTFinding(
            rule_id="test-rule",
            message="Test message",
            severity="HIGH",
            file_path="/path/to/file.py",
            line_start=10,
            line_end=15,
            code_snippet="vulnerable code",
            tool="opengrep",
            metadata={"cwe": "CWE-89"},
        )

        # Convert to dict
        data = finding.to_dict()

        assert data["rule_id"] == "test-rule"
        assert data["severity"] == "HIGH"
        assert data["metadata"]["cwe"] == "CWE-89"

        # Reconstruct from dict
        finding2 = SASTFinding.from_dict(data)

        assert finding2.rule_id == finding.rule_id
        assert finding2.severity == finding.severity
        assert finding2.metadata == finding.metadata


class TestSeverityScore:
    """Test severity score conversion."""

    def test_severity_to_score_critical(self):
        """Test CRITICAL severity score."""
        from mrzero.core.sast_runner import severity_to_score

        assert severity_to_score("CRITICAL") == 95
        assert severity_to_score("critical") == 95

    def test_severity_to_score_high(self):
        """Test HIGH severity score."""
        from mrzero.core.sast_runner import severity_to_score

        assert severity_to_score("HIGH") == 80

    def test_severity_to_score_medium(self):
        """Test MEDIUM severity score."""
        from mrzero.core.sast_runner import severity_to_score

        assert severity_to_score("MEDIUM") == 55

    def test_severity_to_score_low(self):
        """Test LOW severity score."""
        from mrzero.core.sast_runner import severity_to_score

        assert severity_to_score("LOW") == 30

    def test_severity_to_score_unknown(self):
        """Test unknown severity score."""
        from mrzero.core.sast_runner import severity_to_score

        assert severity_to_score("UNKNOWN") == 40
        assert severity_to_score("xyz") == 40


class TestPlatformInfo:
    """Test PlatformInfo class."""

    def test_platform_info_creation(self):
        """Test PlatformInfo can be created."""
        from mrzero.core.sast_runner import PlatformInfo

        info = PlatformInfo()

        assert info.system in ["linux", "darwin", "windows"]
        assert isinstance(info.is_linux, bool)
        assert isinstance(info.is_macos, bool)
        assert isinstance(info.is_windows, bool)

    def test_platform_info_to_dict(self):
        """Test PlatformInfo to_dict."""
        from mrzero.core.sast_runner import PlatformInfo

        info = PlatformInfo()
        data = info.to_dict()

        assert "system" in data
        assert "is_linux" in data
        assert "is_macos" in data
        assert "is_windows" in data
        assert "python_version" in data


class TestToolCompatibility:
    """Test ToolCompatibility class."""

    def test_tool_compatibility_creation(self):
        """Test ToolCompatibility can be created."""
        from mrzero.core.sast_runner import ToolCompatibility

        compat = ToolCompatibility()

        assert compat.platform is not None
        assert len(compat.TOOL_COMPATIBILITY) > 0

    def test_is_compatible_known_tool(self):
        """Test is_compatible for known tools."""
        from mrzero.core.sast_runner import ToolCompatibility

        compat = ToolCompatibility()

        # These should be compatible on most platforms
        assert compat.is_compatible("opengrep") is True
        assert compat.is_compatible("gitleaks") is True

    def test_is_compatible_unknown_tool(self):
        """Test is_compatible for unknown tools defaults to True."""
        from mrzero.core.sast_runner import ToolCompatibility

        compat = ToolCompatibility()

        # Unknown tools are assumed compatible
        assert compat.is_compatible("unknown_tool_xyz") is True

    def test_get_available_tools(self):
        """Test getting available tools list."""
        from mrzero.core.sast_runner import ToolCompatibility

        compat = ToolCompatibility()
        available = compat.get_available_tools()

        assert isinstance(available, list)

    def test_get_unavailable_tools(self):
        """Test getting unavailable tools with reasons."""
        from mrzero.core.sast_runner import ToolCompatibility

        compat = ToolCompatibility()
        unavailable = compat.get_unavailable_tools()

        assert isinstance(unavailable, dict)
        for tool, reason in unavailable.items():
            assert isinstance(reason, str)

    def test_get_tool_info(self):
        """Test getting tool info."""
        from mrzero.core.sast_runner import ToolCompatibility

        compat = ToolCompatibility()

        # Known tool
        info = compat.get_tool_info("opengrep")
        assert info is not None
        assert "platforms" in info
        assert "binary" in info
        assert "compatible" in info
        assert "available" in info

        # Unknown tool
        info = compat.get_tool_info("unknown_xyz")
        assert info is None


class TestDeprecatedSASTRunner:
    """Test deprecated SASTRunner for backward compatibility."""

    @pytest.fixture
    def temp_target(self):
        """Create a temporary target directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            (target / "app.py").write_text("print('hello')")
            yield target

    def test_runner_initialization(self, temp_target):
        """Test SASTRunner initializes with deprecation warning."""
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            runner = SASTRunner(temp_target)

            assert len(w) == 1
            assert "deprecated" in str(w[0].message).lower()

        assert runner.target_path == temp_target

    def test_get_available_tools(self, temp_target):
        """Test getting available tools."""
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            runner = SASTRunner(temp_target)
            available = runner.get_available_tools()

        assert isinstance(available, list)

    def test_get_platform_info(self, temp_target):
        """Test getting platform info."""
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            runner = SASTRunner(temp_target)
            info = runner.get_platform_info()

        assert "system" in info
        assert "is_linux" in info

    def test_get_tool_status(self, temp_target):
        """Test getting tool status."""
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            runner = SASTRunner(temp_target)
            status = runner.get_tool_status()

        assert "platform" in status
        assert "available" in status
        assert "unavailable" in status


class TestToolsServiceIntegration:
    """Test new ToolsService integration (replaces deprecated SASTRunner tests)."""

    @pytest.fixture
    def temp_target(self):
        """Create a temporary target directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            (target / "app.py").write_text("print('hello')")
            yield target

    @pytest.mark.asyncio
    async def test_tools_service_initialization(self):
        """Test ToolsService initializes correctly."""
        from mrzero.core.tools_service import ToolsService

        service = ToolsService()
        await service.initialize()

        assert service._initialized is True
        assert len(service._tools) > 0

    @pytest.mark.asyncio
    async def test_tools_service_get_status(self):
        """Test getting service status."""
        from mrzero.core.tools_service import get_initialized_tools_service

        service = await get_initialized_tools_service()
        status = service.get_status()

        assert "initialized" in status
        assert "backends" in status
        assert "tools" in status

    @pytest.mark.asyncio
    async def test_tools_service_get_available_tools(self):
        """Test getting available tools."""
        from mrzero.core.tools_service import get_initialized_tools_service

        service = await get_initialized_tools_service()
        available = service.get_available_tools()

        assert isinstance(available, list)

    @pytest.mark.asyncio
    async def test_tools_service_run_sast_unavailable_tool(self, temp_target):
        """Test running SAST with unavailable tool."""
        from mrzero.core.tools_service import get_initialized_tools_service

        service = await get_initialized_tools_service()

        # Mark the tool as unavailable
        spec = service.get_tool("opengrep")
        if spec:
            original_available = spec.available
            spec.available = False

            result = await service.run_sast("opengrep", temp_target)

            assert result.success is False
            assert "not available" in result.error

            # Restore
            spec.available = original_available

    @pytest.mark.asyncio
    async def test_tools_service_run_all_sast_no_tools(self, temp_target):
        """Test run_all_sast when no tools available."""
        from mrzero.core.tools_service import get_initialized_tools_service

        service = await get_initialized_tools_service()

        # Temporarily mark all tools as unavailable
        original_states = {}
        for name, spec in service._tools.items():
            original_states[name] = spec.available
            spec.available = False

        try:
            results = await service.run_all_sast(temp_target)
            assert results == []
        finally:
            # Restore states
            for name, available in original_states.items():
                service._tools[name].available = available
