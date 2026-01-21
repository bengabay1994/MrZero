"""Unit tests for SAST tools."""

import pytest
from pathlib import Path

from mrzero.tools.sast import OpengrepTool, GitleaksTool, TrivyTool


class TestOpengrepTool:
    """Tests for Opengrep tool wrapper."""

    def test_tool_properties(self):
        """Test tool properties are set correctly."""
        tool = OpengrepTool()
        assert tool.name == "opengrep"
        assert tool.required_binary == "opengrep"
        assert "static analysis" in tool.description.lower()

    @pytest.mark.asyncio
    async def test_unavailable_tool_returns_error(self, temp_dir):
        """Test that unavailable tool returns appropriate error."""
        tool = OpengrepTool(use_docker=False)
        # Force tool to be unavailable (both local and docker)
        tool._available = False
        tool._docker_available = False

        result = await tool.run(str(temp_dir))

        assert result.success is False
        assert "not available" in result.error.lower() or "not installed" in result.error.lower()


class TestGitleaksTool:
    """Tests for Gitleaks tool wrapper."""

    def test_tool_properties(self):
        """Test tool properties are set correctly."""
        tool = GitleaksTool()
        assert tool.name == "gitleaks"
        assert tool.required_binary == "gitleaks"
        assert "secret" in tool.description.lower()

    @pytest.mark.asyncio
    async def test_unavailable_tool_returns_error(self, temp_dir):
        """Test that unavailable tool returns appropriate error."""
        tool = GitleaksTool()
        tool._available = False

        result = await tool.run(str(temp_dir))

        assert result.success is False
        assert "not installed" in result.error.lower()


class TestTrivyTool:
    """Tests for Trivy tool wrapper."""

    def test_tool_properties(self):
        """Test tool properties are set correctly."""
        tool = TrivyTool()
        assert tool.name == "trivy"
        assert tool.required_binary == "trivy"
        assert "vulnerability" in tool.description.lower()

    @pytest.mark.asyncio
    async def test_unavailable_tool_returns_error(self, temp_dir):
        """Test that unavailable tool returns appropriate error."""
        tool = TrivyTool()
        tool._available = False

        result = await tool.run(str(temp_dir))

        assert result.success is False
        assert "not installed" in result.error.lower()
