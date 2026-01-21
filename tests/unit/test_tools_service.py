"""Tests for the unified ToolsService."""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mrzero.core.tools_service import (
    ToolBackend,
    ToolCategory,
    ToolExecutionResult,
    ToolSpec,
    ToolsService,
    get_tools_service,
    get_initialized_tools_service,
)


# =============================================================================
# Test ToolSpec
# =============================================================================


class TestToolSpec:
    """Tests for ToolSpec dataclass."""

    def test_tool_spec_creation(self):
        """Test creating a ToolSpec."""
        spec = ToolSpec(
            name="test-tool",
            description="A test tool",
            category=ToolCategory.SAST,
            backend=ToolBackend.LOCAL,
            binary_name="test-bin",
        )

        assert spec.name == "test-tool"
        assert spec.description == "A test tool"
        assert spec.category == ToolCategory.SAST
        assert spec.backend == ToolBackend.LOCAL
        assert spec.binary_name == "test-bin"
        assert spec.available is False  # Default

    def test_tool_spec_mcp(self):
        """Test MCP tool spec."""
        spec = ToolSpec(
            name="ghidra",
            description="Binary analysis",
            category=ToolCategory.BINARY_ANALYSIS,
            backend=ToolBackend.MCP,
            mcp_server="ghidra",
        )

        assert spec.backend == ToolBackend.MCP
        assert spec.mcp_server == "ghidra"

    def test_tool_spec_docker(self):
        """Test Docker tool spec."""
        spec = ToolSpec(
            name="opengrep",
            description="SAST scanner",
            category=ToolCategory.SAST,
            backend=ToolBackend.DOCKER,
            docker_image="ghcr.io/test/toolbox:latest",
        )

        assert spec.backend == ToolBackend.DOCKER
        assert spec.docker_image == "ghcr.io/test/toolbox:latest"


# =============================================================================
# Test ToolExecutionResult
# =============================================================================


class TestToolExecutionResult:
    """Tests for ToolExecutionResult."""

    def test_result_creation(self):
        """Test creating a tool result."""
        result = ToolExecutionResult(
            tool="opengrep",
            backend=ToolBackend.DOCKER,
            success=True,
            output={"results": []},
            execution_time=1.5,
        )

        assert result.tool == "opengrep"
        assert result.backend == ToolBackend.DOCKER
        assert result.success is True
        assert result.output == {"results": []}
        assert result.execution_time == 1.5

    def test_result_to_dict(self):
        """Test converting result to dict."""
        result = ToolExecutionResult(
            tool="gitleaks",
            backend=ToolBackend.LOCAL,
            success=False,
            output=None,
            error="Tool not found",
            exit_code=1,
        )

        d = result.to_dict()
        assert d["tool"] == "gitleaks"
        assert d["backend"] == "local"
        assert d["success"] is False
        assert d["error"] == "Tool not found"
        assert d["exit_code"] == 1


# =============================================================================
# Test ToolsService - Initialization
# =============================================================================


class TestToolsServiceInit:
    """Tests for ToolsService initialization."""

    def test_service_creation(self):
        """Test creating service without initialization."""
        service = ToolsService()
        assert service._initialized is False
        assert service._tools == {}

    @pytest.mark.asyncio
    async def test_service_initialization(self):
        """Test service initialization registers tools."""
        service = ToolsService()
        await service.initialize()

        assert service._initialized is True
        assert len(service._tools) > 0

    @pytest.mark.asyncio
    async def test_double_initialization(self):
        """Test that double initialization is idempotent."""
        service = ToolsService()
        await service.initialize()
        tool_count = len(service._tools)

        await service.initialize()
        assert len(service._tools) == tool_count


# =============================================================================
# Test ToolsService - Tool Registration
# =============================================================================


class TestToolsServiceRegistration:
    """Tests for tool registration."""

    @pytest.mark.asyncio
    async def test_sast_tools_registered(self):
        """Test that SAST tools are registered."""
        service = ToolsService()
        await service.initialize()

        # Check opengrep is registered
        spec = service.get_tool("opengrep")
        assert spec is not None
        assert spec.category == ToolCategory.SAST

    @pytest.mark.asyncio
    async def test_mcp_tools_registered(self):
        """Test that MCP tools are registered."""
        service = ToolsService()
        await service.initialize()

        # Check ghidra is registered
        spec = service.get_tool("ghidra")
        assert spec is not None
        assert spec.backend == ToolBackend.MCP
        assert spec.mcp_server == "ghidra"

    @pytest.mark.asyncio
    async def test_get_tools_by_category(self):
        """Test getting tools by category."""
        service = ToolsService()
        await service.initialize()

        # Get SAST tools
        sast_tools = service.get_tools_by_category(ToolCategory.SAST)
        assert isinstance(sast_tools, list)

        # Check all returned tools are SAST
        for spec in sast_tools:
            assert spec.category == ToolCategory.SAST

    @pytest.mark.asyncio
    async def test_all_categories_have_tools(self):
        """Test that tools are registered for expected categories."""
        service = ToolsService()
        await service.initialize()

        # These categories should have tools registered
        expected_categories = [
            ToolCategory.SAST,
            ToolCategory.SECRET_DETECTION,
            ToolCategory.DEPENDENCY,
            ToolCategory.BINARY_ANALYSIS,
            ToolCategory.DEBUGGING,
            ToolCategory.EXPLOITATION,
            ToolCategory.DYNAMIC_ANALYSIS,
        ]

        for category in expected_categories:
            # Check tools are registered (even if not available)
            tools = [s for s in service._tools.values() if s.category == category]
            assert len(tools) > 0, f"No tools registered for {category}"


# =============================================================================
# Test ToolsService - Tool Queries
# =============================================================================


class TestToolsServiceQueries:
    """Tests for tool query methods."""

    @pytest.mark.asyncio
    async def test_get_tool_exists(self):
        """Test getting an existing tool."""
        service = ToolsService()
        await service.initialize()

        spec = service.get_tool("opengrep")
        assert spec is not None
        assert spec.name == "opengrep"

    @pytest.mark.asyncio
    async def test_get_tool_not_exists(self):
        """Test getting a non-existent tool."""
        service = ToolsService()
        await service.initialize()

        spec = service.get_tool("nonexistent-tool")
        assert spec is None

    @pytest.mark.asyncio
    async def test_is_tool_available_unknown(self):
        """Test availability check for unknown tool."""
        service = ToolsService()
        await service.initialize()

        assert service.is_tool_available("nonexistent") is False

    @pytest.mark.asyncio
    async def test_get_status(self):
        """Test getting service status."""
        service = ToolsService()
        await service.initialize()

        status = service.get_status()

        assert "initialized" in status
        assert status["initialized"] is True
        assert "backends" in status
        assert "docker" in status["backends"]
        assert "mcp" in status["backends"]
        assert "local" in status["backends"]
        assert "tools" in status
        assert "total" in status["tools"]
        assert "available" in status["tools"]


# =============================================================================
# Test ToolsService - SAST Execution
# =============================================================================


class TestToolsServiceSAST:
    """Tests for SAST tool execution."""

    @pytest.mark.asyncio
    async def test_run_sast_unknown_tool(self):
        """Test running unknown SAST tool."""
        service = ToolsService()
        await service.initialize()

        result = await service.run_sast("unknown-tool", Path("/tmp"))

        assert result.success is False
        assert "Unknown tool" in result.error

    @pytest.mark.asyncio
    async def test_run_sast_unavailable_tool(self):
        """Test running unavailable SAST tool."""
        service = ToolsService()
        await service.initialize()

        # Mark opengrep as unavailable
        spec = service.get_tool("opengrep")
        if spec:
            spec.available = False

        result = await service.run_sast("opengrep", Path("/tmp"))

        assert result.success is False
        assert "not available" in result.error

    @pytest.mark.asyncio
    async def test_run_sast_nonexistent_path(self):
        """Test running SAST on non-existent path."""
        service = ToolsService()
        await service.initialize()

        # Mock the tool as available
        spec = service.get_tool("opengrep")
        if spec:
            spec.available = True

        # The actual execution will fail due to path not existing
        result = await service.run_sast("opengrep", Path("/nonexistent/path"))

        # Should fail (either due to subprocess or validation)
        assert result.success is False

    @pytest.mark.asyncio
    async def test_run_all_sast_no_tools(self):
        """Test run_all_sast when no tools available."""
        service = ToolsService()
        await service.initialize()

        # Mark all tools as unavailable
        for spec in service._tools.values():
            spec.available = False

        results = await service.run_all_sast(Path("/tmp"))

        assert results == []


# =============================================================================
# Test ToolsService - Docker Backend
# =============================================================================


class TestToolsServiceDocker:
    """Tests for Docker backend execution."""

    @pytest.mark.asyncio
    async def test_docker_sast_no_toolbox(self):
        """Test Docker SAST when toolbox not available."""
        service = ToolsService()
        # Don't initialize - manually set toolbox to None
        service._docker_toolbox = None

        spec = ToolSpec(
            name="opengrep",
            description="test",
            category=ToolCategory.SAST,
            backend=ToolBackend.DOCKER,
        )

        result = await service._run_docker_sast(spec, Path("/tmp"), None, 60)

        assert result.success is False
        assert "not available" in result.error or result.error is not None

    @pytest.mark.asyncio
    async def test_docker_opengrep_execution(self):
        """Test Docker opengrep execution with mock."""
        service = ToolsService()

        # Mock Docker toolbox
        mock_toolbox = MagicMock()
        mock_toolbox.is_toolbox_available.return_value = True
        mock_toolbox.run_opengrep_async = AsyncMock(
            return_value=MagicMock(
                success=True,
                output='{"results": []}',
                error=None,
                exit_code=0,
            )
        )
        service._docker_toolbox = mock_toolbox

        spec = ToolSpec(
            name="opengrep",
            description="SAST",
            category=ToolCategory.SAST,
            backend=ToolBackend.DOCKER,
        )

        result = await service._run_docker_sast(spec, Path("/tmp"), "auto", 60)

        assert result.success is True
        mock_toolbox.run_opengrep_async.assert_called_once()


# =============================================================================
# Test ToolsService - MCP Backend
# =============================================================================


class TestToolsServiceMCP:
    """Tests for MCP backend execution."""

    @pytest.mark.asyncio
    async def test_mcp_tool_no_manager(self):
        """Test MCP tool when manager not available."""
        service = ToolsService()
        service._mcp_manager = None

        spec = ToolSpec(
            name="ghidra",
            description="Binary analysis",
            category=ToolCategory.BINARY_ANALYSIS,
            backend=ToolBackend.MCP,
            mcp_server="ghidra",
        )

        result = await service._run_mcp_tool(spec, "analyze")

        assert result.success is False
        assert "MCP manager not available" in result.error

    @pytest.mark.asyncio
    async def test_mcp_tool_no_server_config(self):
        """Test MCP tool with no server configured."""
        service = ToolsService()
        service._mcp_manager = MagicMock()

        spec = ToolSpec(
            name="test",
            description="test",
            category=ToolCategory.BINARY_ANALYSIS,
            backend=ToolBackend.MCP,
            mcp_server=None,
        )

        result = await service._run_mcp_tool(spec, "analyze")

        assert result.success is False
        assert "No MCP server configured" in result.error

    @pytest.mark.asyncio
    async def test_mcp_tool_not_connected(self):
        """Test MCP tool when server not connected."""
        service = ToolsService()

        mock_manager = MagicMock()
        mock_manager.get_connection.return_value = None
        service._mcp_manager = mock_manager

        spec = ToolSpec(
            name="ghidra",
            description="Binary analysis",
            category=ToolCategory.BINARY_ANALYSIS,
            backend=ToolBackend.MCP,
            mcp_server="ghidra",
        )

        result = await service._run_mcp_tool(spec, "analyze")

        assert result.success is False
        assert "not connected" in result.error


# =============================================================================
# Test ToolsService - Output Parsing
# =============================================================================


class TestToolsServiceParsing:
    """Tests for output parsing methods."""

    def test_parse_opengrep_output_valid(self):
        """Test parsing valid opengrep output."""
        service = ToolsService()

        output = json.dumps(
            {
                "results": [{"check_id": "test", "path": "test.py"}],
                "errors": [],
            }
        )

        parsed = service._parse_opengrep_output(output)

        assert parsed is not None
        assert "results" in parsed
        assert len(parsed["results"]) == 1

    def test_parse_opengrep_output_invalid(self):
        """Test parsing invalid opengrep output."""
        service = ToolsService()

        parsed = service._parse_opengrep_output("not json")

        assert parsed is not None
        assert "raw" in parsed

    def test_parse_opengrep_output_empty(self):
        """Test parsing empty opengrep output."""
        service = ToolsService()

        parsed = service._parse_opengrep_output("")

        assert parsed is None

    def test_parse_linguist_output(self):
        """Test parsing linguist output."""
        service = ToolsService()

        output = "50.00% Python\n30.00% JavaScript\n20.00% HTML"

        parsed = service._parse_linguist_output(output)

        assert parsed is not None
        assert "languages" in parsed
        assert parsed["languages"]["Python"] == 50.0
        assert parsed["languages"]["JavaScript"] == 30.0


# =============================================================================
# Test ToolsService - Global Instance
# =============================================================================


class TestToolsServiceGlobal:
    """Tests for global service instance."""

    def test_get_tools_service_singleton(self):
        """Test that get_tools_service returns singleton."""
        # Reset global
        import mrzero.core.tools_service as ts

        ts._tools_service = None

        service1 = get_tools_service()
        service2 = get_tools_service()

        assert service1 is service2

    @pytest.mark.asyncio
    async def test_get_initialized_tools_service(self):
        """Test getting initialized service."""
        # Reset global
        import mrzero.core.tools_service as ts

        ts._tools_service = None

        service = await get_initialized_tools_service()

        assert service._initialized is True


# =============================================================================
# Test ToolsService - Hybrid Backend
# =============================================================================


class TestToolsServiceHybrid:
    """Tests for hybrid backend (Docker preferred, local fallback)."""

    @pytest.mark.asyncio
    async def test_hybrid_prefers_docker(self):
        """Test that hybrid backend prefers Docker when available."""
        service = ToolsService()

        # Mock Docker toolbox as available
        mock_toolbox = MagicMock()
        mock_toolbox.is_toolbox_available.return_value = True
        mock_toolbox.run_opengrep_async = AsyncMock(
            return_value=MagicMock(
                success=True,
                output='{"results": []}',
                error=None,
                exit_code=0,
            )
        )
        service._docker_toolbox = mock_toolbox

        spec = ToolSpec(
            name="opengrep",
            description="SAST",
            category=ToolCategory.SAST,
            backend=ToolBackend.HYBRID,
            docker_image="test",
            binary_name="opengrep",
        )

        result = await service._run_hybrid_sast(spec, Path("/tmp"), None, 60)

        assert result.backend == ToolBackend.DOCKER
        mock_toolbox.run_opengrep_async.assert_called_once()

    @pytest.mark.asyncio
    async def test_hybrid_falls_back_to_local(self):
        """Test that hybrid backend falls back to local when Docker unavailable."""
        service = ToolsService()
        service._docker_toolbox = None

        spec = ToolSpec(
            name="opengrep",
            description="SAST",
            category=ToolCategory.SAST,
            backend=ToolBackend.HYBRID,
            docker_image="test",
            binary_name="opengrep",
        )

        # This will fail because opengrep binary isn't installed
        result = await service._run_hybrid_sast(spec, Path("/tmp"), None, 60)

        assert result.backend == ToolBackend.LOCAL


# =============================================================================
# Test ToolsService - Secret Scanning
# =============================================================================


class TestToolsServiceSecrets:
    """Tests for secret scanning."""

    @pytest.mark.asyncio
    async def test_run_secret_scan_unavailable(self):
        """Test running secret scan when tool unavailable."""
        service = ToolsService()
        await service.initialize()

        # Mark gitleaks as unavailable
        spec = service.get_tool("gitleaks")
        if spec:
            spec.available = False

        result = await service.run_secret_scan("gitleaks", Path("/tmp"))

        assert result.success is False
        assert "not available" in result.error


# =============================================================================
# Test ToolsService - Binary Analysis
# =============================================================================


class TestToolsServiceBinaryAnalysis:
    """Tests for binary analysis tools."""

    @pytest.mark.asyncio
    async def test_run_binary_analysis_unavailable(self):
        """Test running binary analysis when tool unavailable."""
        service = ToolsService()
        await service.initialize()

        result = await service.run_binary_analysis("ghidra", Path("/tmp/test.bin"))

        # Should fail because MCP server not connected
        assert result.success is False

    @pytest.mark.asyncio
    async def test_run_binary_analysis_wrong_backend(self):
        """Test running binary analysis on non-MCP tool."""
        service = ToolsService()
        await service.initialize()

        # opengrep is not a binary analysis tool
        result = await service.run_binary_analysis("opengrep", Path("/tmp/test.bin"))

        assert result.success is False


# =============================================================================
# Test ToolsService - Language Detection
# =============================================================================


class TestToolsServiceLanguageDetection:
    """Tests for language detection."""

    @pytest.mark.asyncio
    async def test_run_language_detection_unavailable(self):
        """Test language detection when linguist unavailable."""
        service = ToolsService()
        await service.initialize()

        # Mark linguist as unavailable
        spec = service.get_tool("linguist")
        if spec:
            spec.available = False

        result = await service.run_language_detection(Path("/tmp"))

        assert result.success is False
        assert "not available" in result.error

    @pytest.mark.asyncio
    async def test_run_language_detection_docker(self):
        """Test language detection prefers Docker."""
        service = ToolsService()

        # Mock Docker toolbox
        mock_toolbox = MagicMock()
        mock_toolbox.is_toolbox_available.return_value = True
        mock_toolbox.run_linguist_async = AsyncMock(
            return_value=MagicMock(
                success=True,
                output="50.00% Python\n50.00% JavaScript",
                error=None,
                exit_code=0,
            )
        )
        service._docker_toolbox = mock_toolbox

        # Register linguist as available
        service._tools["linguist"] = ToolSpec(
            name="linguist",
            description="Language detection",
            category=ToolCategory.LANGUAGE_DETECTION,
            backend=ToolBackend.HYBRID,
            available=True,
        )

        result = await service.run_language_detection(Path("/tmp"))

        assert result.backend == ToolBackend.DOCKER
        mock_toolbox.run_linguist_async.assert_called_once()


# =============================================================================
# Test ToolCategory Enum
# =============================================================================


class TestToolCategory:
    """Tests for ToolCategory enum."""

    def test_all_categories_exist(self):
        """Test all expected categories exist."""
        expected = [
            "SAST",
            "SECRET_DETECTION",
            "DEPENDENCY",
            "BINARY_ANALYSIS",
            "DEBUGGING",
            "EXPLOITATION",
            "DYNAMIC_ANALYSIS",
            "LANGUAGE_DETECTION",
            "SMART_CONTRACT",
        ]

        for name in expected:
            assert hasattr(ToolCategory, name)


# =============================================================================
# Test ToolBackend Enum
# =============================================================================


class TestToolBackend:
    """Tests for ToolBackend enum."""

    def test_all_backends_exist(self):
        """Test all expected backends exist."""
        expected = ["DOCKER", "MCP", "LOCAL", "HYBRID"]

        for name in expected:
            assert hasattr(ToolBackend, name)

    def test_backend_values(self):
        """Test backend enum values."""
        assert ToolBackend.DOCKER.value == "docker"
        assert ToolBackend.MCP.value == "mcp"
        assert ToolBackend.LOCAL.value == "local"
        assert ToolBackend.HYBRID.value == "hybrid"
