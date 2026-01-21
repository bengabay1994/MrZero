"""Unit tests for MCP infrastructure."""

import asyncio
import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock, MagicMock

from mrzero.core.mcp.registry import (
    MCPServerConfig,
    MCPServerType,
    MCPTransport,
    MCPServerRegistry,
    MCP_SERVERS,
    get_mcp_registry,
)
from mrzero.core.mcp.installer import (
    MCPInstaller,
    InstallResult,
    get_mcp_installer,
)
from mrzero.core.mcp.client import (
    MCPClient,
    MCPServerConnection,
    MCPServerManager,
    ToolResult,
    get_mcp_client,
    get_mcp_manager,
)


class TestMCPServerConfig:
    """Tests for MCPServerConfig."""

    def test_create_config(self):
        """Test creating a server config."""
        config = MCPServerConfig(
            name="test-server",
            description="A test server",
            repo_url="https://github.com/test/server",
            server_type=MCPServerType.PYTHON,
        )

        assert config.name == "test-server"
        assert config.description == "A test server"
        assert config.server_type == MCPServerType.PYTHON
        assert config.transport == MCPTransport.STDIO  # default

    def test_get_start_command(self):
        """Test getting the start command."""
        config = MCPServerConfig(
            name="test",
            description="Test",
            repo_url="https://test.com",
            server_type=MCPServerType.PYTHON,
            command=["python", "server.py"],
            default_args=["--mode", "stdio"],
        )

        cmd = config.get_start_command()
        assert cmd == ["python", "server.py", "--mode", "stdio"]

    def test_get_env(self):
        """Test getting environment variables."""
        config = MCPServerConfig(
            name="test",
            description="Test",
            repo_url="https://test.com",
            server_type=MCPServerType.PYTHON,
            env={"API_KEY": "default", "PORT": "8080"},
        )

        env = config.get_env(API_KEY="custom")
        assert env["API_KEY"] == "custom"
        assert env["PORT"] == "8080"


class TestMCPServerRegistry:
    """Tests for MCPServerRegistry."""

    def test_registry_has_predefined_servers(self):
        """Test that registry contains predefined servers."""
        registry = MCPServerRegistry()

        assert "ghidra" in registry.list_server_names()
        assert "metasploit" in registry.list_server_names()
        assert "pwndbg" in registry.list_server_names()
        assert "frida" in registry.list_server_names()

    def test_get_server(self):
        """Test getting a server by name."""
        registry = MCPServerRegistry()

        ghidra = registry.get_server("ghidra")
        assert ghidra is not None
        assert ghidra.name == "ghidra"
        assert "Ghidra" in ghidra.description

    def test_get_nonexistent_server(self):
        """Test getting a non-existent server returns None."""
        registry = MCPServerRegistry()

        result = registry.get_server("nonexistent")
        assert result is None

    def test_list_servers(self):
        """Test listing all servers."""
        registry = MCPServerRegistry()

        servers = registry.list_servers()
        assert len(servers) > 0
        assert all(isinstance(s, MCPServerConfig) for s in servers)

    def test_get_compatible_servers_linux(self):
        """Test getting Linux-compatible servers."""
        registry = MCPServerRegistry()

        servers = registry.get_compatible_servers("linux")
        assert len(servers) > 0
        assert all("linux" in s.platforms for s in servers)

    def test_get_compatible_servers_windows(self):
        """Test getting Windows-compatible servers."""
        registry = MCPServerRegistry()

        servers = registry.get_compatible_servers("win32")
        assert len(servers) > 0

    def test_get_servers_by_category(self):
        """Test getting servers by category."""
        registry = MCPServerRegistry()

        re_servers = registry.get_servers_by_category("reverse_engineering")
        assert len(re_servers) > 0
        assert any(s.name == "ghidra" for s in re_servers)

    def test_register_custom_server(self):
        """Test registering a custom server."""
        registry = MCPServerRegistry()

        custom = MCPServerConfig(
            name="custom-server",
            description="Custom test server",
            repo_url="https://test.com",
            server_type=MCPServerType.PYTHON,
        )

        registry.register_server(custom)
        assert registry.get_server("custom-server") is not None

    def test_mark_installed(self):
        """Test marking a server as installed."""
        registry = MCPServerRegistry()

        assert not registry.is_installed("ghidra")

        registry.mark_installed("ghidra", Path("/tmp/ghidra"))
        assert registry.is_installed("ghidra")
        assert registry.get_install_path("ghidra") == Path("/tmp/ghidra")

    def test_global_registry(self):
        """Test global registry singleton."""
        registry1 = get_mcp_registry()
        registry2 = get_mcp_registry()
        assert registry1 is registry2


class TestMCPInstaller:
    """Tests for MCPInstaller."""

    def test_installer_creates_base_dir(self, tmp_path):
        """Test that installer creates base directory."""
        base_dir = tmp_path / "mcp-servers"
        installer = MCPInstaller(base_dir=base_dir)

        assert base_dir.exists()

    def test_get_install_path(self, tmp_path):
        """Test getting install path for a server."""
        installer = MCPInstaller(base_dir=tmp_path)

        path = installer.get_install_path("ghidra")
        assert path == tmp_path / "ghidra"

    def test_is_installed_false(self, tmp_path):
        """Test is_installed returns False when not installed."""
        installer = MCPInstaller(base_dir=tmp_path)

        assert not installer.is_installed("ghidra")

    def test_is_installed_true(self, tmp_path):
        """Test is_installed returns True when installed."""
        installer = MCPInstaller(base_dir=tmp_path)

        # Simulate installation
        install_path = tmp_path / "ghidra"
        install_path.mkdir()
        (install_path / ".installed").touch()

        assert installer.is_installed("ghidra")

    def test_install_unknown_server(self, tmp_path):
        """Test installing unknown server fails."""
        installer = MCPInstaller(base_dir=tmp_path)

        result = installer.install("unknown-server")

        assert not result.success
        assert "Unknown server" in result.message

    def test_check_requirements(self, tmp_path):
        """Test checking server requirements."""
        installer = MCPInstaller(base_dir=tmp_path)

        requirements = installer.check_requirements("ghidra")
        assert "ghidra" in requirements

    def test_uninstall(self, tmp_path):
        """Test uninstalling a server."""
        installer = MCPInstaller(base_dir=tmp_path)

        # Create fake installation
        install_path = tmp_path / "test-server"
        install_path.mkdir()
        (install_path / "file.txt").touch()

        assert installer.uninstall("test-server")
        assert not install_path.exists()

    def test_uninstall_not_installed(self, tmp_path):
        """Test uninstalling non-installed server succeeds."""
        installer = MCPInstaller(base_dir=tmp_path)

        assert installer.uninstall("nonexistent")


class TestMCPClient:
    """Tests for MCPClient."""

    def test_register_tool(self):
        """Test registering a tool."""
        client = MCPClient()

        mock_tool = Mock()
        mock_tool.name = "test-tool"

        client.register_tool(mock_tool)
        assert client.get_tool("test-tool") is mock_tool

    def test_get_nonexistent_tool(self):
        """Test getting non-existent tool returns None."""
        client = MCPClient()

        assert client.get_tool("nonexistent") is None

    def test_list_tools(self):
        """Test listing tools."""
        client = MCPClient()

        mock_tool = Mock()
        mock_tool.name = "test"
        mock_tool.get_schema.return_value = {"name": "test", "description": "Test"}

        client.register_tool(mock_tool)
        tools = client.list_tools()

        assert len(tools) == 1
        assert tools[0]["name"] == "test"

    @pytest.mark.asyncio
    async def test_execute_tool(self):
        """Test executing a tool."""
        client = MCPClient()

        mock_tool = Mock()
        mock_tool.name = "test"
        mock_tool.execute = AsyncMock(
            return_value=ToolResult(
                tool_name="test",
                success=True,
                output={"result": "ok"},
            )
        )

        client.register_tool(mock_tool)
        result = await client.execute("test", arg1="value1")

        assert result.success
        mock_tool.execute.assert_called_once_with(arg1="value1")

    @pytest.mark.asyncio
    async def test_execute_nonexistent_tool(self):
        """Test executing non-existent tool raises error."""
        client = MCPClient()

        with pytest.raises(ValueError, match="not found"):
            await client.execute("nonexistent")

    @pytest.mark.asyncio
    async def test_execute_with_caching(self):
        """Test tool execution caching."""
        client = MCPClient()

        mock_tool = Mock()
        mock_tool.name = "test"
        mock_tool.execute = AsyncMock(
            return_value=ToolResult(
                tool_name="test",
                success=True,
                output={"result": "ok"},
            )
        )

        client.register_tool(mock_tool)

        # First call
        result1 = await client.execute("test", cache_key="key1")
        # Second call with same cache key
        result2 = await client.execute("test", cache_key="key1")

        # Should only call execute once
        assert mock_tool.execute.call_count == 1
        assert result1 is result2

    def test_global_client(self):
        """Test global client singleton."""
        client1 = get_mcp_client()
        client2 = get_mcp_client()
        assert client1 is client2


class TestMCPServerConnection:
    """Tests for MCPServerConnection."""

    def test_create_connection(self):
        """Test creating a connection."""
        conn = MCPServerConnection(
            name="test",
            command=["python", "server.py"],
            env={"KEY": "value"},
        )

        assert conn.name == "test"
        assert conn.command == ["python", "server.py"]
        assert conn.env == {"KEY": "value"}
        assert not conn.connected

    def test_command_string_split(self):
        """Test command string is split correctly."""
        conn = MCPServerConnection(
            name="test",
            command="python server.py --arg value",
        )

        assert conn.command == ["python", "server.py", "--arg", "value"]

    @pytest.mark.asyncio
    async def test_disconnect_when_not_connected(self):
        """Test disconnect when not connected does nothing."""
        conn = MCPServerConnection(name="test", command=["test"])

        await conn.disconnect()  # Should not raise
        assert not conn.connected


class TestMCPServerManager:
    """Tests for MCPServerManager."""

    def test_list_connections_empty(self):
        """Test listing connections when empty."""
        manager = MCPServerManager()

        assert manager.list_connections() == []

    def test_get_nonexistent_connection(self):
        """Test getting non-existent connection returns None."""
        manager = MCPServerManager()

        assert manager.get_connection("nonexistent") is None

    @pytest.mark.asyncio
    async def test_call_tool_not_connected(self):
        """Test calling tool when server not connected raises error."""
        manager = MCPServerManager()

        with pytest.raises(ValueError, match="not connected"):
            await manager.call_tool("server", "tool", {})

    def test_global_manager(self):
        """Test global manager singleton."""
        manager1 = get_mcp_manager()
        manager2 = get_mcp_manager()
        assert manager1 is manager2


class TestToolResult:
    """Tests for ToolResult dataclass."""

    def test_create_success_result(self):
        """Test creating a successful result."""
        result = ToolResult(
            tool_name="test",
            success=True,
            output={"data": "value"},
            execution_time=1.5,
        )

        assert result.success
        assert result.error is None
        assert result.output == {"data": "value"}

    def test_create_error_result(self):
        """Test creating an error result."""
        result = ToolResult(
            tool_name="test",
            success=False,
            output={},
            error="Something went wrong",
            execution_time=0.5,
        )

        assert not result.success
        assert result.error == "Something went wrong"


class TestMCPServers:
    """Tests for predefined MCP server configurations."""

    def test_all_servers_have_required_fields(self):
        """Test all predefined servers have required fields."""
        for name, config in MCP_SERVERS.items():
            assert config.name == name
            assert config.description
            assert config.repo_url
            assert config.server_type in MCPServerType

    def test_ghidra_config(self):
        """Test GhidraMCP configuration."""
        ghidra = MCP_SERVERS.get("ghidra")
        assert ghidra is not None
        assert "ghidra" in ghidra.requires
        assert ghidra.server_type == MCPServerType.PYTHON
        assert "LaurieWired" in ghidra.repo_url

    def test_metasploit_config(self):
        """Test MetasploitMCP configuration."""
        msf = MCP_SERVERS.get("metasploit")
        assert msf is not None
        assert "metasploit" in msf.requires
        assert "MSF_PASSWORD" in msf.env

    def test_pwndbg_config(self):
        """Test pwndbg-mcp configuration."""
        pwndbg = MCP_SERVERS.get("pwndbg")
        assert pwndbg is not None
        assert "linux" in pwndbg.platforms
        # pwndbg is Linux-only
        assert "win32" not in pwndbg.platforms

    def test_frida_config(self):
        """Test frida-mcp configuration."""
        frida = MCP_SERVERS.get("frida")
        assert frida is not None
        assert frida.server_type == MCPServerType.NODE
        assert "npx" in frida.command


class TestInstallResult:
    """Tests for InstallResult dataclass."""

    def test_success_result(self):
        """Test successful install result."""
        result = InstallResult(
            server_name="test",
            success=True,
            install_path=Path("/tmp/test"),
            message="Installed successfully",
        )

        assert result.success
        assert result.error is None

    def test_failure_result(self):
        """Test failed install result."""
        result = InstallResult(
            server_name="test",
            success=False,
            install_path=None,
            message="Installation failed",
            error="Git clone failed",
        )

        assert not result.success
        assert result.error == "Git clone failed"
