"""MCP Server registry and configuration."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class MCPServerType(Enum):
    """Type of MCP server based on installation method."""

    PYTHON = "python"  # Python-based, install via uv
    NODE = "node"  # Node.js-based, install via npx
    BINARY = "binary"  # Pre-built binary
    MANUAL = "manual"  # Requires manual setup


class MCPTransport(Enum):
    """MCP transport method."""

    STDIO = "stdio"  # Standard input/output (default)
    SSE = "sse"  # Server-Sent Events over HTTP


@dataclass
class MCPServerConfig:
    """Configuration for an MCP server."""

    # Basic info
    name: str
    description: str
    repo_url: str

    # Installation
    server_type: MCPServerType
    install_command: list[str] | None = (
        None  # Command to install (e.g., ["uv", "pip", "install", "..."])
    )

    # Runtime
    command: list[str] = field(default_factory=list)  # Command to start server
    env: dict[str, str] = field(default_factory=dict)  # Environment variables
    transport: MCPTransport = MCPTransport.STDIO
    default_args: list[str] = field(default_factory=list)  # Default arguments

    # Requirements
    requires: list[str] = field(
        default_factory=list
    )  # External dependencies (e.g., ["ghidra", "metasploit"])
    platforms: list[str] = field(default_factory=lambda: ["linux", "darwin", "win32"])

    # Optional
    docs_url: str | None = None
    version: str | None = None

    def get_start_command(self, **kwargs: Any) -> list[str]:
        """Get the command to start the server.

        Args:
            **kwargs: Override default environment variables.

        Returns:
            Command list to execute.
        """
        cmd = self.command.copy()
        cmd.extend(self.default_args)
        return cmd

    def get_env(self, **overrides: str) -> dict[str, str]:
        """Get environment variables for the server.

        Args:
            **overrides: Override default env vars.

        Returns:
            Environment variables dict.
        """
        env = self.env.copy()
        env.update(overrides)
        return env


# =============================================================================
# MCP Server Configurations
# =============================================================================

GHIDRA_MCP = MCPServerConfig(
    name="ghidra",
    description="MCP Server for Ghidra - Binary analysis and reverse engineering",
    repo_url="https://github.com/LaurieWired/GhidraMCP",
    server_type=MCPServerType.PYTHON,
    install_command=["uv", "pip", "install", "mcp", "requests"],
    command=["python", "bridge_mcp_ghidra.py"],
    default_args=["--ghidra-server", "http://127.0.0.1:8080/"],
    requires=["ghidra"],  # Requires Ghidra to be installed with GhidraMCP plugin
    docs_url="https://github.com/LaurieWired/GhidraMCP#readme",
)

PWNDBG_MCP = MCPServerConfig(
    name="pwndbg",
    description="MCP Server for pwndbg/GDB - Debugging and exploit development",
    repo_url="https://github.com/bengabay1994/pwndbg-mcp",
    server_type=MCPServerType.PYTHON,
    install_command=["uv", "pip", "install", "-e", "."],
    command=["python", "-m", "pwndbg_mcp"],
    requires=["gdb", "pwndbg"],
    platforms=["linux"],  # pwndbg is Linux-only
    docs_url="https://github.com/bengabay1994/pwndbg-mcp#readme",
)

METASPLOIT_MCP = MCPServerConfig(
    name="metasploit",
    description="MCP Server for Metasploit Framework - Exploitation and payload generation",
    repo_url="https://github.com/GH05TCREW/MetasploitMCP",
    server_type=MCPServerType.PYTHON,
    install_command=["uv", "pip", "install", "mcp", "pymetasploit3", "python-dotenv"],
    command=["python", "MetasploitMCP.py"],
    default_args=["--transport", "stdio"],
    env={
        "MSF_PASSWORD": "",  # User must set this
        "MSF_SERVER": "127.0.0.1",
        "MSF_PORT": "55553",
        "MSF_SSL": "false",
    },
    requires=["metasploit"],  # Requires msfrpcd running
    docs_url="https://github.com/GH05TCREW/MetasploitMCP#readme",
)

FRIDA_MCP = MCPServerConfig(
    name="frida",
    description="MCP Server for Frida - Dynamic instrumentation toolkit",
    repo_url="https://github.com/dnakov/frida-mcp",
    server_type=MCPServerType.NODE,
    install_command=["npx", "-y", "frida-mcp"],  # npx handles installation
    command=["npx", "-y", "frida-mcp"],
    requires=["frida"],  # Requires frida-tools
    docs_url="https://github.com/dnakov/frida-mcp#readme",
)

IDA_PRO_MCP = MCPServerConfig(
    name="ida-pro",
    description="MCP Server for IDA Pro - Disassembler and debugger",
    repo_url="https://github.com/mrexodia/ida-pro-mcp",
    server_type=MCPServerType.PYTHON,
    install_command=["uv", "pip", "install", "mcp"],
    command=["python", "ida_mcp_server.py"],
    requires=["ida-pro"],  # Requires IDA Pro license
    docs_url="https://github.com/mrexodia/ida-pro-mcp#readme",
)

BINARY_NINJA_MCP = MCPServerConfig(
    name="binary-ninja",
    description="MCP Server for Binary Ninja - Binary analysis platform",
    repo_url="https://github.com/fosdickio/binary_ninja_mcp",
    server_type=MCPServerType.PYTHON,
    install_command=["uv", "pip", "install", "mcp"],
    command=["python", "binja_mcp_server.py"],
    requires=["binary-ninja"],  # Requires Binary Ninja license
    docs_url="https://github.com/fosdickio/binary_ninja_mcp#readme",
)

WINDBG_MCP = MCPServerConfig(
    name="windbg",
    description="MCP Server for WinDbg - Windows debugger",
    repo_url="https://github.com/svnscha/mcp-windbg",
    server_type=MCPServerType.PYTHON,
    install_command=["uv", "pip", "install", "mcp"],
    command=["python", "windbg_mcp_server.py"],
    requires=["windbg"],
    platforms=["win32"],  # Windows only
    docs_url="https://github.com/svnscha/mcp-windbg#readme",
)


# =============================================================================
# Server Registry
# =============================================================================

# All available MCP servers
MCP_SERVERS: dict[str, MCPServerConfig] = {
    "ghidra": GHIDRA_MCP,
    "pwndbg": PWNDBG_MCP,
    "metasploit": METASPLOIT_MCP,
    "frida": FRIDA_MCP,
    "ida-pro": IDA_PRO_MCP,
    "binary-ninja": BINARY_NINJA_MCP,
    "windbg": WINDBG_MCP,
}

# Servers grouped by category
MCP_SERVERS_BY_CATEGORY: dict[str, list[str]] = {
    "reverse_engineering": ["ghidra", "ida-pro", "binary-ninja"],
    "debugging": ["pwndbg", "windbg"],
    "exploitation": ["metasploit"],
    "dynamic_analysis": ["frida"],
}


class MCPServerRegistry:
    """Registry for managing MCP server configurations."""

    def __init__(self) -> None:
        """Initialize the registry."""
        self._servers: dict[str, MCPServerConfig] = MCP_SERVERS.copy()
        self._installed: dict[str, Path] = {}  # server_name -> install_path

    def get_server(self, name: str) -> MCPServerConfig | None:
        """Get server configuration by name.

        Args:
            name: Server name.

        Returns:
            Server config or None if not found.
        """
        return self._servers.get(name)

    def list_servers(self) -> list[MCPServerConfig]:
        """List all registered servers.

        Returns:
            List of server configs.
        """
        return list(self._servers.values())

    def list_server_names(self) -> list[str]:
        """List all registered server names.

        Returns:
            List of server names.
        """
        return list(self._servers.keys())

    def get_servers_by_category(self, category: str) -> list[MCPServerConfig]:
        """Get servers in a category.

        Args:
            category: Category name.

        Returns:
            List of server configs in the category.
        """
        names = MCP_SERVERS_BY_CATEGORY.get(category, [])
        return [self._servers[name] for name in names if name in self._servers]

    def get_compatible_servers(self, platform: str | None = None) -> list[MCPServerConfig]:
        """Get servers compatible with the current platform.

        Args:
            platform: Platform to check (defaults to current).

        Returns:
            List of compatible server configs.
        """
        import sys

        if platform is None:
            platform = sys.platform

        return [server for server in self._servers.values() if platform in server.platforms]

    def register_server(self, config: MCPServerConfig) -> None:
        """Register a custom server configuration.

        Args:
            config: Server configuration to register.
        """
        self._servers[config.name] = config

    def mark_installed(self, name: str, path: Path) -> None:
        """Mark a server as installed.

        Args:
            name: Server name.
            path: Installation path.
        """
        self._installed[name] = path

    def is_installed(self, name: str) -> bool:
        """Check if a server is installed.

        Args:
            name: Server name.

        Returns:
            True if installed.
        """
        return name in self._installed

    def get_install_path(self, name: str) -> Path | None:
        """Get the installation path for a server.

        Args:
            name: Server name.

        Returns:
            Installation path or None.
        """
        return self._installed.get(name)


# Global registry instance
_registry: MCPServerRegistry | None = None


def get_mcp_registry() -> MCPServerRegistry:
    """Get the global MCP server registry.

    Returns:
        MCPServerRegistry instance.
    """
    global _registry
    if _registry is None:
        _registry = MCPServerRegistry()
    return _registry
