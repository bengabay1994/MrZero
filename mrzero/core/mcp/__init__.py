"""MCP module - Model Context Protocol client implementation."""

from mrzero.core.mcp.client import (
    MCPClient,
    MCPServerConnection,
    MCPServerManager,
    MCPTool,
    CLITool,
    ToolResult,
    get_mcp_client,
    get_mcp_manager,
)
from mrzero.core.mcp.registry import (
    MCPServerConfig,
    MCPServerType,
    MCPTransport,
    MCPServerRegistry,
    get_mcp_registry,
    MCP_SERVERS,
)
from mrzero.core.mcp.installer import (
    MCPInstaller,
    InstallResult,
    get_mcp_installer,
)

__all__ = [
    # Client
    "MCPClient",
    "MCPServerConnection",
    "MCPServerManager",
    "MCPTool",
    "CLITool",
    "ToolResult",
    "get_mcp_client",
    "get_mcp_manager",
    # Registry
    "MCPServerConfig",
    "MCPServerType",
    "MCPTransport",
    "MCPServerRegistry",
    "get_mcp_registry",
    "MCP_SERVERS",
    # Installer
    "MCPInstaller",
    "InstallResult",
    "get_mcp_installer",
]
