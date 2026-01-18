"""MCP (Model Context Protocol) client for tool communication."""

import asyncio
import json
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel


@dataclass
class ToolResult:
    """Result from a tool execution."""

    tool_name: str
    success: bool
    output: dict[str, Any]
    error: str | None = None
    execution_time: float = 0.0


class MCPTool(ABC):
    """Abstract base class for MCP tools."""

    name: str
    description: str

    @abstractmethod
    async def execute(self, **kwargs: Any) -> ToolResult:
        """Execute the tool with given arguments.

        Args:
            **kwargs: Tool-specific arguments.

        Returns:
            ToolResult with execution outcome.
        """
        pass

    def get_schema(self) -> dict[str, Any]:
        """Get the tool's JSON schema for LLM consumption.

        Returns:
            JSON schema describing the tool's parameters.
        """
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self._get_parameters_schema(),
        }

    @abstractmethod
    def _get_parameters_schema(self) -> dict[str, Any]:
        """Get the parameters JSON schema.

        Returns:
            JSON schema for parameters.
        """
        pass


class CLITool(MCPTool):
    """Base class for CLI-based tools."""

    def __init__(
        self,
        name: str,
        description: str,
        command: str,
        timeout: int = 300,
    ) -> None:
        """Initialize the CLI tool.

        Args:
            name: Tool name.
            description: Tool description.
            command: Base command to execute.
            timeout: Execution timeout in seconds.
        """
        self.name = name
        self.description = description
        self.command = command
        self.timeout = timeout

    async def execute(self, **kwargs: Any) -> ToolResult:
        """Execute the CLI tool.

        Args:
            **kwargs: Arguments to pass to the command.

        Returns:
            ToolResult with execution outcome.
        """
        import time

        start_time = time.time()
        cmd = self._build_command(**kwargs)

        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.timeout,
            )

            execution_time = time.time() - start_time

            if proc.returncode == 0:
                return ToolResult(
                    tool_name=self.name,
                    success=True,
                    output=self._parse_output(stdout.decode()),
                    execution_time=execution_time,
                )
            else:
                return ToolResult(
                    tool_name=self.name,
                    success=False,
                    output={},
                    error=stderr.decode() or f"Command failed with code {proc.returncode}",
                    execution_time=execution_time,
                )

        except asyncio.TimeoutError:
            return ToolResult(
                tool_name=self.name,
                success=False,
                output={},
                error=f"Command timed out after {self.timeout} seconds",
                execution_time=self.timeout,
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                success=False,
                output={},
                error=str(e),
                execution_time=time.time() - start_time,
            )

    @abstractmethod
    def _build_command(self, **kwargs: Any) -> str:
        """Build the command string with arguments.

        Args:
            **kwargs: Arguments for the command.

        Returns:
            Full command string.
        """
        pass

    def _parse_output(self, output: str) -> dict[str, Any]:
        """Parse the command output.

        Args:
            output: Raw command output.

        Returns:
            Parsed output dictionary.
        """
        # Try to parse as JSON first
        try:
            return {"data": json.loads(output)}
        except json.JSONDecodeError:
            return {"raw": output}

    def _get_parameters_schema(self) -> dict[str, Any]:
        """Get default parameters schema."""
        return {
            "type": "object",
            "properties": {},
        }


class MCPClient:
    """Client for managing and executing MCP tools."""

    def __init__(self) -> None:
        """Initialize the MCP client."""
        self.tools: dict[str, MCPTool] = {}
        self._tool_cache: dict[str, ToolResult] = {}

    def register_tool(self, tool: MCPTool) -> None:
        """Register a tool with the client.

        Args:
            tool: Tool to register.
        """
        self.tools[tool.name] = tool

    def get_tool(self, name: str) -> MCPTool | None:
        """Get a tool by name.

        Args:
            name: Tool name.

        Returns:
            Tool instance or None if not found.
        """
        return self.tools.get(name)

    def list_tools(self) -> list[dict[str, Any]]:
        """List all registered tools.

        Returns:
            List of tool schemas.
        """
        return [tool.get_schema() for tool in self.tools.values()]

    async def execute(
        self,
        tool_name: str,
        cache_key: str | None = None,
        **kwargs: Any,
    ) -> ToolResult:
        """Execute a tool by name.

        Args:
            tool_name: Name of the tool to execute.
            cache_key: Optional cache key for deduplication.
            **kwargs: Arguments for the tool.

        Returns:
            ToolResult from execution.

        Raises:
            ValueError: If tool is not found.
        """
        tool = self.get_tool(tool_name)
        if tool is None:
            raise ValueError(f"Tool '{tool_name}' not found")

        # Check cache
        if cache_key and cache_key in self._tool_cache:
            return self._tool_cache[cache_key]

        # Execute tool
        result = await tool.execute(**kwargs)

        # Cache result if key provided
        if cache_key and result.success:
            self._tool_cache[cache_key] = result

        return result

    async def execute_batch(
        self,
        tool_calls: list[tuple[str, dict[str, Any]]],
        parallel: bool = True,
    ) -> list[ToolResult]:
        """Execute multiple tools, optionally in parallel.

        Args:
            tool_calls: List of (tool_name, kwargs) tuples.
            parallel: Whether to run in parallel.

        Returns:
            List of ToolResults.
        """
        if parallel:
            tasks = [self.execute(name, **kwargs) for name, kwargs in tool_calls]
            return await asyncio.gather(*tasks)
        else:
            results = []
            for name, kwargs in tool_calls:
                result = await self.execute(name, **kwargs)
                results.append(result)
            return results


class MCPServerConnection:
    """Connection to an external MCP server."""

    def __init__(
        self,
        name: str,
        command: str | list[str],
        env: dict[str, str] | None = None,
    ) -> None:
        """Initialize an MCP server connection.

        Args:
            name: Server name.
            command: Command to start the server.
            env: Environment variables.
        """
        self.name = name
        self.command = command if isinstance(command, list) else command.split()
        self.env = env
        self.process: subprocess.Popen | None = None
        self._connected = False

    async def connect(self) -> bool:
        """Start and connect to the MCP server.

        Returns:
            True if connection successful.
        """
        try:
            self.process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.env,
            )
            self._connected = True
            return True
        except Exception:
            return False

    async def disconnect(self) -> None:
        """Disconnect from the MCP server."""
        if self.process:
            self.process.terminate()
            self.process = None
        self._connected = False

    async def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Call a method on the MCP server.

        Args:
            method: Method name.
            params: Method parameters.

        Returns:
            Response from server.
        """
        if not self._connected or not self.process:
            raise RuntimeError("Not connected to MCP server")

        # JSON-RPC request
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }

        self.process.stdin.write(json.dumps(request).encode() + b"\n")
        self.process.stdin.flush()

        response_line = self.process.stdout.readline()
        response = json.loads(response_line.decode())

        if "error" in response:
            raise RuntimeError(response["error"])

        return response.get("result", {})

    @property
    def connected(self) -> bool:
        """Check if connected."""
        return self._connected


# Global MCP client instance
_mcp_client: MCPClient | None = None


def get_mcp_client() -> MCPClient:
    """Get the global MCP client.

    Returns:
        MCPClient instance.
    """
    global _mcp_client
    if _mcp_client is None:
        _mcp_client = MCPClient()
    return _mcp_client
