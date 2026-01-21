"""MCP (Model Context Protocol) client for tool communication."""

import asyncio
import json
import os
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
    """Connection to an external MCP server via stdio JSON-RPC."""

    def __init__(
        self,
        name: str,
        command: str | list[str],
        env: dict[str, str] | None = None,
        cwd: str | Path | None = None,
    ) -> None:
        """Initialize an MCP server connection.

        Args:
            name: Server name.
            command: Command to start the server.
            env: Environment variables (merged with current env).
            cwd: Working directory for the server process.
        """
        self.name = name
        self.command = command if isinstance(command, list) else command.split()
        self.env = env
        self.cwd = Path(cwd) if cwd else None
        self.process: asyncio.subprocess.Process | None = None
        self._connected = False
        self._request_id = 0
        self._lock = asyncio.Lock()

    async def connect(self) -> bool:
        """Start and connect to the MCP server.

        Returns:
            True if connection successful.
        """
        try:
            # Build environment
            process_env = os.environ.copy()
            if self.env:
                process_env.update(self.env)

            # Start the server process
            self.process = await asyncio.create_subprocess_exec(
                *self.command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=process_env,
                cwd=self.cwd,
            )

            self._connected = True
            return True

        except Exception as e:
            self._connected = False
            return False

    async def disconnect(self) -> None:
        """Disconnect from the MCP server."""
        if self.process:
            try:
                self.process.terminate()
                await asyncio.wait_for(self.process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self.process.kill()
            except Exception:
                pass
            self.process = None
        self._connected = False

    async def call(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Call a method on the MCP server.

        Args:
            method: Method name.
            params: Method parameters.
            timeout: Request timeout in seconds.

        Returns:
            Response from server.

        Raises:
            RuntimeError: If not connected or call fails.
        """
        if not self._connected or not self.process:
            raise RuntimeError(f"Not connected to MCP server '{self.name}'")

        if self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("Process stdin/stdout not available")

        async with self._lock:
            self._request_id += 1
            request_id = self._request_id

            # JSON-RPC request
            request = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
            }
            if params:
                request["params"] = params

            try:
                # Send request
                request_data = json.dumps(request) + "\n"
                self.process.stdin.write(request_data.encode())
                await self.process.stdin.drain()

                # Read response
                response_line = await asyncio.wait_for(
                    self.process.stdout.readline(),
                    timeout=timeout,
                )

                if not response_line:
                    raise RuntimeError("Server closed connection")

                response = json.loads(response_line.decode())

                # Validate response
                if response.get("id") != request_id:
                    raise RuntimeError(f"Response ID mismatch: expected {request_id}")

                if "error" in response:
                    error = response["error"]
                    error_msg = error.get("message", str(error))
                    raise RuntimeError(f"MCP error: {error_msg}")

                return response.get("result", {})

            except asyncio.TimeoutError:
                raise RuntimeError(f"Request timed out after {timeout} seconds")
            except json.JSONDecodeError as e:
                raise RuntimeError(f"Invalid JSON response: {e}")

    async def list_tools(self) -> list[dict[str, Any]]:
        """List available tools on the server.

        Returns:
            List of tool schemas.
        """
        result = await self.call("tools/list")
        return result.get("tools", [])

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        """Call a tool on the MCP server.

        Args:
            tool_name: Name of the tool.
            arguments: Tool arguments.
            timeout: Request timeout in seconds.

        Returns:
            Tool execution result.
        """
        params: dict[str, Any] = {"name": tool_name}
        if arguments:
            params["arguments"] = arguments

        return await self.call("tools/call", params, timeout)

    @property
    def connected(self) -> bool:
        """Check if connected."""
        if not self._connected or not self.process:
            return False
        # Check if process is still running
        return self.process.returncode is None

    async def health_check(self) -> bool:
        """Check if the server is healthy.

        Returns:
            True if server responds to ping.
        """
        if not self.connected:
            return False

        try:
            # Try to list tools as a health check
            await asyncio.wait_for(self.list_tools(), timeout=5.0)
            return True
        except Exception:
            return False


class MCPServerManager:
    """Manages multiple MCP server connections."""

    def __init__(self) -> None:
        """Initialize the manager."""
        self._connections: dict[str, MCPServerConnection] = {}

    async def connect(
        self,
        name: str,
        command: str | list[str],
        env: dict[str, str] | None = None,
        cwd: str | Path | None = None,
    ) -> MCPServerConnection:
        """Connect to an MCP server.

        Args:
            name: Server name.
            command: Command to start the server.
            env: Environment variables.
            cwd: Working directory.

        Returns:
            MCPServerConnection instance.

        Raises:
            RuntimeError: If connection fails.
        """
        # Disconnect existing connection if any
        if name in self._connections:
            await self._connections[name].disconnect()

        connection = MCPServerConnection(name, command, env, cwd)
        success = await connection.connect()

        if not success:
            raise RuntimeError(f"Failed to connect to MCP server '{name}'")

        self._connections[name] = connection
        return connection

    def get_connection(self, name: str) -> MCPServerConnection | None:
        """Get an existing connection by name.

        Args:
            name: Server name.

        Returns:
            Connection or None if not found.
        """
        return self._connections.get(name)

    async def disconnect(self, name: str) -> None:
        """Disconnect from a server.

        Args:
            name: Server name.
        """
        if name in self._connections:
            await self._connections[name].disconnect()
            del self._connections[name]

    async def disconnect_all(self) -> None:
        """Disconnect from all servers."""
        for name in list(self._connections.keys()):
            await self.disconnect(name)

    def list_connections(self) -> list[str]:
        """List connected server names.

        Returns:
            List of server names.
        """
        return list(self._connections.keys())

    async def call_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        """Call a tool on a specific server.

        Args:
            server_name: Name of the server.
            tool_name: Name of the tool.
            arguments: Tool arguments.
            timeout: Request timeout.

        Returns:
            Tool execution result.

        Raises:
            ValueError: If server not connected.
        """
        connection = self.get_connection(server_name)
        if connection is None:
            raise ValueError(f"Server '{server_name}' not connected")

        return await connection.call_tool(tool_name, arguments, timeout)


# Global instances
_mcp_client: MCPClient | None = None
_mcp_manager: MCPServerManager | None = None


def get_mcp_client() -> MCPClient:
    """Get the global MCP client.

    Returns:
        MCPClient instance.
    """
    global _mcp_client
    if _mcp_client is None:
        _mcp_client = MCPClient()
    return _mcp_client


def get_mcp_manager() -> MCPServerManager:
    """Get the global MCP server manager.

    Returns:
        MCPServerManager instance.
    """
    global _mcp_manager
    if _mcp_manager is None:
        _mcp_manager = MCPServerManager()
    return _mcp_manager
