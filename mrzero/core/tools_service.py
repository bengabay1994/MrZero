"""Unified Tools Service for MrZero agents.

This module provides a single interface for agents to execute tools across
different backends:
1. Docker toolbox (Opengrep, Linguist)
2. MCP servers (Ghidra, pwndbg, Metasploit, Frida, etc.)
3. Local tools (gitleaks, trivy, slither)

The LLM decides WHAT tools to run - this service handles HOW to run them.
"""

import asyncio
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from mrzero.core.config import get_config


class ToolBackend(Enum):
    """Backend type for tool execution."""

    DOCKER = "docker"  # Docker toolbox container
    MCP = "mcp"  # External MCP server
    LOCAL = "local"  # Local binary/subprocess
    HYBRID = "hybrid"  # Prefer Docker, fallback to local


class ToolCategory(Enum):
    """Categories of security tools."""

    SAST = "sast"  # Static Application Security Testing
    SECRET_DETECTION = "secret_detection"  # Secret/credential scanning
    DEPENDENCY = "dependency"  # Dependency vulnerability scanning
    BINARY_ANALYSIS = "binary_analysis"  # Reverse engineering
    DEBUGGING = "debugging"  # Debuggers (GDB, WinDbg)
    EXPLOITATION = "exploitation"  # Exploitation frameworks
    DYNAMIC_ANALYSIS = "dynamic_analysis"  # Runtime instrumentation
    LANGUAGE_DETECTION = "language_detection"  # Language/framework detection
    SMART_CONTRACT = "smart_contract"  # Solidity/Vyper analysis


@dataclass
class ToolSpec:
    """Specification for a tool available in the service."""

    name: str
    description: str
    category: ToolCategory
    backend: ToolBackend
    available: bool = False
    version: str | None = None
    # For MCP tools
    mcp_server: str | None = None
    # For Docker tools
    docker_image: str | None = None
    # For local tools
    binary_name: str | None = None


@dataclass
class ToolExecutionResult:
    """Result of a tool execution."""

    tool: str
    backend: ToolBackend
    success: bool
    output: Any
    error: str | None = None
    exit_code: int = 0
    execution_time: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tool": self.tool,
            "backend": self.backend.value,
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "exit_code": self.exit_code,
            "execution_time": self.execution_time,
            "metadata": self.metadata,
        }


class ToolsService:
    """Unified service for executing security tools.

    This service provides a single interface for agents to run tools,
    abstracting away the complexity of different backends (Docker, MCP, local).

    Example usage:
        service = ToolsService()
        await service.initialize()

        # Run SAST scan
        result = await service.run_sast("opengrep", target_path)

        # Run binary analysis via MCP
        result = await service.run_binary_analysis("ghidra", binary_path)

        # Get all available tools
        tools = service.get_available_tools()
    """

    def __init__(self) -> None:
        """Initialize the tools service."""
        self._config = get_config()
        self._initialized = False

        # Tool backends
        self._docker_toolbox = None
        self._mcp_manager = None
        self._sast_runner = None

        # Tool registry
        self._tools: dict[str, ToolSpec] = {}

        # Execution callbacks for progress reporting
        self._progress_callback: Callable[[str, str], None] | None = None

    async def initialize(self) -> None:
        """Initialize all tool backends.

        This should be called before using the service.
        """
        if self._initialized:
            return

        # Initialize Docker toolbox
        await self._init_docker_toolbox()

        # Initialize MCP manager
        await self._init_mcp_manager()

        # Register all known tools
        self._register_tools()

        self._initialized = True

    async def _init_docker_toolbox(self) -> None:
        """Initialize Docker toolbox if available."""
        try:
            from mrzero.core.docker.toolbox import ToolboxManager

            self._docker_toolbox = ToolboxManager()

            # Check if Docker is available
            if not self._docker_toolbox.is_docker_available():
                self._docker_toolbox = None
        except ImportError:
            self._docker_toolbox = None
        except Exception:
            self._docker_toolbox = None

    async def _init_mcp_manager(self) -> None:
        """Initialize MCP server manager."""
        try:
            from mrzero.core.mcp.client import get_mcp_manager

            self._mcp_manager = get_mcp_manager()
        except ImportError:
            self._mcp_manager = None
        except Exception:
            self._mcp_manager = None

    def _register_tools(self) -> None:
        """Register all known tools with their specs."""
        # SAST Tools - Docker preferred, local fallback
        self._register_tool(
            ToolSpec(
                name="opengrep",
                description="SAST scanner (Semgrep-compatible) for vulnerability detection",
                category=ToolCategory.SAST,
                backend=ToolBackend.HYBRID,
                docker_image="ghcr.io/bengabay94/mrzero-toolbox:latest",
                binary_name="opengrep",
            )
        )

        # Secret Detection - Local only
        self._register_tool(
            ToolSpec(
                name="gitleaks",
                description="Secret and credential scanner",
                category=ToolCategory.SECRET_DETECTION,
                backend=ToolBackend.LOCAL,
                binary_name="gitleaks",
            )
        )

        # Dependency Scanning - Local only
        self._register_tool(
            ToolSpec(
                name="trivy",
                description="Vulnerability scanner for dependencies and containers",
                category=ToolCategory.DEPENDENCY,
                backend=ToolBackend.LOCAL,
                binary_name="trivy",
            )
        )

        # Language Detection - Docker preferred
        self._register_tool(
            ToolSpec(
                name="linguist",
                description="GitHub Linguist for language and framework detection",
                category=ToolCategory.LANGUAGE_DETECTION,
                backend=ToolBackend.HYBRID,
                docker_image="ghcr.io/bengabay94/mrzero-toolbox:latest",
                binary_name="linguist",
            )
        )

        # Smart Contract Tools - Local only
        self._register_tool(
            ToolSpec(
                name="slither",
                description="Solidity static analysis framework",
                category=ToolCategory.SMART_CONTRACT,
                backend=ToolBackend.LOCAL,
                binary_name="slither",
            )
        )

        self._register_tool(
            ToolSpec(
                name="mythril",
                description="Security analysis tool for EVM bytecode",
                category=ToolCategory.SMART_CONTRACT,
                backend=ToolBackend.LOCAL,
                binary_name="myth",
            )
        )

        # Binary Analysis - MCP servers
        self._register_tool(
            ToolSpec(
                name="ghidra",
                description="Binary analysis and reverse engineering via MCP",
                category=ToolCategory.BINARY_ANALYSIS,
                backend=ToolBackend.MCP,
                mcp_server="ghidra",
            )
        )

        self._register_tool(
            ToolSpec(
                name="ida-pro",
                description="Disassembler and debugger via MCP",
                category=ToolCategory.BINARY_ANALYSIS,
                backend=ToolBackend.MCP,
                mcp_server="ida-pro",
            )
        )

        self._register_tool(
            ToolSpec(
                name="binary-ninja",
                description="Binary analysis platform via MCP",
                category=ToolCategory.BINARY_ANALYSIS,
                backend=ToolBackend.MCP,
                mcp_server="binary-ninja",
            )
        )

        # Debugging - MCP servers
        self._register_tool(
            ToolSpec(
                name="pwndbg",
                description="GDB with pwndbg for exploit development via MCP",
                category=ToolCategory.DEBUGGING,
                backend=ToolBackend.MCP,
                mcp_server="pwndbg",
            )
        )

        self._register_tool(
            ToolSpec(
                name="windbg",
                description="Windows debugger via MCP",
                category=ToolCategory.DEBUGGING,
                backend=ToolBackend.MCP,
                mcp_server="windbg",
            )
        )

        # Exploitation - MCP servers
        self._register_tool(
            ToolSpec(
                name="metasploit",
                description="Penetration testing framework via MCP",
                category=ToolCategory.EXPLOITATION,
                backend=ToolBackend.MCP,
                mcp_server="metasploit",
            )
        )

        # Dynamic Analysis - MCP servers
        self._register_tool(
            ToolSpec(
                name="frida",
                description="Dynamic instrumentation toolkit via MCP",
                category=ToolCategory.DYNAMIC_ANALYSIS,
                backend=ToolBackend.MCP,
                mcp_server="frida",
            )
        )

        # Update availability for all tools
        self._update_tool_availability()

    def _register_tool(self, spec: ToolSpec) -> None:
        """Register a tool specification."""
        self._tools[spec.name] = spec

    def _update_tool_availability(self) -> None:
        """Update availability status for all tools."""
        import shutil

        for name, spec in self._tools.items():
            available = False

            if spec.backend == ToolBackend.DOCKER:
                # Docker-only tools require toolbox
                available = (
                    self._docker_toolbox is not None and self._docker_toolbox.is_toolbox_available()
                )

            elif spec.backend == ToolBackend.LOCAL:
                # Local tools require binary in PATH
                if spec.binary_name:
                    available = shutil.which(spec.binary_name) is not None

            elif spec.backend == ToolBackend.HYBRID:
                # Hybrid tools: prefer Docker, fallback to local
                docker_available = (
                    self._docker_toolbox is not None and self._docker_toolbox.is_toolbox_available()
                )
                local_available = (
                    spec.binary_name is not None and shutil.which(spec.binary_name) is not None
                )
                available = docker_available or local_available

            elif spec.backend == ToolBackend.MCP:
                # MCP tools: check if server is registered (not necessarily connected)
                if spec.mcp_server:
                    try:
                        from mrzero.core.mcp.registry import get_mcp_registry

                        registry = get_mcp_registry()
                        available = registry.get_server(spec.mcp_server) is not None
                    except ImportError:
                        available = False

            spec.available = available

    # =========================================================================
    # Public API - Tool Queries
    # =========================================================================

    def get_available_tools(self) -> list[ToolSpec]:
        """Get list of all available tools.

        Returns:
            List of available tool specifications.
        """
        return [spec for spec in self._tools.values() if spec.available]

    def get_tools_by_category(self, category: ToolCategory) -> list[ToolSpec]:
        """Get tools in a specific category.

        Args:
            category: Tool category.

        Returns:
            List of tool specifications in the category.
        """
        return [
            spec for spec in self._tools.values() if spec.category == category and spec.available
        ]

    def get_tool(self, name: str) -> ToolSpec | None:
        """Get a specific tool by name.

        Args:
            name: Tool name.

        Returns:
            Tool specification or None if not found.
        """
        return self._tools.get(name)

    def is_tool_available(self, name: str) -> bool:
        """Check if a tool is available.

        Args:
            name: Tool name.

        Returns:
            True if tool is available.
        """
        spec = self._tools.get(name)
        return spec is not None and spec.available

    def get_status(self) -> dict[str, Any]:
        """Get overall tools service status.

        Returns:
            Status dictionary with backend and tool availability.
        """
        status = {
            "initialized": self._initialized,
            "backends": {
                "docker": {
                    "available": self._docker_toolbox is not None,
                    "toolbox_ready": (
                        self._docker_toolbox.is_toolbox_available()
                        if self._docker_toolbox
                        else False
                    ),
                },
                "mcp": {
                    "available": self._mcp_manager is not None,
                    "connected_servers": (
                        self._mcp_manager.list_connections() if self._mcp_manager else []
                    ),
                },
                "local": {
                    "available": True,  # Local always available
                },
            },
            "tools": {
                "total": len(self._tools),
                "available": len(self.get_available_tools()),
                "by_category": {},
            },
        }

        # Count tools by category
        for category in ToolCategory:
            tools_in_category = self.get_tools_by_category(category)
            if tools_in_category:
                status["tools"]["by_category"][category.value] = len(tools_in_category)

        return status

    # =========================================================================
    # Public API - Tool Execution
    # =========================================================================

    async def run_sast(
        self,
        tool: str,
        target_path: Path | str,
        config: str | None = None,
        timeout: int = 600,
    ) -> ToolExecutionResult:
        """Run a SAST tool.

        Args:
            tool: Tool name (e.g., "opengrep").
            target_path: Path to scan.
            config: Optional tool configuration.
            timeout: Timeout in seconds.

        Returns:
            Tool execution result.
        """
        target_path = Path(target_path)
        spec = self._tools.get(tool)

        if spec is None:
            return ToolExecutionResult(
                tool=tool,
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=f"Unknown tool: {tool}",
            )

        if not spec.available:
            return ToolExecutionResult(
                tool=tool,
                backend=spec.backend,
                success=False,
                output=None,
                error=f"Tool '{tool}' is not available",
            )

        # Route to appropriate backend
        if spec.backend == ToolBackend.HYBRID:
            return await self._run_hybrid_sast(spec, target_path, config, timeout)
        elif spec.backend == ToolBackend.DOCKER:
            return await self._run_docker_sast(spec, target_path, config, timeout)
        else:
            return await self._run_local_sast(spec, target_path, config, timeout)

    async def run_all_sast(
        self,
        target_path: Path | str,
        timeout: int = 600,
    ) -> list[ToolExecutionResult]:
        """Run all available SAST tools in parallel.

        Args:
            target_path: Path to scan.
            timeout: Timeout per tool.

        Returns:
            List of tool execution results.
        """
        target_path = Path(target_path)
        sast_tools = self.get_tools_by_category(ToolCategory.SAST)
        secret_tools = self.get_tools_by_category(ToolCategory.SECRET_DETECTION)
        dep_tools = self.get_tools_by_category(ToolCategory.DEPENDENCY)

        # Combine all scanning tools
        tools_to_run = sast_tools + secret_tools + dep_tools

        # Check for Solidity files - add smart contract tools
        if any(target_path.rglob("*.sol")):
            tools_to_run.extend(self.get_tools_by_category(ToolCategory.SMART_CONTRACT))

        if not tools_to_run:
            return []

        # Run all tools in parallel
        tasks = []
        for spec in tools_to_run:
            if spec.category == ToolCategory.SAST:
                tasks.append(self.run_sast(spec.name, target_path, timeout=timeout))
            elif spec.category == ToolCategory.SECRET_DETECTION:
                tasks.append(self.run_secret_scan(spec.name, target_path, timeout=timeout))
            elif spec.category == ToolCategory.DEPENDENCY:
                tasks.append(self.run_dependency_scan(spec.name, target_path, timeout=timeout))
            elif spec.category == ToolCategory.SMART_CONTRACT:
                tasks.append(self.run_smart_contract_scan(spec.name, target_path, timeout=timeout))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions
        return [r for r in results if isinstance(r, ToolExecutionResult)]

    async def run_secret_scan(
        self,
        tool: str,
        target_path: Path | str,
        timeout: int = 300,
    ) -> ToolExecutionResult:
        """Run a secret detection tool.

        Args:
            tool: Tool name (e.g., "gitleaks").
            target_path: Path to scan.
            timeout: Timeout in seconds.

        Returns:
            Tool execution result.
        """
        target_path = Path(target_path)
        spec = self._tools.get(tool)

        if spec is None or not spec.available:
            return ToolExecutionResult(
                tool=tool,
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=f"Tool '{tool}' is not available",
            )

        return await self._run_local_secret_scan(spec, target_path, timeout)

    async def run_dependency_scan(
        self,
        tool: str,
        target_path: Path | str,
        timeout: int = 600,
    ) -> ToolExecutionResult:
        """Run a dependency vulnerability scanner.

        Args:
            tool: Tool name (e.g., "trivy").
            target_path: Path to scan.
            timeout: Timeout in seconds.

        Returns:
            Tool execution result.
        """
        target_path = Path(target_path)
        spec = self._tools.get(tool)

        if spec is None or not spec.available:
            return ToolExecutionResult(
                tool=tool,
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=f"Tool '{tool}' is not available",
            )

        return await self._run_local_dependency_scan(spec, target_path, timeout)

    async def run_smart_contract_scan(
        self,
        tool: str,
        target_path: Path | str,
        timeout: int = 600,
    ) -> ToolExecutionResult:
        """Run a smart contract analysis tool.

        Args:
            tool: Tool name (e.g., "slither", "mythril").
            target_path: Path to scan.
            timeout: Timeout in seconds.

        Returns:
            Tool execution result.
        """
        target_path = Path(target_path)
        spec = self._tools.get(tool)

        if spec is None or not spec.available:
            return ToolExecutionResult(
                tool=tool,
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=f"Tool '{tool}' is not available",
            )

        return await self._run_local_smart_contract_scan(spec, target_path, timeout)

    async def run_binary_analysis(
        self,
        tool: str,
        binary_path: Path | str,
        operation: str = "analyze",
        **kwargs: Any,
    ) -> ToolExecutionResult:
        """Run a binary analysis tool via MCP.

        Args:
            tool: Tool name (e.g., "ghidra", "ida-pro").
            binary_path: Path to binary file.
            operation: Operation to perform.
            **kwargs: Tool-specific arguments.

        Returns:
            Tool execution result.
        """
        spec = self._tools.get(tool)

        if spec is None or not spec.available:
            return ToolExecutionResult(
                tool=tool,
                backend=ToolBackend.MCP,
                success=False,
                output=None,
                error=f"Tool '{tool}' is not available",
            )

        if spec.backend != ToolBackend.MCP:
            return ToolExecutionResult(
                tool=tool,
                backend=spec.backend,
                success=False,
                output=None,
                error=f"Tool '{tool}' does not support binary analysis",
            )

        return await self._run_mcp_tool(
            spec,
            operation,
            binary_path=str(binary_path),
            **kwargs,
        )

    async def run_debugger(
        self,
        tool: str,
        target: str,
        operation: str = "attach",
        **kwargs: Any,
    ) -> ToolExecutionResult:
        """Run a debugger tool via MCP.

        Args:
            tool: Tool name (e.g., "pwndbg", "windbg").
            target: Target to debug (process, binary path, etc.).
            operation: Debugger operation.
            **kwargs: Tool-specific arguments.

        Returns:
            Tool execution result.
        """
        spec = self._tools.get(tool)

        if spec is None or not spec.available:
            return ToolExecutionResult(
                tool=tool,
                backend=ToolBackend.MCP,
                success=False,
                output=None,
                error=f"Tool '{tool}' is not available",
            )

        return await self._run_mcp_tool(spec, operation, target=target, **kwargs)

    async def run_exploitation(
        self,
        tool: str,
        operation: str,
        **kwargs: Any,
    ) -> ToolExecutionResult:
        """Run an exploitation framework tool via MCP.

        Args:
            tool: Tool name (e.g., "metasploit").
            operation: Operation to perform.
            **kwargs: Tool-specific arguments.

        Returns:
            Tool execution result.
        """
        spec = self._tools.get(tool)

        if spec is None or not spec.available:
            return ToolExecutionResult(
                tool=tool,
                backend=ToolBackend.MCP,
                success=False,
                output=None,
                error=f"Tool '{tool}' is not available",
            )

        return await self._run_mcp_tool(spec, operation, **kwargs)

    async def run_language_detection(
        self,
        target_path: Path | str,
        timeout: int = 120,
    ) -> ToolExecutionResult:
        """Run language detection on a target.

        Args:
            target_path: Path to analyze.
            timeout: Timeout in seconds.

        Returns:
            Tool execution result with language breakdown.
        """
        target_path = Path(target_path)
        spec = self._tools.get("linguist")

        if spec is None or not spec.available:
            return ToolExecutionResult(
                tool="linguist",
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error="Linguist tool is not available",
            )

        # Prefer Docker if available
        if self._docker_toolbox and self._docker_toolbox.is_toolbox_available():
            return await self._run_docker_linguist(target_path, timeout)
        else:
            return await self._run_local_linguist(target_path, timeout)

    # =========================================================================
    # Private - Backend Execution Methods
    # =========================================================================

    async def _run_hybrid_sast(
        self,
        spec: ToolSpec,
        target_path: Path,
        config: str | None,
        timeout: int,
    ) -> ToolExecutionResult:
        """Run SAST tool with hybrid backend (Docker preferred, local fallback)."""
        # Try Docker first
        if self._docker_toolbox and self._docker_toolbox.is_toolbox_available():
            return await self._run_docker_sast(spec, target_path, config, timeout)

        # Fallback to local
        return await self._run_local_sast(spec, target_path, config, timeout)

    async def _run_docker_sast(
        self,
        spec: ToolSpec,
        target_path: Path,
        config: str | None,
        timeout: int,
    ) -> ToolExecutionResult:
        """Run SAST tool via Docker toolbox."""
        import time

        start_time = time.time()

        if not self._docker_toolbox:
            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.DOCKER,
                success=False,
                output=None,
                error="Docker toolbox not available",
            )

        try:
            if spec.name == "opengrep":
                result = await self._docker_toolbox.run_opengrep_async(
                    target_path=target_path,
                    config=config or "auto",
                    output_format="json",
                    timeout=timeout,
                )

                return ToolExecutionResult(
                    tool=spec.name,
                    backend=ToolBackend.DOCKER,
                    success=result.success,
                    output=self._parse_opengrep_output(result.output),
                    error=result.error,
                    exit_code=result.exit_code,
                    execution_time=time.time() - start_time,
                )

            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.DOCKER,
                success=False,
                output=None,
                error=f"Docker execution not implemented for {spec.name}",
            )

        except Exception as e:
            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.DOCKER,
                success=False,
                output=None,
                error=str(e),
                execution_time=time.time() - start_time,
            )

    async def _run_local_sast(
        self,
        spec: ToolSpec,
        target_path: Path,
        config: str | None,
        timeout: int,
    ) -> ToolExecutionResult:
        """Run SAST tool locally via subprocess."""
        import time

        start_time = time.time()

        if spec.name == "opengrep":
            cmd = [
                "opengrep",
                "scan",
                "--json",
                "--config",
                config or "auto",
                str(target_path),
            ]
        else:
            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=f"Local execution not implemented for {spec.name}",
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )

            output = self._parse_opengrep_output(stdout.decode()) if stdout else None

            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.LOCAL,
                success=proc.returncode == 0,
                output=output,
                error=stderr.decode() if stderr and proc.returncode != 0 else None,
                exit_code=proc.returncode or 0,
                execution_time=time.time() - start_time,
            )

        except asyncio.TimeoutError:
            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=f"Timeout after {timeout} seconds",
                execution_time=timeout,
            )
        except FileNotFoundError:
            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=f"Tool binary '{spec.binary_name}' not found",
                execution_time=time.time() - start_time,
            )
        except Exception as e:
            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=str(e),
                execution_time=time.time() - start_time,
            )

    async def _run_local_secret_scan(
        self,
        spec: ToolSpec,
        target_path: Path,
        timeout: int,
    ) -> ToolExecutionResult:
        """Run secret scanner locally."""
        import time

        start_time = time.time()

        if spec.name == "gitleaks":
            cmd = [
                "gitleaks",
                "detect",
                "--source",
                str(target_path),
                "--report-format",
                "json",
                "--report-path",
                "/dev/stdout",
                "--no-git",
            ]
        else:
            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=f"Secret scan not implemented for {spec.name}",
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )

            output = None
            if stdout:
                try:
                    output = json.loads(stdout.decode())
                except json.JSONDecodeError:
                    output = {"raw": stdout.decode()}

            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.LOCAL,
                success=True,  # gitleaks returns non-zero if secrets found
                output=output,
                error=None,
                exit_code=proc.returncode or 0,
                execution_time=time.time() - start_time,
            )

        except asyncio.TimeoutError:
            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=f"Timeout after {timeout} seconds",
                execution_time=timeout,
            )
        except Exception as e:
            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=str(e),
                execution_time=time.time() - start_time,
            )

    async def _run_local_dependency_scan(
        self,
        spec: ToolSpec,
        target_path: Path,
        timeout: int,
    ) -> ToolExecutionResult:
        """Run dependency scanner locally."""
        import time

        start_time = time.time()

        if spec.name == "trivy":
            cmd = [
                "trivy",
                "fs",
                "--format",
                "json",
                "--scanners",
                "vuln,secret,misconfig",
                str(target_path),
            ]
        else:
            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=f"Dependency scan not implemented for {spec.name}",
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )

            output = None
            if stdout:
                try:
                    output = json.loads(stdout.decode())
                except json.JSONDecodeError:
                    output = {"raw": stdout.decode()}

            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.LOCAL,
                success=proc.returncode == 0,
                output=output,
                error=stderr.decode() if stderr and proc.returncode != 0 else None,
                exit_code=proc.returncode or 0,
                execution_time=time.time() - start_time,
            )

        except asyncio.TimeoutError:
            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=f"Timeout after {timeout} seconds",
                execution_time=timeout,
            )
        except Exception as e:
            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=str(e),
                execution_time=time.time() - start_time,
            )

    async def _run_local_smart_contract_scan(
        self,
        spec: ToolSpec,
        target_path: Path,
        timeout: int,
    ) -> ToolExecutionResult:
        """Run smart contract scanner locally."""
        import time

        start_time = time.time()

        if spec.name == "slither":
            cmd = ["slither", str(target_path), "--json", "-"]
        elif spec.name == "mythril":
            # Mythril needs a specific contract file
            sol_files = list(target_path.rglob("*.sol"))
            if not sol_files:
                return ToolExecutionResult(
                    tool=spec.name,
                    backend=ToolBackend.LOCAL,
                    success=False,
                    output=None,
                    error="No Solidity files found",
                )
            cmd = ["myth", "analyze", str(sol_files[0]), "-o", "json"]
        else:
            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=f"Smart contract scan not implemented for {spec.name}",
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )

            output = None
            if stdout:
                try:
                    output = json.loads(stdout.decode())
                except json.JSONDecodeError:
                    output = {"raw": stdout.decode()}

            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.LOCAL,
                success=proc.returncode == 0,
                output=output,
                error=stderr.decode() if stderr and proc.returncode != 0 else None,
                exit_code=proc.returncode or 0,
                execution_time=time.time() - start_time,
            )

        except asyncio.TimeoutError:
            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=f"Timeout after {timeout} seconds",
                execution_time=timeout,
            )
        except Exception as e:
            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=str(e),
                execution_time=time.time() - start_time,
            )

    async def _run_docker_linguist(
        self,
        target_path: Path,
        timeout: int,
    ) -> ToolExecutionResult:
        """Run linguist via Docker toolbox."""
        import time

        start_time = time.time()

        if not self._docker_toolbox:
            return ToolExecutionResult(
                tool="linguist",
                backend=ToolBackend.DOCKER,
                success=False,
                output=None,
                error="Docker toolbox not available",
            )

        try:
            result = await self._docker_toolbox.run_linguist_async(
                target_path=target_path,
                breakdown=True,
                timeout=timeout,
            )

            return ToolExecutionResult(
                tool="linguist",
                backend=ToolBackend.DOCKER,
                success=result.success,
                output=self._parse_linguist_output(result.output),
                error=result.error,
                exit_code=result.exit_code,
                execution_time=time.time() - start_time,
            )

        except Exception as e:
            return ToolExecutionResult(
                tool="linguist",
                backend=ToolBackend.DOCKER,
                success=False,
                output=None,
                error=str(e),
                execution_time=time.time() - start_time,
            )

    async def _run_local_linguist(
        self,
        target_path: Path,
        timeout: int,
    ) -> ToolExecutionResult:
        """Run linguist locally."""
        import time

        start_time = time.time()

        cmd = ["linguist", str(target_path), "--breakdown"]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )

            return ToolExecutionResult(
                tool="linguist",
                backend=ToolBackend.LOCAL,
                success=proc.returncode == 0,
                output=self._parse_linguist_output(stdout.decode()) if stdout else None,
                error=stderr.decode() if stderr and proc.returncode != 0 else None,
                exit_code=proc.returncode or 0,
                execution_time=time.time() - start_time,
            )

        except asyncio.TimeoutError:
            return ToolExecutionResult(
                tool="linguist",
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=f"Timeout after {timeout} seconds",
                execution_time=timeout,
            )
        except Exception as e:
            return ToolExecutionResult(
                tool="linguist",
                backend=ToolBackend.LOCAL,
                success=False,
                output=None,
                error=str(e),
                execution_time=time.time() - start_time,
            )

    async def _run_mcp_tool(
        self,
        spec: ToolSpec,
        operation: str,
        **kwargs: Any,
    ) -> ToolExecutionResult:
        """Run a tool via MCP server."""
        import time

        start_time = time.time()

        if not self._mcp_manager:
            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.MCP,
                success=False,
                output=None,
                error="MCP manager not available",
            )

        if not spec.mcp_server:
            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.MCP,
                success=False,
                output=None,
                error=f"No MCP server configured for {spec.name}",
            )

        try:
            # Check if server is connected
            connection = self._mcp_manager.get_connection(spec.mcp_server)
            if connection is None or not connection.connected:
                return ToolExecutionResult(
                    tool=spec.name,
                    backend=ToolBackend.MCP,
                    success=False,
                    output=None,
                    error=f"MCP server '{spec.mcp_server}' not connected. Run 'mrzero mcp install {spec.mcp_server}' first.",
                )

            # Build tool arguments
            arguments = {"operation": operation, **kwargs}

            # Call the tool
            result = await connection.call_tool(spec.name, arguments)

            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.MCP,
                success=True,
                output=result,
                error=None,
                execution_time=time.time() - start_time,
            )

        except Exception as e:
            return ToolExecutionResult(
                tool=spec.name,
                backend=ToolBackend.MCP,
                success=False,
                output=None,
                error=str(e),
                execution_time=time.time() - start_time,
            )

    # =========================================================================
    # Private - Output Parsing
    # =========================================================================

    def _parse_opengrep_output(self, output: str) -> dict[str, Any] | None:
        """Parse Opengrep JSON output."""
        if not output:
            return None

        try:
            data = json.loads(output)
            return {
                "results": data.get("results", []),
                "errors": data.get("errors", []),
                "paths": data.get("paths", {}),
            }
        except json.JSONDecodeError:
            return {"raw": output}

    def _parse_linguist_output(self, output: str) -> dict[str, Any] | None:
        """Parse linguist output."""
        if not output:
            return None

        # Linguist outputs in a specific format:
        # 50.00% Python
        # 30.00% JavaScript
        # etc.
        languages = {}
        for line in output.strip().split("\n"):
            line = line.strip()
            if "%" in line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        percentage = float(parts[0].replace("%", ""))
                        language = " ".join(parts[1:])
                        languages[language] = percentage
                    except ValueError:
                        continue

        return {"languages": languages, "raw": output}


# =============================================================================
# Global Instance
# =============================================================================

_tools_service: ToolsService | None = None


def get_tools_service() -> ToolsService:
    """Get the global tools service instance.

    Returns:
        ToolsService instance.
    """
    global _tools_service
    if _tools_service is None:
        _tools_service = ToolsService()
    return _tools_service


async def get_initialized_tools_service() -> ToolsService:
    """Get an initialized tools service.

    Returns:
        Initialized ToolsService instance.
    """
    service = get_tools_service()
    await service.initialize()
    return service
