"""Base tool wrapper class."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ToolOutput:
    """Standard output format for tools."""

    success: bool
    data: dict[str, Any]
    error: str | None = None
    raw_output: str | None = None


class BaseTool(ABC):
    """Base class for security tool wrappers."""

    name: str
    description: str
    required_binary: str | None = None

    def __init__(self) -> None:
        """Initialize the tool."""
        self._available: bool | None = None

    def is_available(self) -> bool:
        """Check if the tool is available on the system.

        Returns:
            True if tool is available.
        """
        if self._available is not None:
            return self._available

        if self.required_binary is None:
            self._available = True
            return True

        import shutil

        self._available = shutil.which(self.required_binary) is not None
        return self._available

    @abstractmethod
    async def run(self, target: str, **kwargs: Any) -> ToolOutput:
        """Run the tool against a target.

        Args:
            target: Target path or identifier.
            **kwargs: Tool-specific arguments.

        Returns:
            ToolOutput with results.
        """
        pass

    async def _run_command(
        self,
        command: str | list[str],
        timeout: int = 300,
        cwd: str | None = None,
    ) -> tuple[int, str, str]:
        """Run a shell command.

        Args:
            command: Command to run.
            timeout: Timeout in seconds.
            cwd: Working directory.

        Returns:
            Tuple of (return_code, stdout, stderr).
        """
        import asyncio

        if isinstance(command, list):
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )
        else:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
            return proc.returncode or 0, stdout.decode(), stderr.decode()
        except asyncio.TimeoutError:
            proc.kill()
            return -1, "", f"Command timed out after {timeout} seconds"


class DockerTool(BaseTool):
    """Base class for tools that can run via Docker toolbox.

    Subclasses can run either locally (if installed) or via Docker.
    """

    # Docker toolbox tool name (e.g., "opengrep", "linguist")
    docker_tool_name: str | None = None
    # Prefer Docker over local installation
    prefer_docker: bool = True

    def __init__(self, use_docker: bool | None = None) -> None:
        """Initialize the Docker tool.

        Args:
            use_docker: Force Docker usage (True), local (False), or auto (None).
        """
        super().__init__()
        self._use_docker = use_docker
        self._docker_available: bool | None = None
        self._toolbox_manager = None

    @property
    def toolbox_manager(self):
        """Get the toolbox manager (lazy initialization)."""
        if self._toolbox_manager is None:
            from mrzero.core.docker.toolbox import ToolboxManager

            self._toolbox_manager = ToolboxManager()
        return self._toolbox_manager

    def is_docker_available(self) -> bool:
        """Check if Docker toolbox is available.

        Returns:
            True if Docker toolbox is available.
        """
        if self._docker_available is not None:
            return self._docker_available

        try:
            self._docker_available = (
                self.toolbox_manager.is_docker_available()
                and self.toolbox_manager.is_toolbox_available()
            )
        except Exception:
            self._docker_available = False

        return self._docker_available

    def should_use_docker(self) -> bool:
        """Determine whether to use Docker or local installation.

        Returns:
            True if should use Docker.
        """
        # Explicit override
        if self._use_docker is not None:
            return self._use_docker

        # Check if Docker tool name is set
        if not self.docker_tool_name:
            return False

        # Check if local is available
        local_available = super().is_available()
        docker_available = self.is_docker_available()

        if self.prefer_docker:
            # Prefer Docker if available
            return docker_available
        else:
            # Use local if available, fall back to Docker
            if local_available:
                return False
            return docker_available

    def is_available(self) -> bool:
        """Check if the tool is available (local or Docker).

        Returns:
            True if tool is available.
        """
        return super().is_available() or self.is_docker_available()

    def get_execution_method(self) -> str:
        """Get the execution method being used.

        Returns:
            "docker", "local", or "unavailable".
        """
        if self.should_use_docker():
            return "docker"
        elif super().is_available():
            return "local"
        else:
            return "unavailable"

    async def _run_docker_tool(
        self,
        args: list[str],
        target_path: str | Path,
        timeout: int = 300,
    ) -> tuple[int, str, str]:
        """Run tool via Docker toolbox.

        Args:
            args: Arguments to pass to the tool.
            target_path: Path to mount as /workspace.
            timeout: Timeout in seconds.

        Returns:
            Tuple of (return_code, stdout, stderr).
        """
        if not self.docker_tool_name:
            raise ValueError("docker_tool_name not set")

        result = await self.toolbox_manager.run_tool_async(
            tool=self.docker_tool_name,
            args=args,
            target_path=target_path,
            timeout=timeout,
        )

        return result.exit_code, result.output, result.error or ""
