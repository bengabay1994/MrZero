"""MrZero Toolbox manager for Docker-based tools."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from mrzero.core.docker.client import ContainerResult, DockerClient
from mrzero.core.docker.exceptions import (
    ContainerError,
    DockerNotInstalledError,
    ImageNotFoundError,
)


# Default toolbox image
TOOLBOX_IMAGE = "ghcr.io/bengabay94/mrzero-toolbox:latest"

# Available tools in the toolbox
AVAILABLE_TOOLS = {
    "opengrep": {
        "description": "SAST scanner (Semgrep-compatible)",
        "version_cmd": ["opengrep", "--version"],
    },
    "linguist": {
        "description": "Language detection (GitHub Linguist)",
        "version_cmd": ["linguist", "--version"],
    },
}


@dataclass
class ToolResult:
    """Result of a tool execution."""

    tool: str
    success: bool
    output: str
    error: str | None
    exit_code: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tool": self.tool,
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "exit_code": self.exit_code,
        }


class ToolboxManager:
    """Manages the MrZero toolbox Docker container.

    The toolbox contains SAST and code analysis tools that run inside
    a Docker container for consistency and isolation.
    """

    def __init__(self, image: str = TOOLBOX_IMAGE) -> None:
        """Initialize the toolbox manager.

        Args:
            image: Docker image name for the toolbox.
        """
        self.image = image
        self.client = DockerClient()

    def is_docker_available(self) -> bool:
        """Check if Docker is available.

        Returns:
            True if Docker is available and running.
        """
        return self.client.is_available()

    def is_toolbox_available(self) -> bool:
        """Check if the toolbox image is available locally.

        Returns:
            True if toolbox image exists.
        """
        try:
            return self.client.image_exists(self.image)
        except DockerNotInstalledError:
            return False

    def ensure_toolbox(self, progress_callback: Callable[[str], None] | None = None) -> bool:
        """Ensure the toolbox image is available.

        Downloads the image if not present.

        Args:
            progress_callback: Optional callback for progress updates.

        Returns:
            True if toolbox is available.

        Raises:
            DockerNotInstalledError: If Docker is not installed.
        """
        self.client.verify()

        if self.is_toolbox_available():
            return True

        return self.pull_toolbox(progress_callback)

    def pull_toolbox(self, progress_callback: Callable[[str], None] | None = None) -> bool:
        """Pull the toolbox image.

        Args:
            progress_callback: Optional callback for progress updates.

        Returns:
            True if pull succeeded.
        """
        return self.client.pull_image(self.image, progress_callback)

    def get_toolbox_info(self) -> dict[str, Any] | None:
        """Get information about the toolbox image.

        Returns:
            Image info dict or None if not found.
        """
        return self.client.get_image_info(self.image)

    def get_status(self) -> dict[str, Any]:
        """Get toolbox status.

        Returns:
            Status dict with docker/toolbox availability and info.
        """
        status = {
            "docker_available": False,
            "toolbox_available": False,
            "image": self.image,
            "tools": list(AVAILABLE_TOOLS.keys()),
            "image_info": None,
        }

        if not self.client.is_available():
            status["error"] = "Docker is not installed or not running"
            return status

        status["docker_available"] = True

        if not self.is_toolbox_available():
            status["error"] = f"Toolbox image not found. Run 'mrzero docker pull'"
            return status

        status["toolbox_available"] = True
        status["image_info"] = self.get_toolbox_info()

        return status

    def run_tool(
        self,
        tool: str,
        args: list[str],
        target_path: Path | str,
        timeout: int = 300,
        environment: dict[str, str] | None = None,
    ) -> ToolResult:
        """Run a tool from the toolbox.

        Args:
            tool: Tool name (e.g., "opengrep", "linguist").
            args: Arguments to pass to the tool.
            target_path: Path to mount as /workspace.
            timeout: Timeout in seconds.
            environment: Additional environment variables.

        Returns:
            ToolResult with output and status.

        Raises:
            DockerNotInstalledError: If Docker is not installed.
            ImageNotFoundError: If toolbox image is not found.
            ContainerError: If execution fails.
        """
        if tool not in AVAILABLE_TOOLS:
            return ToolResult(
                tool=tool,
                success=False,
                output="",
                error=f"Unknown tool: {tool}. Available: {list(AVAILABLE_TOOLS.keys())}",
                exit_code=1,
            )

        target_path = Path(target_path).resolve()
        if not target_path.exists():
            return ToolResult(
                tool=tool,
                success=False,
                output="",
                error=f"Target path does not exist: {target_path}",
                exit_code=1,
            )

        # Build command: [tool, ...args]
        command = [tool] + list(args)

        try:
            result = self.client.run_container(
                image=self.image,
                command=command,
                volumes={str(target_path): "/workspace"},
                workdir="/workspace",
                timeout=timeout,
                environment=environment,
            )

            return ToolResult(
                tool=tool,
                success=result.success,
                output=result.stdout,
                error=result.stderr if not result.success else None,
                exit_code=result.exit_code,
            )

        except (DockerNotInstalledError, ImageNotFoundError):
            raise
        except ContainerError as e:
            return ToolResult(
                tool=tool,
                success=False,
                output="",
                error=str(e),
                exit_code=e.exit_code or 1,
            )

    async def run_tool_async(
        self,
        tool: str,
        args: list[str],
        target_path: Path | str,
        timeout: int = 300,
        environment: dict[str, str] | None = None,
    ) -> ToolResult:
        """Run a tool from the toolbox asynchronously.

        Args:
            tool: Tool name (e.g., "opengrep", "linguist").
            args: Arguments to pass to the tool.
            target_path: Path to mount as /workspace.
            timeout: Timeout in seconds.
            environment: Additional environment variables.

        Returns:
            ToolResult with output and status.
        """
        if tool not in AVAILABLE_TOOLS:
            return ToolResult(
                tool=tool,
                success=False,
                output="",
                error=f"Unknown tool: {tool}. Available: {list(AVAILABLE_TOOLS.keys())}",
                exit_code=1,
            )

        target_path = Path(target_path).resolve()
        if not target_path.exists():
            return ToolResult(
                tool=tool,
                success=False,
                output="",
                error=f"Target path does not exist: {target_path}",
                exit_code=1,
            )

        command = [tool] + list(args)

        try:
            result = await self.client.run_container_async(
                image=self.image,
                command=command,
                volumes={str(target_path): "/workspace"},
                workdir="/workspace",
                timeout=timeout,
                environment=environment,
            )

            return ToolResult(
                tool=tool,
                success=result.success,
                output=result.stdout,
                error=result.stderr if not result.success else None,
                exit_code=result.exit_code,
            )

        except (DockerNotInstalledError, ImageNotFoundError):
            raise
        except ContainerError as e:
            return ToolResult(
                tool=tool,
                success=False,
                output="",
                error=str(e),
                exit_code=e.exit_code or 1,
            )

    def run_opengrep(
        self,
        target_path: Path | str,
        config: str = "auto",
        output_format: str = "json",
        timeout: int = 600,
    ) -> ToolResult:
        """Run Opengrep SAST scanner.

        Args:
            target_path: Path to scan.
            config: Config to use (e.g., "auto", "p/security-audit").
            output_format: Output format ("json", "text", "sarif").
            timeout: Timeout in seconds.

        Returns:
            ToolResult with scan results.
        """
        args = [
            "scan",
            "--config",
            config,
            "--json" if output_format == "json" else f"--{output_format}",
            "/workspace",
        ]

        return self.run_tool("opengrep", args, target_path, timeout)

    async def run_opengrep_async(
        self,
        target_path: Path | str,
        config: str = "auto",
        output_format: str = "json",
        timeout: int = 600,
    ) -> ToolResult:
        """Run Opengrep SAST scanner asynchronously.

        Args:
            target_path: Path to scan.
            config: Config to use.
            output_format: Output format.
            timeout: Timeout in seconds.

        Returns:
            ToolResult with scan results.
        """
        args = [
            "scan",
            "--config",
            config,
            "--json" if output_format == "json" else f"--{output_format}",
            "/workspace",
        ]

        return await self.run_tool_async("opengrep", args, target_path, timeout)

    def run_linguist(
        self,
        target_path: Path | str,
        breakdown: bool = True,
        timeout: int = 120,
    ) -> ToolResult:
        """Run GitHub Linguist for language detection.

        Args:
            target_path: Path to analyze.
            breakdown: Include file-by-file breakdown.
            timeout: Timeout in seconds.

        Returns:
            ToolResult with language detection results.
        """
        args = ["/workspace"]
        if breakdown:
            args.append("--breakdown")

        return self.run_tool("linguist", args, target_path, timeout)

    async def run_linguist_async(
        self,
        target_path: Path | str,
        breakdown: bool = True,
        timeout: int = 120,
    ) -> ToolResult:
        """Run GitHub Linguist for language detection asynchronously.

        Args:
            target_path: Path to analyze.
            breakdown: Include file-by-file breakdown.
            timeout: Timeout in seconds.

        Returns:
            ToolResult with language detection results.
        """
        args = ["/workspace"]
        if breakdown:
            args.append("--breakdown")

        return await self.run_tool_async("linguist", args, target_path, timeout)

    def get_available_tools(self) -> dict[str, dict[str, Any]]:
        """Get list of available tools in the toolbox.

        Returns:
            Dict of tool name to tool info.
        """
        return AVAILABLE_TOOLS.copy()
