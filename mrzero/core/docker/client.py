"""Docker client wrapper for MrZero."""

import asyncio
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from mrzero.core.docker.exceptions import (
    ContainerError,
    DockerNotInstalledError,
    ImageNotFoundError,
)


@dataclass
class ContainerResult:
    """Result of a container execution."""

    exit_code: int
    stdout: str
    stderr: str
    success: bool

    @property
    def output(self) -> str:
        """Get combined output (stdout preferred, stderr if stdout empty)."""
        return self.stdout if self.stdout else self.stderr


class DockerClient:
    """Low-level Docker client using CLI commands."""

    def __init__(self) -> None:
        """Initialize the Docker client."""
        self._docker_path: str | None = None
        self._verified = False

    @property
    def docker_path(self) -> str:
        """Get path to Docker executable."""
        if self._docker_path is None:
            self._docker_path = shutil.which("docker")
            if self._docker_path is None:
                raise DockerNotInstalledError()
        return self._docker_path

    def is_available(self) -> bool:
        """Check if Docker is available and running.

        Returns:
            True if Docker is available and running.
        """
        try:
            result = subprocess.run(
                [self.docker_path, "info"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        except DockerNotInstalledError:
            return False

    def verify(self) -> None:
        """Verify Docker is available and running.

        Raises:
            DockerNotInstalledError: If Docker is not installed or not running.
        """
        if self._verified:
            return

        if not self.is_available():
            raise DockerNotInstalledError(
                "Docker is not running. Please start Docker and try again."
            )
        self._verified = True

    def image_exists(self, image: str) -> bool:
        """Check if a Docker image exists locally.

        Args:
            image: Image name with optional tag.

        Returns:
            True if image exists locally.
        """
        self.verify()
        result = subprocess.run(
            [self.docker_path, "image", "inspect", image],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0

    def pull_image(
        self,
        image: str,
        progress_callback: Callable[[str], None] | None = None,
    ) -> bool:
        """Pull a Docker image.

        Args:
            image: Image name with optional tag.
            progress_callback: Optional callback for progress updates.

        Returns:
            True if pull succeeded.
        """
        self.verify()

        process = subprocess.Popen(
            [self.docker_path, "pull", image],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        output_lines = []
        if process.stdout:
            for line in process.stdout:
                output_lines.append(line.strip())
                if progress_callback:
                    progress_callback(line.strip())

        process.wait()
        return process.returncode == 0

    def get_image_info(self, image: str) -> dict[str, Any] | None:
        """Get information about a Docker image.

        Args:
            image: Image name with optional tag.

        Returns:
            Image info dict or None if not found.
        """
        self.verify()
        result = subprocess.run(
            [self.docker_path, "image", "inspect", image],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return None

        try:
            data = json.loads(result.stdout)
            if data and len(data) > 0:
                return data[0]
        except json.JSONDecodeError:
            pass

        return None

    def run_container(
        self,
        image: str,
        command: list[str],
        volumes: dict[str, str] | None = None,
        environment: dict[str, str] | None = None,
        workdir: str | None = None,
        timeout: int = 300,
        remove: bool = True,
    ) -> ContainerResult:
        """Run a command in a Docker container.

        Args:
            image: Image name with optional tag.
            command: Command and arguments to run.
            volumes: Host path -> container path mappings.
            environment: Environment variables.
            workdir: Working directory inside container.
            timeout: Timeout in seconds.
            remove: Remove container after execution.

        Returns:
            ContainerResult with output and exit code.

        Raises:
            ImageNotFoundError: If image is not found.
            ContainerError: If container execution fails.
        """
        self.verify()

        if not self.image_exists(image):
            raise ImageNotFoundError(image)

        cmd = [self.docker_path, "run"]

        if remove:
            cmd.append("--rm")

        # Add volume mounts
        if volumes:
            for host_path, container_path in volumes.items():
                # Resolve to absolute path
                abs_host_path = str(Path(host_path).resolve())
                cmd.extend(["-v", f"{abs_host_path}:{container_path}"])

        # Add environment variables
        if environment:
            for key, value in environment.items():
                cmd.extend(["-e", f"{key}={value}"])

        # Set working directory
        if workdir:
            cmd.extend(["-w", workdir])

        # Add image and command
        cmd.append(image)
        cmd.extend(command)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            return ContainerResult(
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                success=result.returncode == 0,
            )

        except subprocess.TimeoutExpired as e:
            raise ContainerError(f"Container execution timed out after {timeout} seconds") from e
        except Exception as e:
            raise ContainerError(f"Container execution failed: {e}") from e

    async def run_container_async(
        self,
        image: str,
        command: list[str],
        volumes: dict[str, str] | None = None,
        environment: dict[str, str] | None = None,
        workdir: str | None = None,
        timeout: int = 300,
        remove: bool = True,
    ) -> ContainerResult:
        """Run a command in a Docker container asynchronously.

        Args:
            image: Image name with optional tag.
            command: Command and arguments to run.
            volumes: Host path -> container path mappings.
            environment: Environment variables.
            workdir: Working directory inside container.
            timeout: Timeout in seconds.
            remove: Remove container after execution.

        Returns:
            ContainerResult with output and exit code.
        """
        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.run_container(
                image=image,
                command=command,
                volumes=volumes,
                environment=environment,
                workdir=workdir,
                timeout=timeout,
                remove=remove,
            ),
        )

    def list_images(self, filter_pattern: str | None = None) -> list[dict[str, Any]]:
        """List Docker images.

        Args:
            filter_pattern: Optional filter pattern (e.g., "mrzero*").

        Returns:
            List of image info dicts.
        """
        self.verify()

        cmd = [self.docker_path, "images", "--format", "json"]
        if filter_pattern:
            cmd.extend(["--filter", f"reference={filter_pattern}"])

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            return []

        images = []
        for line in result.stdout.strip().split("\n"):
            if line:
                try:
                    images.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        return images

    def remove_image(self, image: str, force: bool = False) -> bool:
        """Remove a Docker image.

        Args:
            image: Image name with optional tag.
            force: Force removal.

        Returns:
            True if removal succeeded.
        """
        self.verify()

        cmd = [self.docker_path, "rmi"]
        if force:
            cmd.append("-f")
        cmd.append(image)

        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0
