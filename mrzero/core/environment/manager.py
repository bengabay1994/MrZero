"""Environment Manager for MrZero.

This module provides unified lifecycle management for target environments:
- Docker containers (built from Dockerfile or docker-compose)
- Native processes (harnesses, scripts)
- Manages start/stop/health checks
"""

import asyncio
import json
import os
import signal
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from mrzero.core.docker.client import DockerClient, ContainerResult
from mrzero.core.docker.exceptions import DockerNotInstalledError


class EnvironmentType(str, Enum):
    """Type of environment."""

    DOCKER = "docker"
    DOCKER_COMPOSE = "docker-compose"
    NATIVE = "native"
    HARNESS = "harness"


class EnvironmentStatus(str, Enum):
    """Status of an environment."""

    NOT_CREATED = "not_created"
    BUILDING = "building"
    READY = "ready"
    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"


@dataclass
class BuildResult:
    """Result of a build operation."""

    success: bool
    env_type: EnvironmentType
    message: str = ""
    error: str = ""
    output: str = ""
    container_id: str | None = None
    image_name: str | None = None
    process_id: int | None = None
    port: int | None = None
    build_time_seconds: float = 0.0


@dataclass
class EnvironmentState:
    """State of a managed environment."""

    env_type: EnvironmentType
    status: EnvironmentStatus = EnvironmentStatus.NOT_CREATED
    target_path: str = ""
    container_id: str | None = None
    container_name: str | None = None
    image_name: str | None = None
    process_id: int | None = None
    port: int | None = None
    host: str = "localhost"
    harness_dir: str | None = None
    build_log: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class EnvironmentManager:
    """Manages environment lifecycle for vulnerability reproduction.

    This class handles:
    - Docker container creation and management
    - docker-compose stack management
    - Native process management (harnesses)
    - Health checking and port detection
    """

    MRZERO_CONTAINER_PREFIX = "mrzero-target"
    DEFAULT_TIMEOUT = 300  # 5 minutes for builds

    def __init__(self) -> None:
        """Initialize the environment manager."""
        self._docker: DockerClient | None = None
        self._active_environments: dict[str, EnvironmentState] = {}

    @property
    def docker(self) -> DockerClient:
        """Get Docker client, initializing if needed."""
        if self._docker is None:
            self._docker = DockerClient()
        return self._docker

    def docker_available(self) -> bool:
        """Check if Docker is available."""
        try:
            return self.docker.is_available()
        except DockerNotInstalledError:
            return False

    # =========================================================================
    # Docker Build Operations
    # =========================================================================

    async def build_docker_image(
        self,
        target_path: Path,
        dockerfile_path: Path | None = None,
        image_name: str | None = None,
        build_args: dict[str, str] | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> BuildResult:
        """Build a Docker image from a Dockerfile.

        Args:
            target_path: Path to the target codebase.
            dockerfile_path: Path to Dockerfile (relative to target_path).
            image_name: Custom image name (default: mrzero-target-<hash>).
            build_args: Build arguments to pass.
            timeout: Build timeout in seconds.

        Returns:
            BuildResult with build outcome.
        """
        import time

        start_time = time.time()

        if not self.docker_available():
            return BuildResult(
                success=False,
                env_type=EnvironmentType.DOCKER,
                error="Docker is not available",
            )

        # Determine Dockerfile location
        if dockerfile_path is None:
            # Look for common Dockerfile locations
            for name in ["Dockerfile", "dockerfile", "docker/Dockerfile"]:
                candidate = target_path / name
                if candidate.exists():
                    dockerfile_path = candidate
                    break
        else:
            dockerfile_path = target_path / dockerfile_path

        if dockerfile_path is None or not dockerfile_path.exists():
            return BuildResult(
                success=False,
                env_type=EnvironmentType.DOCKER,
                error="No Dockerfile found in target directory",
            )

        # Generate image name if not provided
        if image_name is None:
            target_hash = hex(hash(str(target_path)))[-8:]
            image_name = f"{self.MRZERO_CONTAINER_PREFIX}-{target_hash}"

        # Build command
        cmd = [
            self.docker.docker_path,
            "build",
            "-t",
            image_name,
            "-f",
            str(dockerfile_path),
        ]

        if build_args:
            for key, value in build_args.items():
                cmd.extend(["--build-arg", f"{key}={value}"])

        cmd.append(str(target_path))

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

            build_time = time.time() - start_time

            if proc.returncode == 0:
                return BuildResult(
                    success=True,
                    env_type=EnvironmentType.DOCKER,
                    message=f"Successfully built image {image_name}",
                    output=stdout.decode("utf-8", errors="ignore"),
                    image_name=image_name,
                    build_time_seconds=build_time,
                )
            else:
                return BuildResult(
                    success=False,
                    env_type=EnvironmentType.DOCKER,
                    error=stderr.decode("utf-8", errors="ignore"),
                    output=stdout.decode("utf-8", errors="ignore"),
                    build_time_seconds=build_time,
                )

        except asyncio.TimeoutError:
            return BuildResult(
                success=False,
                env_type=EnvironmentType.DOCKER,
                error=f"Build timed out after {timeout} seconds",
                build_time_seconds=timeout,
            )
        except Exception as e:
            return BuildResult(
                success=False,
                env_type=EnvironmentType.DOCKER,
                error=str(e),
            )

    async def run_docker_container(
        self,
        image_name: str,
        container_name: str | None = None,
        ports: dict[int, int] | None = None,
        volumes: dict[str, str] | None = None,
        environment: dict[str, str] | None = None,
        command: list[str] | None = None,
        detach: bool = True,
    ) -> BuildResult:
        """Run a Docker container from an image.

        Args:
            image_name: Docker image to run.
            container_name: Name for the container.
            ports: Port mappings (host -> container).
            volumes: Volume mappings (host -> container).
            environment: Environment variables.
            command: Command to run in container.
            detach: Run in background.

        Returns:
            BuildResult with container info.
        """
        if not self.docker_available():
            return BuildResult(
                success=False,
                env_type=EnvironmentType.DOCKER,
                error="Docker is not available",
            )

        if container_name is None:
            container_name = f"{self.MRZERO_CONTAINER_PREFIX}-{os.urandom(4).hex()}"

        cmd = [
            self.docker.docker_path,
            "run",
            "--name",
            container_name,
        ]

        if detach:
            cmd.append("-d")

        if ports:
            for host_port, container_port in ports.items():
                cmd.extend(["-p", f"{host_port}:{container_port}"])

        if volumes:
            for host_path, container_path in volumes.items():
                abs_path = str(Path(host_path).resolve())
                cmd.extend(["-v", f"{abs_path}:{container_path}"])

        if environment:
            for key, value in environment.items():
                cmd.extend(["-e", f"{key}={value}"])

        cmd.append(image_name)

        if command:
            cmd.extend(command)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=60,
            )

            if proc.returncode == 0:
                container_id = stdout.decode().strip()[:12]

                # Determine exposed port
                exposed_port = None
                if ports:
                    exposed_port = list(ports.keys())[0]

                # Store state
                state = EnvironmentState(
                    env_type=EnvironmentType.DOCKER,
                    status=EnvironmentStatus.RUNNING,
                    container_id=container_id,
                    container_name=container_name,
                    image_name=image_name,
                    port=exposed_port,
                )
                self._active_environments[container_name] = state

                return BuildResult(
                    success=True,
                    env_type=EnvironmentType.DOCKER,
                    message=f"Container {container_name} started",
                    container_id=container_id,
                    port=exposed_port,
                )
            else:
                return BuildResult(
                    success=False,
                    env_type=EnvironmentType.DOCKER,
                    error=stderr.decode("utf-8", errors="ignore"),
                )

        except asyncio.TimeoutError:
            return BuildResult(
                success=False,
                env_type=EnvironmentType.DOCKER,
                error="Container start timed out",
            )
        except Exception as e:
            return BuildResult(
                success=False,
                env_type=EnvironmentType.DOCKER,
                error=str(e),
            )

    async def stop_container(self, container_name: str, timeout: int = 10) -> bool:
        """Stop a running container.

        Args:
            container_name: Name of the container to stop.
            timeout: Timeout before force kill.

        Returns:
            True if stopped successfully.
        """
        if not self.docker_available():
            return False

        try:
            proc = await asyncio.create_subprocess_exec(
                self.docker.docker_path,
                "stop",
                "-t",
                str(timeout),
                container_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

            if container_name in self._active_environments:
                self._active_environments[container_name].status = EnvironmentStatus.STOPPED

            return proc.returncode == 0
        except Exception:
            return False

    async def remove_container(self, container_name: str, force: bool = True) -> bool:
        """Remove a container.

        Args:
            container_name: Name of the container.
            force: Force removal of running container.

        Returns:
            True if removed successfully.
        """
        if not self.docker_available():
            return False

        cmd = [self.docker.docker_path, "rm"]
        if force:
            cmd.append("-f")
        cmd.append(container_name)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

            if container_name in self._active_environments:
                del self._active_environments[container_name]

            return proc.returncode == 0
        except Exception:
            return False

    async def get_container_logs(
        self,
        container_name: str,
        tail: int = 100,
    ) -> str:
        """Get logs from a container.

        Args:
            container_name: Name of the container.
            tail: Number of lines to return.

        Returns:
            Container logs.
        """
        if not self.docker_available():
            return ""

        try:
            proc = await asyncio.create_subprocess_exec(
                self.docker.docker_path,
                "logs",
                "--tail",
                str(tail),
                container_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    async def container_health_check(self, container_name: str) -> bool:
        """Check if a container is running and healthy.

        Args:
            container_name: Name of the container.

        Returns:
            True if container is running.
        """
        if not self.docker_available():
            return False

        try:
            proc = await asyncio.create_subprocess_exec(
                self.docker.docker_path,
                "inspect",
                "--format",
                "{{.State.Running}}",
                container_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode().strip().lower() == "true"
        except Exception:
            return False

    # =========================================================================
    # docker-compose Operations
    # =========================================================================

    async def compose_up(
        self,
        target_path: Path,
        compose_file: str | None = None,
        build: bool = True,
        detach: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> BuildResult:
        """Start services with docker-compose.

        Args:
            target_path: Path to the project.
            compose_file: Compose file name (default: docker-compose.yml).
            build: Build images before starting.
            detach: Run in background.
            timeout: Timeout in seconds.

        Returns:
            BuildResult with compose outcome.
        """
        import time

        start_time = time.time()

        compose_cmd = shutil.which("docker-compose") or shutil.which("docker")
        if compose_cmd is None:
            return BuildResult(
                success=False,
                env_type=EnvironmentType.DOCKER_COMPOSE,
                error="docker-compose not found",
            )

        # Determine compose file
        if compose_file is None:
            for name in [
                "docker-compose.yml",
                "docker-compose.yaml",
                "compose.yml",
                "compose.yaml",
            ]:
                if (target_path / name).exists():
                    compose_file = name
                    break

        if compose_file is None or not (target_path / compose_file).exists():
            return BuildResult(
                success=False,
                env_type=EnvironmentType.DOCKER_COMPOSE,
                error="No docker-compose file found",
            )

        # Build command
        if "docker-compose" in compose_cmd:
            cmd = [compose_cmd, "-f", compose_file, "up"]
        else:
            cmd = [compose_cmd, "compose", "-f", compose_file, "up"]

        if build:
            cmd.append("--build")
        if detach:
            cmd.append("-d")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(target_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )

            build_time = time.time() - start_time

            if proc.returncode == 0:
                # Get container IDs
                container_id = await self._get_compose_container_id(target_path, compose_file)

                return BuildResult(
                    success=True,
                    env_type=EnvironmentType.DOCKER_COMPOSE,
                    message="docker-compose stack started",
                    output=stdout.decode("utf-8", errors="ignore"),
                    container_id=container_id,
                    build_time_seconds=build_time,
                )
            else:
                return BuildResult(
                    success=False,
                    env_type=EnvironmentType.DOCKER_COMPOSE,
                    error=stderr.decode("utf-8", errors="ignore"),
                    output=stdout.decode("utf-8", errors="ignore"),
                    build_time_seconds=build_time,
                )

        except asyncio.TimeoutError:
            return BuildResult(
                success=False,
                env_type=EnvironmentType.DOCKER_COMPOSE,
                error=f"docker-compose timed out after {timeout} seconds",
                build_time_seconds=timeout,
            )
        except Exception as e:
            return BuildResult(
                success=False,
                env_type=EnvironmentType.DOCKER_COMPOSE,
                error=str(e),
            )

    async def compose_down(self, target_path: Path, compose_file: str | None = None) -> bool:
        """Stop docker-compose services.

        Args:
            target_path: Path to the project.
            compose_file: Compose file name.

        Returns:
            True if stopped successfully.
        """
        compose_cmd = shutil.which("docker-compose") or shutil.which("docker")
        if compose_cmd is None:
            return False

        if compose_file is None:
            for name in ["docker-compose.yml", "docker-compose.yaml"]:
                if (target_path / name).exists():
                    compose_file = name
                    break

        if compose_file is None:
            return False

        if "docker-compose" in compose_cmd:
            cmd = [compose_cmd, "-f", compose_file, "down"]
        else:
            cmd = [compose_cmd, "compose", "-f", compose_file, "down"]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(target_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            return proc.returncode == 0
        except Exception:
            return False

    async def _get_compose_container_id(
        self,
        target_path: Path,
        compose_file: str,
    ) -> str | None:
        """Get container ID from docker-compose project."""
        compose_cmd = shutil.which("docker-compose") or shutil.which("docker")
        if compose_cmd is None:
            return None

        if "docker-compose" in compose_cmd:
            cmd = [compose_cmd, "-f", compose_file, "ps", "-q"]
        else:
            cmd = [compose_cmd, "compose", "-f", compose_file, "ps", "-q"]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(target_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            container_ids = stdout.decode().strip().split("\n")
            return container_ids[0][:12] if container_ids and container_ids[0] else None
        except Exception:
            return None

    # =========================================================================
    # Native/Harness Process Operations
    # =========================================================================

    async def run_harness(
        self,
        harness_path: Path,
        command: list[str] | None = None,
        environment: dict[str, str] | None = None,
        capture_output: bool = True,
        timeout: int = 60,
    ) -> BuildResult:
        """Run a harness script/program.

        Args:
            harness_path: Path to the harness directory or file.
            command: Command to run (default: python harness.py).
            environment: Environment variables.
            capture_output: Capture stdout/stderr.
            timeout: Execution timeout.

        Returns:
            BuildResult with execution outcome.
        """
        if not harness_path.exists():
            return BuildResult(
                success=False,
                env_type=EnvironmentType.HARNESS,
                error=f"Harness path does not exist: {harness_path}",
            )

        # Determine working directory
        if harness_path.is_file():
            work_dir = harness_path.parent
            harness_file = harness_path.name
        else:
            work_dir = harness_path
            harness_file = "harness.py"

        # Determine command
        if command is None:
            harness_full = work_dir / harness_file
            if harness_full.exists():
                # Detect language and build command
                if harness_file.endswith(".py"):
                    command = ["python3", harness_file]
                elif harness_file.endswith(".js"):
                    command = ["node", harness_file]
                elif harness_file.endswith(".sh"):
                    command = ["bash", harness_file]
                else:
                    command = [f"./{harness_file}"]
            else:
                return BuildResult(
                    success=False,
                    env_type=EnvironmentType.HARNESS,
                    error=f"Harness file not found: {harness_full}",
                )

        # Build environment
        env = os.environ.copy()
        if environment:
            env.update(environment)

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                cwd=str(work_dir),
                env=env,
                stdout=asyncio.subprocess.PIPE if capture_output else None,
                stderr=asyncio.subprocess.PIPE if capture_output else None,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )

            if proc.returncode == 0:
                return BuildResult(
                    success=True,
                    env_type=EnvironmentType.HARNESS,
                    message="Harness executed successfully",
                    output=stdout.decode("utf-8", errors="ignore") if stdout else "",
                    process_id=proc.pid,
                )
            else:
                return BuildResult(
                    success=False,
                    env_type=EnvironmentType.HARNESS,
                    error=stderr.decode("utf-8", errors="ignore") if stderr else "",
                    output=stdout.decode("utf-8", errors="ignore") if stdout else "",
                )

        except asyncio.TimeoutError:
            return BuildResult(
                success=False,
                env_type=EnvironmentType.HARNESS,
                error=f"Harness execution timed out after {timeout} seconds",
            )
        except Exception as e:
            return BuildResult(
                success=False,
                env_type=EnvironmentType.HARNESS,
                error=str(e),
            )

    async def start_background_process(
        self,
        command: list[str],
        working_dir: Path,
        environment: dict[str, str] | None = None,
        name: str | None = None,
    ) -> BuildResult:
        """Start a background process.

        Args:
            command: Command to run.
            working_dir: Working directory.
            environment: Environment variables.
            name: Name for tracking the process.

        Returns:
            BuildResult with process info.
        """
        env = os.environ.copy()
        if environment:
            env.update(environment)

        if name is None:
            name = f"mrzero-proc-{os.urandom(4).hex()}"

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                cwd=str(working_dir),
                env=env,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True,
            )

            # Store state
            state = EnvironmentState(
                env_type=EnvironmentType.NATIVE,
                status=EnvironmentStatus.RUNNING,
                target_path=str(working_dir),
                process_id=proc.pid,
            )
            self._active_environments[name] = state

            return BuildResult(
                success=True,
                env_type=EnvironmentType.NATIVE,
                message=f"Process started with PID {proc.pid}",
                process_id=proc.pid,
            )

        except Exception as e:
            return BuildResult(
                success=False,
                env_type=EnvironmentType.NATIVE,
                error=str(e),
            )

    async def stop_process(self, name: str) -> bool:
        """Stop a background process.

        Args:
            name: Name of the process.

        Returns:
            True if stopped successfully.
        """
        if name not in self._active_environments:
            return False

        state = self._active_environments[name]
        if state.process_id is None:
            return False

        try:
            os.kill(state.process_id, signal.SIGTERM)
            await asyncio.sleep(1)

            # Force kill if still running
            try:
                os.kill(state.process_id, 0)  # Check if alive
                os.kill(state.process_id, signal.SIGKILL)
            except ProcessLookupError:
                pass  # Already dead

            state.status = EnvironmentStatus.STOPPED
            return True

        except Exception:
            return False

    # =========================================================================
    # Cleanup
    # =========================================================================

    async def cleanup_all(self) -> None:
        """Stop and remove all managed environments."""
        for name, state in list(self._active_environments.items()):
            if state.env_type == EnvironmentType.DOCKER:
                await self.remove_container(name, force=True)
            elif state.env_type == EnvironmentType.NATIVE:
                await self.stop_process(name)

        self._active_environments.clear()

    def get_active_environments(self) -> dict[str, EnvironmentState]:
        """Get all active environments."""
        return self._active_environments.copy()


# Singleton instance
_environment_manager: EnvironmentManager | None = None


def get_environment_manager() -> EnvironmentManager:
    """Get the global environment manager instance."""
    global _environment_manager
    if _environment_manager is None:
        _environment_manager = EnvironmentManager()
    return _environment_manager
