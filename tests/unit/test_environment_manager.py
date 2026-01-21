"""Unit tests for EnvironmentManager."""

import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mrzero.core.environment.manager import (
    BuildResult,
    EnvironmentManager,
    EnvironmentState,
    EnvironmentStatus,
    EnvironmentType,
    get_environment_manager,
)


@pytest.fixture
def env_manager():
    """Create a fresh EnvironmentManager for testing."""
    return EnvironmentManager()


@pytest.fixture
def mock_docker_available(env_manager):
    """Mock Docker as available."""
    with patch.object(env_manager, "docker_available", return_value=True):
        # Also mock the docker client
        mock_docker = MagicMock()
        mock_docker.docker_path = "/usr/bin/docker"
        mock_docker.is_available.return_value = True
        mock_docker.image_exists.return_value = True
        env_manager._docker = mock_docker
        yield mock_docker


@pytest.fixture
def temp_project(tmp_path):
    """Create a temporary project directory."""
    project_dir = tmp_path / "test_project"
    project_dir.mkdir()

    # Create a simple Dockerfile
    dockerfile = project_dir / "Dockerfile"
    dockerfile.write_text("""
FROM python:3.12-slim
WORKDIR /app
COPY . .
CMD ["python", "-c", "print('Hello from container')"]
""")

    # Create a docker-compose file
    compose_file = project_dir / "docker-compose.yml"
    compose_file.write_text("""
version: '3'
services:
  app:
    build: .
    ports:
      - "8080:8080"
""")

    # Create a simple Python file
    app_file = project_dir / "app.py"
    app_file.write_text("print('Hello World')")

    return project_dir


@pytest.fixture
def temp_harness(tmp_path):
    """Create a temporary harness directory."""
    harness_dir = tmp_path / "harness"
    harness_dir.mkdir()

    harness_file = harness_dir / "harness.py"
    harness_file.write_text("""
print("Harness running")
print("Test complete")
""")

    return harness_dir


class TestEnvironmentManagerBasics:
    """Basic tests for EnvironmentManager."""

    def test_init(self, env_manager):
        """Test EnvironmentManager initialization."""
        assert env_manager._docker is None
        assert env_manager._active_environments == {}

    def test_docker_available_no_docker(self, env_manager):
        """Test docker_available when Docker is not installed."""
        from mrzero.core.docker.exceptions import DockerNotInstalledError

        with patch.object(env_manager, "_docker", None):
            with patch("mrzero.core.environment.manager.DockerClient") as MockDockerClient:
                mock_instance = MagicMock()
                mock_instance.is_available.return_value = False
                MockDockerClient.return_value = mock_instance

                # Reset the cached docker client
                env_manager._docker = None
                assert env_manager.docker_available() is False

    def test_get_active_environments_empty(self, env_manager):
        """Test getting active environments when none exist."""
        result = env_manager.get_active_environments()
        assert result == {}

    def test_singleton_get_environment_manager(self):
        """Test get_environment_manager returns singleton."""
        mgr1 = get_environment_manager()
        mgr2 = get_environment_manager()
        assert mgr1 is mgr2


class TestDockerBuild:
    """Tests for Docker build operations."""

    @pytest.mark.asyncio
    async def test_build_docker_image_no_docker(self, env_manager, temp_project):
        """Test build fails when Docker unavailable."""
        with patch.object(env_manager, "docker_available", return_value=False):
            result = await env_manager.build_docker_image(temp_project)

            assert result.success is False
            assert result.env_type == EnvironmentType.DOCKER
            assert "not available" in result.error.lower()

    @pytest.mark.asyncio
    async def test_build_docker_image_no_dockerfile(self, env_manager, tmp_path):
        """Test build fails when no Dockerfile exists."""
        empty_project = tmp_path / "empty"
        empty_project.mkdir()

        with patch.object(env_manager, "docker_available", return_value=True):
            result = await env_manager.build_docker_image(empty_project)

            assert result.success is False
            assert "No Dockerfile" in result.error

    @pytest.mark.asyncio
    async def test_build_docker_image_success(
        self, env_manager, temp_project, mock_docker_available
    ):
        """Test successful Docker image build."""

        async def mock_communicate():
            return (b"Successfully built abc123", b"")

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = mock_communicate
            mock_exec.return_value = mock_proc

            result = await env_manager.build_docker_image(temp_project)

            assert result.success is True
            assert result.env_type == EnvironmentType.DOCKER
            assert result.image_name is not None
            assert "mrzero-target" in result.image_name

    @pytest.mark.asyncio
    async def test_build_docker_image_custom_name(
        self, env_manager, temp_project, mock_docker_available
    ):
        """Test Docker build with custom image name."""

        async def mock_communicate():
            return (b"Successfully built", b"")

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = mock_communicate
            mock_exec.return_value = mock_proc

            result = await env_manager.build_docker_image(
                temp_project, image_name="my-custom-image"
            )

            assert result.success is True
            assert result.image_name == "my-custom-image"

    @pytest.mark.asyncio
    async def test_build_docker_image_timeout(
        self, env_manager, temp_project, mock_docker_available
    ):
        """Test Docker build timeout."""

        async def slow_communicate():
            await asyncio.sleep(10)
            return (b"", b"")

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = slow_communicate
            mock_exec.return_value = mock_proc

            result = await env_manager.build_docker_image(
                temp_project,
                timeout=0.1,  # Very short timeout
            )

            assert result.success is False
            assert "timed out" in result.error.lower()


class TestContainerOperations:
    """Tests for container start/stop operations."""

    @pytest.mark.asyncio
    async def test_run_container_no_docker(self, env_manager):
        """Test run container fails without Docker."""
        with patch.object(env_manager, "docker_available", return_value=False):
            result = await env_manager.run_docker_container("test-image")

            assert result.success is False
            assert "not available" in result.error.lower()

    @pytest.mark.asyncio
    async def test_run_container_success(self, env_manager, mock_docker_available):
        """Test successful container run."""

        async def mock_communicate():
            return (b"abc123def456", b"")

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = mock_communicate
            mock_exec.return_value = mock_proc

            result = await env_manager.run_docker_container(
                image_name="test-image",
                ports={8080: 8080},
            )

            assert result.success is True
            assert result.container_id == "abc123def456"
            assert result.port == 8080

            # Check it was tracked
            assert len(env_manager._active_environments) == 1

    @pytest.mark.asyncio
    async def test_stop_container(self, env_manager, mock_docker_available):
        """Test stopping a container."""
        # First add a container to track
        state = EnvironmentState(
            env_type=EnvironmentType.DOCKER,
            status=EnvironmentStatus.RUNNING,
            container_id="abc123",
            container_name="test-container",
        )
        env_manager._active_environments["test-container"] = state

        async def mock_communicate():
            return (b"test-container", b"")

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = mock_communicate
            mock_exec.return_value = mock_proc

            success = await env_manager.stop_container("test-container")

            assert success is True
            assert (
                env_manager._active_environments["test-container"].status
                == EnvironmentStatus.STOPPED
            )

    @pytest.mark.asyncio
    async def test_remove_container(self, env_manager, mock_docker_available):
        """Test removing a container."""
        state = EnvironmentState(
            env_type=EnvironmentType.DOCKER,
            status=EnvironmentStatus.STOPPED,
            container_id="abc123",
            container_name="test-container",
        )
        env_manager._active_environments["test-container"] = state

        async def mock_communicate():
            return (b"", b"")

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = mock_communicate
            mock_exec.return_value = mock_proc

            success = await env_manager.remove_container("test-container")

            assert success is True
            assert "test-container" not in env_manager._active_environments

    @pytest.mark.asyncio
    async def test_container_health_check(self, env_manager, mock_docker_available):
        """Test container health check."""

        async def mock_communicate():
            return (b"true\n", b"")

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = mock_communicate
            mock_exec.return_value = mock_proc

            healthy = await env_manager.container_health_check("test-container")

            assert healthy is True

    @pytest.mark.asyncio
    async def test_get_container_logs(self, env_manager, mock_docker_available):
        """Test getting container logs."""

        async def mock_communicate():
            return (b"Log line 1\nLog line 2\n", b"")

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = mock_communicate
            mock_exec.return_value = mock_proc

            logs = await env_manager.get_container_logs("test-container")

            assert "Log line 1" in logs
            assert "Log line 2" in logs


class TestDockerCompose:
    """Tests for docker-compose operations."""

    @pytest.mark.asyncio
    async def test_compose_up_no_file(self, env_manager, tmp_path):
        """Test compose up fails without compose file."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        with patch("shutil.which", return_value="/usr/bin/docker-compose"):
            result = await env_manager.compose_up(empty_dir)

            assert result.success is False
            assert "No docker-compose" in result.error

    @pytest.mark.asyncio
    async def test_compose_up_success(self, env_manager, temp_project):
        """Test successful docker-compose up."""

        async def mock_communicate():
            return (b"Creating network... done\nStarting service...", b"")

        with patch("shutil.which", return_value="/usr/bin/docker-compose"):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_proc = AsyncMock()
                mock_proc.returncode = 0
                mock_proc.communicate = mock_communicate
                mock_exec.return_value = mock_proc

                result = await env_manager.compose_up(temp_project)

                assert result.success is True
                assert result.env_type == EnvironmentType.DOCKER_COMPOSE

    @pytest.mark.asyncio
    async def test_compose_down(self, env_manager, temp_project):
        """Test docker-compose down."""

        async def mock_communicate():
            return (b"Stopping...", b"")

        with patch("shutil.which", return_value="/usr/bin/docker-compose"):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_proc = AsyncMock()
                mock_proc.returncode = 0
                mock_proc.communicate = mock_communicate
                mock_exec.return_value = mock_proc

                success = await env_manager.compose_down(temp_project)

                assert success is True


class TestHarnessExecution:
    """Tests for harness execution."""

    @pytest.mark.asyncio
    async def test_run_harness_not_exists(self, env_manager, tmp_path):
        """Test harness run fails for non-existent path."""
        result = await env_manager.run_harness(tmp_path / "nonexistent")

        assert result.success is False
        assert "does not exist" in result.error

    @pytest.mark.asyncio
    async def test_run_harness_success(self, env_manager, temp_harness):
        """Test successful harness execution."""
        result = await env_manager.run_harness(temp_harness)

        assert result.success is True
        assert result.env_type == EnvironmentType.HARNESS
        assert "Harness running" in result.output
        assert "Test complete" in result.output

    @pytest.mark.asyncio
    async def test_run_harness_with_custom_command(self, env_manager, temp_harness):
        """Test harness with custom command."""
        result = await env_manager.run_harness(
            temp_harness,
            command=["python3", "-c", "print('Custom command')"],
        )

        assert result.success is True
        assert "Custom command" in result.output

    @pytest.mark.asyncio
    async def test_run_harness_timeout(self, env_manager, tmp_path):
        """Test harness execution timeout."""
        harness_dir = tmp_path / "slow_harness"
        harness_dir.mkdir()

        # Create a slow harness
        harness_file = harness_dir / "harness.py"
        harness_file.write_text("""
import time
time.sleep(100)
print("Done")
""")

        result = await env_manager.run_harness(
            harness_dir,
            timeout=1,  # Very short timeout
        )

        assert result.success is False
        assert "timed out" in result.error.lower()

    @pytest.mark.asyncio
    async def test_run_harness_failure(self, env_manager, tmp_path):
        """Test harness that exits with error."""
        harness_dir = tmp_path / "failing_harness"
        harness_dir.mkdir()

        harness_file = harness_dir / "harness.py"
        harness_file.write_text("""
import sys
print("Error occurred", file=sys.stderr)
sys.exit(1)
""")

        result = await env_manager.run_harness(harness_dir)

        assert result.success is False
        assert "Error occurred" in result.error or result.output


class TestNativeProcessManagement:
    """Tests for native process management."""

    @pytest.mark.asyncio
    async def test_start_background_process(self, env_manager, tmp_path):
        """Test starting a background process."""
        result = await env_manager.start_background_process(
            command=["sleep", "1"],
            working_dir=tmp_path,
            name="test-process",
        )

        assert result.success is True
        assert result.env_type == EnvironmentType.NATIVE
        assert result.process_id is not None
        assert "test-process" in env_manager._active_environments

        # Cleanup
        await env_manager.stop_process("test-process")

    @pytest.mark.asyncio
    async def test_stop_process_not_found(self, env_manager):
        """Test stopping non-existent process."""
        success = await env_manager.stop_process("nonexistent")
        assert success is False


class TestCleanup:
    """Tests for cleanup operations."""

    @pytest.mark.asyncio
    async def test_cleanup_all(self, env_manager, mock_docker_available):
        """Test cleaning up all environments."""
        # Add some fake environments
        env_manager._active_environments["container1"] = EnvironmentState(
            env_type=EnvironmentType.DOCKER,
            status=EnvironmentStatus.RUNNING,
            container_id="abc123",
            container_name="container1",
        )
        env_manager._active_environments["proc1"] = EnvironmentState(
            env_type=EnvironmentType.NATIVE,
            status=EnvironmentStatus.RUNNING,
            process_id=12345,
        )

        # Mock the remove operations
        async def mock_communicate():
            return (b"", b"")

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.communicate = mock_communicate
            mock_exec.return_value = mock_proc

            with patch("os.kill"):  # Mock process kill
                await env_manager.cleanup_all()

        assert len(env_manager._active_environments) == 0


class TestBuildResult:
    """Tests for BuildResult dataclass."""

    def test_build_result_success(self):
        """Test successful BuildResult."""
        result = BuildResult(
            success=True,
            env_type=EnvironmentType.DOCKER,
            message="Build complete",
            container_id="abc123",
            port=8080,
        )

        assert result.success is True
        assert result.env_type == EnvironmentType.DOCKER
        assert result.container_id == "abc123"

    def test_build_result_failure(self):
        """Test failed BuildResult."""
        result = BuildResult(
            success=False,
            env_type=EnvironmentType.DOCKER,
            error="Build failed: missing dependency",
        )

        assert result.success is False
        assert "missing dependency" in result.error


class TestEnvironmentState:
    """Tests for EnvironmentState dataclass."""

    def test_environment_state_defaults(self):
        """Test EnvironmentState default values."""
        state = EnvironmentState(env_type=EnvironmentType.DOCKER)

        assert state.status == EnvironmentStatus.NOT_CREATED
        assert state.container_id is None
        assert state.process_id is None
        assert state.build_log == []
        assert state.errors == []
