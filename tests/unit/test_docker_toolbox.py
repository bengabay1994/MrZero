"""Unit tests for Docker toolbox functionality."""

import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from mrzero.core.docker.client import DockerClient, ContainerResult
from mrzero.core.docker.toolbox import ToolboxManager, ToolResult, TOOLBOX_IMAGE, AVAILABLE_TOOLS
from mrzero.core.docker.exceptions import (
    DockerError,
    DockerNotInstalledError,
    ImageNotFoundError,
    ContainerError,
)


class TestDockerClient:
    """Tests for DockerClient."""

    def test_is_available_when_docker_not_installed(self):
        """Test is_available returns False when Docker is not installed."""
        client = DockerClient()

        with patch("shutil.which", return_value=None):
            assert client.is_available() is False

    def test_is_available_when_docker_running(self):
        """Test is_available returns True when Docker is running."""
        client = DockerClient()

        with patch("shutil.which", return_value="/usr/bin/docker"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0)
                assert client.is_available() is True

    def test_is_available_when_docker_not_running(self):
        """Test is_available returns False when Docker is not running."""
        client = DockerClient()

        with patch("shutil.which", return_value="/usr/bin/docker"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=1)
                assert client.is_available() is False

    def test_verify_raises_when_not_available(self):
        """Test verify raises exception when Docker not available."""
        client = DockerClient()

        with patch.object(client, "is_available", return_value=False):
            with pytest.raises(DockerNotInstalledError):
                client.verify()

    def test_image_exists_when_present(self):
        """Test image_exists returns True when image is present."""
        client = DockerClient()
        client._verified = True

        with patch("shutil.which", return_value="/usr/bin/docker"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0)
                assert client.image_exists("test-image:latest") is True

    def test_image_exists_when_missing(self):
        """Test image_exists returns False when image is missing."""
        client = DockerClient()
        client._verified = True

        with patch("shutil.which", return_value="/usr/bin/docker"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=1)
                assert client.image_exists("test-image:latest") is False

    def test_get_image_info_returns_data(self):
        """Test get_image_info returns image data."""
        client = DockerClient()
        client._verified = True

        image_data = [{"Id": "sha256:abc123", "Created": "2024-01-01"}]

        with patch("shutil.which", return_value="/usr/bin/docker"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout=json.dumps(image_data))
                result = client.get_image_info("test-image:latest")
                assert result == image_data[0]

    def test_get_image_info_returns_none_when_not_found(self):
        """Test get_image_info returns None when image not found."""
        client = DockerClient()
        client._verified = True

        with patch("shutil.which", return_value="/usr/bin/docker"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = Mock(returncode=1, stdout="")
                result = client.get_image_info("nonexistent:latest")
                assert result is None

    def test_run_container_success(self):
        """Test run_container returns successful result."""
        client = DockerClient()
        client._verified = True

        with patch("shutil.which", return_value="/usr/bin/docker"):
            with patch.object(client, "image_exists", return_value=True):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(
                        returncode=0,
                        stdout="output",
                        stderr="",
                    )
                    result = client.run_container(
                        image="test:latest",
                        command=["echo", "hello"],
                    )

                    assert result.success is True
                    assert result.exit_code == 0
                    assert result.stdout == "output"

    def test_run_container_failure(self):
        """Test run_container returns failed result."""
        client = DockerClient()
        client._verified = True

        with patch("shutil.which", return_value="/usr/bin/docker"):
            with patch.object(client, "image_exists", return_value=True):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(
                        returncode=1,
                        stdout="",
                        stderr="error message",
                    )
                    result = client.run_container(
                        image="test:latest",
                        command=["bad", "command"],
                    )

                    assert result.success is False
                    assert result.exit_code == 1
                    assert result.stderr == "error message"

    def test_run_container_raises_when_image_not_found(self):
        """Test run_container raises ImageNotFoundError when image missing."""
        client = DockerClient()
        client._verified = True

        with patch("shutil.which", return_value="/usr/bin/docker"):
            with patch.object(client, "image_exists", return_value=False):
                with pytest.raises(ImageNotFoundError):
                    client.run_container(
                        image="nonexistent:latest",
                        command=["test"],
                    )

    def test_run_container_with_volumes(self):
        """Test run_container correctly mounts volumes."""
        client = DockerClient()
        client._verified = True

        with patch("shutil.which", return_value="/usr/bin/docker"):
            with patch.object(client, "image_exists", return_value=True):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

                    client.run_container(
                        image="test:latest",
                        command=["ls"],
                        volumes={"/host/path": "/container/path"},
                    )

                    # Verify volume mount was passed
                    call_args = mock_run.call_args[0][0]
                    assert "-v" in call_args


class TestToolboxManager:
    """Tests for ToolboxManager."""

    def test_default_image(self):
        """Test default toolbox image is set correctly."""
        manager = ToolboxManager()
        assert manager.image == TOOLBOX_IMAGE
        assert "ghcr.io" in manager.image

    def test_custom_image(self):
        """Test custom toolbox image can be set."""
        manager = ToolboxManager(image="custom/image:v1")
        assert manager.image == "custom/image:v1"

    def test_is_docker_available(self):
        """Test is_docker_available delegates to client."""
        manager = ToolboxManager()

        with patch.object(manager.client, "is_available", return_value=True):
            assert manager.is_docker_available() is True

        with patch.object(manager.client, "is_available", return_value=False):
            assert manager.is_docker_available() is False

    def test_is_toolbox_available_when_present(self):
        """Test is_toolbox_available returns True when image present."""
        manager = ToolboxManager()

        with patch.object(manager.client, "image_exists", return_value=True):
            assert manager.is_toolbox_available() is True

    def test_is_toolbox_available_when_missing(self):
        """Test is_toolbox_available returns False when image missing."""
        manager = ToolboxManager()

        with patch.object(manager.client, "image_exists", return_value=False):
            assert manager.is_toolbox_available() is False

    def test_get_status_docker_not_available(self):
        """Test get_status when Docker not available."""
        manager = ToolboxManager()

        with patch.object(manager.client, "is_available", return_value=False):
            status = manager.get_status()

            assert status["docker_available"] is False
            assert status["toolbox_available"] is False
            assert "error" in status

    def test_get_status_toolbox_not_installed(self):
        """Test get_status when toolbox not installed."""
        manager = ToolboxManager()

        with patch.object(manager.client, "is_available", return_value=True):
            with patch.object(manager, "is_toolbox_available", return_value=False):
                status = manager.get_status()

                assert status["docker_available"] is True
                assert status["toolbox_available"] is False
                assert "error" in status

    def test_get_status_all_available(self):
        """Test get_status when everything is available."""
        manager = ToolboxManager()

        with patch.object(manager.client, "is_available", return_value=True):
            with patch.object(manager, "is_toolbox_available", return_value=True):
                with patch.object(manager, "get_toolbox_info", return_value={"Id": "test"}):
                    status = manager.get_status()

                    assert status["docker_available"] is True
                    assert status["toolbox_available"] is True
                    assert "error" not in status
                    assert "tools" in status

    def test_run_tool_unknown_tool(self):
        """Test run_tool returns error for unknown tool."""
        manager = ToolboxManager()

        result = manager.run_tool(
            tool="unknown_tool",
            args=[],
            target_path="/tmp",
        )

        assert result.success is False
        assert "Unknown tool" in result.error

    def test_run_tool_target_not_exists(self):
        """Test run_tool returns error when target doesn't exist."""
        manager = ToolboxManager()

        result = manager.run_tool(
            tool="opengrep",
            args=[],
            target_path="/nonexistent/path",
        )

        assert result.success is False
        assert "does not exist" in result.error

    def test_run_tool_success(self, tmp_path):
        """Test run_tool returns successful result."""
        manager = ToolboxManager()

        mock_result = ContainerResult(
            exit_code=0,
            stdout="scan output",
            stderr="",
            success=True,
        )

        with patch.object(manager.client, "run_container", return_value=mock_result):
            result = manager.run_tool(
                tool="opengrep",
                args=["scan", "--config", "auto", "/workspace"],
                target_path=tmp_path,
            )

            assert result.success is True
            assert result.output == "scan output"

    def test_run_opengrep(self, tmp_path):
        """Test run_opengrep helper method."""
        manager = ToolboxManager()

        mock_result = ContainerResult(
            exit_code=0,
            stdout='{"results": []}',
            stderr="",
            success=True,
        )

        with patch.object(manager.client, "run_container", return_value=mock_result):
            result = manager.run_opengrep(target_path=tmp_path)

            assert result.success is True

    def test_run_linguist(self, tmp_path):
        """Test run_linguist helper method."""
        manager = ToolboxManager()

        mock_result = ContainerResult(
            exit_code=0,
            stdout="100%  Python",
            stderr="",
            success=True,
        )

        with patch.object(manager.client, "run_container", return_value=mock_result):
            result = manager.run_linguist(target_path=tmp_path)

            assert result.success is True

    def test_get_available_tools(self):
        """Test get_available_tools returns tools dict."""
        manager = ToolboxManager()
        tools = manager.get_available_tools()

        assert "opengrep" in tools
        assert "linguist" in tools
        assert "description" in tools["opengrep"]


class TestToolResult:
    """Tests for ToolResult dataclass."""

    def test_to_dict(self):
        """Test ToolResult.to_dict() conversion."""
        result = ToolResult(
            tool="opengrep",
            success=True,
            output="test output",
            error=None,
            exit_code=0,
        )

        data = result.to_dict()

        assert data["tool"] == "opengrep"
        assert data["success"] is True
        assert data["output"] == "test output"
        assert data["error"] is None
        assert data["exit_code"] == 0

    def test_failed_result(self):
        """Test ToolResult for failed execution."""
        result = ToolResult(
            tool="linguist",
            success=False,
            output="",
            error="Tool failed",
            exit_code=1,
        )

        assert result.success is False
        assert result.error == "Tool failed"


class TestContainerResult:
    """Tests for ContainerResult dataclass."""

    def test_output_property_returns_stdout(self):
        """Test output property returns stdout when present."""
        result = ContainerResult(
            exit_code=0,
            stdout="stdout output",
            stderr="stderr output",
            success=True,
        )

        assert result.output == "stdout output"

    def test_output_property_returns_stderr_when_stdout_empty(self):
        """Test output property returns stderr when stdout is empty."""
        result = ContainerResult(
            exit_code=1,
            stdout="",
            stderr="error output",
            success=False,
        )

        assert result.output == "error output"


class TestDockerExceptions:
    """Tests for Docker exceptions."""

    def test_docker_not_installed_error_message(self):
        """Test DockerNotInstalledError has helpful message."""
        error = DockerNotInstalledError()
        assert "Docker is not installed" in str(error)
        assert "docker.com" in str(error)

    def test_docker_not_installed_error_custom_message(self):
        """Test DockerNotInstalledError with custom message."""
        error = DockerNotInstalledError("Custom message")
        assert str(error) == "Custom message"

    def test_image_not_found_error(self):
        """Test ImageNotFoundError contains image name."""
        error = ImageNotFoundError("ghcr.io/test/image:latest")
        assert "ghcr.io/test/image:latest" in str(error)
        assert error.image == "ghcr.io/test/image:latest"
        assert "mrzero docker pull" in str(error)

    def test_container_error_with_exit_code(self):
        """Test ContainerError with exit code."""
        error = ContainerError("Container failed", exit_code=127)
        assert "Container failed" in str(error)
        assert error.exit_code == 127


class TestAvailableTools:
    """Tests for available tools configuration."""

    def test_available_tools_has_required_tools(self):
        """Test AVAILABLE_TOOLS contains required tools."""
        assert "opengrep" in AVAILABLE_TOOLS
        assert "linguist" in AVAILABLE_TOOLS

    def test_tools_have_description(self):
        """Test all tools have description."""
        for tool_name, tool_info in AVAILABLE_TOOLS.items():
            assert "description" in tool_info, f"{tool_name} missing description"

    def test_tools_have_version_cmd(self):
        """Test all tools have version command."""
        for tool_name, tool_info in AVAILABLE_TOOLS.items():
            assert "version_cmd" in tool_info, f"{tool_name} missing version_cmd"


class TestToolboxImage:
    """Tests for toolbox image configuration."""

    def test_toolbox_image_format(self):
        """Test toolbox image has correct format."""
        assert TOOLBOX_IMAGE.startswith("ghcr.io/")
        assert "mrzero-toolbox" in TOOLBOX_IMAGE
        assert ":latest" in TOOLBOX_IMAGE or ":" in TOOLBOX_IMAGE
