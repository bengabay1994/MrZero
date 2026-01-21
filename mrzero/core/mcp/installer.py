"""MCP Server installer - handles cloning and setting up MCP servers."""

import asyncio
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from mrzero.core.mcp.registry import (
    MCPServerConfig,
    MCPServerType,
    get_mcp_registry,
)


@dataclass
class InstallResult:
    """Result of an installation attempt."""

    server_name: str
    success: bool
    install_path: Path | None
    message: str
    error: str | None = None


class MCPInstaller:
    """Handles installation of MCP servers."""

    def __init__(self, base_dir: Path | None = None) -> None:
        """Initialize the installer.

        Args:
            base_dir: Base directory for MCP server installations.
                     Defaults to ~/.mrzero/mcp-servers/
        """
        if base_dir is None:
            base_dir = Path.home() / ".mrzero" / "mcp-servers"
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def get_install_path(self, server_name: str) -> Path:
        """Get the installation path for a server.

        Args:
            server_name: Name of the server.

        Returns:
            Path where the server will be/is installed.
        """
        return self.base_dir / server_name

    def is_installed(self, server_name: str) -> bool:
        """Check if a server is installed.

        Args:
            server_name: Name of the server.

        Returns:
            True if installed.
        """
        path = self.get_install_path(server_name)
        return path.exists() and (path / ".installed").exists()

    def install(
        self,
        server_name: str,
        progress_callback: Callable[[str], None] | None = None,
    ) -> InstallResult:
        """Install an MCP server.

        Args:
            server_name: Name of the server to install.
            progress_callback: Optional callback for progress updates.

        Returns:
            InstallResult with outcome.
        """
        registry = get_mcp_registry()
        config = registry.get_server(server_name)

        if config is None:
            return InstallResult(
                server_name=server_name,
                success=False,
                install_path=None,
                message=f"Unknown server: {server_name}",
                error=f"Server '{server_name}' not found in registry",
            )

        # Check platform compatibility
        import sys

        if sys.platform not in config.platforms:
            return InstallResult(
                server_name=server_name,
                success=False,
                install_path=None,
                message=f"Server not compatible with {sys.platform}",
                error=f"Supported platforms: {', '.join(config.platforms)}",
            )

        install_path = self.get_install_path(server_name)

        try:
            # Step 1: Clone repository
            if progress_callback:
                progress_callback(f"Cloning {config.repo_url}...")

            if install_path.exists():
                # Update existing installation
                self._git_pull(install_path)
            else:
                self._git_clone(config.repo_url, install_path)

            # Step 2: Run install command if specified
            if config.install_command:
                if progress_callback:
                    progress_callback(f"Installing dependencies...")

                self._run_install_command(config, install_path)

            # Step 3: Mark as installed
            (install_path / ".installed").touch()
            registry.mark_installed(server_name, install_path)

            return InstallResult(
                server_name=server_name,
                success=True,
                install_path=install_path,
                message=f"Successfully installed {server_name}",
            )

        except Exception as e:
            return InstallResult(
                server_name=server_name,
                success=False,
                install_path=install_path if install_path.exists() else None,
                message=f"Failed to install {server_name}",
                error=str(e),
            )

    async def install_async(
        self,
        server_name: str,
        progress_callback: Callable[[str], None] | None = None,
    ) -> InstallResult:
        """Install an MCP server asynchronously.

        Args:
            server_name: Name of the server to install.
            progress_callback: Optional callback for progress updates.

        Returns:
            InstallResult with outcome.
        """
        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.install(server_name, progress_callback),
        )

    def uninstall(self, server_name: str) -> bool:
        """Uninstall an MCP server.

        Args:
            server_name: Name of the server to uninstall.

        Returns:
            True if uninstalled successfully.
        """
        install_path = self.get_install_path(server_name)

        if not install_path.exists():
            return True  # Already not installed

        try:
            shutil.rmtree(install_path)
            return True
        except Exception:
            return False

    def _git_clone(self, repo_url: str, target_path: Path) -> None:
        """Clone a git repository.

        Args:
            repo_url: Repository URL.
            target_path: Target directory.
        """
        git_path = shutil.which("git")
        if git_path is None:
            raise RuntimeError("Git is not installed")

        result = subprocess.run(
            [git_path, "clone", "--depth", "1", repo_url, str(target_path)],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(f"Git clone failed: {result.stderr}")

    def _git_pull(self, repo_path: Path) -> None:
        """Pull latest changes in a git repository.

        Args:
            repo_path: Repository directory.
        """
        git_path = shutil.which("git")
        if git_path is None:
            raise RuntimeError("Git is not installed")

        result = subprocess.run(
            [git_path, "pull"],
            cwd=repo_path,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(f"Git pull failed: {result.stderr}")

    def _run_install_command(self, config: MCPServerConfig, install_path: Path) -> None:
        """Run the installation command for a server.

        Args:
            config: Server configuration.
            install_path: Installation directory.
        """
        if not config.install_command:
            return

        # For Python servers, use uv
        if config.server_type == MCPServerType.PYTHON:
            self._install_python_deps(config, install_path)
        elif config.server_type == MCPServerType.NODE:
            self._install_node_deps(config, install_path)

    def _install_python_deps(self, config: MCPServerConfig, install_path: Path) -> None:
        """Install Python dependencies using uv.

        Args:
            config: Server configuration.
            install_path: Installation directory.
        """
        uv_path = shutil.which("uv")
        if uv_path is None:
            raise RuntimeError("uv is not installed. Install it from https://docs.astral.sh/uv/")

        # Create virtual environment in the install path
        venv_path = install_path / ".venv"

        if not venv_path.exists():
            result = subprocess.run(
                [uv_path, "venv", str(venv_path)],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise RuntimeError(f"Failed to create venv: {result.stderr}")

        # Install dependencies
        if config.install_command:
            # Replace "uv" with actual path and add --python flag
            cmd = config.install_command.copy()
            if cmd[0] == "uv":
                cmd[0] = uv_path
                # Add python path from venv
                if "pip" in cmd:
                    cmd.insert(cmd.index("pip") + 1, "--python")
                    cmd.insert(cmd.index("--python") + 1, str(venv_path / "bin" / "python"))

            result = subprocess.run(
                cmd,
                cwd=install_path,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise RuntimeError(f"Failed to install dependencies: {result.stderr}")

        # Check for requirements.txt
        req_file = install_path / "requirements.txt"
        if req_file.exists():
            result = subprocess.run(
                [
                    uv_path,
                    "pip",
                    "install",
                    "--python",
                    str(venv_path / "bin" / "python"),
                    "-r",
                    str(req_file),
                ],
                cwd=install_path,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise RuntimeError(f"Failed to install from requirements.txt: {result.stderr}")

    def _install_node_deps(self, config: MCPServerConfig, install_path: Path) -> None:
        """Install Node.js dependencies.

        Args:
            config: Server configuration.
            install_path: Installation directory.
        """
        # For npx-based servers, we don't need to pre-install
        # npx handles it at runtime
        npm_path = shutil.which("npm")
        if npm_path is None:
            # Just check that npx is available
            npx_path = shutil.which("npx")
            if npx_path is None:
                raise RuntimeError("npm/npx is not installed")
            return

        # Check for package.json
        package_json = install_path / "package.json"
        if package_json.exists():
            result = subprocess.run(
                [npm_path, "install"],
                cwd=install_path,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise RuntimeError(f"npm install failed: {result.stderr}")

    def get_server_command(self, server_name: str) -> list[str] | None:
        """Get the command to start a server.

        Args:
            server_name: Name of the server.

        Returns:
            Command list or None if not installed.
        """
        if not self.is_installed(server_name):
            return None

        registry = get_mcp_registry()
        config = registry.get_server(server_name)
        if config is None:
            return None

        install_path = self.get_install_path(server_name)
        cmd = config.get_start_command()

        # Adjust command based on server type
        if config.server_type == MCPServerType.PYTHON:
            venv_python = install_path / ".venv" / "bin" / "python"
            if venv_python.exists():
                # Replace "python" with venv python
                if cmd and cmd[0] == "python":
                    cmd[0] = str(venv_python)

        return cmd

    def check_requirements(self, server_name: str) -> dict[str, bool]:
        """Check if server requirements are met.

        Args:
            server_name: Name of the server.

        Returns:
            Dict of requirement -> is_available.
        """
        registry = get_mcp_registry()
        config = registry.get_server(server_name)
        if config is None:
            return {}

        results = {}
        for req in config.requires:
            results[req] = self._check_requirement(req)

        return results

    def _check_requirement(self, requirement: str) -> bool:
        """Check if a requirement is available.

        Args:
            requirement: Requirement name.

        Returns:
            True if available.
        """
        # Map requirement names to check methods
        checks = {
            "ghidra": self._check_ghidra,
            "gdb": lambda: shutil.which("gdb") is not None,
            "pwndbg": self._check_pwndbg,
            "metasploit": self._check_metasploit,
            "frida": lambda: shutil.which("frida") is not None,
            "ida-pro": self._check_ida,
            "binary-ninja": self._check_binja,
            "windbg": lambda: shutil.which("windbg") is not None,
        }

        check_fn = checks.get(requirement)
        if check_fn:
            try:
                return check_fn()
            except Exception:
                return False

        # Default: check if it's an executable
        return shutil.which(requirement) is not None

    def _check_ghidra(self) -> bool:
        """Check if Ghidra is installed."""
        # Check for GHIDRA_INSTALL_DIR env var
        if os.environ.get("GHIDRA_INSTALL_DIR"):
            return True
        # Check for ghidraRun in PATH
        return shutil.which("ghidraRun") is not None

    def _check_pwndbg(self) -> bool:
        """Check if pwndbg is installed."""
        # pwndbg is a GDB plugin, check for its setup file
        pwndbg_paths = [
            Path.home() / "pwndbg",
            Path.home() / ".pwndbg",
            Path("/opt/pwndbg"),
        ]
        return any(p.exists() for p in pwndbg_paths)

    def _check_metasploit(self) -> bool:
        """Check if Metasploit is installed."""
        return shutil.which("msfconsole") is not None

    def _check_ida(self) -> bool:
        """Check if IDA Pro is installed."""
        # Check for common IDA paths
        if os.environ.get("IDADIR"):
            return True
        return shutil.which("ida64") is not None or shutil.which("ida") is not None

    def _check_binja(self) -> bool:
        """Check if Binary Ninja is installed."""
        try:
            import binaryninja

            return True
        except ImportError:
            return False


# Global installer instance
_installer: MCPInstaller | None = None


def get_mcp_installer() -> MCPInstaller:
    """Get the global MCP installer.

    Returns:
        MCPInstaller instance.
    """
    global _installer
    if _installer is None:
        _installer = MCPInstaller()
    return _installer
