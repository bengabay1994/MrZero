"""Unit tests for CLI config commands."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from mrzero.cli.main import app, config_app, is_first_run, mark_initialized
from mrzero.core.config import MrZeroConfig, LLMConfig, ToolPreferences, get_config, set_config


runner = CliRunner()


@pytest.fixture
def temp_config(tmp_path):
    """Create a temporary config for testing."""
    config = MrZeroConfig(
        data_dir=tmp_path / ".mrzero",
        output_dir=tmp_path / "output",
    )
    config.ensure_directories()
    return config


@pytest.fixture
def mock_config(temp_config):
    """Mock the global config with temp config."""
    with patch("mrzero.cli.main.get_config", return_value=temp_config):
        yield temp_config


class TestConfigShow:
    """Tests for 'mrzero config show' command."""

    def test_config_show_runs(self, mock_config):
        """Test config show command executes successfully."""
        result = runner.invoke(app, ["config", "show"])
        assert result.exit_code == 0

    def test_config_show_displays_provider(self, mock_config):
        """Test config show displays LLM provider."""
        result = runner.invoke(app, ["config", "show"])
        assert "aws_bedrock" in result.output or "Provider" in result.output

    def test_config_show_displays_data_dir(self, mock_config):
        """Test config show displays data directory."""
        result = runner.invoke(app, ["config", "show"])
        assert "Data Directory" in result.output or ".mrzero" in result.output

    def test_config_show_displays_tool_preferences(self, mock_config):
        """Test config show displays tool preferences."""
        result = runner.invoke(app, ["config", "show"])
        # Check for tool-related content
        assert "Tool" in result.output or "SAST" in result.output or "Disassembly" in result.output


class TestConfigReset:
    """Tests for 'mrzero config reset' command."""

    def test_config_reset_with_confirmation(self, mock_config, tmp_path):
        """Test config reset with user confirmation."""
        # Create a custom config first
        mock_config.llm.temperature = 0.9
        mock_config.save()

        result = runner.invoke(app, ["config", "reset"], input="y\n")
        assert result.exit_code == 0
        assert "reset" in result.output.lower() or "defaults" in result.output.lower()

    def test_config_reset_cancelled(self, mock_config):
        """Test config reset cancelled by user."""
        result = runner.invoke(app, ["config", "reset"], input="n\n")
        assert result.exit_code == 0


class TestConfigTools:
    """Tests for 'mrzero config tools' command."""

    def test_config_tools_displays_categories(self, mock_config):
        """Test config tools shows tool categories."""
        # Just hit enter for all prompts to use defaults
        result = runner.invoke(app, ["config", "tools"], input="\n\n\n\n\n\n")
        assert result.exit_code == 0
        # Should mention disassembly or SAST tools
        assert "Disassembly" in result.output or "SAST" in result.output

    def test_config_tools_accepts_input(self, mock_config):
        """Test config tools accepts user input."""
        # Provide custom tool preferences
        result = runner.invoke(
            app,
            ["config", "tools"],
            input="ghidra,radare2\nopengrep,gitleaks\ngdb\nwindbg\nafl++\nwinafl\n",
        )
        assert result.exit_code == 0
        assert "saved" in result.output.lower()


class TestConfigLLM:
    """Tests for 'mrzero config llm' command."""

    def test_config_llm_shows_providers(self, mock_config):
        """Test config llm shows available providers."""
        # Use defaults for all prompts
        result = runner.invoke(app, ["config", "llm"], input="\n\n\n\n\n")
        assert result.exit_code == 0
        assert "Bedrock" in result.output or "Gemini" in result.output

    def test_config_llm_accepts_aws_bedrock(self, mock_config):
        """Test config llm accepts AWS Bedrock configuration."""
        result = runner.invoke(
            app,
            ["config", "llm"],
            input="aws_bedrock\n\n0.1\nus-west-2\n\n",
        )
        assert result.exit_code == 0
        assert "saved" in result.output.lower()

    def test_config_llm_accepts_google_gemini(self, mock_config):
        """Test config llm accepts Google Gemini configuration."""
        result = runner.invoke(
            app,
            ["config", "llm"],
            input="google_gemini\n\n0.2\nmy-project\n",
        )
        assert result.exit_code == 0
        assert "saved" in result.output.lower()


class TestFirstRun:
    """Tests for first-run detection and onboarding."""

    def test_is_first_run_true(self, tmp_path):
        """Test is_first_run returns True when marker doesn't exist."""
        config = MrZeroConfig(data_dir=tmp_path / ".mrzero")
        config.ensure_directories()

        with patch("mrzero.cli.main.get_config", return_value=config):
            assert is_first_run() is True

    def test_is_first_run_false_after_mark(self, tmp_path):
        """Test is_first_run returns False after marking initialized."""
        config = MrZeroConfig(data_dir=tmp_path / ".mrzero")
        config.ensure_directories()

        with patch("mrzero.cli.main.get_config", return_value=config):
            mark_initialized()
            assert is_first_run() is False

    def test_mark_initialized_creates_marker(self, tmp_path):
        """Test mark_initialized creates the marker file."""
        config = MrZeroConfig(data_dir=tmp_path / ".mrzero")
        config.ensure_directories()

        with patch("mrzero.cli.main.get_config", return_value=config):
            mark_initialized()
            marker_path = config.data_dir / ".mrzero_initialized"
            assert marker_path.exists()


class TestToolsCommand:
    """Tests for 'mrzero tools' command."""

    def test_tools_command_runs(self, mock_config):
        """Test tools command executes."""
        result = runner.invoke(app, ["tools"])
        # May have non-zero exit if tools aren't installed, that's OK
        # Just verify it doesn't crash
        assert (
            "Security Tool" in result.output or "SAST" in result.output or "Tool" in result.output
        )

    def test_tools_command_shows_categories(self, mock_config):
        """Test tools command shows tool categories."""
        result = runner.invoke(app, ["tools"])
        # Should show at least one category
        assert any(
            cat in result.output
            for cat in ["SAST", "Binary", "Exploitation", "Debugging", "Language"]
        )


class TestMrZeroConfigModel:
    """Tests for MrZeroConfig model."""

    def test_default_config(self):
        """Test default configuration values."""
        config = MrZeroConfig()
        assert config.llm.provider == "aws_bedrock"
        assert config.llm.temperature == 0.1
        assert "opengrep" in config.tools.sast_tools

    def test_config_save_and_load(self, tmp_path):
        """Test config save and load."""
        config = MrZeroConfig(data_dir=tmp_path / ".mrzero")
        config.llm.temperature = 0.5
        config.llm.provider = "google_gemini"
        config.ensure_directories()
        config.save()

        loaded = MrZeroConfig.load(tmp_path / ".mrzero" / "config.json")
        assert loaded.llm.temperature == 0.5
        assert loaded.llm.provider == "google_gemini"

    def test_config_paths_computed(self, tmp_path):
        """Test config computes paths correctly."""
        config = MrZeroConfig(data_dir=tmp_path / ".mrzero")
        assert config.db_path == tmp_path / ".mrzero" / "mrzero.db"
        assert config.vector_db_path == tmp_path / ".mrzero" / "vectordb"

    def test_config_ensure_directories(self, tmp_path):
        """Test ensure_directories creates all needed dirs."""
        config = MrZeroConfig(
            data_dir=tmp_path / ".mrzero",
            output_dir=tmp_path / "output",
        )
        config.ensure_directories()

        assert config.data_dir.exists()
        assert config.output_dir.exists()
        assert config.vector_db_path.exists()

    def test_get_debugger_linux(self, tmp_path):
        """Test get_debugger returns linux debugger on non-Windows."""
        config = MrZeroConfig(data_dir=tmp_path / ".mrzero")
        with patch.object(MrZeroConfig, "is_windows", return_value=False):
            assert config.get_debugger() == "gdb"

    def test_get_debugger_windows(self, tmp_path):
        """Test get_debugger returns windows debugger on Windows."""
        config = MrZeroConfig(data_dir=tmp_path / ".mrzero")
        with patch.object(MrZeroConfig, "is_windows", return_value=True):
            assert config.get_debugger() == "windbg"

    def test_get_fuzzer_linux(self, tmp_path):
        """Test get_fuzzer returns linux fuzzer on non-Windows."""
        config = MrZeroConfig(data_dir=tmp_path / ".mrzero")
        with patch.object(MrZeroConfig, "is_windows", return_value=False):
            assert config.get_fuzzer() == "afl++"

    def test_get_fuzzer_windows(self, tmp_path):
        """Test get_fuzzer returns windows fuzzer on Windows."""
        config = MrZeroConfig(data_dir=tmp_path / ".mrzero")
        with patch.object(MrZeroConfig, "is_windows", return_value=True):
            assert config.get_fuzzer() == "winafl"


class TestLLMConfig:
    """Tests for LLMConfig model."""

    def test_default_llm_config(self):
        """Test default LLM configuration."""
        llm = LLMConfig()
        assert llm.provider == "aws_bedrock"
        assert llm.model is None
        assert llm.temperature == 0.1
        assert llm.max_tokens == 4096
        assert llm.aws_region == "us-east-1"

    def test_custom_llm_config(self):
        """Test custom LLM configuration."""
        llm = LLMConfig(
            provider="google_gemini",
            model="gemini-pro",
            temperature=0.7,
            google_project_id="my-project",
        )
        assert llm.provider == "google_gemini"
        assert llm.model == "gemini-pro"
        assert llm.temperature == 0.7
        assert llm.google_project_id == "my-project"


class TestToolPreferences:
    """Tests for ToolPreferences model."""

    def test_default_tool_preferences(self):
        """Test default tool preferences."""
        tools = ToolPreferences()
        assert "ghidra" in tools.disassembly
        assert "opengrep" in tools.sast_tools
        assert tools.debugger_linux == "gdb"
        assert tools.debugger_windows == "windbg"

    def test_custom_tool_preferences(self):
        """Test custom tool preferences."""
        tools = ToolPreferences(
            disassembly=["radare2", "ghidra"],
            sast_tools=["opengrep"],
            debugger_linux="lldb",
        )
        assert tools.disassembly == ["radare2", "ghidra"]
        assert tools.sast_tools == ["opengrep"]
        assert tools.debugger_linux == "lldb"


class TestVersionCommand:
    """Tests for version command."""

    def test_version_flag(self):
        """Test --version flag shows version."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "MrZero" in result.output or "version" in result.output.lower()

    def test_version_short_flag(self):
        """Test -v flag shows version."""
        result = runner.invoke(app, ["-v"])
        assert result.exit_code == 0
