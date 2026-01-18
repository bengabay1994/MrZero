"""Configuration management for MrZero."""

import json
import platform
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMConfig(BaseModel):
    """LLM configuration."""

    provider: str = "aws_bedrock"  # aws_bedrock, google_gemini
    model: str | None = None  # None = use provider default
    temperature: float = 0.1
    max_tokens: int = 4096

    # AWS Bedrock specific
    aws_region: str = "us-east-1"
    aws_profile: str | None = None

    # Google Gemini specific
    google_project_id: str | None = None


class ToolPreferences(BaseModel):
    """Tool preferences for the system."""

    # Disassembly preference order
    disassembly: list[str] = Field(default_factory=lambda: ["ghidra", "ida", "binaryninja"])

    # SAST tools to use
    sast_tools: list[str] = Field(
        default_factory=lambda: ["opengrep", "codeql", "joern", "bearer", "gitleaks"]
    )

    # Debugging tools (OS-dependent)
    debugger_linux: str = "gdb"
    debugger_windows: str = "windbg"

    # Fuzzing tools (OS-dependent)
    fuzzer_linux: str = "afl++"
    fuzzer_windows: str = "winafl"


class MrZeroConfig(BaseSettings):
    """Main configuration for MrZero."""

    model_config = SettingsConfigDict(
        env_prefix="MRZERO_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Data directories
    data_dir: Path = Field(default_factory=lambda: Path.home() / ".mrzero")
    db_path: Path | None = None
    vector_db_path: Path | None = None

    # LLM configuration
    llm: LLMConfig = Field(default_factory=LLMConfig)

    # Tool preferences
    tools: ToolPreferences = Field(default_factory=ToolPreferences)

    # Execution settings
    max_build_attempts: int = 5
    hunter_verifier_max_iterations: int = 3
    min_true_positives: int = 3

    # Output settings
    output_dir: Path = Field(default_factory=lambda: Path.cwd() / "mrzero_output")

    def __init__(self, **data: Any) -> None:
        """Initialize config with computed paths."""
        super().__init__(**data)
        if self.db_path is None:
            self.db_path = self.data_dir / "mrzero.db"
        if self.vector_db_path is None:
            self.vector_db_path = self.data_dir / "vectordb"

    def ensure_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if self.vector_db_path:
            self.vector_db_path.mkdir(parents=True, exist_ok=True)

    @classmethod
    def get_os_info(cls) -> dict[str, str]:
        """Get current OS information."""
        return {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        }

    @classmethod
    def is_linux(cls) -> bool:
        """Check if running on Linux."""
        return platform.system() == "Linux"

    @classmethod
    def is_windows(cls) -> bool:
        """Check if running on Windows."""
        return platform.system() == "Windows"

    @classmethod
    def is_macos(cls) -> bool:
        """Check if running on macOS."""
        return platform.system() == "Darwin"

    def get_debugger(self) -> str:
        """Get appropriate debugger for current OS."""
        if self.is_windows():
            return self.tools.debugger_windows
        return self.tools.debugger_linux

    def get_fuzzer(self) -> str:
        """Get appropriate fuzzer for current OS."""
        if self.is_windows():
            return self.tools.fuzzer_windows
        return self.tools.fuzzer_linux

    def save(self, path: Path | None = None) -> None:
        """Save configuration to file.

        Args:
            path: Path to save to. Defaults to data_dir/config.json.
        """
        save_path = path or (self.data_dir / "config.json")
        save_path.parent.mkdir(parents=True, exist_ok=True)
        with open(save_path, "w") as f:
            json.dump(self.model_dump(mode="json"), f, indent=2, default=str)

    @classmethod
    def load(cls, path: Path | None = None) -> "MrZeroConfig":
        """Load configuration from file.

        Args:
            path: Path to load from. Defaults to ~/.mrzero/config.json.

        Returns:
            Loaded configuration or default config if file doesn't exist.
        """
        load_path = path or (Path.home() / ".mrzero" / "config.json")
        if load_path.exists():
            with open(load_path) as f:
                data = json.load(f)
            return cls(**data)
        return cls()


# Global config instance
_config: MrZeroConfig | None = None


def get_config() -> MrZeroConfig:
    """Get the global configuration instance.

    Returns:
        MrZeroConfig instance.
    """
    global _config
    if _config is None:
        _config = MrZeroConfig.load()
    return _config


def set_config(config: MrZeroConfig) -> None:
    """Set the global configuration instance.

    Args:
        config: Configuration to set.
    """
    global _config
    _config = config
