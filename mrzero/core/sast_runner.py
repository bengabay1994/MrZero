"""SAST tool execution service for running security analysis tools.

DEPRECATED: This module is deprecated. Use mrzero.core.tools_service.ToolsService instead.
This module now serves as a thin wrapper around ToolsService for backward compatibility.
"""

import platform
import sys
import warnings
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from mrzero.core.config import get_config


@dataclass
class SASTFinding:
    """A finding from a SAST tool."""

    rule_id: str
    message: str
    severity: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    tool: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for caching."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SASTFinding":
        """Create from dictionary (for cache retrieval)."""
        return cls(**data)


class PlatformInfo:
    """Information about the current platform for tool compatibility.

    DEPRECATED: This class is kept for backward compatibility.
    """

    def __init__(self) -> None:
        """Initialize platform detection."""
        self._system = platform.system().lower()
        self._machine = platform.machine().lower()
        self._python_version = sys.version_info

    @property
    def system(self) -> str:
        """Get the operating system name."""
        return self._system

    @property
    def is_linux(self) -> bool:
        """Check if running on Linux."""
        return self._system == "linux"

    @property
    def is_macos(self) -> bool:
        """Check if running on macOS."""
        return self._system == "darwin"

    @property
    def is_windows(self) -> bool:
        """Check if running on Windows."""
        return self._system == "windows"

    @property
    def is_arm(self) -> bool:
        """Check if running on ARM architecture."""
        return "arm" in self._machine or "aarch" in self._machine

    @property
    def is_x86(self) -> bool:
        """Check if running on x86 architecture."""
        return "x86" in self._machine or "amd64" in self._machine or "i686" in self._machine

    def to_dict(self) -> dict[str, Any]:
        """Get platform info as dictionary."""
        return {
            "system": self._system,
            "machine": self._machine,
            "is_linux": self.is_linux,
            "is_macos": self.is_macos,
            "is_windows": self.is_windows,
            "is_arm": self.is_arm,
            "is_x86": self.is_x86,
            "python_version": f"{self._python_version.major}.{self._python_version.minor}.{self._python_version.micro}",
        }


# Global platform info instance
_platform_info: PlatformInfo | None = None


def get_platform_info() -> PlatformInfo:
    """Get the global platform info instance."""
    global _platform_info
    if _platform_info is None:
        _platform_info = PlatformInfo()
    return _platform_info


class ToolCompatibility:
    """Tool compatibility and availability checker.

    DEPRECATED: This class is kept for backward compatibility.
    Use mrzero.core.tools_service.ToolsService instead.
    """

    # Tool platform compatibility matrix
    TOOL_COMPATIBILITY = {
        "opengrep": {
            "platforms": ["linux", "darwin", "windows"],
            "binary": "opengrep",
            "notes": "Semgrep fork, cross-platform",
        },
        "gitleaks": {
            "platforms": ["linux", "darwin", "windows"],
            "binary": "gitleaks",
            "notes": "Go binary, cross-platform",
        },
        "trivy": {
            "platforms": ["linux", "darwin", "windows"],
            "binary": "trivy",
            "notes": "Go binary, cross-platform",
        },
        "slither": {
            "platforms": ["linux", "darwin", "windows"],
            "binary": "slither",
            "notes": "Python tool, cross-platform",
        },
        "mythril": {
            "platforms": ["linux", "darwin"],
            "binary": "myth",
            "notes": "Python tool, best on Linux/macOS",
        },
        "binwalk": {
            "platforms": ["linux", "darwin"],
            "binary": "binwalk",
            "notes": "Linux/macOS, requires various extractors",
        },
        "strings": {
            "platforms": ["linux", "darwin"],
            "binary": "strings",
            "notes": "Unix built-in",
        },
        "ropgadget": {
            "platforms": ["linux", "darwin", "windows"],
            "binary": "ROPgadget",
            "notes": "Python tool, cross-platform",
        },
        "pwntools": {
            "platforms": ["linux", "darwin"],
            "binary": None,
            "notes": "Python exploit development library, best on Linux",
        },
        "frida": {
            "platforms": ["linux", "darwin", "windows"],
            "binary": "frida",
            "notes": "Dynamic instrumentation framework, cross-platform",
        },
        "gdb": {
            "platforms": ["linux", "darwin"],
            "binary": "gdb",
            "notes": "GNU Debugger, enhanced with pwndbg",
        },
        "metasploit": {
            "platforms": ["linux", "darwin", "windows"],
            "binary": "msfconsole",
            "notes": "Penetration testing framework",
        },
        # Additional SAST tools
        "codeql": {
            "platforms": ["linux", "darwin", "windows"],
            "binary": "codeql",
            "notes": "GitHub CodeQL, requires setup",
        },
        "infer": {
            "platforms": ["linux", "darwin"],  # No Windows support
            "binary": "infer",
            "notes": "Facebook Infer, Linux/macOS only",
        },
        "bearer": {
            "platforms": ["linux", "darwin", "windows"],
            "binary": "bearer",
            "notes": "Go binary, cross-platform",
        },
        "appinspector": {
            "platforms": ["linux", "darwin", "windows"],
            "binary": "appinspector",
            "notes": ".NET tool, cross-platform with .NET runtime",
        },
        "joern": {
            "platforms": ["linux", "darwin"],
            "binary": "joern",
            "notes": "JVM-based, Linux/macOS recommended",
        },
        "afl": {
            "platforms": ["linux"],
            "binary": "afl-fuzz",
            "notes": "AFL++ fuzzer, Linux only",
        },
        "msfvenom": {
            "platforms": ["linux", "darwin", "windows"],
            "binary": "msfvenom",
            "notes": "Payload generator (part of Metasploit)",
        },
        "windbg": {
            "platforms": ["windows"],
            "binary": "cdb",
            "notes": "Windows Debugger, Windows only",
        },
        "winafl": {
            "platforms": ["windows"],
            "binary": "afl-fuzz.exe",
            "notes": "Windows AFL fuzzer, Windows only",
        },
    }

    def __init__(self) -> None:
        """Initialize tool compatibility checker."""
        self.platform = get_platform_info()
        self._availability_cache: dict[str, bool] = {}

    def is_compatible(self, tool_name: str) -> bool:
        """Check if a tool is compatible with the current platform."""
        tool_info = self.TOOL_COMPATIBILITY.get(tool_name)
        if tool_info is None:
            return True
        return self.platform.system in tool_info.get("platforms", [])

    def is_available(self, tool_name: str) -> bool:
        """Check if a tool is available on the system."""
        if tool_name in self._availability_cache:
            return self._availability_cache[tool_name]

        if not self.is_compatible(tool_name):
            self._availability_cache[tool_name] = False
            return False

        import shutil

        tool_info = self.TOOL_COMPATIBILITY.get(tool_name, {})
        binary_name = tool_info.get("binary", tool_name)

        if binary_name is None:
            self._availability_cache[tool_name] = True
            return True

        available = shutil.which(binary_name) is not None
        self._availability_cache[tool_name] = available
        return available

    def get_available_tools(self) -> list[str]:
        """Get list of all available tools on this platform."""
        available = []
        for tool_name in self.TOOL_COMPATIBILITY:
            if self.is_available(tool_name):
                available.append(tool_name)
        return available

    def get_unavailable_tools(self) -> dict[str, str]:
        """Get dict of unavailable tools with reasons."""
        unavailable = {}
        for tool_name, tool_info in self.TOOL_COMPATIBILITY.items():
            if not self.is_compatible(tool_name):
                unavailable[tool_name] = f"Not compatible with {self.platform.system}"
            elif not self.is_available(tool_name):
                binary = tool_info.get("binary", tool_name)
                unavailable[tool_name] = f"Binary '{binary}' not found in PATH"
        return unavailable

    def get_tool_info(self, tool_name: str) -> dict[str, Any] | None:
        """Get information about a specific tool."""
        tool_info = self.TOOL_COMPATIBILITY.get(tool_name)
        if tool_info is None:
            return None

        return {
            **tool_info,
            "name": tool_name,
            "compatible": self.is_compatible(tool_name),
            "available": self.is_available(tool_name),
        }


class SASTRunner:
    """Service for running SAST tools and aggregating results.

    DEPRECATED: Use mrzero.core.tools_service.ToolsService instead.

    This class now wraps ToolsService for backward compatibility.
    """

    def __init__(self, target_path: Path, session_id: str | None = None) -> None:
        """Initialize the SAST runner.

        Args:
            target_path: Path to the target codebase.
            session_id: Optional session ID for cache scoping.
        """
        warnings.warn(
            "SASTRunner is deprecated. Use mrzero.core.tools_service.ToolsService instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self.target_path = target_path
        self.session_id = session_id
        self._tools_service = None
        self._tool_compat = ToolCompatibility()

    async def _get_tools_service(self):
        """Get initialized tools service."""
        if self._tools_service is None:
            from mrzero.core.tools_service import get_initialized_tools_service

            self._tools_service = await get_initialized_tools_service()
        return self._tools_service

    async def run_all_available(self, use_cache: bool = True) -> list[SASTFinding]:
        """Run all available SAST tools in parallel.

        Args:
            use_cache: Whether to use cached results if available.

        Returns:
            Aggregated findings from all tools.
        """
        service = await self._get_tools_service()
        results = await service.run_all_sast(self.target_path)

        # Convert ToolExecutionResults to SASTFindings
        findings = []
        for result in results:
            if not result.success or not result.output:
                continue

            findings.extend(self._convert_result_to_findings(result))

        return findings

    def _convert_result_to_findings(self, result) -> list[SASTFinding]:
        """Convert a ToolExecutionResult to SASTFindings."""
        findings = []

        if result.tool == "opengrep" and isinstance(result.output, dict):
            for item in result.output.get("results", []):
                findings.append(
                    SASTFinding(
                        rule_id=item.get("check_id", "unknown"),
                        message=item.get("extra", {}).get("message", ""),
                        severity=item.get("extra", {}).get("severity", "WARNING"),
                        file_path=item.get("path", ""),
                        line_start=item.get("start", {}).get("line", 0),
                        line_end=item.get("end", {}).get("line", 0),
                        code_snippet=item.get("extra", {}).get("lines", ""),
                        tool="opengrep",
                        metadata=item.get("extra", {}).get("metadata", {}),
                    )
                )

        elif result.tool == "gitleaks" and isinstance(result.output, list):
            for item in result.output:
                findings.append(
                    SASTFinding(
                        rule_id=item.get("RuleID", "secret"),
                        message=f"Secret detected: {item.get('Description', 'Unknown secret')}",
                        severity="HIGH",
                        file_path=item.get("File", ""),
                        line_start=item.get("StartLine", 0),
                        line_end=item.get("EndLine", 0),
                        code_snippet=item.get("Secret", "")[:50] + "...",
                        tool="gitleaks",
                        metadata={
                            "entropy": item.get("Entropy", 0),
                            "match": item.get("Match", ""),
                        },
                    )
                )

        elif result.tool == "trivy" and isinstance(result.output, dict):
            for trivy_result in result.output.get("Results", []):
                target = trivy_result.get("Target", "")
                for vuln in trivy_result.get("Vulnerabilities", []) or []:
                    findings.append(
                        SASTFinding(
                            rule_id=vuln.get("VulnerabilityID", "unknown"),
                            message=vuln.get("Title", "") or vuln.get("Description", ""),
                            severity=vuln.get("Severity", "UNKNOWN"),
                            file_path=target,
                            line_start=0,
                            line_end=0,
                            code_snippet=f"{vuln.get('PkgName', '')}@{vuln.get('InstalledVersion', '')}",
                            tool="trivy",
                            metadata={
                                "cve": vuln.get("VulnerabilityID", ""),
                                "fixed_version": vuln.get("FixedVersion", ""),
                            },
                        )
                    )

        elif result.tool == "slither" and isinstance(result.output, dict):
            for detector in result.output.get("results", {}).get("detectors", []):
                elements = detector.get("elements", [])
                first_element = elements[0] if elements else {}
                findings.append(
                    SASTFinding(
                        rule_id=detector.get("check", "unknown"),
                        message=detector.get("description", ""),
                        severity=detector.get("impact", "Medium").upper(),
                        file_path=first_element.get("source_mapping", {}).get(
                            "filename_relative", ""
                        ),
                        line_start=first_element.get("source_mapping", {}).get("lines", [0])[0],
                        line_end=first_element.get("source_mapping", {}).get("lines", [0])[-1]
                        if first_element.get("source_mapping", {}).get("lines")
                        else 0,
                        code_snippet="",
                        tool="slither",
                        metadata={
                            "confidence": detector.get("confidence", ""),
                            "elements": len(elements),
                        },
                    )
                )

        return findings

    def get_available_tools(self) -> list[str]:
        """Get list of all available SAST tools.

        Returns:
            List of available tool names.
        """
        return self._tool_compat.get_available_tools()

    def get_platform_info(self) -> dict[str, Any]:
        """Get information about the current platform.

        Returns:
            Platform info dictionary.
        """
        return get_platform_info().to_dict()

    def get_tool_status(self) -> dict[str, Any]:
        """Get status of all known tools.

        Returns:
            Dict with available and unavailable tools.
        """
        return {
            "platform": self.get_platform_info(),
            "available": self._tool_compat.get_available_tools(),
            "unavailable": self._tool_compat.get_unavailable_tools(),
        }

    def _is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available.

        Args:
            tool_name: Name of the tool.

        Returns:
            True if tool is available.
        """
        return self._tool_compat.is_available(tool_name)


def severity_to_score(severity: str) -> int:
    """Convert severity string to numeric score.

    Args:
        severity: Severity string (CRITICAL, HIGH, MEDIUM, LOW, INFO).

    Returns:
        Numeric score 0-100.
    """
    severity_map = {
        "CRITICAL": 95,
        "HIGH": 80,
        "MEDIUM": 55,
        "LOW": 30,
        "INFO": 15,
        "WARNING": 50,
        "UNKNOWN": 40,
    }
    return severity_map.get(severity.upper(), 40)
