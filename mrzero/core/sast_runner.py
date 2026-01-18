"""SAST tool execution service for running security analysis tools."""

import asyncio
import json
import hashlib
import platform
import sys
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
    """Information about the current platform for tool compatibility."""

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

    This class handles OS-aware tool filtering, checking which tools
    are available and compatible with the current platform.
    """

    # Tool platform compatibility matrix
    # Format: tool_name -> {platforms: [...], notes: str}
    TOOL_COMPATIBILITY = {
        # Core SAST tools - available on all platforms
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
        # Heavy analysis tools
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
        # Smart contract tools
        "slither": {
            "platforms": ["linux", "darwin", "windows"],
            "binary": "slither",
            "notes": "Python tool, cross-platform",
        },
        "mythril": {
            "platforms": ["linux", "darwin"],  # Limited Windows support
            "binary": "myth",
            "notes": "Python tool, best on Linux/macOS",
        },
        # Binary analysis tools
        "binwalk": {
            "platforms": ["linux", "darwin"],  # Limited Windows support
            "binary": "binwalk",
            "notes": "Linux/macOS, requires various extractors",
        },
        "strings": {
            "platforms": ["linux", "darwin"],  # Built-in on Unix
            "binary": "strings",
            "notes": "Unix built-in",
        },
        "ropgadget": {
            "platforms": ["linux", "darwin", "windows"],
            "binary": "ROPgadget",
            "notes": "Python tool, cross-platform",
        },
        # Code analysis tools
        "joern": {
            "platforms": ["linux", "darwin"],
            "binary": "joern",
            "notes": "JVM-based, Linux/macOS recommended",
        },
        # Dynamic analysis tools
        "pwntools": {
            "platforms": ["linux", "darwin"],
            "binary": None,  # Python library
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
        "afl": {
            "platforms": ["linux"],
            "binary": "afl-fuzz",
            "notes": "AFL++ fuzzer, Linux only",
        },
        "metasploit": {
            "platforms": ["linux", "darwin", "windows"],
            "binary": "msfconsole",
            "notes": "Penetration testing framework",
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
        """Check if a tool is compatible with the current platform.

        Args:
            tool_name: Name of the tool.

        Returns:
            True if compatible with current platform.
        """
        tool_info = self.TOOL_COMPATIBILITY.get(tool_name)
        if tool_info is None:
            # Unknown tool - assume compatible and let availability check handle it
            return True

        return self.platform.system in tool_info.get("platforms", [])

    def is_available(self, tool_name: str) -> bool:
        """Check if a tool is available on the system.

        This combines platform compatibility check with actual binary availability.

        Args:
            tool_name: Name of the tool.

        Returns:
            True if tool is available and compatible.
        """
        # Check cache first
        if tool_name in self._availability_cache:
            return self._availability_cache[tool_name]

        # Check platform compatibility
        if not self.is_compatible(tool_name):
            self._availability_cache[tool_name] = False
            return False

        # Check if binary exists
        import shutil

        tool_info = self.TOOL_COMPATIBILITY.get(tool_name, {})
        binary_name = tool_info.get("binary", tool_name)

        # Handle tools that don't have a binary (e.g., Python libraries)
        if binary_name is None:
            # For Python libraries, assume available if platform compatible
            # Actual availability check happens in the tool wrapper
            self._availability_cache[tool_name] = True
            return True

        available = shutil.which(binary_name) is not None
        self._availability_cache[tool_name] = available
        return available

    def get_available_tools(self) -> list[str]:
        """Get list of all available tools on this platform.

        Returns:
            List of available tool names.
        """
        available = []
        for tool_name in self.TOOL_COMPATIBILITY:
            if self.is_available(tool_name):
                available.append(tool_name)
        return available

    def get_unavailable_tools(self) -> dict[str, str]:
        """Get dict of unavailable tools with reasons.

        Returns:
            Dict mapping tool name to reason it's unavailable.
        """
        unavailable = {}
        for tool_name, tool_info in self.TOOL_COMPATIBILITY.items():
            if not self.is_compatible(tool_name):
                unavailable[tool_name] = f"Not compatible with {self.platform.system}"
            elif not self.is_available(tool_name):
                binary = tool_info.get("binary", tool_name)
                unavailable[tool_name] = f"Binary '{binary}' not found in PATH"
        return unavailable

    def get_tool_info(self, tool_name: str) -> dict[str, Any] | None:
        """Get information about a specific tool.

        Args:
            tool_name: Name of the tool.

        Returns:
            Tool info dict or None if unknown tool.
        """
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

    This service executes external SAST tools and collects their findings.
    It does NOT make any decisions - findings are passed to the LLM for analysis.

    Features:
    - Automatic caching of tool results in SQLite to avoid redundant execution
    - Parallel execution of multiple tools
    - Deduplication of findings
    - OS-aware tool filtering

    Required tools must be installed before using MrZero.
    """

    # Cache TTL in hours for different tool types
    CACHE_TTL = {
        "opengrep": 24,  # Rules don't change often
        "gitleaks": 24,  # Secrets detection is stable
        "trivy": 12,  # Vulnerability DBs update more frequently
        "slither": 24,  # Smart contract analysis is stable
        "codeql": 24,  # Heavy tool, cache longer
        "infer": 24,  # Heavy tool, cache longer
        "bearer": 24,  # Rules don't change often
        "appinspector": 24,  # Pattern matching is stable
        "default": 12,
    }

    def __init__(self, target_path: Path, session_id: str | None = None) -> None:
        """Initialize the SAST runner.

        Args:
            target_path: Path to the target codebase.
            session_id: Optional session ID for cache scoping.
        """
        self.target_path = target_path
        self.config = get_config()
        self.session_id = session_id
        self._db_manager = None
        self._cache_enabled = True
        self._tool_compat = ToolCompatibility()

    @property
    def db_manager(self):
        """Lazy-load database manager for caching."""
        if self._db_manager is None and self.config.db_path:
            try:
                from mrzero.core.memory.sqlite import SQLiteManager

                self._db_manager = SQLiteManager(self.config.db_path)
            except Exception:
                self._cache_enabled = False
        return self._db_manager

    def _get_cache_key(self, tool: str, args: dict[str, Any] | None = None) -> str:
        """Generate a unique cache key for a tool execution.

        The cache key includes:
        - Tool name
        - Target path
        - Tool arguments (if any)
        - Hash of file modification times (to invalidate on changes)

        Args:
            tool: Tool name.
            args: Optional tool arguments.

        Returns:
            Cache key string.
        """
        # Include target path and tool name
        key_parts = [tool, str(self.target_path)]

        # Include arguments if provided
        if args:
            key_parts.append(json.dumps(args, sort_keys=True))

        # Include modification time hash of target directory
        # This invalidates cache when files change
        try:
            mtime_hash = self._compute_target_hash()
            key_parts.append(mtime_hash)
        except Exception:
            # If we can't compute hash, add timestamp to prevent caching
            import time

            key_parts.append(str(time.time()))

        key_data = ":".join(key_parts)
        return hashlib.sha256(key_data.encode()).hexdigest()

    def _compute_target_hash(self) -> str:
        """Compute a hash of the target directory based on file mtimes.

        This allows cache invalidation when source files change.

        Returns:
            Hash string representing current state of target.
        """
        # Get mtimes of relevant source files (limit for performance)
        code_extensions = {".py", ".js", ".ts", ".java", ".go", ".c", ".cpp", ".sol", ".rb", ".php"}
        mtimes = []

        for i, file_path in enumerate(self.target_path.rglob("*")):
            if i > 1000:  # Limit files checked for performance
                break
            if file_path.is_file() and file_path.suffix.lower() in code_extensions:
                try:
                    mtimes.append(f"{file_path}:{file_path.stat().st_mtime}")
                except Exception:
                    continue

        # Sort for consistency
        mtimes.sort()
        combined = "\n".join(mtimes[:500])  # Limit for hash computation
        return hashlib.sha256(combined.encode()).hexdigest()[:16]

    def _get_cached_findings(
        self, tool: str, args: dict[str, Any] | None = None
    ) -> list[SASTFinding] | None:
        """Get cached findings for a tool if available.

        Args:
            tool: Tool name.
            args: Tool arguments.

        Returns:
            List of cached findings or None if not cached.
        """
        if not self._cache_enabled or not self.db_manager:
            return None

        try:
            cache_key = self._get_cache_key(tool, args)
            cached = self.db_manager.get_cached_result(
                tool_name=tool,
                args=args or {},
                target_file=str(self.target_path),
            )

            if cached and "findings" in cached:
                # Reconstruct SASTFinding objects from cached data
                return [SASTFinding.from_dict(f) for f in cached["findings"]]

        except Exception:
            # Cache retrieval failed, proceed without cache
            pass

        return None

    def _cache_findings(
        self, tool: str, findings: list[SASTFinding], args: dict[str, Any] | None = None
    ) -> None:
        """Cache findings for a tool.

        Args:
            tool: Tool name.
            findings: List of findings to cache.
            args: Tool arguments.
        """
        if not self._cache_enabled or not self.db_manager:
            return

        try:
            ttl = self.CACHE_TTL.get(tool, self.CACHE_TTL["default"])
            self.db_manager.cache_result(
                tool_name=tool,
                args=args or {},
                target_file=str(self.target_path),
                output={"findings": [f.to_dict() for f in findings]},
                ttl_hours=ttl,
            )
        except Exception:
            # Cache storage failed, continue without caching
            pass

    async def run_all_available(self, use_cache: bool = True) -> list[SASTFinding]:
        """Run all available SAST tools in parallel.

        Args:
            use_cache: Whether to use cached results if available.

        Returns:
            Aggregated findings from all tools. Returns empty list if no tools available.
        """
        tasks = []
        tools_to_run = []

        # Check which tools are available and run them
        if self._is_tool_available("opengrep"):
            tasks.append(self._run_with_cache("opengrep", self.run_opengrep, use_cache))
            tools_to_run.append("opengrep")

        if self._is_tool_available("gitleaks"):
            tasks.append(self._run_with_cache("gitleaks", self.run_gitleaks, use_cache))
            tools_to_run.append("gitleaks")

        if self._is_tool_available("trivy"):
            tasks.append(self._run_with_cache("trivy", self.run_trivy, use_cache))
            tools_to_run.append("trivy")

        # For Solidity projects, run Slither
        if self._has_solidity_files():
            if self._is_tool_available("slither"):
                tasks.append(self._run_with_cache("slither", self.run_slither, use_cache))
                tools_to_run.append("slither")

        # No fallback - if no tools are available, return empty list
        # The LLM will analyze code directly without SAST hints
        if not tasks:
            return []

        # Run all tools in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate findings
        all_findings = []
        for i, result in enumerate(results):
            if isinstance(result, list):
                all_findings.extend(result)
            elif isinstance(result, Exception):
                # Log but continue - tool failures shouldn't stop analysis
                pass

        # Deduplicate findings
        return self._deduplicate_findings(all_findings)

    async def _run_with_cache(
        self,
        tool: str,
        run_func,
        use_cache: bool = True,
    ) -> list[SASTFinding]:
        """Run a tool with caching support.

        Args:
            tool: Tool name.
            run_func: Async function to run the tool.
            use_cache: Whether to use cache.

        Returns:
            List of findings.
        """
        # Check cache first
        if use_cache:
            cached = self._get_cached_findings(tool)
            if cached is not None:
                return cached

        # Run the tool
        findings = await run_func()

        # Cache the results
        if use_cache and findings:
            self._cache_findings(tool, findings)

        return findings

    def _is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available on the system.

        Uses the ToolCompatibility class for OS-aware checking.

        Args:
            tool_name: Name of the tool.

        Returns:
            True if tool is available and compatible with current platform.
        """
        return self._tool_compat.is_available(tool_name)

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
            "available": self.get_available_tools(),
            "unavailable": self._tool_compat.get_unavailable_tools(),
        }

    def _has_solidity_files(self) -> bool:
        """Check if the target has Solidity files."""
        return any(self.target_path.rglob("*.sol"))

    async def run_opengrep(self) -> list[SASTFinding]:
        """Run Opengrep SAST scanner.

        Returns:
            List of findings from Opengrep.
        """
        findings = []

        # Build command - use auto config for common vulnerability rules
        cmd = [
            "opengrep",
            "scan",
            "--json",
            "--config",
            "auto",  # Auto-detect rules
            str(self.target_path),
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=600,  # 10 minute timeout
            )

            if stdout:
                try:
                    results = json.loads(stdout.decode())
                    for result in results.get("results", []):
                        findings.append(
                            SASTFinding(
                                rule_id=result.get("check_id", "unknown"),
                                message=result.get("extra", {}).get("message", ""),
                                severity=result.get("extra", {}).get("severity", "WARNING"),
                                file_path=result.get("path", ""),
                                line_start=result.get("start", {}).get("line", 0),
                                line_end=result.get("end", {}).get("line", 0),
                                code_snippet=result.get("extra", {}).get("lines", ""),
                                tool="opengrep",
                                metadata=result.get("extra", {}).get("metadata", {}),
                            )
                        )
                except json.JSONDecodeError:
                    pass

        except asyncio.TimeoutError:
            pass
        except FileNotFoundError:
            pass

        return findings

    async def run_gitleaks(self) -> list[SASTFinding]:
        """Run Gitleaks secret scanner.

        Returns:
            List of secret findings.
        """
        findings = []

        cmd = [
            "gitleaks",
            "detect",
            "--source",
            str(self.target_path),
            "--report-format",
            "json",
            "--report-path",
            "/dev/stdout",
            "--no-git",  # Scan files, not git history
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=300,
            )

            if stdout:
                try:
                    results = json.loads(stdout.decode())
                    for result in results if isinstance(results, list) else []:
                        findings.append(
                            SASTFinding(
                                rule_id=result.get("RuleID", "secret"),
                                message=f"Secret detected: {result.get('Description', 'Unknown secret')}",
                                severity="HIGH",
                                file_path=result.get("File", ""),
                                line_start=result.get("StartLine", 0),
                                line_end=result.get("EndLine", 0),
                                code_snippet=result.get("Secret", "")[:50]
                                + "...",  # Truncate secret
                                tool="gitleaks",
                                metadata={
                                    "entropy": result.get("Entropy", 0),
                                    "match": result.get("Match", ""),
                                },
                            )
                        )
                except json.JSONDecodeError:
                    pass

        except (asyncio.TimeoutError, FileNotFoundError):
            pass

        return findings

    async def run_trivy(self) -> list[SASTFinding]:
        """Run Trivy vulnerability scanner.

        Returns:
            List of findings.
        """
        findings = []

        cmd = [
            "trivy",
            "fs",
            "--format",
            "json",
            "--scanners",
            "vuln,secret,misconfig",
            str(self.target_path),
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=600,
            )

            if stdout:
                try:
                    results = json.loads(stdout.decode())
                    for result in results.get("Results", []):
                        target = result.get("Target", "")

                        # Vulnerability findings
                        for vuln in result.get("Vulnerabilities", []) or []:
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
                                        "references": vuln.get("References", []),
                                    },
                                )
                            )

                        # Misconfig findings
                        for misconfig in result.get("Misconfigurations", []) or []:
                            findings.append(
                                SASTFinding(
                                    rule_id=misconfig.get("ID", "unknown"),
                                    message=misconfig.get("Message", ""),
                                    severity=misconfig.get("Severity", "UNKNOWN"),
                                    file_path=target,
                                    line_start=misconfig.get("CauseMetadata", {}).get(
                                        "StartLine", 0
                                    ),
                                    line_end=misconfig.get("CauseMetadata", {}).get("EndLine", 0),
                                    code_snippet=misconfig.get("CauseMetadata", {})
                                    .get("Code", {})
                                    .get("Lines", [{}])[0]
                                    .get("Content", ""),
                                    tool="trivy",
                                    metadata={
                                        "type": misconfig.get("Type", ""),
                                        "resolution": misconfig.get("Resolution", ""),
                                    },
                                )
                            )

                except json.JSONDecodeError:
                    pass

        except (asyncio.TimeoutError, FileNotFoundError):
            pass

        return findings

    async def run_slither(self) -> list[SASTFinding]:
        """Run Slither for Solidity analysis.

        Returns:
            List of smart contract findings.
        """
        findings = []

        cmd = [
            "slither",
            str(self.target_path),
            "--json",
            "-",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=600,
            )

            if stdout:
                try:
                    results = json.loads(stdout.decode())
                    for detector in results.get("results", {}).get("detectors", []):
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
                                line_start=first_element.get("source_mapping", {}).get(
                                    "lines", [0]
                                )[0],
                                line_end=first_element.get("source_mapping", {}).get("lines", [0])[
                                    -1
                                ]
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
                except json.JSONDecodeError:
                    pass

        except (asyncio.TimeoutError, FileNotFoundError):
            pass

        return findings

    async def run_codeql(self, language: str | None = None) -> list[SASTFinding]:
        """Run CodeQL analysis if available.

        Args:
            language: Target language (auto-detected if not specified).

        Returns:
            List of findings.
        """
        if not self._is_tool_available("codeql"):
            return []

        # Check cache first
        cached = self._get_cached_findings("codeql", {"language": language})
        if cached is not None:
            return cached

        try:
            from mrzero.tools.code_analysis import CodeQLTool

            tool = CodeQLTool()
            result = await tool.run(str(self.target_path), language=language)

            if result.success:
                findings = []
                for f in result.data.get("findings", []):
                    findings.append(
                        SASTFinding(
                            rule_id=f.get("rule_id", "unknown"),
                            message=f.get("message", ""),
                            severity=f.get("severity", "WARNING").upper(),
                            file_path=f.get("file", ""),
                            line_start=f.get("line_start", 0),
                            line_end=f.get("line_end", 0),
                            code_snippet="",
                            tool="codeql",
                            metadata={},
                        )
                    )

                # Cache results
                self._cache_findings("codeql", findings, {"language": language})
                return findings

        except Exception:
            pass

        return []

    def _deduplicate_findings(self, findings: list[SASTFinding]) -> list[SASTFinding]:
        """Remove duplicate findings based on file+line+rule.

        Args:
            findings: List of findings to deduplicate.

        Returns:
            Deduplicated list.
        """
        seen = set()
        unique = []

        for finding in findings:
            key = f"{finding.file_path}:{finding.line_start}:{finding.rule_id}"
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    def clear_cache(self, tool: str | None = None) -> None:
        """Clear cached results.

        Args:
            tool: Specific tool to clear cache for, or None for all.
        """
        # For now, cache is managed by SQLite with TTL
        # This method is a placeholder for manual cache invalidation
        pass


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
