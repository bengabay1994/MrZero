"""Security Tool Definitions for LLM Tool Calling.

This module provides tool definitions that can be used with LLM function calling.
Each tool is defined with its parameters and an executor that bridges to the
actual tool implementations in mrzero.tools.
"""

import json
from typing import Any

from mrzero.core.llm.tool_calling import (
    ToolDefinition,
    ToolParameter,
    ToolParameterType,
    ToolRegistry,
    ToolResult,
)
from mrzero.tools import (
    OpengrepTool,
    GitleaksTool,
    TrivyTool,
    BinwalkTool,
    StringsTool,
    ROPgadgetTool,
)


def create_security_tool_registry() -> ToolRegistry:
    """Create a tool registry with all security tools.

    Returns:
        ToolRegistry with security tools registered.
    """
    registry = ToolRegistry()

    # Register each tool
    _register_opengrep(registry)
    _register_gitleaks(registry)
    _register_trivy(registry)
    _register_binwalk(registry)
    _register_strings(registry)
    _register_ropgadget(registry)
    _register_read_file(registry)
    _register_list_files(registry)
    _register_search_code(registry)

    return registry


def _register_opengrep(registry: ToolRegistry) -> None:
    """Register the Opengrep tool."""
    definition = ToolDefinition(
        name="opengrep_scan",
        description="""Run Opengrep (Semgrep OSS) static analysis to find security vulnerabilities in code.
Use this tool to scan source code for common vulnerability patterns like SQL injection, XSS, command injection, etc.
Returns findings with file paths, line numbers, and vulnerability descriptions.""",
        parameters=[
            ToolParameter(
                name="target",
                description="Path to the directory or file to scan",
                type=ToolParameterType.STRING,
                required=True,
            ),
            ToolParameter(
                name="rules_path",
                description="Optional path to custom rules file or directory. If not specified, uses default security rules.",
                type=ToolParameterType.STRING,
                required=False,
            ),
        ],
    )

    async def executor(tool_call_id: str, target: str, rules_path: str | None = None) -> ToolResult:
        tool = OpengrepTool()
        if not tool.is_available():
            return ToolResult(
                tool_call_id=tool_call_id,
                name="opengrep_scan",
                success=False,
                output="",
                error="Opengrep is not installed on this system",
            )

        result = await tool.run(target=target, rules_path=rules_path)

        return ToolResult(
            tool_call_id=tool_call_id,
            name="opengrep_scan",
            success=result.success,
            output=json.dumps(result.data, indent=2) if result.success else "",
            error=result.error,
        )

    registry.register(definition, executor)


def _register_gitleaks(registry: ToolRegistry) -> None:
    """Register the Gitleaks tool."""
    definition = ToolDefinition(
        name="gitleaks_scan",
        description="""Run Gitleaks to detect hardcoded secrets and sensitive information in code.
Use this tool to find API keys, passwords, private keys, and other credentials that shouldn't be in source code.
Returns findings with file paths, line numbers, and secret types.""",
        parameters=[
            ToolParameter(
                name="target",
                description="Path to the directory to scan for secrets",
                type=ToolParameterType.STRING,
                required=True,
            ),
        ],
    )

    async def executor(tool_call_id: str, target: str) -> ToolResult:
        tool = GitleaksTool()
        if not tool.is_available():
            return ToolResult(
                tool_call_id=tool_call_id,
                name="gitleaks_scan",
                success=False,
                output="",
                error="Gitleaks is not installed on this system",
            )

        result = await tool.run(target=target)

        return ToolResult(
            tool_call_id=tool_call_id,
            name="gitleaks_scan",
            success=result.success,
            output=json.dumps(result.data, indent=2) if result.success else "",
            error=result.error,
        )

    registry.register(definition, executor)


def _register_trivy(registry: ToolRegistry) -> None:
    """Register the Trivy tool."""
    definition = ToolDefinition(
        name="trivy_scan",
        description="""Run Trivy vulnerability scanner to find known CVEs in dependencies and containers.
Use this tool to scan for vulnerabilities in package dependencies (requirements.txt, package.json, etc.) or container images.
Returns findings with CVE IDs, severity levels, and affected packages.""",
        parameters=[
            ToolParameter(
                name="target",
                description="Path to scan (directory for filesystem scan, or image name for container scan)",
                type=ToolParameterType.STRING,
                required=True,
            ),
            ToolParameter(
                name="scan_type",
                description="Type of scan: 'fs' for filesystem, 'image' for container images",
                type=ToolParameterType.STRING,
                required=False,
                default="fs",
                enum=["fs", "image", "config"],
            ),
        ],
    )

    async def executor(tool_call_id: str, target: str, scan_type: str = "fs") -> ToolResult:
        tool = TrivyTool()
        if not tool.is_available():
            return ToolResult(
                tool_call_id=tool_call_id,
                name="trivy_scan",
                success=False,
                output="",
                error="Trivy is not installed on this system",
            )

        result = await tool.run(target=target, scan_type=scan_type)

        return ToolResult(
            tool_call_id=tool_call_id,
            name="trivy_scan",
            success=result.success,
            output=json.dumps(result.data, indent=2) if result.success else "",
            error=result.error,
        )

    registry.register(definition, executor)


def _register_binwalk(registry: ToolRegistry) -> None:
    """Register the Binwalk tool."""
    definition = ToolDefinition(
        name="binwalk_analyze",
        description="""Run Binwalk to analyze binary files for embedded content and firmware signatures.
Use this tool to extract and identify embedded files, firmware headers, compression signatures, etc.
Useful for analyzing firmware, binary executables, and compiled files.""",
        parameters=[
            ToolParameter(
                name="target",
                description="Path to the binary file to analyze",
                type=ToolParameterType.STRING,
                required=True,
            ),
            ToolParameter(
                name="extract",
                description="Whether to extract embedded files (default: false)",
                type=ToolParameterType.BOOLEAN,
                required=False,
                default=False,
            ),
        ],
    )

    async def executor(tool_call_id: str, target: str, extract: bool = False) -> ToolResult:
        tool = BinwalkTool()
        if not tool.is_available():
            return ToolResult(
                tool_call_id=tool_call_id,
                name="binwalk_analyze",
                success=False,
                output="",
                error="Binwalk is not installed on this system",
            )

        result = await tool.run(target=target, extract=extract)

        return ToolResult(
            tool_call_id=tool_call_id,
            name="binwalk_analyze",
            success=result.success,
            output=json.dumps(result.data, indent=2) if result.success else "",
            error=result.error,
        )

    registry.register(definition, executor)


def _register_strings(registry: ToolRegistry) -> None:
    """Register the Strings tool."""
    definition = ToolDefinition(
        name="strings_extract",
        description="""Extract printable strings from binary files.
Use this tool to find embedded strings, URLs, credentials, debug messages, and other text in binaries.
Useful for reverse engineering and finding hardcoded values.""",
        parameters=[
            ToolParameter(
                name="target",
                description="Path to the binary file to extract strings from",
                type=ToolParameterType.STRING,
                required=True,
            ),
            ToolParameter(
                name="min_length",
                description="Minimum string length to extract (default: 4)",
                type=ToolParameterType.INTEGER,
                required=False,
                default=4,
            ),
        ],
    )

    async def executor(tool_call_id: str, target: str, min_length: int = 4) -> ToolResult:
        tool = StringsTool()
        if not tool.is_available():
            return ToolResult(
                tool_call_id=tool_call_id,
                name="strings_extract",
                success=False,
                output="",
                error="strings command is not available on this system",
            )

        result = await tool.run(target=target, min_length=min_length)

        return ToolResult(
            tool_call_id=tool_call_id,
            name="strings_extract",
            success=result.success,
            output=json.dumps(result.data, indent=2) if result.success else "",
            error=result.error,
        )

    registry.register(definition, executor)


def _register_ropgadget(registry: ToolRegistry) -> None:
    """Register the ROPgadget tool."""
    definition = ToolDefinition(
        name="ropgadget_find",
        description="""Find ROP gadgets in binary executables for exploit development.
Use this tool to identify code sequences useful for Return-Oriented Programming attacks.
Returns gadgets with their addresses and assembly instructions.""",
        parameters=[
            ToolParameter(
                name="target",
                description="Path to the binary executable to analyze",
                type=ToolParameterType.STRING,
                required=True,
            ),
        ],
    )

    async def executor(tool_call_id: str, target: str) -> ToolResult:
        tool = ROPgadgetTool()
        if not tool.is_available():
            return ToolResult(
                tool_call_id=tool_call_id,
                name="ropgadget_find",
                success=False,
                output="",
                error="ROPgadget is not installed on this system",
            )

        result = await tool.run(target=target)

        return ToolResult(
            tool_call_id=tool_call_id,
            name="ropgadget_find",
            success=result.success,
            output=json.dumps(result.data, indent=2) if result.success else "",
            error=result.error,
        )

    registry.register(definition, executor)


def _register_read_file(registry: ToolRegistry) -> None:
    """Register a file reading tool."""
    definition = ToolDefinition(
        name="read_file",
        description="""Read the contents of a source code file.
Use this tool to examine specific files when you need to understand the code or verify a potential vulnerability.
Returns the file contents with line numbers.""",
        parameters=[
            ToolParameter(
                name="file_path",
                description="Path to the file to read",
                type=ToolParameterType.STRING,
                required=True,
            ),
            ToolParameter(
                name="start_line",
                description="Starting line number (1-based, default: 1)",
                type=ToolParameterType.INTEGER,
                required=False,
                default=1,
            ),
            ToolParameter(
                name="end_line",
                description="Ending line number (default: read to end, max 500 lines)",
                type=ToolParameterType.INTEGER,
                required=False,
            ),
        ],
    )

    async def executor(
        tool_call_id: str,
        file_path: str,
        start_line: int = 1,
        end_line: int | None = None,
    ) -> ToolResult:
        from pathlib import Path

        path = Path(file_path)
        if not path.exists():
            return ToolResult(
                tool_call_id=tool_call_id,
                name="read_file",
                success=False,
                output="",
                error=f"File not found: {file_path}",
            )

        if not path.is_file():
            return ToolResult(
                tool_call_id=tool_call_id,
                name="read_file",
                success=False,
                output="",
                error=f"Not a file: {file_path}",
            )

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            lines = content.split("\n")

            # Apply line limits
            start_idx = max(0, start_line - 1)
            if end_line:
                end_idx = min(len(lines), end_line)
            else:
                end_idx = min(len(lines), start_idx + 500)  # Max 500 lines

            selected_lines = lines[start_idx:end_idx]

            # Format with line numbers
            numbered_lines = [
                f"{i + start_line:4d} | {line}" for i, line in enumerate(selected_lines)
            ]

            output = {
                "file_path": str(path),
                "start_line": start_line,
                "end_line": start_idx + len(selected_lines),
                "total_lines": len(lines),
                "content": "\n".join(numbered_lines),
            }

            return ToolResult(
                tool_call_id=tool_call_id,
                name="read_file",
                success=True,
                output=json.dumps(output, indent=2),
            )
        except Exception as e:
            return ToolResult(
                tool_call_id=tool_call_id,
                name="read_file",
                success=False,
                output="",
                error=f"Failed to read file: {str(e)}",
            )

    registry.register(definition, executor)


def _register_list_files(registry: ToolRegistry) -> None:
    """Register a file listing tool."""
    definition = ToolDefinition(
        name="list_files",
        description="""List files in a directory with optional filtering.
Use this tool to explore the codebase structure and find relevant files.
Returns file paths relative to the directory.""",
        parameters=[
            ToolParameter(
                name="directory",
                description="Path to the directory to list",
                type=ToolParameterType.STRING,
                required=True,
            ),
            ToolParameter(
                name="pattern",
                description="Glob pattern to filter files (e.g., '*.py', '**/*.js')",
                type=ToolParameterType.STRING,
                required=False,
                default="*",
            ),
            ToolParameter(
                name="recursive",
                description="Whether to list files recursively (default: true)",
                type=ToolParameterType.BOOLEAN,
                required=False,
                default=True,
            ),
        ],
    )

    async def executor(
        tool_call_id: str,
        directory: str,
        pattern: str = "*",
        recursive: bool = True,
    ) -> ToolResult:
        from pathlib import Path

        path = Path(directory)
        if not path.exists():
            return ToolResult(
                tool_call_id=tool_call_id,
                name="list_files",
                success=False,
                output="",
                error=f"Directory not found: {directory}",
            )

        if not path.is_dir():
            return ToolResult(
                tool_call_id=tool_call_id,
                name="list_files",
                success=False,
                output="",
                error=f"Not a directory: {directory}",
            )

        try:
            if recursive:
                files = list(path.rglob(pattern))
            else:
                files = list(path.glob(pattern))

            # Filter to only files and limit results
            files = [f for f in files if f.is_file()][:500]

            # Sort and format
            file_list = sorted([str(f.relative_to(path)) for f in files])

            output = {
                "directory": str(path),
                "pattern": pattern,
                "recursive": recursive,
                "file_count": len(file_list),
                "files": file_list,
            }

            return ToolResult(
                tool_call_id=tool_call_id,
                name="list_files",
                success=True,
                output=json.dumps(output, indent=2),
            )
        except Exception as e:
            return ToolResult(
                tool_call_id=tool_call_id,
                name="list_files",
                success=False,
                output="",
                error=f"Failed to list files: {str(e)}",
            )

    registry.register(definition, executor)


def _register_search_code(registry: ToolRegistry) -> None:
    """Register a code search tool."""
    definition = ToolDefinition(
        name="search_code",
        description="""Search for patterns in code files using regex.
Use this tool to find specific code patterns, function calls, or suspicious constructs.
Returns matching files with line numbers and context.""",
        parameters=[
            ToolParameter(
                name="directory",
                description="Path to the directory to search",
                type=ToolParameterType.STRING,
                required=True,
            ),
            ToolParameter(
                name="pattern",
                description="Regex pattern to search for",
                type=ToolParameterType.STRING,
                required=True,
            ),
            ToolParameter(
                name="file_pattern",
                description="Glob pattern to filter files (e.g., '*.py')",
                type=ToolParameterType.STRING,
                required=False,
                default="*",
            ),
        ],
    )

    async def executor(
        tool_call_id: str,
        directory: str,
        pattern: str,
        file_pattern: str = "*",
    ) -> ToolResult:
        import re
        from pathlib import Path

        path = Path(directory)
        if not path.exists():
            return ToolResult(
                tool_call_id=tool_call_id,
                name="search_code",
                success=False,
                output="",
                error=f"Directory not found: {directory}",
            )

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return ToolResult(
                tool_call_id=tool_call_id,
                name="search_code",
                success=False,
                output="",
                error=f"Invalid regex pattern: {str(e)}",
            )

        try:
            matches = []
            files_searched = 0

            for file_path in path.rglob(file_pattern):
                if not file_path.is_file():
                    continue

                # Skip binary files and large files
                if file_path.suffix.lower() in {".exe", ".dll", ".so", ".bin", ".pyc"}:
                    continue

                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    files_searched += 1
                except Exception:
                    continue

                lines = content.split("\n")
                for i, line in enumerate(lines, 1):
                    if regex.search(line):
                        matches.append(
                            {
                                "file": str(file_path.relative_to(path)),
                                "line": i,
                                "content": line.strip()[:200],  # Truncate long lines
                            }
                        )

                # Limit total matches
                if len(matches) >= 100:
                    break

            output = {
                "directory": str(path),
                "pattern": pattern,
                "file_pattern": file_pattern,
                "files_searched": files_searched,
                "match_count": len(matches),
                "matches": matches,
            }

            return ToolResult(
                tool_call_id=tool_call_id,
                name="search_code",
                success=True,
                output=json.dumps(output, indent=2),
            )
        except Exception as e:
            return ToolResult(
                tool_call_id=tool_call_id,
                name="search_code",
                success=False,
                output="",
                error=f"Search failed: {str(e)}",
            )

    registry.register(definition, executor)


# Convenience function to get available tools
def get_available_tools() -> list[str]:
    """Get list of available security tools on this system.

    Returns:
        List of tool names that are installed and available.
    """
    available = []

    tools = [
        ("opengrep_scan", OpengrepTool()),
        ("gitleaks_scan", GitleaksTool()),
        ("trivy_scan", TrivyTool()),
        ("binwalk_analyze", BinwalkTool()),
        ("strings_extract", StringsTool()),
        ("ropgadget_find", ROPgadgetTool()),
    ]

    for name, tool in tools:
        if tool.is_available():
            available.append(name)

    # These are always available (built-in)
    available.extend(["read_file", "list_files", "search_code"])

    return available
