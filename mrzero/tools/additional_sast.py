"""Additional SAST tools - Infer, Bearer, and Application Inspector."""

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from mrzero.tools.base import BaseTool, ToolOutput


class InferTool(BaseTool):
    """Wrapper for Facebook/Meta Infer static analyzer.

    Infer is a static analysis tool that finds null pointer exceptions,
    memory leaks, and other bugs in Java, C, C++, and Objective-C code.
    https://fbinfer.com/
    """

    name = "infer"
    description = "Static analyzer for finding bugs in Java, C, C++, and Objective-C"
    required_binary = "infer"

    # Supported languages and their build commands
    SUPPORTED_LANGUAGES = {
        "java": ["javac", "gradle", "mvn"],
        "c": ["gcc", "clang", "make"],
        "cpp": ["g++", "clang++", "make"],
        "objc": ["clang"],
    }

    # Infer checker categories for security
    SECURITY_CHECKERS = [
        "BUFFER_OVERRUN",
        "NULL_DEREFERENCE",
        "RESOURCE_LEAK",
        "USE_AFTER_FREE",
        "DEAD_STORE",
        "UNINITIALIZED_VALUE",
        "TAINT_ERROR",
        "SQL_INJECTION",
        "SHELL_INJECTION",
        "COMMAND_INJECTION",
    ]

    async def run(
        self,
        target: str,
        build_command: str | None = None,
        checkers: list[str] | None = None,
        capture_only: bool = False,
        incremental: bool = False,
        **kwargs: Any,
    ) -> ToolOutput:
        """Run Infer analysis.

        Args:
            target: Target directory to analyze.
            build_command: Build command to capture (e.g., "make", "gradle build").
            checkers: List of checker names to enable.
            capture_only: Only capture build, don't analyze.
            incremental: Run incremental analysis.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with analysis results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="Infer is not installed. Install from: https://fbinfer.com/docs/getting-started",
            )

        target_path = Path(target)
        if not target_path.exists():
            return ToolOutput(
                success=False,
                data={},
                error=f"Target path does not exist: {target}",
            )

        # Auto-detect build command if not specified
        if build_command is None:
            build_command = self._detect_build_command(target_path)

        if build_command is None:
            # For simple source files, use compile mode
            return await self._run_compile_mode(target_path, checkers)

        # Run with build capture
        return await self._run_with_build(target_path, build_command, checkers, capture_only)

    def _detect_build_command(self, target_path: Path) -> str | None:
        """Auto-detect the build command for a project."""
        # Check for common build files
        if (target_path / "Makefile").exists():
            return "make"
        if (target_path / "build.gradle").exists() or (target_path / "build.gradle.kts").exists():
            return "gradle build"
        if (target_path / "pom.xml").exists():
            return "mvn compile"
        if (target_path / "CMakeLists.txt").exists():
            return "cmake --build ."

        return None

    async def _run_compile_mode(
        self,
        target_path: Path,
        checkers: list[str] | None = None,
    ) -> ToolOutput:
        """Run Infer in compile mode for individual source files."""
        # Find source files
        source_files = []
        for ext in [".c", ".cpp", ".m", ".java"]:
            source_files.extend(target_path.rglob(f"*{ext}"))

        if not source_files:
            return ToolOutput(
                success=False,
                data={},
                error="No supported source files found (C, C++, Objective-C, Java)",
            )

        findings = []
        errors = []

        with tempfile.TemporaryDirectory() as temp_dir:
            results_dir = Path(temp_dir) / "infer-out"

            for source_file in source_files[:50]:  # Limit for performance
                # Determine compiler
                ext = source_file.suffix.lower()
                if ext == ".java":
                    compiler = "javac"
                elif ext == ".m":
                    compiler = "clang"
                elif ext == ".cpp":
                    compiler = "clang++"
                else:
                    compiler = "clang"

                cmd = [
                    "infer",
                    "run",
                    "--results-dir",
                    str(results_dir),
                    "--",
                    compiler,
                    "-c",
                    str(source_file),
                ]

                if checkers:
                    for checker in checkers:
                        cmd.extend(["--enable-checker", checker])

                returncode, stdout, stderr = await self._run_command(cmd, timeout=120)

                # Parse results from this run
                report_path = results_dir / "report.json"
                if report_path.exists():
                    file_findings = self._parse_report(report_path)
                    findings.extend(file_findings)

        return ToolOutput(
            success=True,
            data={
                "findings": findings,
                "total": len(findings),
                "files_analyzed": len(source_files),
            },
        )

    async def _run_with_build(
        self,
        target_path: Path,
        build_command: str,
        checkers: list[str] | None = None,
        capture_only: bool = False,
    ) -> ToolOutput:
        """Run Infer with build capture."""
        with tempfile.TemporaryDirectory() as temp_dir:
            results_dir = Path(temp_dir) / "infer-out"

            # Build the infer command
            cmd = [
                "infer",
                "run" if not capture_only else "capture",
                "--results-dir",
                str(results_dir),
            ]

            if checkers:
                for checker in checkers:
                    cmd.extend(["--enable-checker", checker])

            cmd.append("--")
            cmd.extend(build_command.split())

            returncode, stdout, stderr = await self._run_command(
                cmd, timeout=900, cwd=str(target_path)
            )

            if returncode != 0 and not (results_dir / "report.json").exists():
                return ToolOutput(
                    success=False,
                    data={},
                    error=f"Infer analysis failed: {stderr}",
                    raw_output=stderr,
                )

            # Parse results
            report_path = results_dir / "report.json"
            if report_path.exists():
                findings = self._parse_report(report_path)
                return ToolOutput(
                    success=True,
                    data={
                        "findings": findings,
                        "total": len(findings),
                        "build_command": build_command,
                    },
                    raw_output=stdout,
                )

            return ToolOutput(
                success=True,
                data={"findings": [], "total": 0},
            )

    def _parse_report(self, report_path: Path) -> list[dict[str, Any]]:
        """Parse Infer JSON report."""
        try:
            with open(report_path) as f:
                reports = json.load(f)

            findings = []
            for report in reports:
                # Map Infer severity to our severity levels
                severity = report.get("severity", "WARNING")
                if severity == "ERROR":
                    severity = "HIGH"
                elif severity == "WARNING":
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                findings.append(
                    {
                        "bug_type": report.get("bug_type", ""),
                        "qualifier": report.get("qualifier", ""),
                        "severity": severity,
                        "file": report.get("file", ""),
                        "line": report.get("line", 0),
                        "procedure": report.get("procedure", ""),
                        "bug_trace": report.get("bug_trace", []),
                        "hash": report.get("hash", ""),
                    }
                )

            return findings
        except (json.JSONDecodeError, IOError):
            return []


class BearerTool(BaseTool):
    """Wrapper for Bearer data security scanner.

    Bearer is a security tool that scans code to find data security risks,
    including sensitive data leaks and OWASP vulnerabilities.
    https://github.com/Bearer/bearer
    """

    name = "bearer"
    description = "Data security scanner for finding sensitive data leaks and security risks"
    required_binary = "bearer"

    # Supported languages
    SUPPORTED_LANGUAGES = [
        "ruby",
        "javascript",
        "typescript",
        "java",
        "go",
        "php",
        "python",
    ]

    async def run(
        self,
        target: str,
        scanner: str = "sast",
        severity: str = "critical,high,medium",
        only_rules: list[str] | None = None,
        skip_rules: list[str] | None = None,
        report_format: str = "json",
        **kwargs: Any,
    ) -> ToolOutput:
        """Run Bearer scan.

        Args:
            target: Target directory to scan.
            scanner: Scanner type (sast, secrets).
            severity: Minimum severity levels to include.
            only_rules: Only run specific rules.
            skip_rules: Skip specific rules.
            report_format: Output format (json, yaml, sarif).
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with scan results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="Bearer is not installed. Install from: https://docs.bearer.com/getting-started/install/",
            )

        target_path = Path(target)
        if not target_path.exists():
            return ToolOutput(
                success=False,
                data={},
                error=f"Target path does not exist: {target}",
            )

        # Build command
        cmd = [
            "bearer",
            "scan",
            str(target_path),
            "--format",
            report_format,
            "--scanner",
            scanner,
            "--severity",
            severity,
        ]

        if only_rules:
            cmd.extend(["--only-rule", ",".join(only_rules)])

        if skip_rules:
            cmd.extend(["--skip-rule", ",".join(skip_rules)])

        # Run scan
        returncode, stdout, stderr = await self._run_command(cmd, timeout=600)

        # Bearer returns non-zero exit code when findings exist, which is expected
        if not stdout and returncode != 0:
            return ToolOutput(
                success=False,
                data={},
                error=f"Bearer scan failed: {stderr}",
                raw_output=stderr,
            )

        # Parse results
        try:
            if report_format == "json":
                return self._parse_json_output(stdout)
            elif report_format == "sarif":
                return self._parse_sarif_output(stdout)
            else:
                return ToolOutput(
                    success=True,
                    data={"raw": stdout},
                    raw_output=stdout,
                )
        except Exception as e:
            return ToolOutput(
                success=False,
                data={},
                error=f"Failed to parse Bearer output: {e}",
                raw_output=stdout,
            )

    def _parse_json_output(self, output: str) -> ToolOutput:
        """Parse Bearer JSON output."""
        try:
            results = json.loads(output)
        except json.JSONDecodeError:
            return ToolOutput(
                success=True,
                data={"findings": [], "total": 0},
                raw_output=output,
            )

        findings = []

        # Handle different output structures
        if isinstance(results, dict):
            # Extract findings from the report structure
            for severity_level in ["critical", "high", "medium", "low", "warning"]:
                level_findings = results.get(severity_level, [])
                if isinstance(level_findings, list):
                    for finding in level_findings:
                        findings.append(self._normalize_finding(finding, severity_level))

            # Also check for a flat "findings" array
            if "findings" in results:
                for finding in results["findings"]:
                    findings.append(self._normalize_finding(finding))

        elif isinstance(results, list):
            for finding in results:
                findings.append(self._normalize_finding(finding))

        return ToolOutput(
            success=True,
            data={
                "findings": findings,
                "total": len(findings),
            },
            raw_output=output,
        )

    def _normalize_finding(
        self, finding: dict[str, Any], default_severity: str = "medium"
    ) -> dict[str, Any]:
        """Normalize a Bearer finding to our standard format."""
        return {
            "rule_id": finding.get(
                "rule_id",
                finding.get("cwe_ids", ["unknown"])[0] if finding.get("cwe_ids") else "unknown",
            ),
            "title": finding.get("title", finding.get("description", "")),
            "description": finding.get("description", ""),
            "severity": finding.get("severity", default_severity).upper(),
            "file": finding.get("filename", finding.get("file", "")),
            "line_start": finding.get("line_number", finding.get("line", 0)),
            "line_end": finding.get("line_number", finding.get("line", 0)),
            "cwe_ids": finding.get("cwe_ids", []),
            "owasp_ids": finding.get("owasp_ids", []),
            "documentation_url": finding.get("documentation_url", ""),
            "category": finding.get("category_groups", []),
        }

    def _parse_sarif_output(self, output: str) -> ToolOutput:
        """Parse Bearer SARIF output."""
        try:
            sarif = json.loads(output)
            findings = []

            for run in sarif.get("runs", []):
                for result in run.get("results", []):
                    rule_id = result.get("ruleId", "")
                    message = result.get("message", {}).get("text", "")
                    level = result.get("level", "warning")

                    # Map SARIF levels to severity
                    severity_map = {
                        "error": "HIGH",
                        "warning": "MEDIUM",
                        "note": "LOW",
                        "none": "INFO",
                    }
                    severity = severity_map.get(level, "MEDIUM")

                    locations = result.get("locations", [])
                    if locations:
                        loc = locations[0].get("physicalLocation", {})
                        artifact = loc.get("artifactLocation", {})
                        region = loc.get("region", {})

                        findings.append(
                            {
                                "rule_id": rule_id,
                                "message": message,
                                "severity": severity,
                                "file": artifact.get("uri", ""),
                                "line_start": region.get("startLine", 0),
                                "line_end": region.get("endLine", 0),
                            }
                        )

            return ToolOutput(
                success=True,
                data={
                    "findings": findings,
                    "total": len(findings),
                },
                raw_output=output,
            )
        except json.JSONDecodeError:
            return ToolOutput(
                success=True,
                data={"findings": [], "total": 0},
                raw_output=output,
            )


class ApplicationInspectorTool(BaseTool):
    """Wrapper for Microsoft Application Inspector.

    Application Inspector is a software characterization tool that
    identifies features and metadata in source code.
    https://github.com/microsoft/ApplicationInspector
    """

    name = "appinspector"
    description = (
        "Software characterization tool for identifying code features and security patterns"
    )
    required_binary = "appinspector"

    # Feature categories relevant to security
    SECURITY_CATEGORIES = [
        "Authentication",
        "Authorization",
        "Cryptography",
        "Data.Sensitive",
        "Frameworks.Security",
        "Network",
        "OS.SystemRegistry",
        "OS.FileOperation",
        "OS.Process",
        "OS.Environment",
        "DataStorage",
    ]

    async def run(
        self,
        target: str,
        output_format: str = "json",
        include_tags: list[str] | None = None,
        exclude_tags: list[str] | None = None,
        confidence: str = "high,medium",
        unique_matches: bool = True,
        **kwargs: Any,
    ) -> ToolOutput:
        """Run Application Inspector analysis.

        Args:
            target: Target directory to analyze.
            output_format: Output format (json, text, html).
            include_tags: Only include matches with these tags.
            exclude_tags: Exclude matches with these tags.
            confidence: Minimum confidence level.
            unique_matches: Only report unique matches.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with analysis results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="Application Inspector is not installed. Install from: https://github.com/microsoft/ApplicationInspector",
            )

        target_path = Path(target)
        if not target_path.exists():
            return ToolOutput(
                success=False,
                data={},
                error=f"Target path does not exist: {target}",
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / f"report.{output_format}"

            # Build command
            cmd = [
                "appinspector",
                "analyze",
                "--source-path",
                str(target_path),
                "--output-file-path",
                str(output_file),
                "--output-file-format",
                output_format,
                "--confidence-filters",
                confidence,
            ]

            if unique_matches:
                cmd.append("--single-threaded")  # More consistent results

            if include_tags:
                cmd.extend(["--include-tags", ",".join(include_tags)])

            if exclude_tags:
                cmd.extend(["--exclude-tags", ",".join(exclude_tags)])

            # Run analysis
            returncode, stdout, stderr = await self._run_command(cmd, timeout=600)

            if returncode != 0 and not output_file.exists():
                return ToolOutput(
                    success=False,
                    data={},
                    error=f"Application Inspector failed: {stderr}",
                    raw_output=stderr,
                )

            # Parse results
            if output_file.exists():
                raw_output = output_file.read_text()

                if output_format == "json":
                    return self._parse_json_output(raw_output)
                else:
                    return ToolOutput(
                        success=True,
                        data={"raw": raw_output},
                        raw_output=raw_output,
                    )

            return ToolOutput(
                success=True,
                data={"findings": [], "total": 0},
            )

    def _parse_json_output(self, output: str) -> ToolOutput:
        """Parse Application Inspector JSON output."""
        try:
            results = json.loads(output)
        except json.JSONDecodeError:
            return ToolOutput(
                success=True,
                data={"findings": [], "total": 0},
                raw_output=output,
            )

        findings = []
        metadata = {}

        # Extract metadata summary
        if "metaData" in results:
            meta = results["metaData"]
            metadata = {
                "application_name": meta.get("applicationName", ""),
                "source_path": meta.get("sourcePath", ""),
                "languages": meta.get("languages", {}),
                "unique_tags": meta.get("uniqueTagsCount", 0),
                "total_matches": meta.get("totalMatchesCount", 0),
                "unique_matches": meta.get("uniqueMatchesCount", 0),
            }

        # Extract match results
        for match in results.get("matchList", []):
            # Determine severity based on category
            tags = match.get("tags", [])
            severity = self._determine_severity(tags)

            findings.append(
                {
                    "rule_name": match.get("ruleName", ""),
                    "rule_id": match.get("ruleId", ""),
                    "tags": tags,
                    "severity": severity,
                    "confidence": match.get("confidence", ""),
                    "file": match.get("fileName", ""),
                    "line_start": match.get("startLocationLine", 0),
                    "line_end": match.get("endLocationLine", 0),
                    "excerpt": match.get("excerpt", "")[:500],  # Truncate long excerpts
                    "pattern_match": match.get("sample", ""),
                }
            )

        return ToolOutput(
            success=True,
            data={
                "findings": findings,
                "total": len(findings),
                "metadata": metadata,
                "security_findings": [
                    f
                    for f in findings
                    if any(cat in str(f.get("tags", [])) for cat in self.SECURITY_CATEGORIES)
                ],
            },
            raw_output=output,
        )

    def _determine_severity(self, tags: list[str]) -> str:
        """Determine severity based on tags."""
        tags_str = str(tags).lower()

        # Critical patterns
        if any(
            pattern in tags_str
            for pattern in [
                "cryptography.hash.weak",
                "authentication.hardcoded",
                "sensitive.secret",
            ]
        ):
            return "CRITICAL"

        # High severity patterns
        if any(
            pattern in tags_str
            for pattern in ["cryptography", "authentication", "authorization", "sensitive"]
        ):
            return "HIGH"

        # Medium severity patterns
        if any(pattern in tags_str for pattern in ["network", "process", "fileop", "datastorage"]):
            return "MEDIUM"

        return "LOW"
