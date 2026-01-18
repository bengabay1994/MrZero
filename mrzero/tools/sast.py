"""Opengrep and other SAST tool wrappers."""

import json
from pathlib import Path
from typing import Any

from mrzero.tools.base import BaseTool, DockerTool, ToolOutput


class OpengrepTool(DockerTool):
    """Wrapper for Opengrep static analysis tool.

    Opengrep is a community fork of Semgrep under LGPL-2.1 license.
    https://github.com/opengrep/opengrep

    Can run locally if installed, or via Docker toolbox.
    """

    name = "opengrep"
    description = "Open-source static analysis engine to find security issues in code"
    required_binary = "opengrep"
    docker_tool_name = "opengrep"
    prefer_docker = True

    async def run(
        self,
        target: str,
        rules_path: str | None = None,
        config: str | None = None,
        severity: str = "WARNING",
        exclude: list[str] | None = None,
        sarif_output: str | None = None,
        **kwargs: Any,
    ) -> ToolOutput:
        """Run Opengrep scan.

        Args:
            target: Target directory to scan.
            rules_path: Path to rules directory or file.
            config: Custom config file path.
            severity: Minimum severity (INFO, WARNING, ERROR).
            exclude: Patterns to exclude.
            sarif_output: Path for SARIF output file.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with scan results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="Opengrep is not available. Install locally or run 'mrzero docker pull' for Docker support.",
            )

        # Determine execution method
        use_docker = self.should_use_docker()

        if use_docker:
            return await self._run_docker(target, config, rules_path, exclude)
        else:
            return await self._run_local(target, config, rules_path, exclude, sarif_output)

    async def _run_local(
        self,
        target: str,
        config: str | None,
        rules_path: str | None,
        exclude: list[str] | None,
        sarif_output: str | None,
    ) -> ToolOutput:
        """Run Opengrep locally."""
        cmd = ["opengrep", "scan", "--json"]

        if config:
            cmd.extend(["-f", config])
        elif rules_path:
            cmd.extend(["-f", rules_path])

        if sarif_output:
            cmd.extend(["--sarif-output", sarif_output])

        if exclude:
            for pattern in exclude:
                cmd.extend(["--exclude", pattern])

        cmd.append(target)

        returncode, stdout, stderr = await self._run_command(cmd, timeout=600)
        return self._parse_output(returncode, stdout, stderr)

    async def _run_docker(
        self,
        target: str,
        config: str | None,
        rules_path: str | None,
        exclude: list[str] | None,
    ) -> ToolOutput:
        """Run Opengrep via Docker toolbox."""
        args = ["scan", "--json"]

        if config:
            args.extend(["--config", config])
        elif rules_path:
            args.extend(["--config", rules_path])
        else:
            args.extend(["--config", "auto"])

        if exclude:
            for pattern in exclude:
                args.extend(["--exclude", pattern])

        args.append("/workspace")

        returncode, stdout, stderr = await self._run_docker_tool(
            args=args,
            target_path=target,
            timeout=600,
        )
        return self._parse_output(returncode, stdout, stderr)

    def _parse_output(self, returncode: int, stdout: str, stderr: str) -> ToolOutput:
        """Parse Opengrep output."""
        if returncode != 0 and not stdout:
            return ToolOutput(
                success=False,
                data={},
                error=stderr or "Opengrep scan failed",
                raw_output=stderr,
            )

        try:
            results = json.loads(stdout)
            findings = results.get("results", [])

            parsed_findings = []
            for finding in findings:
                parsed_findings.append(
                    {
                        "rule_id": finding.get("check_id", ""),
                        "message": finding.get("extra", {}).get("message", ""),
                        "severity": finding.get("extra", {}).get("severity", "WARNING"),
                        "file": finding.get("path", ""),
                        "line_start": finding.get("start", {}).get("line", 0),
                        "line_end": finding.get("end", {}).get("line", 0),
                        "code": finding.get("extra", {}).get("lines", ""),
                        "metadata": finding.get("extra", {}).get("metadata", {}),
                    }
                )

            return ToolOutput(
                success=True,
                data={
                    "findings": parsed_findings,
                    "total": len(parsed_findings),
                    "errors": results.get("errors", []),
                    "execution_method": self.get_execution_method(),
                },
                raw_output=stdout,
            )

        except json.JSONDecodeError as e:
            return ToolOutput(
                success=False,
                data={},
                error=f"Failed to parse Opengrep output: {e}",
                raw_output=stdout,
            )


class GitleaksTool(BaseTool):
    """Wrapper for Gitleaks secret detection tool."""

    name = "gitleaks"
    description = "Secret detection tool for finding hardcoded secrets"
    required_binary = "gitleaks"

    async def run(
        self,
        target: str,
        config: str | None = None,
        no_git: bool = True,
        **kwargs: Any,
    ) -> ToolOutput:
        """Run Gitleaks scan.

        Args:
            target: Target directory to scan.
            config: Custom config file path.
            no_git: Scan without git history.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with scan results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="Gitleaks is not installed",
            )

        # Build command
        cmd = [
            "gitleaks",
            "detect",
            "--source",
            target,
            "--report-format",
            "json",
            "--report-path",
            "/dev/stdout",
        ]

        if no_git:
            cmd.append("--no-git")

        if config:
            cmd.extend(["--config", config])

        # Run scan
        returncode, stdout, stderr = await self._run_command(cmd, timeout=300)

        # Gitleaks returns non-zero if leaks found, which is expected
        try:
            if stdout.strip():
                results = json.loads(stdout)
            else:
                results = []

            findings = []
            for leak in results:
                findings.append(
                    {
                        "rule_id": leak.get("RuleID", ""),
                        "description": leak.get("Description", ""),
                        "file": leak.get("File", ""),
                        "line": leak.get("StartLine", 0),
                        "secret": leak.get("Secret", "")[:20] + "...",  # Truncate for safety
                        "match": leak.get("Match", ""),
                        "entropy": leak.get("Entropy", 0),
                    }
                )

            return ToolOutput(
                success=True,
                data={
                    "findings": findings,
                    "total": len(findings),
                },
                raw_output=stdout,
            )

        except json.JSONDecodeError:
            # No findings (empty output)
            return ToolOutput(
                success=True,
                data={"findings": [], "total": 0},
                raw_output=stdout,
            )


class TrivyTool(BaseTool):
    """Wrapper for Trivy vulnerability scanner."""

    name = "trivy"
    description = "Vulnerability scanner for containers, filesystems, and code"
    required_binary = "trivy"

    async def run(
        self,
        target: str,
        scan_type: str = "fs",
        severity: str = "CRITICAL,HIGH,MEDIUM",
        **kwargs: Any,
    ) -> ToolOutput:
        """Run Trivy scan.

        Args:
            target: Target to scan (path, image, etc.).
            scan_type: Type of scan (fs, image, config, etc.).
            severity: Severity levels to include.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with scan results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="Trivy is not installed",
            )

        # Build command
        cmd = [
            "trivy",
            scan_type,
            "--format",
            "json",
            "--severity",
            severity,
            target,
        ]

        # Run scan
        returncode, stdout, stderr = await self._run_command(cmd, timeout=600)

        if returncode != 0 and not stdout:
            return ToolOutput(
                success=False,
                data={},
                error=stderr or "Trivy scan failed",
                raw_output=stderr,
            )

        try:
            results = json.loads(stdout)

            findings = []
            for result in results.get("Results", []):
                target_name = result.get("Target", "")
                for vuln in result.get("Vulnerabilities", []):
                    findings.append(
                        {
                            "vuln_id": vuln.get("VulnerabilityID", ""),
                            "package": vuln.get("PkgName", ""),
                            "version": vuln.get("InstalledVersion", ""),
                            "fixed_version": vuln.get("FixedVersion", ""),
                            "severity": vuln.get("Severity", ""),
                            "title": vuln.get("Title", ""),
                            "description": vuln.get("Description", ""),
                            "target": target_name,
                        }
                    )

            return ToolOutput(
                success=True,
                data={
                    "findings": findings,
                    "total": len(findings),
                },
                raw_output=stdout,
            )

        except json.JSONDecodeError as e:
            return ToolOutput(
                success=False,
                data={},
                error=f"Failed to parse Trivy output: {e}",
                raw_output=stdout,
            )
