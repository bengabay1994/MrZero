"""Smart contract analysis tools."""

import json
from typing import Any

from mrzero.tools.base import BaseTool, ToolOutput


class SlitherTool(BaseTool):
    """Wrapper for Slither static analysis tool for Solidity."""

    name = "slither"
    description = "Static analysis framework for Solidity smart contracts"
    required_binary = "slither"

    async def run(
        self,
        target: str,
        checkers: list[str] | None = None,
        exclude_detectors: list[str] | None = None,
        **kwargs: Any,
    ) -> ToolOutput:
        """Run Slither analysis.

        Args:
            target: Target contract or directory.
            checkers: Specific detectors to run.
            exclude_detectors: Detectors to exclude.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with analysis results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="Slither is not installed",
            )

        # Build command
        cmd = ["slither", target, "--json", "-"]

        if checkers:
            cmd.extend(["--detect", ",".join(checkers)])

        if exclude_detectors:
            cmd.extend(["--exclude", ",".join(exclude_detectors)])

        # Run analysis
        returncode, stdout, stderr = await self._run_command(cmd, timeout=300)

        try:
            results = json.loads(stdout) if stdout.strip() else {}

            findings = []
            for detector in results.get("results", {}).get("detectors", []):
                findings.append(
                    {
                        "check": detector.get("check", ""),
                        "impact": detector.get("impact", ""),
                        "confidence": detector.get("confidence", ""),
                        "description": detector.get("description", ""),
                        "elements": [
                            {
                                "type": elem.get("type", ""),
                                "name": elem.get("name", ""),
                                "source_mapping": elem.get("source_mapping", {}),
                            }
                            for elem in detector.get("elements", [])
                        ],
                    }
                )

            return ToolOutput(
                success=True,
                data={
                    "findings": findings,
                    "total": len(findings),
                    "compilation_warnings": results.get("results", {}).get("printers", []),
                },
                raw_output=stdout,
            )

        except json.JSONDecodeError as e:
            return ToolOutput(
                success=False,
                data={},
                error=f"Failed to parse Slither output: {e}",
                raw_output=stdout + stderr,
            )


class MythrilTool(BaseTool):
    """Wrapper for Mythril security analysis tool."""

    name = "mythril"
    description = "Security analysis tool for EVM bytecode"
    required_binary = "myth"

    async def run(
        self,
        target: str,
        mode: str = "analyze",
        execution_timeout: int = 300,
        **kwargs: Any,
    ) -> ToolOutput:
        """Run Mythril analysis.

        Args:
            target: Target contract file or address.
            mode: Analysis mode (analyze, disassemble, etc.).
            execution_timeout: Analysis timeout.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with analysis results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="Mythril is not installed",
            )

        # Build command
        cmd = [
            "myth",
            mode,
            target,
            "--output",
            "json",
            "--execution-timeout",
            str(execution_timeout),
        ]

        # Run analysis
        returncode, stdout, stderr = await self._run_command(
            cmd,
            timeout=execution_timeout + 60,
        )

        try:
            results = json.loads(stdout) if stdout.strip() else {}

            findings = []
            for issue in results.get("issues", []):
                findings.append(
                    {
                        "title": issue.get("title", ""),
                        "swc_id": issue.get("swc-id", ""),
                        "severity": issue.get("severity", ""),
                        "description": issue.get("description", ""),
                        "contract": issue.get("contract", ""),
                        "function": issue.get("function", ""),
                        "address": issue.get("address", ""),
                        "tx_sequence": issue.get("tx_sequence", {}),
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
            return ToolOutput(
                success=True,
                data={"findings": [], "total": 0},
                raw_output=stdout,
            )
