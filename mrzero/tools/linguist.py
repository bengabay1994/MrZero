"""Language detection tool using GitHub Linguist."""

import re
from pathlib import Path
from typing import Any

from mrzero.tools.base import DockerTool, ToolOutput


class LinguistTool(DockerTool):
    """Wrapper for GitHub Linguist language detection tool.

    Linguist is used to detect programming languages in a codebase.
    https://github.com/github-linguist/linguist

    Runs via Docker toolbox (Linguist requires Ruby).
    """

    name = "linguist"
    description = "Language detection tool using GitHub Linguist"
    required_binary = "github-linguist"
    docker_tool_name = "linguist"
    prefer_docker = True  # Linguist requires Ruby, Docker is easier

    async def run(
        self,
        target: str,
        breakdown: bool = True,
        **kwargs: Any,
    ) -> ToolOutput:
        """Run Linguist for language detection.

        Args:
            target: Target directory to analyze.
            breakdown: Include file-by-file breakdown.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with language detection results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="Linguist is not available. Run 'mrzero docker pull' for Docker support.",
            )

        use_docker = self.should_use_docker()

        if use_docker:
            return await self._run_docker(target, breakdown)
        else:
            return await self._run_local(target, breakdown)

    async def _run_local(self, target: str, breakdown: bool) -> ToolOutput:
        """Run Linguist locally."""
        cmd = ["github-linguist", target]
        if breakdown:
            cmd.append("--breakdown")

        returncode, stdout, stderr = await self._run_command(cmd, timeout=120)
        return self._parse_output(returncode, stdout, stderr)

    async def _run_docker(self, target: str, breakdown: bool) -> ToolOutput:
        """Run Linguist via Docker toolbox."""
        args = ["/workspace"]
        if breakdown:
            args.append("--breakdown")

        returncode, stdout, stderr = await self._run_docker_tool(
            args=args,
            target_path=target,
            timeout=120,
        )
        return self._parse_output(returncode, stdout, stderr)

    def _parse_output(self, returncode: int, stdout: str, stderr: str) -> ToolOutput:
        """Parse Linguist output.

        Linguist output format:
        ```
        97.5%  Python
        2.5%   Shell

        Python:
        file1.py
        file2.py
        ...
        ```
        """
        if returncode != 0:
            return ToolOutput(
                success=False,
                data={},
                error=stderr or "Linguist scan failed",
                raw_output=stderr,
            )

        languages = {}
        file_breakdown = {}
        current_language = None

        lines = stdout.strip().split("\n")

        # Parse percentage lines (e.g., "97.5%  Python")
        percentage_pattern = re.compile(r"^\s*([\d.]+)%\s+(.+)$")
        # Parse language header (e.g., "Python:")
        header_pattern = re.compile(r"^(\w+):$")

        in_breakdown = False

        for line in lines:
            line = line.rstrip()

            # Check for percentage line
            match = percentage_pattern.match(line)
            if match:
                percentage = float(match.group(1))
                language = match.group(2).strip()
                languages[language] = percentage
                continue

            # Check for language header in breakdown
            match = header_pattern.match(line)
            if match:
                current_language = match.group(1)
                file_breakdown[current_language] = []
                in_breakdown = True
                continue

            # Check for file in breakdown
            if in_breakdown and current_language and line.strip():
                file_breakdown[current_language].append(line.strip())

        # Sort languages by percentage
        sorted_languages = sorted(
            languages.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        return ToolOutput(
            success=True,
            data={
                "languages": dict(sorted_languages),
                "primary_language": sorted_languages[0][0] if sorted_languages else None,
                "file_breakdown": file_breakdown,
                "total_languages": len(languages),
                "execution_method": self.get_execution_method(),
            },
            raw_output=stdout,
        )
