"""Binary analysis tools."""

import json
from typing import Any

from mrzero.tools.base import BaseTool, ToolOutput


class BinwalkTool(BaseTool):
    """Wrapper for Binwalk firmware analysis tool."""

    name = "binwalk"
    description = "Firmware analysis and extraction tool"
    required_binary = "binwalk"

    async def run(
        self,
        target: str,
        extract: bool = False,
        signature: bool = True,
        entropy: bool = False,
        **kwargs: Any,
    ) -> ToolOutput:
        """Run Binwalk analysis.

        Args:
            target: Target firmware/binary file.
            extract: Extract identified files.
            signature: Perform signature scan.
            entropy: Calculate entropy.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with analysis results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="Binwalk is not installed",
            )

        # Build command
        cmd = ["binwalk"]

        if signature:
            cmd.append("-B")

        if entropy:
            cmd.append("-E")

        if extract:
            cmd.append("-e")

        cmd.append(target)

        # Run analysis
        returncode, stdout, stderr = await self._run_command(cmd, timeout=300)

        # Parse text output (binwalk doesn't have JSON output)
        findings = []
        for line in stdout.split("\n"):
            line = line.strip()
            if not line or line.startswith("DECIMAL"):
                continue

            parts = line.split(None, 2)
            if len(parts) >= 3:
                try:
                    findings.append(
                        {
                            "offset_decimal": int(parts[0]),
                            "offset_hex": parts[1],
                            "description": parts[2],
                        }
                    )
                except ValueError:
                    continue

        return ToolOutput(
            success=returncode == 0,
            data={
                "findings": findings,
                "total": len(findings),
            },
            raw_output=stdout,
        )


class StringsTool(BaseTool):
    """Wrapper for strings command for extracting strings from binaries."""

    name = "strings"
    description = "Extract printable strings from binary files"
    required_binary = "strings"

    async def run(
        self,
        target: str,
        min_length: int = 4,
        encoding: str = "s",  # s=7-bit, S=8-bit, b=16-bit big-endian, etc.
        **kwargs: Any,
    ) -> ToolOutput:
        """Run strings extraction.

        Args:
            target: Target binary file.
            min_length: Minimum string length.
            encoding: Character encoding.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with extracted strings.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="strings is not installed",
            )

        cmd = ["strings", f"-n{min_length}", f"-e{encoding}", target]

        returncode, stdout, stderr = await self._run_command(cmd, timeout=60)

        strings = stdout.strip().split("\n") if stdout.strip() else []

        # Look for interesting patterns
        interesting = {
            "urls": [],
            "paths": [],
            "potential_secrets": [],
            "emails": [],
        }

        import re

        for s in strings:
            if re.match(r"https?://", s):
                interesting["urls"].append(s)
            elif re.match(r"^/[\w/]+", s):
                interesting["paths"].append(s)
            elif re.search(r"(password|secret|key|token|api).*=", s, re.I):
                interesting["potential_secrets"].append(s)
            elif re.search(r"\b[\w.-]+@[\w.-]+\.\w+\b", s):
                interesting["emails"].append(s)

        return ToolOutput(
            success=returncode == 0,
            data={
                "strings": strings[:1000],  # Limit to first 1000
                "total": len(strings),
                "interesting": interesting,
            },
            raw_output=stdout[:50000],  # Limit raw output
        )


class ROPgadgetTool(BaseTool):
    """Wrapper for ROPgadget tool."""

    name = "ropgadget"
    description = "Tool to find ROP gadgets in binaries"
    required_binary = "ROPgadget"

    async def run(
        self,
        target: str,
        rop_chain: bool = False,
        depth: int = 10,
        **kwargs: Any,
    ) -> ToolOutput:
        """Run ROPgadget analysis.

        Args:
            target: Target binary file.
            rop_chain: Generate ROP chain.
            depth: Search depth.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with gadgets.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="ROPgadget is not installed",
            )

        cmd = ["ROPgadget", "--binary", target, f"--depth={depth}"]

        if rop_chain:
            cmd.append("--ropchain")

        returncode, stdout, stderr = await self._run_command(cmd, timeout=120)

        gadgets = []
        rop_chain_code = None

        lines = stdout.split("\n")
        in_ropchain = False

        for line in lines:
            line = line.strip()

            if "ROP chain" in line:
                in_ropchain = True
                rop_chain_code = []
                continue

            if in_ropchain:
                rop_chain_code.append(line)
                continue

            if " : " in line and line.startswith("0x"):
                parts = line.split(" : ", 1)
                if len(parts) == 2:
                    gadgets.append(
                        {
                            "address": parts[0],
                            "gadget": parts[1],
                        }
                    )

        return ToolOutput(
            success=returncode == 0,
            data={
                "gadgets": gadgets[:500],  # Limit
                "total_gadgets": len(gadgets),
                "rop_chain": "\n".join(rop_chain_code) if rop_chain_code else None,
            },
            raw_output=stdout[:50000],
        )
