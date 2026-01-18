"""Dynamic analysis tools for exploit development and runtime instrumentation.

This module provides wrappers for exploitation and dynamic analysis tools:
- pwntools: Exploit development framework
- Frida: Runtime instrumentation
- GDB/pwndbg: Debugger wrapper
- AFL++: Fuzzing framework
- Metasploit: Exploitation framework
- MSFVenom: Payload generation
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from mrzero.tools.base import BaseTool, ToolOutput


class PwntoolsTool(BaseTool):
    """Wrapper for pwntools exploit development library.

    pwntools is a CTF framework and exploit development library.
    This tool provides structured access to common pwntools operations.

    Note: This tool requires the pwntools Python package to be installed.
    """

    name = "pwntools"
    description = "Exploit development and binary analysis framework"
    required_binary = None  # Python library, checked differently

    def __init__(self) -> None:
        """Initialize pwntools tool."""
        super().__init__()
        self._pwn_available: bool | None = None

    def is_available(self) -> bool:
        """Check if pwntools is installed."""
        if self._pwn_available is not None:
            return self._pwn_available

        try:
            import pwn  # noqa: F401

            self._pwn_available = True
        except ImportError:
            self._pwn_available = False

        return self._pwn_available

    async def run(
        self,
        target: str,
        operation: str = "checksec",
        **kwargs: Any,
    ) -> ToolOutput:
        """Run pwntools operation on target.

        Args:
            target: Target binary path.
            operation: Operation to perform:
                - checksec: Check binary security properties
                - rop_gadgets: Find ROP gadgets
                - symbols: Extract symbols
                - elf_info: Get ELF information
                - find_got: Find GOT entries
                - find_plt: Find PLT entries
            **kwargs: Operation-specific arguments.

        Returns:
            ToolOutput with operation results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="pwntools is not installed. Install with: pip install pwntools",
            )

        if not os.path.exists(target):
            return ToolOutput(
                success=False,
                data={},
                error=f"Target binary not found: {target}",
            )

        try:
            if operation == "checksec":
                return await self._checksec(target)
            elif operation == "rop_gadgets":
                return await self._find_rop_gadgets(target, **kwargs)
            elif operation == "symbols":
                return await self._get_symbols(target)
            elif operation == "elf_info":
                return await self._get_elf_info(target)
            elif operation == "find_got":
                return await self._find_got(target)
            elif operation == "find_plt":
                return await self._find_plt(target)
            else:
                return ToolOutput(
                    success=False,
                    data={},
                    error=f"Unknown operation: {operation}",
                )
        except Exception as e:
            return ToolOutput(
                success=False,
                data={},
                error=f"pwntools error: {str(e)}",
            )

    async def _checksec(self, target: str) -> ToolOutput:
        """Check security properties of binary."""
        from pwn import ELF

        elf = ELF(target, checksec=False)

        security = {
            "arch": elf.arch,
            "bits": elf.bits,
            "endian": elf.endian,
            "canary": elf.canary,
            "nx": elf.nx,
            "pie": elf.pie,
            "relro": "Full" if elf.relro == "Full" else ("Partial" if elf.relro else "None"),
            "rpath": elf.rpath,
            "runpath": elf.runpath,
        }

        return ToolOutput(
            success=True,
            data={
                "security": security,
                "file": target,
            },
            raw_output=str(security),
        )

    async def _find_rop_gadgets(
        self, target: str, max_gadgets: int = 100, **kwargs: Any
    ) -> ToolOutput:
        """Find ROP gadgets in binary."""
        from pwn import ELF, ROP

        elf = ELF(target, checksec=False)
        rop = ROP(elf)

        # Get gadgets
        gadgets = []
        for gadget in list(rop.gadgets.values())[:max_gadgets]:
            gadgets.append(
                {
                    "address": hex(gadget.address),
                    "insns": gadget.insns,
                }
            )

        return ToolOutput(
            success=True,
            data={
                "gadgets": gadgets,
                "total": len(rop.gadgets),
                "shown": len(gadgets),
            },
        )

    async def _get_symbols(self, target: str) -> ToolOutput:
        """Get symbols from binary."""
        from pwn import ELF

        elf = ELF(target, checksec=False)

        symbols = {}
        for name, addr in elf.symbols.items():
            symbols[name] = hex(addr)

        return ToolOutput(
            success=True,
            data={
                "symbols": dict(list(symbols.items())[:200]),  # Limit output
                "total": len(symbols),
            },
        )

    async def _get_elf_info(self, target: str) -> ToolOutput:
        """Get ELF file information."""
        from pwn import ELF

        elf = ELF(target, checksec=False)

        info = {
            "arch": elf.arch,
            "bits": elf.bits,
            "endian": elf.endian,
            "entry": hex(elf.entry),
            "sections": list(elf.sections.keys())[:50],
            "segments": len(elf.segments),
        }

        return ToolOutput(
            success=True,
            data=info,
        )

    async def _find_got(self, target: str) -> ToolOutput:
        """Find GOT entries."""
        from pwn import ELF

        elf = ELF(target, checksec=False)

        got = {}
        for name, addr in elf.got.items():
            got[name] = hex(addr)

        return ToolOutput(
            success=True,
            data={"got": got},
        )

    async def _find_plt(self, target: str) -> ToolOutput:
        """Find PLT entries."""
        from pwn import ELF

        elf = ELF(target, checksec=False)

        plt = {}
        for name, addr in elf.plt.items():
            plt[name] = hex(addr)

        return ToolOutput(
            success=True,
            data={"plt": plt},
        )


class FridaTool(BaseTool):
    """Wrapper for Frida dynamic instrumentation framework.

    Frida enables runtime code injection and instrumentation
    for dynamic analysis and exploit development.
    """

    name = "frida"
    description = "Dynamic instrumentation and runtime code injection"
    required_binary = "frida"

    async def run(
        self,
        target: str,
        operation: str = "spawn",
        script: str | None = None,
        pid: int | None = None,
        timeout: int = 30,
        **kwargs: Any,
    ) -> ToolOutput:
        """Run Frida operation.

        Args:
            target: Target process name, binary path, or package name.
            operation: Operation to perform:
                - spawn: Spawn and instrument a process
                - attach: Attach to running process
                - list: List running processes
                - trace: Trace function calls
            script: JavaScript instrumentation script.
            pid: Process ID for attach operation.
            timeout: Execution timeout in seconds.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with instrumentation results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="Frida is not installed. Install with: pip install frida-tools",
            )

        try:
            if operation == "list":
                return await self._list_processes()
            elif operation == "spawn":
                return await self._spawn_and_instrument(target, script, timeout)
            elif operation == "attach":
                return await self._attach_and_instrument(target, script, pid, timeout)
            elif operation == "trace":
                return await self._trace(target, kwargs.get("functions", []), timeout)
            else:
                return ToolOutput(
                    success=False,
                    data={},
                    error=f"Unknown operation: {operation}",
                )
        except Exception as e:
            return ToolOutput(
                success=False,
                data={},
                error=f"Frida error: {str(e)}",
            )

    async def _list_processes(self) -> ToolOutput:
        """List running processes."""
        cmd = ["frida-ps", "-a"]

        returncode, stdout, stderr = await self._run_command(cmd, timeout=10)

        processes = []
        for line in stdout.split("\n")[1:]:  # Skip header
            parts = line.split(None, 2)
            if len(parts) >= 2:
                processes.append(
                    {
                        "pid": parts[0],
                        "name": parts[1] if len(parts) > 1 else "",
                        "identifier": parts[2] if len(parts) > 2 else "",
                    }
                )

        return ToolOutput(
            success=returncode == 0,
            data={"processes": processes},
            raw_output=stdout,
        )

    async def _spawn_and_instrument(
        self, target: str, script: str | None, timeout: int
    ) -> ToolOutput:
        """Spawn process and run instrumentation script."""
        if not script:
            # Default script just logs module loads
            script = """
            console.log("[*] Process spawned");
            Process.enumerateModules().forEach(function(m) {
                console.log("Module: " + m.name + " @ " + m.base);
            });
            """

        # Write script to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(script)
            script_path = f.name

        try:
            cmd = ["frida", "-f", target, "-l", script_path, "--no-pause", "-q"]

            returncode, stdout, stderr = await self._run_command(cmd, timeout=timeout)

            return ToolOutput(
                success=returncode == 0,
                data={
                    "output": stdout,
                    "target": target,
                },
                raw_output=stdout,
                error=stderr if returncode != 0 else None,
            )
        finally:
            os.unlink(script_path)

    async def _attach_and_instrument(
        self,
        target: str,
        script: str | None,
        pid: int | None,
        timeout: int,
    ) -> ToolOutput:
        """Attach to process and run instrumentation script."""
        if not script:
            script = """
            console.log("[*] Attached to process");
            console.log("[*] Modules:");
            Process.enumerateModules().slice(0, 10).forEach(function(m) {
                console.log("  " + m.name + " @ " + m.base);
            });
            """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(script)
            script_path = f.name

        try:
            if pid:
                cmd = ["frida", "-p", str(pid), "-l", script_path, "-q"]
            else:
                cmd = ["frida", "-n", target, "-l", script_path, "-q"]

            returncode, stdout, stderr = await self._run_command(cmd, timeout=timeout)

            return ToolOutput(
                success=returncode == 0,
                data={
                    "output": stdout,
                    "target": target or str(pid),
                },
                raw_output=stdout,
                error=stderr if returncode != 0 else None,
            )
        finally:
            os.unlink(script_path)

    async def _trace(self, target: str, functions: list[str], timeout: int) -> ToolOutput:
        """Trace function calls."""
        if not functions:
            return ToolOutput(
                success=False,
                data={},
                error="No functions specified for tracing",
            )

        cmd = ["frida-trace", "-f", target]
        for func in functions:
            cmd.extend(["-i", func])

        returncode, stdout, stderr = await self._run_command(cmd, timeout=timeout)

        return ToolOutput(
            success=returncode == 0,
            data={
                "trace": stdout,
                "functions": functions,
            },
            raw_output=stdout,
            error=stderr if returncode != 0 else None,
        )


class GDBTool(BaseTool):
    """Wrapper for GDB debugger with pwndbg support.

    Provides automated debugging operations through GDB commands.
    Enhanced functionality available when pwndbg is installed.
    """

    name = "gdb"
    description = "GNU Debugger with exploitation features (pwndbg compatible)"
    required_binary = "gdb"

    async def run(
        self,
        target: str,
        operation: str = "analyze",
        commands: list[str] | None = None,
        core_file: str | None = None,
        timeout: int = 60,
        **kwargs: Any,
    ) -> ToolOutput:
        """Run GDB operation.

        Args:
            target: Target binary path.
            operation: Operation to perform:
                - analyze: Run analysis commands
                - checksec: Check security properties (pwndbg)
                - vmmap: Show memory mappings
                - examine: Examine memory/registers
                - run_commands: Run custom GDB commands
            commands: Custom GDB commands to run.
            core_file: Core dump file for post-mortem debugging.
            timeout: Execution timeout in seconds.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with debugging results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="GDB is not installed",
            )

        if not os.path.exists(target) and operation not in ["vmmap"]:
            return ToolOutput(
                success=False,
                data={},
                error=f"Target binary not found: {target}",
            )

        try:
            if operation == "analyze":
                return await self._analyze(target, core_file, timeout)
            elif operation == "checksec":
                return await self._checksec(target, timeout)
            elif operation == "vmmap":
                return await self._vmmap(target, timeout)
            elif operation == "examine":
                return await self._examine(
                    target,
                    kwargs.get("address"),
                    kwargs.get("format", "x"),
                    kwargs.get("count", 16),
                    timeout,
                )
            elif operation == "run_commands":
                if not commands:
                    return ToolOutput(
                        success=False,
                        data={},
                        error="No commands specified",
                    )
                return await self._run_gdb_commands(target, commands, core_file, timeout)
            else:
                return ToolOutput(
                    success=False,
                    data={},
                    error=f"Unknown operation: {operation}",
                )
        except Exception as e:
            return ToolOutput(
                success=False,
                data={},
                error=f"GDB error: {str(e)}",
            )

    async def _run_gdb_commands(
        self,
        target: str,
        commands: list[str],
        core_file: str | None = None,
        timeout: int = 60,
    ) -> ToolOutput:
        """Run GDB with specified commands."""
        # Build command file
        gdb_script = "\n".join(commands) + "\nquit\n"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
            f.write(gdb_script)
            script_path = f.name

        try:
            cmd = ["gdb", "-batch", "-x", script_path, target]
            if core_file:
                cmd.extend(["-c", core_file])

            returncode, stdout, stderr = await self._run_command(cmd, timeout=timeout)

            return ToolOutput(
                success=returncode == 0,
                data={
                    "output": stdout,
                    "commands": commands,
                },
                raw_output=stdout,
                error=stderr if returncode != 0 else None,
            )
        finally:
            os.unlink(script_path)

    async def _analyze(self, target: str, core_file: str | None, timeout: int) -> ToolOutput:
        """Run basic binary analysis."""
        commands = [
            "info file",
            "info functions",
            "info variables",
            "maintenance info sections",
        ]

        return await self._run_gdb_commands(target, commands, core_file, timeout)

    async def _checksec(self, target: str, timeout: int) -> ToolOutput:
        """Check binary security properties (requires pwndbg)."""
        commands = ["checksec"]

        result = await self._run_gdb_commands(target, commands, timeout=timeout)

        # Parse checksec output if available
        if result.success and result.raw_output:
            security = {}
            for line in result.raw_output.split("\n"):
                if "RELRO" in line:
                    security["relro"] = (
                        "Full" if "Full" in line else "Partial" if "Partial" in line else "None"
                    )
                elif "STACK CANARY" in line:
                    security["canary"] = "Canary found" in line
                elif "NX" in line:
                    security["nx"] = "NX enabled" in line
                elif "PIE" in line:
                    security["pie"] = "PIE enabled" in line

            result.data["security"] = security

        return result

    async def _vmmap(self, target: str, timeout: int) -> ToolOutput:
        """Show memory mappings (requires pwndbg or running process)."""
        commands = ["vmmap"]
        return await self._run_gdb_commands(target, commands, timeout=timeout)

    async def _examine(
        self,
        target: str,
        address: str | None,
        fmt: str,
        count: int,
        timeout: int,
    ) -> ToolOutput:
        """Examine memory at address."""
        if not address:
            return ToolOutput(
                success=False,
                data={},
                error="No address specified for examine operation",
            )

        commands = [f"x/{count}{fmt} {address}"]
        return await self._run_gdb_commands(target, commands, timeout=timeout)


class AFLTool(BaseTool):
    """Wrapper for AFL++ fuzzer.

    AFL++ is a coverage-guided fuzzer for finding bugs and vulnerabilities
    through automated input mutation.
    """

    name = "afl"
    description = "American Fuzzy Lop++ coverage-guided fuzzer"
    required_binary = "afl-fuzz"

    async def run(
        self,
        target: str,
        operation: str = "fuzz",
        input_dir: str | None = None,
        output_dir: str | None = None,
        timeout: int = 3600,
        **kwargs: Any,
    ) -> ToolOutput:
        """Run AFL++ operation.

        Args:
            target: Target binary path.
            operation: Operation to perform:
                - fuzz: Start fuzzing campaign
                - showmap: Show coverage map for input
                - cmin: Minimize test corpus
                - tmin: Minimize single test case
                - analyze: Analyze crash/hang
            input_dir: Input corpus directory.
            output_dir: Output directory for results.
            timeout: Fuzzing timeout in seconds (default 1 hour).
            **kwargs: Additional AFL arguments.

        Returns:
            ToolOutput with fuzzing results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="AFL++ is not installed. Install from: https://github.com/AFLplusplus/AFLplusplus",
            )

        if not os.path.exists(target):
            return ToolOutput(
                success=False,
                data={},
                error=f"Target binary not found: {target}",
            )

        try:
            if operation == "fuzz":
                return await self._fuzz(
                    target,
                    input_dir,
                    output_dir,
                    timeout,
                    kwargs.get("args", ""),
                    kwargs.get("dictionary"),
                )
            elif operation == "showmap":
                return await self._showmap(
                    target,
                    kwargs.get("test_input"),
                    timeout,
                )
            elif operation == "cmin":
                return await self._corpus_minimize(
                    target,
                    input_dir,
                    output_dir,
                    timeout,
                )
            elif operation == "tmin":
                return await self._testcase_minimize(
                    target,
                    kwargs.get("test_input"),
                    output_dir,
                    timeout,
                )
            elif operation == "analyze":
                return await self._analyze_crash(
                    target,
                    kwargs.get("crash_file"),
                )
            else:
                return ToolOutput(
                    success=False,
                    data={},
                    error=f"Unknown operation: {operation}",
                )
        except Exception as e:
            return ToolOutput(
                success=False,
                data={},
                error=f"AFL++ error: {str(e)}",
            )

    async def _fuzz(
        self,
        target: str,
        input_dir: str | None,
        output_dir: str | None,
        timeout: int,
        extra_args: str,
        dictionary: str | None,
    ) -> ToolOutput:
        """Start fuzzing campaign."""
        # Create default directories if not specified
        if not input_dir:
            input_dir = tempfile.mkdtemp(prefix="afl_in_")
            # Create a minimal seed
            with open(os.path.join(input_dir, "seed"), "w") as f:
                f.write("AAAA")

        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix="afl_out_")

        cmd = [
            "afl-fuzz",
            "-i",
            input_dir,
            "-o",
            output_dir,
        ]

        if dictionary and os.path.exists(dictionary):
            cmd.extend(["-x", dictionary])

        # Add target
        cmd.extend(["--", target])

        if extra_args:
            cmd.extend(extra_args.split())

        # Note: AFL runs indefinitely, so we just start it and collect initial stats
        returncode, stdout, stderr = await self._run_command(cmd, timeout=timeout)

        # Try to read fuzzer_stats if available
        stats = {}
        stats_file = os.path.join(output_dir, "default", "fuzzer_stats")
        if os.path.exists(stats_file):
            with open(stats_file) as f:
                for line in f:
                    if ":" in line:
                        key, value = line.split(":", 1)
                        stats[key.strip()] = value.strip()

        return ToolOutput(
            success=True,  # AFL exit doesn't mean failure
            data={
                "input_dir": input_dir,
                "output_dir": output_dir,
                "stats": stats,
            },
            raw_output=stdout + stderr,
        )

    async def _showmap(self, target: str, test_input: str | None, timeout: int) -> ToolOutput:
        """Show coverage map for a test input."""
        if not test_input or not os.path.exists(test_input):
            return ToolOutput(
                success=False,
                data={},
                error="Test input file not found",
            )

        cmd = [
            "afl-showmap",
            "-o",
            "/dev/stdout",
            "-q",
            "--",
            target,
        ]

        returncode, stdout, stderr = await self._run_command(
            cmd,
            timeout=timeout,
        )

        # Parse coverage map
        coverage = {}
        for line in stdout.split("\n"):
            if ":" in line:
                edge, count = line.split(":")
                coverage[edge] = int(count)

        return ToolOutput(
            success=returncode == 0,
            data={
                "coverage_edges": len(coverage),
                "coverage": dict(list(coverage.items())[:100]),  # Limit output
            },
            raw_output=stdout,
        )

    async def _corpus_minimize(
        self,
        target: str,
        input_dir: str | None,
        output_dir: str | None,
        timeout: int,
    ) -> ToolOutput:
        """Minimize test corpus."""
        if not input_dir or not os.path.exists(input_dir):
            return ToolOutput(
                success=False,
                data={},
                error="Input directory not found",
            )

        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix="afl_cmin_")

        cmd = [
            "afl-cmin",
            "-i",
            input_dir,
            "-o",
            output_dir,
            "--",
            target,
        ]

        returncode, stdout, stderr = await self._run_command(cmd, timeout=timeout)

        # Count files
        input_count = len(list(Path(input_dir).glob("*")))
        output_count = len(list(Path(output_dir).glob("*")))

        return ToolOutput(
            success=returncode == 0,
            data={
                "input_count": input_count,
                "output_count": output_count,
                "reduction_ratio": f"{(1 - output_count / input_count) * 100:.1f}%"
                if input_count > 0
                else "N/A",
                "output_dir": output_dir,
            },
            raw_output=stdout,
            error=stderr if returncode != 0 else None,
        )

    async def _testcase_minimize(
        self,
        target: str,
        test_input: str | None,
        output_dir: str | None,
        timeout: int,
    ) -> ToolOutput:
        """Minimize a single test case."""
        if not test_input or not os.path.exists(test_input):
            return ToolOutput(
                success=False,
                data={},
                error="Test input file not found",
            )

        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix="afl_tmin_")

        output_file = os.path.join(output_dir, "minimized")

        cmd = [
            "afl-tmin",
            "-i",
            test_input,
            "-o",
            output_file,
            "--",
            target,
        ]

        returncode, stdout, stderr = await self._run_command(cmd, timeout=timeout)

        original_size = os.path.getsize(test_input)
        minimized_size = os.path.getsize(output_file) if os.path.exists(output_file) else 0

        return ToolOutput(
            success=returncode == 0,
            data={
                "original_size": original_size,
                "minimized_size": minimized_size,
                "reduction": f"{(1 - minimized_size / original_size) * 100:.1f}%"
                if original_size > 0
                else "N/A",
                "output_file": output_file,
            },
            raw_output=stdout,
            error=stderr if returncode != 0 else None,
        )

    async def _analyze_crash(self, target: str, crash_file: str | None) -> ToolOutput:
        """Analyze a crash file."""
        if not crash_file or not os.path.exists(crash_file):
            return ToolOutput(
                success=False,
                data={},
                error="Crash file not found",
            )

        # Run target with crash input and capture signals
        cmd = [target]

        # Read crash input
        with open(crash_file, "rb") as f:
            crash_input = f.read()

        # We'll just report the crash file info for now
        # Actual crash analysis would require running the binary
        return ToolOutput(
            success=True,
            data={
                "crash_file": crash_file,
                "crash_size": len(crash_input),
                "crash_preview": crash_input[:100].hex(),
            },
        )


class MetasploitTool(BaseTool):
    """Wrapper for Metasploit Framework.

    Provides access to Metasploit's exploitation capabilities
    through msfconsole and msfrpcd.
    """

    name = "metasploit"
    description = "Penetration testing and exploitation framework"
    required_binary = "msfconsole"

    async def run(
        self,
        target: str,
        operation: str = "search",
        module: str | None = None,
        options: dict[str, Any] | None = None,
        timeout: int = 120,
        **kwargs: Any,
    ) -> ToolOutput:
        """Run Metasploit operation.

        Args:
            target: Target for exploitation or search query.
            operation: Operation to perform:
                - search: Search for modules
                - info: Get module information
                - check: Check if target is vulnerable
                - exploit: Run exploit (use with caution!)
            module: Metasploit module path (e.g., exploit/linux/http/example).
            options: Module options as dict.
            timeout: Execution timeout.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with Metasploit results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="Metasploit is not installed",
            )

        try:
            if operation == "search":
                return await self._search(target, timeout)
            elif operation == "info":
                if not module:
                    return ToolOutput(
                        success=False,
                        data={},
                        error="Module path required for info operation",
                    )
                return await self._module_info(module, timeout)
            elif operation == "check":
                if not module:
                    return ToolOutput(
                        success=False,
                        data={},
                        error="Module path required for check operation",
                    )
                return await self._check_vuln(target, module, options or {}, timeout)
            elif operation == "exploit":
                return ToolOutput(
                    success=False,
                    data={},
                    error="Exploit operation disabled for safety. Use msfconsole directly.",
                )
            else:
                return ToolOutput(
                    success=False,
                    data={},
                    error=f"Unknown operation: {operation}",
                )
        except Exception as e:
            return ToolOutput(
                success=False,
                data={},
                error=f"Metasploit error: {str(e)}",
            )

    async def _search(self, query: str, timeout: int) -> ToolOutput:
        """Search for Metasploit modules."""
        # Run msfconsole with resource file
        rc_content = f"search {query}\nexit\n"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rc", delete=False) as f:
            f.write(rc_content)
            rc_path = f.name

        try:
            cmd = ["msfconsole", "-q", "-r", rc_path]

            returncode, stdout, stderr = await self._run_command(cmd, timeout=timeout)

            # Parse search results
            modules = []
            for line in stdout.split("\n"):
                line = line.strip()
                if (
                    line.startswith("exploit/")
                    or line.startswith("auxiliary/")
                    or line.startswith("post/")
                ):
                    parts = line.split()
                    if parts:
                        modules.append(
                            {
                                "module": parts[0],
                                "info": " ".join(parts[1:]) if len(parts) > 1 else "",
                            }
                        )

            return ToolOutput(
                success=True,
                data={
                    "query": query,
                    "modules": modules[:50],  # Limit results
                    "total": len(modules),
                },
                raw_output=stdout,
            )
        finally:
            os.unlink(rc_path)

    async def _module_info(self, module: str, timeout: int) -> ToolOutput:
        """Get information about a module."""
        rc_content = f"use {module}\ninfo\nexit\n"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rc", delete=False) as f:
            f.write(rc_content)
            rc_path = f.name

        try:
            cmd = ["msfconsole", "-q", "-r", rc_path]

            returncode, stdout, stderr = await self._run_command(cmd, timeout=timeout)

            return ToolOutput(
                success=returncode == 0,
                data={
                    "module": module,
                    "info": stdout,
                },
                raw_output=stdout,
            )
        finally:
            os.unlink(rc_path)

    async def _check_vuln(
        self,
        target: str,
        module: str,
        options: dict[str, Any],
        timeout: int,
    ) -> ToolOutput:
        """Check if target is vulnerable using specified module."""
        # Build resource file
        rc_lines = [f"use {module}"]
        rc_lines.append(f"set RHOSTS {target}")

        for key, value in options.items():
            rc_lines.append(f"set {key} {value}")

        rc_lines.extend(["check", "exit"])
        rc_content = "\n".join(rc_lines)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rc", delete=False) as f:
            f.write(rc_content)
            rc_path = f.name

        try:
            cmd = ["msfconsole", "-q", "-r", rc_path]

            returncode, stdout, stderr = await self._run_command(cmd, timeout=timeout)

            # Parse check result
            vulnerable = (
                "is vulnerable" in stdout.lower() or "appears to be vulnerable" in stdout.lower()
            )
            not_vulnerable = "is not vulnerable" in stdout.lower()

            return ToolOutput(
                success=True,
                data={
                    "target": target,
                    "module": module,
                    "vulnerable": vulnerable,
                    "not_vulnerable": not_vulnerable,
                    "inconclusive": not vulnerable and not not_vulnerable,
                },
                raw_output=stdout,
            )
        finally:
            os.unlink(rc_path)


class MSFVenomTool(BaseTool):
    """Wrapper for MSFVenom payload generator.

    MSFVenom generates payloads for use in exploits.
    """

    name = "msfvenom"
    description = "Metasploit payload generator"
    required_binary = "msfvenom"

    async def run(
        self,
        target: str,  # Architecture/platform target
        operation: str = "generate",
        payload: str | None = None,
        format: str = "raw",
        output_file: str | None = None,
        options: dict[str, Any] | None = None,
        encoder: str | None = None,
        iterations: int = 1,
        timeout: int = 60,
        **kwargs: Any,
    ) -> ToolOutput:
        """Run MSFVenom operation.

        Args:
            target: Target architecture (e.g., "linux/x86", "windows/x64").
            operation: Operation to perform:
                - generate: Generate payload
                - list: List available payloads/encoders/formats
            payload: Payload to use (e.g., linux/x86/shell_reverse_tcp).
            format: Output format (raw, elf, exe, python, c, etc.).
            output_file: Optional output file path.
            options: Payload options (LHOST, LPORT, etc.).
            encoder: Encoder to use for evasion.
            iterations: Number of encoding iterations.
            timeout: Execution timeout.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with payload or list results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="MSFVenom is not installed (part of Metasploit)",
            )

        try:
            if operation == "list":
                return await self._list(kwargs.get("type", "payloads"), timeout)
            elif operation == "generate":
                if not payload:
                    return ToolOutput(
                        success=False,
                        data={},
                        error="Payload required for generate operation",
                    )
                return await self._generate(
                    payload,
                    format,
                    output_file,
                    options or {},
                    encoder,
                    iterations,
                    timeout,
                )
            else:
                return ToolOutput(
                    success=False,
                    data={},
                    error=f"Unknown operation: {operation}",
                )
        except Exception as e:
            return ToolOutput(
                success=False,
                data={},
                error=f"MSFVenom error: {str(e)}",
            )

    async def _list(self, list_type: str, timeout: int) -> ToolOutput:
        """List available payloads, encoders, or formats."""
        type_map = {
            "payloads": "-l payloads",
            "encoders": "-l encoders",
            "formats": "--list formats",
            "platforms": "--list platforms",
            "archs": "--list archs",
        }

        if list_type not in type_map:
            return ToolOutput(
                success=False,
                data={},
                error=f"Unknown list type: {list_type}. Valid: {list(type_map.keys())}",
            )

        cmd = f"msfvenom {type_map[list_type]}"

        returncode, stdout, stderr = await self._run_command(cmd, timeout=timeout)

        # Parse output
        items = []
        for line in stdout.split("\n"):
            line = line.strip()
            if line and not line.startswith("=") and not line.startswith("Framework"):
                items.append(line)

        return ToolOutput(
            success=returncode == 0,
            data={
                "type": list_type,
                "items": items[:100],  # Limit output
                "total": len(items),
            },
            raw_output=stdout,
        )

    async def _generate(
        self,
        payload: str,
        format: str,
        output_file: str | None,
        options: dict[str, Any],
        encoder: str | None,
        iterations: int,
        timeout: int,
    ) -> ToolOutput:
        """Generate a payload."""
        cmd = ["msfvenom", "-p", payload, "-f", format]

        # Add options
        for key, value in options.items():
            cmd.append(f"{key}={value}")

        if encoder:
            cmd.extend(["-e", encoder, "-i", str(iterations)])

        if output_file:
            cmd.extend(["-o", output_file])

        returncode, stdout, stderr = await self._run_command(cmd, timeout=timeout)

        result_data = {
            "payload": payload,
            "format": format,
            "options": options,
        }

        if output_file and os.path.exists(output_file):
            result_data["output_file"] = output_file
            result_data["size"] = os.path.getsize(output_file)
        elif stdout:
            result_data["size"] = len(stdout)
            # Don't include raw shellcode in output for safety
            result_data["preview"] = f"Generated {len(stdout)} bytes"

        return ToolOutput(
            success=returncode == 0,
            data=result_data,
            raw_output=f"Generated payload: {len(stdout)} bytes" if stdout else stderr,
            error=stderr if returncode != 0 else None,
        )


class WinDbgTool(BaseTool):
    """Wrapper for WinDbg debugger (Windows only).

    Provides debugging capabilities for Windows binaries.
    """

    name = "windbg"
    description = "Windows Debugger for Windows binary analysis"
    required_binary = "cdb"  # Command-line version of WinDbg

    def is_available(self) -> bool:
        """Check if WinDbg/cdb is available (Windows only)."""
        import platform

        if platform.system() != "Windows":
            self._available = False
            return False

        return super().is_available()

    async def run(
        self,
        target: str,
        operation: str = "analyze",
        commands: list[str] | None = None,
        dump_file: str | None = None,
        timeout: int = 60,
        **kwargs: Any,
    ) -> ToolOutput:
        """Run WinDbg operation.

        Args:
            target: Target binary or process.
            operation: Operation to perform:
                - analyze: Basic binary analysis
                - run_commands: Run custom WinDbg commands
                - dump_analyze: Analyze crash dump
            commands: Custom WinDbg commands.
            dump_file: Crash dump file path.
            timeout: Execution timeout.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with debugging results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="WinDbg/cdb is not available (Windows only)",
            )

        try:
            if operation == "analyze":
                return await self._analyze(target, timeout)
            elif operation == "run_commands":
                if not commands:
                    return ToolOutput(
                        success=False,
                        data={},
                        error="No commands specified",
                    )
                return await self._run_windbg_commands(target, commands, timeout)
            elif operation == "dump_analyze":
                if not dump_file:
                    return ToolOutput(
                        success=False,
                        data={},
                        error="No dump file specified",
                    )
                return await self._analyze_dump(dump_file, timeout)
            else:
                return ToolOutput(
                    success=False,
                    data={},
                    error=f"Unknown operation: {operation}",
                )
        except Exception as e:
            return ToolOutput(
                success=False,
                data={},
                error=f"WinDbg error: {str(e)}",
            )

    async def _run_windbg_commands(
        self, target: str, commands: list[str], timeout: int
    ) -> ToolOutput:
        """Run WinDbg with specified commands."""
        # Join commands with semicolons for WinDbg
        cmd_str = ";".join(commands) + ";q"

        cmd = ["cdb", "-c", cmd_str, target]

        returncode, stdout, stderr = await self._run_command(cmd, timeout=timeout)

        return ToolOutput(
            success=returncode == 0,
            data={
                "output": stdout,
                "commands": commands,
            },
            raw_output=stdout,
            error=stderr if returncode != 0 else None,
        )

    async def _analyze(self, target: str, timeout: int) -> ToolOutput:
        """Run basic analysis on target."""
        commands = ["lm", "x *!*main*", ".symfix", ".reload"]
        return await self._run_windbg_commands(target, commands, timeout)

    async def _analyze_dump(self, dump_file: str, timeout: int) -> ToolOutput:
        """Analyze a crash dump file."""
        cmd = ["cdb", "-z", dump_file, "-c", "!analyze -v;q"]

        returncode, stdout, stderr = await self._run_command(cmd, timeout=timeout)

        return ToolOutput(
            success=returncode == 0,
            data={
                "dump_file": dump_file,
                "analysis": stdout,
            },
            raw_output=stdout,
            error=stderr if returncode != 0 else None,
        )


class WinAFLTool(BaseTool):
    """Wrapper for WinAFL fuzzer (Windows only).

    WinAFL is a Windows port of AFL for fuzzing Windows applications.
    """

    name = "winafl"
    description = "Windows AFL fuzzer for Windows applications"
    required_binary = "afl-fuzz.exe"

    def is_available(self) -> bool:
        """Check if WinAFL is available (Windows only)."""
        import platform

        if platform.system() != "Windows":
            self._available = False
            return False

        return super().is_available()

    async def run(
        self,
        target: str,
        operation: str = "fuzz",
        input_dir: str | None = None,
        output_dir: str | None = None,
        target_module: str | None = None,
        target_offset: str | None = None,
        timeout: int = 3600,
        **kwargs: Any,
    ) -> ToolOutput:
        """Run WinAFL operation.

        Args:
            target: Target binary path.
            operation: Operation to perform:
                - fuzz: Start fuzzing with DynamoRIO
                - drrun: Run with DynamoRIO instrumentation
            input_dir: Input corpus directory.
            output_dir: Output directory.
            target_module: Target module name for coverage.
            target_offset: Target function offset.
            timeout: Execution timeout.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with fuzzing results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="WinAFL is not available (Windows only)",
            )

        if not os.path.exists(target):
            return ToolOutput(
                success=False,
                data={},
                error=f"Target binary not found: {target}",
            )

        try:
            if operation == "fuzz":
                return await self._fuzz(
                    target,
                    input_dir,
                    output_dir,
                    target_module,
                    target_offset,
                    timeout,
                    kwargs,
                )
            elif operation == "drrun":
                return await self._drrun(target, target_module, timeout)
            else:
                return ToolOutput(
                    success=False,
                    data={},
                    error=f"Unknown operation: {operation}",
                )
        except Exception as e:
            return ToolOutput(
                success=False,
                data={},
                error=f"WinAFL error: {str(e)}",
            )

    async def _fuzz(
        self,
        target: str,
        input_dir: str | None,
        output_dir: str | None,
        target_module: str | None,
        target_offset: str | None,
        timeout: int,
        extra_kwargs: dict[str, Any],
    ) -> ToolOutput:
        """Start WinAFL fuzzing campaign."""
        if not input_dir:
            input_dir = tempfile.mkdtemp(prefix="winafl_in_")
            with open(os.path.join(input_dir, "seed.txt"), "w") as f:
                f.write("AAAA")

        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix="winafl_out_")

        if not target_module:
            target_module = os.path.basename(target)

        dynamorio_dir = extra_kwargs.get("dynamorio_dir", r"C:\DynamoRIO\bin64")

        cmd = [
            "afl-fuzz.exe",
            "-i",
            input_dir,
            "-o",
            output_dir,
            "-D",
            dynamorio_dir,
            "-t",
            "10000",
            "--",
            "-coverage_module",
            target_module,
        ]

        if target_offset:
            cmd.extend(["-target_offset", target_offset])

        cmd.extend(["--", target, "@@"])

        returncode, stdout, stderr = await self._run_command(cmd, timeout=timeout)

        return ToolOutput(
            success=True,
            data={
                "input_dir": input_dir,
                "output_dir": output_dir,
                "target_module": target_module,
            },
            raw_output=stdout + stderr,
        )

    async def _drrun(self, target: str, target_module: str | None, timeout: int) -> ToolOutput:
        """Run target with DynamoRIO instrumentation for testing."""
        if not target_module:
            target_module = os.path.basename(target)

        cmd = [
            "drrun.exe",
            "-c",
            "winafl.dll",
            "-coverage_module",
            target_module,
            "-debug",
            "--",
            target,
        ]

        returncode, stdout, stderr = await self._run_command(cmd, timeout=timeout)

        return ToolOutput(
            success=returncode == 0,
            data={
                "output": stdout,
                "target_module": target_module,
            },
            raw_output=stdout,
            error=stderr if returncode != 0 else None,
        )
