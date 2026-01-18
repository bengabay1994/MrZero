"""Unit tests for dynamic analysis tools."""

import os
import platform
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mrzero.tools.dynamic_analysis import (
    PwntoolsTool,
    FridaTool,
    GDBTool,
    AFLTool,
    MetasploitTool,
    MSFVenomTool,
    WinDbgTool,
    WinAFLTool,
)


class TestPwntoolsTool:
    """Tests for pwntools wrapper."""

    def test_tool_properties(self):
        """Test tool properties are set correctly."""
        tool = PwntoolsTool()
        assert tool.name == "pwntools"
        assert tool.description is not None
        assert "exploit" in tool.description.lower()

    def test_is_available_checks_import(self):
        """Test availability check uses import."""
        tool = PwntoolsTool()
        # Reset cached value
        tool._pwn_available = None

        # Should try to import pwn
        result = tool.is_available()
        # Result depends on whether pwntools is installed
        assert isinstance(result, bool)

    @pytest.mark.asyncio
    async def test_unavailable_returns_error(self, temp_dir):
        """Test unavailable tool returns appropriate error."""
        tool = PwntoolsTool()
        tool._pwn_available = False

        result = await tool.run(str(temp_dir))

        assert result.success is False
        assert "not installed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_nonexistent_target_returns_error(self, temp_dir):
        """Test nonexistent target returns error."""
        tool = PwntoolsTool()
        tool._pwn_available = True

        result = await tool.run("/nonexistent/binary")

        assert result.success is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_unknown_operation_returns_error(self, temp_dir):
        """Test unknown operation returns error."""
        tool = PwntoolsTool()
        tool._pwn_available = True

        # Create a dummy file
        dummy = temp_dir / "dummy"
        dummy.write_bytes(b"\x7fELF")

        result = await tool.run(str(dummy), operation="unknown_op")

        assert result.success is False
        assert "unknown operation" in result.error.lower()

    @pytest.mark.asyncio
    async def test_checksec_operation(self, temp_dir):
        """Test checksec operation with mocked pwntools."""
        tool = PwntoolsTool()
        tool._pwn_available = True

        # Create a dummy ELF file
        dummy = temp_dir / "test_binary"
        dummy.write_bytes(b"\x7fELF" + b"\x00" * 100)

        # Mock pwntools ELF class
        with patch("mrzero.tools.dynamic_analysis.PwntoolsTool._checksec") as mock_checksec:
            from mrzero.tools.base import ToolOutput

            mock_checksec.return_value = ToolOutput(
                success=True,
                data={
                    "security": {
                        "arch": "amd64",
                        "bits": 64,
                        "canary": True,
                        "nx": True,
                        "pie": True,
                        "relro": "Full",
                    },
                    "file": str(dummy),
                },
            )

            result = await tool.run(str(dummy), operation="checksec")

            assert result.success is True
            assert "security" in result.data


class TestFridaTool:
    """Tests for Frida wrapper."""

    def test_tool_properties(self):
        """Test tool properties are set correctly."""
        tool = FridaTool()
        assert tool.name == "frida"
        assert tool.required_binary == "frida"
        assert "instrumentation" in tool.description.lower()

    @pytest.mark.asyncio
    async def test_unavailable_returns_error(self):
        """Test unavailable tool returns error."""
        tool = FridaTool()
        tool._available = False

        result = await tool.run("target")

        assert result.success is False
        assert "not installed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_list_processes(self):
        """Test list processes operation."""
        tool = FridaTool()
        tool._available = True

        with patch.object(tool, "_run_command") as mock_run:
            mock_run.return_value = (0, "PID  Name\n123  test_app", "")

            result = await tool.run("", operation="list")

            assert result.success is True
            assert "processes" in result.data

    @pytest.mark.asyncio
    async def test_trace_no_functions_error(self):
        """Test trace without functions returns error."""
        tool = FridaTool()
        tool._available = True

        result = await tool.run("target", operation="trace", functions=[])

        assert result.success is False
        assert "no functions" in result.error.lower()


class TestGDBTool:
    """Tests for GDB wrapper."""

    def test_tool_properties(self):
        """Test tool properties are set correctly."""
        tool = GDBTool()
        assert tool.name == "gdb"
        assert tool.required_binary == "gdb"
        assert "debugger" in tool.description.lower()

    @pytest.mark.asyncio
    async def test_unavailable_returns_error(self, temp_dir):
        """Test unavailable tool returns error."""
        tool = GDBTool()
        tool._available = False

        result = await tool.run(str(temp_dir))

        assert result.success is False
        assert "not installed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_nonexistent_target_returns_error(self):
        """Test nonexistent target returns error."""
        tool = GDBTool()
        tool._available = True

        result = await tool.run("/nonexistent/binary", operation="analyze")

        assert result.success is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_run_commands_no_commands_error(self, temp_dir):
        """Test run_commands without commands returns error."""
        tool = GDBTool()
        tool._available = True

        dummy = temp_dir / "dummy"
        dummy.write_bytes(b"\x7fELF")

        result = await tool.run(str(dummy), operation="run_commands", commands=None)

        assert result.success is False
        assert "no commands" in result.error.lower()

    @pytest.mark.asyncio
    async def test_examine_no_address_error(self, temp_dir):
        """Test examine without address returns error."""
        tool = GDBTool()
        tool._available = True

        dummy = temp_dir / "dummy"
        dummy.write_bytes(b"\x7fELF")

        result = await tool.run(str(dummy), operation="examine", address=None)

        assert result.success is False
        assert "no address" in result.error.lower()

    @pytest.mark.asyncio
    async def test_unknown_operation_error(self, temp_dir):
        """Test unknown operation returns error."""
        tool = GDBTool()
        tool._available = True

        dummy = temp_dir / "dummy"
        dummy.write_bytes(b"\x7fELF")

        result = await tool.run(str(dummy), operation="unknown_op")

        assert result.success is False
        assert "unknown operation" in result.error.lower()


class TestAFLTool:
    """Tests for AFL++ wrapper."""

    def test_tool_properties(self):
        """Test tool properties are set correctly."""
        tool = AFLTool()
        assert tool.name == "afl"
        assert tool.required_binary == "afl-fuzz"
        assert "fuzzer" in tool.description.lower()

    @pytest.mark.asyncio
    async def test_unavailable_returns_error(self, temp_dir):
        """Test unavailable tool returns error."""
        tool = AFLTool()
        tool._available = False

        result = await tool.run(str(temp_dir))

        assert result.success is False
        assert "not installed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_nonexistent_target_returns_error(self):
        """Test nonexistent target returns error."""
        tool = AFLTool()
        tool._available = True

        result = await tool.run("/nonexistent/binary")

        assert result.success is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_showmap_no_input_error(self, temp_dir):
        """Test showmap without input returns error."""
        tool = AFLTool()
        tool._available = True

        dummy = temp_dir / "dummy"
        dummy.write_bytes(b"\x7fELF")

        result = await tool.run(str(dummy), operation="showmap", test_input=None)

        assert result.success is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_cmin_no_input_dir_error(self, temp_dir):
        """Test corpus minimize without input dir returns error."""
        tool = AFLTool()
        tool._available = True

        dummy = temp_dir / "dummy"
        dummy.write_bytes(b"\x7fELF")

        result = await tool.run(str(dummy), operation="cmin", input_dir=None)

        assert result.success is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_tmin_no_input_error(self, temp_dir):
        """Test testcase minimize without input returns error."""
        tool = AFLTool()
        tool._available = True

        dummy = temp_dir / "dummy"
        dummy.write_bytes(b"\x7fELF")

        result = await tool.run(str(dummy), operation="tmin", test_input=None)

        assert result.success is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_analyze_crash_no_file_error(self, temp_dir):
        """Test analyze crash without file returns error."""
        tool = AFLTool()
        tool._available = True

        dummy = temp_dir / "dummy"
        dummy.write_bytes(b"\x7fELF")

        result = await tool.run(str(dummy), operation="analyze", crash_file=None)

        assert result.success is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_unknown_operation_error(self, temp_dir):
        """Test unknown operation returns error."""
        tool = AFLTool()
        tool._available = True

        dummy = temp_dir / "dummy"
        dummy.write_bytes(b"\x7fELF")

        result = await tool.run(str(dummy), operation="unknown_op")

        assert result.success is False
        assert "unknown operation" in result.error.lower()


class TestMetasploitTool:
    """Tests for Metasploit wrapper."""

    def test_tool_properties(self):
        """Test tool properties are set correctly."""
        tool = MetasploitTool()
        assert tool.name == "metasploit"
        assert tool.required_binary == "msfconsole"
        assert "exploit" in tool.description.lower() or "penetration" in tool.description.lower()

    @pytest.mark.asyncio
    async def test_unavailable_returns_error(self):
        """Test unavailable tool returns error."""
        tool = MetasploitTool()
        tool._available = False

        result = await tool.run("target")

        assert result.success is False
        assert "not installed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_exploit_disabled(self):
        """Test exploit operation is disabled for safety."""
        tool = MetasploitTool()
        tool._available = True

        result = await tool.run("target", operation="exploit")

        assert result.success is False
        assert "disabled" in result.error.lower()

    @pytest.mark.asyncio
    async def test_info_no_module_error(self):
        """Test info without module returns error."""
        tool = MetasploitTool()
        tool._available = True

        result = await tool.run("target", operation="info", module=None)

        assert result.success is False
        assert "module" in result.error.lower()

    @pytest.mark.asyncio
    async def test_check_no_module_error(self):
        """Test check without module returns error."""
        tool = MetasploitTool()
        tool._available = True

        result = await tool.run("target", operation="check", module=None)

        assert result.success is False
        assert "module" in result.error.lower()

    @pytest.mark.asyncio
    async def test_unknown_operation_error(self):
        """Test unknown operation returns error."""
        tool = MetasploitTool()
        tool._available = True

        result = await tool.run("target", operation="unknown_op")

        assert result.success is False
        assert "unknown operation" in result.error.lower()


class TestMSFVenomTool:
    """Tests for MSFVenom wrapper."""

    def test_tool_properties(self):
        """Test tool properties are set correctly."""
        tool = MSFVenomTool()
        assert tool.name == "msfvenom"
        assert tool.required_binary == "msfvenom"
        assert "payload" in tool.description.lower()

    @pytest.mark.asyncio
    async def test_unavailable_returns_error(self):
        """Test unavailable tool returns error."""
        tool = MSFVenomTool()
        tool._available = False

        result = await tool.run("linux/x86")

        assert result.success is False
        assert "not installed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_generate_no_payload_error(self):
        """Test generate without payload returns error."""
        tool = MSFVenomTool()
        tool._available = True

        result = await tool.run("linux/x86", operation="generate", payload=None)

        assert result.success is False
        assert "payload required" in result.error.lower()

    @pytest.mark.asyncio
    async def test_list_invalid_type_error(self):
        """Test list with invalid type returns error."""
        tool = MSFVenomTool()
        tool._available = True

        result = await tool.run("linux/x86", operation="list", type="invalid")

        assert result.success is False
        assert "unknown list type" in result.error.lower()

    @pytest.mark.asyncio
    async def test_unknown_operation_error(self):
        """Test unknown operation returns error."""
        tool = MSFVenomTool()
        tool._available = True

        result = await tool.run("linux/x86", operation="unknown_op")

        assert result.success is False
        assert "unknown operation" in result.error.lower()


class TestWinDbgTool:
    """Tests for WinDbg wrapper."""

    def test_tool_properties(self):
        """Test tool properties are set correctly."""
        tool = WinDbgTool()
        assert tool.name == "windbg"
        assert tool.required_binary == "cdb"
        assert "windows" in tool.description.lower()

    def test_availability_requires_windows(self):
        """Test availability check requires Windows."""
        tool = WinDbgTool()
        tool._available = None

        # On non-Windows, should return False
        if platform.system() != "Windows":
            assert tool.is_available() is False

    @pytest.mark.asyncio
    async def test_unavailable_returns_error(self):
        """Test unavailable tool returns error."""
        tool = WinDbgTool()
        tool._available = False

        result = await tool.run("target.exe")

        assert result.success is False
        assert "not available" in result.error.lower()

    @pytest.mark.asyncio
    async def test_run_commands_no_commands_error(self):
        """Test run_commands without commands returns error."""
        tool = WinDbgTool()

        # Skip if not on Windows (can't set _available to True on non-Windows)
        if platform.system() != "Windows":
            # Verify the tool reports unavailable on non-Windows
            result = await tool.run("target.exe", operation="run_commands", commands=None)
            assert result.success is False
            assert "not available" in result.error.lower()
            return

        tool._available = True
        result = await tool.run("target.exe", operation="run_commands", commands=None)
        assert result.success is False
        assert "no commands" in result.error.lower()

    @pytest.mark.asyncio
    async def test_dump_analyze_no_file_error(self):
        """Test dump_analyze without file returns error."""
        tool = WinDbgTool()

        # Skip if not on Windows
        if platform.system() != "Windows":
            result = await tool.run("target.exe", operation="dump_analyze", dump_file=None)
            assert result.success is False
            assert "not available" in result.error.lower()
            return

        tool._available = True
        result = await tool.run("target.exe", operation="dump_analyze", dump_file=None)
        assert result.success is False
        assert "no dump file" in result.error.lower()

    @pytest.mark.asyncio
    async def test_unknown_operation_error(self):
        """Test unknown operation returns error."""
        tool = WinDbgTool()

        # Skip if not on Windows
        if platform.system() != "Windows":
            result = await tool.run("target.exe", operation="unknown_op")
            assert result.success is False
            assert "not available" in result.error.lower()
            return

        tool._available = True
        result = await tool.run("target.exe", operation="unknown_op")
        assert result.success is False
        assert "unknown operation" in result.error.lower()


class TestWinAFLTool:
    """Tests for WinAFL wrapper."""

    def test_tool_properties(self):
        """Test tool properties are set correctly."""
        tool = WinAFLTool()
        assert tool.name == "winafl"
        assert tool.required_binary == "afl-fuzz.exe"
        assert "windows" in tool.description.lower()

    def test_availability_requires_windows(self):
        """Test availability check requires Windows."""
        tool = WinAFLTool()
        tool._available = None

        # On non-Windows, should return False
        if platform.system() != "Windows":
            assert tool.is_available() is False

    @pytest.mark.asyncio
    async def test_unavailable_returns_error(self):
        """Test unavailable tool returns error."""
        tool = WinAFLTool()
        tool._available = False

        result = await tool.run("target.exe")

        assert result.success is False
        assert "not available" in result.error.lower()

    @pytest.mark.asyncio
    async def test_nonexistent_target_error(self):
        """Test nonexistent target returns error."""
        tool = WinAFLTool()

        # Skip if not on Windows
        if platform.system() != "Windows":
            result = await tool.run("/nonexistent/target.exe")
            assert result.success is False
            assert "not available" in result.error.lower()
            return

        tool._available = True
        result = await tool.run("/nonexistent/target.exe")
        assert result.success is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_unknown_operation_error(self, temp_dir):
        """Test unknown operation returns error."""
        tool = WinAFLTool()

        # Skip if not on Windows
        if platform.system() != "Windows":
            result = await tool.run("dummy.exe", operation="unknown_op")
            assert result.success is False
            assert "not available" in result.error.lower()
            return

        tool._available = True
        dummy = temp_dir / "dummy.exe"
        dummy.write_bytes(b"MZ" + b"\x00" * 100)

        result = await tool.run(str(dummy), operation="unknown_op")

        assert result.success is False
        assert "unknown operation" in result.error.lower()


class TestToolImports:
    """Test that all tools can be imported from the module."""

    def test_import_from_tools_package(self):
        """Test importing tools from main package."""
        from mrzero.tools import (
            PwntoolsTool,
            FridaTool,
            GDBTool,
            AFLTool,
            MetasploitTool,
            MSFVenomTool,
            WinDbgTool,
            WinAFLTool,
        )

        # Verify all classes are accessible
        assert PwntoolsTool is not None
        assert FridaTool is not None
        assert GDBTool is not None
        assert AFLTool is not None
        assert MetasploitTool is not None
        assert MSFVenomTool is not None
        assert WinDbgTool is not None
        assert WinAFLTool is not None

    def test_tool_inheritance(self):
        """Test all tools inherit from BaseTool."""
        from mrzero.tools.base import BaseTool

        tools = [
            PwntoolsTool(),
            FridaTool(),
            GDBTool(),
            AFLTool(),
            MetasploitTool(),
            MSFVenomTool(),
            WinDbgTool(),
            WinAFLTool(),
        ]

        for tool in tools:
            assert isinstance(tool, BaseTool), f"{tool.name} should inherit from BaseTool"


class TestToolCompatibilityMatrix:
    """Test tool compatibility matrix includes dynamic tools."""

    def test_dynamic_tools_in_compatibility_matrix(self):
        """Test dynamic tools are in compatibility matrix."""
        from mrzero.core.sast_runner import ToolCompatibility

        compat = ToolCompatibility()

        dynamic_tools = [
            "pwntools",
            "frida",
            "gdb",
            "afl",
            "metasploit",
            "msfvenom",
            "windbg",
            "winafl",
        ]

        for tool in dynamic_tools:
            assert tool in compat.TOOL_COMPATIBILITY, f"{tool} should be in compatibility matrix"

    def test_platform_specific_tools(self):
        """Test platform-specific tools have correct platforms."""
        from mrzero.core.sast_runner import ToolCompatibility

        compat = ToolCompatibility()

        # Linux-only tools
        assert "windows" not in compat.TOOL_COMPATIBILITY["afl"]["platforms"]
        assert "linux" in compat.TOOL_COMPATIBILITY["afl"]["platforms"]

        # Windows-only tools
        assert compat.TOOL_COMPATIBILITY["windbg"]["platforms"] == ["windows"]
        assert compat.TOOL_COMPATIBILITY["winafl"]["platforms"] == ["windows"]

        # Cross-platform tools
        assert "linux" in compat.TOOL_COMPATIBILITY["frida"]["platforms"]
        assert "windows" in compat.TOOL_COMPATIBILITY["frida"]["platforms"]
