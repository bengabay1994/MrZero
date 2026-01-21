"""Tests for LLM Tool Calling infrastructure."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from mrzero.core.llm.tool_calling import (
    ToolCall,
    ToolDefinition,
    ToolParameter,
    ToolParameterType,
    ToolRegistry,
    ToolResult,
    parse_tool_calls_from_bedrock,
    format_tool_results_for_bedrock,
)
from mrzero.core.llm.security_tools import (
    create_security_tool_registry,
    get_available_tools,
)


class TestToolDefinition:
    """Tests for ToolDefinition class."""

    def test_create_simple_definition(self):
        """Test creating a simple tool definition."""
        definition = ToolDefinition(
            name="test_tool",
            description="A test tool",
            parameters=[
                ToolParameter(
                    name="target",
                    description="Target path",
                    type=ToolParameterType.STRING,
                    required=True,
                ),
            ],
        )

        assert definition.name == "test_tool"
        assert definition.description == "A test tool"
        assert len(definition.parameters) == 1
        assert definition.parameters[0].name == "target"

    def test_to_bedrock_format(self):
        """Test converting definition to Bedrock format."""
        definition = ToolDefinition(
            name="scan_code",
            description="Scan code for vulnerabilities",
            parameters=[
                ToolParameter(
                    name="target",
                    description="Target directory",
                    type=ToolParameterType.STRING,
                    required=True,
                ),
                ToolParameter(
                    name="recursive",
                    description="Scan recursively",
                    type=ToolParameterType.BOOLEAN,
                    required=False,
                    default=True,
                ),
            ],
        )

        bedrock_format = definition.to_bedrock_format()

        assert "toolSpec" in bedrock_format
        spec = bedrock_format["toolSpec"]
        assert spec["name"] == "scan_code"
        assert spec["description"] == "Scan code for vulnerabilities"
        assert "inputSchema" in spec

        schema = spec["inputSchema"]["json"]
        assert schema["type"] == "object"
        assert "target" in schema["properties"]
        assert "recursive" in schema["properties"]
        assert "target" in schema["required"]
        assert "recursive" not in schema["required"]

    def test_to_openai_format(self):
        """Test converting definition to OpenAI format."""
        definition = ToolDefinition(
            name="read_file",
            description="Read a file",
            parameters=[
                ToolParameter(
                    name="path",
                    description="File path",
                    type=ToolParameterType.STRING,
                    required=True,
                ),
            ],
        )

        openai_format = definition.to_openai_format()

        assert openai_format["type"] == "function"
        assert "function" in openai_format
        func = openai_format["function"]
        assert func["name"] == "read_file"
        assert func["description"] == "Read a file"
        assert "parameters" in func

    def test_enum_parameter(self):
        """Test parameter with enum values."""
        definition = ToolDefinition(
            name="scan",
            description="Scan",
            parameters=[
                ToolParameter(
                    name="scan_type",
                    description="Type of scan",
                    type=ToolParameterType.STRING,
                    required=True,
                    enum=["fs", "image", "config"],
                ),
            ],
        )

        bedrock_format = definition.to_bedrock_format()
        schema = bedrock_format["toolSpec"]["inputSchema"]["json"]

        assert schema["properties"]["scan_type"]["enum"] == ["fs", "image", "config"]

    def test_array_parameter(self):
        """Test array type parameter."""
        definition = ToolDefinition(
            name="batch_scan",
            description="Scan multiple files",
            parameters=[
                ToolParameter(
                    name="files",
                    description="List of files to scan",
                    type=ToolParameterType.ARRAY,
                    required=True,
                    items_type=ToolParameterType.STRING,
                ),
            ],
        )

        bedrock_format = definition.to_bedrock_format()
        schema = bedrock_format["toolSpec"]["inputSchema"]["json"]

        assert schema["properties"]["files"]["type"] == "array"
        assert schema["properties"]["files"]["items"]["type"] == "string"


class TestToolRegistry:
    """Tests for ToolRegistry class."""

    def test_register_and_get_tool(self):
        """Test registering and retrieving a tool."""
        registry = ToolRegistry()

        definition = ToolDefinition(
            name="test_tool",
            description="Test",
            parameters=[],
        )

        async def executor(tool_call_id: str) -> ToolResult:
            return ToolResult(
                tool_call_id=tool_call_id,
                name="test_tool",
                success=True,
                output="result",
            )

        registry.register(definition, executor)

        assert "test_tool" in registry.list_tools()
        assert registry.get_definition("test_tool") is not None
        assert registry.get_executor("test_tool") is not None

    def test_list_tools(self):
        """Test listing registered tools."""
        registry = ToolRegistry()

        for i in range(3):
            definition = ToolDefinition(name=f"tool_{i}", description=f"Tool {i}")
            registry.register(definition, AsyncMock())

        tools = registry.list_tools()
        assert len(tools) == 3
        assert "tool_0" in tools
        assert "tool_1" in tools
        assert "tool_2" in tools

    @pytest.mark.asyncio
    async def test_execute_tool(self):
        """Test executing a tool through the registry."""
        registry = ToolRegistry()

        definition = ToolDefinition(
            name="adder",
            description="Add numbers",
            parameters=[
                ToolParameter(name="a", description="First number", type=ToolParameterType.INTEGER),
                ToolParameter(
                    name="b", description="Second number", type=ToolParameterType.INTEGER
                ),
            ],
        )

        async def executor(tool_call_id: str, a: int, b: int) -> ToolResult:
            return ToolResult(
                tool_call_id=tool_call_id,
                name="adder",
                success=True,
                output=json.dumps({"result": a + b}),
            )

        registry.register(definition, executor)

        tool_call = ToolCall(
            id="call_123",
            name="adder",
            arguments={"a": 5, "b": 3},
        )

        result = await registry.execute(tool_call)

        assert result.success
        assert result.tool_call_id == "call_123"
        assert json.loads(result.output)["result"] == 8

    @pytest.mark.asyncio
    async def test_execute_unknown_tool(self):
        """Test executing an unknown tool returns error."""
        registry = ToolRegistry()

        tool_call = ToolCall(
            id="call_456",
            name="nonexistent",
            arguments={},
        )

        result = await registry.execute(tool_call)

        assert not result.success
        assert "Unknown tool" in result.error

    def test_to_bedrock_format(self):
        """Test getting all definitions in Bedrock format."""
        registry = ToolRegistry()

        for i in range(2):
            definition = ToolDefinition(
                name=f"tool_{i}",
                description=f"Tool {i}",
                parameters=[
                    ToolParameter(name="target", description="Target"),
                ],
            )
            registry.register(definition, AsyncMock())

        bedrock_tools = registry.to_bedrock_format()

        assert len(bedrock_tools) == 2
        assert all("toolSpec" in t for t in bedrock_tools)


class TestBedrockParsing:
    """Tests for Bedrock response parsing."""

    def test_parse_tool_calls_from_bedrock(self):
        """Test parsing tool calls from Bedrock response."""
        response = {
            "output": {
                "message": {
                    "content": [
                        {"text": "Let me scan this code."},
                        {
                            "toolUse": {
                                "toolUseId": "tool_001",
                                "name": "opengrep_scan",
                                "input": {"target": "/path/to/code"},
                            }
                        },
                        {
                            "toolUse": {
                                "toolUseId": "tool_002",
                                "name": "gitleaks_scan",
                                "input": {"target": "/path/to/code"},
                            }
                        },
                    ]
                }
            },
            "stopReason": "tool_use",
        }

        tool_calls = parse_tool_calls_from_bedrock(response)

        assert len(tool_calls) == 2
        assert tool_calls[0].id == "tool_001"
        assert tool_calls[0].name == "opengrep_scan"
        assert tool_calls[0].arguments["target"] == "/path/to/code"
        assert tool_calls[1].id == "tool_002"
        assert tool_calls[1].name == "gitleaks_scan"

    def test_parse_no_tool_calls(self):
        """Test parsing response with no tool calls."""
        response = {
            "output": {
                "message": {
                    "content": [
                        {"text": "I found 3 vulnerabilities."},
                    ]
                }
            },
            "stopReason": "end_turn",
        }

        tool_calls = parse_tool_calls_from_bedrock(response)

        assert len(tool_calls) == 0

    def test_format_tool_results_for_bedrock(self):
        """Test formatting tool results for Bedrock."""
        results = [
            ToolResult(
                tool_call_id="tool_001",
                name="opengrep_scan",
                success=True,
                output='{"findings": []}',
            ),
            ToolResult(
                tool_call_id="tool_002",
                name="gitleaks_scan",
                success=False,
                output="",
                error="Tool not available",
            ),
        ]

        formatted = format_tool_results_for_bedrock(results)

        assert len(formatted) == 2

        # Check success result
        assert formatted[0]["toolResult"]["toolUseId"] == "tool_001"
        assert formatted[0]["toolResult"]["status"] == "success"
        assert formatted[0]["toolResult"]["content"][0]["text"] == '{"findings": []}'

        # Check error result
        assert formatted[1]["toolResult"]["toolUseId"] == "tool_002"
        assert formatted[1]["toolResult"]["status"] == "error"
        assert formatted[1]["toolResult"]["content"][0]["text"] == "Tool not available"


class TestSecurityToolRegistry:
    """Tests for the security tool registry."""

    def test_create_registry(self):
        """Test creating the security tool registry."""
        registry = create_security_tool_registry()

        tools = registry.list_tools()

        # Check that expected tools are registered
        assert "opengrep_scan" in tools
        assert "gitleaks_scan" in tools
        assert "trivy_scan" in tools
        assert "binwalk_analyze" in tools
        assert "strings_extract" in tools
        assert "ropgadget_find" in tools
        assert "read_file" in tools
        assert "list_files" in tools
        assert "search_code" in tools

    def test_tool_definitions_are_valid(self):
        """Test that all tool definitions can be converted to Bedrock format."""
        registry = create_security_tool_registry()

        bedrock_tools = registry.to_bedrock_format()

        # All should be valid Bedrock format
        for tool in bedrock_tools:
            assert "toolSpec" in tool
            assert "name" in tool["toolSpec"]
            assert "description" in tool["toolSpec"]
            assert "inputSchema" in tool["toolSpec"]

    @pytest.mark.asyncio
    async def test_get_available_tools(self):
        """Test getting available tools."""
        available = await get_available_tools()

        # Built-in tools should always be available
        assert "read_file" in available
        assert "list_files" in available
        assert "search_code" in available

        # Other tools depend on system installation
        assert isinstance(available, list)

    @pytest.mark.asyncio
    async def test_read_file_tool(self, tmp_path):
        """Test the read_file tool."""
        # Create a test file
        test_file = tmp_path / "test.py"
        test_file.write_text("def hello():\n    print('world')\n")

        registry = create_security_tool_registry()

        tool_call = ToolCall(
            id="call_001",
            name="read_file",
            arguments={"file_path": str(test_file)},
        )

        result = await registry.execute(tool_call)

        assert result.success
        output = json.loads(result.output)
        assert "def hello():" in output["content"]
        assert output["total_lines"] == 3

    @pytest.mark.asyncio
    async def test_read_file_not_found(self):
        """Test read_file with non-existent file."""
        registry = create_security_tool_registry()

        tool_call = ToolCall(
            id="call_002",
            name="read_file",
            arguments={"file_path": "/nonexistent/file.py"},
        )

        result = await registry.execute(tool_call)

        assert not result.success
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_list_files_tool(self, tmp_path):
        """Test the list_files tool."""
        # Create test files
        (tmp_path / "file1.py").write_text("# test")
        (tmp_path / "file2.py").write_text("# test")
        (tmp_path / "subdir").mkdir()
        (tmp_path / "subdir" / "file3.py").write_text("# test")

        registry = create_security_tool_registry()

        tool_call = ToolCall(
            id="call_003",
            name="list_files",
            arguments={
                "directory": str(tmp_path),
                "pattern": "*.py",
                "recursive": True,
            },
        )

        result = await registry.execute(tool_call)

        assert result.success
        output = json.loads(result.output)
        assert output["file_count"] == 3
        assert "file1.py" in output["files"]
        assert "file2.py" in output["files"]

    @pytest.mark.asyncio
    async def test_search_code_tool(self, tmp_path):
        """Test the search_code tool."""
        # Create test files with patterns
        (tmp_path / "vuln.py").write_text(
            "query = f'SELECT * FROM users WHERE id = {user_id}'\ncursor.execute(query)\n"
        )
        (tmp_path / "safe.py").write_text(
            "query = 'SELECT * FROM users WHERE id = ?'\ncursor.execute(query, (user_id,))\n"
        )

        registry = create_security_tool_registry()

        tool_call = ToolCall(
            id="call_004",
            name="search_code",
            arguments={
                "directory": str(tmp_path),
                "pattern": r"f['\"]SELECT.*\{",
                "file_pattern": "*.py",
            },
        )

        result = await registry.execute(tool_call)

        assert result.success
        output = json.loads(result.output)
        assert output["match_count"] == 1
        assert output["matches"][0]["file"] == "vuln.py"


class TestToolCall:
    """Tests for ToolCall dataclass."""

    def test_create_tool_call(self):
        """Test creating a ToolCall."""
        call = ToolCall(
            id="call_123",
            name="scan_code",
            arguments={"target": "/path", "recursive": True},
        )

        assert call.id == "call_123"
        assert call.name == "scan_code"
        assert call.arguments["target"] == "/path"
        assert call.arguments["recursive"] is True


class TestToolResult:
    """Tests for ToolResult dataclass."""

    def test_create_success_result(self):
        """Test creating a successful ToolResult."""
        result = ToolResult(
            tool_call_id="call_123",
            name="scan_code",
            success=True,
            output='{"findings": []}',
        )

        assert result.success
        assert result.error is None

    def test_create_error_result(self):
        """Test creating an error ToolResult."""
        result = ToolResult(
            tool_call_id="call_123",
            name="scan_code",
            success=False,
            output="",
            error="Tool not available",
        )

        assert not result.success
        assert result.error == "Tool not available"
