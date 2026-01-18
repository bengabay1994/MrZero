"""LLM Tool/Function Calling Support.

This module provides the infrastructure for LLM-driven tool calling,
allowing agents to dynamically invoke tools based on LLM decisions.

The key principle: The LLM decides WHICH tools to call and WITH WHAT arguments.
We execute the tools and return results to the LLM for further analysis.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable
from enum import Enum


class ToolParameterType(str, Enum):
    """Supported parameter types for tool definitions."""

    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"


@dataclass
class ToolParameter:
    """Definition of a tool parameter."""

    name: str
    description: str
    type: ToolParameterType = ToolParameterType.STRING
    required: bool = True
    default: Any = None
    enum: list[str] | None = None  # For constrained string values
    items_type: ToolParameterType | None = None  # For array types


@dataclass
class ToolDefinition:
    """Definition of a tool for LLM function calling.

    This follows the common schema used by OpenAI, Anthropic, and AWS Bedrock.
    """

    name: str
    description: str
    parameters: list[ToolParameter] = field(default_factory=list)

    def to_bedrock_format(self) -> dict[str, Any]:
        """Convert to AWS Bedrock tool specification format."""
        properties = {}
        required = []

        for param in self.parameters:
            prop: dict[str, Any] = {
                "type": param.type.value,
                "description": param.description,
            }

            if param.enum:
                prop["enum"] = param.enum

            if param.type == ToolParameterType.ARRAY and param.items_type:
                prop["items"] = {"type": param.items_type.value}

            properties[param.name] = prop

            if param.required:
                required.append(param.name)

        return {
            "toolSpec": {
                "name": self.name,
                "description": self.description,
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": properties,
                        "required": required,
                    }
                },
            }
        }

    def to_openai_format(self) -> dict[str, Any]:
        """Convert to OpenAI function calling format."""
        properties = {}
        required = []

        for param in self.parameters:
            prop: dict[str, Any] = {
                "type": param.type.value,
                "description": param.description,
            }

            if param.enum:
                prop["enum"] = param.enum

            if param.type == ToolParameterType.ARRAY and param.items_type:
                prop["items"] = {"type": param.items_type.value}

            properties[param.name] = prop

            if param.required:
                required.append(param.name)

        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        }


@dataclass
class ToolCall:
    """A tool call requested by the LLM."""

    id: str  # Unique ID for this tool call
    name: str  # Tool name
    arguments: dict[str, Any]  # Arguments to pass to the tool


@dataclass
class ToolResult:
    """Result of executing a tool call."""

    tool_call_id: str
    name: str
    success: bool
    output: str  # JSON string or text output
    error: str | None = None


class ToolRegistry:
    """Registry for tools that can be called by the LLM.

    This maintains a mapping of tool names to their definitions and executors.
    """

    def __init__(self) -> None:
        """Initialize the tool registry."""
        self._definitions: dict[str, ToolDefinition] = {}
        self._executors: dict[str, Callable[..., Awaitable[ToolResult]]] = {}

    def register(
        self,
        definition: ToolDefinition,
        executor: Callable[..., Awaitable[ToolResult]],
    ) -> None:
        """Register a tool with the registry.

        Args:
            definition: The tool definition for LLM.
            executor: Async function to execute the tool.
        """
        self._definitions[definition.name] = definition
        self._executors[definition.name] = executor

    def get_definition(self, name: str) -> ToolDefinition | None:
        """Get a tool definition by name."""
        return self._definitions.get(name)

    def get_executor(self, name: str) -> Callable[..., Awaitable[ToolResult]] | None:
        """Get a tool executor by name."""
        return self._executors.get(name)

    def list_tools(self) -> list[str]:
        """List all registered tool names."""
        return list(self._definitions.keys())

    def get_all_definitions(self) -> list[ToolDefinition]:
        """Get all tool definitions."""
        return list(self._definitions.values())

    def to_bedrock_format(self) -> list[dict[str, Any]]:
        """Get all tool definitions in Bedrock format."""
        return [d.to_bedrock_format() for d in self._definitions.values()]

    def to_openai_format(self) -> list[dict[str, Any]]:
        """Get all tool definitions in OpenAI format."""
        return [d.to_openai_format() for d in self._definitions.values()]

    async def execute(self, tool_call: ToolCall) -> ToolResult:
        """Execute a tool call.

        Args:
            tool_call: The tool call to execute.

        Returns:
            ToolResult with the execution result.
        """
        executor = self._executors.get(tool_call.name)

        if executor is None:
            return ToolResult(
                tool_call_id=tool_call.id,
                name=tool_call.name,
                success=False,
                output="",
                error=f"Unknown tool: {tool_call.name}",
            )

        try:
            return await executor(tool_call.id, **tool_call.arguments)
        except Exception as e:
            return ToolResult(
                tool_call_id=tool_call.id,
                name=tool_call.name,
                success=False,
                output="",
                error=f"Tool execution failed: {str(e)}",
            )


def parse_tool_calls_from_bedrock(response: dict[str, Any]) -> list[ToolCall]:
    """Parse tool calls from a Bedrock Converse API response.

    Args:
        response: The response from Bedrock Converse API.

    Returns:
        List of ToolCall objects.
    """
    tool_calls = []

    output = response.get("output", {})
    message = output.get("message", {})
    content_blocks = message.get("content", [])

    for block in content_blocks:
        if "toolUse" in block:
            tool_use = block["toolUse"]
            tool_calls.append(
                ToolCall(
                    id=tool_use.get("toolUseId", ""),
                    name=tool_use.get("name", ""),
                    arguments=tool_use.get("input", {}),
                )
            )

    return tool_calls


def format_tool_results_for_bedrock(results: list[ToolResult]) -> list[dict[str, Any]]:
    """Format tool results for sending back to Bedrock.

    Args:
        results: List of tool execution results.

    Returns:
        Formatted content blocks for Bedrock.
    """
    content_blocks = []

    for result in results:
        content_blocks.append(
            {
                "toolResult": {
                    "toolUseId": result.tool_call_id,
                    "content": [
                        {"text": result.output if result.success else result.error or "Error"}
                    ],
                    "status": "success" if result.success else "error",
                }
            }
        )

    return content_blocks
