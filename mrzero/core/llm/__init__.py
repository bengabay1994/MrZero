"""LLM module for MrZero."""

from mrzero.core.llm.providers import (
    AWSBedrockProvider,
    BaseLLMProvider,
    GoogleGeminiProvider,
    LLMMessage,
    LLMResponse,
    get_llm_provider,
)
from mrzero.core.llm.tool_calling import (
    ToolCall,
    ToolDefinition,
    ToolParameter,
    ToolParameterType,
    ToolRegistry,
    ToolResult,
    format_tool_results_for_bedrock,
    parse_tool_calls_from_bedrock,
)
from mrzero.core.llm.security_tools import (
    create_security_tool_registry,
    get_available_tools,
)

__all__ = [
    # Providers
    "AWSBedrockProvider",
    "BaseLLMProvider",
    "GoogleGeminiProvider",
    "LLMMessage",
    "LLMResponse",
    "get_llm_provider",
    # Tool Calling
    "ToolCall",
    "ToolDefinition",
    "ToolParameter",
    "ToolParameterType",
    "ToolRegistry",
    "ToolResult",
    "format_tool_results_for_bedrock",
    "parse_tool_calls_from_bedrock",
    # Security Tools
    "create_security_tool_registry",
    "get_available_tools",
]


# Import agentic loop separately to avoid circular imports
def get_tool_calling_loop():
    """Get the ToolCallingLoop class."""
    from mrzero.core.llm.agentic_loop import ToolCallingLoop

    return ToolCallingLoop


def get_tool_calling_hunter():
    """Get the run_tool_calling_hunter function."""
    from mrzero.core.llm.agentic_loop import run_tool_calling_hunter

    return run_tool_calling_hunter


def get_tool_calling_verifier():
    """Get the run_tool_calling_verifier function."""
    from mrzero.core.llm.agentic_loop import run_tool_calling_verifier

    return run_tool_calling_verifier
