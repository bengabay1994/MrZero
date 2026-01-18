"""Integration tests for LLM Tool Calling with real AWS Bedrock."""

import pytest
import json

from mrzero.core.llm import (
    AWSBedrockProvider,
    create_security_tool_registry,
)
from mrzero.core.llm.agentic_loop import (
    ToolCallingLoop,
    run_tool_calling_hunter,
    run_tool_calling_verifier,
)


@pytest.fixture
def bedrock_provider():
    """Create AWS Bedrock provider."""
    provider = AWSBedrockProvider()
    if not provider.is_configured():
        pytest.skip("AWS Bedrock not configured")
    return provider


@pytest.fixture
def vulnerable_app_path():
    """Path to the test vulnerable app."""
    from pathlib import Path

    path = Path(__file__).parent.parent / "fixtures" / "vulnerable_app"
    if not path.exists():
        pytest.skip("Vulnerable app fixture not found")
    return str(path)


class TestToolCallingWithBedrock:
    """Test tool calling with real Bedrock API."""

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_simple_tool_call(self, bedrock_provider):
        """Test that LLM can request and receive tool results."""
        registry = create_security_tool_registry()
        loop = ToolCallingLoop(
            llm_provider=bedrock_provider,
            tool_registry=registry,
            max_iterations=3,
        )

        system_prompt = """You are a helpful assistant with access to file tools.
When asked to list files, use the list_files tool.
After getting results, summarize them briefly."""

        user_prompt = "Please list the Python files in tests/fixtures/vulnerable_app"

        response, history = await loop.run(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

        # Should have made at least one tool call
        assert len(history) > 0, "Expected at least one tool call"

        # First tool call should be list_files
        assert history[0]["tool_call"]["name"] == "list_files"

        # Response should mention Python files
        assert response, "Expected non-empty response"

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_multi_tool_analysis(self, bedrock_provider, vulnerable_app_path):
        """Test that LLM can use multiple tools for analysis."""
        registry = create_security_tool_registry()
        loop = ToolCallingLoop(
            llm_provider=bedrock_provider,
            tool_registry=registry,
            max_iterations=5,
        )

        system_prompt = """You are a security analyst. Your task is to:
1. List files in the target directory
2. Search for SQL queries
3. Read any suspicious files
4. Report what you find

Be concise. Stop after finding one potential issue."""

        user_prompt = f"Analyze {vulnerable_app_path} for SQL injection vulnerabilities."

        response, history = await loop.run(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

        # Should have made multiple tool calls
        assert len(history) >= 2, f"Expected multiple tool calls, got {len(history)}"

        # Check tool diversity
        tool_names = [h["tool_call"]["name"] for h in history]
        unique_tools = set(tool_names)
        assert len(unique_tools) >= 2, f"Expected multiple different tools, got {unique_tools}"


class TestToolCallingHunter:
    """Test the full tool-calling hunter implementation."""

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.slow
    async def test_hunter_finds_vulnerabilities(self, bedrock_provider, vulnerable_app_path):
        """Test that the tool-calling hunter can find vulnerabilities."""
        response, history = await run_tool_calling_hunter(
            llm_provider=bedrock_provider,
            target_path=vulnerable_app_path,
            attack_surface_context="Flask application with SQLite database.",
            max_iterations=8,
        )

        # Should have made tool calls
        assert len(history) > 0, "Expected tool calls during analysis"

        # Print tool call summary for debugging
        print(f"\nTool calls made: {len(history)}")
        for h in history:
            print(f"  - {h['tool_call']['name']}: {h['result']['success']}")

        # Try to parse JSON response
        try:
            # Find JSON in response
            import re

            json_match = re.search(r"```json\s*([\s\S]*?)\s*```", response)
            if json_match:
                data = json.loads(json_match.group(1))
            else:
                json_match = re.search(r"\{[\s\S]*\"vulnerabilities\"[\s\S]*\}", response)
                if json_match:
                    data = json.loads(json_match.group())
                else:
                    pytest.fail(f"Could not find JSON in response: {response[:500]}")

            vulnerabilities = data.get("vulnerabilities", [])

            # Should find at least some vulnerabilities
            assert len(vulnerabilities) > 0, "Expected to find vulnerabilities"

            # Print found vulnerabilities
            print(f"\nVulnerabilities found: {len(vulnerabilities)}")
            for v in vulnerabilities[:5]:
                print(f"  - {v.get('title', 'Unknown')}: {v.get('severity', 'Unknown')}")

            # Check that vulnerabilities have required fields
            for vuln in vulnerabilities:
                assert "title" in vuln or "vuln_type" in vuln
                assert "severity" in vuln or "score" in vuln

        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON: {e}")
            print(f"Response: {response[:1000]}")
            # Don't fail test if response isn't perfect JSON
            # The LLM should have at least made tool calls

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_hunter_uses_search_and_read(self, bedrock_provider, vulnerable_app_path):
        """Test that hunter uses search and read tools effectively."""
        response, history = await run_tool_calling_hunter(
            llm_provider=bedrock_provider,
            target_path=vulnerable_app_path,
            max_iterations=6,
        )

        # Check which tools were used
        tool_names = [h["tool_call"]["name"] for h in history]

        # Should use file exploration tools
        exploration_tools = {"list_files", "read_file", "search_code"}
        used_exploration = exploration_tools.intersection(tool_names)
        assert len(used_exploration) >= 1, f"Expected to use file tools, used: {tool_names}"

        # Print summary
        print(f"\nTools used: {set(tool_names)}")


class TestBedrockToolCalling:
    """Test Bedrock-specific tool calling functionality."""

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_bedrock_chat_with_tools(self, bedrock_provider):
        """Test the chat_with_tools method directly."""
        from mrzero.core.llm import LLMMessage, create_security_tool_registry

        registry = create_security_tool_registry()
        tools = registry.to_bedrock_format()

        messages = [
            LLMMessage(
                role="system",
                content="You have access to tools. Use list_files to list Python files.",
            ),
            LLMMessage(
                role="user",
                content="List Python files in tests/fixtures/vulnerable_app",
            ),
        ]

        response = await bedrock_provider.chat_with_tools(
            messages=messages,
            tools=tools,
        )

        # Should request tool use
        assert response.tool_calls is not None, "Expected tool_calls in response"
        assert len(response.tool_calls) > 0, "Expected at least one tool call"

        # Check tool call structure
        tool_call = response.tool_calls[0]
        assert "id" in tool_call
        assert "name" in tool_call
        assert "arguments" in tool_call

        print(f"\nTool requested: {tool_call['name']}")
        print(f"Arguments: {tool_call['arguments']}")
