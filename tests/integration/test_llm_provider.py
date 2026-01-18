"""Integration tests for LLM providers.

These tests verify that the LLM providers (AWS Bedrock, Google Gemini) are
properly configured and can successfully communicate with their respective APIs.
"""

import asyncio
import os
import pytest
from typing import Any

from mrzero.core.llm.providers import (
    AWSBedrockProvider,
    GoogleGeminiProvider,
    LLMMessage,
    LLMResponse,
    get_llm_provider,
)


class TestAWSBedrockProvider:
    """Integration tests for AWS Bedrock provider."""

    @pytest.fixture
    def provider(self) -> AWSBedrockProvider:
        """Create a Bedrock provider instance."""
        return AWSBedrockProvider()

    def test_provider_creation(self, provider: AWSBedrockProvider) -> None:
        """Test that provider can be created."""
        assert provider is not None
        assert provider.name == "aws_bedrock"

    def test_is_configured(self, provider: AWSBedrockProvider) -> None:
        """Test that AWS credentials are configured."""
        is_configured = provider.is_configured()
        if not is_configured:
            pytest.skip("AWS credentials not configured - skipping integration test")
        assert is_configured is True

    @pytest.mark.asyncio
    async def test_simple_chat(self, provider: AWSBedrockProvider) -> None:
        """Test a simple chat completion."""
        if not provider.is_configured():
            pytest.skip("AWS credentials not configured")

        messages = [
            LLMMessage(role="user", content="Say 'Hello MrZero' and nothing else."),
        ]

        response = await provider.chat(
            messages=messages,
            temperature=0.0,
            max_tokens=50,
        )

        assert response is not None
        assert isinstance(response, LLMResponse)
        assert response.content is not None
        assert len(response.content) > 0
        assert "hello" in response.content.lower() or "mrzero" in response.content.lower()
        print(f"\nBedrock response: {response.content}")

    @pytest.mark.asyncio
    async def test_chat_with_system_prompt(self, provider: AWSBedrockProvider) -> None:
        """Test chat with a system prompt."""
        if not provider.is_configured():
            pytest.skip("AWS credentials not configured")

        messages = [
            LLMMessage(
                role="system",
                content="You are a security researcher. Always respond with JSON.",
            ),
            LLMMessage(
                role="user",
                content="What is SQL injection? Respond with a JSON object containing 'name' and 'description' fields.",
            ),
        ]

        response = await provider.chat(
            messages=messages,
            temperature=0.0,
            max_tokens=200,
        )

        assert response is not None
        assert response.content is not None
        # Check that response contains JSON-like content
        assert "{" in response.content and "}" in response.content
        print(f"\nBedrock JSON response: {response.content}")

    @pytest.mark.asyncio
    async def test_usage_tracking(self, provider: AWSBedrockProvider) -> None:
        """Test that token usage is tracked."""
        if not provider.is_configured():
            pytest.skip("AWS credentials not configured")

        messages = [
            LLMMessage(role="user", content="Count to 5."),
        ]

        response = await provider.chat(
            messages=messages,
            temperature=0.0,
            max_tokens=100,
        )

        assert response.usage is not None
        assert "input_tokens" in response.usage
        assert "output_tokens" in response.usage
        assert response.usage["input_tokens"] > 0
        assert response.usage["output_tokens"] > 0
        print(f"\nToken usage: {response.usage}")


class TestGoogleGeminiProvider:
    """Integration tests for Google Gemini provider."""

    @pytest.fixture
    def provider(self) -> GoogleGeminiProvider:
        """Create a Gemini provider instance."""
        return GoogleGeminiProvider()

    def test_provider_creation(self, provider: GoogleGeminiProvider) -> None:
        """Test that provider can be created."""
        assert provider is not None
        assert provider.name == "google_gemini"

    def test_is_configured(self, provider: GoogleGeminiProvider) -> None:
        """Test configuration status."""
        # Just check that the method works - may or may not be configured
        is_configured = provider.is_configured()
        print(f"\nGemini configured: {is_configured}")

    @pytest.mark.asyncio
    async def test_simple_chat(self, provider: GoogleGeminiProvider) -> None:
        """Test a simple chat completion with Gemini."""
        if not provider.is_configured():
            pytest.skip("Google Gemini not configured - run 'mrzero auth login'")

        messages = [
            LLMMessage(role="user", content="Say 'Hello MrZero' and nothing else."),
        ]

        response = await provider.chat(
            messages=messages,
            temperature=0.0,
            max_tokens=50,
        )

        assert response is not None
        assert isinstance(response, LLMResponse)
        assert response.content is not None
        assert len(response.content) > 0
        print(f"\nGemini response: {response.content}")


class TestGetLLMProvider:
    """Test the get_llm_provider factory function."""

    def test_get_bedrock_provider(self) -> None:
        """Test getting Bedrock provider."""
        provider = get_llm_provider("aws_bedrock")
        assert provider is not None
        assert isinstance(provider, AWSBedrockProvider)

    def test_get_gemini_provider(self) -> None:
        """Test getting Gemini provider."""
        provider = get_llm_provider("google_gemini")
        assert provider is not None
        assert isinstance(provider, GoogleGeminiProvider)

    def test_get_unknown_provider(self) -> None:
        """Test that unknown provider raises error."""
        with pytest.raises(ValueError):
            get_llm_provider("unknown_provider")

    def test_provider_with_kwargs(self) -> None:
        """Test provider creation with custom kwargs."""
        provider = get_llm_provider("aws_bedrock", region="us-west-2")
        assert provider.region == "us-west-2"


# Standalone test runner
if __name__ == "__main__":
    """Run a quick LLM connectivity test."""
    print("=" * 60)
    print("MrZero LLM Provider Connectivity Test")
    print("=" * 60)

    async def test_connectivity() -> None:
        # Test AWS Bedrock
        print("\n[1] Testing AWS Bedrock...")
        bedrock = AWSBedrockProvider()

        if bedrock.is_configured():
            print("    AWS credentials: CONFIGURED")
            try:
                response = await bedrock.chat(
                    messages=[LLMMessage(role="user", content="Say 'Bedrock OK'")],
                    temperature=0.0,
                    max_tokens=20,
                )
                print(f"    Response: {response.content}")
                print("    Status: SUCCESS")
            except Exception as e:
                print(f"    Error: {e}")
                print("    Status: FAILED")
        else:
            print("    AWS credentials: NOT CONFIGURED")
            print("    Run 'aws configure' to set up credentials")

        # Test Google Gemini
        print("\n[2] Testing Google Gemini...")
        gemini = GoogleGeminiProvider()

        if gemini.is_configured():
            print("    Google OAuth: CONFIGURED")
            try:
                response = await gemini.chat(
                    messages=[LLMMessage(role="user", content="Say 'Gemini OK'")],
                    temperature=0.0,
                    max_tokens=20,
                )
                print(f"    Response: {response.content}")
                print("    Status: SUCCESS")
            except Exception as e:
                print(f"    Error: {e}")
                print("    Status: FAILED")
        else:
            print("    Google OAuth: NOT CONFIGURED")
            print("    Run 'mrzero auth login' to authenticate")

        print("\n" + "=" * 60)

    asyncio.run(test_connectivity())
