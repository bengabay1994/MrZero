"""LLM Provider management for MrZero."""

import os
from abc import ABC, abstractmethod
from typing import Any, AsyncIterator

from pydantic import BaseModel, Field


class LLMMessage(BaseModel):
    """A message in a conversation."""

    role: str  # "system", "user", "assistant", "tool"
    content: str
    tool_call_id: str | None = None  # For tool result messages
    tool_calls: list[dict[str, Any]] | None = None  # For assistant messages with tool calls


class LLMResponse(BaseModel):
    """Response from an LLM."""

    content: str
    model: str
    usage: dict[str, int] = Field(default_factory=dict)
    finish_reason: str | None = None
    tool_calls: list[dict[str, Any]] | None = None  # Tool calls requested by the LLM
    raw_response: dict[str, Any] | None = None  # Raw response for tool call parsing


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""

    name: str

    @abstractmethod
    async def chat(
        self,
        messages: list[LLMMessage],
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> LLMResponse:
        """Send a chat completion request.

        Args:
            messages: List of messages in the conversation.
            model: Model to use.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            **kwargs: Provider-specific arguments.

        Returns:
            LLMResponse with the completion.
        """
        pass

    @abstractmethod
    async def chat_stream(
        self,
        messages: list[LLMMessage],
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Send a streaming chat completion request.

        Args:
            messages: List of messages in the conversation.
            model: Model to use.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            **kwargs: Provider-specific arguments.

        Yields:
            Content chunks as they arrive.
        """
        pass

    async def chat_with_tools(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]],
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> LLMResponse:
        """Send a chat completion request with tool definitions.

        Args:
            messages: List of messages in the conversation.
            tools: List of tool definitions in provider-specific format.
            model: Model to use.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            **kwargs: Provider-specific arguments.

        Returns:
            LLMResponse with the completion (may include tool_calls).
        """
        # Default implementation: fall back to regular chat
        return await self.chat(messages, model, temperature, max_tokens, **kwargs)

    @abstractmethod
    def is_configured(self) -> bool:
        """Check if the provider is properly configured.

        Returns:
            True if configured and ready to use.
        """
        pass


class AWSBedrockProvider(BaseLLMProvider):
    """AWS Bedrock LLM provider."""

    name = "aws_bedrock"

    # Supported models on Bedrock (using inference profile IDs for on-demand access)
    SUPPORTED_MODELS = {
        # Claude models (use us. prefix for inference profiles)
        "us.anthropic.claude-3-5-sonnet-20241022-v2:0": "Claude 3.5 Sonnet v2",
        "us.anthropic.claude-3-5-haiku-20241022-v1:0": "Claude 3.5 Haiku",
        "us.anthropic.claude-3-haiku-20240307-v1:0": "Claude 3 Haiku",
        "us.anthropic.claude-3-sonnet-20240229-v1:0": "Claude 3 Sonnet",
        "us.anthropic.claude-3-opus-20240229-v1:0": "Claude 3 Opus",
        # Claude 4 models
        "us.anthropic.claude-sonnet-4-20250514-v1:0": "Claude Sonnet 4",
        "us.anthropic.claude-haiku-4-5-20251001-v1:0": "Claude Haiku 4.5",
        # Amazon Nova
        "amazon.nova-pro-v1:0": "Amazon Nova Pro",
        "amazon.nova-lite-v1:0": "Amazon Nova Lite",
        # Llama models
        "meta.llama3-1-405b-instruct-v1:0": "Llama 3.1 405B",
        "meta.llama3-1-70b-instruct-v1:0": "Llama 3.1 70B",
    }

    # Use inference profile for default model (required for on-demand)
    DEFAULT_MODEL = "us.anthropic.claude-3-5-sonnet-20241022-v2:0"

    def __init__(
        self,
        region: str | None = None,
        profile: str | None = None,
    ) -> None:
        """Initialize AWS Bedrock provider.

        Args:
            region: AWS region (defaults to AWS_REGION or us-east-1).
            profile: AWS profile name (optional).
        """
        self.region = region or os.environ.get("AWS_REGION", "us-east-1")
        self.profile = profile or os.environ.get("AWS_PROFILE")
        self._client = None

    def _get_client(self) -> Any:
        """Get or create the Bedrock runtime client."""
        if self._client is None:
            try:
                import boto3

                session_kwargs = {}
                if self.profile:
                    session_kwargs["profile_name"] = self.profile

                session = boto3.Session(**session_kwargs)
                self._client = session.client(
                    "bedrock-runtime",
                    region_name=self.region,
                )
            except ImportError:
                raise ImportError(
                    "boto3 is required for AWS Bedrock. Install with: pip install boto3"
                )

        return self._client

    def is_configured(self) -> bool:
        """Check if AWS credentials are configured."""
        try:
            import boto3

            session = boto3.Session(profile_name=self.profile) if self.profile else boto3.Session()
            credentials = session.get_credentials()
            return credentials is not None
        except Exception:
            return False

    async def chat(
        self,
        messages: list[LLMMessage],
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> LLMResponse:
        """Send a chat completion request to Bedrock."""
        import json

        client = self._get_client()
        model_id = model or self.DEFAULT_MODEL

        # Format messages for Bedrock Converse API
        bedrock_messages = []
        system_prompt = None

        for msg in messages:
            if msg.role == "system":
                system_prompt = msg.content
            else:
                bedrock_messages.append(
                    {
                        "role": msg.role,
                        "content": [{"text": msg.content}],
                    }
                )

        # Build request
        request = {
            "modelId": model_id,
            "messages": bedrock_messages,
            "inferenceConfig": {
                "temperature": temperature,
                "maxTokens": max_tokens,
            },
        }

        if system_prompt:
            request["system"] = [{"text": system_prompt}]

        # Call Bedrock
        response = client.converse(**request)

        # Parse response
        output = response.get("output", {})
        message = output.get("message", {})
        content_blocks = message.get("content", [])
        content = "".join(block.get("text", "") for block in content_blocks)

        usage = response.get("usage", {})

        return LLMResponse(
            content=content,
            model=model_id,
            usage={
                "input_tokens": usage.get("inputTokens", 0),
                "output_tokens": usage.get("outputTokens", 0),
            },
            finish_reason=response.get("stopReason"),
        )

    async def chat_stream(
        self,
        messages: list[LLMMessage],
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Send a streaming chat completion request to Bedrock."""
        client = self._get_client()
        model_id = model or self.DEFAULT_MODEL

        # Format messages
        bedrock_messages = []
        system_prompt = None

        for msg in messages:
            if msg.role == "system":
                system_prompt = msg.content
            else:
                bedrock_messages.append(
                    {
                        "role": msg.role,
                        "content": [{"text": msg.content}],
                    }
                )

        # Build request
        request = {
            "modelId": model_id,
            "messages": bedrock_messages,
            "inferenceConfig": {
                "temperature": temperature,
                "maxTokens": max_tokens,
            },
        }

        if system_prompt:
            request["system"] = [{"text": system_prompt}]

        # Call Bedrock with streaming
        response = client.converse_stream(**request)

        for event in response.get("stream", []):
            if "contentBlockDelta" in event:
                delta = event["contentBlockDelta"].get("delta", {})
                text = delta.get("text", "")
                if text:
                    yield text

    async def chat_with_tools(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]],
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> LLMResponse:
        """Send a chat completion request with tool definitions to Bedrock.

        Uses the Bedrock Converse API with toolConfig.

        Args:
            messages: List of messages in the conversation.
            tools: List of tool definitions in Bedrock format.
            model: Model to use.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            **kwargs: Provider-specific arguments.

        Returns:
            LLMResponse with the completion (may include tool_calls).
        """
        client = self._get_client()
        model_id = model or self.DEFAULT_MODEL

        # Format messages for Bedrock Converse API
        bedrock_messages = []
        system_prompt = None

        for msg in messages:
            if msg.role == "system":
                system_prompt = msg.content
            elif msg.role == "tool":
                # Tool result message
                bedrock_messages.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "toolResult": {
                                    "toolUseId": msg.tool_call_id,
                                    "content": [{"text": msg.content}],
                                    "status": "success",
                                }
                            }
                        ],
                    }
                )
            elif msg.tool_calls:
                # Assistant message with tool calls
                content_blocks = []
                if msg.content:
                    content_blocks.append({"text": msg.content})
                for tc in msg.tool_calls:
                    content_blocks.append(
                        {
                            "toolUse": {
                                "toolUseId": tc.get("id", ""),
                                "name": tc.get("name", ""),
                                "input": tc.get("arguments", {}),
                            }
                        }
                    )
                bedrock_messages.append(
                    {
                        "role": "assistant",
                        "content": content_blocks,
                    }
                )
            else:
                bedrock_messages.append(
                    {
                        "role": msg.role,
                        "content": [{"text": msg.content}],
                    }
                )

        # Build request
        request: dict[str, Any] = {
            "modelId": model_id,
            "messages": bedrock_messages,
            "inferenceConfig": {
                "temperature": temperature,
                "maxTokens": max_tokens,
            },
        }

        if system_prompt:
            request["system"] = [{"text": system_prompt}]

        # Add tool configuration if tools provided
        if tools:
            request["toolConfig"] = {
                "tools": tools,
            }

        # Call Bedrock
        response = client.converse(**request)

        # Parse response
        output = response.get("output", {})
        message = output.get("message", {})
        content_blocks = message.get("content", [])

        # Extract text content
        text_content = ""
        tool_calls = []

        for block in content_blocks:
            if "text" in block:
                text_content += block.get("text", "")
            elif "toolUse" in block:
                tool_use = block["toolUse"]
                tool_calls.append(
                    {
                        "id": tool_use.get("toolUseId", ""),
                        "name": tool_use.get("name", ""),
                        "arguments": tool_use.get("input", {}),
                    }
                )

        usage = response.get("usage", {})
        stop_reason = response.get("stopReason", "")

        return LLMResponse(
            content=text_content,
            model=model_id,
            usage={
                "input_tokens": usage.get("inputTokens", 0),
                "output_tokens": usage.get("outputTokens", 0),
            },
            finish_reason=stop_reason,
            tool_calls=tool_calls if tool_calls else None,
            raw_response=response,
        )


class GoogleGeminiProvider(BaseLLMProvider):
    """Google Gemini LLM provider with OAuth support."""

    name = "google_gemini"

    # Supported Gemini models
    SUPPORTED_MODELS = {
        "gemini-2.0-flash": "Gemini 2.0 Flash",
        "gemini-2.0-flash-thinking": "Gemini 2.0 Flash Thinking",
        "gemini-1.5-pro": "Gemini 1.5 Pro",
        "gemini-1.5-flash": "Gemini 1.5 Flash",
        "gemini-1.5-flash-8b": "Gemini 1.5 Flash 8B",
    }

    DEFAULT_MODEL = "gemini-2.0-flash"

    # OAuth configuration (same as gemini-cli)
    OAUTH_CLIENT_ID = "936733804402-rjlls3bpsnvv89ipkj26geg0r5qbm0l8.apps.googleusercontent.com"
    OAUTH_SCOPES = [
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/userinfo.email",
    ]
    TOKEN_FILE = ".mrzero_google_token.json"

    def __init__(
        self,
        project_id: str | None = None,
        credentials_path: str | None = None,
    ) -> None:
        """Initialize Google Gemini provider.

        Args:
            project_id: Google Cloud project ID.
            credentials_path: Path to service account credentials (optional).
        """
        self.project_id = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT")
        self.credentials_path = credentials_path or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        self._credentials = None
        self._token_path = os.path.expanduser(f"~/.mrzero/{self.TOKEN_FILE}")

    def is_configured(self) -> bool:
        """Check if Google credentials are configured."""
        # Check for OAuth token
        if os.path.exists(self._token_path):
            return True

        # Check for service account credentials
        if self.credentials_path and os.path.exists(self.credentials_path):
            return True

        # Check for application default credentials
        try:
            from google.auth import default

            credentials, project = default()
            return credentials is not None
        except Exception:
            return False

    async def authenticate_oauth(self) -> bool:
        """Perform OAuth authentication flow.

        Returns:
            True if authentication successful.
        """
        import json
        import webbrowser
        from http.server import HTTPServer, BaseHTTPRequestHandler
        from urllib.parse import urlencode, parse_qs, urlparse
        import secrets

        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)

        # OAuth authorization URL
        auth_params = {
            "client_id": self.OAUTH_CLIENT_ID,
            "redirect_uri": "http://localhost:8085/callback",
            "response_type": "code",
            "scope": " ".join(self.OAUTH_SCOPES),
            "state": state,
            "access_type": "offline",
            "prompt": "consent",
        }

        auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(auth_params)}"

        print(f"\nOpening browser for Google authentication...")
        print(f"If browser doesn't open, visit:\n{auth_url}\n")

        auth_code = None
        received_state = None

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                nonlocal auth_code, received_state

                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)

                if "code" in params:
                    auth_code = params["code"][0]
                    received_state = params.get("state", [None])[0]

                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(
                        b"<html><body><h1>Authentication successful!</h1>"
                        b"<p>You can close this window.</p></body></html>"
                    )
                else:
                    self.send_response(400)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body><h1>Authentication failed</h1></body></html>")

            def log_message(self, format: str, *args: Any) -> None:
                pass  # Suppress logging

        # Start local server
        server = HTTPServer(("localhost", 8085), CallbackHandler)
        server.timeout = 120  # 2 minute timeout

        # Open browser
        webbrowser.open(auth_url)

        # Wait for callback
        server.handle_request()
        server.server_close()

        if not auth_code or received_state != state:
            print("Authentication failed: Invalid response")
            return False

        # Exchange code for tokens
        try:
            import httpx

            token_response = httpx.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": self.OAUTH_CLIENT_ID,
                    "code": auth_code,
                    "grant_type": "authorization_code",
                    "redirect_uri": "http://localhost:8085/callback",
                },
            )

            if token_response.status_code != 200:
                print(f"Token exchange failed: {token_response.text}")
                return False

            tokens = token_response.json()

            # Save tokens
            os.makedirs(os.path.dirname(self._token_path), exist_ok=True)
            with open(self._token_path, "w") as f:
                json.dump(tokens, f)

            print("Authentication successful!")
            return True

        except Exception as e:
            print(f"Token exchange error: {e}")
            return False

    def _get_access_token(self) -> str | None:
        """Get a valid access token, refreshing if necessary."""
        import json
        import time

        if not os.path.exists(self._token_path):
            return None

        with open(self._token_path) as f:
            tokens = json.load(f)

        # Check if token needs refresh
        expires_at = tokens.get("expires_at", 0)
        if time.time() > expires_at - 60:  # Refresh 1 minute before expiry
            # Refresh token
            try:
                import httpx

                response = httpx.post(
                    "https://oauth2.googleapis.com/token",
                    data={
                        "client_id": self.OAUTH_CLIENT_ID,
                        "refresh_token": tokens.get("refresh_token"),
                        "grant_type": "refresh_token",
                    },
                )

                if response.status_code == 200:
                    new_tokens = response.json()
                    tokens["access_token"] = new_tokens["access_token"]
                    tokens["expires_at"] = time.time() + new_tokens.get("expires_in", 3600)

                    with open(self._token_path, "w") as f:
                        json.dump(tokens, f)

            except Exception:
                pass

        return tokens.get("access_token")

    async def chat(
        self,
        messages: list[LLMMessage],
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> LLMResponse:
        """Send a chat completion request to Gemini."""
        import httpx

        access_token = self._get_access_token()
        if not access_token:
            raise RuntimeError(
                "Not authenticated. Run 'mrzero auth login' to authenticate with Google."
            )

        model_id = model or self.DEFAULT_MODEL

        # Format messages for Gemini
        contents = []
        system_instruction = None

        for msg in messages:
            if msg.role == "system":
                system_instruction = msg.content
            else:
                role = "user" if msg.role == "user" else "model"
                contents.append(
                    {
                        "role": role,
                        "parts": [{"text": msg.content}],
                    }
                )

        # Build request
        request_body = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }

        if system_instruction:
            request_body["systemInstruction"] = {"parts": [{"text": system_instruction}]}

        # Call Gemini API
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent"

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
                json=request_body,
                timeout=120,
            )

            if response.status_code != 200:
                raise RuntimeError(f"Gemini API error: {response.text}")

            data = response.json()

        # Parse response
        candidates = data.get("candidates", [])
        if not candidates:
            raise RuntimeError("No response from Gemini")

        content_parts = candidates[0].get("content", {}).get("parts", [])
        content = "".join(part.get("text", "") for part in content_parts)

        usage_metadata = data.get("usageMetadata", {})

        return LLMResponse(
            content=content,
            model=model_id,
            usage={
                "input_tokens": usage_metadata.get("promptTokenCount", 0),
                "output_tokens": usage_metadata.get("candidatesTokenCount", 0),
            },
            finish_reason=candidates[0].get("finishReason"),
        )

    async def chat_stream(
        self,
        messages: list[LLMMessage],
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Send a streaming chat completion request to Gemini."""
        import httpx

        access_token = self._get_access_token()
        if not access_token:
            raise RuntimeError(
                "Not authenticated. Run 'mrzero auth login' to authenticate with Google."
            )

        model_id = model or self.DEFAULT_MODEL

        # Format messages
        contents = []
        system_instruction = None

        for msg in messages:
            if msg.role == "system":
                system_instruction = msg.content
            else:
                role = "user" if msg.role == "user" else "model"
                contents.append(
                    {
                        "role": role,
                        "parts": [{"text": msg.content}],
                    }
                )

        # Build request
        request_body = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }

        if system_instruction:
            request_body["systemInstruction"] = {"parts": [{"text": system_instruction}]}

        # Call Gemini API with streaming
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:streamGenerateContent?alt=sse"

        async with httpx.AsyncClient() as client:
            async with client.stream(
                "POST",
                url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
                json=request_body,
                timeout=120,
            ) as response:
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        import json

                        try:
                            data = json.loads(line[6:])
                            candidates = data.get("candidates", [])
                            if candidates:
                                parts = candidates[0].get("content", {}).get("parts", [])
                                for part in parts:
                                    text = part.get("text", "")
                                    if text:
                                        yield text
                        except json.JSONDecodeError:
                            continue


def get_llm_provider(provider_name: str, **kwargs: Any) -> BaseLLMProvider:
    """Get an LLM provider by name.

    Args:
        provider_name: Name of the provider ("aws_bedrock" or "google_gemini").
        **kwargs: Provider-specific configuration.

    Returns:
        Configured LLM provider.

    Raises:
        ValueError: If provider is not supported.
    """
    providers = {
        "aws_bedrock": AWSBedrockProvider,
        "google_gemini": GoogleGeminiProvider,
    }

    if provider_name not in providers:
        raise ValueError(
            f"Unknown provider: {provider_name}. Supported providers: {list(providers.keys())}"
        )

    return providers[provider_name](**kwargs)
