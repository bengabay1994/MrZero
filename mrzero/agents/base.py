"""Base agent class for all MrZero agents."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from mrzero.core.memory.state import AgentState
from mrzero.core.llm.providers import (
    BaseLLMProvider,
    LLMMessage,
    LLMResponse,
    get_llm_provider,
)
from mrzero.core.config import get_config


class AgentType(str, Enum):
    """Types of agents in the MrZero system."""

    MAPPER = "mapper"
    HUNTER = "hunter"
    VERIFIER = "verifier"
    ENV_BUILDER = "env_builder"
    EXPLOIT_BUILDER = "exploit_builder"
    REPORTER = "reporter"


class AgentResult(BaseModel):
    """Result returned by an agent after execution."""

    agent_type: AgentType
    success: bool
    output: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    next_agent: AgentType | None = None
    requires_human_input: bool = False
    human_prompt: str | None = None


class BaseAgent(ABC):
    """Abstract base class for all MrZero agents."""

    agent_type: AgentType

    def __init__(
        self,
        llm: BaseLLMProvider | None = None,
        tools: list[Any] | None = None,
    ) -> None:
        """Initialize the agent.

        Args:
            llm: The language model provider to use for reasoning.
            tools: List of tools available to this agent.
        """
        self._llm = llm
        self.tools = tools or []
        self._config = get_config()

    @property
    def llm(self) -> BaseLLMProvider:
        """Get the LLM provider, initializing from config if needed."""
        if self._llm is None:
            llm_config = self._config.llm
            provider_kwargs = {}

            if llm_config.provider == "aws_bedrock":
                provider_kwargs = {
                    "region": llm_config.aws_region,
                    "profile": llm_config.aws_profile,
                }
            elif llm_config.provider == "google_gemini":
                provider_kwargs = {
                    "project_id": llm_config.google_project_id,
                }

            self._llm = get_llm_provider(llm_config.provider, **provider_kwargs)

        return self._llm

    async def chat(
        self,
        user_message: str,
        context: str | None = None,
        temperature: float | None = None,
    ) -> str:
        """Send a chat message to the LLM.

        Args:
            user_message: The user's message/query.
            context: Additional context to include.
            temperature: Override temperature for this call.

        Returns:
            The LLM's response content.
        """
        messages = [
            LLMMessage(role="system", content=self.get_system_prompt()),
        ]

        if context:
            messages.append(LLMMessage(role="user", content=f"Context:\n{context}"))

        messages.append(LLMMessage(role="user", content=user_message))

        llm_config = self._config.llm
        response = await self.llm.chat(
            messages=messages,
            model=llm_config.model,
            temperature=temperature or llm_config.temperature,
            max_tokens=llm_config.max_tokens,
        )

        return response.content

    async def analyze(
        self,
        code: str,
        query: str,
        file_path: str | None = None,
    ) -> str:
        """Analyze code using the LLM.

        Args:
            code: The code to analyze.
            query: What to analyze for.
            file_path: Optional file path for context.

        Returns:
            Analysis result.
        """
        context = f"File: {file_path}\n\n```\n{code}\n```" if file_path else f"```\n{code}\n```"
        return await self.chat(query, context=context)

    @abstractmethod
    async def execute(self, state: AgentState) -> AgentResult:
        """Execute the agent's main task.

        Args:
            state: Current state of the workflow.

        Returns:
            AgentResult with the outcome of execution.
        """
        pass

    @abstractmethod
    def get_system_prompt(self) -> str:
        """Get the system prompt for this agent.

        Returns:
            System prompt string.
        """
        pass

    def get_available_tools(self) -> list[str]:
        """Get list of tool names available to this agent.

        Returns:
            List of tool names.
        """
        return [tool.name if hasattr(tool, "name") else str(tool) for tool in self.tools]

    def get_tool_schemas(self) -> list[dict[str, Any]]:
        """Get JSON schemas for all available tools.

        Returns:
            List of tool schemas for LLM function calling.
        """
        schemas = []
        for tool in self.tools:
            if hasattr(tool, "get_schema"):
                schemas.append(tool.get_schema())
        return schemas
