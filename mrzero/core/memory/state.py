"""Agent state management for LangGraph."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mrzero.core.schemas import (
    AttackSurfaceMap,
    EnvironmentInfo,
    ExecutionMode,
    Exploit,
    Vulnerability,
)


def add_messages(left: list[Any], right: list[Any]) -> list[Any]:
    """Merge message lists for LangGraph state.

    Args:
        left: Existing messages.
        right: New messages to add.

    Returns:
        Combined message list.
    """
    return left + right


class HunterVerifierState(BaseModel):
    """State for the Hunter-Verifier feedback loop."""

    iteration_count: int = 0
    max_iterations: int = 3
    min_true_positives: int = 3
    candidates: list[Vulnerability] = Field(default_factory=list)
    confirmed: list[Vulnerability] = Field(default_factory=list)
    false_positives: list[Vulnerability] = Field(default_factory=list)
    feedback: list[str] = Field(default_factory=list)


class AgentState(BaseModel):
    """Global state shared across all agents in the workflow."""

    # Session info
    session_id: str
    target_path: str
    mode: ExecutionMode = ExecutionMode.HITL

    # Messages for LLM context
    messages: list[Any] = Field(default_factory=list)

    # Current workflow position
    current_agent: str = "mapper"
    workflow_status: str = "pending"  # pending, running, paused, completed, failed

    # Agent outputs
    attack_surface: AttackSurfaceMap | None = None
    hunter_verifier_state: HunterVerifierState = Field(default_factory=HunterVerifierState)
    confirmed_vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    environment: EnvironmentInfo | None = None
    exploits: list[Exploit] = Field(default_factory=list)

    # Human-in-the-loop
    awaiting_human_input: bool = False
    human_prompt: str | None = None
    human_response: str | None = None

    # Error tracking
    errors: list[str] = Field(default_factory=list)

    # Tool execution cache references
    tool_cache_hits: int = 0
    tool_cache_misses: int = 0

    model_config = ConfigDict(arbitrary_types_allowed=True)
