"""LangGraph workflow definition for MrZero."""

import json
import uuid
from typing import Any, Literal

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from mrzero.core.config import get_config
from mrzero.core.memory.state import AgentState, HunterVerifierState
from mrzero.core.memory.sqlite import SessionManager
from mrzero.core.memory.checkpoint import CheckpointManager
from mrzero.core.schemas import ExecutionMode

console = Console()

# Type for routing decisions
RouteDecision = Literal[
    "mapper",
    "hunter",
    "verifier",
    "env_builder",
    "exploit_builder",
    "reporter",
    "human_input",
    "end",
]


class MrZeroWorkflow:
    """LangGraph-based workflow orchestrator for MrZero."""

    def __init__(self, checkpoint_interval: int = 1) -> None:
        """Initialize the workflow orchestrator.

        Args:
            checkpoint_interval: Save checkpoint every N agent completions.
                                 Set to 0 to disable checkpointing.
        """
        self.config = get_config()
        self.session_manager = SessionManager(self.config.db_path)
        self.checkpoint_manager = CheckpointManager(self.config.db_path)
        self.checkpoint_interval = checkpoint_interval
        self._checkpoint_counter = 0
        self._graph = None

    def _build_graph(self) -> Any:
        """Build the LangGraph state graph.

        Returns:
            Compiled LangGraph.
        """
        try:
            from langgraph.graph import StateGraph, END
        except ImportError:
            raise ImportError("LangGraph is not installed. Install it with: pip install langgraph")

        # Import agents
        from mrzero.agents.mapper.agent import MapperAgent
        from mrzero.agents.hunter.agent import HunterAgent
        from mrzero.agents.verifier.agent import VerifierAgent
        from mrzero.agents.builder.agent import EnvBuilderAgent
        from mrzero.agents.exploiter.agent import ExploitBuilderAgent
        from mrzero.agents.reporter.agent import ReporterAgent

        # Initialize agents
        self.mapper = MapperAgent()
        self.hunter = HunterAgent()
        self.verifier = VerifierAgent()
        self.env_builder = EnvBuilderAgent()
        self.exploit_builder = ExploitBuilderAgent()
        self.reporter = ReporterAgent()

        # Create state graph
        workflow = StateGraph(AgentState)

        # Add nodes
        workflow.add_node("mapper", self._run_mapper)
        workflow.add_node("hunter", self._run_hunter)
        workflow.add_node("verifier", self._run_verifier)
        workflow.add_node("env_builder", self._run_env_builder)
        workflow.add_node("exploit_builder", self._run_exploit_builder)
        workflow.add_node("reporter", self._run_reporter)
        workflow.add_node("human_input", self._handle_human_input)

        # Set entry point
        workflow.set_entry_point("mapper")

        # Add conditional edges
        workflow.add_conditional_edges(
            "mapper",
            self._route_after_mapper,
            {
                "hunter": "hunter",
                "end": END,
            },
        )

        workflow.add_conditional_edges(
            "hunter",
            self._route_after_hunter,
            {
                "verifier": "verifier",
                "human_input": "human_input",
                "end": END,
            },
        )

        workflow.add_conditional_edges(
            "verifier",
            self._route_after_verifier,
            {
                "hunter": "hunter",
                "env_builder": "env_builder",
                "reporter": "reporter",
                "human_input": "human_input",
            },
        )

        workflow.add_conditional_edges(
            "env_builder",
            self._route_after_env_builder,
            {
                "exploit_builder": "exploit_builder",
                "reporter": "reporter",
                "human_input": "human_input",
            },
        )

        workflow.add_conditional_edges(
            "exploit_builder",
            self._route_after_exploit_builder,
            {
                "reporter": "reporter",
                "human_input": "human_input",
            },
        )

        workflow.add_edge("reporter", END)

        workflow.add_conditional_edges(
            "human_input",
            self._route_after_human_input,
            {
                "hunter": "hunter",
                "verifier": "verifier",
                "env_builder": "env_builder",
                "exploit_builder": "exploit_builder",
                "reporter": "reporter",
                "end": END,
            },
        )

        return workflow.compile()

    async def _run_mapper(self, state: AgentState) -> dict[str, Any]:
        """Run the Mapper agent."""
        console.print("[cyan]Running MrZeroMapper - Analyzing attack surface...[/cyan]")
        result = await self.mapper.execute(state)

        updates = {
            "current_agent": "mapper",
            "attack_surface": result.output.get("attack_surface"),
        }

        if result.errors:
            updates["errors"] = state.errors + result.errors

        # Save checkpoint after mapper completes
        self._save_checkpoint_from_updates(state, updates, "mapper")

        return updates

    async def _run_hunter(self, state: AgentState) -> dict[str, Any]:
        """Run the Hunter agent."""
        iteration = state.hunter_verifier_state.iteration_count + 1
        console.print(f"[cyan]Running MrZeroVulnHunter - Iteration {iteration}...[/cyan]")
        result = await self.hunter.execute(state)

        # Update hunter-verifier state
        hv_state = state.hunter_verifier_state.model_copy()
        hv_state.candidates = result.output.get("candidates", [])
        hv_state.iteration_count = iteration

        updates = {
            "current_agent": "hunter",
            "hunter_verifier_state": hv_state,
        }

        if result.requires_human_input:
            updates["awaiting_human_input"] = True
            updates["human_prompt"] = result.human_prompt

        if result.errors:
            updates["errors"] = state.errors + result.errors

        # Save checkpoint after hunter completes
        self._save_checkpoint_from_updates(state, updates, f"hunter_iter_{iteration}")

        return updates

    async def _run_verifier(self, state: AgentState) -> dict[str, Any]:
        """Run the Verifier agent."""
        console.print("[cyan]Running MrZeroVerifier - Filtering false positives...[/cyan]")
        result = await self.verifier.execute(state)

        # Update hunter-verifier state
        hv_state = state.hunter_verifier_state.model_copy()
        hv_state.confirmed = result.output.get("confirmed", [])
        hv_state.false_positives = result.output.get("false_positives", [])
        hv_state.feedback = result.output.get("feedback", [])

        updates = {
            "current_agent": "verifier",
            "hunter_verifier_state": hv_state,
            "confirmed_vulnerabilities": hv_state.confirmed,
        }

        if result.requires_human_input:
            updates["awaiting_human_input"] = True
            updates["human_prompt"] = result.human_prompt

        if result.errors:
            updates["errors"] = state.errors + result.errors

        # Save checkpoint after verifier completes
        self._save_checkpoint_from_updates(state, updates, "verifier")

        return updates

    async def _run_env_builder(self, state: AgentState) -> dict[str, Any]:
        """Run the EnvBuilder agent."""
        console.print("[cyan]Running MrZeroEnvBuilder - Setting up environment...[/cyan]")
        result = await self.env_builder.execute(state)

        updates = {
            "current_agent": "env_builder",
            "environment": result.output.get("environment"),
        }

        if result.requires_human_input:
            updates["awaiting_human_input"] = True
            updates["human_prompt"] = result.human_prompt

        if result.errors:
            updates["errors"] = state.errors + result.errors

        # Save checkpoint after env_builder completes
        self._save_checkpoint_from_updates(state, updates, "env_builder")

        return updates

    async def _run_exploit_builder(self, state: AgentState) -> dict[str, Any]:
        """Run the ExploitBuilder agent."""
        console.print("[cyan]Running MrZeroExploitBuilder - Generating exploits...[/cyan]")
        result = await self.exploit_builder.execute(state)

        updates = {
            "current_agent": "exploit_builder",
            "exploits": state.exploits + result.output.get("exploits", []),
        }

        if result.requires_human_input:
            updates["awaiting_human_input"] = True
            updates["human_prompt"] = result.human_prompt

        if result.errors:
            updates["errors"] = state.errors + result.errors

        # Save checkpoint after exploit_builder completes
        self._save_checkpoint_from_updates(state, updates, "exploit_builder")

        return updates

    async def _run_reporter(self, state: AgentState) -> dict[str, Any]:
        """Run the Reporter agent."""
        console.print("[cyan]Running MrZeroConclusion - Generating report...[/cyan]")
        result = await self.reporter.execute(state)

        updates = {
            "current_agent": "reporter",
            "workflow_status": "completed",
        }

        if result.errors:
            updates["errors"] = state.errors + result.errors

        # Final checkpoint is saved in run() method

        return updates

    def _save_checkpoint_from_updates(
        self,
        state: AgentState,
        updates: dict[str, Any],
        node_name: str,
    ) -> None:
        """Save checkpoint by merging state with updates.

        Args:
            state: Current AgentState.
            updates: Updates to merge into state.
            node_name: Name of the current node.
        """
        if self.checkpoint_interval <= 0:
            return

        # Create a merged state dict for checkpointing
        try:
            state_dict = state.model_dump()
            state_dict.update(updates)
            self._save_checkpoint(state_dict, node_name)
        except Exception as e:
            console.print(f"[dim]Checkpoint save failed: {e}[/dim]")

    async def _handle_human_input(self, state: AgentState) -> dict[str, Any]:
        """Handle human input in HITL mode."""
        from rich.prompt import Prompt

        console.print(f"\n[yellow]Human input required:[/yellow]")
        console.print(f"[bold]{state.human_prompt}[/bold]\n")

        response = Prompt.ask("Your response")

        return {
            "human_response": response,
            "awaiting_human_input": False,
            "human_prompt": None,
        }

    def _route_after_mapper(self, state: AgentState) -> RouteDecision:
        """Route after Mapper agent."""
        if state.attack_surface is None:
            console.print("[red]Mapper failed to produce attack surface map[/red]")
            return "end"

        if not state.attack_surface.endpoints and not state.attack_surface.data_flows:
            console.print("[yellow]No entry points found. Ending scan.[/yellow]")
            return "end"

        return "hunter"

    def _route_after_hunter(self, state: AgentState) -> RouteDecision:
        """Route after Hunter agent."""
        if state.awaiting_human_input:
            return "human_input"

        candidates = state.hunter_verifier_state.candidates
        if not candidates:
            console.print("[yellow]No vulnerability candidates found.[/yellow]")
            return "end"

        return "verifier"

    def _route_after_verifier(self, state: AgentState) -> RouteDecision:
        """Route after Verifier agent."""
        if state.awaiting_human_input:
            return "human_input"

        hv_state = state.hunter_verifier_state
        confirmed_count = len(hv_state.confirmed)

        # Check exit conditions
        if confirmed_count >= hv_state.min_true_positives:
            console.print(f"[green]Found {confirmed_count} confirmed vulnerabilities![/green]")
            return "env_builder"

        if hv_state.iteration_count >= hv_state.max_iterations:
            console.print(
                f"[yellow]Max iterations reached. {confirmed_count} vulnerabilities confirmed.[/yellow]"
            )
            if confirmed_count > 0:
                return "env_builder"
            # No vulnerabilities found after max iterations - go to reporter
            console.print("[yellow]No vulnerabilities confirmed. Generating report...[/yellow]")
            return "reporter"

        # Continue the loop
        return "hunter"

    def _route_after_env_builder(self, state: AgentState) -> RouteDecision:
        """Route after EnvBuilder agent."""
        if state.awaiting_human_input:
            return "human_input"

        if state.environment is None:
            console.print("[yellow]Environment setup failed. Skipping to report.[/yellow]")
            return "reporter"

        if not state.environment.build_successful:
            console.print("[yellow]Build failed. Manual guide generated.[/yellow]")
            return "reporter"

        return "exploit_builder"

    def _route_after_exploit_builder(self, state: AgentState) -> RouteDecision:
        """Route after ExploitBuilder agent."""
        if state.awaiting_human_input:
            return "human_input"

        return "reporter"

    def _route_after_human_input(self, state: AgentState) -> RouteDecision:
        """Route after human input."""
        response = state.human_response

        if response and response.lower() in ["quit", "exit", "stop"]:
            return "end"

        if response and response.lower() == "skip":
            # Skip to next logical step
            current = state.current_agent
            if current == "hunter":
                return "env_builder"
            elif current == "verifier":
                return "env_builder"
            elif current == "env_builder":
                return "reporter"
            elif current == "exploit_builder":
                return "reporter"

        # Return to the agent that requested input
        current = state.current_agent
        if current in ["hunter", "verifier", "env_builder", "exploit_builder", "reporter"]:
            return current

        return "reporter"

    async def run(
        self,
        target_path: str,
        mode: ExecutionMode,
        resume_session_id: str | None = None,
    ) -> AgentState:
        """Run the MrZero workflow.

        Args:
            target_path: Path to the target codebase.
            mode: Execution mode (YOLO or HITL).
            resume_session_id: Optional session ID to resume.

        Returns:
            Final AgentState after workflow completion.
        """
        # Build the graph
        if self._graph is None:
            self._graph = self._build_graph()

        # Create or resume session
        if resume_session_id:
            session = self.session_manager.get_session(resume_session_id)
            if session is None:
                raise ValueError(f"Session {resume_session_id} not found")
            session_id = resume_session_id

            # Try to restore state from checkpoint
            restored_state = self.checkpoint_manager.get_resumable_state(session_id, target_path)
            if restored_state:
                state = restored_state
                last_checkpoint = self.checkpoint_manager.get_latest_checkpoint(session_id)
                if last_checkpoint:
                    console.print(
                        f"[green]Resuming from checkpoint at '{last_checkpoint['node_name']}'[/green]"
                    )
            else:
                console.print("[yellow]No checkpoint found, starting fresh[/yellow]")
                state = AgentState(
                    session_id=session_id,
                    target_path=target_path,
                    mode=mode,
                )
        else:
            session_id = str(uuid.uuid4())
            self.session_manager.create_session(session_id, target_path, mode)
            state = AgentState(
                session_id=session_id,
                target_path=target_path,
                mode=mode,
            )

        # Store session_id for checkpoint callbacks
        self._current_session_id = session_id

        # Update session status
        self.session_manager.update_session(session_id, status="running")

        console.print(f"\n[bold blue]Session ID:[/bold blue] {session_id[:8]}...")
        console.print(f"[bold blue]Mode:[/bold blue] {mode.value.upper()}")
        if self.checkpoint_interval > 0:
            console.print(
                f"[bold blue]Checkpointing:[/bold blue] Every {self.checkpoint_interval} agent(s)\n"
            )
        else:
            console.print("[bold blue]Checkpointing:[/bold blue] Disabled\n")

        try:
            # Run the workflow
            final_state = await self._graph.ainvoke(state)

            # LangGraph returns a dict, convert to JSON for storage
            if isinstance(final_state, dict):
                state_json = json.dumps(final_state, default=str)
            else:
                state_json = json.dumps(final_state.model_dump(), default=str)

            # Save final checkpoint
            if self.checkpoint_interval > 0:
                self._save_checkpoint(final_state, "completed")

            # Update session as completed
            self.session_manager.update_session(
                session_id,
                status="completed",
                state_json=state_json,
            )

            return final_state

        except KeyboardInterrupt:
            # Save checkpoint on interrupt for resume
            console.print("\n[yellow]Interrupted! Saving checkpoint...[/yellow]")
            if self.checkpoint_interval > 0:
                self._save_checkpoint(state, state.current_agent)
                console.print(
                    f"[green]Checkpoint saved. Resume with: --resume {session_id}[/green]"
                )
            self.session_manager.update_session(session_id, status="paused")
            raise

        except Exception as e:
            # Save checkpoint on error for debugging
            if self.checkpoint_interval > 0:
                try:
                    self._save_checkpoint(state, f"error_{state.current_agent}")
                except Exception:
                    pass  # Don't mask the original error
            self.session_manager.update_session(session_id, status="failed")
            raise

    def _save_checkpoint(
        self,
        state: AgentState | dict,
        node_name: str,
    ) -> str | None:
        """Save a checkpoint if checkpointing is enabled.

        Args:
            state: Current state to checkpoint.
            node_name: Name of the current node/agent.

        Returns:
            Checkpoint ID or None if checkpointing disabled.
        """
        if self.checkpoint_interval <= 0:
            return None

        self._checkpoint_counter += 1

        # Only save at intervals (or always for errors/completion)
        if (
            self._checkpoint_counter % self.checkpoint_interval == 0
            or node_name.startswith("error_")
            or node_name == "completed"
        ):
            session_id = getattr(self, "_current_session_id", None)
            if session_id:
                checkpoint_id = self.checkpoint_manager.save_checkpoint(
                    session_id=session_id,
                    node_name=node_name,
                    state=state,
                )
                console.print(f"[dim]Checkpoint saved: {checkpoint_id[:8]}...[/dim]")
                return checkpoint_id

        return None


async def run_scan(
    target_path: str,
    mode: ExecutionMode,
    resume_session_id: str | None = None,
    checkpoint_interval: int = 1,
) -> AgentState:
    """Entry point for running a scan.

    Args:
        target_path: Path to the target codebase.
        mode: Execution mode.
        resume_session_id: Optional session ID to resume.
        checkpoint_interval: Save checkpoint every N agents (0 to disable).

    Returns:
        Final AgentState.
    """
    workflow = MrZeroWorkflow(checkpoint_interval=checkpoint_interval)
    return await workflow.run(target_path, mode, resume_session_id)
