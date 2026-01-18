"""Checkpoint manager for session persistence and resume."""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from mrzero.core.memory.sqlite import CheckpointModel, SQLiteManager
from mrzero.core.memory.state import AgentState, HunterVerifierState
from mrzero.core.schemas import (
    AttackSurfaceMap,
    DataFlow,
    Endpoint,
    EnvironmentInfo,
    ExecutionMode,
    Exploit,
    Technology,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
    VulnerabilityType,
)


class StateSerializer:
    """Handles serialization/deserialization of complex state objects."""

    @staticmethod
    def serialize_state(state: AgentState | dict) -> str:
        """Serialize AgentState to JSON string.

        Args:
            state: AgentState or dict to serialize.

        Returns:
            JSON string representation.
        """
        if isinstance(state, dict):
            data = state
        else:
            data = StateSerializer._state_to_dict(state)

        return json.dumps(data, default=StateSerializer._json_encoder)

    @staticmethod
    def deserialize_state(json_str: str) -> AgentState:
        """Deserialize JSON string to AgentState.

        Args:
            json_str: JSON string to deserialize.

        Returns:
            AgentState object.
        """
        data = json.loads(json_str)
        return StateSerializer._dict_to_state(data)

    @staticmethod
    def _json_encoder(obj: Any) -> Any:
        """Custom JSON encoder for datetime and other types."""
        if isinstance(obj, datetime):
            return {"__datetime__": obj.isoformat()}
        elif hasattr(obj, "model_dump"):
            return obj.model_dump()
        elif hasattr(obj, "value"):  # Enum
            return obj.value
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    @staticmethod
    def _state_to_dict(state: AgentState) -> dict[str, Any]:
        """Convert AgentState to a serializable dict.

        Args:
            state: AgentState to convert.

        Returns:
            Dictionary representation.
        """
        return {
            "session_id": state.session_id,
            "target_path": state.target_path,
            "mode": state.mode.value,
            "messages": state.messages,
            "current_agent": state.current_agent,
            "workflow_status": state.workflow_status,
            "attack_surface": (state.attack_surface.model_dump() if state.attack_surface else None),
            "hunter_verifier_state": StateSerializer._hv_state_to_dict(state.hunter_verifier_state),
            "confirmed_vulnerabilities": [v.model_dump() for v in state.confirmed_vulnerabilities],
            "environment": (state.environment.model_dump() if state.environment else None),
            "exploits": [e.model_dump() for e in state.exploits],
            "awaiting_human_input": state.awaiting_human_input,
            "human_prompt": state.human_prompt,
            "human_response": state.human_response,
            "errors": state.errors,
            "tool_cache_hits": state.tool_cache_hits,
            "tool_cache_misses": state.tool_cache_misses,
        }

    @staticmethod
    def _hv_state_to_dict(hv_state: HunterVerifierState) -> dict[str, Any]:
        """Convert HunterVerifierState to dict.

        Args:
            hv_state: HunterVerifierState to convert.

        Returns:
            Dictionary representation.
        """
        return {
            "iteration_count": hv_state.iteration_count,
            "max_iterations": hv_state.max_iterations,
            "min_true_positives": hv_state.min_true_positives,
            "candidates": [v.model_dump() for v in hv_state.candidates],
            "confirmed": [v.model_dump() for v in hv_state.confirmed],
            "false_positives": [v.model_dump() for v in hv_state.false_positives],
            "feedback": hv_state.feedback,
        }

    @staticmethod
    def _dict_to_state(data: dict[str, Any]) -> AgentState:
        """Convert dict back to AgentState.

        Args:
            data: Dictionary to convert.

        Returns:
            AgentState object.
        """
        # Parse attack surface
        attack_surface = None
        if data.get("attack_surface"):
            attack_surface = StateSerializer._parse_attack_surface(data["attack_surface"])

        # Parse hunter-verifier state
        hv_state = StateSerializer._parse_hv_state(data.get("hunter_verifier_state", {}))

        # Parse confirmed vulnerabilities
        confirmed_vulns = [
            StateSerializer._parse_vulnerability(v)
            for v in data.get("confirmed_vulnerabilities", [])
        ]

        # Parse environment
        environment = None
        if data.get("environment"):
            environment = EnvironmentInfo(**data["environment"])

        # Parse exploits
        exploits = [Exploit(**e) for e in data.get("exploits", [])]

        return AgentState(
            session_id=data["session_id"],
            target_path=data["target_path"],
            mode=ExecutionMode(data["mode"]),
            messages=data.get("messages", []),
            current_agent=data.get("current_agent", "mapper"),
            workflow_status=data.get("workflow_status", "pending"),
            attack_surface=attack_surface,
            hunter_verifier_state=hv_state,
            confirmed_vulnerabilities=confirmed_vulns,
            environment=environment,
            exploits=exploits,
            awaiting_human_input=data.get("awaiting_human_input", False),
            human_prompt=data.get("human_prompt"),
            human_response=data.get("human_response"),
            errors=data.get("errors", []),
            tool_cache_hits=data.get("tool_cache_hits", 0),
            tool_cache_misses=data.get("tool_cache_misses", 0),
        )

    @staticmethod
    def _parse_attack_surface(data: dict[str, Any]) -> AttackSurfaceMap:
        """Parse attack surface from dict.

        Args:
            data: Dictionary representation.

        Returns:
            AttackSurfaceMap object.
        """
        # Parse datetime
        scan_timestamp = data.get("scan_timestamp")
        if isinstance(scan_timestamp, str):
            scan_timestamp = datetime.fromisoformat(scan_timestamp)
        elif isinstance(scan_timestamp, dict) and "__datetime__" in scan_timestamp:
            scan_timestamp = datetime.fromisoformat(scan_timestamp["__datetime__"])

        return AttackSurfaceMap(
            target_path=data["target_path"],
            scan_timestamp=scan_timestamp or datetime.now(),
            languages=[Technology(**t) for t in data.get("languages", [])],
            frameworks=[Technology(**f) for f in data.get("frameworks", [])],
            endpoints=[Endpoint(**e) for e in data.get("endpoints", [])],
            data_flows=[DataFlow(**d) for d in data.get("data_flows", [])],
            dependencies=data.get("dependencies", {}),
            file_count=data.get("file_count", 0),
            loc=data.get("loc", 0),
            auth_boundaries=data.get("auth_boundaries", []),
            trust_zones=data.get("trust_zones", []),
        )

    @staticmethod
    def _parse_hv_state(data: dict[str, Any]) -> HunterVerifierState:
        """Parse HunterVerifierState from dict.

        Args:
            data: Dictionary representation.

        Returns:
            HunterVerifierState object.
        """
        return HunterVerifierState(
            iteration_count=data.get("iteration_count", 0),
            max_iterations=data.get("max_iterations", 3),
            min_true_positives=data.get("min_true_positives", 3),
            candidates=[
                StateSerializer._parse_vulnerability(v) for v in data.get("candidates", [])
            ],
            confirmed=[StateSerializer._parse_vulnerability(v) for v in data.get("confirmed", [])],
            false_positives=[
                StateSerializer._parse_vulnerability(v) for v in data.get("false_positives", [])
            ],
            feedback=data.get("feedback", []),
        )

    @staticmethod
    def _parse_vulnerability(data: dict[str, Any]) -> Vulnerability:
        """Parse Vulnerability from dict.

        Args:
            data: Dictionary representation.

        Returns:
            Vulnerability object.
        """
        # Parse datetime fields
        discovered_at = data.get("discovered_at")
        if isinstance(discovered_at, str):
            discovered_at = datetime.fromisoformat(discovered_at)
        elif isinstance(discovered_at, dict) and "__datetime__" in discovered_at:
            discovered_at = datetime.fromisoformat(discovered_at["__datetime__"])

        verified_at = data.get("verified_at")
        if isinstance(verified_at, str):
            verified_at = datetime.fromisoformat(verified_at)
        elif isinstance(verified_at, dict) and "__datetime__" in verified_at:
            verified_at = datetime.fromisoformat(verified_at["__datetime__"])

        # Parse data flow
        data_flow = None
        if data.get("data_flow"):
            data_flow = DataFlow(**data["data_flow"])

        return Vulnerability(
            id=data.get("id", ""),
            vuln_type=VulnerabilityType(data["vuln_type"]),
            severity=VulnerabilitySeverity(data["severity"]),
            score=data["score"],
            status=VulnerabilityStatus(data.get("status", "candidate")),
            title=data["title"],
            description=data["description"],
            file_path=data["file_path"],
            line_number=data["line_number"],
            code_snippet=data.get("code_snippet"),
            data_flow=data_flow,
            cwe_id=data.get("cwe_id"),
            cvss=data.get("cvss"),
            tool_source=data["tool_source"],
            confidence=data.get("confidence", 0.5),
            remediation=data.get("remediation"),
            discovered_at=discovered_at or datetime.now(),
            verified_at=verified_at,
        )


class CheckpointManager:
    """Manages checkpoints for session persistence and resume.

    Checkpoints allow saving scan state at any point and resuming
    interrupted scans from where they left off.
    """

    def __init__(self, db_path: Path | str) -> None:
        """Initialize the checkpoint manager.

        Args:
            db_path: Path to the SQLite database.
        """
        self.db = SQLiteManager(db_path)
        self.serializer = StateSerializer()

    def save_checkpoint(
        self,
        session_id: str,
        node_name: str,
        state: AgentState | dict,
        checkpoint_id: str | None = None,
    ) -> str:
        """Save a checkpoint for a session.

        Args:
            session_id: Session identifier.
            node_name: Name of the current node/agent.
            state: Current AgentState or dict.
            checkpoint_id: Optional checkpoint ID (auto-generated if not provided).

        Returns:
            Checkpoint ID.
        """
        if checkpoint_id is None:
            checkpoint_id = str(uuid.uuid4())

        state_json = self.serializer.serialize_state(state)

        with self.db.get_session() as session:
            checkpoint = CheckpointModel(
                session_id=session_id,
                checkpoint_id=checkpoint_id,
                node_name=node_name,
                state_json=state_json,
                created_at=datetime.now(),
            )
            session.add(checkpoint)
            session.commit()

        return checkpoint_id

    def load_checkpoint(
        self,
        session_id: str,
        checkpoint_id: str | None = None,
    ) -> AgentState | None:
        """Load a checkpoint for a session.

        Args:
            session_id: Session identifier.
            checkpoint_id: Specific checkpoint ID to load.
                          If None, loads the latest checkpoint.

        Returns:
            AgentState or None if not found.
        """
        with self.db.get_session() as session:
            if checkpoint_id:
                checkpoint = (
                    session.query(CheckpointModel)
                    .filter(
                        CheckpointModel.session_id == session_id,
                        CheckpointModel.checkpoint_id == checkpoint_id,
                    )
                    .first()
                )
            else:
                # Get the latest checkpoint
                checkpoint = (
                    session.query(CheckpointModel)
                    .filter(CheckpointModel.session_id == session_id)
                    .order_by(CheckpointModel.created_at.desc())
                    .first()
                )

            if not checkpoint:
                return None

            return self.serializer.deserialize_state(checkpoint.state_json)

    def get_latest_checkpoint(self, session_id: str) -> dict[str, Any] | None:
        """Get metadata about the latest checkpoint for a session.

        Args:
            session_id: Session identifier.

        Returns:
            Dict with checkpoint metadata or None.
        """
        with self.db.get_session() as session:
            checkpoint = (
                session.query(CheckpointModel)
                .filter(CheckpointModel.session_id == session_id)
                .order_by(CheckpointModel.created_at.desc())
                .first()
            )

            if not checkpoint:
                return None

            return {
                "checkpoint_id": checkpoint.checkpoint_id,
                "session_id": checkpoint.session_id,
                "node_name": checkpoint.node_name,
                "created_at": checkpoint.created_at,
            }

    def list_checkpoints(self, session_id: str) -> list[dict[str, Any]]:
        """List all checkpoints for a session.

        Args:
            session_id: Session identifier.

        Returns:
            List of checkpoint metadata dicts.
        """
        with self.db.get_session() as session:
            checkpoints = (
                session.query(CheckpointModel)
                .filter(CheckpointModel.session_id == session_id)
                .order_by(CheckpointModel.created_at.desc())
                .all()
            )

            return [
                {
                    "checkpoint_id": cp.checkpoint_id,
                    "session_id": cp.session_id,
                    "node_name": cp.node_name,
                    "created_at": cp.created_at,
                }
                for cp in checkpoints
            ]

    def delete_checkpoint(self, session_id: str, checkpoint_id: str) -> bool:
        """Delete a specific checkpoint.

        Args:
            session_id: Session identifier.
            checkpoint_id: Checkpoint ID to delete.

        Returns:
            True if deleted, False if not found.
        """
        with self.db.get_session() as session:
            deleted = (
                session.query(CheckpointModel)
                .filter(
                    CheckpointModel.session_id == session_id,
                    CheckpointModel.checkpoint_id == checkpoint_id,
                )
                .delete()
            )
            session.commit()
            return deleted > 0

    def delete_all_checkpoints(self, session_id: str) -> int:
        """Delete all checkpoints for a session.

        Args:
            session_id: Session identifier.

        Returns:
            Number of checkpoints deleted.
        """
        with self.db.get_session() as session:
            deleted = (
                session.query(CheckpointModel)
                .filter(CheckpointModel.session_id == session_id)
                .delete()
            )
            session.commit()
            return deleted

    def get_resumable_state(
        self,
        session_id: str,
        target_path: str | None = None,
    ) -> AgentState | None:
        """Get state ready for resuming a scan.

        This loads the latest checkpoint and prepares it for resumption.

        Args:
            session_id: Session identifier.
            target_path: Optional target path override.

        Returns:
            AgentState ready for resumption or None.
        """
        state = self.load_checkpoint(session_id)
        if state is None:
            return None

        # Update target path if provided
        if target_path:
            state.target_path = target_path

        # Reset workflow status to running
        state.workflow_status = "running"

        # Clear any pending human input flags
        state.awaiting_human_input = False
        state.human_prompt = None
        state.human_response = None

        return state

    def get_checkpoint_node(self, session_id: str) -> str | None:
        """Get the node name from the latest checkpoint.

        Args:
            session_id: Session identifier.

        Returns:
            Node name or None.
        """
        metadata = self.get_latest_checkpoint(session_id)
        if metadata:
            return metadata["node_name"]
        return None


def create_checkpoint_saver(db_path: Path | str) -> "CheckpointSaver":
    """Create a checkpoint saver compatible with LangGraph.

    Args:
        db_path: Path to the SQLite database.

    Returns:
        CheckpointSaver instance.
    """
    return CheckpointSaver(db_path)


class CheckpointSaver:
    """LangGraph-compatible checkpoint saver.

    This class provides an interface compatible with LangGraph's
    checkpointer protocol for automatic state persistence.
    """

    def __init__(self, db_path: Path | str) -> None:
        """Initialize the checkpoint saver.

        Args:
            db_path: Path to the SQLite database.
        """
        self.manager = CheckpointManager(db_path)
        self._current_session_id: str | None = None

    def set_session_id(self, session_id: str) -> None:
        """Set the current session ID for checkpointing.

        Args:
            session_id: Session identifier.
        """
        self._current_session_id = session_id

    def put(self, config: dict, checkpoint: dict, metadata: dict) -> dict:
        """Save a checkpoint (LangGraph protocol).

        Args:
            config: Configuration dict (contains thread_id).
            checkpoint: Checkpoint data.
            metadata: Checkpoint metadata.

        Returns:
            Updated config with checkpoint info.
        """
        session_id = self._current_session_id or config.get("configurable", {}).get(
            "thread_id", "default"
        )
        node_name = metadata.get("source", "unknown")

        checkpoint_id = self.manager.save_checkpoint(
            session_id=session_id,
            node_name=node_name,
            state=checkpoint,
        )

        return {**config, "checkpoint_id": checkpoint_id}

    def get(self, config: dict) -> dict | None:
        """Get the latest checkpoint (LangGraph protocol).

        Args:
            config: Configuration dict.

        Returns:
            Checkpoint data or None.
        """
        session_id = self._current_session_id or config.get("configurable", {}).get(
            "thread_id", "default"
        )

        state = self.manager.load_checkpoint(session_id)
        if state:
            return StateSerializer._state_to_dict(state)
        return None

    def list(self, config: dict) -> list[dict]:
        """List checkpoints (LangGraph protocol).

        Args:
            config: Configuration dict.

        Returns:
            List of checkpoint metadata.
        """
        session_id = self._current_session_id or config.get("configurable", {}).get(
            "thread_id", "default"
        )

        return self.manager.list_checkpoints(session_id)
