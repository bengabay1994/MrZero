"""Integration tests for checkpoint and resume functionality."""

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mrzero.core.memory.checkpoint import CheckpointManager, StateSerializer
from mrzero.core.memory.sqlite import SessionManager
from mrzero.core.memory.state import AgentState, HunterVerifierState
from mrzero.core.orchestration.graph import MrZeroWorkflow, run_scan
from mrzero.core.schemas import (
    AttackSurfaceMap,
    Endpoint,
    ExecutionMode,
    Technology,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
    VulnerabilityType,
)


@pytest.fixture
def temp_db_dir():
    """Create a temporary directory for test databases."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_config(temp_db_dir):
    """Create a mock config with temp db path."""
    config = MagicMock()
    config.db_path = temp_db_dir / "test.db"
    config.vector_db_path = temp_db_dir / "vectordb"
    config.output_dir = temp_db_dir / "output"
    config.hunter_verifier_max_iterations = 3
    config.min_true_positives = 2
    return config


@pytest.fixture
def sample_attack_surface():
    """Create a sample attack surface."""
    return AttackSurfaceMap(
        target_path="/test/target",
        languages=[Technology(name="Python", version="3.12", category="language")],
        endpoints=[
            Endpoint(
                path="/api/test",
                method="GET",
                file_path="/test/app.py",
                line_number=10,
                authenticated=False,
            )
        ],
        file_count=10,
        loc=1000,
    )


@pytest.fixture
def sample_vulnerability():
    """Create a sample vulnerability."""
    return Vulnerability(
        id="test-vuln-001",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=VulnerabilitySeverity.HIGH,
        score=85,
        status=VulnerabilityStatus.CONFIRMED,
        title="Test SQL Injection",
        description="Test vulnerability",
        file_path="/test/app.py",
        line_number=42,
        tool_source="test",
        confidence=0.9,
    )


class TestCheckpointResumeFunctionality:
    """Integration tests for checkpoint and resume."""

    def test_workflow_creates_checkpoints(self, temp_db_dir, mock_config):
        """Test that workflow creates checkpoints after agent execution."""
        with patch("mrzero.core.orchestration.graph.get_config", return_value=mock_config):
            workflow = MrZeroWorkflow(checkpoint_interval=1)

            # Verify checkpoint manager was initialized
            assert workflow.checkpoint_manager is not None
            assert workflow.checkpoint_interval == 1

    def test_checkpoint_saved_after_state_update(self, temp_db_dir, sample_attack_surface):
        """Test that state is properly checkpointed."""
        checkpoint_manager = CheckpointManager(temp_db_dir / "test.db")

        state = AgentState(
            session_id="test-session-001",
            target_path="/test/target",
            mode=ExecutionMode.YOLO,
            attack_surface=sample_attack_surface,
            current_agent="mapper",
        )

        # Save checkpoint
        checkpoint_id = checkpoint_manager.save_checkpoint(
            session_id=state.session_id,
            node_name="mapper",
            state=state,
        )

        # Verify checkpoint was saved
        assert checkpoint_id is not None

        # Load and verify
        loaded = checkpoint_manager.load_checkpoint(state.session_id)
        assert loaded is not None
        assert loaded.attack_surface is not None
        assert loaded.attack_surface.target_path == "/test/target"

    def test_resume_from_checkpoint(self, temp_db_dir, sample_attack_surface, sample_vulnerability):
        """Test resuming a scan from a checkpoint."""
        checkpoint_manager = CheckpointManager(temp_db_dir / "test.db")

        # Create a state at hunter stage
        hv_state = HunterVerifierState(
            iteration_count=1,
            candidates=[sample_vulnerability],
            confirmed=[],
        )

        state = AgentState(
            session_id="resume-test-001",
            target_path="/test/target",
            mode=ExecutionMode.YOLO,
            attack_surface=sample_attack_surface,
            hunter_verifier_state=hv_state,
            current_agent="hunter",
            workflow_status="running",
        )

        # Save checkpoint
        checkpoint_manager.save_checkpoint(
            session_id=state.session_id,
            node_name="hunter_iter_1",
            state=state,
        )

        # Simulate resume
        resumed_state = checkpoint_manager.get_resumable_state(state.session_id)

        assert resumed_state is not None
        assert resumed_state.session_id == "resume-test-001"
        assert resumed_state.current_agent == "hunter"
        assert resumed_state.hunter_verifier_state.iteration_count == 1
        assert len(resumed_state.hunter_verifier_state.candidates) == 1
        assert resumed_state.workflow_status == "running"

    def test_multiple_checkpoints_per_session(
        self, temp_db_dir, sample_attack_surface, sample_vulnerability
    ):
        """Test that multiple checkpoints are tracked correctly."""
        checkpoint_manager = CheckpointManager(temp_db_dir / "test.db")

        session_id = "multi-checkpoint-test"

        # Checkpoint 1: After mapper
        state1 = AgentState(
            session_id=session_id,
            target_path="/test/target",
            mode=ExecutionMode.YOLO,
            attack_surface=sample_attack_surface,
            current_agent="mapper",
        )
        checkpoint_manager.save_checkpoint(session_id, "mapper", state1)

        # Checkpoint 2: After hunter iteration 1
        hv_state = HunterVerifierState(iteration_count=1, candidates=[sample_vulnerability])
        state2 = state1.model_copy()
        state2.hunter_verifier_state = hv_state
        state2.current_agent = "hunter"
        checkpoint_manager.save_checkpoint(session_id, "hunter_iter_1", state2)

        # Checkpoint 3: After verifier
        hv_state.confirmed = [sample_vulnerability]
        state3 = state2.model_copy()
        state3.hunter_verifier_state = hv_state
        state3.current_agent = "verifier"
        state3.confirmed_vulnerabilities = [sample_vulnerability]
        checkpoint_manager.save_checkpoint(session_id, "verifier", state3)

        # Verify all checkpoints exist
        checkpoints = checkpoint_manager.list_checkpoints(session_id)
        assert len(checkpoints) == 3

        # Verify latest checkpoint is verifier
        latest = checkpoint_manager.get_latest_checkpoint(session_id)
        assert latest["node_name"] == "verifier"

        # Verify we can load latest and it has all data
        loaded = checkpoint_manager.load_checkpoint(session_id)
        assert loaded.current_agent == "verifier"
        assert len(loaded.confirmed_vulnerabilities) == 1

    def test_session_manager_integration(self, temp_db_dir):
        """Test checkpoint manager works with session manager."""
        db_path = temp_db_dir / "test.db"
        session_manager = SessionManager(db_path)
        checkpoint_manager = CheckpointManager(db_path)

        # Create session
        session_id = "integrated-test-001"
        session = session_manager.create_session(
            session_id=session_id,
            target_path="/test/target",
            mode=ExecutionMode.HITL,
        )

        # Update session status
        session_manager.update_session(session_id, status="running", current_agent="mapper")

        # Save checkpoint
        state = AgentState(
            session_id=session_id,
            target_path="/test/target",
            mode=ExecutionMode.HITL,
            current_agent="mapper",
        )
        checkpoint_manager.save_checkpoint(session_id, "mapper", state)

        # Verify session can be retrieved
        retrieved_session = session_manager.get_session(session_id)
        assert retrieved_session is not None
        assert retrieved_session.status == "running"

        # Verify checkpoint can be retrieved
        loaded_state = checkpoint_manager.load_checkpoint(session_id)
        assert loaded_state is not None
        assert loaded_state.current_agent == "mapper"

    def test_checkpoint_with_large_state(self, temp_db_dir):
        """Test checkpointing with a large state (many vulnerabilities)."""
        checkpoint_manager = CheckpointManager(temp_db_dir / "test.db")

        # Create many vulnerabilities
        vulns = []
        for i in range(100):
            vuln = Vulnerability(
                id=f"vuln-{i:03d}",
                vuln_type=VulnerabilityType.SQL_INJECTION,
                severity=VulnerabilitySeverity.HIGH,
                score=80,
                title=f"Test Vulnerability {i}",
                description=f"Description for vulnerability {i}",
                file_path=f"/test/file_{i}.py",
                line_number=i * 10,
                tool_source="test",
                confidence=0.8,
            )
            vulns.append(vuln)

        hv_state = HunterVerifierState(
            candidates=vulns[:50],
            confirmed=vulns[50:],
        )

        state = AgentState(
            session_id="large-state-test",
            target_path="/test/target",
            mode=ExecutionMode.YOLO,
            hunter_verifier_state=hv_state,
            confirmed_vulnerabilities=vulns[50:],
        )

        # Save checkpoint
        checkpoint_manager.save_checkpoint("large-state-test", "verifier", state)

        # Load and verify
        loaded = checkpoint_manager.load_checkpoint("large-state-test")
        assert len(loaded.hunter_verifier_state.candidates) == 50
        assert len(loaded.hunter_verifier_state.confirmed) == 50
        assert len(loaded.confirmed_vulnerabilities) == 50

    def test_state_serialization_roundtrip(self, sample_attack_surface, sample_vulnerability):
        """Test complete serialization roundtrip preserves all data."""
        hv_state = HunterVerifierState(
            iteration_count=2,
            max_iterations=5,
            min_true_positives=3,
            candidates=[sample_vulnerability],
            confirmed=[sample_vulnerability],
            feedback=["Focus on injection patterns", "Check auth boundaries"],
        )

        original = AgentState(
            session_id="roundtrip-test",
            target_path="/test/target",
            mode=ExecutionMode.YOLO,
            messages=[{"role": "user", "content": "test"}],
            current_agent="verifier",
            workflow_status="running",
            attack_surface=sample_attack_surface,
            hunter_verifier_state=hv_state,
            confirmed_vulnerabilities=[sample_vulnerability],
            awaiting_human_input=False,
            errors=["Warning: some files skipped"],
            tool_cache_hits=5,
            tool_cache_misses=2,
        )

        # Serialize
        json_str = StateSerializer.serialize_state(original)

        # Deserialize
        restored = StateSerializer.deserialize_state(json_str)

        # Verify all fields
        assert restored.session_id == original.session_id
        assert restored.target_path == original.target_path
        assert restored.mode == original.mode
        assert restored.current_agent == original.current_agent
        assert restored.workflow_status == original.workflow_status
        assert restored.tool_cache_hits == original.tool_cache_hits
        assert restored.tool_cache_misses == original.tool_cache_misses
        assert restored.errors == original.errors

        # Verify attack surface
        assert restored.attack_surface.target_path == original.attack_surface.target_path
        assert len(restored.attack_surface.languages) == 1
        assert len(restored.attack_surface.endpoints) == 1

        # Verify hunter-verifier state
        assert restored.hunter_verifier_state.iteration_count == 2
        assert restored.hunter_verifier_state.max_iterations == 5
        assert len(restored.hunter_verifier_state.candidates) == 1
        assert len(restored.hunter_verifier_state.feedback) == 2

        # Verify vulnerabilities
        assert len(restored.confirmed_vulnerabilities) == 1
        assert restored.confirmed_vulnerabilities[0].vuln_type == VulnerabilityType.SQL_INJECTION

    @pytest.mark.asyncio
    async def test_workflow_checkpoint_interval(self, temp_db_dir, mock_config):
        """Test that checkpoint interval controls when checkpoints are saved."""
        with patch("mrzero.core.orchestration.graph.get_config", return_value=mock_config):
            # Create workflow with interval of 2
            workflow = MrZeroWorkflow(checkpoint_interval=2)

            # Simulate checkpoint saving
            workflow._current_session_id = "interval-test"

            state = AgentState(
                session_id="interval-test",
                target_path="/test",
                mode=ExecutionMode.YOLO,
            )

            # First call - should not save (counter=1, interval=2)
            result1 = workflow._save_checkpoint(state, "mapper")
            # Note: First call increments to 1, 1 % 2 != 0, so no save

            # Second call - should save (counter=2, 2 % 2 == 0)
            result2 = workflow._save_checkpoint(state, "hunter")
            # Counter is 2, 2 % 2 == 0, so it should save

            # Verify checkpoint was saved on second call
            checkpoints = workflow.checkpoint_manager.list_checkpoints("interval-test")
            assert len(checkpoints) == 1
            assert checkpoints[0]["node_name"] == "hunter"

    def test_workflow_no_checkpoints_when_disabled(self, temp_db_dir, mock_config):
        """Test that no checkpoints are saved when interval is 0."""
        with patch("mrzero.core.orchestration.graph.get_config", return_value=mock_config):
            workflow = MrZeroWorkflow(checkpoint_interval=0)
            workflow._current_session_id = "disabled-test"

            state = AgentState(
                session_id="disabled-test",
                target_path="/test",
                mode=ExecutionMode.YOLO,
            )

            # Multiple calls should not save anything
            workflow._save_checkpoint(state, "mapper")
            workflow._save_checkpoint(state, "hunter")
            workflow._save_checkpoint(state, "verifier")

            checkpoints = workflow.checkpoint_manager.list_checkpoints("disabled-test")
            assert len(checkpoints) == 0

    def test_error_checkpoint_always_saved(self, temp_db_dir, mock_config):
        """Test that error checkpoints are always saved regardless of interval."""
        with patch("mrzero.core.orchestration.graph.get_config", return_value=mock_config):
            workflow = MrZeroWorkflow(checkpoint_interval=100)  # Very high interval
            workflow._current_session_id = "error-test"

            state = AgentState(
                session_id="error-test",
                target_path="/test",
                mode=ExecutionMode.YOLO,
            )

            # Error checkpoint should be saved regardless of interval
            workflow._save_checkpoint(state, "error_hunter")

            checkpoints = workflow.checkpoint_manager.list_checkpoints("error-test")
            assert len(checkpoints) == 1
            assert checkpoints[0]["node_name"] == "error_hunter"

    def test_completed_checkpoint_always_saved(self, temp_db_dir, mock_config):
        """Test that completed checkpoint is always saved regardless of interval."""
        with patch("mrzero.core.orchestration.graph.get_config", return_value=mock_config):
            workflow = MrZeroWorkflow(checkpoint_interval=100)
            workflow._current_session_id = "completed-test"

            state = AgentState(
                session_id="completed-test",
                target_path="/test",
                mode=ExecutionMode.YOLO,
            )

            # Completed checkpoint should be saved regardless of interval
            workflow._save_checkpoint(state, "completed")

            checkpoints = workflow.checkpoint_manager.list_checkpoints("completed-test")
            assert len(checkpoints) == 1
            assert checkpoints[0]["node_name"] == "completed"
