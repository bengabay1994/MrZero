"""Unit tests for the CheckpointManager."""

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from mrzero.core.memory.checkpoint import (
    CheckpointManager,
    CheckpointSaver,
    StateSerializer,
    create_checkpoint_saver,
)
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


@pytest.fixture
def temp_db_path():
    """Create a temporary database path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / "test_checkpoints.db"


@pytest.fixture
def checkpoint_manager(temp_db_path):
    """Create a CheckpointManager instance."""
    return CheckpointManager(temp_db_path)


@pytest.fixture
def sample_vulnerability():
    """Create a sample vulnerability."""
    return Vulnerability(
        id="vuln-001",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=VulnerabilitySeverity.CRITICAL,
        score=95,
        status=VulnerabilityStatus.CONFIRMED,
        title="SQL Injection in login form",
        description="User input is directly concatenated into SQL query",
        file_path="/app/login.py",
        line_number=42,
        code_snippet="query = f\"SELECT * FROM users WHERE username = '{username}'\"",
        cwe_id="CWE-89",
        cvss=9.8,
        tool_source="opengrep",
        confidence=0.95,
        remediation="Use parameterized queries",
    )


@pytest.fixture
def sample_attack_surface():
    """Create a sample attack surface map."""
    return AttackSurfaceMap(
        target_path="/app/target",
        languages=[Technology(name="Python", version="3.12", category="language")],
        frameworks=[Technology(name="Flask", version="3.0", category="framework")],
        endpoints=[
            Endpoint(
                path="/api/login",
                method="POST",
                file_path="/app/routes.py",
                line_number=10,
                authenticated=False,
                parameters=["username", "password"],
                risk_score=80,
            )
        ],
        data_flows=[
            DataFlow(
                source="request.form['username']",
                sink="cursor.execute()",
                source_file="/app/routes.py",
                source_line=15,
                sink_file="/app/db.py",
                sink_line=25,
                tainted=True,
            )
        ],
        file_count=50,
        loc=5000,
    )


@pytest.fixture
def sample_state(sample_vulnerability, sample_attack_surface):
    """Create a sample AgentState."""
    hv_state = HunterVerifierState(
        iteration_count=2,
        max_iterations=5,
        min_true_positives=3,
        candidates=[sample_vulnerability],
        confirmed=[sample_vulnerability],
        false_positives=[],
        feedback=["Focus on SQL injection patterns"],
    )

    return AgentState(
        session_id="test-session-123",
        target_path="/app/target",
        mode=ExecutionMode.YOLO,
        current_agent="verifier",
        workflow_status="running",
        attack_surface=sample_attack_surface,
        hunter_verifier_state=hv_state,
        confirmed_vulnerabilities=[sample_vulnerability],
        errors=["Warning: Some files skipped"],
    )


class TestStateSerializer:
    """Tests for StateSerializer."""

    def test_serialize_simple_state(self):
        """Test serializing a simple state."""
        state = AgentState(
            session_id="test-123",
            target_path="/test/path",
            mode=ExecutionMode.HITL,
        )

        json_str = StateSerializer.serialize_state(state)
        assert isinstance(json_str, str)

        data = json.loads(json_str)
        assert data["session_id"] == "test-123"
        assert data["target_path"] == "/test/path"
        assert data["mode"] == "hitl"

    def test_deserialize_simple_state(self):
        """Test deserializing a simple state."""
        state = AgentState(
            session_id="test-123",
            target_path="/test/path",
            mode=ExecutionMode.YOLO,
        )

        json_str = StateSerializer.serialize_state(state)
        restored = StateSerializer.deserialize_state(json_str)

        assert restored.session_id == "test-123"
        assert restored.target_path == "/test/path"
        assert restored.mode == ExecutionMode.YOLO

    def test_serialize_state_with_attack_surface(self, sample_state):
        """Test serializing state with attack surface."""
        json_str = StateSerializer.serialize_state(sample_state)
        data = json.loads(json_str)

        assert data["attack_surface"] is not None
        assert data["attack_surface"]["target_path"] == "/app/target"
        assert len(data["attack_surface"]["languages"]) == 1
        assert data["attack_surface"]["languages"][0]["name"] == "Python"

    def test_deserialize_state_with_attack_surface(self, sample_state):
        """Test deserializing state with attack surface."""
        json_str = StateSerializer.serialize_state(sample_state)
        restored = StateSerializer.deserialize_state(json_str)

        assert restored.attack_surface is not None
        assert restored.attack_surface.target_path == "/app/target"
        assert len(restored.attack_surface.languages) == 1
        assert restored.attack_surface.languages[0].name == "Python"

    def test_serialize_state_with_vulnerabilities(self, sample_state):
        """Test serializing state with vulnerabilities."""
        json_str = StateSerializer.serialize_state(sample_state)
        data = json.loads(json_str)

        assert len(data["confirmed_vulnerabilities"]) == 1
        vuln = data["confirmed_vulnerabilities"][0]
        assert vuln["vuln_type"] == "sql_injection"
        assert vuln["severity"] == "critical"

    def test_deserialize_state_with_vulnerabilities(self, sample_state):
        """Test deserializing state with vulnerabilities."""
        json_str = StateSerializer.serialize_state(sample_state)
        restored = StateSerializer.deserialize_state(json_str)

        assert len(restored.confirmed_vulnerabilities) == 1
        vuln = restored.confirmed_vulnerabilities[0]
        assert vuln.vuln_type == VulnerabilityType.SQL_INJECTION
        assert vuln.severity == VulnerabilitySeverity.CRITICAL

    def test_serialize_hunter_verifier_state(self, sample_state):
        """Test serializing hunter-verifier state."""
        json_str = StateSerializer.serialize_state(sample_state)
        data = json.loads(json_str)

        hv = data["hunter_verifier_state"]
        assert hv["iteration_count"] == 2
        assert hv["max_iterations"] == 5
        assert len(hv["candidates"]) == 1
        assert len(hv["confirmed"]) == 1
        assert len(hv["feedback"]) == 1

    def test_deserialize_hunter_verifier_state(self, sample_state):
        """Test deserializing hunter-verifier state."""
        json_str = StateSerializer.serialize_state(sample_state)
        restored = StateSerializer.deserialize_state(json_str)

        hv = restored.hunter_verifier_state
        assert hv.iteration_count == 2
        assert hv.max_iterations == 5
        assert len(hv.candidates) == 1
        assert len(hv.confirmed) == 1
        assert hv.feedback[0] == "Focus on SQL injection patterns"

    def test_serialize_dict_state(self):
        """Test serializing a dict instead of AgentState."""
        data = {
            "session_id": "test-dict",
            "target_path": "/test",
            "mode": "yolo",
            "current_agent": "mapper",
        }

        json_str = StateSerializer.serialize_state(data)
        parsed = json.loads(json_str)

        assert parsed["session_id"] == "test-dict"
        assert parsed["mode"] == "yolo"

    def test_datetime_serialization(self, sample_vulnerability):
        """Test that datetime fields are properly serialized."""
        state = AgentState(
            session_id="test-123",
            target_path="/test",
            mode=ExecutionMode.HITL,
            confirmed_vulnerabilities=[sample_vulnerability],
        )

        json_str = StateSerializer.serialize_state(state)
        restored = StateSerializer.deserialize_state(json_str)

        # Check that datetime was preserved
        assert restored.confirmed_vulnerabilities[0].discovered_at is not None


class TestCheckpointManager:
    """Tests for CheckpointManager."""

    def test_save_checkpoint(self, checkpoint_manager, sample_state):
        """Test saving a checkpoint."""
        checkpoint_id = checkpoint_manager.save_checkpoint(
            session_id="session-001",
            node_name="mapper",
            state=sample_state,
        )

        assert checkpoint_id is not None
        assert len(checkpoint_id) == 36  # UUID length

    def test_load_checkpoint(self, checkpoint_manager, sample_state):
        """Test loading a checkpoint."""
        checkpoint_id = checkpoint_manager.save_checkpoint(
            session_id="session-001",
            node_name="mapper",
            state=sample_state,
        )

        loaded = checkpoint_manager.load_checkpoint(
            session_id="session-001",
            checkpoint_id=checkpoint_id,
        )

        assert loaded is not None
        assert loaded.session_id == sample_state.session_id
        assert loaded.target_path == sample_state.target_path

    def test_load_latest_checkpoint(self, checkpoint_manager, sample_state):
        """Test loading the latest checkpoint."""
        # Save multiple checkpoints
        checkpoint_manager.save_checkpoint(
            session_id="session-001",
            node_name="mapper",
            state=sample_state,
        )

        sample_state.current_agent = "hunter"
        checkpoint_manager.save_checkpoint(
            session_id="session-001",
            node_name="hunter",
            state=sample_state,
        )

        # Load without specifying checkpoint_id
        loaded = checkpoint_manager.load_checkpoint(session_id="session-001")

        assert loaded is not None
        assert loaded.current_agent == "hunter"

    def test_load_nonexistent_checkpoint(self, checkpoint_manager):
        """Test loading a non-existent checkpoint."""
        loaded = checkpoint_manager.load_checkpoint(session_id="nonexistent")
        assert loaded is None

    def test_get_latest_checkpoint_metadata(self, checkpoint_manager, sample_state):
        """Test getting metadata for the latest checkpoint."""
        checkpoint_manager.save_checkpoint(
            session_id="session-001",
            node_name="verifier",
            state=sample_state,
        )

        metadata = checkpoint_manager.get_latest_checkpoint("session-001")

        assert metadata is not None
        assert metadata["node_name"] == "verifier"
        assert "checkpoint_id" in metadata
        assert "created_at" in metadata

    def test_list_checkpoints(self, checkpoint_manager, sample_state):
        """Test listing all checkpoints for a session."""
        # Save multiple checkpoints
        for node in ["mapper", "hunter", "verifier"]:
            sample_state.current_agent = node
            checkpoint_manager.save_checkpoint(
                session_id="session-001",
                node_name=node,
                state=sample_state,
            )

        checkpoints = checkpoint_manager.list_checkpoints("session-001")

        assert len(checkpoints) == 3
        # Should be ordered by created_at desc
        assert checkpoints[0]["node_name"] == "verifier"

    def test_delete_checkpoint(self, checkpoint_manager, sample_state):
        """Test deleting a specific checkpoint."""
        checkpoint_id = checkpoint_manager.save_checkpoint(
            session_id="session-001",
            node_name="mapper",
            state=sample_state,
        )

        result = checkpoint_manager.delete_checkpoint("session-001", checkpoint_id)
        assert result is True

        loaded = checkpoint_manager.load_checkpoint("session-001", checkpoint_id)
        assert loaded is None

    def test_delete_all_checkpoints(self, checkpoint_manager, sample_state):
        """Test deleting all checkpoints for a session."""
        for node in ["mapper", "hunter", "verifier"]:
            checkpoint_manager.save_checkpoint(
                session_id="session-001",
                node_name=node,
                state=sample_state,
            )

        deleted = checkpoint_manager.delete_all_checkpoints("session-001")
        assert deleted == 3

        checkpoints = checkpoint_manager.list_checkpoints("session-001")
        assert len(checkpoints) == 0

    def test_get_resumable_state(self, checkpoint_manager, sample_state):
        """Test getting state ready for resume."""
        sample_state.workflow_status = "paused"
        sample_state.awaiting_human_input = True
        sample_state.human_prompt = "Need approval"

        checkpoint_manager.save_checkpoint(
            session_id="session-001",
            node_name="hunter",
            state=sample_state,
        )

        resumed = checkpoint_manager.get_resumable_state("session-001")

        assert resumed is not None
        assert resumed.workflow_status == "running"
        assert resumed.awaiting_human_input is False
        assert resumed.human_prompt is None

    def test_get_resumable_state_with_new_target(self, checkpoint_manager, sample_state):
        """Test getting resumable state with a different target path."""
        checkpoint_manager.save_checkpoint(
            session_id="session-001",
            node_name="mapper",
            state=sample_state,
        )

        resumed = checkpoint_manager.get_resumable_state(
            session_id="session-001",
            target_path="/new/target/path",
        )

        assert resumed is not None
        assert resumed.target_path == "/new/target/path"

    def test_get_checkpoint_node(self, checkpoint_manager, sample_state):
        """Test getting the node name from the latest checkpoint."""
        checkpoint_manager.save_checkpoint(
            session_id="session-001",
            node_name="exploit_builder",
            state=sample_state,
        )

        node = checkpoint_manager.get_checkpoint_node("session-001")
        assert node == "exploit_builder"

    def test_checkpoint_with_custom_id(self, checkpoint_manager, sample_state):
        """Test saving a checkpoint with a custom ID."""
        custom_id = "my-custom-checkpoint-id"

        result_id = checkpoint_manager.save_checkpoint(
            session_id="session-001",
            node_name="mapper",
            state=sample_state,
            checkpoint_id=custom_id,
        )

        assert result_id == custom_id

        loaded = checkpoint_manager.load_checkpoint("session-001", custom_id)
        assert loaded is not None


class TestCheckpointSaver:
    """Tests for CheckpointSaver (LangGraph compatible)."""

    def test_create_checkpoint_saver(self, temp_db_path):
        """Test creating a checkpoint saver."""
        saver = create_checkpoint_saver(temp_db_path)
        assert isinstance(saver, CheckpointSaver)

    def test_put_checkpoint(self, temp_db_path):
        """Test putting a checkpoint (LangGraph protocol)."""
        saver = CheckpointSaver(temp_db_path)
        saver.set_session_id("test-session")

        config = {"configurable": {"thread_id": "test-session"}}
        checkpoint = {
            "session_id": "test-session",
            "target_path": "/test",
            "mode": "hitl",
            "current_agent": "mapper",
        }
        metadata = {"source": "mapper"}

        result = saver.put(config, checkpoint, metadata)

        assert "checkpoint_id" in result

    def test_get_checkpoint(self, temp_db_path):
        """Test getting a checkpoint (LangGraph protocol)."""
        saver = CheckpointSaver(temp_db_path)
        saver.set_session_id("test-session")

        config = {"configurable": {"thread_id": "test-session"}}
        checkpoint = {
            "session_id": "test-session",
            "target_path": "/test",
            "mode": "hitl",
            "current_agent": "mapper",
            "workflow_status": "running",
        }
        metadata = {"source": "mapper"}

        saver.put(config, checkpoint, metadata)
        result = saver.get(config)

        assert result is not None
        assert result["session_id"] == "test-session"

    def test_list_checkpoints(self, temp_db_path):
        """Test listing checkpoints (LangGraph protocol)."""
        saver = CheckpointSaver(temp_db_path)
        saver.set_session_id("test-session")

        config = {"configurable": {"thread_id": "test-session"}}

        # Put multiple checkpoints
        for node in ["mapper", "hunter"]:
            checkpoint = {
                "session_id": "test-session",
                "target_path": "/test",
                "mode": "hitl",
                "current_agent": node,
            }
            saver.put(config, checkpoint, {"source": node})

        result = saver.list(config)

        assert len(result) == 2


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_serialize_empty_lists(self):
        """Test serializing state with empty lists."""
        state = AgentState(
            session_id="test",
            target_path="/test",
            mode=ExecutionMode.HITL,
            confirmed_vulnerabilities=[],
            exploits=[],
            errors=[],
        )

        json_str = StateSerializer.serialize_state(state)
        restored = StateSerializer.deserialize_state(json_str)

        assert restored.confirmed_vulnerabilities == []
        assert restored.exploits == []
        assert restored.errors == []

    def test_serialize_state_with_environment(self):
        """Test serializing state with environment info."""
        env = EnvironmentInfo(
            env_type="docker",
            connection_ip="127.0.0.1",
            connection_port=8080,
            container_id="abc123",
            build_successful=True,
            build_attempts=2,
        )

        state = AgentState(
            session_id="test",
            target_path="/test",
            mode=ExecutionMode.YOLO,
            environment=env,
        )

        json_str = StateSerializer.serialize_state(state)
        restored = StateSerializer.deserialize_state(json_str)

        assert restored.environment is not None
        assert restored.environment.env_type == "docker"
        assert restored.environment.container_id == "abc123"

    def test_serialize_state_with_exploits(self):
        """Test serializing state with exploits."""
        exploit = Exploit(
            vulnerability_id="vuln-001",
            exploit_type="poc",
            language="python",
            code="import requests; requests.get('...')",
            description="SQL injection PoC",
            tested=True,
            successful=True,
        )

        state = AgentState(
            session_id="test",
            target_path="/test",
            mode=ExecutionMode.HITL,
            exploits=[exploit],
        )

        json_str = StateSerializer.serialize_state(state)
        restored = StateSerializer.deserialize_state(json_str)

        assert len(restored.exploits) == 1
        assert restored.exploits[0].exploit_type == "poc"
        assert restored.exploits[0].successful is True

    def test_checkpoint_isolation(self, temp_db_path):
        """Test that checkpoints from different sessions are isolated."""
        manager = CheckpointManager(temp_db_path)

        state1 = AgentState(
            session_id="session-1",
            target_path="/test1",
            mode=ExecutionMode.HITL,
        )
        state2 = AgentState(
            session_id="session-2",
            target_path="/test2",
            mode=ExecutionMode.YOLO,
        )

        manager.save_checkpoint("session-1", "mapper", state1)
        manager.save_checkpoint("session-2", "hunter", state2)

        checkpoints1 = manager.list_checkpoints("session-1")
        checkpoints2 = manager.list_checkpoints("session-2")

        assert len(checkpoints1) == 1
        assert len(checkpoints2) == 1
        assert checkpoints1[0]["node_name"] == "mapper"
        assert checkpoints2[0]["node_name"] == "hunter"

    def test_serialize_none_fields(self):
        """Test serializing state with None optional fields."""
        state = AgentState(
            session_id="test",
            target_path="/test",
            mode=ExecutionMode.HITL,
            attack_surface=None,
            environment=None,
            human_prompt=None,
        )

        json_str = StateSerializer.serialize_state(state)
        restored = StateSerializer.deserialize_state(json_str)

        assert restored.attack_surface is None
        assert restored.environment is None
        assert restored.human_prompt is None
