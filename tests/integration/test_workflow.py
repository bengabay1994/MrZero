"""Integration tests for workflow orchestration."""

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from mrzero.core.orchestration.graph import MrZeroWorkflow, run_scan
from mrzero.core.memory.state import AgentState, HunterVerifierState
from mrzero.core.schemas import (
    ExecutionMode,
    AttackSurfaceMap,
    Vulnerability,
    VulnerabilityType,
    VulnerabilitySeverity,
    VulnerabilityStatus,
    Endpoint,
    DataFlow,
    Technology,
    EnvironmentInfo,
)
from mrzero.agents.base import AgentResult, AgentType


class TestMrZeroWorkflow:
    """Test MrZeroWorkflow class."""

    @pytest.fixture
    def temp_target(self):
        """Create a temporary target directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)

            # Create a simple vulnerable app
            (target / "app.py").write_text("""
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("db.sqlite")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query).fetchone()
""")
            yield target

    @pytest.fixture
    def mock_config(self, temp_target, monkeypatch):
        """Create mock config."""
        config_dir = temp_target / ".mrzero"
        config_dir.mkdir(exist_ok=True)

        monkeypatch.setenv("MRZERO_DATA_DIR", str(config_dir))

        from mrzero.core.config import MrZeroConfig, set_config

        config = MrZeroConfig(
            data_dir=config_dir,
            output_dir=temp_target / "output",
        )
        config.ensure_directories()
        set_config(config)
        return config

    def test_workflow_initialization(self, mock_config):
        """Test workflow initializes correctly."""
        workflow = MrZeroWorkflow()

        assert workflow.config is not None
        assert workflow.session_manager is not None
        assert workflow._graph is None  # Lazy loaded

    def test_route_after_mapper_success(self, mock_config):
        """Test routing after successful mapper."""
        workflow = MrZeroWorkflow()

        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.YOLO,
            attack_surface=AttackSurfaceMap(
                target_path="/app",
                endpoints=[
                    Endpoint(
                        path="/api/users",
                        method="GET",
                        file_path="app.py",
                        line_number=5,
                    )
                ],
                data_flows=[],
            ),
        )

        decision = workflow._route_after_mapper(state)
        assert decision == "hunter"

    def test_route_after_mapper_no_attack_surface(self, mock_config):
        """Test routing when mapper fails to produce attack surface."""
        workflow = MrZeroWorkflow()

        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.YOLO,
            attack_surface=None,
        )

        decision = workflow._route_after_mapper(state)
        assert decision == "end"

    def test_route_after_mapper_no_entry_points(self, mock_config):
        """Test routing when no entry points found."""
        workflow = MrZeroWorkflow()

        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.YOLO,
            attack_surface=AttackSurfaceMap(
                target_path="/app",
                endpoints=[],  # No endpoints
                data_flows=[],  # No data flows
            ),
        )

        decision = workflow._route_after_mapper(state)
        assert decision == "end"

    def test_route_after_hunter_with_candidates(self, mock_config):
        """Test routing after hunter finds candidates."""
        workflow = MrZeroWorkflow()

        vuln = Vulnerability(
            id="test-vuln",
            vuln_type=VulnerabilityType.SQL_INJECTION,
            severity=VulnerabilitySeverity.HIGH,
            score=80,
            status=VulnerabilityStatus.CANDIDATE,
            title="SQL Injection",
            description="SQL injection vulnerability",
            file_path="app.py",
            line_number=5,
            tool_source="test",
            confidence=0.9,
        )

        hv_state = HunterVerifierState(candidates=[vuln])

        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.YOLO,
            hunter_verifier_state=hv_state,
        )

        decision = workflow._route_after_hunter(state)
        assert decision == "verifier"

    def test_route_after_hunter_no_candidates(self, mock_config):
        """Test routing when hunter finds no candidates."""
        workflow = MrZeroWorkflow()

        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.YOLO,
            hunter_verifier_state=HunterVerifierState(candidates=[]),
        )

        decision = workflow._route_after_hunter(state)
        assert decision == "end"

    def test_route_after_hunter_awaiting_human_input(self, mock_config):
        """Test routing to human input when requested."""
        workflow = MrZeroWorkflow()

        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.HITL,
            awaiting_human_input=True,
        )

        decision = workflow._route_after_hunter(state)
        assert decision == "human_input"

    def test_route_after_verifier_enough_confirmed(self, mock_config):
        """Test routing when enough vulnerabilities confirmed."""
        workflow = MrZeroWorkflow()

        confirmed_vulns = [
            Vulnerability(
                id=f"vuln-{i}",
                vuln_type=VulnerabilityType.SQL_INJECTION,
                severity=VulnerabilitySeverity.HIGH,
                score=80,
                status=VulnerabilityStatus.CONFIRMED,
                title=f"Vulnerability {i}",
                description=f"Vulnerability description {i}",
                file_path="app.py",
                line_number=i,
                tool_source="test",
                confidence=0.9,
            )
            for i in range(3)  # 3 confirmed, default min is 3
        ]

        hv_state = HunterVerifierState(
            confirmed=confirmed_vulns,
            min_true_positives=3,
        )

        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.YOLO,
            hunter_verifier_state=hv_state,
        )

        decision = workflow._route_after_verifier(state)
        assert decision == "env_builder"

    def test_route_after_verifier_max_iterations(self, mock_config):
        """Test routing when max iterations reached."""
        workflow = MrZeroWorkflow()

        # Some confirmed but not enough, max iterations reached
        confirmed = [
            Vulnerability(
                id="vuln-1",
                vuln_type=VulnerabilityType.SQL_INJECTION,
                severity=VulnerabilitySeverity.HIGH,
                score=80,
                status=VulnerabilityStatus.CONFIRMED,
                title="Vulnerability 1",
                description="Vulnerability description",
                file_path="app.py",
                line_number=1,
                tool_source="test",
                confidence=0.9,
            )
        ]

        hv_state = HunterVerifierState(
            confirmed=confirmed,
            iteration_count=5,
            max_iterations=5,
            min_true_positives=3,
        )

        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.YOLO,
            hunter_verifier_state=hv_state,
        )

        decision = workflow._route_after_verifier(state)
        # Has some confirmed, should go to env_builder
        assert decision == "env_builder"

    def test_route_after_verifier_max_iterations_no_vulns(self, mock_config):
        """Test routing when max iterations reached with no vulns."""
        workflow = MrZeroWorkflow()

        hv_state = HunterVerifierState(
            confirmed=[],
            iteration_count=5,
            max_iterations=5,
        )

        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.YOLO,
            hunter_verifier_state=hv_state,
        )

        decision = workflow._route_after_verifier(state)
        # No vulns, go directly to reporter
        assert decision == "reporter"

    def test_route_after_verifier_continue_loop(self, mock_config):
        """Test routing to continue hunter-verifier loop."""
        workflow = MrZeroWorkflow()

        # Not enough confirmed, not max iterations
        hv_state = HunterVerifierState(
            confirmed=[],
            iteration_count=1,
            max_iterations=5,
            min_true_positives=3,
        )

        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.YOLO,
            hunter_verifier_state=hv_state,
        )

        decision = workflow._route_after_verifier(state)
        assert decision == "hunter"

    def test_route_after_env_builder_success(self, mock_config):
        """Test routing after successful env build."""
        workflow = MrZeroWorkflow()

        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.YOLO,
            environment=EnvironmentInfo(
                env_type="docker",
                build_successful=True,
            ),
        )

        decision = workflow._route_after_env_builder(state)
        assert decision == "exploit_builder"

    def test_route_after_env_builder_failed(self, mock_config):
        """Test routing when env build fails."""
        workflow = MrZeroWorkflow()

        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.YOLO,
            environment=EnvironmentInfo(
                env_type="docker",
                build_successful=False,
            ),
        )

        decision = workflow._route_after_env_builder(state)
        assert decision == "reporter"

    def test_route_after_env_builder_no_env(self, mock_config):
        """Test routing when no environment produced."""
        workflow = MrZeroWorkflow()

        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.YOLO,
            environment=None,
        )

        decision = workflow._route_after_env_builder(state)
        assert decision == "reporter"

    def test_route_after_exploit_builder(self, mock_config):
        """Test routing after exploit builder."""
        workflow = MrZeroWorkflow()

        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.YOLO,
        )

        decision = workflow._route_after_exploit_builder(state)
        assert decision == "reporter"

    def test_route_after_human_input_quit(self, mock_config):
        """Test routing when user quits."""
        workflow = MrZeroWorkflow()

        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.HITL,
            human_response="quit",
        )

        decision = workflow._route_after_human_input(state)
        assert decision == "end"

    def test_route_after_human_input_skip(self, mock_config):
        """Test routing when user skips."""
        workflow = MrZeroWorkflow()

        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.HITL,
            human_response="skip",
            current_agent="hunter",
        )

        decision = workflow._route_after_human_input(state)
        assert decision == "env_builder"

    def test_route_after_human_input_continue(self, mock_config):
        """Test routing when user continues."""
        workflow = MrZeroWorkflow()

        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.HITL,
            human_response="continue with analysis",
            current_agent="verifier",
        )

        decision = workflow._route_after_human_input(state)
        assert decision == "verifier"


class TestWorkflowNodeExecution:
    """Test individual workflow node execution."""

    @pytest.fixture
    def temp_target(self):
        """Create a temporary target directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            (target / "app.py").write_text("print('hello')")
            yield target

    @pytest.fixture
    def mock_config(self, temp_target, monkeypatch):
        """Create mock config."""
        config_dir = temp_target / ".mrzero"
        config_dir.mkdir(exist_ok=True)

        monkeypatch.setenv("MRZERO_DATA_DIR", str(config_dir))

        from mrzero.core.config import MrZeroConfig, set_config

        config = MrZeroConfig(
            data_dir=config_dir,
            output_dir=temp_target / "output",
        )
        config.ensure_directories()
        set_config(config)
        return config

    @pytest.mark.asyncio
    async def test_run_mapper_node(self, temp_target, mock_config):
        """Test running the mapper node."""
        workflow = MrZeroWorkflow()
        workflow._build_graph()

        state = AgentState(
            session_id="test",
            target_path=str(temp_target),
            mode=ExecutionMode.YOLO,
        )

        # Mock the mapper's execute method
        mock_attack_surface = AttackSurfaceMap(
            target_path=str(temp_target),
            endpoints=[
                Endpoint(
                    path="/api/test",
                    method="GET",
                    file_path="app.py",
                    line_number=1,
                )
            ],
        )

        mock_result = AgentResult(
            agent_type=AgentType.MAPPER,
            success=True,
            output={"attack_surface": mock_attack_surface},
        )

        with patch.object(workflow.mapper, "execute", new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = mock_result

            updates = await workflow._run_mapper(state)

        assert updates["current_agent"] == "mapper"
        assert updates["attack_surface"] is not None

    @pytest.mark.asyncio
    async def test_run_hunter_node(self, temp_target, mock_config):
        """Test running the hunter node."""
        workflow = MrZeroWorkflow()
        workflow._build_graph()

        state = AgentState(
            session_id="test",
            target_path=str(temp_target),
            mode=ExecutionMode.YOLO,
        )

        mock_candidates = [
            Vulnerability(
                id="vuln-test",
                vuln_type=VulnerabilityType.SQL_INJECTION,
                severity=VulnerabilitySeverity.HIGH,
                score=85,
                status=VulnerabilityStatus.CANDIDATE,
                title="SQL Injection",
                description="SQL injection vulnerability",
                file_path="app.py",
                line_number=5,
                tool_source="test",
                confidence=0.9,
            )
        ]

        mock_result = AgentResult(
            agent_type=AgentType.HUNTER,
            success=True,
            output={"candidates": mock_candidates},
        )

        with patch.object(workflow.hunter, "execute", new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = mock_result

            updates = await workflow._run_hunter(state)

        assert updates["current_agent"] == "hunter"
        assert len(updates["hunter_verifier_state"].candidates) == 1

    @pytest.mark.asyncio
    async def test_run_verifier_node(self, temp_target, mock_config):
        """Test running the verifier node."""
        workflow = MrZeroWorkflow()
        workflow._build_graph()

        state = AgentState(
            session_id="test",
            target_path=str(temp_target),
            mode=ExecutionMode.YOLO,
        )

        confirmed_vulns = [
            Vulnerability(
                id="confirmed-vuln",
                vuln_type=VulnerabilityType.SQL_INJECTION,
                severity=VulnerabilitySeverity.HIGH,
                score=90,
                status=VulnerabilityStatus.CONFIRMED,
                title="Confirmed SQL Injection",
                description="Confirmed SQL injection vulnerability",
                file_path="app.py",
                line_number=10,
                tool_source="test",
                confidence=0.95,
            )
        ]

        mock_result = AgentResult(
            agent_type=AgentType.VERIFIER,
            success=True,
            output={
                "confirmed": confirmed_vulns,
                "false_positives": [],
                "feedback": [],
            },
        )

        with patch.object(workflow.verifier, "execute", new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = mock_result

            updates = await workflow._run_verifier(state)

        assert updates["current_agent"] == "verifier"
        assert len(updates["hunter_verifier_state"].confirmed) == 1
        assert len(updates["confirmed_vulnerabilities"]) == 1


class TestWorkflowSessionManagement:
    """Test workflow session management."""

    @pytest.fixture
    def temp_target(self):
        """Create a temporary target directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            (target / "app.py").write_text("print('hello')")
            yield target

    @pytest.fixture
    def mock_config(self, temp_target, monkeypatch):
        """Create mock config."""
        config_dir = temp_target / ".mrzero"
        config_dir.mkdir(exist_ok=True)

        monkeypatch.setenv("MRZERO_DATA_DIR", str(config_dir))

        from mrzero.core.config import MrZeroConfig, set_config

        config = MrZeroConfig(
            data_dir=config_dir,
            output_dir=temp_target / "output",
        )
        config.ensure_directories()
        set_config(config)
        return config

    def test_session_created_on_run(self, temp_target, mock_config):
        """Test session is created when workflow starts."""
        workflow = MrZeroWorkflow()

        # Just test session creation without running full workflow
        from mrzero.core.memory.sqlite import SessionManager

        session_id = "manual-session-test"
        workflow.session_manager.create_session(
            session_id=session_id,
            target_path=str(temp_target),
            mode=ExecutionMode.YOLO,
        )

        session = workflow.session_manager.get_session(session_id)
        assert session is not None
        assert session.target_path == str(temp_target)

    def test_session_status_updates(self, temp_target, mock_config):
        """Test session status is updated during workflow."""
        workflow = MrZeroWorkflow()

        session_id = "status-test"
        workflow.session_manager.create_session(
            session_id=session_id,
            target_path=str(temp_target),
            mode=ExecutionMode.YOLO,
        )

        # Update to running
        workflow.session_manager.update_session(session_id, status="running")
        session = workflow.session_manager.get_session(session_id)
        assert session.status == "running"

        # Update to completed
        workflow.session_manager.update_session(session_id, status="completed")
        session = workflow.session_manager.get_session(session_id)
        assert session.status == "completed"
        assert session.completed_at is not None


class TestAgentStateTransitions:
    """Test AgentState transitions through workflow."""

    def test_initial_state(self):
        """Test initial state has correct defaults."""
        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.YOLO,
        )

        assert state.current_agent == "mapper"  # Default is "mapper"
        assert state.attack_surface is None
        assert state.confirmed_vulnerabilities == []
        assert state.exploits == []
        assert state.errors == []
        assert state.awaiting_human_input is False
        assert state.workflow_status == "pending"

    def test_hunter_verifier_state_defaults(self):
        """Test HunterVerifierState has correct defaults."""
        hv_state = HunterVerifierState()

        assert hv_state.candidates == []
        assert hv_state.confirmed == []
        assert hv_state.false_positives == []
        assert hv_state.feedback == []
        assert hv_state.iteration_count == 0
        assert hv_state.max_iterations == 3
        assert hv_state.min_true_positives == 3

    def test_state_with_attack_surface(self):
        """Test state with attack surface."""
        attack_surface = AttackSurfaceMap(
            target_path="/app",
            languages=[Technology(name="Python", category="language")],
            frameworks=[Technology(name="Flask", category="web")],
            endpoints=[
                Endpoint(path="/api/users", method="GET", file_path="app.py", line_number=10)
            ],
            data_flows=[
                DataFlow(
                    source="request.args",
                    sink="cursor.execute",
                    source_file="app.py",
                    source_line=10,
                    sink_file="app.py",
                    sink_line=15,
                    tainted=True,
                )
            ],
        )

        state = AgentState(
            session_id="test",
            target_path="/app",
            mode=ExecutionMode.YOLO,
            attack_surface=attack_surface,
        )

        assert len(state.attack_surface.endpoints) == 1
        assert len(state.attack_surface.data_flows) == 1
        assert state.attack_surface.data_flows[0].tainted is True
