"""Unit tests for the EnvBuilder agent."""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from mrzero.agents.builder.agent import EnvBuilderAgent
from mrzero.agents.base import AgentType
from mrzero.core.memory.state import AgentState
from mrzero.core.schemas import (
    ExecutionMode,
    Vulnerability,
    VulnerabilityStatus,
    VulnerabilityType,
    VulnerabilitySeverity,
)


@pytest.fixture
def builder():
    """Create an EnvBuilder agent instance."""
    return EnvBuilderAgent()


@pytest.fixture
def sample_vulnerability():
    """Create a sample vulnerability for testing."""
    return Vulnerability(
        id="VULN-001",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=VulnerabilitySeverity.HIGH,
        score=85,
        status=VulnerabilityStatus.CONFIRMED,
        title="SQL Injection in login handler",
        description="Unsanitized user input in SQL query",
        file_path="app/routes/auth.py",
        line_number=42,
        code_snippet="query = f\"SELECT * FROM users WHERE username='{username}'\"",
        tool_source="hunter",
        confidence=0.9,
    )


@pytest.fixture
def sample_state_with_vulns(tmp_path, sample_vulnerability):
    """Create a sample state with confirmed vulnerabilities."""
    target_dir = tmp_path / "target_project"
    target_dir.mkdir()

    # Create some files
    (target_dir / "app").mkdir()
    (target_dir / "app" / "routes").mkdir()
    (target_dir / "app" / "routes" / "auth.py").write_text("""
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}'"
    return execute_query(query)
""")

    (target_dir / "Dockerfile").write_text("""
FROM python:3.12-slim
WORKDIR /app
COPY . .
CMD ["python", "app.py"]
""")

    (target_dir / "requirements.txt").write_text("flask\nsqlalchemy\n")

    return AgentState(
        session_id="test-session",
        target_path=str(target_dir),
        mode=ExecutionMode.HITL,
        confirmed_vulnerabilities=[sample_vulnerability],
    )


class TestEnvBuilderAgent:
    """Tests for the EnvBuilder agent."""

    def test_agent_type(self, builder):
        """Test agent type is correct."""
        assert builder.agent_type == AgentType.ENV_BUILDER

    def test_system_prompt(self, builder):
        """Test system prompt contains key concepts."""
        prompt = builder.get_system_prompt()
        assert "MrZeroEnvBuilder" in prompt
        assert "environment" in prompt.lower()
        assert "build" in prompt.lower()

    def test_system_prompt_mentions_strategies(self, builder):
        """Test system prompt mentions build strategies."""
        prompt = builder.get_system_prompt()
        prompt_lower = prompt.lower()
        assert "docker" in prompt_lower
        assert "harness" in prompt_lower
        assert "minimal" in prompt_lower

    def test_system_prompt_mentions_vulnerability_context(self, builder):
        """Test system prompt mentions understanding vulnerabilities."""
        prompt = builder.get_system_prompt()
        prompt_lower = prompt.lower()
        assert "vulnerable" in prompt_lower
        assert "code path" in prompt_lower

    def test_max_build_attempts(self, builder):
        """Test MAX_BUILD_ATTEMPTS is set correctly."""
        assert builder.MAX_BUILD_ATTEMPTS == 5

    def test_env_manager_property(self, builder):
        """Test env_manager property initializes lazily."""
        assert builder._env_manager is None
        manager = builder.env_manager
        assert manager is not None
        # Should return same instance
        assert builder.env_manager is manager


class TestEnvBuilderExecution:
    """Tests for EnvBuilder execution."""

    @pytest.mark.asyncio
    async def test_execute_nonexistent_path(self, builder, sample_vulnerability):
        """Test execution with non-existent path fails gracefully."""
        state = AgentState(
            session_id="test-session",
            target_path="/nonexistent/path",
            mode=ExecutionMode.HITL,
            confirmed_vulnerabilities=[sample_vulnerability],
        )

        result = await builder.execute(state)

        assert result.success is False
        assert len(result.errors) > 0
        assert "not exist" in result.errors[0].lower()

    @pytest.mark.asyncio
    async def test_execute_no_vulnerabilities(self, builder, tmp_path):
        """Test execution fails without vulnerabilities."""
        target_dir = tmp_path / "empty_project"
        target_dir.mkdir()

        state = AgentState(
            session_id="test-session",
            target_path=str(target_dir),
            mode=ExecutionMode.HITL,
            confirmed_vulnerabilities=[],
        )

        result = await builder.execute(state)

        assert result.success is False
        assert len(result.errors) > 0
        assert "No confirmed vulnerabilities" in result.errors[0]

    @pytest.mark.asyncio
    async def test_execute_returns_environment_info(self, builder, sample_state_with_vulns):
        """Test execution returns environment info."""
        # Mock LLM to return a harness strategy
        mock_strategy = {
            "strategy": {
                "type": "harness",
                "reasoning": "Test strategy",
                "build_steps": [],
            },
            "harness_code": {
                "needed": True,
                "language": "python",
                "files": [
                    {
                        "filename": "harness.py",
                        "content": "print('test harness')",
                        "description": "Test harness",
                    }
                ],
            },
        }

        with patch.object(builder, "_plan_build_strategy_with_llm", return_value=mock_strategy):
            with patch.object(builder.env_manager, "run_harness") as mock_run:
                mock_run.return_value = MagicMock(
                    success=True,
                    output="Harness executed",
                )

                result = await builder.execute(sample_state_with_vulns)

        assert "environment" in result.output
        env = result.output["environment"]
        assert env.build_attempts >= 1


class TestBuildConfigGathering:
    """Tests for build configuration gathering."""

    def test_gather_build_config_dockerfile(self, builder, tmp_path):
        """Test gathering config detects Dockerfile."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "Dockerfile").write_text("FROM python:3.12")

        config = builder._gather_build_config(project)

        assert "docker" in config["build_systems"]
        assert any(f["build_system"] == "docker" for f in config["detected_files"])

    def test_gather_build_config_python(self, builder, tmp_path):
        """Test gathering config detects Python project."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "requirements.txt").write_text("flask")
        (project / "app.py").write_text("print('hello')")

        config = builder._gather_build_config(project)

        assert "python" in config["languages"]
        assert "python-pip" in config["build_systems"]

    def test_gather_build_config_javascript(self, builder, tmp_path):
        """Test gathering config detects JavaScript project."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text('{"name": "test"}')
        (project / "index.js").write_text("console.log('hello');")

        config = builder._gather_build_config(project)

        assert "javascript" in config["languages"]
        assert "npm" in config["build_systems"]

    def test_gather_build_config_go(self, builder, tmp_path):
        """Test gathering config detects Go project."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "go.mod").write_text("module test")
        (project / "main.go").write_text("package main")

        config = builder._gather_build_config(project)

        assert "go" in config["languages"]
        assert "go" in config["build_systems"]

    def test_gather_build_config_checks_tool_availability(self, builder, tmp_path):
        """Test config includes tool availability info."""
        project = tmp_path / "project"
        project.mkdir()

        config = builder._gather_build_config(project)

        assert "available_tools" in config
        assert "docker" in config["available_tools"]
        assert "make" in config["available_tools"]
        assert "python3" in config["available_tools"]


class TestProjectStructure:
    """Tests for project structure gathering."""

    def test_gather_project_structure(self, builder, tmp_path):
        """Test project structure gathering."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "src").mkdir()
        (project / "src" / "main.py").write_text("print('hello')")
        (project / "tests").mkdir()
        (project / "tests" / "test_main.py").write_text("pass")

        structure = builder._gather_project_structure(project)

        assert "src/" in structure
        assert "main.py" in structure
        assert "tests/" in structure

    def test_gather_project_structure_limits_files(self, builder, tmp_path):
        """Test structure gathering limits number of files."""
        project = tmp_path / "project"
        project.mkdir()

        # Create many files
        for i in range(200):
            (project / f"file_{i}.py").write_text("pass")

        structure = builder._gather_project_structure(project, max_files=50)

        # Should be truncated
        assert "truncated" in structure.lower() or structure.count("file_") <= 50


class TestBuildFileReading:
    """Tests for build file reading."""

    def test_read_build_files(self, builder, tmp_path):
        """Test reading build files content."""
        project = tmp_path / "project"
        project.mkdir()

        dockerfile_content = "FROM python:3.12\nCOPY . ."
        (project / "Dockerfile").write_text(dockerfile_content)

        config = builder._gather_build_config(project)
        content = builder._read_build_files(project, config)

        assert "Dockerfile" in content
        assert "FROM python:3.12" in content

    def test_read_build_files_skips_large_files(self, builder, tmp_path):
        """Test reading skips files larger than 50KB."""
        project = tmp_path / "project"
        project.mkdir()

        # Create a file larger than 50KB
        large_content = "x" * 60000
        (project / "Dockerfile").write_text(large_content)

        config = builder._gather_build_config(project)
        content = builder._read_build_files(project, config)

        # Should not contain the large file content
        assert len(content) < 60000


class TestVulnerabilityFormatting:
    """Tests for vulnerability formatting."""

    def test_format_vulnerabilities(self, builder, sample_vulnerability):
        """Test vulnerability formatting for LLM."""
        formatted = builder._format_vulnerabilities([sample_vulnerability])

        assert "SQL Injection" in formatted
        assert "HIGH" in formatted.upper()
        assert "app/routes/auth.py" in formatted
        assert "42" in formatted

    def test_format_vulnerabilities_limits_count(self, builder):
        """Test formatting limits to 5 vulnerabilities."""
        vulns = [
            Vulnerability(
                id=f"VULN-{i}",
                vuln_type=VulnerabilityType.SQL_INJECTION,
                severity=VulnerabilitySeverity.HIGH,
                score=80,
                status=VulnerabilityStatus.CONFIRMED,
                title=f"Vuln {i}",
                description="Test",
                file_path=f"file{i}.py",
                line_number=i,
                tool_source="test",
                confidence=0.8,
            )
            for i in range(10)
        ]

        formatted = builder._format_vulnerabilities(vulns)

        # Should only format first 5
        assert "VULN-0" in formatted
        assert "VULN-4" in formatted
        # VULN-5 and beyond should not be in formatted output


class TestHarnessCreation:
    """Tests for harness file creation."""

    @pytest.mark.asyncio
    async def test_create_harness_files(self, builder, tmp_path, sample_vulnerability):
        """Test harness file creation."""
        project = tmp_path / "project"
        project.mkdir()

        # Create the vulnerable file
        (project / "app").mkdir(parents=True)
        (project / "app" / "routes").mkdir(parents=True)
        (project / "app" / "routes" / "auth.py").write_text("def login(): pass")

        harness_code = {
            "needed": True,
            "language": "python",
            "files": [
                {
                    "filename": "harness.py",
                    "content": "print('test harness')",
                    "description": "Test harness",
                },
                {
                    "filename": "requirements.txt",
                    "content": "flask",
                    "description": "Dependencies",
                },
            ],
        }

        result = await builder._create_harness_files(project, harness_code, [sample_vulnerability])

        assert result["success"] is True
        assert "harness_dir" in result

        harness_dir = Path(result["harness_dir"])
        assert harness_dir.exists()
        assert (harness_dir / "harness.py").exists()
        assert (harness_dir / "requirements.txt").exists()

    def test_create_harness_fallback_strategy(self, builder, sample_vulnerability):
        """Test fallback harness strategy creation."""
        strategy = builder._create_harness_fallback_strategy([sample_vulnerability])

        assert strategy["strategy"]["type"] == "harness"
        assert strategy["harness_code"]["needed"] is True
        assert strategy["harness_code"]["language"] == "python"
        assert len(strategy["harness_code"]["files"]) > 0


class TestLLMJsonParsing:
    """Tests for LLM JSON response parsing."""

    def test_parse_json_code_block(self, builder):
        """Test parsing JSON from code block."""
        response = """
Here is my analysis:
```json
{
    "strategy": {"type": "docker"},
    "result": "success"
}
```
"""
        result = builder._parse_llm_json_response(response)

        assert result is not None
        assert result["strategy"]["type"] == "docker"

    def test_parse_raw_json(self, builder):
        """Test parsing raw JSON without code block."""
        response = '{"strategy": {"type": "harness"}, "result": "ok"}'
        result = builder._parse_llm_json_response(response)

        assert result is not None
        assert result["strategy"]["type"] == "harness"

    def test_parse_invalid_json(self, builder):
        """Test parsing invalid JSON returns None."""
        response = "This is not valid JSON at all"
        result = builder._parse_llm_json_response(response)

        assert result is None

    def test_parse_malformed_json(self, builder):
        """Test parsing malformed JSON returns None."""
        response = '{"strategy": {"type": "docker"'  # Missing closing braces
        result = builder._parse_llm_json_response(response)

        assert result is None


class TestCommandExecution:
    """Tests for command execution."""

    @pytest.mark.asyncio
    async def test_run_command_success(self, builder, tmp_path):
        """Test successful command execution."""
        result = await builder._run_command("echo 'hello'", tmp_path)

        assert result["success"] is True
        assert "hello" in result["output"]

    @pytest.mark.asyncio
    async def test_run_command_failure(self, builder, tmp_path):
        """Test failed command execution."""
        result = await builder._run_command("nonexistent_command", tmp_path)

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_run_command_timeout(self, builder, tmp_path):
        """Test command timeout."""
        result = await builder._run_command("sleep 10", tmp_path, timeout=1)

        assert result["success"] is False
        assert "timed out" in result["error"].lower()


class TestStrategyExecution:
    """Tests for build strategy execution."""

    @pytest.mark.asyncio
    async def test_execute_harness_strategy(self, builder, tmp_path, sample_vulnerability):
        """Test harness strategy execution."""
        project = tmp_path / "project"
        project.mkdir()

        # Create vulnerable file
        (project / "app").mkdir(parents=True)
        (project / "app" / "routes").mkdir(parents=True)
        (project / "app" / "routes" / "auth.py").write_text("def login(): pass")

        strategy = {
            "strategy": {
                "type": "harness",
                "build_steps": [],
            },
            "harness_code": {
                "needed": True,
                "language": "python",
                "files": [
                    {
                        "filename": "harness.py",
                        "content": "print('test')",
                        "description": "Test",
                    }
                ],
            },
        }

        with patch.object(builder.env_manager, "run_harness") as mock_run:
            mock_run.return_value = MagicMock(
                success=True,
                output="Test output",
            )

            success, result = await builder._execute_build_strategy(
                project, strategy, [sample_vulnerability]
            )

        assert success is True
        assert "harness_dir" in result

    @pytest.mark.asyncio
    async def test_execute_docker_strategy_no_docker(self, builder, tmp_path, sample_vulnerability):
        """Test Docker strategy fails without Docker."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "Dockerfile").write_text("FROM python:3.12")

        strategy = {
            "strategy": {
                "type": "docker",
                "build_steps": [],
            },
            "harness_code": {},
        }

        with patch.object(builder.env_manager, "docker_available", return_value=False):
            success, result = await builder._execute_build_strategy(
                project, strategy, [sample_vulnerability]
            )

        assert success is False
        assert "not available" in result["error"].lower()
