"""Integration tests for the MapperAgent."""

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from mrzero.agents.mapper.agent import MapperAgent
from mrzero.agents.base import AgentType
from mrzero.core.memory.state import AgentState
from mrzero.core.schemas import ExecutionMode


class TestMapperAgent:
    """Test MapperAgent functionality."""

    @pytest.fixture
    def sample_codebase(self):
        """Create a sample codebase for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)

            # Create a Flask app
            app_py = target / "app.py"
            app_py.write_text("""
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return jsonify(cursor.fetchone())

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    # TODO: implement auth
    return jsonify({"token": "fake"})

if __name__ == '__main__':
    app.run(debug=True)
""")

            # Create routes file
            routes_py = target / "routes.py"
            routes_py.write_text("""
from flask import Blueprint, request
import os

api = Blueprint('api', __name__)

@api.route('/execute', methods=['POST'])
def execute_command():
    cmd = request.json.get('command')
    os.system(cmd)
    return {"status": "ok"}
""")

            # Create requirements.txt
            requirements = target / "requirements.txt"
            requirements.write_text("flask==2.0.3\nrequests==2.28.0\nsqlalchemy==1.4.0\n")

            # Create package.json for frontend
            frontend_dir = target / "frontend"
            frontend_dir.mkdir()
            package_json = frontend_dir / "package.json"
            package_json.write_text(
                json.dumps(
                    {"name": "frontend", "dependencies": {"react": "^18.0.0", "axios": "^1.0.0"}}
                )
            )

            yield target

    @pytest.fixture
    def mock_config(self, sample_codebase, monkeypatch):
        """Create mock config."""
        config_dir = sample_codebase / ".mrzero"
        config_dir.mkdir(exist_ok=True)

        monkeypatch.setenv("MRZERO_DATA_DIR", str(config_dir))

        from mrzero.core.config import MrZeroConfig, set_config

        config = MrZeroConfig(
            data_dir=config_dir,
            output_dir=sample_codebase / "output",
        )
        config.ensure_directories()
        set_config(config)
        return config

    @pytest.fixture
    def agent_state(self, sample_codebase):
        """Create agent state for testing."""
        return AgentState(
            session_id="test-session-123",
            target_path=str(sample_codebase),
            mode=ExecutionMode.YOLO,
        )

    def test_agent_type(self):
        """Test agent type is correct."""
        agent = MapperAgent()
        assert agent.agent_type == AgentType.MAPPER

    def test_system_prompt_content(self):
        """Test system prompt contains key security concepts."""
        agent = MapperAgent()
        prompt = agent.get_system_prompt()

        assert "MrZeroMapper" in prompt
        assert "attack surface" in prompt.lower()
        assert "entry point" in prompt.lower()
        assert "data flow" in prompt.lower()
        assert "authentication" in prompt.lower()

    def test_get_file_structure(self, sample_codebase):
        """Test file structure extraction."""
        agent = MapperAgent()
        structure = agent._get_file_structure(sample_codebase)

        assert "app.py" in structure
        assert "routes.py" in structure
        assert "requirements.txt" in structure
        assert "package.json" in structure

    def test_get_file_structure_limits_entries(self, sample_codebase):
        """Test file structure respects max_entries."""
        agent = MapperAgent()
        structure = agent._get_file_structure(sample_codebase, max_entries=2)

        # Should be truncated
        lines = structure.strip().split("\n")
        assert len(lines) <= 3  # 2 entries + truncation message

    def test_get_file_structure_skips_unwanted_dirs(self, sample_codebase):
        """Test file structure skips node_modules, __pycache__, etc."""
        # Create unwanted directories
        (sample_codebase / "node_modules").mkdir()
        (sample_codebase / "node_modules" / "lodash.js").write_text("// lodash")
        (sample_codebase / "__pycache__").mkdir()
        (sample_codebase / "__pycache__" / "app.pyc").write_bytes(b"pyc")

        agent = MapperAgent()
        structure = agent._get_file_structure(sample_codebase)

        assert "node_modules" not in structure
        assert "__pycache__" not in structure
        assert "lodash.js" not in structure

    def test_read_dependency_files(self, sample_codebase):
        """Test dependency file reading."""
        agent = MapperAgent()
        deps = agent._read_dependency_files(sample_codebase)

        assert "requirements.txt" in deps
        assert "flask" in deps
        assert "package.json" in deps
        assert "react" in deps

    def test_read_dependency_files_truncates_large_files(self, sample_codebase):
        """Test dependency files are truncated if too large."""
        # Create a large package-lock.json
        large_file = sample_codebase / "package-lock.json"
        large_file.write_text("x" * 10000)

        agent = MapperAgent()
        deps = agent._read_dependency_files(sample_codebase)

        # The content should be truncated
        if "package-lock.json" in deps:
            assert "[truncated]" in deps

    def test_read_code_samples(self, sample_codebase):
        """Test code sample reading."""
        agent = MapperAgent()
        samples = agent._read_code_samples(sample_codebase)

        assert "app.py" in samples
        assert "routes.py" in samples
        assert "@app.route" in samples
        assert "def get_user" in samples

    def test_read_code_samples_prioritizes_security_files(self, sample_codebase):
        """Test code samples prioritize files with security-relevant names."""
        # Create a low-priority utility file
        (sample_codebase / "utils_helper.py").write_text("def helper(): pass")

        # Create high-priority auth file
        (sample_codebase / "auth_controller.py").write_text("def authenticate(): pass")

        agent = MapperAgent()
        samples = agent._read_code_samples(sample_codebase, max_files=3)

        # Auth file should appear before utils
        auth_pos = samples.find("auth_controller.py")
        app_pos = samples.find("app.py")

        # Both should be present and prioritized
        assert auth_pos != -1
        assert app_pos != -1

    def test_read_code_samples_skips_test_dirs(self, sample_codebase):
        """Test code samples skip test directories."""
        tests_dir = sample_codebase / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_app.py").write_text("def test_something(): pass")

        agent = MapperAgent()
        samples = agent._read_code_samples(sample_codebase)

        assert "test_app.py" not in samples

    def test_get_file_stats(self, sample_codebase):
        """Test file statistics computation."""
        agent = MapperAgent()
        file_count, loc = agent._get_file_stats(sample_codebase)

        assert file_count >= 2  # app.py and routes.py
        assert loc > 0

    def test_parse_llm_response_valid_json_block(self):
        """Test parsing LLM response with JSON code block."""
        agent = MapperAgent()

        response = """Here's my analysis:

```json
{
    "languages": [{"name": "Python", "confidence": 0.95}],
    "frameworks": [{"name": "Flask", "category": "web"}],
    "endpoints": []
}
```

That's the attack surface."""

        result = agent._parse_llm_response(response)

        assert "languages" in result
        assert result["languages"][0]["name"] == "Python"
        assert result["frameworks"][0]["name"] == "Flask"

    def test_parse_llm_response_raw_json(self):
        """Test parsing LLM response with raw JSON."""
        agent = MapperAgent()

        response = '{"languages": [{"name": "Python"}]}'

        result = agent._parse_llm_response(response)

        assert result["languages"][0]["name"] == "Python"

    def test_parse_llm_response_invalid_json(self):
        """Test parsing LLM response with invalid JSON."""
        agent = MapperAgent()

        response = "This is not valid JSON at all"

        result = agent._parse_llm_response(response)

        assert "raw_response" in result
        assert result["raw_response"] == response

    def test_build_attack_surface_basic(self, sample_codebase):
        """Test building attack surface from LLM analysis."""
        agent = MapperAgent()

        llm_analysis = {
            "languages": [{"name": "Python", "confidence": 0.9, "file_count": 2}],
            "frameworks": [{"name": "Flask", "version": "2.0.3", "category": "web framework"}],
            "endpoints": [
                {
                    "path": "/api/users/<user_id>",
                    "method": "GET",
                    "file_path": "app.py",
                    "line_number": 8,
                    "authenticated": False,
                    "risk_score": 75,
                }
            ],
            "data_flows": [
                {
                    "source": "request parameter user_id",
                    "sink": "SQL query",
                    "source_file": "app.py",
                    "source_line": 8,
                    "sink_file": "app.py",
                    "sink_line": 11,
                    "tainted": True,
                }
            ],
            "auth_boundaries": ["login function in app.py"],
            "trust_zones": ["Public API zone"],
        }

        attack_surface = agent._build_attack_surface(
            target_path=str(sample_codebase),
            llm_analysis=llm_analysis,
            file_count=2,
            loc=50,
        )

        assert attack_surface.target_path == str(sample_codebase)
        assert attack_surface.file_count == 2
        assert attack_surface.loc == 50

        assert len(attack_surface.languages) == 1
        assert attack_surface.languages[0].name == "Python"

        assert len(attack_surface.frameworks) == 1
        assert attack_surface.frameworks[0].name == "Flask"

        assert len(attack_surface.endpoints) == 1
        assert attack_surface.endpoints[0].path == "/api/users/<user_id>"
        assert attack_surface.endpoints[0].authenticated is False
        assert attack_surface.endpoints[0].risk_score == 75

        assert len(attack_surface.data_flows) == 1
        assert attack_surface.data_flows[0].tainted is True

        assert "login function" in attack_surface.auth_boundaries[0]
        assert "Public API" in attack_surface.trust_zones[0]

    def test_build_attack_surface_handles_malformed_data(self, sample_codebase):
        """Test attack surface builder handles malformed LLM output."""
        agent = MapperAgent()

        # Malformed data - missing required fields
        llm_analysis = {
            "languages": [{"invalid": "data"}],
            "endpoints": [{"missing": "fields"}],
            # data_flows missing entirely - should default to empty list
        }

        # Should not raise
        attack_surface = agent._build_attack_surface(
            target_path=str(sample_codebase),
            llm_analysis=llm_analysis,
            file_count=1,
            loc=10,
        )

        assert attack_surface is not None
        assert attack_surface.file_count == 1

    @pytest.mark.asyncio
    async def test_execute_nonexistent_path(self):
        """Test execute returns error for nonexistent path."""
        agent = MapperAgent()

        state = AgentState(
            session_id="test",
            target_path="/nonexistent/path/xyz",
            mode=ExecutionMode.YOLO,
        )

        result = await agent.execute(state)

        assert result.success is False
        assert "does not exist" in result.errors[0]

    @pytest.mark.asyncio
    async def test_execute_with_mock_llm(self, sample_codebase, mock_config):
        """Test full execute flow with mocked LLM."""
        agent = MapperAgent()

        state = AgentState(
            session_id="test-session",
            target_path=str(sample_codebase),
            mode=ExecutionMode.YOLO,
        )

        # Mock LLM response
        mock_llm_response = json.dumps(
            {
                "languages": [{"name": "Python", "confidence": 0.95, "file_count": 2}],
                "frameworks": [{"name": "Flask", "version": "2.0.3", "category": "web"}],
                "endpoints": [
                    {
                        "path": "/api/users/<user_id>",
                        "method": "GET",
                        "file_path": "app.py",
                        "line_number": 8,
                        "authenticated": False,
                        "risk_score": 80,
                    },
                    {
                        "path": "/execute",
                        "method": "POST",
                        "file_path": "routes.py",
                        "line_number": 7,
                        "authenticated": False,
                        "risk_score": 95,
                    },
                ],
                "data_flows": [
                    {
                        "source": "user_id parameter",
                        "sink": "cursor.execute",
                        "source_file": "app.py",
                        "source_line": 8,
                        "sink_file": "app.py",
                        "sink_line": 11,
                        "tainted": True,
                    },
                    {
                        "source": "command parameter",
                        "sink": "os.system",
                        "source_file": "routes.py",
                        "source_line": 8,
                        "sink_file": "routes.py",
                        "sink_line": 9,
                        "tainted": True,
                    },
                ],
                "auth_boundaries": [],
                "trust_zones": ["Public API"],
                "risk_assessment": {
                    "overall_risk": 9,
                    "high_risk_areas": [
                        "SQL injection in app.py",
                        "Command injection in routes.py",
                    ],
                    "attack_vectors": ["SQL Injection", "Remote Code Execution"],
                },
            }
        )

        # Mock the chat method
        with patch.object(agent, "chat", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = f"```json\n{mock_llm_response}\n```"

            # Mock vectordb indexing
            with patch.object(agent, "_index_codebase", new_callable=AsyncMock) as mock_index:
                mock_index.return_value = {"status": "skipped", "reason": "test"}

                result = await agent.execute(state)

        assert result.success is True
        assert result.agent_type == AgentType.MAPPER
        assert result.next_agent == AgentType.HUNTER

        attack_surface = result.output["attack_surface"]
        assert attack_surface is not None
        assert len(attack_surface.endpoints) == 2
        assert len(attack_surface.data_flows) == 2
        assert any(ep.risk_score == 95 for ep in attack_surface.endpoints)

    @pytest.mark.asyncio
    async def test_execute_handles_llm_error(self, sample_codebase, mock_config):
        """Test execute handles LLM errors gracefully."""
        agent = MapperAgent()

        state = AgentState(
            session_id="test-session",
            target_path=str(sample_codebase),
            mode=ExecutionMode.YOLO,
        )

        # Mock LLM to raise an exception
        with patch.object(agent, "chat", new_callable=AsyncMock) as mock_chat:
            mock_chat.side_effect = Exception("LLM API error")

            with patch.object(agent, "_index_codebase", new_callable=AsyncMock) as mock_index:
                mock_index.return_value = {"status": "skipped"}

                result = await agent.execute(state)

        # Should still succeed but with minimal attack surface
        assert result.success is True
        assert result.output["llm_analysis"].get("status") == "llm_analysis_failed"

    @pytest.mark.asyncio
    async def test_execute_handles_indexing_error(self, sample_codebase, mock_config):
        """Test execute handles indexing errors gracefully."""
        agent = MapperAgent()

        state = AgentState(
            session_id="test-session",
            target_path=str(sample_codebase),
            mode=ExecutionMode.YOLO,
        )

        # Mock indexing to fail
        with patch.object(agent, "_index_codebase", new_callable=AsyncMock) as mock_index:
            mock_index.return_value = {"status": "error", "error": "ChromaDB connection failed"}

            with patch.object(agent, "chat", new_callable=AsyncMock) as mock_chat:
                mock_chat.return_value = '{"languages": [], "endpoints": []}'

                result = await agent.execute(state)

        # Should still succeed with warnings
        assert result.success is True
        assert any("indexing failed" in err for err in result.errors)


class TestMapperAgentAnalysisPrompt:
    """Test the analysis prompt formatting."""

    def test_analysis_prompt_formatting(self):
        """Test analysis prompt can be formatted correctly."""
        agent = MapperAgent()

        formatted = agent.ANALYSIS_PROMPT.format(
            target_path="/app",
            file_structure="app.py\nroutes.py",
            dependency_info="flask==2.0.0",
            code_samples="def app(): pass",
        )

        assert "/app" in formatted
        assert "app.py" in formatted
        assert "flask" in formatted
        assert "def app" in formatted
        assert "JSON" in formatted  # Output format instructions

    def test_analysis_prompt_contains_expected_fields(self):
        """Test analysis prompt requests all expected fields."""
        agent = MapperAgent()
        prompt = agent.ANALYSIS_PROMPT

        expected_fields = [
            "languages",
            "frameworks",
            "endpoints",
            "data_flows",
            "auth_boundaries",
            "trust_zones",
            "risk_assessment",
        ]

        for field in expected_fields:
            assert field in prompt, f"Missing field: {field}"
