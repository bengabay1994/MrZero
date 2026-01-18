"""Test configuration and fixtures for MrZero."""

import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_codebase(temp_dir):
    """Create a sample codebase with vulnerabilities for testing."""
    # Create a Python file with SQL injection
    vuln_py = temp_dir / "vulnerable.py"
    vuln_py.write_text("""
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

def run_command(cmd):
    import os
    # Command injection vulnerability
    os.system(f"echo {cmd}")
""")

    # Create a JavaScript file with XSS
    vuln_js = temp_dir / "vulnerable.js"
    vuln_js.write_text("""
function displayUser(name) {
    // XSS vulnerability
    document.getElementById("user").innerHTML = name;
}

function fetchData(url) {
    // SSRF vulnerability
    fetch(url).then(res => res.json());
}
""")

    # Create a requirements.txt
    requirements = temp_dir / "requirements.txt"
    requirements.write_text("flask==2.0.0\nrequests==2.26.0\n")

    return temp_dir


@pytest.fixture
def mock_config(temp_dir, monkeypatch):
    """Create a mock configuration for tests."""
    config_dir = temp_dir / ".mrzero"
    config_dir.mkdir()

    monkeypatch.setenv("MRZERO_DATA_DIR", str(config_dir))

    from mrzero.core.config import MrZeroConfig, set_config

    config = MrZeroConfig(
        data_dir=config_dir,
        output_dir=temp_dir / "output",
    )
    config.ensure_directories()
    set_config(config)

    return config


@pytest.fixture
def mock_llm_response():
    """Mock LLM response for testing agents."""

    class MockResponse:
        content = "This is a mock LLM response."
        model = "mock-model"
        usage = {"input_tokens": 10, "output_tokens": 20}
        finish_reason = "stop"

    return MockResponse()
