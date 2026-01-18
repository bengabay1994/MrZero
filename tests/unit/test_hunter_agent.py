"""Unit tests for the Hunter agent."""

import pytest
from pathlib import Path

from mrzero.agents.hunter.agent import HunterAgent
from mrzero.agents.base import AgentType
from mrzero.core.memory.state import AgentState
from mrzero.core.schemas import ExecutionMode


class TestHunterAgent:
    """Tests for the Hunter vulnerability detection agent."""

    @pytest.fixture
    def hunter(self):
        """Create a Hunter agent instance."""
        return HunterAgent()

    def test_agent_type(self, hunter):
        """Test agent type is correct."""
        assert hunter.agent_type == AgentType.HUNTER

    def test_system_prompt(self, hunter):
        """Test system prompt contains key concepts."""
        prompt = hunter.get_system_prompt()
        assert "MrZeroVulnHunter" in prompt
        assert "vulnerability" in prompt.lower()
        # The new LLM-first approach should mention static analysis
        assert "static analysis" in prompt.lower()

    def test_system_prompt_contains_severity_matrix(self, hunter):
        """Test system prompt contains severity scoring guidance."""
        prompt = hunter.get_system_prompt()
        # Should contain severity levels
        assert "critical" in prompt.lower()
        assert "high" in prompt.lower()
        assert "medium" in prompt.lower()
        assert "low" in prompt.lower()

    def test_system_prompt_mentions_vulnerability_types(self, hunter):
        """Test system prompt mentions common vulnerability types."""
        prompt = hunter.get_system_prompt()
        prompt_lower = prompt.lower()
        # Should mention key vulnerability types
        assert "sql injection" in prompt_lower or "injection" in prompt_lower
        assert "xss" in prompt_lower or "cross-site scripting" in prompt_lower
        assert "command injection" in prompt_lower or "rce" in prompt_lower

    @pytest.mark.asyncio
    async def test_execute_nonexistent_path(self, hunter):
        """Test execution with non-existent path fails gracefully."""
        state = AgentState(
            session_id="test-session",
            target_path="/nonexistent/path",
            mode=ExecutionMode.HITL,
        )

        result = await hunter.execute(state)

        assert result.success is False
        assert len(result.errors) > 0
        assert "not exist" in result.errors[0].lower()

    @pytest.mark.asyncio
    async def test_execute_returns_candidates(self, hunter, sample_codebase):
        """Test execution returns vulnerability candidates."""
        state = AgentState(
            session_id="test-session",
            target_path=str(sample_codebase),
            mode=ExecutionMode.HITL,
        )

        result = await hunter.execute(state)

        assert result.success is True
        assert "candidates" in result.output
        # Candidates may be empty if LLM isn't available, but the key should exist
        assert isinstance(result.output.get("candidates"), list)

    @pytest.mark.asyncio
    async def test_execute_sets_next_agent(self, hunter, sample_codebase):
        """Test execution sets the next agent to Verifier."""
        state = AgentState(
            session_id="test-session",
            target_path=str(sample_codebase),
            mode=ExecutionMode.HITL,
        )

        result = await hunter.execute(state)

        assert result.next_agent == AgentType.VERIFIER

    def test_deduplicate_candidates(self, hunter):
        """Test deduplication removes duplicate vulnerabilities."""
        from mrzero.core.schemas import (
            Vulnerability,
            VulnerabilityStatus,
            VulnerabilityType,
            VulnerabilitySeverity,
        )

        # Create duplicate candidates
        candidates = [
            Vulnerability(
                id="VULN-1",
                vuln_type=VulnerabilityType.SQL_INJECTION,
                severity=VulnerabilitySeverity.HIGH,
                score=85,
                status=VulnerabilityStatus.CANDIDATE,
                title="SQL Injection",
                description="Test",
                file_path="app.py",
                line_number=10,
                tool_source="test",
                confidence=0.8,
            ),
            Vulnerability(
                id="VULN-2",  # Same location, same type - should be deduplicated
                vuln_type=VulnerabilityType.SQL_INJECTION,
                severity=VulnerabilitySeverity.HIGH,
                score=80,
                status=VulnerabilityStatus.CANDIDATE,
                title="SQL Injection Duplicate",
                description="Test",
                file_path="app.py",
                line_number=10,
                tool_source="test2",
                confidence=0.7,
            ),
            Vulnerability(
                id="VULN-3",  # Different location - should be kept
                vuln_type=VulnerabilityType.SQL_INJECTION,
                severity=VulnerabilitySeverity.HIGH,
                score=75,
                status=VulnerabilityStatus.CANDIDATE,
                title="Another SQL Injection",
                description="Test",
                file_path="app.py",
                line_number=20,
                tool_source="test",
                confidence=0.6,
            ),
        ]

        deduplicated = hunter._deduplicate_candidates(candidates)

        # Should have 2 unique candidates (line 10 and line 20)
        assert len(deduplicated) == 2
        assert any(c.line_number == 10 for c in deduplicated)
        assert any(c.line_number == 20 for c in deduplicated)

    def test_map_vuln_type(self, hunter):
        """Test vulnerability type mapping from strings."""
        from mrzero.core.schemas import VulnerabilityType

        assert hunter._map_vuln_type("sql_injection") == VulnerabilityType.SQL_INJECTION
        assert hunter._map_vuln_type("command_injection") == VulnerabilityType.COMMAND_INJECTION
        assert hunter._map_vuln_type("xss_stored") == VulnerabilityType.STORED_XSS
        assert hunter._map_vuln_type("path_traversal") == VulnerabilityType.PATH_TRAVERSAL
        assert hunter._map_vuln_type("unknown_type") == VulnerabilityType.OTHER

    def test_map_severity(self, hunter):
        """Test severity mapping from strings."""
        from mrzero.core.schemas import VulnerabilitySeverity

        assert hunter._map_severity("critical") == VulnerabilitySeverity.CRITICAL
        assert hunter._map_severity("high") == VulnerabilitySeverity.HIGH
        assert hunter._map_severity("medium") == VulnerabilitySeverity.MEDIUM
        assert hunter._map_severity("low") == VulnerabilitySeverity.LOW
        assert (
            hunter._map_severity("CRITICAL") == VulnerabilitySeverity.CRITICAL
        )  # Case insensitive
