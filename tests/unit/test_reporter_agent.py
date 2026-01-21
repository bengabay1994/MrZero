"""Unit tests for the Reporter (MrZeroConclusion) agent."""

import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from mrzero.agents.reporter.agent import ReporterAgent
from mrzero.agents.base import AgentType
from mrzero.core.memory.state import AgentState
from mrzero.core.schemas import (
    AttackSurfaceMap,
    DataFlow,
    Endpoint,
    EnvironmentInfo,
    ExecutionMode,
    Exploit,
    Technology,
    Vulnerability,
    VulnerabilityStatus,
    VulnerabilityType,
    VulnerabilitySeverity,
)


@pytest.fixture
def reporter():
    """Create a Reporter agent instance."""
    return ReporterAgent()


@pytest.fixture
def sample_vulnerability():
    """Create a sample vulnerability for testing."""
    return Vulnerability(
        id="VULN-001",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=VulnerabilitySeverity.CRITICAL,
        score=95,
        status=VulnerabilityStatus.CONFIRMED,
        title="SQL Injection in login handler",
        description="Unsanitized user input in SQL query allows attackers to bypass authentication.",
        file_path="app/routes/auth.py",
        line_number=42,
        code_snippet="query = f\"SELECT * FROM users WHERE username='{username}'\"",
        tool_source="hunter",
        confidence=0.95,
        cwe_id="CWE-89",
    )


@pytest.fixture
def sample_vulnerabilities(sample_vulnerability):
    """Create a list of sample vulnerabilities."""
    return [
        sample_vulnerability,
        Vulnerability(
            id="VULN-002",
            vuln_type=VulnerabilityType.COMMAND_INJECTION,
            severity=VulnerabilitySeverity.HIGH,
            score=85,
            status=VulnerabilityStatus.CONFIRMED,
            title="Command Injection in file processor",
            description="User input passed to os.system() without sanitization.",
            file_path="app/utils/processor.py",
            line_number=78,
            code_snippet="os.system(f'convert {filename}')",
            tool_source="hunter",
            confidence=0.9,
            cwe_id="CWE-78",
        ),
        Vulnerability(
            id="VULN-003",
            vuln_type=VulnerabilityType.STORED_XSS,
            severity=VulnerabilitySeverity.MEDIUM,
            score=55,
            status=VulnerabilityStatus.CONFIRMED,
            title="Stored XSS in comment section",
            description="User comments rendered without HTML encoding.",
            file_path="app/views/comments.py",
            line_number=23,
            code_snippet="return f'<div>{comment}</div>'",
            tool_source="hunter",
            confidence=0.85,
            cwe_id="CWE-79",
        ),
    ]


@pytest.fixture
def sample_attack_surface():
    """Create a sample attack surface map."""
    return AttackSurfaceMap(
        target_path="/test/project",
        file_count=150,
        loc=25000,
        languages=[
            Technology(name="Python", confidence=0.85, category="language"),
            Technology(name="JavaScript", confidence=0.12, category="language"),
        ],
        frameworks=[
            Technology(name="Flask", version="2.0.0", confidence=0.95, category="framework"),
            Technology(name="SQLAlchemy", version="1.4.0", confidence=0.9, category="framework"),
        ],
        endpoints=[
            Endpoint(
                path="/api/login",
                method="POST",
                file_path="app/routes/auth.py",
                line_number=10,
                authenticated=False,
                risk_score=85,
            ),
            Endpoint(
                path="/api/users",
                method="GET",
                file_path="app/routes/users.py",
                line_number=20,
                authenticated=True,
                risk_score=30,
            ),
        ],
        data_flows=[],
        dependencies={},
    )


@pytest.fixture
def sample_environment():
    """Create a sample environment info."""
    return EnvironmentInfo(
        env_type="docker",
        build_successful=True,
        build_attempts=1,
        container_id="abc123def456",
        connection_port=8080,
        connection_ip="127.0.0.1",
    )


@pytest.fixture
def sample_exploits(sample_vulnerability):
    """Create sample exploits."""
    return [
        Exploit(
            vulnerability_id="VULN-001",
            exploit_type="sqli",
            language="python",
            code="""#!/usr/bin/env python3
import requests

def exploit(target_url):
    payload = "' OR '1'='1' --"
    response = requests.post(
        f"{target_url}/api/login",
        data={"username": payload, "password": "anything"}
    )
    return "admin" in response.text

if __name__ == "__main__":
    print(exploit("http://localhost:8080"))
""",
            description="SQL injection bypass for authentication",
            file_path="/tmp/exploits/exploit_VULN-001.py",
            tested=True,
            successful=True,
            test_output="Authentication bypassed successfully",
        ),
    ]


@pytest.fixture
def sample_state(
    tmp_path, sample_vulnerabilities, sample_attack_surface, sample_environment, sample_exploits
):
    """Create a complete sample state for testing."""
    target_dir = tmp_path / "target_project"
    target_dir.mkdir()

    return AgentState(
        session_id="test-session-123",
        target_path=str(target_dir),
        mode=ExecutionMode.HITL,
        confirmed_vulnerabilities=sample_vulnerabilities,
        attack_surface=sample_attack_surface,
        environment=sample_environment,
        exploits=sample_exploits,
    )


@pytest.fixture
def empty_state(tmp_path):
    """Create a state with no findings."""
    target_dir = tmp_path / "empty_project"
    target_dir.mkdir()

    return AgentState(
        session_id="empty-session",
        target_path=str(target_dir),
        mode=ExecutionMode.HITL,
        confirmed_vulnerabilities=[],
    )


class TestReporterAgent:
    """Tests for the Reporter agent."""

    def test_agent_type(self, reporter):
        """Test agent type is correct."""
        assert reporter.agent_type == AgentType.REPORTER

    def test_system_prompt(self, reporter):
        """Test system prompt contains key concepts."""
        prompt = reporter.get_system_prompt()
        assert "MrZeroConclusion" in prompt
        assert "report" in prompt.lower()
        assert "executive summary" in prompt.lower()

    def test_system_prompt_mentions_analysis_capabilities(self, reporter):
        """Test system prompt mentions analysis capabilities."""
        prompt = reporter.get_system_prompt()
        prompt_lower = prompt.lower()
        assert "risk" in prompt_lower
        assert "pattern" in prompt_lower
        assert "remediation" in prompt_lower

    def test_system_prompt_mentions_report_sections(self, reporter):
        """Test system prompt mentions report sections."""
        prompt = reporter.get_system_prompt()
        prompt_lower = prompt.lower()
        assert "executive summary" in prompt_lower
        assert "vulnerability" in prompt_lower
        assert "remediation" in prompt_lower


class TestReporterExecution:
    """Tests for Reporter execute method."""

    @pytest.mark.asyncio
    async def test_execute_generates_report(self, reporter, sample_state, mock_config):
        """Test that execute generates a report successfully."""
        with patch.object(reporter, "chat", new_callable=AsyncMock) as mock_chat:
            # Mock LLM responses
            mock_chat.return_value = json.dumps(
                {
                    "overall_risk_level": "critical",
                    "risk_score": 90,
                    "posture_assessment": "The application has critical security issues.",
                    "key_risks": [
                        {"risk": "SQL Injection", "impact": "Data breach", "urgency": "immediate"}
                    ],
                    "patterns_identified": [],
                    "top_recommendations": [
                        {
                            "priority": 1,
                            "recommendation": "Fix SQLi",
                            "rationale": "Critical risk",
                            "effort": "medium",
                        }
                    ],
                    "exploitation_summary": "1 successful exploit",
                    "executive_narrative": "Critical security issues were found.",
                }
            )

            result = await reporter.execute(sample_state)

            assert result.success is True
            assert "report_path" in result.output
            assert "json_path" in result.output
            assert result.next_agent is None  # Reporter is the last agent

    @pytest.mark.asyncio
    async def test_execute_creates_report_files(self, reporter, sample_state, mock_config):
        """Test that execute creates actual report files."""
        with patch.object(reporter, "chat", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = "{}"

            result = await reporter.execute(sample_state)

            # Check files were created
            report_path = Path(result.output["report_path"])
            json_path = Path(result.output["json_path"])

            assert report_path.exists()
            assert json_path.exists()
            assert report_path.suffix == ".md"
            assert json_path.suffix == ".json"

    @pytest.mark.asyncio
    async def test_execute_empty_state(self, reporter, empty_state, mock_config):
        """Test execute with no vulnerabilities."""
        with patch.object(reporter, "chat", new_callable=AsyncMock) as mock_chat:
            mock_chat.return_value = "{}"

            result = await reporter.execute(empty_state)

            assert result.success is True
            # Report should still be generated even with no findings


class TestReporterReportContent:
    """Tests for report content generation."""

    def test_build_report_contains_sections(self, reporter, sample_state):
        """Test that built report contains all expected sections."""
        executive_analysis = {
            "overall_risk_level": "high",
            "risk_score": 75,
            "executive_narrative": "Security issues found.",
            "key_risks": [],
            "patterns_identified": [],
            "top_recommendations": [],
        }
        remediation_strategy = {
            "remediation_groups": [],
            "quick_wins": [],
            "long_term_improvements": [],
            "preventive_measures": [],
        }

        report = reporter._build_report(
            state=sample_state,
            executive_analysis=executive_analysis,
            remediation_strategy=remediation_strategy,
        )

        # Check all major sections
        assert "# Security Assessment Report" in report
        assert "## Executive Summary" in report
        assert "## Vulnerability Summary" in report
        assert "## Attack Surface Analysis" in report
        assert "## Vulnerability Details" in report
        assert "## Remediation Strategy" in report
        assert "## Environment Setup" in report
        assert "## Exploit Documentation" in report
        assert "## Appendix" in report

    def test_build_report_includes_vulnerability_details(self, reporter, sample_state):
        """Test that report includes vulnerability details."""
        report = reporter._build_report(
            state=sample_state,
            executive_analysis={
                "overall_risk_level": "high",
                "risk_score": 75,
                "key_risks": [],
                "patterns_identified": [],
                "top_recommendations": [],
            },
            remediation_strategy={},
        )

        # Should include vulnerability info
        assert "SQL Injection" in report
        assert "VULN-001" in report
        assert "CWE-89" in report
        assert "app/routes/auth.py" in report

    def test_build_report_includes_attack_surface(self, reporter, sample_state):
        """Test that report includes attack surface data."""
        report = reporter._build_report(
            state=sample_state,
            executive_analysis={
                "overall_risk_level": "medium",
                "risk_score": 50,
                "key_risks": [],
                "patterns_identified": [],
                "top_recommendations": [],
            },
            remediation_strategy={},
        )

        assert "150" in report  # file count
        assert "25,000" in report or "25000" in report  # LOC
        assert "Python" in report
        assert "Flask" in report

    def test_build_report_includes_exploits(self, reporter, sample_state):
        """Test that report includes exploit information."""
        report = reporter._build_report(
            state=sample_state,
            executive_analysis={
                "overall_risk_level": "critical",
                "risk_score": 90,
                "key_risks": [],
                "patterns_identified": [],
                "top_recommendations": [],
            },
            remediation_strategy={},
        )

        assert "Successful Exploits" in report
        assert "VULN-001" in report
        assert "python" in report.lower()

    def test_build_report_includes_environment(self, reporter, sample_state):
        """Test that report includes environment information."""
        report = reporter._build_report(
            state=sample_state,
            executive_analysis={
                "overall_risk_level": "high",
                "risk_score": 75,
                "key_risks": [],
                "patterns_identified": [],
                "top_recommendations": [],
            },
            remediation_strategy={},
        )

        assert "docker" in report.lower()
        assert "abc123" in report  # container ID
        assert "8080" in report  # port


class TestReporterJSONReport:
    """Tests for JSON report generation."""

    def test_generate_json_report_structure(self, reporter, sample_state):
        """Test JSON report has correct structure."""
        executive_analysis = {
            "overall_risk_level": "high",
            "risk_score": 75,
        }
        remediation_strategy = {}

        json_report = reporter._generate_json_report(
            state=sample_state,
            executive_analysis=executive_analysis,
            remediation_strategy=remediation_strategy,
        )

        # Check structure
        assert "meta" in json_report
        assert "executive_summary" in json_report
        assert "summary" in json_report
        assert "attack_surface" in json_report
        assert "vulnerabilities" in json_report
        assert "remediation_strategy" in json_report
        assert "environment" in json_report
        assert "exploits" in json_report

    def test_generate_json_report_meta(self, reporter, sample_state):
        """Test JSON report meta section."""
        json_report = reporter._generate_json_report(
            state=sample_state,
            executive_analysis={},
            remediation_strategy={},
        )

        meta = json_report["meta"]
        assert meta["session_id"] == "test-session-123"
        assert meta["mode"] == "hitl"
        assert "timestamp" in meta
        assert "version" in meta

    def test_generate_json_report_summary(self, reporter, sample_state):
        """Test JSON report summary section."""
        json_report = reporter._generate_json_report(
            state=sample_state,
            executive_analysis={},
            remediation_strategy={},
        )

        summary = json_report["summary"]
        assert summary["total_vulnerabilities"] == 3
        assert "by_severity" in summary
        assert "by_type" in summary

    def test_count_by_type(self, reporter, sample_vulnerabilities):
        """Test vulnerability counting by type."""
        counts = reporter._count_by_type(sample_vulnerabilities)

        assert counts["sql_injection"] == 1
        assert counts["command_injection"] == 1
        assert counts["stored_xss"] == 1  # The enum value is stored_xss not xss_stored


class TestReporterFallbacks:
    """Tests for fallback methods when LLM fails."""

    def test_generate_fallback_executive_summary_critical(self, reporter, sample_vulnerabilities):
        """Test fallback summary with many critical/high vulns."""
        severity_counts = {
            VulnerabilitySeverity.CRITICAL: 3,  # Need > 5 critical+high for "critical" risk
            VulnerabilitySeverity.HIGH: 3,
            VulnerabilitySeverity.MEDIUM: 1,
            VulnerabilitySeverity.LOW: 0,
            VulnerabilitySeverity.INFO: 0,
        }

        result = reporter._generate_fallback_executive_summary(
            sample_vulnerabilities, severity_counts, []
        )

        assert result["overall_risk_level"] == "critical"
        assert result["risk_score"] == 90

    def test_generate_fallback_executive_summary_high(self, reporter, sample_vulnerabilities):
        """Test fallback summary with high vulns."""
        severity_counts = {
            VulnerabilitySeverity.CRITICAL: 0,
            VulnerabilitySeverity.HIGH: 2,
            VulnerabilitySeverity.MEDIUM: 1,
            VulnerabilitySeverity.LOW: 0,
            VulnerabilitySeverity.INFO: 0,
        }

        result = reporter._generate_fallback_executive_summary(
            sample_vulnerabilities, severity_counts, []
        )

        assert result["overall_risk_level"] == "high"
        assert result["risk_score"] == 70

    def test_generate_fallback_executive_summary_medium(self, reporter):
        """Test fallback summary with only medium vulns."""
        severity_counts = {
            VulnerabilitySeverity.CRITICAL: 0,
            VulnerabilitySeverity.HIGH: 0,
            VulnerabilitySeverity.MEDIUM: 3,
            VulnerabilitySeverity.LOW: 0,
            VulnerabilitySeverity.INFO: 0,
        }

        result = reporter._generate_fallback_executive_summary([], severity_counts, [])

        assert result["overall_risk_level"] == "medium"
        assert result["risk_score"] == 50

    def test_generate_fallback_executive_summary_low(self, reporter):
        """Test fallback summary with only low vulns."""
        severity_counts = {
            VulnerabilitySeverity.CRITICAL: 0,
            VulnerabilitySeverity.HIGH: 0,
            VulnerabilitySeverity.MEDIUM: 0,
            VulnerabilitySeverity.LOW: 2,
            VulnerabilitySeverity.INFO: 0,
        }

        result = reporter._generate_fallback_executive_summary([], severity_counts, [])

        assert result["overall_risk_level"] == "low"
        assert result["risk_score"] == 25

    def test_generate_fallback_remediation(self, reporter, sample_vulnerabilities):
        """Test fallback remediation strategy."""
        result = reporter._generate_fallback_remediation(sample_vulnerabilities)

        assert "fix_order" in result
        assert "preventive_measures" in result
        assert len(result["preventive_measures"]) > 0

    def test_generate_basic_narrative_no_vulns(self, reporter):
        """Test basic narrative with no vulnerabilities."""
        severity_counts = {s: 0 for s in VulnerabilitySeverity}

        narrative = reporter._generate_basic_narrative([], severity_counts)

        assert "did not identify" in narrative.lower()

    def test_generate_basic_narrative_with_vulns(self, reporter, sample_vulnerabilities):
        """Test basic narrative with vulnerabilities."""
        severity_counts = {
            VulnerabilitySeverity.CRITICAL: 1,
            VulnerabilitySeverity.HIGH: 1,
            VulnerabilitySeverity.MEDIUM: 1,
            VulnerabilitySeverity.LOW: 0,
            VulnerabilitySeverity.INFO: 0,
        }

        narrative = reporter._generate_basic_narrative(sample_vulnerabilities, severity_counts)

        assert "3 confirmed vulnerabilities" in narrative
        assert "critical" in narrative.lower()
        assert "high" in narrative.lower()


class TestReporterRemediation:
    """Tests for remediation advice generation."""

    def test_get_default_remediation_sql_injection(self, reporter, sample_vulnerability):
        """Test default remediation for SQL injection."""
        remediation = reporter._get_default_remediation(sample_vulnerability)

        assert "parameterized" in remediation.lower() or "prepared" in remediation.lower()

    def test_get_default_remediation_command_injection(self, reporter):
        """Test default remediation for command injection."""
        vuln = Vulnerability(
            id="test",
            vuln_type=VulnerabilityType.COMMAND_INJECTION,
            severity=VulnerabilitySeverity.HIGH,
            score=85,
            status=VulnerabilityStatus.CONFIRMED,
            title="Test",
            description="Command injection vulnerability",
            file_path="test.py",
            line_number=1,
            tool_source="test",
            confidence=0.9,
        )

        remediation = reporter._get_default_remediation(vuln)

        assert "shell" in remediation.lower() or "subprocess" in remediation.lower()

    def test_get_default_remediation_xss(self, reporter):
        """Test default remediation for XSS."""
        vuln = Vulnerability(
            id="test",
            vuln_type=VulnerabilityType.STORED_XSS,
            severity=VulnerabilitySeverity.MEDIUM,
            score=55,
            status=VulnerabilityStatus.CONFIRMED,
            title="Test",
            description="XSS vulnerability",
            file_path="test.py",
            line_number=1,
            tool_source="test",
            confidence=0.9,
        )

        remediation = reporter._get_default_remediation(vuln)

        assert "encode" in remediation.lower() or "csp" in remediation.lower()

    def test_get_remediation_for_vuln_quick_win(self, reporter, sample_vulnerability):
        """Test getting remediation for a quick win vulnerability."""
        remediation_strategy = {
            "quick_wins": [
                {
                    "vuln_id": "VULN-001",
                    "fix": "Use parameterized queries",
                    "time_estimate": "2 hours",
                    "impact": "Eliminates SQL injection risk",
                }
            ],
            "remediation_groups": [],
        }

        remediation = reporter._get_remediation_for_vuln(sample_vulnerability, remediation_strategy)

        assert "Quick Win" in remediation
        assert "parameterized" in remediation.lower()

    def test_get_remediation_for_vuln_in_group(self, reporter, sample_vulnerability):
        """Test getting remediation for a grouped vulnerability."""
        remediation_strategy = {
            "quick_wins": [],
            "remediation_groups": [
                {
                    "group_name": "Input Validation",
                    "vulnerabilities": ["VULN-001", "VULN-002"],
                    "common_fix": "Implement input validation framework",
                    "effort": "days",
                }
            ],
        }

        remediation = reporter._get_remediation_for_vuln(sample_vulnerability, remediation_strategy)

        assert "Input Validation" in remediation


class TestReporterPrompts:
    """Tests for prompt templates."""

    def test_executive_summary_prompt_placeholders(self, reporter):
        """Test executive summary prompt has required placeholders."""
        prompt = reporter.EXECUTIVE_SUMMARY_PROMPT

        assert "{target_path}" in prompt
        assert "{mode}" in prompt
        assert "{session_id}" in prompt
        assert "{vuln_stats}" in prompt
        assert "{top_vulns}" in prompt
        assert "{attack_surface_summary}" in prompt
        assert "{env_exploit_summary}" in prompt

    def test_remediation_analysis_prompt_placeholders(self, reporter):
        """Test remediation analysis prompt has required placeholders."""
        prompt = reporter.REMEDIATION_ANALYSIS_PROMPT

        assert "{vulnerabilities}" in prompt

    def test_parse_llm_json_response_valid(self, reporter):
        """Test parsing valid JSON response."""
        response = '```json\n{"key": "value"}\n```'
        result = reporter._parse_llm_json_response(response)

        assert result == {"key": "value"}

    def test_parse_llm_json_response_raw(self, reporter):
        """Test parsing raw JSON without code blocks."""
        response = 'Here is the response: {"key": "value"}'
        result = reporter._parse_llm_json_response(response)

        assert result == {"key": "value"}

    def test_parse_llm_json_response_invalid(self, reporter):
        """Test parsing invalid JSON returns None."""
        response = "This is not JSON at all"
        result = reporter._parse_llm_json_response(response)

        assert result is None


class TestReporterEdgeCases:
    """Tests for edge cases and error handling."""

    def test_build_report_no_attack_surface(self, reporter, sample_state):
        """Test report generation without attack surface."""
        sample_state.attack_surface = None

        report = reporter._build_report(
            state=sample_state,
            executive_analysis={
                "overall_risk_level": "medium",
                "risk_score": 50,
                "key_risks": [],
                "patterns_identified": [],
                "top_recommendations": [],
            },
            remediation_strategy={},
        )

        assert "Attack surface analysis was not performed" in report

    def test_build_report_no_environment(self, reporter, sample_state):
        """Test report generation without environment."""
        sample_state.environment = None

        report = reporter._build_report(
            state=sample_state,
            executive_analysis={
                "overall_risk_level": "medium",
                "risk_score": 50,
                "key_risks": [],
                "patterns_identified": [],
                "top_recommendations": [],
            },
            remediation_strategy={},
        )

        assert "Environment setup was not performed" in report

    def test_build_report_no_exploits(self, reporter, sample_state):
        """Test report generation without exploits."""
        sample_state.exploits = []

        report = reporter._build_report(
            state=sample_state,
            executive_analysis={
                "overall_risk_level": "medium",
                "risk_score": 50,
                "key_risks": [],
                "patterns_identified": [],
                "top_recommendations": [],
            },
            remediation_strategy={},
        )

        assert "No exploits were generated" in report

    def test_build_report_failed_environment(self, reporter, sample_state):
        """Test report with failed environment build."""
        sample_state.environment = EnvironmentInfo(
            env_type="docker",
            build_successful=False,
            build_attempts=5,
            build_errors=["Missing dependency: libssl-dev"],
            manual_guide_path="/path/to/guide.md",
        )

        report = reporter._build_report(
            state=sample_state,
            executive_analysis={
                "overall_risk_level": "medium",
                "risk_score": 50,
                "key_risks": [],
                "patterns_identified": [],
                "top_recommendations": [],
            },
            remediation_strategy={},
        )

        assert "Failed" in report
        assert "manual setup guide" in report.lower()

    def test_vulnerability_with_data_flow(self, reporter, sample_state):
        """Test report includes data flow information."""
        # Add data flow to first vulnerability
        sample_state.confirmed_vulnerabilities[0].data_flow = DataFlow(
            source="request.form['username']",
            source_file="app/routes/auth.py",
            source_line=35,
            sink="cursor.execute(query)",
            sink_file="app/routes/auth.py",
            sink_line=42,
            tainted=True,
        )

        report = reporter._build_report(
            state=sample_state,
            executive_analysis={
                "overall_risk_level": "critical",
                "risk_score": 90,
                "key_risks": [],
                "patterns_identified": [],
                "top_recommendations": [],
            },
            remediation_strategy={},
        )

        assert "Data Flow" in report
        assert "Source:" in report
        assert "Sink:" in report
