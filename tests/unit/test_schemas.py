"""Unit tests for core schemas."""

import pytest
from mrzero.core.schemas import (
    Vulnerability,
    VulnerabilityType,
    VulnerabilitySeverity,
    VulnerabilityStatus,
    AttackSurfaceMap,
    Technology,
    Endpoint,
    DataFlow,
    get_severity_from_score,
    SEVERITY_SCORES,
)


class TestSeverityScoring:
    """Tests for severity scoring functions."""

    def test_critical_score(self):
        """Test critical severity score range."""
        assert get_severity_from_score(95) == VulnerabilitySeverity.CRITICAL
        assert get_severity_from_score(100) == VulnerabilitySeverity.CRITICAL
        assert get_severity_from_score(90) == VulnerabilitySeverity.CRITICAL

    def test_high_score(self):
        """Test high severity score range."""
        assert get_severity_from_score(85) == VulnerabilitySeverity.HIGH
        assert get_severity_from_score(70) == VulnerabilitySeverity.HIGH
        assert get_severity_from_score(89) == VulnerabilitySeverity.HIGH

    def test_medium_score(self):
        """Test medium severity score range."""
        assert get_severity_from_score(50) == VulnerabilitySeverity.MEDIUM
        assert get_severity_from_score(40) == VulnerabilitySeverity.MEDIUM
        assert get_severity_from_score(69) == VulnerabilitySeverity.MEDIUM

    def test_low_score(self):
        """Test low severity score range."""
        assert get_severity_from_score(30) == VulnerabilitySeverity.LOW
        assert get_severity_from_score(20) == VulnerabilitySeverity.LOW
        assert get_severity_from_score(39) == VulnerabilitySeverity.LOW

    def test_info_score(self):
        """Test info severity score range."""
        assert get_severity_from_score(10) == VulnerabilitySeverity.INFO
        assert get_severity_from_score(0) == VulnerabilitySeverity.INFO
        assert get_severity_from_score(19) == VulnerabilitySeverity.INFO


class TestVulnerability:
    """Tests for Vulnerability schema."""

    def test_create_vulnerability(self):
        """Test creating a vulnerability."""
        vuln = Vulnerability(
            id="VULN-001",
            vuln_type=VulnerabilityType.SQL_INJECTION,
            severity=VulnerabilitySeverity.CRITICAL,
            score=95,
            status=VulnerabilityStatus.CANDIDATE,
            title="SQL Injection in login",
            description="User input is directly concatenated into SQL query.",
            file_path="src/auth/login.py",
            line_number=42,
            code_snippet="query = f'SELECT * FROM users WHERE id = {user_id}'",
            cwe_id="CWE-89",
            tool_source="opengrep",
            confidence=0.9,
        )

        assert vuln.id == "VULN-001"
        assert vuln.vuln_type == VulnerabilityType.SQL_INJECTION
        assert vuln.severity == VulnerabilitySeverity.CRITICAL
        assert vuln.score == 95

    def test_vulnerability_with_data_flow(self):
        """Test vulnerability with data flow information."""
        flow = DataFlow(
            source="request.form['user_id']",
            source_file="app.py",
            source_line=10,
            sink="cursor.execute",
            sink_file="db.py",
            sink_line=25,
            tainted=True,
        )

        vuln = Vulnerability(
            id="VULN-002",
            vuln_type=VulnerabilityType.SQL_INJECTION,
            severity=VulnerabilitySeverity.CRITICAL,
            score=95,
            status=VulnerabilityStatus.CONFIRMED,
            title="SQL Injection via form input",
            description="Form input flows to SQL query without sanitization.",
            file_path="db.py",
            line_number=25,
            data_flow=flow,
            tool_source="dataflow_analysis",
            confidence=0.9,
        )

        assert vuln.data_flow is not None
        assert vuln.data_flow.tainted is True
        assert vuln.data_flow.source == "request.form['user_id']"


class TestAttackSurfaceMap:
    """Tests for AttackSurfaceMap schema."""

    def test_create_attack_surface(self):
        """Test creating an attack surface map."""
        attack_surface = AttackSurfaceMap(
            target_path="/path/to/target",
            file_count=100,
            loc=5000,
            languages=[
                Technology(name="Python", confidence=0.8, category="language"),
                Technology(name="JavaScript", confidence=0.7, category="language"),
            ],
            frameworks=[
                Technology(name="Flask", version="2.0.0", confidence=0.9, category="framework"),
            ],
            endpoints=[
                Endpoint(
                    path="/api/users",
                    method="GET",
                    file_path="routes.py",
                    line_number=20,
                    authenticated=False,
                ),
            ],
            data_flows=[],
        )

        assert attack_surface.file_count == 100
        assert len(attack_surface.languages) == 2
        assert attack_surface.languages[0].name == "Python"
        assert len(attack_surface.endpoints) == 1
        assert attack_surface.endpoints[0].authenticated is False


class TestDataFlow:
    """Tests for DataFlow schema."""

    def test_tainted_flow(self):
        """Test creating a tainted data flow."""
        flow = DataFlow(
            source="user_input",
            source_file="input.py",
            source_line=5,
            sink="os.system",
            sink_file="exec.py",
            sink_line=15,
            tainted=True,
        )

        assert flow.tainted is True
        assert flow.source == "user_input"
        assert flow.sink == "os.system"

    def test_untainted_flow(self):
        """Test data flow that's not tainted."""
        flow = DataFlow(
            source="user_input",
            source_file="input.py",
            source_line=5,
            sink="cursor.execute",
            sink_file="db.py",
            sink_line=20,
            tainted=False,
        )

        assert flow.tainted is False
