"""Core schema models for MrZero."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ExecutionMode(str, Enum):
    """Execution mode for MrZero."""

    YOLO = "yolo"  # Autonomous mode
    HITL = "hitl"  # Human-in-the-loop mode


class VulnerabilitySeverity(str, Enum):
    """Severity levels for vulnerabilities."""

    CRITICAL = "critical"  # Score 90-100
    HIGH = "high"  # Score 70-89
    MEDIUM = "medium"  # Score 40-69
    LOW = "low"  # Score 20-39
    INFO = "info"  # Score 0-19


class VulnerabilityStatus(str, Enum):
    """Status of a vulnerability finding."""

    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    EXPLOITED = "exploited"


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities."""

    # Critical (90-100)
    RCE = "rce"
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    AUTH_BYPASS = "auth_bypass"
    REENTRANCY = "reentrancy"
    PRIVATE_KEY_LEAK = "private_key_leak"
    FLASH_LOAN = "flash_loan"

    # High (70-89)
    LPE = "lpe"  # Local Privilege Escalation
    SSRF = "ssrf"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    XXE = "xxe"
    PATH_TRAVERSAL = "path_traversal"
    LFI = "lfi"
    IDOR = "idor"
    STORED_XSS = "stored_xss"

    # Medium (40-69)
    REFLECTED_XSS = "reflected_xss"
    DOS = "dos"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    CSRF = "csrf"
    RACE_CONDITION = "race_condition"

    # Low (20-39)
    OPEN_REDIRECT = "open_redirect"
    CRLF_INJECTION = "crlf_injection"

    # Other
    OTHER = "other"


class Technology(BaseModel):
    """Detected technology/framework in the codebase."""

    name: str
    version: str | None = None
    category: str = "unknown"  # e.g., "language", "framework", "database"
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    file_count: int = 0  # Number of files using this technology


class Endpoint(BaseModel):
    """API endpoint or entry point."""

    path: str
    method: str | None = None  # HTTP method if applicable
    file_path: str
    line_number: int
    authenticated: bool = True
    parameters: list[str] = Field(default_factory=list)
    risk_score: int = Field(default=50, ge=0, le=100)


class DataFlow(BaseModel):
    """Data flow from source to sink."""

    source: str
    sink: str
    source_file: str
    source_line: int
    sink_file: str
    sink_line: int
    tainted: bool = False
    sanitizers: list[str] = Field(default_factory=list)


class AttackSurfaceMap(BaseModel):
    """Output of MrZeroMapper - attack surface analysis."""

    target_path: str
    scan_timestamp: datetime = Field(default_factory=datetime.now)
    languages: list[Technology] = Field(default_factory=list)
    frameworks: list[Technology] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    data_flows: list[DataFlow] = Field(default_factory=list)
    dependencies: dict[str, str] = Field(default_factory=dict)  # name -> version
    file_count: int = 0
    loc: int = 0  # Lines of code
    auth_boundaries: list[str] = Field(default_factory=list)
    trust_zones: list[str] = Field(default_factory=list)


class Vulnerability(BaseModel):
    """A vulnerability finding."""

    id: str = Field(default_factory=lambda: "")
    vuln_type: VulnerabilityType
    severity: VulnerabilitySeverity
    score: int = Field(ge=0, le=100)
    status: VulnerabilityStatus = VulnerabilityStatus.CANDIDATE
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str | None = None
    data_flow: DataFlow | None = None
    cwe_id: str | None = None
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    tool_source: str  # Which tool found this (e.g., "codeql", "opengrep")
    confidence: float = Field(ge=0.0, le=1.0)
    remediation: str | None = None
    discovered_at: datetime = Field(default_factory=datetime.now)
    verified_at: datetime | None = None


class EnvironmentInfo(BaseModel):
    """Information about a running test environment."""

    env_type: str  # "docker", "vm", "native", "harness"
    connection_ip: str | None = None
    connection_port: int | None = None
    process_id: int | None = None
    container_id: str | None = None
    build_successful: bool = False
    build_attempts: int = 0
    build_errors: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    manual_guide_path: str | None = None


class Exploit(BaseModel):
    """An exploit for a vulnerability."""

    vulnerability_id: str
    exploit_type: str  # e.g., "rop_chain", "reverse_shell", "poc"
    language: str  # e.g., "python", "c"
    code: str
    description: str | None = None
    file_path: str | None = None
    tested: bool = False
    successful: bool = False
    test_output: str | None = None
    notes: str | None = None


class ScanSession(BaseModel):
    """A complete scan session."""

    id: str
    target_path: str
    mode: ExecutionMode
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: datetime | None = None
    current_agent: str | None = None
    attack_surface: AttackSurfaceMap | None = None
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    environment: EnvironmentInfo | None = None
    exploits: list[Exploit] = Field(default_factory=list)
    status: str = "pending"  # pending, running, paused, completed, failed


# Severity scoring based on PRD prioritization matrix
SEVERITY_SCORES: dict[VulnerabilityType, tuple[int, int]] = {
    # Critical (90-100)
    VulnerabilityType.RCE: (95, 100),
    VulnerabilityType.COMMAND_INJECTION: (90, 98),
    VulnerabilityType.SQL_INJECTION: (90, 98),
    VulnerabilityType.AUTH_BYPASS: (90, 98),
    VulnerabilityType.REENTRANCY: (95, 100),
    VulnerabilityType.PRIVATE_KEY_LEAK: (95, 100),
    VulnerabilityType.FLASH_LOAN: (90, 98),
    # High (70-89)
    VulnerabilityType.LPE: (80, 89),
    VulnerabilityType.SSRF: (75, 85),
    VulnerabilityType.INSECURE_DESERIALIZATION: (80, 89),
    VulnerabilityType.XXE: (75, 85),
    VulnerabilityType.PATH_TRAVERSAL: (70, 80),
    VulnerabilityType.LFI: (70, 80),
    VulnerabilityType.IDOR: (70, 85),
    VulnerabilityType.STORED_XSS: (70, 80),
    # Medium (40-69)
    VulnerabilityType.REFLECTED_XSS: (50, 65),
    VulnerabilityType.DOS: (40, 60),
    VulnerabilityType.SUBDOMAIN_TAKEOVER: (50, 65),
    VulnerabilityType.CSRF: (45, 60),
    VulnerabilityType.RACE_CONDITION: (50, 65),
    # Low (20-39)
    VulnerabilityType.OPEN_REDIRECT: (25, 35),
    VulnerabilityType.CRLF_INJECTION: (20, 35),
    # Other
    VulnerabilityType.OTHER: (20, 50),
}


def get_severity_from_score(score: int) -> VulnerabilitySeverity:
    """Get severity level from a numeric score.

    Args:
        score: Vulnerability score (0-100).

    Returns:
        VulnerabilitySeverity enum value.
    """
    if score >= 90:
        return VulnerabilitySeverity.CRITICAL
    elif score >= 70:
        return VulnerabilitySeverity.HIGH
    elif score >= 40:
        return VulnerabilitySeverity.MEDIUM
    elif score >= 20:
        return VulnerabilitySeverity.LOW
    else:
        return VulnerabilitySeverity.INFO
