"""Tests for the Enhanced Hunter-Verifier Loop."""

import pytest
import json

from mrzero.core.llm import AWSBedrockProvider
from mrzero.core.orchestration.enhanced_loop import (
    EnhancedHunterVerifierLoop,
    LoopMetrics,
    run_enhanced_hunter_verifier,
    _compute_vuln_hash,
    _parse_vulnerabilities_from_response,
    _parse_verifications_from_response,
)


class TestVulnHash:
    """Tests for vulnerability hashing."""

    def test_same_vuln_same_hash(self):
        """Same vulnerability should produce same hash."""
        v1 = {"file_path": "app.py", "line_number": 42, "vuln_type": "sql_injection"}
        v2 = {"file_path": "app.py", "line_number": 42, "vuln_type": "sql_injection"}

        assert _compute_vuln_hash(v1) == _compute_vuln_hash(v2)

    def test_different_vulns_different_hash(self):
        """Different vulnerabilities should have different hashes."""
        v1 = {"file_path": "app.py", "line_number": 42, "vuln_type": "sql_injection"}
        v2 = {"file_path": "app.py", "line_number": 43, "vuln_type": "sql_injection"}
        v3 = {"file_path": "app.py", "line_number": 42, "vuln_type": "xss"}

        hash1 = _compute_vuln_hash(v1)
        hash2 = _compute_vuln_hash(v2)
        hash3 = _compute_vuln_hash(v3)

        assert hash1 != hash2
        assert hash1 != hash3
        assert hash2 != hash3


class TestParseVulnerabilities:
    """Tests for parsing vulnerability responses."""

    def test_parse_json_block(self):
        """Test parsing JSON from code block."""
        response = """Here are the findings:

```json
{
    "vulnerabilities": [
        {
            "title": "SQL Injection",
            "vuln_type": "sql_injection",
            "file_path": "app.py",
            "line_number": 42
        }
    ]
}
```"""

        vulns = _parse_vulnerabilities_from_response(response)

        assert len(vulns) == 1
        assert vulns[0]["title"] == "SQL Injection"
        assert vulns[0]["file_path"] == "app.py"

    def test_parse_raw_json(self):
        """Test parsing raw JSON without code block."""
        response = """{
    "vulnerabilities": [
        {"title": "XSS", "vuln_type": "xss_stored"}
    ]
}"""

        vulns = _parse_vulnerabilities_from_response(response)

        assert len(vulns) == 1
        assert vulns[0]["title"] == "XSS"

    def test_parse_no_json(self):
        """Test parsing when no JSON present."""
        response = "I couldn't find any vulnerabilities."

        vulns = _parse_vulnerabilities_from_response(response)

        assert len(vulns) == 0

    def test_parse_invalid_json(self):
        """Test parsing invalid JSON."""
        response = "```json\n{invalid json}\n```"

        vulns = _parse_vulnerabilities_from_response(response)

        assert len(vulns) == 0


class TestParseVerifications:
    """Tests for parsing verification responses."""

    def test_parse_verifications(self):
        """Test parsing verification results."""
        response = """```json
{
    "verifications": [
        {
            "vuln_id": "V001",
            "verdict": "confirmed",
            "confidence": 0.9,
            "reasoning": "User input flows directly to SQL query"
        },
        {
            "vuln_id": "V002",
            "verdict": "false_positive",
            "confidence": 0.95,
            "reasoning": "Input is properly sanitized"
        }
    ],
    "summary": {
        "total_analyzed": 2,
        "confirmed_count": 1,
        "false_positive_count": 1
    }
}
```"""

        result = _parse_verifications_from_response(response)

        assert "verifications" in result
        assert len(result["verifications"]) == 2
        assert result["verifications"][0]["verdict"] == "confirmed"
        assert result["verifications"][1]["verdict"] == "false_positive"


class TestLoopMetrics:
    """Tests for LoopMetrics class."""

    def test_confirmation_rate_zero_candidates(self):
        """Test confirmation rate with no candidates."""
        metrics = LoopMetrics()

        assert metrics.confirmation_rate == 0.0

    def test_confirmation_rate_calculation(self):
        """Test confirmation rate calculation."""
        metrics = LoopMetrics()
        metrics.total_candidates_found = 10
        metrics.total_confirmed = 7

        assert metrics.confirmation_rate == 0.7

    def test_to_dict(self):
        """Test conversion to dictionary."""
        metrics = LoopMetrics()
        metrics.total_iterations = 2
        metrics.total_candidates_found = 5
        metrics.total_confirmed = 3
        metrics.total_false_positives = 2
        metrics.tools_used.add("read_file")
        metrics.tools_used.add("search_code")

        d = metrics.to_dict()

        assert d["total_iterations"] == 2
        assert d["total_candidates_found"] == 5
        assert d["total_confirmed"] == 3
        assert d["total_false_positives"] == 2
        assert set(d["tools_used"]) == {"read_file", "search_code"}


class TestEnhancedLoopDeduplication:
    """Tests for vulnerability deduplication."""

    def test_deduplication(self):
        """Test that duplicates are removed."""
        loop = EnhancedHunterVerifierLoop(
            llm_provider=None,  # Won't be used in this test
        )

        candidates = [
            {"file_path": "app.py", "line_number": 10, "vuln_type": "sql_injection"},
            {"file_path": "app.py", "line_number": 10, "vuln_type": "sql_injection"},  # Duplicate
            {"file_path": "app.py", "line_number": 20, "vuln_type": "xss"},
        ]

        unique = loop._deduplicate_candidates(candidates)

        assert len(unique) == 2

    def test_deduplication_across_calls(self):
        """Test that duplicates are tracked across multiple calls."""
        loop = EnhancedHunterVerifierLoop(llm_provider=None)

        # First batch
        batch1 = [
            {"file_path": "app.py", "line_number": 10, "vuln_type": "sql_injection"},
        ]
        unique1 = loop._deduplicate_candidates(batch1)
        assert len(unique1) == 1

        # Second batch with same vuln
        batch2 = [
            {
                "file_path": "app.py",
                "line_number": 10,
                "vuln_type": "sql_injection",
            },  # Already seen
            {"file_path": "app.py", "line_number": 20, "vuln_type": "xss"},  # New
        ]
        unique2 = loop._deduplicate_candidates(batch2)
        assert len(unique2) == 1  # Only the new one


@pytest.fixture
def bedrock_provider():
    """Create AWS Bedrock provider."""
    provider = AWSBedrockProvider()
    if not provider.is_configured():
        pytest.skip("AWS Bedrock not configured")
    return provider


@pytest.fixture
def vulnerable_app_path():
    """Path to the test vulnerable app."""
    from pathlib import Path

    path = Path(__file__).parent.parent / "fixtures" / "vulnerable_app"
    if not path.exists():
        pytest.skip("Vulnerable app fixture not found")
    return str(path)


class TestEnhancedLoopIntegration:
    """Integration tests for the enhanced loop."""

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.slow
    async def test_single_iteration(self, bedrock_provider, vulnerable_app_path):
        """Test a single iteration of the enhanced loop."""
        loop = EnhancedHunterVerifierLoop(
            llm_provider=bedrock_provider,
            max_iterations=1,
            min_confirmed=10,  # High threshold to force single iteration
            max_tool_calls_per_agent=6,
        )

        confirmed, fps, metrics = await loop.run(
            target_path=vulnerable_app_path,
            attack_surface_context="Flask web application with SQLite database",
        )

        # Should have completed one iteration
        assert metrics.total_iterations == 1

        # Should have found at least something
        assert metrics.total_candidates_found > 0 or metrics.total_tool_calls > 0

        # Print summary for debugging
        print(f"\nIteration: {metrics.total_iterations}")
        print(f"Candidates found: {metrics.total_candidates_found}")
        print(f"Confirmed: {metrics.total_confirmed}")
        print(f"False positives: {metrics.total_false_positives}")
        print(f"Tool calls: {metrics.total_tool_calls}")
        print(f"Tools used: {metrics.tools_used}")

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.slow
    async def test_full_loop(self, bedrock_provider, vulnerable_app_path):
        """Test the full enhanced Hunter-Verifier loop."""
        confirmed, fps, metrics = await run_enhanced_hunter_verifier(
            llm_provider=bedrock_provider,
            target_path=vulnerable_app_path,
            attack_surface_context="Flask application with known SQL injection and command injection vulnerabilities",
            max_iterations=2,
            min_confirmed=3,
        )

        # Print detailed summary
        print(f"\n=== Enhanced Loop Results ===")
        print(f"Total iterations: {metrics.total_iterations}")
        print(f"Candidates found: {metrics.total_candidates_found}")
        print(f"Confirmed vulnerabilities: {len(confirmed)}")
        print(f"False positives: {len(fps)}")
        print(f"Confirmation rate: {metrics.confirmation_rate:.1%}")
        print(f"Total tool calls: {metrics.total_tool_calls}")
        print(f"Tools used: {metrics.tools_used}")
        print(f"Duration: {metrics.duration_seconds:.1f}s")

        if confirmed:
            print(f"\nConfirmed vulnerabilities:")
            for v in confirmed[:5]:
                print(
                    f"  - {v.get('title', v.get('vuln_type', 'Unknown'))}: {v.get('file_path')}:{v.get('line_number')}"
                )

        # Should find at least some vulnerabilities in our test app
        assert metrics.total_iterations >= 1
        # The vulnerable app has known vulns, so we should find some
        assert len(confirmed) > 0 or metrics.total_candidates_found > 0
