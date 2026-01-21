"""MrZeroVulnHunter - LLM-Powered Vulnerability Hunter Agent."""

import json
import uuid
from pathlib import Path
from typing import Any

from mrzero.agents.base import AgentResult, AgentType, BaseAgent
from mrzero.core.memory.state import AgentState
from mrzero.core.schemas import (
    Vulnerability,
    VulnerabilityStatus,
    VulnerabilityType,
    VulnerabilitySeverity,
)


class HunterAgent(BaseAgent):
    """Agent for hunting vulnerabilities using LLM-powered analysis.

    This agent uses the LLM as the PRIMARY decision maker for identifying
    security vulnerabilities. Tools (SAST scanners, code readers) are used
    to gather information, but ALL decisions about what constitutes a
    vulnerability are made by the LLM.

    The agent leverages VectorDB semantic search to find security-relevant
    code patterns that might be missed by traditional file-based scanning.
    """

    agent_type = AgentType.HUNTER
    _indexer = None  # Lazy-loaded code indexer for semantic search

    SYSTEM_PROMPT = """You are MrZeroVulnHunter, an elite security researcher and vulnerability hunter.

## Your Mission
Analyze source code to identify security vulnerabilities that could be exploited by attackers.
You work through STATIC ANALYSIS - examining code without executing it.

## Your Expertise
You are an expert in identifying:
- **Injection Flaws**: SQL Injection, Command Injection, LDAP Injection, XPath Injection
- **Cross-Site Scripting (XSS)**: Stored, Reflected, DOM-based
- **Broken Authentication**: Weak credentials, session management flaws
- **Sensitive Data Exposure**: Hardcoded secrets, unencrypted data, info leaks
- **Security Misconfiguration**: Debug modes, default credentials, verbose errors
- **Insecure Deserialization**: Pickle, YAML, JSON with type hints
- **Server-Side Request Forgery (SSRF)**: URL fetching with user input
- **Path Traversal**: File read/write with unsanitized paths
- **Remote Code Execution (RCE)**: eval(), exec(), dynamic imports
- **Smart Contract Vulnerabilities**: Reentrancy, integer overflow, access control

## Analysis Methodology

For each piece of code you analyze:

1. **Identify Entry Points**: Where does user/external input enter the system?
   - HTTP request parameters, headers, body
   - File uploads
   - Database values (could be user-controlled)
   - Environment variables
   - Command line arguments

2. **Trace Data Flow**: Follow the data from entry to usage
   - Is the input used in a dangerous operation?
   - Is there any validation/sanitization in between?
   - Could an attacker control the malicious portion?

3. **Identify Dangerous Sinks**: Operations that could be exploited
   - Database queries (SQL, NoSQL)
   - System command execution
   - File operations
   - HTML rendering
   - Deserialization
   - Network requests

4. **Assess Exploitability**: Could this actually be exploited?
   - Is the vulnerable code reachable?
   - What privileges would an attacker gain?
   - What are the preconditions for exploitation?

## Severity Scoring (Follow This Matrix)

| Score | Severity | Vulnerability Types |
|-------|----------|---------------------|
| 90-100 | CRITICAL | RCE, Command Injection, SQL Injection (data exfil), Auth Bypass, Reentrancy, Private Key Leaks |
| 70-89 | HIGH | LPE, SSRF, XXE, Insecure Deserialization, Path Traversal (sensitive files), Stored XSS |
| 40-69 | MEDIUM | Reflected XSS, CSRF, DoS, Race Conditions, Info Disclosure |
| 20-39 | LOW | Open Redirect, CRLF Injection, Verbose Errors |

## Output Requirements

For each vulnerability you identify, provide:
- Exact file path and line number
- Vulnerability type and CWE ID
- Severity score (0-100)
- Clear description of the issue
- The vulnerable code snippet
- How an attacker would exploit it
- Confidence level (0.0-1.0)"""

    HUNT_PROMPT = """## Vulnerability Hunting Task

Analyze the following code and identify ALL security vulnerabilities.

### Target Information
- **Path**: {target_path}
- **Languages**: {languages}
- **Frameworks**: {frameworks}

### Attack Surface Context
{attack_surface_context}

### Semantic Code Search Results (High-Risk Patterns Found)
{semantic_search_results}

### SAST Tool Findings (Use as hints, but make your own assessment)
{sast_findings}

### Source Code to Analyze
{code_content}

---

## Your Task

1. Review ALL the code provided above
2. Pay special attention to the semantic search results - these are areas where dangerous patterns were found
3. Identify every potential security vulnerability
4. For each vulnerability, determine:
   - Is this a real exploitable issue or false positive?
   - What type of vulnerability is it?
   - How severe is it (using the scoring matrix)?
   - How would an attacker exploit it?

Respond with a JSON array of vulnerabilities:

```json
{{
    "vulnerabilities": [
        {{
            "title": "<descriptive title>",
            "vuln_type": "<sql_injection|command_injection|xss_stored|xss_reflected|path_traversal|ssrf|insecure_deserialization|xxe|auth_bypass|idor|csrf|rce|private_key_leak|reentrancy|lpe|dos|open_redirect|other>",
            "severity": "<critical|high|medium|low>",
            "score": <0-100>,
            "file_path": "<relative path to file>",
            "line_number": <line number>,
            "code_snippet": "<the vulnerable code>",
            "description": "<detailed description of the vulnerability>",
            "attack_scenario": "<how an attacker would exploit this>",
            "cwe_id": "<CWE-XXX>",
            "confidence": <0.0-1.0>
        }}
    ],
    "analysis_summary": {{
        "total_files_analyzed": <number>,
        "high_risk_areas": ["<area1>", "<area2>"],
        "recommended_focus": "<what the verifier should pay attention to>"
    }}
}}
```

Be thorough - examine every function, every input handler, every database query.
Do NOT miss real vulnerabilities, but also don't report obvious false positives."""

    def __init__(self, llm: Any = None, tools: list[Any] | None = None) -> None:
        """Initialize the Hunter agent."""
        super().__init__(llm, tools)

    def get_system_prompt(self) -> str:
        """Get the system prompt."""
        return self.SYSTEM_PROMPT

    async def execute(self, state: AgentState) -> AgentResult:
        """Execute vulnerability hunting using LLM analysis.

        The LLM is the PRIMARY decision maker. We gather information using
        tools, then send everything to the LLM for analysis.

        Args:
            state: Current workflow state.

        Returns:
            AgentResult with vulnerability candidates.
        """
        target_path = Path(state.target_path)
        errors: list[str] = []

        if not target_path.exists():
            return AgentResult(
                agent_type=self.agent_type,
                success=False,
                errors=[f"Target path does not exist: {target_path}"],
            )

        # Get context from state
        attack_surface = state.attack_surface
        feedback = state.hunter_verifier_state.feedback

        # Step 1: Gather information using tools (no decisions yet)

        # 1a. Run SAST tools to get hints
        sast_findings = await self._run_sast_tools(target_path)

        # 1b. Use semantic search to find high-risk code patterns
        semantic_results = await self._search_vulnerability_patterns(state.session_id)

        # 1c. Read the actual source code (prioritize files from semantic search)
        priority_files = self._extract_priority_files(semantic_results)
        code_content = await self._read_source_code(target_path, priority_files=priority_files)

        # 1d. Format attack surface context
        attack_surface_context = self._format_attack_surface(attack_surface)

        # 1e. Format languages and frameworks
        languages = self._get_languages(attack_surface)
        frameworks = self._get_frameworks(attack_surface)

        # 1f. Format SAST findings as hints
        sast_hints = self._format_sast_findings(sast_findings)

        # 1g. Format semantic search results
        semantic_hints = self._format_semantic_results(semantic_results)

        # 1h. Include feedback from previous iterations
        if feedback:
            attack_surface_context += f"\n\n### Feedback from Previous Iteration:\n"
            for fb in feedback:
                attack_surface_context += f"- {fb}\n"

        # Step 2: Send everything to LLM for analysis (LLM makes ALL decisions)
        candidates = await self._analyze_with_llm(
            target_path=str(target_path),
            languages=languages,
            frameworks=frameworks,
            attack_surface_context=attack_surface_context,
            semantic_search_results=semantic_hints,
            sast_findings=sast_hints,
            code_content=code_content,
        )

        # Step 3: Deduplicate results
        candidates = self._deduplicate_candidates(candidates)

        # Sort by score (LLM already assigned scores)
        candidates.sort(key=lambda v: (v.score, v.confidence), reverse=True)

        # Limit to top 50
        candidates = candidates[:50]

        return AgentResult(
            agent_type=self.agent_type,
            success=True,
            output={"candidates": candidates},
            errors=errors,
            next_agent=AgentType.VERIFIER,
        )

    async def _run_sast_tools(self, target_path: Path) -> list[Any]:
        """Run SAST tools to gather findings (as hints for LLM).

        These findings are NOT decisions - they're hints for the LLM to consider.
        Uses the unified ToolsService which routes to Docker/Local/MCP backends.

        Args:
            target_path: Path to the target codebase.

        Returns:
            List of SASTFinding objects (or tool results converted to findings).
        """
        try:
            from mrzero.core.tools_service import get_initialized_tools_service
            from mrzero.core.sast_runner import SASTFinding

            # Get initialized tools service
            tools_service = await get_initialized_tools_service()

            # Run all available SAST/secret/dependency tools
            results = await tools_service.run_all_sast(target_path)

            # Convert tool results to SASTFinding objects for compatibility
            findings = []
            for result in results:
                if not result.success or not result.output:
                    continue

                # Parse results based on tool
                if result.tool == "opengrep" and isinstance(result.output, dict):
                    for item in result.output.get("results", []):
                        findings.append(
                            SASTFinding(
                                rule_id=item.get("check_id", "unknown"),
                                message=item.get("extra", {}).get("message", ""),
                                severity=item.get("extra", {}).get("severity", "WARNING"),
                                file_path=item.get("path", ""),
                                line_start=item.get("start", {}).get("line", 0),
                                line_end=item.get("end", {}).get("line", 0),
                                code_snippet=item.get("extra", {}).get("lines", ""),
                                tool="opengrep",
                                metadata=item.get("extra", {}).get("metadata", {}),
                            )
                        )

                elif result.tool == "gitleaks" and isinstance(result.output, list):
                    for item in result.output:
                        findings.append(
                            SASTFinding(
                                rule_id=item.get("RuleID", "secret"),
                                message=f"Secret detected: {item.get('Description', 'Unknown secret')}",
                                severity="HIGH",
                                file_path=item.get("File", ""),
                                line_start=item.get("StartLine", 0),
                                line_end=item.get("EndLine", 0),
                                code_snippet=item.get("Secret", "")[:50] + "...",
                                tool="gitleaks",
                                metadata={
                                    "entropy": item.get("Entropy", 0),
                                    "match": item.get("Match", ""),
                                },
                            )
                        )

                elif result.tool == "trivy" and isinstance(result.output, dict):
                    for trivy_result in result.output.get("Results", []):
                        target = trivy_result.get("Target", "")
                        for vuln in trivy_result.get("Vulnerabilities", []) or []:
                            findings.append(
                                SASTFinding(
                                    rule_id=vuln.get("VulnerabilityID", "unknown"),
                                    message=vuln.get("Title", "") or vuln.get("Description", ""),
                                    severity=vuln.get("Severity", "UNKNOWN"),
                                    file_path=target,
                                    line_start=0,
                                    line_end=0,
                                    code_snippet=f"{vuln.get('PkgName', '')}@{vuln.get('InstalledVersion', '')}",
                                    tool="trivy",
                                    metadata={
                                        "cve": vuln.get("VulnerabilityID", ""),
                                        "fixed_version": vuln.get("FixedVersion", ""),
                                    },
                                )
                            )

                elif result.tool == "slither" and isinstance(result.output, dict):
                    for detector in result.output.get("results", {}).get("detectors", []):
                        elements = detector.get("elements", [])
                        first_element = elements[0] if elements else {}
                        findings.append(
                            SASTFinding(
                                rule_id=detector.get("check", "unknown"),
                                message=detector.get("description", ""),
                                severity=detector.get("impact", "Medium").upper(),
                                file_path=first_element.get("source_mapping", {}).get(
                                    "filename_relative", ""
                                ),
                                line_start=first_element.get("source_mapping", {}).get(
                                    "lines", [0]
                                )[0],
                                line_end=first_element.get("source_mapping", {}).get("lines", [0])[
                                    -1
                                ]
                                if first_element.get("source_mapping", {}).get("lines")
                                else 0,
                                code_snippet="",
                                tool="slither",
                                metadata={
                                    "confidence": detector.get("confidence", ""),
                                    "elements": len(elements),
                                },
                            )
                        )

            return findings

        except ImportError:
            # Fallback to legacy SASTRunner if ToolsService not available
            try:
                from mrzero.core.sast_runner import SASTRunner

                runner = SASTRunner(target_path)
                return await runner.run_all_available()
            except Exception:
                return []
        except Exception:
            return []

    async def _search_vulnerability_patterns(
        self, session_id: str
    ) -> dict[str, list[dict[str, Any]]]:
        """Use VectorDB semantic search to find high-risk code patterns.

        This searches for patterns commonly associated with vulnerabilities
        like SQL injection, command injection, XSS, etc.

        Args:
            session_id: Session ID for accessing the indexed codebase.

        Returns:
            Dict mapping vulnerability types to relevant code chunks.
        """
        try:
            from mrzero.core.indexing import get_indexer

            indexer = get_indexer(session_id)
            self._indexer = indexer

            results = {}

            # Search for common vulnerability patterns
            vuln_types = [
                "sql_injection",
                "command_injection",
                "xss",
                "path_traversal",
                "ssrf",
                "deserialization",
                "authentication",
                "secrets",
            ]

            for vuln_type in vuln_types:
                findings = indexer.search_vulnerability_patterns(vuln_type, n_results=10)
                if findings:
                    results[vuln_type] = findings

            # Also search for entry points and data sinks
            entry_points = indexer.search_entry_points(n_results=15)
            if entry_points:
                results["entry_points"] = entry_points

            data_sinks = indexer.search_data_sinks(n_results=15)
            if data_sinks:
                results["data_sinks"] = data_sinks

            return results

        except Exception:
            return {}

    def _extract_priority_files(
        self, semantic_results: dict[str, list[dict[str, Any]]]
    ) -> list[str]:
        """Extract file paths from semantic search results for prioritization.

        Args:
            semantic_results: Results from semantic search.

        Returns:
            List of file paths that should be prioritized.
        """
        priority_files = set()

        for vuln_type, results in semantic_results.items():
            for result in results[:5]:  # Top 5 per category
                metadata = result.get("metadata", {})
                file_path = metadata.get("file_path", "")
                if file_path:
                    priority_files.add(file_path)

        return list(priority_files)

    def _format_semantic_results(self, semantic_results: dict[str, list[dict[str, Any]]]) -> str:
        """Format semantic search results for the LLM prompt.

        Args:
            semantic_results: Results from semantic search.

        Returns:
            Formatted string.
        """
        if not semantic_results:
            return "No semantic search results (VectorDB may not be indexed)."

        parts = [
            "The following code sections were identified through semantic analysis as potentially security-relevant:\n"
        ]

        for vuln_type, results in semantic_results.items():
            if not results:
                continue

            # Format vulnerability type nicely
            type_display = vuln_type.replace("_", " ").title()
            parts.append(f"\n### {type_display} Related Code:")

            for i, result in enumerate(results[:5], 1):  # Limit to 5 per type
                metadata = result.get("metadata", {})
                file_path = metadata.get("file_path", "unknown")
                start_line = metadata.get("start_line", 0)
                end_line = metadata.get("end_line", 0)
                relevance = result.get("relevance", 0)
                content = result.get("content", "")[:500]  # Truncate content

                parts.append(
                    f"\n**{i}. {file_path}:{start_line}-{end_line}** (relevance: {relevance:.2f})"
                )
                parts.append(f"```\n{content}\n```")

                # Include matched patterns if available
                matched_patterns = result.get("matched_patterns", [])
                if matched_patterns:
                    parts.append(f"Matched patterns: {', '.join(matched_patterns[:3])}")

        return "\n".join(parts)

    async def _read_source_code(
        self,
        target_path: Path,
        max_files: int = 50,
        max_lines_per_file: int = 500,
        priority_files: list[str] | None = None,
    ) -> str:
        """Read source code files for LLM analysis.

        Args:
            target_path: Path to the codebase.
            max_files: Maximum number of files to read.
            max_lines_per_file: Maximum lines per file.
            priority_files: List of file paths to prioritize (from semantic search).

        Returns:
            Formatted source code content.
        """
        code_extensions = {
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".java",
            ".go",
            ".rb",
            ".php",
            ".sol",
            ".vy",
            ".c",
            ".cpp",
            ".cs",
        }

        content_parts = []
        files_read = 0
        priority_files_set = set(priority_files) if priority_files else set()

        # Prioritize files that are likely to have vulnerabilities
        priority_keywords = [
            "api",
            "route",
            "controller",
            "view",
            "handler",
            "auth",
            "login",
            "user",
            "admin",
            "query",
            "exec",
        ]

        all_files = []
        for file_path in target_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() not in code_extensions:
                continue
            # Skip test files, node_modules, venv, etc.
            path_str = str(file_path).lower()
            if any(
                skip in path_str
                for skip in [
                    "/test",
                    "node_modules",
                    "venv",
                    ".venv",
                    "__pycache__",
                    "/dist/",
                    "/build/",
                ]
            ):
                continue

            # Calculate priority score
            priority = 0

            # Boost files identified by semantic search
            if str(file_path) in priority_files_set:
                priority += 10

            for keyword in priority_keywords:
                if keyword in path_str:
                    priority += 1

            all_files.append((priority, file_path))

        # Sort by priority (highest first)
        all_files.sort(key=lambda x: -x[0])

        for _, file_path in all_files[:max_files]:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                lines = content.split("\n")

                # Truncate if too long
                if len(lines) > max_lines_per_file:
                    lines = lines[:max_lines_per_file]
                    lines.append(
                        f"\n... [truncated, {len(content.split(chr(10))) - max_lines_per_file} more lines]"
                    )

                rel_path = str(file_path.relative_to(target_path))

                # Format with line numbers
                numbered_lines = [f"{i + 1:4d} | {line}" for i, line in enumerate(lines)]

                content_parts.append(
                    f"\n### File: {rel_path}\n```\n" + "\n".join(numbered_lines) + "\n```\n"
                )
                files_read += 1

            except Exception:
                continue

        if not content_parts:
            return "No source code files found."

        return f"## Source Code ({files_read} files)\n" + "\n".join(content_parts)

    def _format_attack_surface(self, attack_surface: Any) -> str:
        """Format attack surface information for LLM.

        Args:
            attack_surface: Attack surface map from Mapper.

        Returns:
            Formatted string.
        """
        if not attack_surface:
            return "No attack surface information available."

        parts = []

        # Endpoints (entry points)
        if attack_surface.endpoints:
            parts.append("### Entry Points (API Endpoints)")
            for ep in attack_surface.endpoints[:20]:
                auth_status = "Authenticated" if ep.authenticated else "UNAUTHENTICATED"
                parts.append(
                    f"- {ep.method} {ep.path} ({ep.file_path}:{ep.line_number}) - {auth_status}"
                )

        # Data flows
        if attack_surface.data_flows:
            parts.append("\n### Data Flows (Source -> Sink)")
            for flow in attack_surface.data_flows[:15]:
                taint_status = "TAINTED (no sanitization)" if flow.tainted else "Sanitized"
                parts.append(
                    f"- {flow.source} -> {flow.sink} ({flow.source_file}:{flow.source_line}) - {taint_status}"
                )

        # Auth boundaries
        if attack_surface.auth_boundaries:
            parts.append("\n### Authentication-Related Files")
            for boundary in attack_surface.auth_boundaries[:10]:
                parts.append(f"- {boundary}")

        return "\n".join(parts) if parts else "No attack surface details available."

    def _get_languages(self, attack_surface: Any) -> str:
        """Get languages from attack surface."""
        if not attack_surface or not attack_surface.languages:
            return "Unknown"
        return ", ".join(lang.name for lang in attack_surface.languages[:5])

    def _get_frameworks(self, attack_surface: Any) -> str:
        """Get frameworks from attack surface."""
        if not attack_surface or not attack_surface.frameworks:
            return "Unknown"
        return ", ".join(f"{fw.name} {fw.version or ''}" for fw in attack_surface.frameworks[:5])

    def _format_sast_findings(self, findings: list[Any]) -> str:
        """Format SAST findings as hints for LLM.

        Args:
            findings: List of SAST findings.

        Returns:
            Formatted string.
        """
        if not findings:
            return "No SAST tool findings (tools may not be installed)."

        parts = [
            "These are hints from automated SAST tools. Use them as starting points but make your own assessment:\n"
        ]

        for i, finding in enumerate(findings[:30], 1):
            parts.append(
                f"{i}. [{finding.severity}] {finding.rule_id}\n"
                f"   File: {finding.file_path}:{finding.line_start}\n"
                f"   Message: {finding.message[:200]}\n"
                f"   Code: {finding.code_snippet[:150] if finding.code_snippet else 'N/A'}\n"
            )

        return "\n".join(parts)

    async def _analyze_with_llm(
        self,
        target_path: str,
        languages: str,
        frameworks: str,
        attack_surface_context: str,
        semantic_search_results: str,
        sast_findings: str,
        code_content: str,
    ) -> list[Vulnerability]:
        """Send all gathered information to LLM for vulnerability analysis.

        The LLM makes ALL decisions about what constitutes a vulnerability.

        Args:
            target_path: Path to target.
            languages: Detected languages.
            frameworks: Detected frameworks.
            attack_surface_context: Attack surface info.
            semantic_search_results: Semantic search hints from VectorDB.
            sast_findings: SAST tool hints.
            code_content: Actual source code.

        Returns:
            List of vulnerabilities identified by LLM.
        """
        prompt = self.HUNT_PROMPT.format(
            target_path=target_path,
            languages=languages,
            frameworks=frameworks,
            attack_surface_context=attack_surface_context,
            semantic_search_results=semantic_search_results,
            sast_findings=sast_findings,
            code_content=code_content,
        )

        try:
            response = await self.chat(prompt)
            return self._parse_llm_response(response)
        except Exception as e:
            # If LLM fails, return empty list (don't fall back to regex)
            return []

    def _parse_llm_response(self, response: str) -> list[Vulnerability]:
        """Parse LLM response into Vulnerability objects.

        Args:
            response: Raw LLM response.

        Returns:
            List of Vulnerability objects.
        """
        import re

        vulnerabilities = []

        try:
            # Find JSON in response
            json_match = re.search(r"```json\s*([\s\S]*?)\s*```", response)
            if json_match:
                data = json.loads(json_match.group(1))
            else:
                # Try to find raw JSON
                json_match = re.search(r"\{[\s\S]*\}", response)
                if json_match:
                    data = json.loads(json_match.group())
                else:
                    return []

            vuln_list = data.get("vulnerabilities", [])

            for vuln_data in vuln_list:
                try:
                    # Map vuln_type string to enum
                    vuln_type = self._map_vuln_type(vuln_data.get("vuln_type", "other"))

                    # Map severity string to enum
                    severity = self._map_severity(vuln_data.get("severity", "medium"))

                    vulnerabilities.append(
                        Vulnerability(
                            id=f"LLM-{uuid.uuid4().hex[:8]}",
                            vuln_type=vuln_type,
                            severity=severity,
                            score=vuln_data.get("score", 50),
                            status=VulnerabilityStatus.CANDIDATE,
                            title=vuln_data.get("title", "Unknown Vulnerability"),
                            description=vuln_data.get("description", ""),
                            file_path=vuln_data.get("file_path", ""),
                            line_number=vuln_data.get("line_number", 0),
                            code_snippet=vuln_data.get("code_snippet", ""),
                            cwe_id=vuln_data.get("cwe_id", ""),
                            tool_source="llm_analysis",
                            confidence=vuln_data.get("confidence", 0.7),
                        )
                    )
                except Exception:
                    continue

        except json.JSONDecodeError:
            pass

        return vulnerabilities

    def _map_vuln_type(self, vuln_type_str: str) -> VulnerabilityType:
        """Map vulnerability type string to enum."""
        mapping = {
            "sql_injection": VulnerabilityType.SQL_INJECTION,
            "command_injection": VulnerabilityType.COMMAND_INJECTION,
            "xss_stored": VulnerabilityType.STORED_XSS,
            "xss_reflected": VulnerabilityType.REFLECTED_XSS,
            "path_traversal": VulnerabilityType.PATH_TRAVERSAL,
            "ssrf": VulnerabilityType.SSRF,
            "insecure_deserialization": VulnerabilityType.INSECURE_DESERIALIZATION,
            "xxe": VulnerabilityType.XXE,
            "auth_bypass": VulnerabilityType.AUTH_BYPASS,
            "idor": VulnerabilityType.IDOR,
            "csrf": VulnerabilityType.CSRF,
            "rce": VulnerabilityType.RCE,
            "private_key_leak": VulnerabilityType.PRIVATE_KEY_LEAK,
            "reentrancy": VulnerabilityType.REENTRANCY,
            "lpe": VulnerabilityType.LPE,
            "dos": VulnerabilityType.DOS,
            "open_redirect": VulnerabilityType.OPEN_REDIRECT,
            "lfi": VulnerabilityType.LFI,
        }
        return mapping.get(vuln_type_str.lower(), VulnerabilityType.OTHER)

    def _map_severity(self, severity_str: str) -> VulnerabilitySeverity:
        """Map severity string to enum."""
        mapping = {
            "critical": VulnerabilitySeverity.CRITICAL,
            "high": VulnerabilitySeverity.HIGH,
            "medium": VulnerabilitySeverity.MEDIUM,
            "low": VulnerabilitySeverity.LOW,
            "info": VulnerabilitySeverity.INFO,
        }
        return mapping.get(severity_str.lower(), VulnerabilitySeverity.MEDIUM)

    def _deduplicate_candidates(self, candidates: list[Vulnerability]) -> list[Vulnerability]:
        """Remove duplicate findings based on file+line+type.

        Args:
            candidates: List of candidates.

        Returns:
            Deduplicated list.
        """
        seen = set()
        unique = []

        for candidate in candidates:
            key = f"{candidate.file_path}:{candidate.line_number}:{candidate.vuln_type.value}"
            if key not in seen:
                seen.add(key)
                unique.append(candidate)

        return unique
