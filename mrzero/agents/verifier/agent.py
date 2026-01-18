"""MrZeroVerifier - LLM-Powered False Positive Filter Agent."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from mrzero.agents.base import AgentResult, AgentType, BaseAgent
from mrzero.core.memory.state import AgentState
from mrzero.core.schemas import (
    Vulnerability,
    VulnerabilityStatus,
)


class VerifierAgent(BaseAgent):
    """Agent for verifying vulnerabilities and filtering false positives.

    This agent uses LLM reasoning as the PRIMARY decision maker for determining
    whether vulnerability candidates are true positives or false positives.
    The LLM analyzes the code context, data flow, and security patterns to make
    informed decisions.

    Enhanced with VectorDB integration for semantic context retrieval, allowing
    the agent to understand related code patterns across the codebase.
    """

    agent_type = AgentType.VERIFIER
    _indexer = None  # Lazy-loaded code indexer for semantic search

    # System prompt that defines the LLM's role and expertise
    # This can be customized/replaced with your own prompt
    SYSTEM_PROMPT = """You are MrZeroVerifier, an elite security researcher specialized in vulnerability verification and false positive elimination.

## Your Role
You receive vulnerability candidates identified by static analysis tools (SAST) and must determine which are TRUE VULNERABILITIES vs FALSE POSITIVES.

## Your Expertise
- Deep understanding of common vulnerability classes (SQLi, XSS, Command Injection, Path Traversal, SSRF, Deserialization, etc.)
- Expert knowledge of security frameworks and their built-in protections
- Ability to trace data flow from user input (sources) to dangerous operations (sinks)
- Understanding of sanitization functions and their effectiveness
- Recognition of security anti-patterns and secure coding practices

## Analysis Methodology
For each vulnerability candidate, you MUST analyze:

1. **Source Analysis**: Where does the potentially malicious data originate?
   - User input (request params, body, headers, cookies)
   - Database values (could be user-controlled)
   - File contents
   - Environment variables
   - Hardcoded values (NOT user-controlled)

2. **Sink Analysis**: What dangerous operation receives this data?
   - SQL queries (execute, raw, query)
   - Command execution (system, exec, popen, subprocess with shell=True)
   - File operations (open, read, write with dynamic paths)
   - HTML rendering (innerHTML, document.write, template without escaping)
   - Deserialization (pickle, yaml.load, unserialize)

3. **Data Flow Analysis**: Trace the path from source to sink
   - Is user input directly concatenated/formatted into the dangerous operation?
   - Are there any sanitization/validation functions in between?
   - Is the data transformed in a way that neutralizes the threat?

4. **Context Analysis**: 
   - Is this code actually reachable in production?
   - Is it in a test file, example, or documentation?
   - Is the vulnerable code commented out or behind a feature flag?
   - Does the framework provide automatic protection?

5. **Exploitability Assessment**:
   - Can an attacker actually control the malicious input?
   - Are there other security controls that would prevent exploitation?
   - What's the realistic attack scenario?

## Decision Criteria

**Mark as CONFIRMED (True Positive) when:**
- User-controlled input flows to a dangerous sink WITHOUT proper sanitization
- The code is reachable in production
- An attacker could realistically exploit this

**Mark as FALSE POSITIVE when:**
- Input is properly sanitized/validated before reaching the sink
- The "vulnerability" is in test code, examples, or documentation
- The data is NOT user-controlled (hardcoded, config values)
- Framework provides automatic protection (e.g., ORM parameterization, template auto-escaping)
- The vulnerable code path is unreachable

## Important Guidelines
- Be THOROUGH but not overly paranoid - real vulnerabilities DO exist
- Don't assume sanitization exists without seeing it in the code
- Consider the SPECIFIC code shown, not general framework capabilities
- When in doubt, lean towards CONFIRMED (better to report than miss)
- Provide DETAILED reasoning for each decision"""

    # Prompt template for vulnerability verification
    VERIFICATION_PROMPT = """## Task: Verify Vulnerability Candidates

Analyze each vulnerability candidate below and determine if it's a TRUE POSITIVE (real vulnerability) or FALSE POSITIVE.

---

## Candidates to Verify:

{candidates}

---

## Code Context for Each Candidate:

{contexts}

---

## Your Analysis

For EACH candidate, provide:
1. Source identification - where does the data come from?
2. Sink identification - what dangerous operation is performed?
3. Data flow analysis - is there sanitization between source and sink?
4. Exploitability assessment - can this realistically be exploited?
5. Final verdict with confidence level

Respond in this exact JSON format:
```json
{{
    "verifications": [
        {{
            "vuln_id": "<the vulnerability ID>",
            "verdict": "confirmed" | "false_positive",
            "confidence": <0.0 to 1.0>,
            "source": "<what is the data source>",
            "sink": "<what is the dangerous sink>",
            "sanitization_present": <true|false>,
            "sanitization_effective": <true|false|null if not present>,
            "reasoning": "<detailed explanation of your analysis>",
            "exploitability": "high" | "medium" | "low" | "none",
            "attack_scenario": "<if confirmed, how would an attacker exploit this>"
        }}
    ],
    "summary": {{
        "total_analyzed": <number>,
        "confirmed_count": <number>,
        "false_positive_count": <number>,
        "high_priority_findings": ["<list of most critical confirmed vulns>"]
    }},
    "feedback_for_hunter": [
        "<patterns that consistently produce false positives to avoid>",
        "<areas that need deeper investigation>"
    ]
}}
```"""

    def __init__(self, llm: Any = None, tools: list[Any] | None = None) -> None:
        """Initialize the Verifier agent."""
        super().__init__(llm, tools)

    def get_system_prompt(self) -> str:
        """Get the system prompt for the LLM."""
        return self.SYSTEM_PROMPT

    async def execute(self, state: AgentState) -> AgentResult:
        """Execute vulnerability verification using LLM analysis.

        The LLM is the PRIMARY decision maker. We only do minimal pre-filtering
        for obvious non-issues (test files, commented code) to save LLM tokens.

        Args:
            state: Current workflow state.

        Returns:
            AgentResult with confirmed and false positive lists.
        """
        target_path = Path(state.target_path)
        candidates = state.hunter_verifier_state.candidates
        confirmed: list[Vulnerability] = []
        false_positives: list[Vulnerability] = []
        feedback: list[str] = []
        errors: list[str] = []

        if not candidates:
            return AgentResult(
                agent_type=self.agent_type,
                success=True,
                output={
                    "confirmed": [],
                    "false_positives": [],
                    "feedback": ["No candidates to verify"],
                },
                next_agent=AgentType.REPORTER,
            )

        # Step 1: Minimal pre-filtering (only obvious non-issues)
        candidates_for_llm = []
        for candidate in candidates:
            is_obvious_fp, reason = self._check_obvious_false_positive(target_path, candidate)
            if is_obvious_fp:
                candidate_copy = candidate.model_copy()
                candidate_copy.status = VulnerabilityStatus.FALSE_POSITIVE
                false_positives.append(candidate_copy)
                feedback.append(f"PRE_FILTER:{candidate.id}:{reason}")
            else:
                candidates_for_llm.append(candidate)

        # Step 2: LLM-based verification (the main decision maker)
        if candidates_for_llm:
            llm_confirmed, llm_fps, llm_feedback = await self._verify_with_llm(
                target_path, candidates_for_llm, session_id=state.session_id
            )
            confirmed.extend(llm_confirmed)
            false_positives.extend(llm_fps)
            feedback.extend(llm_feedback)

        # Step 3: Mark confirmed vulnerabilities with timestamp
        for vuln in confirmed:
            vuln.status = VulnerabilityStatus.CONFIRMED
            vuln.verified_at = datetime.now()

        # Sort confirmed by score (highest first)
        confirmed.sort(key=lambda v: (v.score, v.confidence), reverse=True)

        # Step 4: Determine next agent based on results
        next_agent = self._determine_next_agent(state, confirmed)

        # Generate iteration feedback if needed
        if next_agent == AgentType.HUNTER:
            iteration = state.hunter_verifier_state.iteration_count
            feedback.append(f"ITERATE:iteration_{iteration + 1}:found_{len(confirmed)}_confirmed")

        return AgentResult(
            agent_type=self.agent_type,
            success=True,
            output={
                "confirmed": confirmed,
                "false_positives": false_positives,
                "feedback": feedback,
            },
            errors=errors,
            next_agent=next_agent,
        )

    def _check_obvious_false_positive(
        self, target_path: Path, vuln: Vulnerability
    ) -> tuple[bool, str]:
        """Check for obvious false positives that don't need LLM analysis.

        Only filters out candidates that are OBVIOUSLY not real vulnerabilities
        to save LLM tokens. When in doubt, let the LLM decide.

        Args:
            target_path: Path to the codebase.
            vuln: Vulnerability to check.

        Returns:
            Tuple of (is_obvious_fp, reason).
        """
        file_path = target_path / vuln.file_path

        # Check 1: File doesn't exist
        if not file_path.exists():
            return True, "file_not_found"

        # Check 2: Test file (very likely not production code)
        path_str = str(vuln.file_path).lower()
        test_indicators = [
            "/test_",
            "/_test",
            "/tests/",
            "/test/",
            "/spec/",
            "/__tests__/",
            "/__mocks__/",
            "_test.py",
            "_test.js",
            "_test.ts",
            ".test.py",
            ".test.js",
            ".test.ts",
            "_spec.py",
            "_spec.js",
            "_spec.ts",
            ".spec.py",
            ".spec.js",
            ".spec.ts",
        ]
        if any(indicator in path_str for indicator in test_indicators):
            return True, "test_file"

        # Check 3: Example/documentation file
        doc_indicators = [
            "/examples/",
            "/example/",
            "/docs/",
            "/doc/",
            "/samples/",
            "/sample/",
            "/demo/",
            "/demos/",
            "readme",
            "example.py",
            "example.js",
        ]
        if any(indicator in path_str for indicator in doc_indicators):
            return True, "documentation_or_example"

        # Check 4: Vulnerable line is commented out
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.split("\n")
            if vuln.line_number <= len(lines):
                vulnerable_line = lines[vuln.line_number - 1].strip()
                if vulnerable_line.startswith("#") or vulnerable_line.startswith("//"):
                    return True, "commented_out"
                if vulnerable_line.startswith("*") or vulnerable_line.startswith("/*"):
                    return True, "commented_out"
        except Exception:
            pass

        # Not an obvious FP - let LLM analyze it
        return False, ""

    async def _verify_with_llm(
        self,
        target_path: Path,
        candidates: list[Vulnerability],
        session_id: str | None = None,
    ) -> tuple[list[Vulnerability], list[Vulnerability], list[str]]:
        """Use LLM to verify vulnerability candidates.

        This is the PRIMARY verification method. The LLM analyzes each candidate
        with full code context and makes the determination.

        Args:
            target_path: Path to codebase.
            candidates: Candidates to verify.
            session_id: Session ID for VectorDB access.

        Returns:
            Tuple of (confirmed, false_positives, feedback).
        """
        confirmed = []
        false_positives = []
        feedback = []

        # Build detailed candidate descriptions
        candidate_strs = []
        contexts = []

        for candidate in candidates:
            # Format candidate info (handle None values)
            code_snippet = (candidate.code_snippet or "")[:200]
            description = (candidate.description or "")[:300]

            candidate_strs.append(
                f"### Candidate: {candidate.id}\n"
                f"- **Type:** {candidate.vuln_type.value}\n"
                f"- **File:** `{candidate.file_path}`\n"
                f"- **Line:** {candidate.line_number}\n"
                f"- **Severity Score:** {candidate.score}\n"
                f"- **Detection Tool:** {candidate.tool_source}\n"
                f"- **Tool Confidence:** {candidate.confidence:.0%}\n"
                f"- **Code Snippet:** `{code_snippet}`\n"
                f"- **Description:** {description}\n"
            )

            # Get extended code context (from file + semantic search)
            context = self._get_code_context(target_path, candidate)

            # Also get semantic context from VectorDB if available
            semantic_context = await self._get_semantic_context(session_id, candidate)

            full_context = context
            if semantic_context:
                full_context += f"\n\n### Related Code (from semantic search):\n{semantic_context}"

            if full_context:
                contexts.append(f"### Context for {candidate.id}:\n```\n{full_context}\n```\n")

        # Build the prompt
        prompt = self.VERIFICATION_PROMPT.format(
            candidates="\n".join(candidate_strs),
            contexts="\n".join(contexts) if contexts else "No additional context available.",
        )

        try:
            # Call LLM with system prompt
            response = await self.chat(prompt)

            # Parse the JSON response
            llm_results = self._parse_llm_response(response)

            if llm_results:
                # Apply LLM decisions
                confirmed, false_positives, feedback = self._apply_llm_decisions(
                    candidates, llm_results
                )
            else:
                # LLM response parsing failed - keep all as candidates
                # (conservative: don't filter without LLM decision)
                confirmed = [c.model_copy() for c in candidates]
                feedback.append("LLM_PARSE_FAILED:keeping_all_candidates")

        except Exception as e:
            # LLM call failed - keep all candidates (conservative approach)
            confirmed = [c.model_copy() for c in candidates]
            feedback.append(f"LLM_ERROR:{str(e)[:100]}")

        return confirmed, false_positives, feedback

    async def _get_semantic_context(
        self,
        session_id: str | None,
        vuln: Vulnerability,
    ) -> str:
        """Get semantic context from VectorDB for a vulnerability.

        Searches for related code patterns that might help understand
        the vulnerability context (e.g., sanitization functions, similar patterns).

        Args:
            session_id: Session ID for VectorDB access.
            vuln: Vulnerability to get context for.

        Returns:
            Formatted semantic context string.
        """
        if not session_id:
            return ""

        try:
            from mrzero.core.indexing import get_indexer

            indexer = get_indexer(session_id)
            self._indexer = indexer

            # Search for related code based on vulnerability type
            vuln_type_queries = {
                "sql_injection": [
                    "input sanitization SQL",
                    "parameterized query",
                    "SQL escape function",
                ],
                "command_injection": ["command sanitization", "shell escape", "subprocess safe"],
                "xss_stored": ["HTML encoding", "XSS sanitizer", "output escaping"],
                "xss_reflected": ["HTML encoding", "XSS sanitizer", "output escaping"],
                "path_traversal": [
                    "path validation",
                    "filename sanitization",
                    "directory traversal check",
                ],
                "ssrf": ["URL validation", "allowed hosts", "SSRF protection"],
                "insecure_deserialization": [
                    "safe deserialization",
                    "pickle alternative",
                    "JSON safe load",
                ],
            }

            # Get queries for this vulnerability type
            vuln_type_str = vuln.vuln_type.value.lower()
            queries = vuln_type_queries.get(vuln_type_str, [f"{vuln_type_str} protection"])

            # Search for related sanitization/protection code
            related_chunks = indexer.db.search_by_pattern(queries, n_results=3)

            if not related_chunks:
                return ""

            # Format the results
            parts = []
            for chunk in related_chunks[:3]:
                metadata = chunk.get("metadata", {})
                file_path = metadata.get("file_path", "unknown")
                start_line = metadata.get("start_line", 0)
                content = chunk.get("content", "")[:300]
                relevance = chunk.get("relevance", 0)

                parts.append(
                    f"**{file_path}:{start_line}** (relevance: {relevance:.2f})\n"
                    f"```\n{content}\n```"
                )

            return "\n".join(parts)

        except Exception:
            return ""

    def _get_code_context(
        self, target_path: Path, vuln: Vulnerability, context_lines: int = 25
    ) -> str:
        """Get extended code context around the vulnerable line.

        Args:
            target_path: Path to codebase.
            vuln: Vulnerability to get context for.
            context_lines: Number of lines before and after.

        Returns:
            Code context with line numbers.
        """
        try:
            file_path = target_path / vuln.file_path
            if not file_path.exists():
                return ""

            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.split("\n")

            start = max(0, vuln.line_number - context_lines - 1)
            end = min(len(lines), vuln.line_number + context_lines)

            context_lines_with_numbers = []
            for i in range(start, end):
                line_num = i + 1
                marker = " >>> " if line_num == vuln.line_number else "     "
                context_lines_with_numbers.append(f"{line_num:4d}{marker}{lines[i]}")

            return "\n".join(context_lines_with_numbers)

        except Exception:
            return ""

    def _parse_llm_response(self, response: str) -> dict[str, Any] | None:
        """Parse the LLM's JSON response.

        Args:
            response: Raw LLM response.

        Returns:
            Parsed JSON dict or None if parsing fails.
        """
        import re

        try:
            # Try to find JSON in the response
            # Look for ```json ... ``` blocks first
            json_block_match = re.search(r"```json\s*([\s\S]*?)\s*```", response)
            if json_block_match:
                return json.loads(json_block_match.group(1))

            # Try to find raw JSON object
            json_match = re.search(r"\{[\s\S]*\}", response)
            if json_match:
                return json.loads(json_match.group())

            return None

        except json.JSONDecodeError:
            return None

    def _apply_llm_decisions(
        self,
        candidates: list[Vulnerability],
        llm_results: dict[str, Any],
    ) -> tuple[list[Vulnerability], list[Vulnerability], list[str]]:
        """Apply LLM verification decisions to candidates.

        Args:
            candidates: Original candidates.
            llm_results: Parsed LLM results.

        Returns:
            Tuple of (confirmed, false_positives, feedback).
        """
        confirmed = []
        false_positives = []
        feedback = []

        verifications = llm_results.get("verifications", [])
        verification_map = {v.get("vuln_id"): v for v in verifications}

        for candidate in candidates:
            candidate_copy = candidate.model_copy()

            if candidate.id in verification_map:
                result = verification_map[candidate.id]
                verdict = result.get("verdict", "").lower()

                if verdict == "false_positive":
                    candidate_copy.status = VulnerabilityStatus.FALSE_POSITIVE
                    false_positives.append(candidate_copy)

                    reasoning = result.get("reasoning", "No reasoning provided")
                    feedback.append(f"LLM_FP:{candidate.id}:{reasoning[:150]}")
                else:
                    # confirmed or any other verdict - treat as confirmed
                    candidate_copy.status = VulnerabilityStatus.CONFIRMED

                    # Update confidence based on LLM assessment
                    if "confidence" in result:
                        candidate_copy.confidence = result["confidence"]

                    # Add attack scenario to description if provided
                    attack_scenario = result.get("attack_scenario", "")
                    if attack_scenario and attack_scenario != "N/A":
                        candidate_copy.description += f"\n\n**Attack Scenario:** {attack_scenario}"

                    confirmed.append(candidate_copy)
            else:
                # Candidate not in LLM results - keep as confirmed (conservative)
                confirmed.append(candidate_copy)

        # Extract feedback for hunter from LLM
        hunter_feedback = llm_results.get("feedback_for_hunter", [])
        feedback.extend(hunter_feedback)

        # Add summary info
        summary = llm_results.get("summary", {})
        if summary:
            feedback.append(
                f"LLM_SUMMARY:analyzed_{summary.get('total_analyzed', 0)}"
                f"_confirmed_{summary.get('confirmed_count', 0)}"
                f"_fp_{summary.get('false_positive_count', 0)}"
            )

        return confirmed, false_positives, feedback

    def _determine_next_agent(
        self, state: AgentState, confirmed: list[Vulnerability]
    ) -> AgentType | None:
        """Determine which agent should run next.

        Args:
            state: Current workflow state.
            confirmed: List of confirmed vulnerabilities.

        Returns:
            Next agent type or None.
        """
        hv_state = state.hunter_verifier_state
        confirmed_count = len(confirmed)

        # If we have enough confirmed vulnerabilities, proceed to env builder
        if confirmed_count >= hv_state.min_true_positives:
            return AgentType.ENV_BUILDER

        # If we've reached max iterations, decide based on what we have
        if hv_state.iteration_count >= hv_state.max_iterations:
            if confirmed_count > 0:
                return AgentType.ENV_BUILDER
            else:
                return AgentType.REPORTER  # No vulns found, generate report

        # Need more findings - go back to hunter
        return AgentType.HUNTER
