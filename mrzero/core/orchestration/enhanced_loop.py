"""Enhanced Hunter-Verifier Loop with Tool Calling Support.

This module provides an improved Hunter-Verifier feedback loop that:
1. Supports tool-calling mode for dynamic LLM-driven analysis
2. Better feedback mechanism between Verifier and Hunter
3. Vulnerability deduplication across iterations
4. Progressive context accumulation
5. Detailed metrics and logging

The loop follows this pattern:
1. Hunter finds vulnerability candidates
2. Verifier confirms or rejects candidates
3. Feedback is provided to Hunter for next iteration
4. Loop continues until exit conditions are met
"""

import json
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from mrzero.core.llm.providers import BaseLLMProvider
from mrzero.core.llm.agentic_loop import (
    ToolCallingLoop,
    TOOL_CALLING_HUNTER_PROMPT,
    TOOL_CALLING_VERIFIER_PROMPT,
)
from mrzero.core.llm.security_tools import create_security_tool_registry


@dataclass
class LoopMetrics:
    """Metrics for the Hunter-Verifier loop."""

    total_iterations: int = 0
    total_candidates_found: int = 0
    total_confirmed: int = 0
    total_false_positives: int = 0
    total_tool_calls: int = 0
    tools_used: set = field(default_factory=set)
    start_time: datetime | None = None
    end_time: datetime | None = None

    @property
    def duration_seconds(self) -> float:
        """Get the duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    @property
    def confirmation_rate(self) -> float:
        """Get the confirmation rate."""
        if self.total_candidates_found == 0:
            return 0.0
        return self.total_confirmed / self.total_candidates_found

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_iterations": self.total_iterations,
            "total_candidates_found": self.total_candidates_found,
            "total_confirmed": self.total_confirmed,
            "total_false_positives": self.total_false_positives,
            "total_tool_calls": self.total_tool_calls,
            "tools_used": list(self.tools_used),
            "duration_seconds": self.duration_seconds,
            "confirmation_rate": self.confirmation_rate,
        }


@dataclass
class IterationResult:
    """Result of a single Hunter-Verifier iteration."""

    iteration: int
    candidates: list[dict[str, Any]]
    confirmed: list[dict[str, Any]]
    false_positives: list[dict[str, Any]]
    feedback: list[str]
    hunter_tool_calls: list[dict[str, Any]]
    verifier_tool_calls: list[dict[str, Any]]


def _compute_vuln_hash(vuln: dict[str, Any]) -> str:
    """Compute a hash for vulnerability deduplication.

    Uses file path, line number, and vulnerability type to create a unique hash.
    """
    key = f"{vuln.get('file_path', '')}:{vuln.get('line_number', 0)}:{vuln.get('vuln_type', '')}"
    return hashlib.md5(key.encode()).hexdigest()[:12]


def _parse_vulnerabilities_from_response(response: str) -> list[dict[str, Any]]:
    """Parse vulnerabilities from LLM response."""
    import re

    try:
        # Find JSON in response
        json_match = re.search(r"```json\s*([\s\S]*?)\s*```", response)
        if json_match:
            data = json.loads(json_match.group(1))
        else:
            json_match = re.search(r"\{[\s\S]*\"vulnerabilities\"[\s\S]*\}", response)
            if json_match:
                data = json.loads(json_match.group())
            else:
                return []

        return data.get("vulnerabilities", [])
    except (json.JSONDecodeError, AttributeError):
        return []


def _parse_verifications_from_response(response: str) -> dict[str, Any]:
    """Parse verification results from LLM response."""
    import re

    try:
        json_match = re.search(r"```json\s*([\s\S]*?)\s*```", response)
        if json_match:
            data = json.loads(json_match.group(1))
        else:
            json_match = re.search(r"\{[\s\S]*\"verifications\"[\s\S]*\}", response)
            if json_match:
                data = json.loads(json_match.group())
            else:
                return {}

        return data
    except (json.JSONDecodeError, AttributeError):
        return {}


class EnhancedHunterVerifierLoop:
    """Enhanced Hunter-Verifier feedback loop with tool calling.

    This implements a sophisticated loop that:
    1. Uses LLM tool calling for dynamic analysis
    2. Maintains context across iterations
    3. Deduplicates vulnerabilities
    4. Provides structured feedback between agents
    """

    def __init__(
        self,
        llm_provider: BaseLLMProvider,
        max_iterations: int = 3,
        min_confirmed: int = 3,
        max_tool_calls_per_agent: int = 10,
    ) -> None:
        """Initialize the enhanced loop.

        Args:
            llm_provider: The LLM provider to use.
            max_iterations: Maximum Hunter-Verifier iterations.
            min_confirmed: Minimum confirmed vulnerabilities to stop early.
            max_tool_calls_per_agent: Max tool calls per agent per iteration.
        """
        self.llm = llm_provider
        self.max_iterations = max_iterations
        self.min_confirmed = min_confirmed
        self.max_tool_calls = max_tool_calls_per_agent

        # Tool registry
        self.tool_registry = create_security_tool_registry()

        # State across iterations
        self.all_confirmed: list[dict[str, Any]] = []
        self.all_false_positives: list[dict[str, Any]] = []
        self.seen_vuln_hashes: set[str] = set()
        self.accumulated_feedback: list[str] = []
        self.metrics = LoopMetrics()

    async def run(
        self,
        target_path: str,
        attack_surface_context: str = "",
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], LoopMetrics]:
        """Run the enhanced Hunter-Verifier loop.

        Args:
            target_path: Path to the target codebase.
            attack_surface_context: Optional context from the mapper.

        Returns:
            Tuple of (confirmed_vulns, false_positives, metrics).
        """
        self.metrics.start_time = datetime.now()
        iteration_results: list[IterationResult] = []

        for iteration in range(1, self.max_iterations + 1):
            self.metrics.total_iterations = iteration

            # Run Hunter
            candidates, hunter_tool_calls = await self._run_hunter(
                target_path=target_path,
                attack_surface_context=attack_surface_context,
                iteration=iteration,
            )

            self.metrics.total_tool_calls += len(hunter_tool_calls)
            for tc in hunter_tool_calls:
                self.metrics.tools_used.add(tc["tool_call"]["name"])

            # Deduplicate candidates
            new_candidates = self._deduplicate_candidates(candidates)
            self.metrics.total_candidates_found += len(new_candidates)

            if not new_candidates:
                # No new candidates - might be exhausted
                if iteration == 1:
                    # First iteration with no findings - continue anyway
                    pass
                else:
                    # Later iterations - we might be done
                    self.accumulated_feedback.append(
                        f"Iteration {iteration}: No new candidates found. Consider expanding search scope."
                    )

            # Run Verifier on new candidates
            if new_candidates:
                confirmed, fps, feedback, verifier_tool_calls = await self._run_verifier(
                    target_path=target_path,
                    candidates=new_candidates,
                )

                self.metrics.total_tool_calls += len(verifier_tool_calls)
                for tc in verifier_tool_calls:
                    self.metrics.tools_used.add(tc["tool_call"]["name"])

                # Update state
                self.all_confirmed.extend(confirmed)
                self.all_false_positives.extend(fps)
                self.accumulated_feedback.extend(feedback)

                self.metrics.total_confirmed = len(self.all_confirmed)
                self.metrics.total_false_positives = len(self.all_false_positives)
            else:
                confirmed = []
                fps = []
                feedback = []
                verifier_tool_calls = []

            # Record iteration result
            iteration_results.append(
                IterationResult(
                    iteration=iteration,
                    candidates=new_candidates,
                    confirmed=confirmed,
                    false_positives=fps,
                    feedback=feedback,
                    hunter_tool_calls=hunter_tool_calls,
                    verifier_tool_calls=verifier_tool_calls,
                )
            )

            # Check exit conditions
            if len(self.all_confirmed) >= self.min_confirmed:
                self.accumulated_feedback.append(
                    f"Exit: Found {len(self.all_confirmed)} confirmed vulnerabilities (target: {self.min_confirmed})"
                )
                break

            # Generate feedback for next iteration
            if iteration < self.max_iterations:
                self._generate_iteration_feedback(iteration, confirmed, fps)

        self.metrics.end_time = datetime.now()

        return self.all_confirmed, self.all_false_positives, self.metrics

    async def _run_hunter(
        self,
        target_path: str,
        attack_surface_context: str,
        iteration: int,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Run the Hunter agent with tool calling.

        Returns:
            Tuple of (candidates, tool_call_history).
        """
        # Build hunter prompt with accumulated context
        feedback_context = ""
        if self.accumulated_feedback:
            feedback_context = "\n### Feedback from Previous Iterations\n"
            feedback_context += "\n".join(f"- {fb}" for fb in self.accumulated_feedback[-10:])

        # Include previously found areas to avoid
        avoid_context = ""
        if self.all_confirmed:
            confirmed_locations = set(
                f"{v.get('file_path', '')}:{v.get('line_number', 0)}" for v in self.all_confirmed
            )
            avoid_context = "\n### Already Confirmed Vulnerabilities (focus on other areas)\n"
            avoid_context += "\n".join(f"- {loc}" for loc in list(confirmed_locations)[:10])

        user_prompt = f"""## Vulnerability Hunting - Iteration {iteration}

**Target Path**: {target_path}

{f"### Attack Surface Context" + chr(10) + attack_surface_context if attack_surface_context else ""}
{feedback_context}
{avoid_context}

Please analyze this codebase for security vulnerabilities. Use your tools to:
1. List files to understand the structure
2. Run SAST scans (opengrep_scan, gitleaks_scan)
3. Search for dangerous patterns
4. Read and verify potential vulnerabilities
5. Report findings in JSON format

{"Focus on areas not yet covered in previous iterations." if iteration > 1 else "Start with a comprehensive scan."}"""

        loop = ToolCallingLoop(
            llm_provider=self.llm,
            tool_registry=self.tool_registry,
            max_iterations=self.max_tool_calls,
        )

        response, tool_calls = await loop.run(
            system_prompt=TOOL_CALLING_HUNTER_PROMPT,
            user_prompt=user_prompt,
        )

        # Parse vulnerabilities from response
        candidates = _parse_vulnerabilities_from_response(response)

        # Add IDs if missing
        for i, c in enumerate(candidates):
            if "id" not in c:
                c["id"] = f"HUNTER-{iteration}-{i + 1}"

        return candidates, tool_calls

    async def _run_verifier(
        self,
        target_path: str,
        candidates: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], list[dict[str, Any]]]:
        """Run the Verifier agent with tool calling.

        Returns:
            Tuple of (confirmed, false_positives, feedback, tool_call_history).
        """
        # Format candidates for verifier
        candidate_strs = []
        for i, c in enumerate(candidates, 1):
            candidate_strs.append(f"""### Candidate {i}: {c.get("id", f"VULN-{i}")}
- **Type**: {c.get("vuln_type", "unknown")}
- **File**: {c.get("file_path", "unknown")}
- **Line**: {c.get("line_number", 0)}
- **Severity**: {c.get("severity", "unknown")} (Score: {c.get("score", 50)})
- **Description**: {c.get("description", "No description")[:200]}
- **Code Snippet**: `{c.get("code_snippet", "N/A")[:150]}`
""")

        user_prompt = f"""## Vulnerability Verification Request

**Target Path**: {target_path}

## Candidates to Verify ({len(candidates)} total)

{chr(10).join(candidate_strs)}

---

## Your Task

For each candidate:
1. Use `read_file` to examine the vulnerable code and context
2. Use `search_code` to find sanitization/validation functions
3. Determine TRUE POSITIVE or FALSE POSITIVE
4. Provide detailed reasoning

Start by reading the code for the first candidate."""

        loop = ToolCallingLoop(
            llm_provider=self.llm,
            tool_registry=self.tool_registry,
            max_iterations=self.max_tool_calls,
        )

        response, tool_calls = await loop.run(
            system_prompt=TOOL_CALLING_VERIFIER_PROMPT,
            user_prompt=user_prompt,
        )

        # Parse verification results
        results = _parse_verifications_from_response(response)
        verifications = results.get("verifications", [])

        # Categorize candidates
        confirmed = []
        false_positives = []
        feedback = []

        verification_map = {v.get("vuln_id"): v for v in verifications}

        for candidate in candidates:
            vuln_id = candidate.get("id", "")

            if vuln_id in verification_map:
                v = verification_map[vuln_id]
                verdict = v.get("verdict", "").lower()

                if verdict == "false_positive":
                    candidate["verification"] = v
                    false_positives.append(candidate)

                    # Generate feedback for hunter
                    reason = v.get("reasoning", "")[:100]
                    feedback.append(
                        f"FP: {candidate.get('vuln_type')} at {candidate.get('file_path')}:{candidate.get('line_number')} - {reason}"
                    )
                else:
                    # Confirmed
                    candidate["verification"] = v
                    candidate["confidence"] = v.get("confidence", 0.8)
                    confirmed.append(candidate)
            else:
                # Not verified - assume confirmed (conservative)
                confirmed.append(candidate)

        # Extract hunter feedback
        hunter_feedback = results.get("feedback_for_hunter", [])
        feedback.extend(hunter_feedback)

        return confirmed, false_positives, feedback, tool_calls

    def _deduplicate_candidates(self, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Remove duplicate candidates based on location and type."""
        unique = []

        for c in candidates:
            vuln_hash = _compute_vuln_hash(c)

            if vuln_hash not in self.seen_vuln_hashes:
                self.seen_vuln_hashes.add(vuln_hash)
                unique.append(c)

        return unique

    def _generate_iteration_feedback(
        self,
        iteration: int,
        confirmed: list[dict[str, Any]],
        false_positives: list[dict[str, Any]],
    ) -> None:
        """Generate feedback for the next iteration."""
        total_this_round = len(confirmed) + len(false_positives)

        if total_this_round == 0:
            self.accumulated_feedback.append(
                f"Iteration {iteration}: No candidates found. Try different search patterns."
            )
            return

        fp_rate = len(false_positives) / total_this_round if total_this_round > 0 else 0

        if fp_rate > 0.7:
            self.accumulated_feedback.append(
                f"Iteration {iteration}: High FP rate ({fp_rate:.0%}). Focus on more obvious vulnerabilities."
            )

        # Identify FP patterns
        fp_types = [fp.get("vuln_type", "unknown") for fp in false_positives]
        if fp_types:
            from collections import Counter

            common_fp_types = Counter(fp_types).most_common(2)
            for fp_type, count in common_fp_types:
                if count >= 2:
                    self.accumulated_feedback.append(
                        f"Pattern: {fp_type} had {count} false positives. Be more careful with this type."
                    )


async def run_enhanced_hunter_verifier(
    llm_provider: BaseLLMProvider,
    target_path: str,
    attack_surface_context: str = "",
    max_iterations: int = 3,
    min_confirmed: int = 3,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], LoopMetrics]:
    """Run the enhanced Hunter-Verifier loop.

    Args:
        llm_provider: The LLM provider to use.
        target_path: Path to the target codebase.
        attack_surface_context: Optional context from mapper.
        max_iterations: Maximum iterations.
        min_confirmed: Minimum confirmed to stop early.

    Returns:
        Tuple of (confirmed_vulns, false_positives, metrics).
    """
    loop = EnhancedHunterVerifierLoop(
        llm_provider=llm_provider,
        max_iterations=max_iterations,
        min_confirmed=min_confirmed,
    )

    return await loop.run(target_path, attack_surface_context)
