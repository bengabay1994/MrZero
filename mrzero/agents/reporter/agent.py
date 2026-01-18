"""MrZeroConclusion - LLM-Powered Reporter Agent."""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from mrzero.agents.base import AgentResult, AgentType, BaseAgent
from mrzero.core.memory.state import AgentState
from mrzero.core.schemas import (
    AttackSurfaceMap,
    EnvironmentInfo,
    Exploit,
    Vulnerability,
    VulnerabilitySeverity,
)


class ReporterAgent(BaseAgent):
    """Agent for generating comprehensive security reports using LLM intelligence.

    This agent uses LLM reasoning as the PRIMARY decision maker for:
    1. Generating intelligent executive summaries that highlight key risks
    2. Identifying patterns and relationships between vulnerabilities
    3. Providing context-aware remediation recommendations
    4. Prioritizing findings based on overall risk assessment

    The LLM is the brain - it doesn't just format data, it ANALYZES and INTERPRETS.
    """

    agent_type = AgentType.REPORTER

    SYSTEM_PROMPT = """You are MrZeroConclusion, an elite security report writer and risk analyst.

## Your Mission
Generate comprehensive, actionable security reports that transform raw vulnerability data into strategic security intelligence. Your reports should be clear enough for executives yet detailed enough for security engineers.

## Your Expertise
- **Risk Analysis**: Understand the real-world impact of vulnerabilities in context
- **Pattern Recognition**: Identify systemic security issues across findings
- **Remediation Strategy**: Prioritize fixes based on risk, effort, and dependencies
- **Communication**: Translate technical findings into business impact

## Report Philosophy

### Executive Summary
Don't just count vulnerabilities - ANALYZE them:
- What's the overall security posture?
- What are the most critical risks that need immediate attention?
- Are there patterns suggesting systemic issues?
- What's the potential business impact?

### Vulnerability Analysis
Go beyond listing findings:
- Group related vulnerabilities
- Identify root causes
- Explain attack chains (how vulns could be combined)
- Assess real-world exploitability

### Remediation Guidance
Provide strategic advice:
- Prioritize by risk AND effort
- Identify quick wins vs long-term fixes
- Note dependencies between fixes
- Suggest preventive measures

## Report Quality Standards
- **Actionable**: Every finding should have clear next steps
- **Contextual**: Explain WHY something is a risk, not just WHAT
- **Prioritized**: Help readers focus on what matters most
- **Professional**: Suitable for sharing with stakeholders"""

    EXECUTIVE_SUMMARY_PROMPT = """## Task: Generate Executive Summary

Analyze the security assessment results and create an intelligent executive summary.

---

## Assessment Overview

**Target:** {target_path}
**Mode:** {mode}
**Session ID:** {session_id}

---

## Vulnerability Statistics

{vuln_stats}

---

## Top Vulnerabilities

{top_vulns}

---

## Attack Surface Summary

{attack_surface_summary}

---

## Environment & Exploitation Status

{env_exploit_summary}

---

## Your Task

Generate an executive summary that:
1. Assesses the overall security posture (Critical/High/Medium/Low risk)
2. Highlights the most significant risks and their potential impact
3. Identifies any patterns or systemic issues
4. Provides 3-5 key recommendations prioritized by importance
5. Notes any successful exploits or proof-of-concepts

Be specific and actionable - avoid generic statements.

Respond in this JSON format:
```json
{{
    "overall_risk_level": "critical" | "high" | "medium" | "low",
    "risk_score": <1-100>,
    "posture_assessment": "<2-3 sentence assessment of security posture>",
    "key_risks": [
        {{
            "risk": "<specific risk>",
            "impact": "<potential business/technical impact>",
            "urgency": "immediate" | "short-term" | "medium-term"
        }}
    ],
    "patterns_identified": [
        {{
            "pattern": "<systemic issue identified>",
            "affected_areas": ["<area1>", "<area2>"],
            "root_cause": "<likely root cause>"
        }}
    ],
    "top_recommendations": [
        {{
            "priority": 1,
            "recommendation": "<specific action>",
            "rationale": "<why this is important>",
            "effort": "low" | "medium" | "high"
        }}
    ],
    "exploitation_summary": "<summary of any successful exploits or PoCs>",
    "executive_narrative": "<3-4 paragraph narrative suitable for executives>"
}}
```"""

    REMEDIATION_ANALYSIS_PROMPT = """## Task: Generate Remediation Strategy

Analyze the vulnerabilities and create a strategic remediation plan.

---

## Confirmed Vulnerabilities

{vulnerabilities}

---

## Your Task

Create a remediation strategy that:
1. Groups related vulnerabilities that can be fixed together
2. Prioritizes by risk, effort, and dependencies
3. Identifies quick wins (high impact, low effort)
4. Notes any blocking dependencies between fixes
5. Suggests preventive measures to avoid similar issues

Respond in this JSON format:
```json
{{
    "remediation_groups": [
        {{
            "group_name": "<descriptive name>",
            "vulnerabilities": ["<vuln_id1>", "<vuln_id2>"],
            "common_fix": "<shared remediation approach>",
            "priority": "critical" | "high" | "medium" | "low",
            "effort": "hours" | "days" | "weeks",
            "dependencies": ["<what must be done first>"]
        }}
    ],
    "quick_wins": [
        {{
            "vuln_id": "<id>",
            "fix": "<specific fix>",
            "time_estimate": "<estimate>",
            "impact": "<risk reduction>"
        }}
    ],
    "long_term_improvements": [
        {{
            "improvement": "<systemic improvement>",
            "addresses": ["<issue1>", "<issue2>"],
            "implementation": "<how to implement>"
        }}
    ],
    "fix_order": ["<vuln_id in recommended fix order>"],
    "preventive_measures": [
        "<measure to prevent similar vulnerabilities>"
    ]
}}
```"""

    def __init__(self, llm: Any = None, tools: list[Any] | None = None) -> None:
        """Initialize the Reporter agent."""
        super().__init__(llm, tools)

    def get_system_prompt(self) -> str:
        """Get the system prompt."""
        return self.SYSTEM_PROMPT

    async def execute(self, state: AgentState) -> AgentResult:
        """Execute LLM-powered report generation.

        The LLM is the PRIMARY decision maker for:
        1. Analyzing findings and generating executive summary
        2. Identifying patterns and systemic issues
        3. Creating strategic remediation recommendations

        Args:
            state: Current workflow state.

        Returns:
            AgentResult with report paths.
        """
        from mrzero.core.config import get_config

        config = get_config()
        output_dir = config.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)

        # Step 1: Gather all data for LLM analysis
        vulns = state.confirmed_vulnerabilities
        attack_surface = state.attack_surface
        environment = state.environment
        exploits = state.exploits

        # Step 2: LLM generates executive summary
        executive_analysis = await self._generate_executive_summary(
            target_path=state.target_path,
            mode=state.mode.value,
            session_id=state.session_id,
            vulnerabilities=vulns,
            attack_surface=attack_surface,
            environment=environment,
            exploits=exploits,
        )

        # Step 3: LLM generates remediation strategy
        remediation_strategy = await self._generate_remediation_strategy(vulns)

        # Step 4: Generate the full report using LLM insights
        report_content = self._build_report(
            state=state,
            executive_analysis=executive_analysis,
            remediation_strategy=remediation_strategy,
        )

        # Step 5: Save reports
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = output_dir / f"security_report_{timestamp}.md"
        report_path.write_text(report_content)

        # Generate JSON report for programmatic access
        json_report = self._generate_json_report(
            state=state,
            executive_analysis=executive_analysis,
            remediation_strategy=remediation_strategy,
        )
        json_path = output_dir / f"security_report_{timestamp}.json"
        json_path.write_text(json.dumps(json_report, indent=2, default=str))

        return AgentResult(
            agent_type=self.agent_type,
            success=True,
            output={
                "report_path": str(report_path),
                "json_path": str(json_path),
                "executive_analysis": executive_analysis,
                "remediation_strategy": remediation_strategy,
            },
        )

    async def _generate_executive_summary(
        self,
        target_path: str,
        mode: str,
        session_id: str,
        vulnerabilities: list[Vulnerability],
        attack_surface: AttackSurfaceMap | None,
        environment: EnvironmentInfo | None,
        exploits: list[Exploit],
    ) -> dict[str, Any]:
        """Use LLM to generate intelligent executive summary.

        Args:
            target_path: Path to target.
            mode: Execution mode.
            session_id: Session ID.
            vulnerabilities: List of confirmed vulnerabilities.
            attack_surface: Attack surface map.
            environment: Environment info.
            exploits: Generated exploits.

        Returns:
            Executive analysis dict from LLM.
        """
        # Prepare vulnerability statistics
        severity_counts = {s: 0 for s in VulnerabilitySeverity}
        for v in vulnerabilities:
            severity_counts[v.severity] += 1

        vuln_stats = f"""Total Vulnerabilities: {len(vulnerabilities)}
- Critical: {severity_counts[VulnerabilitySeverity.CRITICAL]}
- High: {severity_counts[VulnerabilitySeverity.HIGH]}
- Medium: {severity_counts[VulnerabilitySeverity.MEDIUM]}
- Low: {severity_counts[VulnerabilitySeverity.LOW]}
- Info: {severity_counts[VulnerabilitySeverity.INFO]}

Vulnerability Types:
"""
        type_counts: dict[str, int] = {}
        for v in vulnerabilities:
            vtype = v.vuln_type.value
            type_counts[vtype] = type_counts.get(vtype, 0) + 1

        for vtype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            vuln_stats += f"- {vtype}: {count}\n"

        # Format top vulnerabilities
        top_vulns = ""
        for v in vulnerabilities[:10]:
            top_vulns += f"""
### {v.title}
- **Severity:** {v.severity.value} (Score: {v.score})
- **Type:** {v.vuln_type.value}
- **Location:** {v.file_path}:{v.line_number}
- **Description:** {(v.description or "")[:200]}
- **CWE:** {v.cwe_id or "N/A"}
"""

        # Format attack surface summary
        attack_surface_summary = "No attack surface data available."
        if attack_surface:
            attack_surface_summary = f"""
- Files Analyzed: {attack_surface.file_count}
- Lines of Code: {attack_surface.loc:,}
- Entry Points: {len(attack_surface.endpoints)}
- Data Flows Tracked: {len(attack_surface.data_flows)}
- Languages: {", ".join(l.name for l in attack_surface.languages[:5])}
- Frameworks: {", ".join(f.name for f in attack_surface.frameworks[:5])}
- Unauthenticated Endpoints: {sum(1 for e in attack_surface.endpoints if not e.authenticated)}
"""

        # Format environment and exploitation summary
        env_exploit_summary = ""
        if environment:
            env_exploit_summary += f"""
**Environment:**
- Type: {environment.env_type}
- Build Status: {"Successful" if environment.build_successful else "Failed"}
- Build Attempts: {environment.build_attempts}
"""
        else:
            env_exploit_summary += "**Environment:** Not configured\n"

        if exploits:
            successful = sum(1 for e in exploits if e.successful)
            tested = sum(1 for e in exploits if e.tested)
            env_exploit_summary += f"""
**Exploits:**
- Total Generated: {len(exploits)}
- Tested: {tested}
- Successful: {successful}
- Exploit Types: {", ".join(set(e.exploit_type for e in exploits))}
"""
        else:
            env_exploit_summary += "**Exploits:** None generated\n"

        # Call LLM
        prompt = self.EXECUTIVE_SUMMARY_PROMPT.format(
            target_path=target_path,
            mode=mode,
            session_id=session_id,
            vuln_stats=vuln_stats,
            top_vulns=top_vulns if vulnerabilities else "No vulnerabilities found.",
            attack_surface_summary=attack_surface_summary,
            env_exploit_summary=env_exploit_summary,
        )

        try:
            response = await self.chat(prompt)
            result = self._parse_llm_json_response(response)
            if result:
                return result
        except Exception as e:
            pass

        # Fallback if LLM fails
        return self._generate_fallback_executive_summary(vulnerabilities, severity_counts, exploits)

    async def _generate_remediation_strategy(
        self, vulnerabilities: list[Vulnerability]
    ) -> dict[str, Any]:
        """Use LLM to generate strategic remediation plan.

        Args:
            vulnerabilities: List of confirmed vulnerabilities.

        Returns:
            Remediation strategy dict from LLM.
        """
        if not vulnerabilities:
            return {"remediation_groups": [], "quick_wins": [], "fix_order": []}

        # Format vulnerabilities for LLM
        vuln_text = ""
        for v in vulnerabilities[:20]:  # Limit to top 20
            vuln_text += f"""
### {v.id}: {v.title}
- **Type:** {v.vuln_type.value}
- **Severity:** {v.severity.value} (Score: {v.score})
- **File:** {v.file_path}:{v.line_number}
- **CWE:** {v.cwe_id or "N/A"}
- **Description:** {(v.description or "")[:300]}
- **Code:**
```
{(v.code_snippet or "")[:200]}
```
"""

        prompt = self.REMEDIATION_ANALYSIS_PROMPT.format(vulnerabilities=vuln_text)

        try:
            response = await self.chat(prompt)
            result = self._parse_llm_json_response(response)
            if result:
                return result
        except Exception:
            pass

        # Fallback
        return self._generate_fallback_remediation(vulnerabilities)

    def _build_report(
        self,
        state: AgentState,
        executive_analysis: dict[str, Any],
        remediation_strategy: dict[str, Any],
    ) -> str:
        """Build the full Markdown report using LLM insights.

        Args:
            state: Current workflow state.
            executive_analysis: LLM executive analysis.
            remediation_strategy: LLM remediation strategy.

        Returns:
            Complete Markdown report.
        """
        vulns = state.confirmed_vulnerabilities
        attack_surface = state.attack_surface
        environment = state.environment
        exploits = state.exploits

        # Build severity counts
        severity_counts = {s: 0 for s in VulnerabilitySeverity}
        for v in vulns:
            severity_counts[v.severity] += 1

        # Start report
        report = f"""# Security Assessment Report

**Target:** {state.target_path}
**Date:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Session ID:** {state.session_id}
**Mode:** {state.mode.value.upper()}
**Overall Risk Level:** {executive_analysis.get("overall_risk_level", "Unknown").upper()}
**Risk Score:** {executive_analysis.get("risk_score", "N/A")}/100

---

## Executive Summary

{executive_analysis.get("executive_narrative", self._generate_basic_narrative(vulns, severity_counts))}

### Key Risks

"""
        # Add key risks from LLM analysis
        for risk in executive_analysis.get("key_risks", []):
            urgency_emoji = {"immediate": "🔴", "short-term": "🟠", "medium-term": "🟡"}.get(
                risk.get("urgency", ""), "⚪"
            )
            report += f"""
{urgency_emoji} **{risk.get("risk", "Unknown Risk")}**
- Impact: {risk.get("impact", "N/A")}
- Urgency: {risk.get("urgency", "N/A").title()}
"""

        # Add patterns identified
        patterns = executive_analysis.get("patterns_identified", [])
        if patterns:
            report += "\n### Patterns & Systemic Issues\n"
            for pattern in patterns:
                report += f"""
**{pattern.get("pattern", "Pattern")}**
- Affected Areas: {", ".join(pattern.get("affected_areas", []))}
- Root Cause: {pattern.get("root_cause", "Unknown")}
"""

        # Add top recommendations
        report += "\n### Priority Recommendations\n"
        for rec in executive_analysis.get("top_recommendations", []):
            effort_badge = {"low": "🟢", "medium": "🟡", "high": "🔴"}.get(
                rec.get("effort", ""), "⚪"
            )
            report += f"""
{rec.get("priority", "?")}. **{rec.get("recommendation", "N/A")}** {effort_badge}
   - {rec.get("rationale", "")}
"""

        # Exploitation summary
        exploit_summary = executive_analysis.get("exploitation_summary", "")
        if exploit_summary:
            report += f"\n### Exploitation Status\n\n{exploit_summary}\n"

        report += "\n---\n\n"

        # Severity breakdown table
        report += f"""## Vulnerability Summary

| Severity | Count |
|----------|-------|
| Critical | {severity_counts[VulnerabilitySeverity.CRITICAL]} |
| High | {severity_counts[VulnerabilitySeverity.HIGH]} |
| Medium | {severity_counts[VulnerabilitySeverity.MEDIUM]} |
| Low | {severity_counts[VulnerabilitySeverity.LOW]} |
| **Total** | **{len(vulns)}** |

"""

        # Attack Surface Section
        report += "---\n\n## Attack Surface Analysis\n\n"

        if attack_surface:
            report += f"""### Overview

- **Total Files Analyzed:** {attack_surface.file_count}
- **Lines of Code:** {attack_surface.loc:,}
- **Entry Points Found:** {len(attack_surface.endpoints)}
- **Data Flows Tracked:** {len(attack_surface.data_flows)}

"""
            if attack_surface.languages:
                report += "### Languages Detected\n\n"
                report += "| Language | Confidence |\n|----------|------------|\n"
                for lang in attack_surface.languages[:10]:
                    report += f"| {lang.name} | {lang.confidence:.0%} |\n"
                report += "\n"

            if attack_surface.frameworks:
                report += "### Frameworks/Technologies\n\n"
                for fw in attack_surface.frameworks:
                    version = f" (v{fw.version})" if fw.version else ""
                    report += f"- {fw.name}{version}\n"
                report += "\n"

            if attack_surface.endpoints:
                unauthenticated = [e for e in attack_surface.endpoints if not e.authenticated]
                if unauthenticated:
                    report += "### Unauthenticated Entry Points (High Risk)\n\n"
                    report += "| Method | Path | File | Risk |\n|--------|------|------|------|\n"
                    for ep in unauthenticated[:15]:
                        report += f"| {ep.method or 'N/A'} | `{ep.path}` | {ep.file_path} | {ep.risk_score} |\n"
                    report += "\n"
        else:
            report += "Attack surface analysis was not performed.\n\n"

        report += "---\n\n"

        # Vulnerability Details
        report += "## Vulnerability Details\n\n"

        for i, vuln in enumerate(vulns, 1):
            report += f"""### {i}. {vuln.title}

| Property | Value |
|----------|-------|
| **ID** | `{vuln.id}` |
| **Severity** | {vuln.severity.value.upper()} (Score: {vuln.score}) |
| **Type** | {vuln.vuln_type.value} |
| **CWE** | {f"[{vuln.cwe_id}](https://cwe.mitre.org/data/definitions/{vuln.cwe_id.replace('CWE-', '')}.html)" if vuln.cwe_id else "N/A"} |
| **Location** | `{vuln.file_path}:{vuln.line_number}` |
| **Tool** | {vuln.tool_source} |
| **Confidence** | {vuln.confidence:.0%} |

#### Description

{vuln.description or "No description available."}

"""
            if vuln.code_snippet:
                report += f"#### Vulnerable Code\n\n```\n{vuln.code_snippet}\n```\n\n"

            if vuln.data_flow:
                report += f"""#### Data Flow

- **Source:** `{vuln.data_flow.source}` at {vuln.data_flow.source_file}:{vuln.data_flow.source_line}
- **Sink:** `{vuln.data_flow.sink}` at {vuln.data_flow.sink_file}:{vuln.data_flow.sink_line}
- **Tainted:** {"Yes" if vuln.data_flow.tainted else "No"}

"""
            # Add remediation from strategy if available
            report += self._get_remediation_for_vuln(vuln, remediation_strategy)
            report += "---\n\n"

        # Remediation Strategy Section
        report += "## Remediation Strategy\n\n"

        quick_wins = remediation_strategy.get("quick_wins", [])
        if quick_wins:
            report += "### Quick Wins (High Impact, Low Effort)\n\n"
            for qw in quick_wins:
                report += f"- **{qw.get('vuln_id', 'N/A')}**: {qw.get('fix', 'N/A')} ({qw.get('time_estimate', 'N/A')})\n"
            report += "\n"

        groups = remediation_strategy.get("remediation_groups", [])
        if groups:
            report += "### Grouped Remediation\n\n"
            for group in groups:
                priority_badge = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
                    group.get("priority", ""), "⚪"
                )
                report += f"""
#### {priority_badge} {group.get("group_name", "Group")}

- **Vulnerabilities:** {", ".join(group.get("vulnerabilities", []))}
- **Common Fix:** {group.get("common_fix", "N/A")}
- **Effort:** {group.get("effort", "N/A")}
- **Dependencies:** {", ".join(group.get("dependencies", [])) or "None"}
"""

        long_term = remediation_strategy.get("long_term_improvements", [])
        if long_term:
            report += "\n### Long-Term Security Improvements\n\n"
            for imp in long_term:
                report += (
                    f"- **{imp.get('improvement', 'N/A')}**: {imp.get('implementation', 'N/A')}\n"
                )

        preventive = remediation_strategy.get("preventive_measures", [])
        if preventive:
            report += "\n### Preventive Measures\n\n"
            for measure in preventive:
                report += f"- {measure}\n"

        report += "\n---\n\n"

        # Environment Section
        report += "## Environment Setup\n\n"

        if environment:
            if environment.build_successful:
                report += f"""**Build Status:** ✅ Successful ({environment.env_type})

| Property | Value |
|----------|-------|
| Type | {environment.env_type} |
| Build Attempts | {environment.build_attempts} |
"""
                if environment.container_id:
                    report += f"| Container ID | `{environment.container_id}` |\n"
                if environment.connection_port:
                    report += f"| Port | {environment.connection_port} |\n"
            else:
                report += "**Build Status:** ❌ Failed\n\n"
                if environment.manual_guide_path:
                    report += f"See manual setup guide: `{environment.manual_guide_path}`\n"
        else:
            report += "Environment setup was not performed.\n"

        report += "\n---\n\n"

        # Exploits Section
        report += "## Exploit Documentation\n\n"

        if exploits:
            successful_exploits = [e for e in exploits if e.successful]
            if successful_exploits:
                report += f"### ✅ Successful Exploits ({len(successful_exploits)})\n\n"
                for exploit in successful_exploits:
                    report += f"""#### {exploit.vulnerability_id}

- **Type:** {exploit.exploit_type}
- **Language:** {exploit.language}
- **File:** `{exploit.file_path}`

```{exploit.language}
{exploit.code[:1500]}{"..." if len(exploit.code) > 1500 else ""}
```

"""

            other_exploits = [e for e in exploits if not e.successful]
            if other_exploits:
                report += f"### 🔄 Other Exploits ({len(other_exploits)})\n\n"
                for exploit in other_exploits:
                    status = "Tested (Failed)" if exploit.tested else "Not Tested"
                    report += f"- **{exploit.vulnerability_id}**: {exploit.exploit_type} ({status}) - `{exploit.file_path}`\n"
        else:
            report += "No exploits were generated.\n"

        report += "\n---\n\n"

        # Appendix
        report += f"""## Appendix

### Assessment Details

- **MrZero Version:** 0.1.0
- **Scan Mode:** {state.mode.value}
- **Analysis Date:** {datetime.now().strftime("%Y-%m-%d")}
- **Session ID:** {state.session_id}

### Disclaimer

This report is provided for informational purposes only. The findings represent a point-in-time assessment and should be validated before remediation. Always test security fixes in a non-production environment first.

### Methodology

This assessment was conducted using MrZero's multi-agent architecture:
1. **MrZeroMapper** - Attack surface analysis
2. **MrZeroHunter** - Vulnerability discovery (SAST)
3. **MrZeroVerifier** - False positive elimination
4. **MrZeroEnvBuilder** - Environment setup
5. **MrZeroExploitBuilder** - Exploit generation
6. **MrZeroConclusion** - Report generation

All agents use LLM-driven decision making for intelligent analysis.
"""

        return report

    def _get_remediation_for_vuln(
        self, vuln: Vulnerability, remediation_strategy: dict[str, Any]
    ) -> str:
        """Get remediation advice for a specific vulnerability.

        Args:
            vuln: Vulnerability to get remediation for.
            remediation_strategy: LLM remediation strategy.

        Returns:
            Remediation section string.
        """
        # Check if this vuln has a quick win
        for qw in remediation_strategy.get("quick_wins", []):
            if qw.get("vuln_id") == vuln.id:
                return f"""#### Remediation (Quick Win 🎯)

{qw.get("fix", "See remediation strategy section.")}

**Time Estimate:** {qw.get("time_estimate", "N/A")}
**Impact:** {qw.get("impact", "N/A")}

"""

        # Check if part of a group
        for group in remediation_strategy.get("remediation_groups", []):
            if vuln.id in group.get("vulnerabilities", []):
                return f"""#### Remediation

{group.get("common_fix", "See remediation strategy section.")}

**Part of Group:** {group.get("group_name", "N/A")}
**Effort:** {group.get("effort", "N/A")}

"""

        # Fall back to generic remediation
        if vuln.remediation:
            return f"#### Remediation\n\n{vuln.remediation}\n\n"

        return self._get_default_remediation(vuln)

    def _get_default_remediation(self, vuln: Vulnerability) -> str:
        """Get default remediation advice for a vulnerability type."""
        from mrzero.core.schemas import VulnerabilityType

        remediations = {
            VulnerabilityType.SQL_INJECTION: """#### Remediation

- Use parameterized queries or prepared statements
- Use an ORM that handles escaping
- Implement input validation with allowlists
- Apply the principle of least privilege to database accounts

""",
            VulnerabilityType.COMMAND_INJECTION: """#### Remediation

- Avoid calling system commands with user input
- Use language-specific libraries instead of shell commands
- If shell is necessary, use subprocess with a list (not shell=True)
- Implement strict allowlist validation for any command arguments

""",
            VulnerabilityType.STORED_XSS: """#### Remediation

- Encode output based on context (HTML entity encoding)
- Use a Content Security Policy (CSP)
- Sanitize input with a library like DOMPurify or bleach
- Use templating engines that auto-escape by default

""",
            VulnerabilityType.REFLECTED_XSS: """#### Remediation

- Encode all user input before reflecting in response
- Implement Content Security Policy (CSP)
- Use HTTP-only cookies for sensitive data
- Validate and sanitize input on the server side

""",
            VulnerabilityType.PATH_TRAVERSAL: """#### Remediation

- Validate paths against an allowlist
- Use os.path.realpath() to resolve paths and verify they're within allowed directories
- Never pass user input directly to file operations
- Use secure file handling functions like secure_filename()

""",
            VulnerabilityType.REENTRANCY: """#### Remediation

- Use the Checks-Effects-Interactions pattern
- Implement a reentrancy guard (mutex)
- Update state before making external calls
- Consider using OpenZeppelin's ReentrancyGuard

""",
            VulnerabilityType.SSRF: """#### Remediation

- Validate and sanitize all URLs
- Use allowlists for permitted domains/IPs
- Block access to internal network ranges (169.254.x.x, 10.x.x.x, etc.)
- Disable unnecessary URL schemes (file://, gopher://, etc.)

""",
            VulnerabilityType.INSECURE_DESERIALIZATION: """#### Remediation

- Never deserialize untrusted data
- Use safe serialization formats (JSON instead of pickle/yaml)
- Implement integrity checks (HMAC) on serialized data
- Run deserialization in a sandboxed environment

""",
        }

        return remediations.get(
            vuln.vuln_type,
            """#### Remediation

Review the vulnerable code and implement appropriate security controls based on the vulnerability type. Consult OWASP guidelines for specific remediation steps.

""",
        )

    def _generate_fallback_executive_summary(
        self,
        vulnerabilities: list[Vulnerability],
        severity_counts: dict[VulnerabilitySeverity, int],
        exploits: list[Exploit],
    ) -> dict[str, Any]:
        """Generate fallback executive summary if LLM fails."""
        critical_high = (
            severity_counts[VulnerabilitySeverity.CRITICAL]
            + severity_counts[VulnerabilitySeverity.HIGH]
        )

        if critical_high > 5:
            risk_level = "critical"
            risk_score = 90
        elif critical_high > 0:
            risk_level = "high"
            risk_score = 70
        elif severity_counts[VulnerabilitySeverity.MEDIUM] > 0:
            risk_level = "medium"
            risk_score = 50
        else:
            risk_level = "low"
            risk_score = 25

        successful_exploits = sum(1 for e in exploits if e.successful)

        return {
            "overall_risk_level": risk_level,
            "risk_score": risk_score,
            "posture_assessment": f"The assessment identified {len(vulnerabilities)} vulnerabilities with {critical_high} critical/high severity issues requiring immediate attention.",
            "key_risks": [
                {
                    "risk": f"{severity_counts[VulnerabilitySeverity.CRITICAL]} critical vulnerabilities",
                    "impact": "Potential for remote code execution or data breach",
                    "urgency": "immediate",
                }
            ]
            if severity_counts[VulnerabilitySeverity.CRITICAL] > 0
            else [],
            "patterns_identified": [],
            "top_recommendations": [
                {
                    "priority": 1,
                    "recommendation": "Address all critical and high severity findings immediately",
                    "rationale": "These represent the highest risk to the application",
                    "effort": "varies",
                }
            ],
            "exploitation_summary": f"{successful_exploits} of {len(exploits)} exploits were successful"
            if exploits
            else "No exploits generated",
            "executive_narrative": self._generate_basic_narrative(vulnerabilities, severity_counts),
        }

    def _generate_fallback_remediation(
        self, vulnerabilities: list[Vulnerability]
    ) -> dict[str, Any]:
        """Generate fallback remediation strategy if LLM fails."""
        return {
            "remediation_groups": [],
            "quick_wins": [],
            "long_term_improvements": [
                {
                    "improvement": "Implement security code review process",
                    "addresses": ["All vulnerability types"],
                    "implementation": "Add security review to PR process",
                }
            ],
            "fix_order": [v.id for v in vulnerabilities],
            "preventive_measures": [
                "Implement static analysis in CI/CD pipeline",
                "Conduct regular security training for developers",
                "Establish secure coding guidelines",
            ],
        }

    def _generate_basic_narrative(
        self,
        vulnerabilities: list[Vulnerability],
        severity_counts: dict[VulnerabilitySeverity, int],
    ) -> str:
        """Generate a basic narrative summary."""
        total = len(vulnerabilities)
        critical = severity_counts[VulnerabilitySeverity.CRITICAL]
        high = severity_counts[VulnerabilitySeverity.HIGH]
        medium = severity_counts[VulnerabilitySeverity.MEDIUM]

        if total == 0:
            return "The security assessment did not identify any confirmed vulnerabilities in the target codebase. However, this does not guarantee the absence of security issues. Regular security assessments and adherence to secure coding practices are recommended."

        narrative = f"The security assessment of the target codebase identified **{total} confirmed vulnerabilities**. "

        if critical > 0:
            narrative += f"Of particular concern are **{critical} critical severity** findings that pose immediate risk to the application's security posture and require urgent attention. "

        if high > 0:
            narrative += f"Additionally, **{high} high severity** vulnerabilities were identified that should be addressed in the near term. "

        if medium > 0:
            narrative += f"The assessment also found **{medium} medium severity** issues that should be included in the remediation roadmap. "

        # Add type breakdown
        type_counts: dict[str, int] = {}
        for v in vulnerabilities:
            vtype = v.vuln_type.value
            type_counts[vtype] = type_counts.get(vtype, 0) + 1

        if type_counts:
            top_types = sorted(type_counts.items(), key=lambda x: -x[1])[:3]
            types_str = ", ".join(f"{t[0]} ({t[1]})" for t in top_types)
            narrative += f"\n\nThe most prevalent vulnerability types were: {types_str}. "

        narrative += "\n\nImmediate remediation of critical and high severity findings is strongly recommended, followed by a systematic approach to addressing remaining issues based on the prioritized remediation strategy provided in this report."

        return narrative

    def _generate_json_report(
        self,
        state: AgentState,
        executive_analysis: dict[str, Any],
        remediation_strategy: dict[str, Any],
    ) -> dict[str, Any]:
        """Generate a JSON report for programmatic access."""
        return {
            "meta": {
                "target": state.target_path,
                "session_id": state.session_id,
                "mode": state.mode.value,
                "timestamp": datetime.now().isoformat(),
                "version": "0.1.0",
            },
            "executive_summary": executive_analysis,
            "summary": {
                "total_vulnerabilities": len(state.confirmed_vulnerabilities),
                "by_severity": {
                    s.value: sum(1 for v in state.confirmed_vulnerabilities if v.severity == s)
                    for s in VulnerabilitySeverity
                },
                "by_type": self._count_by_type(state.confirmed_vulnerabilities),
            },
            "attack_surface": state.attack_surface.model_dump() if state.attack_surface else None,
            "vulnerabilities": [v.model_dump() for v in state.confirmed_vulnerabilities],
            "remediation_strategy": remediation_strategy,
            "environment": state.environment.model_dump() if state.environment else None,
            "exploits": [e.model_dump() for e in state.exploits],
            "errors": state.errors,
        }

    def _count_by_type(self, vulnerabilities: list[Vulnerability]) -> dict[str, int]:
        """Count vulnerabilities by type."""
        counts: dict[str, int] = {}
        for v in vulnerabilities:
            vtype = v.vuln_type.value
            counts[vtype] = counts.get(vtype, 0) + 1
        return counts

    def _parse_llm_json_response(self, response: str) -> dict[str, Any] | None:
        """Parse LLM's JSON response."""
        try:
            json_block_match = re.search(r"```json\s*([\s\S]*?)\s*```", response)
            if json_block_match:
                return json.loads(json_block_match.group(1))

            json_match = re.search(r"\{[\s\S]*\}", response)
            if json_match:
                return json.loads(json_match.group())

            return None
        except json.JSONDecodeError:
            return None
