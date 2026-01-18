"""Output artifact generation for MrZero."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from mrzero.core.memory.state import AgentState
from mrzero.core.schemas import (
    AttackSurface,
    Vulnerability,
    Environment,
    Exploit,
    VulnerabilitySeverity,
)


class ArtifactGenerator:
    """Generates output artifacts from scan results."""

    def __init__(self, output_dir: Path) -> None:
        """Initialize the artifact generator.

        Args:
            output_dir: Directory to write artifacts to.
        """
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate_all(self, state: AgentState) -> dict[str, Path]:
        """Generate all artifacts from the scan state.

        Args:
            state: Final workflow state.

        Returns:
            Dictionary mapping artifact names to file paths.
        """
        artifacts = {}

        # Attack surface map
        if state.attack_surface:
            artifacts["attack_surface_map"] = self.generate_attack_surface_map(state.attack_surface)

        # Confirmed vulnerabilities
        if state.confirmed_vulnerabilities:
            artifacts["confirmed_vulnerabilities"] = self.generate_vulnerabilities_json(
                state.confirmed_vulnerabilities
            )

        # Exploit files
        for exploit in state.exploits:
            path = self.generate_exploit_file(exploit)
            artifacts[f"exploit_{exploit.vulnerability_id}"] = path

        # Manual setup guide (if environment failed)
        if state.environment and not state.environment.build_successful:
            artifacts["manual_setup_guide"] = self.generate_manual_guide(
                state.environment, state.target_path
            )

        # Full report
        artifacts["exploit_report"] = self.generate_exploit_report(state)

        return artifacts

    def generate_attack_surface_map(self, attack_surface: AttackSurface) -> Path:
        """Generate attack_surface_map.json.

        Args:
            attack_surface: Attack surface data.

        Returns:
            Path to generated file.
        """
        output_path = self.output_dir / f"attack_surface_map_{self.timestamp}.json"

        data = {
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "file_count": attack_surface.file_count,
                "lines_of_code": attack_surface.loc,
                "endpoint_count": len(attack_surface.endpoints),
                "data_flow_count": len(attack_surface.data_flows),
            },
            "languages": [
                {
                    "name": lang.name,
                    "confidence": lang.confidence,
                    "file_count": lang.file_count,
                }
                for lang in attack_surface.languages
            ],
            "frameworks": [
                {
                    "name": fw.name,
                    "version": fw.version,
                    "confidence": fw.confidence,
                }
                for fw in attack_surface.frameworks
            ],
            "endpoints": [
                {
                    "path": ep.path,
                    "method": ep.method,
                    "file_path": ep.file_path,
                    "line_number": ep.line_number,
                    "parameters": ep.parameters,
                    "authenticated": ep.authenticated,
                    "risk_score": ep.risk_score,
                }
                for ep in attack_surface.endpoints
            ],
            "data_flows": [
                {
                    "source": flow.source,
                    "source_file": flow.source_file,
                    "source_line": flow.source_line,
                    "sink": flow.sink,
                    "sink_file": flow.sink_file,
                    "sink_line": flow.sink_line,
                    "tainted": flow.tainted,
                    "sanitizers": flow.sanitizers,
                }
                for flow in attack_surface.data_flows
            ],
            "auth_boundaries": attack_surface.auth_boundaries,
            "trust_zones": attack_surface.trust_zones,
        }

        output_path.write_text(json.dumps(data, indent=2))
        return output_path

    def generate_vulnerabilities_json(self, vulnerabilities: list[Vulnerability]) -> Path:
        """Generate confirmed_vulnerabilities.json.

        Args:
            vulnerabilities: List of confirmed vulnerabilities.

        Returns:
            Path to generated file.
        """
        output_path = self.output_dir / f"confirmed_vulnerabilities_{self.timestamp}.json"

        data = {
            "generated_at": datetime.now().isoformat(),
            "total": len(vulnerabilities),
            "by_severity": {
                s.value: sum(1 for v in vulnerabilities if v.severity == s)
                for s in VulnerabilitySeverity
            },
            "vulnerabilities": [
                {
                    "id": v.id,
                    "type": v.vuln_type.value,
                    "severity": v.severity.value,
                    "score": v.score,
                    "title": v.title,
                    "description": v.description,
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "code_snippet": v.code_snippet,
                    "cwe_id": v.cwe_id,
                    "cvss": v.cvss,
                    "tool_source": v.tool_source,
                    "confidence": v.confidence,
                    "remediation": v.remediation,
                    "data_flow": {
                        "source": v.data_flow.source,
                        "sink": v.data_flow.sink,
                        "tainted": v.data_flow.tainted,
                    }
                    if v.data_flow
                    else None,
                }
                for v in vulnerabilities
            ],
        }

        output_path.write_text(json.dumps(data, indent=2))
        return output_path

    def generate_exploit_file(self, exploit: Exploit) -> Path:
        """Generate an exploit file.

        Args:
            exploit: Exploit data.

        Returns:
            Path to generated file.
        """
        # Determine file extension
        extensions = {
            "python": ".py",
            "c": ".c",
            "javascript": ".js",
            "shell": ".sh",
            "solidity": ".sol",
        }
        ext = extensions.get(exploit.language.lower(), ".txt")

        filename = f"exploit_{exploit.vulnerability_id}{ext}"
        output_path = self.output_dir / filename

        # Add header comment
        header_map = {
            ".py": f'''#!/usr/bin/env python3
"""
MrZero Exploit - {exploit.vulnerability_id}
Generated: {datetime.now().isoformat()}
Type: {exploit.exploit_type}
Tested: {exploit.tested}
Successful: {exploit.successful}

Description: {exploit.description or "N/A"}
"""

''',
            ".c": f"""/*
 * MrZero Exploit - {exploit.vulnerability_id}
 * Generated: {datetime.now().isoformat()}
 * Type: {exploit.exploit_type}
 * Tested: {exploit.tested}
 * Successful: {exploit.successful}
 *
 * Description: {exploit.description or "N/A"}
 */

""",
            ".js": f"""/**
 * MrZero Exploit - {exploit.vulnerability_id}
 * Generated: {datetime.now().isoformat()}
 * Type: {exploit.exploit_type}
 * Tested: {exploit.tested}
 * Successful: {exploit.successful}
 *
 * Description: {exploit.description or "N/A"}
 */

""",
            ".sh": f"""#!/bin/bash
# MrZero Exploit - {exploit.vulnerability_id}
# Generated: {datetime.now().isoformat()}
# Type: {exploit.exploit_type}
# Tested: {exploit.tested}
# Successful: {exploit.successful}
#
# Description: {exploit.description or "N/A"}

""",
        }

        header = header_map.get(ext, f"# MrZero Exploit - {exploit.vulnerability_id}\n\n")
        content = header + exploit.code

        output_path.write_text(content)
        return output_path

    def generate_manual_guide(self, environment: Environment, target_path: str) -> Path:
        """Generate manual_setup_guide.md when automated setup fails.

        Args:
            environment: Environment data with build errors.
            target_path: Path to target codebase.

        Returns:
            Path to generated file.
        """
        output_path = self.output_dir / f"manual_setup_guide_{self.timestamp}.md"

        content = f"""# Manual Environment Setup Guide

**Target:** {target_path}
**Generated:** {datetime.now().isoformat()}

## Overview

The automated environment setup failed. This guide provides manual steps to reproduce the findings.

## Build Errors

The following errors occurred during automated setup:

```
{chr(10).join(environment.build_errors or ["No error details available"])}
```

## Prerequisites

Based on the target analysis, you'll need:

"""
        # Add detected dependencies
        if environment.dependencies:
            content += "### Dependencies\n\n"
            for dep in environment.dependencies:
                content += f"- {dep}\n"
            content += "\n"

        content += f"""## Setup Steps

### 1. Clone/Copy the Target

```bash
cp -r {target_path} ./target
cd target
```

### 2. Install Dependencies

"""
        # Add language-specific instructions based on environment type
        if environment.env_type == "docker":
            content += """```bash
# If a Dockerfile exists:
docker build -t mrzero-target .
docker run -it mrzero-target
```

"""
        elif environment.env_type == "virtualenv":
            content += """```bash
# Python project:
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt  # or pip install -e .
```

"""
        elif environment.env_type == "npm":
            content += """```bash
# Node.js project:
npm install
# or
yarn install
```

"""

        content += """### 3. Start the Application

Refer to the project's README for specific startup instructions.

### 4. Verify Vulnerabilities

Once the environment is running, use the exploit files to verify findings.

## Troubleshooting

### Common Issues

1. **Missing dependencies**: Install build tools (`build-essential`, `python-dev`, etc.)
2. **Port conflicts**: Check if ports are already in use
3. **Permission errors**: Run with appropriate permissions or adjust file ownership
4. **Database setup**: Many apps need database initialization

### Getting Help

If you continue to have issues:
1. Check the project's issue tracker
2. Review the build logs for specific errors
3. Try running in a clean container/VM

"""
        output_path.write_text(content)
        return output_path

    def generate_exploit_report(self, state: AgentState) -> Path:
        """Generate exploit_report.md with full exploitation details.

        Args:
            state: Final workflow state.

        Returns:
            Path to generated file.
        """
        output_path = self.output_dir / f"exploit_report_{self.timestamp}.md"

        content = f"""# Exploitation Report

**Target:** {state.target_path}
**Session:** {state.session_id}
**Generated:** {datetime.now().isoformat()}

---

## Summary

| Metric | Value |
|--------|-------|
| Total Vulnerabilities | {len(state.confirmed_vulnerabilities)} |
| Exploits Generated | {len(state.exploits)} |
| Exploits Tested | {sum(1 for e in state.exploits if e.tested)} |
| Successful Exploits | {sum(1 for e in state.exploits if e.successful)} |

---

## Vulnerabilities & Exploits

"""
        for vuln in state.confirmed_vulnerabilities:
            content += f"""### {vuln.id}: {vuln.title}

**Severity:** {vuln.severity.value.upper()} (Score: {vuln.score})
**Type:** {vuln.vuln_type.value}
**Location:** `{vuln.file_path}:{vuln.line_number}`

#### Description

{vuln.description}

#### Vulnerable Code

```
{vuln.code_snippet or "N/A"}
```

"""
            # Find associated exploit
            exploit = next((e for e in state.exploits if e.vulnerability_id == vuln.id), None)

            if exploit:
                content += f"""#### Exploit

**Type:** {exploit.exploit_type}
**Language:** {exploit.language}
**Tested:** {"Yes" if exploit.tested else "No"}
**Successful:** {"Yes" if exploit.successful else "No"}

```{exploit.language}
{exploit.code[:1500]}{"..." if len(exploit.code) > 1500 else ""}
```

"""
                if exploit.test_output:
                    content += f"""#### Test Output

```
{exploit.test_output[:1000]}{"..." if len(exploit.test_output) > 1000 else ""}
```

"""
            else:
                content += "#### Exploit\n\nNo exploit generated for this vulnerability.\n\n"

            content += "---\n\n"

        # Environment section
        content += """## Environment

"""
        if state.environment:
            if state.environment.build_successful:
                content += f"""**Status:** Successful
**Type:** {state.environment.env_type}
"""
                if state.environment.container_id:
                    content += f"**Container:** `{state.environment.container_id}`\n"
                if state.environment.connection_port:
                    content += f"**Port:** {state.environment.connection_port}\n"
            else:
                content += "**Status:** Failed (see manual_setup_guide.md)\n"
        else:
            content += "Environment setup was not performed.\n"

        content += f"""

---

## Reproduction Steps

1. Set up the target environment (see manual_setup_guide.md if automated setup failed)
2. Run the exploit scripts in the `mrzero_output/` directory
3. Verify the vulnerability is exploited as described

## Notes

- All exploits are provided for authorized security testing only
- Test in isolated environments to prevent unintended damage
- Some exploits may need adjustment for your specific environment

---

*Generated by MrZero v0.1.0*
"""

        output_path.write_text(content)
        return output_path


def generate_artifacts(state: AgentState, output_dir: Path | None = None) -> dict[str, Path]:
    """Convenience function to generate all artifacts.

    Args:
        state: Final workflow state.
        output_dir: Output directory (uses config default if not specified).

    Returns:
        Dictionary mapping artifact names to file paths.
    """
    from mrzero.core.config import get_config

    if output_dir is None:
        output_dir = get_config().output_dir

    generator = ArtifactGenerator(output_dir)
    return generator.generate_all(state)
