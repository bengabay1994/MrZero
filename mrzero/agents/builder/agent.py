"""MrZeroEnvBuilder - LLM-Powered Environment Architect Agent."""

import asyncio
import json
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from mrzero.agents.base import AgentResult, AgentType, BaseAgent
from mrzero.core.memory.state import AgentState
from mrzero.core.schemas import EnvironmentInfo, Vulnerability
from mrzero.core.environment.manager import (
    EnvironmentManager,
    EnvironmentType,
    get_environment_manager,
)


class EnvBuilderAgent(BaseAgent):
    """Agent for building reproducible test environments.

    This agent uses LLM reasoning as the PRIMARY decision maker for:
    1. Understanding the vulnerability and what code path needs to be triggered
    2. Analyzing the project's build system and dependencies
    3. Deciding the best strategy to create a reproduction environment
    4. Adapting when builds fail by analyzing errors

    The LLM is the brain - all tools (Docker, Make, etc.) are just its hands.
    """

    agent_type = AgentType.ENV_BUILDER

    SYSTEM_PROMPT = """You are MrZeroEnvBuilder, an elite security researcher and DevOps engineer specializing in vulnerability reproduction environments.

## Your Role
You create minimal, targeted environments that will TRIGGER the vulnerable code path discovered by the security analysis team. Your goal is NOT to build the entire application - it's to create the smallest possible setup that reaches and executes the vulnerable code.

## Your Expertise
- Deep understanding of build systems: Docker, Make, CMake, Meson, Gradle, Maven, npm, pip, cargo, go mod
- Expert knowledge of containerization and isolation techniques
- Ability to create minimal harnesses that isolate vulnerable components
- Understanding of how vulnerabilities are triggered (inputs, conditions, state)
- Reverse engineering of complex build processes

## Analysis Methodology

For each vulnerability, you MUST understand:

1. **Vulnerable Code Path Analysis**
   - What function/method contains the vulnerability?
   - What inputs trigger this code path?
   - What conditions must be met to reach this code?
   - What dependencies does this code have?

2. **Project Build Analysis**
   - What build system does this project use?
   - What are the core dependencies?
   - Can we isolate just the vulnerable component?
   - What's the minimal build target that includes the vulnerable code?

3. **Environment Strategy Selection**
   Choose the SIMPLEST approach that works:
   - **Minimal Harness**: Extract ONLY the vulnerable file(s) + dependencies, create a test driver
   - **Component Build**: Build only the module/package containing the vulnerability
   - **Docker Environment**: Use existing Dockerfile if it's simple enough
   - **Full Build**: Only if absolutely necessary (complex interdependencies)

4. **Trigger Mechanism Design**
   - What input will trigger the vulnerability?
   - Design a test payload or trigger mechanism
   - Ensure the environment is ready for exploitation

## Key Principles

- **MINIMAL**: Always prefer the smallest possible environment
- **TARGETED**: Focus on reaching the vulnerable code path, nothing else
- **PRACTICAL**: If full build is impossible, create a working harness
- **ADAPTIVE**: When builds fail, analyze errors and try alternative approaches

## Example Scenarios

**Scenario 1**: SQL injection in a Flask route
- DON'T: Set up the entire application with all dependencies
- DO: Create a minimal Flask app with just the vulnerable route + database mock

**Scenario 2**: Buffer overflow in image parsing library
- DON'T: Build the entire multimedia application
- DO: Create a minimal C/Python harness that calls the vulnerable parsing function

**Scenario 3**: Deserialization bug in a Java service
- DON'T: Deploy the full microservice architecture
- DO: Create a minimal Java class that deserializes input using the vulnerable class"""

    BUILD_STRATEGY_PROMPT = """## Task: Design Environment Build Strategy

Analyze the vulnerability and project to create a minimal reproduction environment.

---

## Confirmed Vulnerabilities to Reproduce:

{vulnerabilities}

---

## Project Build Configuration:

{build_config}

---

## Project Structure Overview:

{project_structure}

---

## Build Files Content:

{build_files_content}

---

## Your Task

Design the MINIMAL environment that will allow triggering the vulnerable code path.

Think step by step:
1. What code path does the vulnerability require?
2. What's the minimum code needed to reach that path?
3. What dependencies are required?
4. What input/trigger will exercise the vulnerability?

Respond in this exact JSON format:
```json
{{
    "analysis": {{
        "vulnerable_code_path": "<describe the path from entry point to vulnerable code>",
        "required_dependencies": ["<list of required packages/libs>"],
        "trigger_mechanism": "<how the vulnerability will be triggered>",
        "isolation_possible": <true|false>,
        "isolation_reasoning": "<why isolation is/isn't possible>"
    }},
    "strategy": {{
        "type": "harness" | "component" | "docker" | "full_build",
        "reasoning": "<why this strategy was chosen>",
        "build_steps": [
            {{
                "step": 1,
                "action": "<what to do>",
                "command": "<shell command if applicable>",
                "working_dir": "<directory to run in, relative to target>",
                "expected_result": "<what success looks like>"
            }}
        ],
        "fallback_strategy": {{
            "type": "<alternative strategy if primary fails>",
            "trigger": "<when to switch to fallback>"
        }}
    }},
    "harness_code": {{
        "needed": <true|false>,
        "language": "<python|c|java|javascript|etc>",
        "files": [
            {{
                "filename": "<harness file name>",
                "content": "<the actual code for the harness>",
                "description": "<what this file does>"
            }}
        ]
    }},
    "trigger_payload": {{
        "type": "<file|http_request|stdin|function_call>",
        "description": "<what the trigger does>",
        "example": "<example malicious input that would trigger the vuln>"
    }},
    "expected_environment": {{
        "type": "docker" | "native" | "harness",
        "entry_point": "<how to start the vulnerable code>",
        "ready_indicator": "<how to know the environment is ready>"
    }}
}}
```"""

    BUILD_FAILURE_ANALYSIS_PROMPT = """## Task: Analyze Build Failure and Adapt Strategy

The previous build attempt failed. Analyze the error and determine the next approach.

---

## Original Strategy:

{original_strategy}

---

## Build Output/Error:

{error_output}

---

## Attempt Number: {attempt_number} of {max_attempts}

---

## Your Task

Analyze WHY the build failed and decide:
1. Can this be fixed with a small modification?
2. Should we try a different strategy entirely?
3. Should we fall back to a simpler harness approach?

Respond in this exact JSON format:
```json
{{
    "failure_analysis": {{
        "root_cause": "<what caused the failure>",
        "is_fixable": <true|false>,
        "fix_description": "<how to fix if fixable>"
    }},
    "next_action": "retry_with_fix" | "try_alternative" | "create_harness" | "generate_manual_guide",
    "updated_strategy": {{
        "type": "harness" | "component" | "docker" | "full_build",
        "build_steps": [
            {{
                "step": 1,
                "action": "<what to do>",
                "command": "<shell command>",
                "working_dir": "<directory>",
                "expected_result": "<what success looks like>"
            }}
        ]
    }},
    "reasoning": "<detailed explanation of why this approach>"
}}
```"""

    MANUAL_GUIDE_PROMPT = """## Task: Generate Manual Setup Guide

All automated build attempts failed. Create a comprehensive manual guide for setting up the reproduction environment.

---

## Vulnerability Details:

{vulnerabilities}

---

## Build Attempts and Errors:

{build_history}

---

## Project Configuration:

{build_config}

---

## Your Task

Create a detailed, actionable manual setup guide that a security researcher can follow.

Respond in this exact JSON format:
```json
{{
    "guide": {{
        "title": "<descriptive title>",
        "overview": "<1-2 paragraph overview of what needs to be set up>",
        "prerequisites": ["<list of required tools and knowledge>"],
        "sections": [
            {{
                "title": "<section title>",
                "steps": [
                    {{
                        "step_number": 1,
                        "instruction": "<detailed instruction>",
                        "commands": ["<shell commands if any>"],
                        "notes": "<important notes or warnings>"
                    }}
                ]
            }}
        ],
        "verification": {{
            "description": "<how to verify the environment is working>",
            "expected_output": "<what success looks like>"
        }},
        "troubleshooting": [
            {{
                "problem": "<common problem>",
                "solution": "<how to fix it>"
            }}
        ],
        "exploitation_notes": "<notes on how to trigger the vulnerability once environment is ready>"
    }}
}}
```"""

    MAX_BUILD_ATTEMPTS = 5

    def __init__(self, llm: Any = None, tools: list[Any] | None = None) -> None:
        """Initialize the EnvBuilder agent."""
        super().__init__(llm, tools)
        self._env_manager: EnvironmentManager | None = None

    @property
    def env_manager(self) -> EnvironmentManager:
        """Get the environment manager."""
        if self._env_manager is None:
            self._env_manager = get_environment_manager()
        return self._env_manager

    def get_system_prompt(self) -> str:
        """Get the system prompt."""
        return self.SYSTEM_PROMPT

    async def execute(self, state: AgentState) -> AgentResult:
        """Execute environment building using LLM-driven strategy.

        The LLM is the PRIMARY decision maker for:
        1. Understanding the vulnerability and required code path
        2. Choosing the build strategy
        3. Adapting when failures occur

        Args:
            state: Current workflow state.

        Returns:
            AgentResult with environment info.
        """
        target_path = Path(state.target_path)
        errors: list[str] = []
        build_history: list[dict] = []

        if not target_path.exists():
            return AgentResult(
                agent_type=self.agent_type,
                success=False,
                errors=[f"Target path does not exist: {target_path}"],
            )

        # Get confirmed vulnerabilities
        vulnerabilities = state.confirmed_vulnerabilities
        if not vulnerabilities:
            return AgentResult(
                agent_type=self.agent_type,
                success=False,
                errors=["No confirmed vulnerabilities to build environment for"],
                next_agent=AgentType.REPORTER,
            )

        # Step 1: GATHER INFORMATION for LLM
        build_config = self._gather_build_config(target_path)
        project_structure = self._gather_project_structure(target_path)
        build_files_content = self._read_build_files(target_path, build_config)

        # Step 2: LLM DECIDES the build strategy
        strategy = await self._plan_build_strategy_with_llm(
            vulnerabilities=vulnerabilities,
            build_config=build_config,
            project_structure=project_structure,
            build_files_content=build_files_content,
        )

        if not strategy:
            return AgentResult(
                agent_type=self.agent_type,
                success=False,
                errors=["LLM failed to generate build strategy"],
                next_agent=AgentType.REPORTER,
            )

        # Step 3: Execute the LLM's build plan with iterative adaptation
        env_info = EnvironmentInfo(
            env_type="unknown",
            build_successful=False,
            build_attempts=0,
        )

        current_strategy = strategy
        for attempt in range(1, self.MAX_BUILD_ATTEMPTS + 1):
            env_info.build_attempts = attempt

            # Execute current strategy
            success, result = await self._execute_build_strategy(
                target_path, current_strategy, vulnerabilities
            )

            build_history.append(
                {
                    "attempt": attempt,
                    "strategy": current_strategy.get("strategy", {}).get("type", "unknown"),
                    "success": success,
                    "output": result.get("output", "")[:500] if not success else "Success",
                }
            )

            if success:
                env_info.env_type = result.get("env_type", "unknown")
                env_info.build_successful = True
                env_info.container_id = result.get("container_id")
                env_info.connection_port = result.get("port")
                env_info.process_id = result.get("pid")
                break

            # Build failed - LLM analyzes and decides next steps
            errors.append(
                f"Build attempt {attempt} failed: {result.get('error', 'Unknown error')[:200]}"
            )

            if attempt < self.MAX_BUILD_ATTEMPTS:
                adapted_strategy = await self._analyze_failure_with_llm(
                    original_strategy=current_strategy,
                    error_output=result.get("output", "") + "\n" + result.get("error", ""),
                    attempt_number=attempt,
                    max_attempts=self.MAX_BUILD_ATTEMPTS,
                )

                if adapted_strategy:
                    current_strategy = adapted_strategy
                else:
                    # LLM couldn't adapt - try to create harness as fallback
                    current_strategy = self._create_harness_fallback_strategy(vulnerabilities)

        # Step 4: If all attempts failed, generate manual guide
        if not env_info.build_successful:
            guide_path = await self._generate_manual_guide_with_llm(
                target_path=target_path,
                vulnerabilities=vulnerabilities,
                build_config=build_config,
                build_history=build_history,
            )
            env_info.manual_guide_path = str(guide_path) if guide_path else None

        # Determine if we need human input
        requires_human = False
        human_prompt = None

        if state.mode.value == "hitl" and env_info.build_successful:
            requires_human = True
            human_prompt = (
                f"Environment built successfully ({env_info.env_type}). "
                f"Proceed to exploitation phase? (yes/no/skip)"
            )

        return AgentResult(
            agent_type=self.agent_type,
            success=env_info.build_successful,
            output={
                "environment": env_info,
                "strategy_used": current_strategy.get("strategy", {}).get("type"),
                "build_history": build_history,
            },
            errors=errors if errors else [],
            next_agent=AgentType.EXPLOIT_BUILDER
            if env_info.build_successful
            else AgentType.REPORTER,
            requires_human_input=requires_human,
            human_prompt=human_prompt,
        )

    def _gather_build_config(self, target_path: Path) -> dict[str, Any]:
        """Gather information about build configuration.

        This is just information gathering - NO decisions are made here.

        Args:
            target_path: Path to the codebase.

        Returns:
            Dictionary with build configuration info.
        """
        config: dict[str, Any] = {
            "detected_files": [],
            "languages": [],
            "build_systems": [],
        }

        # Detect build files (just collecting facts, not making decisions)
        build_file_patterns = {
            "Dockerfile*": "docker",
            "docker-compose*.yml": "docker-compose",
            "docker-compose*.yaml": "docker-compose",
            "Makefile": "make",
            "CMakeLists.txt": "cmake",
            "meson.build": "meson",
            "setup.py": "python-setuptools",
            "pyproject.toml": "python-pyproject",
            "requirements*.txt": "python-pip",
            "package.json": "npm",
            "yarn.lock": "yarn",
            "Cargo.toml": "cargo",
            "go.mod": "go",
            "pom.xml": "maven",
            "build.gradle": "gradle",
            "*.sln": "dotnet",
            "*.csproj": "dotnet",
        }

        for pattern, build_system in build_file_patterns.items():
            matches = list(target_path.rglob(pattern))
            for match in matches[:3]:  # Limit to first 3 matches per pattern
                config["detected_files"].append(
                    {
                        "path": str(match.relative_to(target_path)),
                        "build_system": build_system,
                    }
                )
                if build_system not in config["build_systems"]:
                    config["build_systems"].append(build_system)

        # Detect languages by file extension
        lang_extensions = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".java": "java",
            ".c": "c",
            ".cpp": "cpp",
            ".h": "c/cpp",
            ".go": "go",
            ".rs": "rust",
            ".rb": "ruby",
            ".php": "php",
            ".sol": "solidity",
            ".cs": "csharp",
        }

        for ext, lang in lang_extensions.items():
            if list(target_path.rglob(f"*{ext}"))[:1]:  # Just check if any exist
                if lang not in config["languages"]:
                    config["languages"].append(lang)

        # Check tool availability
        config["available_tools"] = {
            "docker": shutil.which("docker") is not None,
            "docker-compose": shutil.which("docker-compose") is not None,
            "make": shutil.which("make") is not None,
            "python3": shutil.which("python3") is not None,
            "node": shutil.which("node") is not None,
            "npm": shutil.which("npm") is not None,
        }

        return config

    def _gather_project_structure(self, target_path: Path, max_files: int = 100) -> str:
        """Gather project directory structure.

        Args:
            target_path: Path to the codebase.
            max_files: Maximum number of files to include.

        Returns:
            String representation of project structure.
        """
        structure_lines = []
        file_count = 0

        for item in sorted(target_path.rglob("*")):
            if file_count >= max_files:
                structure_lines.append(f"... and more files (truncated at {max_files})")
                break

            # Skip common non-essential directories
            skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv", ".mypy_cache"}
            if any(skip in item.parts for skip in skip_dirs):
                continue

            try:
                rel_path = item.relative_to(target_path)
                indent = "  " * (len(rel_path.parts) - 1)
                if item.is_dir():
                    structure_lines.append(f"{indent}{rel_path.name}/")
                else:
                    structure_lines.append(f"{indent}{rel_path.name}")
                    file_count += 1
            except ValueError:
                continue

        return "\n".join(structure_lines[:200])  # Limit output

    def _read_build_files(self, target_path: Path, build_config: dict[str, Any]) -> str:
        """Read contents of detected build files.

        Args:
            target_path: Path to the codebase.
            build_config: Build configuration with detected files.

        Returns:
            String with build file contents.
        """
        contents = []

        for file_info in build_config.get("detected_files", [])[:10]:  # Limit to 10 files
            file_path = target_path / file_info["path"]
            try:
                if file_path.exists() and file_path.stat().st_size < 50000:  # Skip large files
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    contents.append(
                        f"### {file_info['path']} ({file_info['build_system']})\n```\n{content[:3000]}\n```\n"
                    )
            except Exception:
                continue

        return "\n".join(contents) if contents else "No build files could be read."

    def _format_vulnerabilities(self, vulnerabilities: list[Vulnerability]) -> str:
        """Format vulnerabilities for LLM prompt.

        Args:
            vulnerabilities: List of confirmed vulnerabilities.

        Returns:
            Formatted string describing vulnerabilities.
        """
        formatted = []
        for vuln in vulnerabilities[:5]:  # Limit to top 5
            formatted.append(
                f"### {vuln.id}: {vuln.title}\n"
                f"- **Type:** {vuln.vuln_type.value}\n"
                f"- **Severity:** {vuln.severity.value} (Score: {vuln.score})\n"
                f"- **File:** `{vuln.file_path}:{vuln.line_number}`\n"
                f"- **Description:** {vuln.description[:300] if vuln.description else 'N/A'}\n"
                f"- **Code:**\n```\n{vuln.code_snippet[:500] if vuln.code_snippet else 'N/A'}\n```\n"
            )
        return "\n".join(formatted)

    async def _plan_build_strategy_with_llm(
        self,
        vulnerabilities: list[Vulnerability],
        build_config: dict[str, Any],
        project_structure: str,
        build_files_content: str,
    ) -> dict[str, Any] | None:
        """Use LLM to plan the build strategy.

        The LLM is the PRIMARY decision maker here.

        Args:
            vulnerabilities: Confirmed vulnerabilities.
            build_config: Build configuration info.
            project_structure: Project directory structure.
            build_files_content: Contents of build files.

        Returns:
            LLM's build strategy or None if failed.
        """
        prompt = self.BUILD_STRATEGY_PROMPT.format(
            vulnerabilities=self._format_vulnerabilities(vulnerabilities),
            build_config=json.dumps(build_config, indent=2),
            project_structure=project_structure,
            build_files_content=build_files_content,
        )

        try:
            response = await self.chat(prompt)
            return self._parse_llm_json_response(response)
        except Exception:
            return None

    async def _analyze_failure_with_llm(
        self,
        original_strategy: dict[str, Any],
        error_output: str,
        attempt_number: int,
        max_attempts: int,
    ) -> dict[str, Any] | None:
        """Use LLM to analyze build failure and adapt strategy.

        Args:
            original_strategy: The strategy that failed.
            error_output: Error output from the build.
            attempt_number: Current attempt number.
            max_attempts: Maximum number of attempts.

        Returns:
            Adapted strategy or None.
        """
        prompt = self.BUILD_FAILURE_ANALYSIS_PROMPT.format(
            original_strategy=json.dumps(original_strategy, indent=2),
            error_output=error_output[:3000],
            attempt_number=attempt_number,
            max_attempts=max_attempts,
        )

        try:
            response = await self.chat(prompt)
            analysis = self._parse_llm_json_response(response)

            if analysis and analysis.get("next_action") != "generate_manual_guide":
                # Return the adapted strategy in the same format as original
                return {
                    "strategy": analysis.get("updated_strategy", {}),
                    "analysis": analysis.get("failure_analysis", {}),
                }
            return None
        except Exception:
            return None

    async def _generate_manual_guide_with_llm(
        self,
        target_path: Path,
        vulnerabilities: list[Vulnerability],
        build_config: dict[str, Any],
        build_history: list[dict],
    ) -> Path | None:
        """Use LLM to generate a comprehensive manual setup guide.

        Args:
            target_path: Path to the codebase.
            vulnerabilities: List of vulnerabilities.
            build_config: Build configuration.
            build_history: History of build attempts.

        Returns:
            Path to the generated guide or None.
        """
        prompt = self.MANUAL_GUIDE_PROMPT.format(
            vulnerabilities=self._format_vulnerabilities(vulnerabilities),
            build_history=json.dumps(build_history, indent=2),
            build_config=json.dumps(build_config, indent=2),
        )

        try:
            response = await self.chat(prompt)
            guide_data = self._parse_llm_json_response(response)

            if guide_data and "guide" in guide_data:
                return self._write_manual_guide(target_path, guide_data["guide"])
            return None
        except Exception:
            return None

    def _write_manual_guide(self, target_path: Path, guide: dict[str, Any]) -> Path:
        """Write the manual guide to a markdown file.

        Args:
            target_path: Path to the codebase.
            guide: Guide data from LLM.

        Returns:
            Path to the generated guide.
        """
        from mrzero.core.config import get_config

        output_dir = get_config().output_dir
        output_dir.mkdir(parents=True, exist_ok=True)

        guide_path = output_dir / "manual_setup_guide.md"

        content = [f"# {guide.get('title', 'Manual Setup Guide')}\n"]
        content.append(f"\n{guide.get('overview', '')}\n")

        if guide.get("prerequisites"):
            content.append("\n## Prerequisites\n")
            for prereq in guide["prerequisites"]:
                content.append(f"- {prereq}\n")

        for section in guide.get("sections", []):
            content.append(f"\n## {section.get('title', 'Section')}\n")
            for step in section.get("steps", []):
                content.append(f"\n### Step {step.get('step_number', '?')}\n")
                content.append(f"{step.get('instruction', '')}\n")
                if step.get("commands"):
                    content.append("```bash\n")
                    for cmd in step["commands"]:
                        content.append(f"{cmd}\n")
                    content.append("```\n")
                if step.get("notes"):
                    content.append(f"\n> **Note:** {step['notes']}\n")

        if guide.get("verification"):
            content.append("\n## Verification\n")
            content.append(f"{guide['verification'].get('description', '')}\n")
            if guide["verification"].get("expected_output"):
                content.append(
                    f"\nExpected output:\n```\n{guide['verification']['expected_output']}\n```\n"
                )

        if guide.get("troubleshooting"):
            content.append("\n## Troubleshooting\n")
            for item in guide["troubleshooting"]:
                content.append(f"\n### {item.get('problem', 'Problem')}\n")
                content.append(f"{item.get('solution', '')}\n")

        if guide.get("exploitation_notes"):
            content.append("\n## Exploitation Notes\n")
            content.append(f"{guide['exploitation_notes']}\n")

        guide_path.write_text("".join(content))
        return guide_path

    async def _execute_build_strategy(
        self,
        target_path: Path,
        strategy: dict[str, Any],
        vulnerabilities: list[Vulnerability],
    ) -> tuple[bool, dict[str, Any]]:
        """Execute the LLM's build strategy using EnvironmentManager.

        Args:
            target_path: Path to the codebase.
            strategy: LLM's build strategy.
            vulnerabilities: List of vulnerabilities.

        Returns:
            Tuple of (success, result_info).
        """
        strategy_info = strategy.get("strategy", {})
        strategy_type = strategy_info.get("type", "harness")
        build_steps = strategy_info.get("build_steps", [])
        harness_code = strategy.get("harness_code", {})

        result: dict[str, Any] = {"output": "", "error": "", "env_type": strategy_type}

        try:
            # Handle different strategy types
            if strategy_type == "docker":
                return await self._execute_docker_strategy(target_path, build_steps, result)
            elif strategy_type == "docker-compose":
                return await self._execute_compose_strategy(target_path, build_steps, result)
            elif strategy_type in ("harness", "component"):
                return await self._execute_harness_strategy(
                    target_path, build_steps, harness_code, vulnerabilities, result
                )
            else:
                # Full build - execute build steps directly
                return await self._execute_build_steps(target_path, build_steps, result)

        except Exception as e:
            result["error"] = str(e)
            return False, result

    async def _execute_docker_strategy(
        self,
        target_path: Path,
        build_steps: list[dict],
        result: dict[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        """Execute Docker-based build strategy.

        Args:
            target_path: Path to the codebase.
            build_steps: Build steps from LLM.
            result: Result dict to populate.

        Returns:
            Tuple of (success, result_info).
        """
        all_output = []

        # Check Docker availability
        if not self.env_manager.docker_available():
            result["error"] = "Docker is not available"
            return False, result

        # First, try to build the image
        build_result = await self.env_manager.build_docker_image(
            target_path=target_path,
            timeout=300,
        )

        all_output.append(f"Docker build: {build_result.message or build_result.error}")
        all_output.append(
            f"Build output: {build_result.output[:500] if build_result.output else 'N/A'}"
        )

        if not build_result.success:
            result["output"] = "\n".join(all_output)
            result["error"] = build_result.error
            return False, result

        # Ensure we have an image name
        image_name = build_result.image_name
        if not image_name:
            result["output"] = "\n".join(all_output)
            result["error"] = "Docker build succeeded but no image name returned"
            return False, result

        # Run the container
        run_result = await self.env_manager.run_docker_container(
            image_name=image_name,
            ports={8080: 8080},  # Default port mapping
            detach=True,
        )

        all_output.append(f"Container start: {run_result.message or run_result.error}")

        if not run_result.success:
            result["output"] = "\n".join(all_output)
            result["error"] = run_result.error
            return False, result

        # Wait a bit for container to initialize
        await asyncio.sleep(2)

        # Health check
        container_healthy = await self.env_manager.container_health_check(
            run_result.container_id or ""
        )

        if container_healthy:
            result["output"] = "\n".join(all_output)
            result["container_id"] = run_result.container_id
            result["port"] = run_result.port or 8080
            result["image_name"] = build_result.image_name
            return True, result
        else:
            # Get logs for debugging
            logs = await self.env_manager.get_container_logs(run_result.container_id or "", tail=50)
            all_output.append(f"Container logs:\n{logs}")
            result["output"] = "\n".join(all_output)
            result["error"] = "Container started but failed health check"
            return False, result

    async def _execute_compose_strategy(
        self,
        target_path: Path,
        build_steps: list[dict],
        result: dict[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        """Execute docker-compose based strategy.

        Args:
            target_path: Path to the codebase.
            build_steps: Build steps from LLM.
            result: Result dict to populate.

        Returns:
            Tuple of (success, result_info).
        """
        all_output = []

        # Run docker-compose up
        compose_result = await self.env_manager.compose_up(
            target_path=target_path,
            build=True,
            detach=True,
            timeout=300,
        )

        all_output.append(f"docker-compose: {compose_result.message or compose_result.error}")
        all_output.append(
            f"Output: {compose_result.output[:500] if compose_result.output else 'N/A'}"
        )

        result["output"] = "\n".join(all_output)

        if compose_result.success:
            result["container_id"] = compose_result.container_id
            result["port"] = compose_result.port or 8080
            return True, result
        else:
            result["error"] = compose_result.error
            return False, result

    async def _execute_harness_strategy(
        self,
        target_path: Path,
        build_steps: list[dict],
        harness_code: dict[str, Any],
        vulnerabilities: list[Vulnerability],
        result: dict[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        """Execute harness-based strategy.

        Args:
            target_path: Path to the codebase.
            build_steps: Build steps from LLM.
            harness_code: Harness code specification.
            vulnerabilities: List of vulnerabilities.
            result: Result dict to populate.

        Returns:
            Tuple of (success, result_info).
        """
        all_output = []

        # Create harness files if needed
        if harness_code.get("needed", False):
            harness_result = await self._create_harness_files(
                target_path, harness_code, vulnerabilities
            )
            if not harness_result["success"]:
                result["error"] = harness_result["error"]
                return False, result
            result["harness_dir"] = harness_result["harness_dir"]
            all_output.append(f"Created harness at: {harness_result['harness_dir']}")

        # Execute any additional build steps
        if build_steps:
            success, step_result = await self._execute_build_steps(target_path, build_steps, result)
            all_output.append(step_result.get("output", ""))
            if not success:
                result["output"] = "\n".join(all_output)
                return False, result

        # Verify harness can run
        harness_dir = Path(result.get("harness_dir", target_path / ".mrzero_harness"))
        if harness_dir.exists():
            harness_verify = await self.env_manager.run_harness(
                harness_path=harness_dir,
                timeout=30,
            )
            all_output.append(
                f"Harness verification: {'Success' if harness_verify.success else 'Failed'}"
            )
            if harness_verify.output:
                all_output.append(f"Harness output:\n{harness_verify.output[:300]}")

        result["output"] = "\n".join(all_output)
        result["harness_dir"] = str(harness_dir)
        return True, result

    async def _execute_build_steps(
        self,
        target_path: Path,
        build_steps: list[dict],
        result: dict[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        """Execute a list of build steps.

        Args:
            target_path: Path to the codebase.
            build_steps: List of build steps.
            result: Result dict to populate.

        Returns:
            Tuple of (success, result_info).
        """
        all_output = []

        for step in build_steps:
            command = step.get("command", "")
            if not command:
                continue

            working_dir = target_path / step.get("working_dir", ".")
            if not working_dir.exists():
                working_dir = target_path

            step_result = await self._run_command(command, working_dir)
            all_output.append(f"Step {step.get('step', '?')}: {step.get('action', '')}")
            all_output.append(f"Command: {command}")
            all_output.append(f"Output: {step_result['output'][:500]}")

            if not step_result["success"]:
                result["output"] = "\n".join(all_output)
                result["error"] = step_result["error"]
                return False, result

        result["output"] = "\n".join(all_output)
        return True, result

    async def _create_harness_files(
        self,
        target_path: Path,
        harness_code: dict[str, Any],
        vulnerabilities: list[Vulnerability],
    ) -> dict[str, Any]:
        """Create harness files as specified by LLM.

        Args:
            target_path: Path to the codebase.
            harness_code: Harness code specification from LLM.
            vulnerabilities: List of vulnerabilities.

        Returns:
            Result dict with success status.
        """
        harness_dir = target_path / ".mrzero_harness"
        harness_dir.mkdir(exist_ok=True)

        try:
            # Copy vulnerable files to harness
            for vuln in vulnerabilities[:3]:
                vuln_file = target_path / vuln.file_path
                if vuln_file.exists():
                    dest = harness_dir / vuln_file.name
                    shutil.copy(vuln_file, dest)

            # Create files specified by LLM
            for file_spec in harness_code.get("files", []):
                filename = file_spec.get("filename", "harness.py")
                content = file_spec.get("content", "")
                file_path = harness_dir / filename
                file_path.write_text(content)

            return {"success": True, "harness_dir": str(harness_dir)}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _run_command(
        self, command: str, working_dir: Path, timeout: int = 300
    ) -> dict[str, Any]:
        """Run a shell command.

        Args:
            command: Command to run.
            working_dir: Working directory.
            timeout: Timeout in seconds.

        Returns:
            Result dict with output and success status.
        """
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                cwd=str(working_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

            return {
                "success": proc.returncode == 0,
                "output": stdout.decode("utf-8", errors="ignore"),
                "error": stderr.decode("utf-8", errors="ignore"),
                "returncode": proc.returncode,
            }

        except asyncio.TimeoutError:
            return {
                "success": False,
                "output": "",
                "error": f"Command timed out after {timeout}s",
                "returncode": -1,
            }
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": str(e),
                "returncode": -1,
            }

    async def _get_docker_container_info(self, target_path: Path) -> dict[str, Any]:
        """Get Docker container info if running.

        Args:
            target_path: Path to check for docker-compose.

        Returns:
            Container info dict.
        """
        # Check active environments in the manager
        active = self.env_manager.get_active_environments()
        for name, state in active.items():
            if state.target_path == str(target_path) and state.container_id:
                return {
                    "success": True,
                    "container_id": state.container_id,
                    "port": state.port or 8080,
                }

        # Fallback: try docker-compose ps
        try:
            result = await self._run_command("docker-compose ps -q", target_path, timeout=30)
            if result["success"] and result["output"].strip():
                container_id = result["output"].strip().split("\n")[0][:12]
                return {"success": True, "container_id": container_id, "port": 8080}

            # Try getting running containers with mrzero prefix
            result = await self._run_command(
                "docker ps -q --filter 'name=mrzero' | head -1",
                target_path,
                timeout=30,
            )
            if result["success"] and result["output"].strip():
                return {
                    "success": True,
                    "container_id": result["output"].strip()[:12],
                    "port": 8080,
                }

            return {"success": False}

        except Exception:
            return {"success": False}

    def _create_harness_fallback_strategy(
        self, vulnerabilities: list[Vulnerability]
    ) -> dict[str, Any]:
        """Create a minimal harness fallback strategy.

        This is used when LLM adaptation fails.

        Args:
            vulnerabilities: List of vulnerabilities.

        Returns:
            Simple harness strategy.
        """
        top_vuln = vulnerabilities[0]

        return {
            "strategy": {
                "type": "harness",
                "reasoning": "Fallback to minimal harness after build failures",
                "build_steps": [],
            },
            "harness_code": {
                "needed": True,
                "language": "python",
                "files": [
                    {
                        "filename": "harness.py",
                        "content": f'''"""MrZero minimal harness for {top_vuln.file_path}"""

import sys
import os

# Add harness directory to path
sys.path.insert(0, os.path.dirname(__file__))

print("=" * 60)
print("MrZero Minimal Harness")
print("=" * 60)
print(f"Target Vulnerability: {top_vuln.title}")
print(f"File: {top_vuln.file_path}:{top_vuln.line_number}")
print(f"Type: {top_vuln.vuln_type.value}")
print("=" * 60)

# Attempt to import the vulnerable module
try:
    from {Path(top_vuln.file_path).stem} import *
    print("Successfully imported vulnerable module")
except ImportError as e:
    print(f"Import error: {{e}}")
    print("Module may have dependencies that need to be installed")

print("\\nHarness is ready for manual testing.")
print("Use Python's interactive mode or write test code here.")

if __name__ == "__main__":
    import code
    code.interact(local=locals())
''',
                        "description": "Minimal Python harness for testing",
                    }
                ],
            },
        }

    def _parse_llm_json_response(self, response: str) -> dict[str, Any] | None:
        """Parse LLM's JSON response.

        Args:
            response: Raw LLM response.

        Returns:
            Parsed JSON dict or None.
        """
        try:
            # Try to find JSON in ```json ... ``` blocks
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
