"""MrZeroMapper - LLM-Powered Attack Surface Surveyor Agent."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from mrzero.agents.base import AgentResult, AgentType, BaseAgent
from mrzero.core.memory.state import AgentState
from mrzero.core.schemas import (
    AttackSurfaceMap,
    DataFlow,
    Endpoint,
    Technology,
)


class MapperAgent(BaseAgent):
    """Agent for mapping the attack surface of a codebase using LLM analysis.

    This agent uses the LLM as the PRIMARY decision maker for understanding
    the codebase structure and identifying security-relevant components.
    Tools are used to gather raw information, but the LLM interprets and
    analyzes everything.
    """

    agent_type = AgentType.MAPPER

    SYSTEM_PROMPT = """You are MrZeroMapper, an elite security researcher specializing in attack surface analysis and reconnaissance.

## Your Mission
Analyze codebases to create comprehensive attack surface maps that will guide vulnerability hunting.
You identify technologies, entry points, data flows, and potential security concerns.

## Your Expertise
- **Technology Fingerprinting**: Identify languages, frameworks, and libraries
- **Entry Point Discovery**: Find API endpoints, routes, handlers, and user input points
- **Data Flow Mapping**: Trace how data moves from sources (user input) to sinks (dangerous operations)
- **Security Boundary Analysis**: Identify authentication, authorization, and trust boundaries
- **Dependency Analysis**: Understand external dependencies and their security implications

## What You Look For

### Entry Points (Attack Vectors)
- HTTP routes and API endpoints (especially unauthenticated ones)
- WebSocket handlers
- Command-line argument parsers
- File upload handlers
- Form processors
- GraphQL resolvers
- RPC endpoints

### Dangerous Sinks
- Database query functions
- Command execution functions
- File system operations
- Template rendering
- Deserialization functions
- Network request functions

### Security-Relevant Code
- Authentication logic
- Authorization checks
- Session management
- Cryptographic operations
- Input validation functions
- Output encoding functions

## Output Quality
Your attack surface map directly influences vulnerability hunting effectiveness.
Be thorough, accurate, and security-focused."""

    ANALYSIS_PROMPT = """## Attack Surface Mapping Task

Analyze this codebase and create a comprehensive attack surface map.

### Target Path
{target_path}

### File Structure
{file_structure}

### Dependency Files Found
{dependency_info}

### Source Code Samples
{code_samples}

---

## Your Task

Analyze the codebase and identify:

1. **Languages & Technologies**: What languages and frameworks are used?
2. **Entry Points**: What are all the ways user input enters the system?
3. **Data Flows**: How does data flow from user input to dangerous operations?
4. **Security Boundaries**: Where are authentication/authorization checks?
5. **Risk Assessment**: What areas are most likely to have vulnerabilities?

Respond with a JSON object:

```json
{{
    "languages": [
        {{
            "name": "<language name>",
            "confidence": <0.0-1.0>,
            "file_count": <estimated count>
        }}
    ],
    "frameworks": [
        {{
            "name": "<framework name>",
            "version": "<version or null>",
            "category": "<web framework|frontend|database|etc>"
        }}
    ],
    "endpoints": [
        {{
            "path": "<route path>",
            "method": "<HTTP method or N/A>",
            "file_path": "<file where defined>",
            "line_number": <line number>,
            "authenticated": <true|false>,
            "description": "<what this endpoint does>",
            "risk_score": <0-100>
        }}
    ],
    "data_flows": [
        {{
            "source": "<where data comes from>",
            "sink": "<where data goes>",
            "source_file": "<file path>",
            "source_line": <line>,
            "sink_file": "<file path>",
            "sink_line": <line>,
            "tainted": <true if no sanitization|false>,
            "description": "<description of the flow>"
        }}
    ],
    "auth_boundaries": [
        "<file or function that handles auth>"
    ],
    "trust_zones": [
        "<description of trust boundary>"
    ],
    "risk_assessment": {{
        "overall_risk": <1-10>,
        "high_risk_areas": ["<area1>", "<area2>"],
        "attack_vectors": ["<likely attack vector 1>", "<vector 2>"],
        "recommendations": ["<what hunter should focus on>"]
    }}
}}
```

Be thorough - the vulnerability hunter depends on your analysis."""

    def __init__(self, llm: Any = None, tools: list[Any] | None = None) -> None:
        """Initialize the Mapper agent."""
        super().__init__(llm, tools)
        self._indexer = None

    def get_system_prompt(self) -> str:
        """Get the system prompt."""
        return self.SYSTEM_PROMPT

    async def execute(self, state: AgentState) -> AgentResult:
        """Execute attack surface mapping using LLM analysis.

        The LLM is the PRIMARY decision maker. We gather raw information
        using file system operations, then send everything to the LLM
        for analysis.

        Args:
            state: Current workflow state.

        Returns:
            AgentResult with attack surface map.
        """
        target_path = Path(state.target_path)
        errors: list[str] = []

        if not target_path.exists():
            return AgentResult(
                agent_type=self.agent_type,
                success=False,
                errors=[f"Target path does not exist: {target_path}"],
            )

        # Step 1: Index codebase into VectorDB for semantic search (tool usage)
        index_stats = await self._index_codebase(state.session_id, target_path)
        if index_stats.get("status") == "error":
            errors.append(f"VectorDB indexing failed: {index_stats.get('error')}")

        # Step 2: Gather raw information (no decisions yet)

        # 2a. Get file structure
        file_structure = self._get_file_structure(target_path)

        # 2b. Read dependency files
        dependency_info = self._read_dependency_files(target_path)

        # 2c. Read code samples (prioritize likely entry points)
        code_samples = self._read_code_samples(target_path)

        # 2d. Get basic file stats
        file_count, loc = self._get_file_stats(target_path)

        # Step 3: Send everything to LLM for analysis (LLM makes ALL decisions)
        llm_analysis = await self._analyze_with_llm(
            target_path=str(target_path),
            file_structure=file_structure,
            dependency_info=dependency_info,
            code_samples=code_samples,
        )

        # Step 4: Build attack surface map from LLM analysis
        attack_surface = self._build_attack_surface(
            target_path=str(target_path),
            llm_analysis=llm_analysis,
            file_count=file_count,
            loc=loc,
        )

        return AgentResult(
            agent_type=self.agent_type,
            success=True,
            output={
                "attack_surface": attack_surface,
                "llm_analysis": llm_analysis,
                "index_stats": index_stats,
            },
            errors=errors if errors else [],
            next_agent=AgentType.HUNTER,
        )

    async def _index_codebase(self, session_id: str, target_path: Path) -> dict[str, Any]:
        """Index the codebase into VectorDB for semantic search.

        Args:
            session_id: Session identifier.
            target_path: Path to the codebase.

        Returns:
            Indexing statistics.
        """
        try:
            from mrzero.core.indexing import get_indexer

            self._indexer = get_indexer(session_id)
            stats = self._indexer.index_codebase(target_path)
            return stats
        except ImportError:
            return {"status": "skipped", "reason": "VectorDB not available"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _get_file_structure(self, target_path: Path, max_entries: int = 200) -> str:
        """Get file structure for LLM analysis.

        Args:
            target_path: Path to the codebase.
            max_entries: Maximum entries to include.

        Returns:
            Formatted file structure.
        """
        entries = []
        skip_dirs = {
            "node_modules",
            "venv",
            ".venv",
            "__pycache__",
            ".git",
            "dist",
            "build",
            ".next",
            "target",
        }

        for item in sorted(target_path.rglob("*")):
            # Skip unwanted directories
            if any(skip_dir in item.parts for skip_dir in skip_dirs):
                continue

            if item.is_file():
                rel_path = str(item.relative_to(target_path))
                size = item.stat().st_size
                entries.append(f"  {rel_path} ({size} bytes)")

            if len(entries) >= max_entries:
                entries.append(f"  ... and more files (truncated at {max_entries})")
                break

        return "\n".join(entries) if entries else "No files found."

    def _read_dependency_files(self, target_path: Path) -> str:
        """Read dependency/config files for analysis.

        Args:
            target_path: Path to the codebase.

        Returns:
            Formatted dependency information.
        """
        dep_files = [
            "requirements.txt",
            "package.json",
            "Pipfile",
            "pyproject.toml",
            "go.mod",
            "Gemfile",
            "pom.xml",
            "Cargo.toml",
            "composer.json",
            "Dockerfile",
            "docker-compose.yml",
            "Makefile",
            ".env.example",
        ]

        content_parts = []

        for dep_file in dep_files:
            for file_path in target_path.rglob(dep_file):
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    # Truncate large files
                    if len(content) > 3000:
                        content = content[:3000] + "\n... [truncated]"

                    rel_path = str(file_path.relative_to(target_path))
                    content_parts.append(f"### {rel_path}\n```\n{content}\n```\n")
                except Exception:
                    continue

        return "\n".join(content_parts) if content_parts else "No dependency files found."

    def _read_code_samples(
        self, target_path: Path, max_files: int = 30, max_lines: int = 300
    ) -> str:
        """Read code samples, prioritizing security-relevant files.

        Args:
            target_path: Path to the codebase.
            max_files: Maximum files to read.
            max_lines: Maximum lines per file.

        Returns:
            Formatted code samples.
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
        }
        # Base directories to always skip
        skip_dirs = {
            "node_modules",
            "venv",
            ".venv",
            "__pycache__",
            ".git",
            "dist",
            "build",
        }

        # Only skip test directories if the target itself is not in a test path
        target_in_test = any(
            part in {"test", "tests", "__tests__"} for part in target_path.resolve().parts
        )
        if not target_in_test:
            skip_dirs.update({"test", "tests", "__tests__"})

        # Priority keywords for file selection
        priority_keywords = [
            "app",
            "main",
            "index",
            "server",
            "api",
            "route",
            "router",
            "controller",
            "view",
            "handler",
            "auth",
            "login",
            "user",
            "admin",
            "config",
            "db",
            "database",
        ]

        all_files = []
        for file_path in target_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() not in code_extensions:
                continue
            if any(skip_dir in file_path.parts for skip_dir in skip_dirs):
                continue

            # Calculate priority
            name_lower = file_path.name.lower()
            priority = sum(1 for kw in priority_keywords if kw in name_lower)
            all_files.append((priority, file_path))

        # Sort by priority
        all_files.sort(key=lambda x: -x[0])

        content_parts = []
        for _, file_path in all_files[:max_files]:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                lines = content.split("\n")

                if len(lines) > max_lines:
                    lines = lines[:max_lines]
                    lines.append(
                        f"... [truncated, {len(content.split(chr(10))) - max_lines} more lines]"
                    )

                rel_path = str(file_path.relative_to(target_path))
                numbered = [f"{i + 1:4d} | {line}" for i, line in enumerate(lines)]

                content_parts.append(f"### {rel_path}\n```\n" + "\n".join(numbered) + "\n```\n")
            except Exception:
                continue

        return "\n".join(content_parts) if content_parts else "No code files found."

    def _get_file_stats(self, target_path: Path) -> tuple[int, int]:
        """Get basic file statistics.

        Args:
            target_path: Path to the codebase.

        Returns:
            Tuple of (file_count, lines_of_code).
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
            ".c",
            ".cpp",
            ".h",
        }
        skip_dirs = {"node_modules", "venv", ".venv", "__pycache__", ".git"}

        file_count = 0
        loc = 0

        for file_path in target_path.rglob("*"):
            if not file_path.is_file():
                continue
            if any(skip_dir in file_path.parts for skip_dir in skip_dirs):
                continue
            if file_path.suffix.lower() in code_extensions:
                file_count += 1
                try:
                    loc += len(file_path.read_text(encoding="utf-8", errors="ignore").split("\n"))
                except Exception:
                    pass

        return file_count, loc

    async def _analyze_with_llm(
        self,
        target_path: str,
        file_structure: str,
        dependency_info: str,
        code_samples: str,
    ) -> dict[str, Any]:
        """Send gathered information to LLM for analysis.

        The LLM makes ALL decisions about the attack surface.

        Args:
            target_path: Path to target.
            file_structure: File structure listing.
            dependency_info: Dependency file contents.
            code_samples: Code samples.

        Returns:
            LLM analysis results.
        """
        prompt = self.ANALYSIS_PROMPT.format(
            target_path=target_path,
            file_structure=file_structure,
            dependency_info=dependency_info,
            code_samples=code_samples,
        )

        try:
            response = await self.chat(prompt)
            return self._parse_llm_response(response)
        except Exception as e:
            return {"error": str(e), "status": "llm_analysis_failed"}

    def _parse_llm_response(self, response: str) -> dict[str, Any]:
        """Parse LLM response JSON.

        Args:
            response: Raw LLM response.

        Returns:
            Parsed JSON dict.
        """
        import re

        try:
            # Find JSON in response
            json_match = re.search(r"```json\s*([\s\S]*?)\s*```", response)
            if json_match:
                return json.loads(json_match.group(1))

            # Try to find raw JSON
            json_match = re.search(r"\{[\s\S]*\}", response)
            if json_match:
                return json.loads(json_match.group())

        except json.JSONDecodeError:
            pass

        return {"raw_response": response}

    def _build_attack_surface(
        self,
        target_path: str,
        llm_analysis: dict[str, Any],
        file_count: int,
        loc: int,
    ) -> AttackSurfaceMap:
        """Build AttackSurfaceMap from LLM analysis.

        Args:
            target_path: Path to target.
            llm_analysis: LLM analysis results.
            file_count: Number of files.
            loc: Lines of code.

        Returns:
            AttackSurfaceMap object.
        """
        # Parse languages
        languages = []
        for lang_data in llm_analysis.get("languages", []):
            try:
                languages.append(
                    Technology(
                        name=lang_data.get("name", "Unknown"),
                        category="language",
                        confidence=lang_data.get("confidence", 0.5),
                        file_count=lang_data.get("file_count", 0),
                    )
                )
            except Exception:
                continue

        # Parse frameworks
        frameworks = []
        for fw_data in llm_analysis.get("frameworks", []):
            try:
                frameworks.append(
                    Technology(
                        name=fw_data.get("name", "Unknown"),
                        version=fw_data.get("version"),
                        category=fw_data.get("category", "framework"),
                        confidence=0.8,
                    )
                )
            except Exception:
                continue

        # Parse endpoints
        endpoints = []
        for ep_data in llm_analysis.get("endpoints", []):
            try:
                endpoints.append(
                    Endpoint(
                        path=ep_data.get("path", "/"),
                        method=ep_data.get("method", "GET"),
                        file_path=ep_data.get("file_path", ""),
                        line_number=ep_data.get("line_number", 0),
                        authenticated=ep_data.get("authenticated", False),
                        risk_score=ep_data.get("risk_score", 50),
                    )
                )
            except Exception:
                continue

        # Parse data flows
        data_flows = []
        for flow_data in llm_analysis.get("data_flows", []):
            try:
                data_flows.append(
                    DataFlow(
                        source=flow_data.get("source", "unknown"),
                        sink=flow_data.get("sink", "unknown"),
                        source_file=flow_data.get("source_file", ""),
                        source_line=flow_data.get("source_line", 0),
                        sink_file=flow_data.get("sink_file", ""),
                        sink_line=flow_data.get("sink_line", 0),
                        tainted=flow_data.get("tainted", True),
                        sanitizers=flow_data.get("sanitizers", []),
                    )
                )
            except Exception:
                continue

        # Get auth boundaries and trust zones
        auth_boundaries = llm_analysis.get("auth_boundaries", [])
        trust_zones = llm_analysis.get("trust_zones", [])

        return AttackSurfaceMap(
            target_path=target_path,
            scan_timestamp=datetime.now(),
            languages=languages,
            frameworks=frameworks,
            endpoints=endpoints,
            data_flows=data_flows,
            dependencies={},  # Could parse from dependency_info if needed
            file_count=file_count,
            loc=loc,
            auth_boundaries=auth_boundaries,
            trust_zones=trust_zones,
        )
