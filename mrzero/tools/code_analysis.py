"""CodeQL, Joern, and Tree-sitter tool wrappers."""

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from mrzero.tools.base import BaseTool, ToolOutput


class CodeQLTool(BaseTool):
    """Wrapper for CodeQL semantic code analysis.

    CodeQL is a semantic code analysis engine that lets you query code as data.
    https://github.com/github/codeql
    """

    name = "codeql"
    description = "Semantic code analysis engine for finding vulnerabilities"
    required_binary = "codeql"

    # Default query suites for different languages
    QUERY_SUITES = {
        "python": "python-security-and-quality",
        "javascript": "javascript-security-and-quality",
        "java": "java-security-and-quality",
        "cpp": "cpp-security-and-quality",
        "csharp": "csharp-security-and-quality",
        "go": "go-security-and-quality",
        "ruby": "ruby-security-and-quality",
    }

    async def run(
        self,
        target: str,
        language: str | None = None,
        query_suite: str | None = None,
        output_format: str = "sarif",
        threads: int = 4,
        **kwargs: Any,
    ) -> ToolOutput:
        """Run CodeQL analysis.

        Args:
            target: Target directory to analyze.
            language: Programming language (auto-detected if not specified).
            query_suite: Query suite to use.
            output_format: Output format (sarif, csv, json).
            threads: Number of threads to use.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with analysis results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="CodeQL is not installed. Get it from: https://github.com/github/codeql-cli-binaries",
            )

        target_path = Path(target)
        if not target_path.exists():
            return ToolOutput(
                success=False,
                data={},
                error=f"Target path does not exist: {target}",
            )

        # Auto-detect language if not specified
        if language is None:
            language = self._detect_language(target_path)

        if language is None:
            return ToolOutput(
                success=False,
                data={},
                error="Could not detect language. Please specify --language",
            )

        # Create temporary database path
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "codeql-db"
            results_path = Path(temp_dir) / f"results.{output_format}"

            # Step 1: Create database
            create_cmd = [
                "codeql",
                "database",
                "create",
                str(db_path),
                f"--language={language}",
                f"--source-root={target}",
                f"--threads={threads}",
                "--overwrite",
            ]

            returncode, stdout, stderr = await self._run_command(create_cmd, timeout=900)
            if returncode != 0:
                return ToolOutput(
                    success=False,
                    data={},
                    error=f"Failed to create CodeQL database: {stderr}",
                    raw_output=stderr,
                )

            # Step 2: Run analysis
            suite = query_suite or self.QUERY_SUITES.get(language, f"{language}-security-extended")

            analyze_cmd = [
                "codeql",
                "database",
                "analyze",
                str(db_path),
                suite,
                f"--format={output_format}",
                f"--output={results_path}",
                f"--threads={threads}",
            ]

            returncode, stdout, stderr = await self._run_command(analyze_cmd, timeout=1800)
            if returncode != 0:
                return ToolOutput(
                    success=False,
                    data={},
                    error=f"CodeQL analysis failed: {stderr}",
                    raw_output=stderr,
                )

            # Parse results
            if results_path.exists():
                raw_output = results_path.read_text()
                findings = self._parse_sarif(raw_output) if output_format == "sarif" else []

                return ToolOutput(
                    success=True,
                    data={
                        "findings": findings,
                        "total": len(findings),
                        "language": language,
                    },
                    raw_output=raw_output,
                )

            return ToolOutput(
                success=False,
                data={},
                error="No results file generated",
            )

    def _detect_language(self, path: Path) -> str | None:
        """Auto-detect the primary language of a codebase."""
        extensions = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "javascript",
            ".java": "java",
            ".cpp": "cpp",
            ".c": "cpp",
            ".cs": "csharp",
            ".go": "go",
            ".rb": "ruby",
        }

        counts: dict[str, int] = {}
        for file in path.rglob("*"):
            if file.is_file():
                ext = file.suffix.lower()
                if ext in extensions:
                    lang = extensions[ext]
                    counts[lang] = counts.get(lang, 0) + 1

        if counts:
            return max(counts, key=counts.get)
        return None

    def _parse_sarif(self, sarif_content: str) -> list[dict[str, Any]]:
        """Parse SARIF output format."""
        try:
            sarif = json.loads(sarif_content)
            findings = []

            for run in sarif.get("runs", []):
                for result in run.get("results", []):
                    rule_id = result.get("ruleId", "")
                    message = result.get("message", {}).get("text", "")

                    locations = result.get("locations", [])
                    if locations:
                        loc = locations[0].get("physicalLocation", {})
                        artifact = loc.get("artifactLocation", {})
                        region = loc.get("region", {})

                        findings.append(
                            {
                                "rule_id": rule_id,
                                "message": message,
                                "file": artifact.get("uri", ""),
                                "line_start": region.get("startLine", 0),
                                "line_end": region.get("endLine", 0),
                                "severity": result.get("level", "warning"),
                            }
                        )

            return findings
        except json.JSONDecodeError:
            return []


class JoernTool(BaseTool):
    """Wrapper for Joern code property graph analysis.

    Joern is a platform for robust analysis of C/C++ and other code.
    https://github.com/joernio/joern
    """

    name = "joern"
    description = "Code property graph analysis for vulnerability detection"
    required_binary = "joern"

    # Common vulnerability queries
    VULN_QUERIES = {
        "buffer_overflow": """
            cpg.call.name("strcpy|strcat|sprintf|gets").l
        """,
        "format_string": """
            cpg.call.name("printf|sprintf|fprintf").filter(_.argument.order(1).isLiteral.not).l
        """,
        "command_injection": """
            cpg.call.name("system|popen|exec.*").l
        """,
        "null_pointer": """
            cpg.call.where(_.argument.isIdentifier.filter(_.code.contains("NULL"))).l
        """,
        "use_after_free": """
            cpg.method.name("free").caller.l
        """,
    }

    async def run(
        self,
        target: str,
        queries: list[str] | None = None,
        custom_query: str | None = None,
        **kwargs: Any,
    ) -> ToolOutput:
        """Run Joern analysis.

        Args:
            target: Target directory to analyze.
            queries: List of predefined query names to run.
            custom_query: Custom Joern/Scala query.
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with analysis results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="Joern is not installed. Install from: https://github.com/joernio/joern",
            )

        target_path = Path(target)
        if not target_path.exists():
            return ToolOutput(
                success=False,
                data={},
                error=f"Target path does not exist: {target}",
            )

        findings = []
        errors = []

        # Determine which queries to run
        queries_to_run = queries or list(self.VULN_QUERIES.keys())

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create CPG
            cpg_path = Path(temp_dir) / "cpg.bin"

            create_cmd = [
                "joern-parse",
                str(target),
                "--output",
                str(cpg_path),
            ]

            returncode, stdout, stderr = await self._run_command(create_cmd, timeout=600)
            if returncode != 0:
                return ToolOutput(
                    success=False,
                    data={},
                    error=f"Failed to create CPG: {stderr}",
                    raw_output=stderr,
                )

            # Run queries
            for query_name in queries_to_run:
                if query_name in self.VULN_QUERIES:
                    query = self.VULN_QUERIES[query_name]
                else:
                    continue

                query_results = await self._run_query(cpg_path, query, query_name)
                if query_results:
                    findings.extend(query_results)

            # Run custom query if provided
            if custom_query:
                custom_results = await self._run_query(cpg_path, custom_query, "custom")
                if custom_results:
                    findings.extend(custom_results)

        return ToolOutput(
            success=True,
            data={
                "findings": findings,
                "total": len(findings),
                "queries_run": queries_to_run,
            },
        )

    async def _run_query(
        self,
        cpg_path: Path,
        query: str,
        query_name: str,
    ) -> list[dict[str, Any]]:
        """Run a single Joern query."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sc", delete=False) as f:
            # Write script to load CPG and run query
            script = f"""
            importCpg("{cpg_path}")
            val results = {query}
            results.foreach(println)
            """
            f.write(script)
            script_path = f.name

        try:
            cmd = ["joern", "--script", script_path]
            returncode, stdout, stderr = await self._run_command(cmd, timeout=300)

            if returncode == 0 and stdout.strip():
                # Parse results (simplified - actual parsing depends on query output)
                findings = []
                for line in stdout.strip().split("\n"):
                    if line and not line.startswith("joern>"):
                        findings.append(
                            {
                                "query": query_name,
                                "finding": line.strip(),
                            }
                        )
                return findings
        finally:
            os.unlink(script_path)

        return []


class TreeSitterTool(BaseTool):
    """Wrapper for Tree-sitter parsing and analysis.

    Tree-sitter is a parser generator tool and incremental parsing library.
    https://tree-sitter.github.io/tree-sitter/
    """

    name = "tree-sitter"
    description = "Fast incremental parser for code analysis"
    required_binary = None  # Uses Python bindings

    # Language file extensions
    LANG_EXTENSIONS = {
        "python": [".py"],
        "javascript": [".js", ".jsx", ".mjs"],
        "typescript": [".ts", ".tsx"],
        "java": [".java"],
        "c": [".c", ".h"],
        "cpp": [".cpp", ".cc", ".cxx", ".hpp"],
        "go": [".go"],
        "rust": [".rs"],
        "ruby": [".rb"],
        "php": [".php"],
    }

    def __init__(self) -> None:
        """Initialize Tree-sitter tool."""
        super().__init__()
        self._parsers: dict[str, Any] = {}

    def is_available(self) -> bool:
        """Check if tree-sitter is available."""
        try:
            import tree_sitter

            return True
        except ImportError:
            return False

    async def run(
        self,
        target: str,
        language: str | None = None,
        query: str | None = None,
        extract: str = "functions",
        **kwargs: Any,
    ) -> ToolOutput:
        """Run Tree-sitter analysis.

        Args:
            target: Target file or directory.
            language: Programming language.
            query: Custom tree-sitter query.
            extract: What to extract (functions, classes, imports, etc.).
            **kwargs: Additional arguments.

        Returns:
            ToolOutput with parsed results.
        """
        if not self.is_available():
            return ToolOutput(
                success=False,
                data={},
                error="tree-sitter Python bindings not installed. Install with: pip install tree-sitter",
            )

        target_path = Path(target)
        if not target_path.exists():
            return ToolOutput(
                success=False,
                data={},
                error=f"Target path does not exist: {target}",
            )

        results: dict[str, Any] = {
            "files_parsed": 0,
            "functions": [],
            "classes": [],
            "imports": [],
            "calls": [],
        }

        # Process single file or directory
        if target_path.is_file():
            file_results = await self._parse_file(target_path, language)
            if file_results:
                self._merge_results(results, file_results)
        else:
            for lang, extensions in self.LANG_EXTENSIONS.items():
                for ext in extensions:
                    for file_path in target_path.rglob(f"*{ext}"):
                        file_results = await self._parse_file(file_path, lang)
                        if file_results:
                            self._merge_results(results, file_results)

        return ToolOutput(
            success=True,
            data=results,
        )

    async def _parse_file(
        self,
        file_path: Path,
        language: str | None = None,
    ) -> dict[str, Any] | None:
        """Parse a single file."""
        try:
            import tree_sitter_python as tspython
            from tree_sitter import Language, Parser
        except ImportError:
            return None

        # Detect language from extension
        if language is None:
            ext = file_path.suffix.lower()
            for lang, extensions in self.LANG_EXTENSIONS.items():
                if ext in extensions:
                    language = lang
                    break

        if language is None or language != "python":
            # For now, only Python is fully supported
            return None

        # Get or create parser
        if language not in self._parsers:
            parser = Parser(Language(tspython.language()))
            self._parsers[language] = parser
        else:
            parser = self._parsers[language]

        # Parse file
        try:
            content = file_path.read_bytes()
            tree = parser.parse(content)
        except Exception:
            return None

        # Extract information
        results = {
            "file": str(file_path),
            "functions": [],
            "classes": [],
            "imports": [],
            "calls": [],
        }

        self._extract_python_info(tree.root_node, content, results)
        return results

    def _extract_python_info(
        self,
        node: Any,
        content: bytes,
        results: dict[str, Any],
    ) -> None:
        """Extract information from Python AST."""
        if node.type == "function_definition":
            name_node = node.child_by_field_name("name")
            if name_node:
                results["functions"].append(
                    {
                        "name": content[name_node.start_byte : name_node.end_byte].decode(),
                        "line": node.start_point[0] + 1,
                        "file": results["file"],
                    }
                )

        elif node.type == "class_definition":
            name_node = node.child_by_field_name("name")
            if name_node:
                results["classes"].append(
                    {
                        "name": content[name_node.start_byte : name_node.end_byte].decode(),
                        "line": node.start_point[0] + 1,
                        "file": results["file"],
                    }
                )

        elif node.type == "import_statement" or node.type == "import_from_statement":
            results["imports"].append(
                {
                    "statement": content[node.start_byte : node.end_byte].decode(),
                    "line": node.start_point[0] + 1,
                    "file": results["file"],
                }
            )

        elif node.type == "call":
            func_node = node.child_by_field_name("function")
            if func_node:
                results["calls"].append(
                    {
                        "function": content[func_node.start_byte : func_node.end_byte].decode(),
                        "line": node.start_point[0] + 1,
                        "file": results["file"],
                    }
                )

        # Recurse into children
        for child in node.children:
            self._extract_python_info(child, content, results)

    def _merge_results(
        self,
        target: dict[str, Any],
        source: dict[str, Any],
    ) -> None:
        """Merge file results into overall results."""
        target["files_parsed"] += 1
        target["functions"].extend(source.get("functions", []))
        target["classes"].extend(source.get("classes", []))
        target["imports"].extend(source.get("imports", []))
        target["calls"].extend(source.get("calls", []))
