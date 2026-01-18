"""Code indexing service for VectorDB integration with agents."""

import hashlib
from pathlib import Path
from typing import Any

from mrzero.core.config import get_config
from mrzero.core.memory.vectordb import CodeChunk, CodeChunker, VectorDBManager


class CodeIndexer:
    """Service for indexing codebases into VectorDB for semantic search."""

    def __init__(self, session_id: str) -> None:
        """Initialize the code indexer.

        Args:
            session_id: Session ID for the collection name.
        """
        self.session_id = session_id
        self.config = get_config()
        self._db: VectorDBManager | None = None
        self._chunker = CodeChunker(chunk_size=1500, chunk_overlap=200)

    @property
    def db(self) -> VectorDBManager:
        """Get or create the VectorDB manager."""
        if self._db is None:
            collection_name = f"mrzero_{self.session_id[:8]}"
            self._db = VectorDBManager(
                self.config.vector_db_path,
                collection_name=collection_name,
            )
        return self._db

    def index_codebase(
        self,
        target_path: Path,
        extensions: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
    ) -> dict[str, Any]:
        """Index a codebase into the vector database.

        Args:
            target_path: Path to the codebase.
            extensions: File extensions to include.
            exclude_patterns: Patterns to exclude.

        Returns:
            Statistics about the indexing.
        """
        exclude_patterns = exclude_patterns or [
            "node_modules",
            ".git",
            "__pycache__",
            ".venv",
            "venv",
            "build",
            "dist",
            ".egg-info",
            ".tox",
            ".pytest_cache",
            ".mypy_cache",
        ]

        # Chunk the codebase
        chunks = self._chunker.chunk_directory(
            target_path,
            extensions=extensions,
            exclude_patterns=exclude_patterns,
        )

        if not chunks:
            return {
                "files_indexed": 0,
                "chunks_created": 0,
                "status": "no_files_found",
            }

        # Add chunks to VectorDB
        num_added = self.db.add_chunks(chunks)

        # Get unique files
        unique_files = set(chunk.file_path for chunk in chunks)

        return {
            "files_indexed": len(unique_files),
            "chunks_created": num_added,
            "status": "success",
        }

    def search_semantic(
        self,
        query: str,
        n_results: int = 10,
        language: str | None = None,
    ) -> list[dict[str, Any]]:
        """Perform semantic search on the indexed codebase.

        Args:
            query: Natural language query (e.g., "authentication logic").
            n_results: Maximum results to return.
            language: Filter by programming language.

        Returns:
            List of relevant code chunks with metadata.
        """
        return self.db.search(
            query=query,
            n_results=n_results,
            filter_language=language,
        )

    def search_vulnerability_patterns(
        self,
        vuln_type: str,
        n_results: int = 20,
    ) -> list[dict[str, Any]]:
        """Search for code patterns related to a vulnerability type.

        Args:
            vuln_type: Type of vulnerability to search for.
            n_results: Maximum results.

        Returns:
            Relevant code chunks.
        """
        # Define semantic queries for different vulnerability types
        vuln_queries = {
            "sql_injection": [
                "database query execution with user input",
                "SQL query string concatenation",
                "raw SQL query execution",
                "cursor execute with format string",
            ],
            "command_injection": [
                "system command execution with user input",
                "shell command with variables",
                "subprocess with shell=True",
                "os.system call",
            ],
            "xss": [
                "HTML rendering with user input",
                "innerHTML assignment",
                "document.write with variables",
                "template rendering without escaping",
            ],
            "path_traversal": [
                "file path construction with user input",
                "directory traversal",
                "file open with concatenated path",
                "reading files based on user input",
            ],
            "ssrf": [
                "HTTP request with user-controlled URL",
                "URL fetch with user input",
                "external API call with dynamic URL",
            ],
            "deserialization": [
                "pickle load",
                "yaml load with untrusted data",
                "object deserialization",
                "unserialize user input",
            ],
            "authentication": [
                "login authentication logic",
                "password verification",
                "session management",
                "access control check",
            ],
            "authorization": [
                "permission check",
                "role-based access control",
                "authorization middleware",
                "admin privilege check",
            ],
            "crypto": [
                "encryption implementation",
                "password hashing",
                "cryptographic key handling",
                "random number generation for security",
            ],
            "secrets": [
                "API key configuration",
                "password storage",
                "secret key handling",
                "credential management",
            ],
        }

        queries = vuln_queries.get(vuln_type, [f"{vuln_type} vulnerability pattern"])
        return self.db.search_by_pattern(queries, n_results=n_results)

    def search_entry_points(self, n_results: int = 30) -> list[dict[str, Any]]:
        """Search for application entry points.

        Args:
            n_results: Maximum results.

        Returns:
            Code chunks containing entry points.
        """
        entry_point_queries = [
            "API endpoint route handler",
            "HTTP request handler",
            "REST API endpoint definition",
            "web socket message handler",
            "command line argument parsing",
            "main function entry point",
            "request parameter extraction",
            "form data processing",
        ]
        return self.db.search_by_pattern(entry_point_queries, n_results=n_results)

    def search_data_sinks(self, n_results: int = 30) -> list[dict[str, Any]]:
        """Search for dangerous data sinks.

        Args:
            n_results: Maximum results.

        Returns:
            Code chunks containing data sinks.
        """
        sink_queries = [
            "database query execution",
            "system command execution",
            "file write operation",
            "HTML output rendering",
            "eval or exec function call",
            "external HTTP request",
            "email sending function",
            "logging user data",
        ]
        return self.db.search_by_pattern(sink_queries, n_results=n_results)

    def get_file_context(
        self,
        file_path: str,
        line_number: int,
        context_lines: int = 30,
    ) -> str | None:
        """Get code context around a specific line.

        Args:
            file_path: Path to the file.
            line_number: Target line number.
            context_lines: Number of lines of context.

        Returns:
            Code context as string, or None if not found.
        """
        chunks = self.db.get_chunk_by_file(file_path)

        if not chunks:
            return None

        # Find the chunk containing the line
        for chunk in chunks:
            meta = chunk.get("metadata", {})
            start = meta.get("start_line", 0)
            end = meta.get("end_line", 0)

            if start <= line_number <= end:
                return chunk.get("content", "")

        return None

    def clear_index(self) -> None:
        """Clear the current index."""
        if self._db is not None:
            self._db.clear_collection()


# Global indexer instance per session
_indexers: dict[str, CodeIndexer] = {}


def get_indexer(session_id: str) -> CodeIndexer:
    """Get or create a CodeIndexer for a session.

    Args:
        session_id: Session identifier.

    Returns:
        CodeIndexer instance.
    """
    if session_id not in _indexers:
        _indexers[session_id] = CodeIndexer(session_id)
    return _indexers[session_id]


def clear_indexer(session_id: str) -> None:
    """Clear and remove an indexer.

    Args:
        session_id: Session identifier.
    """
    if session_id in _indexers:
        _indexers[session_id].clear_index()
        del _indexers[session_id]
