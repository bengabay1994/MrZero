"""Vector database manager for semantic code search (RAG)."""

import hashlib
from pathlib import Path
from typing import Any

try:
    import chromadb
    from chromadb.config import Settings

    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False


class CodeChunk:
    """Represents a chunk of code for embedding."""

    def __init__(
        self,
        content: str,
        file_path: str,
        start_line: int,
        end_line: int,
        language: str = "unknown",
        chunk_type: str = "code",  # code, function, class, comment
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Initialize a code chunk.

        Args:
            content: The code content.
            file_path: Path to the source file.
            start_line: Starting line number.
            end_line: Ending line number.
            language: Programming language.
            chunk_type: Type of code chunk.
            metadata: Additional metadata.
        """
        self.content = content
        self.file_path = file_path
        self.start_line = start_line
        self.end_line = end_line
        self.language = language
        self.chunk_type = chunk_type
        self.metadata = metadata or {}

    @property
    def id(self) -> str:
        """Generate unique ID for this chunk."""
        data = f"{self.file_path}:{self.start_line}:{self.end_line}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "content": self.content,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "language": self.language,
            "chunk_type": self.chunk_type,
            **self.metadata,
        }


class VectorDBManager:
    """Manager for vector database operations using ChromaDB."""

    def __init__(self, db_path: Path | str, collection_name: str = "codebase") -> None:
        """Initialize the vector database manager.

        Args:
            db_path: Path to the vector database directory.
            collection_name: Name of the collection to use.
        """
        if not CHROMADB_AVAILABLE:
            raise ImportError("ChromaDB is not installed. Install it with: pip install chromadb")

        self.db_path = Path(db_path)
        self.db_path.mkdir(parents=True, exist_ok=True)

        # Initialize ChromaDB with persistent storage
        self.client = chromadb.PersistentClient(
            path=str(self.db_path),
            settings=Settings(anonymized_telemetry=False),
        )

        self.collection_name = collection_name
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )

    def add_chunks(self, chunks: list[CodeChunk]) -> int:
        """Add code chunks to the vector database.

        Args:
            chunks: List of CodeChunk objects.

        Returns:
            Number of chunks added.
        """
        if not chunks:
            return 0

        ids = [chunk.id for chunk in chunks]
        documents = [chunk.content for chunk in chunks]
        metadatas = [
            {
                "file_path": chunk.file_path,
                "start_line": chunk.start_line,
                "end_line": chunk.end_line,
                "language": chunk.language,
                "chunk_type": chunk.chunk_type,
            }
            for chunk in chunks
        ]

        self.collection.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
        )

        return len(chunks)

    def search(
        self,
        query: str,
        n_results: int = 10,
        filter_language: str | None = None,
        filter_chunk_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Search for relevant code chunks.

        Args:
            query: Semantic search query (e.g., "input sanitization functions").
            n_results: Maximum number of results.
            filter_language: Optional language filter.
            filter_chunk_type: Optional chunk type filter.

        Returns:
            List of matching chunks with metadata and relevance scores.
        """
        where_filter = {}
        if filter_language:
            where_filter["language"] = filter_language
        if filter_chunk_type:
            where_filter["chunk_type"] = filter_chunk_type

        results = self.collection.query(
            query_texts=[query],
            n_results=n_results,
            where=where_filter if where_filter else None,
            include=["documents", "metadatas", "distances"],
        )

        if not results["ids"][0]:
            return []

        return [
            {
                "id": results["ids"][0][i],
                "content": results["documents"][0][i],
                "metadata": results["metadatas"][0][i],
                "distance": results["distances"][0][i] if results["distances"] else None,
                "relevance": 1 - (results["distances"][0][i] if results["distances"] else 0),
            }
            for i in range(len(results["ids"][0]))
        ]

    def search_by_pattern(
        self,
        patterns: list[str],
        n_results: int = 20,
    ) -> list[dict[str, Any]]:
        """Search for code matching multiple semantic patterns.

        Args:
            patterns: List of semantic patterns to search for.
            n_results: Results per pattern.

        Returns:
            Combined and deduplicated results.
        """
        all_results = {}

        for pattern in patterns:
            results = self.search(pattern, n_results=n_results)
            for r in results:
                chunk_id = r["id"]
                if chunk_id not in all_results:
                    all_results[chunk_id] = r
                    all_results[chunk_id]["matched_patterns"] = [pattern]
                else:
                    all_results[chunk_id]["matched_patterns"].append(pattern)
                    # Boost relevance for multiple pattern matches
                    all_results[chunk_id]["relevance"] = min(
                        1.0, all_results[chunk_id]["relevance"] * 1.2
                    )

        # Sort by relevance
        sorted_results = sorted(
            all_results.values(),
            key=lambda x: x["relevance"],
            reverse=True,
        )

        return sorted_results

    def get_chunk_by_file(
        self, file_path: str, start_line: int | None = None
    ) -> list[dict[str, Any]]:
        """Get chunks from a specific file.

        Args:
            file_path: Path to the file.
            start_line: Optional starting line filter.

        Returns:
            List of chunks from the file.
        """
        where_filter: dict[str, Any] = {"file_path": file_path}
        if start_line is not None:
            where_filter["start_line"] = {"$gte": start_line}

        results = self.collection.get(
            where=where_filter,
            include=["documents", "metadatas"],
        )

        if not results["ids"]:
            return []

        return [
            {
                "id": results["ids"][i],
                "content": results["documents"][i],
                "metadata": results["metadatas"][i],
            }
            for i in range(len(results["ids"]))
        ]

    def delete_file_chunks(self, file_path: str) -> int:
        """Delete all chunks from a specific file.

        Args:
            file_path: Path to the file.

        Returns:
            Number of chunks deleted.
        """
        # Get IDs of chunks from this file
        results = self.collection.get(
            where={"file_path": file_path},
            include=[],
        )

        if not results["ids"]:
            return 0

        self.collection.delete(ids=results["ids"])
        return len(results["ids"])

    def clear_collection(self) -> None:
        """Clear all data from the collection."""
        self.client.delete_collection(self.collection_name)
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"},
        )

    def get_stats(self) -> dict[str, Any]:
        """Get statistics about the vector database.

        Returns:
            Dictionary with collection statistics.
        """
        return {
            "collection_name": self.collection_name,
            "total_chunks": self.collection.count(),
            "db_path": str(self.db_path),
        }


class CodeChunker:
    """Utility to chunk code files for embedding."""

    def __init__(
        self,
        chunk_size: int = 1000,
        chunk_overlap: int = 200,
    ) -> None:
        """Initialize the code chunker.

        Args:
            chunk_size: Target chunk size in characters.
            chunk_overlap: Overlap between chunks.
        """
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def chunk_file(self, file_path: Path, language: str = "unknown") -> list[CodeChunk]:
        """Chunk a code file into embedable pieces.

        Args:
            file_path: Path to the file.
            language: Programming language.

        Returns:
            List of CodeChunk objects.
        """
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        lines = content.split("\n")
        chunks = []
        current_chunk_lines: list[str] = []
        current_chunk_start = 1
        current_size = 0

        for i, line in enumerate(lines, start=1):
            line_size = len(line) + 1  # +1 for newline

            if current_size + line_size > self.chunk_size and current_chunk_lines:
                # Create chunk
                chunk_content = "\n".join(current_chunk_lines)
                chunks.append(
                    CodeChunk(
                        content=chunk_content,
                        file_path=str(file_path),
                        start_line=current_chunk_start,
                        end_line=i - 1,
                        language=language,
                        chunk_type="code",
                    )
                )

                # Calculate overlap
                overlap_lines = []
                overlap_size = 0
                for ol in reversed(current_chunk_lines):
                    if overlap_size + len(ol) > self.chunk_overlap:
                        break
                    overlap_lines.insert(0, ol)
                    overlap_size += len(ol) + 1

                current_chunk_lines = overlap_lines
                current_chunk_start = i - len(overlap_lines)
                current_size = overlap_size

            current_chunk_lines.append(line)
            current_size += line_size

        # Add final chunk
        if current_chunk_lines:
            chunk_content = "\n".join(current_chunk_lines)
            chunks.append(
                CodeChunk(
                    content=chunk_content,
                    file_path=str(file_path),
                    start_line=current_chunk_start,
                    end_line=len(lines),
                    language=language,
                    chunk_type="code",
                )
            )

        return chunks

    def chunk_directory(
        self,
        directory: Path,
        extensions: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
    ) -> list[CodeChunk]:
        """Chunk all code files in a directory.

        Args:
            directory: Directory to process.
            extensions: File extensions to include (e.g., [".py", ".js"]).
            exclude_patterns: Patterns to exclude (e.g., ["node_modules", ".git"]).

        Returns:
            List of CodeChunk objects from all files.
        """
        exclude_patterns = exclude_patterns or [
            "node_modules",
            ".git",
            "__pycache__",
            ".venv",
            "venv",
            "build",
            "dist",
        ]

        # Extension to language mapping
        ext_to_lang = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".java": "java",
            ".c": "c",
            ".cpp": "cpp",
            ".h": "c",
            ".hpp": "cpp",
            ".go": "go",
            ".rs": "rust",
            ".rb": "ruby",
            ".php": "php",
            ".sol": "solidity",
            ".vy": "vyper",
        }

        if extensions is None:
            extensions = list(ext_to_lang.keys())

        all_chunks = []

        for file_path in directory.rglob("*"):
            # Skip excluded patterns
            if any(p in str(file_path) for p in exclude_patterns):
                continue

            # Check extension
            if file_path.suffix not in extensions:
                continue

            if not file_path.is_file():
                continue

            language = ext_to_lang.get(file_path.suffix, "unknown")
            chunks = self.chunk_file(file_path, language)
            all_chunks.extend(chunks)

        return all_chunks
