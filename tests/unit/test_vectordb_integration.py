"""Tests for VectorDB integration with agents."""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mrzero.core.memory.vectordb import CodeChunk, CodeChunker, VectorDBManager


class TestCodeChunker:
    """Tests for CodeChunker."""

    def test_chunk_file_basic(self, temp_dir):
        """Test basic file chunking."""
        # Create a test file
        test_file = temp_dir / "test.py"
        test_file.write_text(
            "def hello():\n    print('hello')\n\ndef world():\n    print('world')\n"
        )

        chunker = CodeChunker(chunk_size=50, chunk_overlap=10)
        chunks = chunker.chunk_file(test_file, language="python")

        assert len(chunks) > 0
        assert all(isinstance(c, CodeChunk) for c in chunks)
        assert all(c.language == "python" for c in chunks)

    def test_chunk_file_preserves_content(self, temp_dir):
        """Test that chunking preserves file content."""
        content = "line1\nline2\nline3\nline4\nline5"
        test_file = temp_dir / "test.py"
        test_file.write_text(content)

        chunker = CodeChunker(chunk_size=1000, chunk_overlap=0)
        chunks = chunker.chunk_file(test_file)

        # Single chunk should contain all content
        assert len(chunks) == 1
        assert chunks[0].content == content

    def test_chunk_directory(self, temp_dir):
        """Test directory chunking."""
        # Create test files
        (temp_dir / "app.py").write_text("def main(): pass")
        (temp_dir / "utils.js").write_text("function util() {}")
        (temp_dir / "readme.txt").write_text("Documentation")  # Should be skipped

        chunker = CodeChunker()
        chunks = chunker.chunk_directory(temp_dir, extensions=[".py", ".js"], exclude_patterns=[])

        # Should have chunks from both .py and .js files
        file_paths = {c.file_path for c in chunks}
        assert any("app.py" in p for p in file_paths)
        assert any("utils.js" in p for p in file_paths)
        assert not any("readme.txt" in p for p in file_paths)

    def test_chunk_directory_excludes_patterns(self, temp_dir):
        """Test that exclude patterns work."""
        (temp_dir / "app.py").write_text("def main(): pass")
        node_modules = temp_dir / "node_modules"
        node_modules.mkdir()
        (node_modules / "package.js").write_text("module.exports = {}")

        chunker = CodeChunker()
        chunks = chunker.chunk_directory(
            temp_dir, extensions=[".py", ".js"], exclude_patterns=["node_modules"]
        )

        file_paths = {c.file_path for c in chunks}
        assert any("app.py" in p for p in file_paths)
        assert not any("node_modules" in p for p in file_paths)


class TestVectorDBManager:
    """Tests for VectorDBManager."""

    @pytest.fixture
    def vector_db(self, temp_dir):
        """Create a VectorDB instance for testing."""
        try:
            return VectorDBManager(temp_dir / "vectordb", collection_name="test")
        except ImportError:
            pytest.skip("ChromaDB not installed")

    def test_add_and_search_chunks(self, vector_db):
        """Test adding and searching chunks."""
        chunks = [
            CodeChunk(
                content="def authenticate_user(username, password):\n    # Check credentials",
                file_path="auth.py",
                start_line=1,
                end_line=5,
                language="python",
                chunk_type="function",
            ),
            CodeChunk(
                content="def execute_query(sql):\n    cursor.execute(sql)",
                file_path="db.py",
                start_line=10,
                end_line=15,
                language="python",
                chunk_type="function",
            ),
        ]

        # Add chunks
        added = vector_db.add_chunks(chunks)
        assert added == 2

        # Search for authentication-related code
        results = vector_db.search("authentication login credentials", n_results=5)
        assert len(results) > 0
        assert any("auth.py" in r.get("metadata", {}).get("file_path", "") for r in results)

    def test_search_with_language_filter(self, vector_db):
        """Test searching with language filter."""
        chunks = [
            CodeChunk(
                content="def python_func(): pass",
                file_path="app.py",
                start_line=1,
                end_line=1,
                language="python",
            ),
            CodeChunk(
                content="function jsFunc() {}",
                file_path="app.js",
                start_line=1,
                end_line=1,
                language="javascript",
            ),
        ]

        vector_db.add_chunks(chunks)

        # Search only Python
        results = vector_db.search("function", filter_language="python")
        assert all(r.get("metadata", {}).get("language") == "python" for r in results)

    def test_search_by_pattern(self, vector_db):
        """Test multi-pattern search."""
        chunks = [
            CodeChunk(
                content="sql = f'SELECT * FROM users WHERE id = {user_id}'",
                file_path="db.py",
                start_line=1,
                end_line=1,
                language="python",
            ),
            CodeChunk(
                content="os.system(f'rm -rf {path}')",
                file_path="utils.py",
                start_line=1,
                end_line=1,
                language="python",
            ),
        ]

        vector_db.add_chunks(chunks)

        # Search with multiple patterns
        results = vector_db.search_by_pattern(
            ["SQL query injection", "command execution shell"], n_results=5
        )

        assert len(results) > 0
        # Results should include matched patterns info
        assert any("matched_patterns" in r for r in results)

    def test_get_stats(self, vector_db):
        """Test getting database stats."""
        chunks = [
            CodeChunk(
                content="test content",
                file_path="test.py",
                start_line=1,
                end_line=1,
            )
        ]
        vector_db.add_chunks(chunks)

        stats = vector_db.get_stats()
        assert stats["collection_name"] == "test"
        assert stats["total_chunks"] == 1

    def test_clear_collection(self, vector_db):
        """Test clearing collection."""
        chunks = [
            CodeChunk(
                content="test",
                file_path="test.py",
                start_line=1,
                end_line=1,
            )
        ]
        vector_db.add_chunks(chunks)

        vector_db.clear_collection()

        stats = vector_db.get_stats()
        assert stats["total_chunks"] == 0


class TestCodeIndexer:
    """Tests for CodeIndexer service."""

    @pytest.fixture
    def mock_config(self, temp_dir, monkeypatch):
        """Create mock config."""
        from mrzero.core.config import MrZeroConfig, set_config

        config = MrZeroConfig(
            data_dir=temp_dir / ".mrzero",
            output_dir=temp_dir / "output",
        )
        config.ensure_directories()
        set_config(config)
        return config

    def test_indexer_creation(self, mock_config):
        """Test indexer can be created."""
        try:
            from mrzero.core.indexing import CodeIndexer

            indexer = CodeIndexer("test-session-123")
            assert indexer.session_id == "test-session-123"
        except ImportError:
            pytest.skip("ChromaDB not available")

    def test_index_codebase(self, mock_config, temp_dir):
        """Test indexing a codebase."""
        try:
            from mrzero.core.indexing import CodeIndexer

            # Create test codebase
            (temp_dir / "app.py").write_text(
                "def login(user, password):\n    return authenticate(user, password)\n"
            )
            (temp_dir / "db.py").write_text("def query(sql):\n    cursor.execute(sql)\n")

            indexer = CodeIndexer("test-session")
            stats = indexer.index_codebase(temp_dir)

            assert stats["status"] == "success"
            assert stats["files_indexed"] >= 2
            assert stats["chunks_created"] >= 2
        except ImportError:
            pytest.skip("ChromaDB not available")

    def test_search_vulnerability_patterns(self, mock_config, temp_dir):
        """Test searching for vulnerability patterns."""
        try:
            from mrzero.core.indexing import CodeIndexer

            # Create test codebase with SQL injection pattern
            (temp_dir / "vulnerable.py").write_text(
                "def get_user(user_id):\n"
                "    sql = f'SELECT * FROM users WHERE id = {user_id}'\n"
                "    cursor.execute(sql)\n"
            )

            indexer = CodeIndexer("test-session")
            indexer.index_codebase(temp_dir)

            results = indexer.search_vulnerability_patterns("sql_injection")

            assert len(results) > 0
        except ImportError:
            pytest.skip("ChromaDB not available")


class TestHunterVectorDBIntegration:
    """Tests for Hunter agent's VectorDB integration."""

    def test_format_semantic_results_empty(self):
        """Test formatting empty semantic results."""
        from mrzero.agents.hunter.agent import HunterAgent

        agent = HunterAgent()
        result = agent._format_semantic_results({})

        assert "No semantic search" in result

    def test_format_semantic_results_with_data(self):
        """Test formatting semantic results with data."""
        from mrzero.agents.hunter.agent import HunterAgent

        agent = HunterAgent()

        semantic_results = {
            "sql_injection": [
                {
                    "content": "sql = f'SELECT * FROM users WHERE id = {user_id}'",
                    "metadata": {
                        "file_path": "db.py",
                        "start_line": 10,
                        "end_line": 12,
                    },
                    "relevance": 0.85,
                    "matched_patterns": ["SQL query", "user input"],
                }
            ],
            "entry_points": [
                {
                    "content": "@app.route('/login')\ndef login():",
                    "metadata": {
                        "file_path": "routes.py",
                        "start_line": 5,
                        "end_line": 10,
                    },
                    "relevance": 0.92,
                }
            ],
        }

        result = agent._format_semantic_results(semantic_results)

        assert "Sql Injection" in result
        assert "Entry Points" in result
        assert "db.py:10-12" in result
        assert "0.85" in result

    def test_extract_priority_files(self):
        """Test extracting priority files from semantic results."""
        from mrzero.agents.hunter.agent import HunterAgent

        agent = HunterAgent()

        semantic_results = {
            "sql_injection": [
                {"metadata": {"file_path": "/path/to/db.py"}},
                {"metadata": {"file_path": "/path/to/api.py"}},
            ],
            "xss": [
                {"metadata": {"file_path": "/path/to/template.py"}},
            ],
        }

        priority_files = agent._extract_priority_files(semantic_results)

        assert "/path/to/db.py" in priority_files
        assert "/path/to/api.py" in priority_files
        assert "/path/to/template.py" in priority_files


class TestVerifierVectorDBIntegration:
    """Tests for Verifier agent's VectorDB integration."""

    @pytest.mark.asyncio
    async def test_get_semantic_context_no_session(self):
        """Test semantic context retrieval without session."""
        from mrzero.agents.verifier.agent import VerifierAgent
        from mrzero.core.schemas import (
            Vulnerability,
            VulnerabilityType,
            VulnerabilitySeverity,
            VulnerabilityStatus,
        )

        agent = VerifierAgent()

        vuln = Vulnerability(
            id="test-1",
            vuln_type=VulnerabilityType.SQL_INJECTION,
            severity=VulnerabilitySeverity.HIGH,
            score=85,
            status=VulnerabilityStatus.CANDIDATE,
            title="Test SQL Injection",
            description="SQL injection vulnerability in db.py",
            file_path="db.py",
            line_number=10,
            tool_source="test",
            confidence=0.8,
        )

        # Without session_id, should return empty string
        result = await agent._get_semantic_context(None, vuln)
        assert result == ""

    @pytest.mark.asyncio
    async def test_get_semantic_context_with_mock_indexer(self):
        """Test semantic context retrieval with mocked indexer."""
        from mrzero.agents.verifier.agent import VerifierAgent
        from mrzero.core.schemas import (
            Vulnerability,
            VulnerabilityType,
            VulnerabilitySeverity,
            VulnerabilityStatus,
        )

        agent = VerifierAgent()

        vuln = Vulnerability(
            id="test-1",
            vuln_type=VulnerabilityType.SQL_INJECTION,
            severity=VulnerabilitySeverity.HIGH,
            score=85,
            status=VulnerabilityStatus.CANDIDATE,
            title="Test SQL Injection",
            description="SQL injection vulnerability in db.py",
            file_path="db.py",
            line_number=10,
            tool_source="test",
            confidence=0.8,
        )

        # Mock the indexer
        with patch("mrzero.core.indexing.get_indexer") as mock_get_indexer:
            mock_indexer = MagicMock()
            mock_indexer.db.search_by_pattern.return_value = [
                {
                    "content": "def sanitize_sql(input): return escape(input)",
                    "metadata": {"file_path": "utils.py", "start_line": 5},
                    "relevance": 0.8,
                }
            ]
            mock_get_indexer.return_value = mock_indexer

            result = await agent._get_semantic_context("test-session", vuln)

            assert "utils.py" in result
            assert "sanitize_sql" in result


class TestCodeChunkModel:
    """Tests for CodeChunk data model."""

    def test_chunk_id_generation(self):
        """Test that chunk IDs are generated consistently."""
        chunk1 = CodeChunk(
            content="test",
            file_path="test.py",
            start_line=1,
            end_line=5,
        )
        chunk2 = CodeChunk(
            content="test",
            file_path="test.py",
            start_line=1,
            end_line=5,
        )

        # Same location should produce same ID
        assert chunk1.id == chunk2.id

    def test_chunk_id_uniqueness(self):
        """Test that different locations produce different IDs."""
        chunk1 = CodeChunk(
            content="test",
            file_path="test.py",
            start_line=1,
            end_line=5,
        )
        chunk2 = CodeChunk(
            content="test",
            file_path="test.py",
            start_line=10,
            end_line=15,
        )

        assert chunk1.id != chunk2.id

    def test_chunk_to_dict(self):
        """Test chunk serialization."""
        chunk = CodeChunk(
            content="def test(): pass",
            file_path="test.py",
            start_line=1,
            end_line=1,
            language="python",
            chunk_type="function",
            metadata={"custom": "value"},
        )

        data = chunk.to_dict()

        assert data["content"] == "def test(): pass"
        assert data["file_path"] == "test.py"
        assert data["language"] == "python"
        assert data["custom"] == "value"
