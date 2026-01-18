"""SQLite database manager for MrZero."""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from mrzero.core.schemas import (
    ExecutionMode,
    ScanSession,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
    VulnerabilityType,
)

Base = declarative_base()


class SessionModel(Base):
    """SQLAlchemy model for scan sessions."""

    __tablename__ = "sessions"

    id = Column(String(64), primary_key=True)
    target_path = Column(String(1024), nullable=False)
    mode = Column(String(16), nullable=False)
    started_at = Column(DateTime, default=datetime.now)
    completed_at = Column(DateTime, nullable=True)
    current_agent = Column(String(64), nullable=True)
    status = Column(String(32), default="pending")
    state_json = Column(Text, nullable=True)  # Serialized LangGraph state


class FindingModel(Base):
    """SQLAlchemy model for vulnerability findings."""

    __tablename__ = "findings"

    id = Column(String(64), primary_key=True)
    session_id = Column(String(64), nullable=False, index=True)
    vuln_type = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False)
    score = Column(Integer, nullable=False)
    status = Column(String(32), default="candidate")
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    file_path = Column(String(1024), nullable=False)
    line_number = Column(Integer, nullable=False)
    code_snippet = Column(Text, nullable=True)
    cwe_id = Column(String(32), nullable=True)
    cvss = Column(Float, nullable=True)
    tool_source = Column(String(64), nullable=False)
    confidence = Column(Float, default=0.5)
    remediation = Column(Text, nullable=True)
    discovered_at = Column(DateTime, default=datetime.now)
    verified_at = Column(DateTime, nullable=True)
    data_flow_json = Column(Text, nullable=True)


class ToolCacheModel(Base):
    """SQLAlchemy model for tool output caching."""

    __tablename__ = "tool_cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cache_key = Column(String(128), unique=True, nullable=False, index=True)
    tool_name = Column(String(64), nullable=False)
    args_hash = Column(String(128), nullable=False)
    target_hash = Column(String(128), nullable=False)
    output_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.now)
    expires_at = Column(DateTime, nullable=True)
    hit_count = Column(Integer, default=0)


class CheckpointModel(Base):
    """SQLAlchemy model for LangGraph checkpoints."""

    __tablename__ = "checkpoints"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), nullable=False, index=True)
    checkpoint_id = Column(String(128), nullable=False)
    node_name = Column(String(64), nullable=False)
    state_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.now)


class SQLiteManager:
    """Manager for SQLite database operations."""

    def __init__(self, db_path: Path | str) -> None:
        """Initialize the SQLite manager.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.engine = create_engine(f"sqlite:///{self.db_path}", echo=False)
        Base.metadata.create_all(self.engine)

        self.SessionLocal = sessionmaker(bind=self.engine)

    def get_session(self) -> Session:
        """Get a new database session.

        Returns:
            SQLAlchemy session.
        """
        return self.SessionLocal()

    # Tool Cache Methods
    @staticmethod
    def _compute_cache_key(tool_name: str, args: dict[str, Any], target_file: str) -> str:
        """Compute a unique cache key for a tool execution.

        Args:
            tool_name: Name of the tool.
            args: Arguments passed to the tool.
            target_file: Path to the target file.

        Returns:
            SHA256 hash as cache key.
        """
        key_data = f"{tool_name}:{json.dumps(args, sort_keys=True)}:{target_file}"
        return hashlib.sha256(key_data.encode()).hexdigest()

    def get_cached_result(
        self, tool_name: str, args: dict[str, Any], target_file: str
    ) -> dict[str, Any] | None:
        """Get a cached tool result if available.

        Args:
            tool_name: Name of the tool.
            args: Arguments passed to the tool.
            target_file: Path to the target file.

        Returns:
            Cached output dict or None if not found.
        """
        cache_key = self._compute_cache_key(tool_name, args, target_file)

        with self.get_session() as session:
            cached = (
                session.query(ToolCacheModel).filter(ToolCacheModel.cache_key == cache_key).first()
            )

            if cached:
                # Check expiration
                if cached.expires_at and cached.expires_at < datetime.now():
                    session.delete(cached)
                    session.commit()
                    return None

                # Update hit count
                cached.hit_count += 1
                session.commit()

                return json.loads(cached.output_json)

        return None

    def cache_result(
        self,
        tool_name: str,
        args: dict[str, Any],
        target_file: str,
        output: dict[str, Any],
        ttl_hours: int | None = None,
    ) -> None:
        """Cache a tool result.

        Args:
            tool_name: Name of the tool.
            args: Arguments passed to the tool.
            target_file: Path to the target file.
            output: Tool output to cache.
            ttl_hours: Optional time-to-live in hours.
        """
        cache_key = self._compute_cache_key(tool_name, args, target_file)
        args_hash = hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest()
        target_hash = hashlib.sha256(target_file.encode()).hexdigest()

        expires_at = None
        if ttl_hours:
            from datetime import timedelta

            expires_at = datetime.now() + timedelta(hours=ttl_hours)

        with self.get_session() as session:
            # Upsert
            existing = (
                session.query(ToolCacheModel).filter(ToolCacheModel.cache_key == cache_key).first()
            )

            if existing:
                existing.output_json = json.dumps(output)
                existing.created_at = datetime.now()
                existing.expires_at = expires_at
            else:
                cache_entry = ToolCacheModel(
                    cache_key=cache_key,
                    tool_name=tool_name,
                    args_hash=args_hash,
                    target_hash=target_hash,
                    output_json=json.dumps(output),
                    expires_at=expires_at,
                )
                session.add(cache_entry)

            session.commit()


class SessionManager:
    """Manager for scan sessions."""

    def __init__(self, db_path: Path | str) -> None:
        """Initialize the session manager.

        Args:
            db_path: Path to the SQLite database.
        """
        self.db = SQLiteManager(db_path)

    def create_session(self, session_id: str, target_path: str, mode: ExecutionMode) -> ScanSession:
        """Create a new scan session.

        Args:
            session_id: Unique session identifier.
            target_path: Path to target codebase.
            mode: Execution mode.

        Returns:
            Created ScanSession.
        """
        with self.db.get_session() as session:
            db_session = SessionModel(
                id=session_id,
                target_path=target_path,
                mode=mode.value,
                status="pending",
            )
            session.add(db_session)
            session.commit()

        return ScanSession(
            id=session_id,
            target_path=target_path,
            mode=mode,
        )

    def get_session(self, session_id: str) -> ScanSession | None:
        """Get a session by ID.

        Args:
            session_id: Session identifier.

        Returns:
            ScanSession or None if not found.
        """
        with self.db.get_session() as session:
            db_session = session.query(SessionModel).filter(SessionModel.id == session_id).first()

            if not db_session:
                return None

            return ScanSession(
                id=db_session.id,
                target_path=db_session.target_path,
                mode=ExecutionMode(db_session.mode),
                started_at=db_session.started_at,
                completed_at=db_session.completed_at,
                current_agent=db_session.current_agent,
                status=db_session.status,
            )

    def update_session(
        self,
        session_id: str,
        current_agent: str | None = None,
        status: str | None = None,
        state_json: str | None = None,
    ) -> bool:
        """Update a session.

        Args:
            session_id: Session identifier.
            current_agent: Current agent name.
            status: Session status.
            state_json: Serialized state.

        Returns:
            True if updated, False if not found.
        """
        with self.db.get_session() as session:
            db_session = session.query(SessionModel).filter(SessionModel.id == session_id).first()

            if not db_session:
                return False

            if current_agent is not None:
                db_session.current_agent = current_agent
            if status is not None:
                db_session.status = status
                if status == "completed":
                    db_session.completed_at = datetime.now()
            if state_json is not None:
                db_session.state_json = state_json

            session.commit()
            return True

    def list_sessions(self, limit: int = 50) -> list[ScanSession]:
        """List recent sessions.

        Args:
            limit: Maximum number of sessions to return.

        Returns:
            List of ScanSession objects.
        """
        with self.db.get_session() as session:
            db_sessions = (
                session.query(SessionModel)
                .order_by(SessionModel.started_at.desc())
                .limit(limit)
                .all()
            )

            return [
                ScanSession(
                    id=s.id,
                    target_path=s.target_path,
                    mode=ExecutionMode(s.mode),
                    started_at=s.started_at,
                    completed_at=s.completed_at,
                    current_agent=s.current_agent,
                    status=s.status,
                )
                for s in db_sessions
            ]

    def delete_session(self, session_id: str) -> bool:
        """Delete a session.

        Args:
            session_id: Session identifier.

        Returns:
            True if deleted, False if not found.
        """
        with self.db.get_session() as session:
            deleted = session.query(SessionModel).filter(SessionModel.id == session_id).delete()
            session.commit()
            return deleted > 0


class FindingManager:
    """Manager for vulnerability findings."""

    def __init__(self, db_path: Path | str) -> None:
        """Initialize the finding manager.

        Args:
            db_path: Path to the SQLite database.
        """
        self.db = SQLiteManager(db_path)

    def save_finding(self, session_id: str, vuln: Vulnerability) -> None:
        """Save a vulnerability finding.

        Args:
            session_id: Session identifier.
            vuln: Vulnerability to save.
        """
        with self.db.get_session() as session:
            finding = FindingModel(
                id=vuln.id,
                session_id=session_id,
                vuln_type=vuln.vuln_type.value,
                severity=vuln.severity.value,
                score=vuln.score,
                status=vuln.status.value,
                title=vuln.title,
                description=vuln.description,
                file_path=vuln.file_path,
                line_number=vuln.line_number,
                code_snippet=vuln.code_snippet,
                cwe_id=vuln.cwe_id,
                cvss=vuln.cvss,
                tool_source=vuln.tool_source,
                confidence=vuln.confidence,
                remediation=vuln.remediation,
                discovered_at=vuln.discovered_at,
                verified_at=vuln.verified_at,
                data_flow_json=vuln.data_flow.model_dump_json() if vuln.data_flow else None,
            )
            session.merge(finding)
            session.commit()

    def get_findings(
        self,
        session_id: str,
        status: VulnerabilityStatus | None = None,
        severity: VulnerabilitySeverity | None = None,
    ) -> list[Vulnerability]:
        """Get findings for a session.

        Args:
            session_id: Session identifier.
            status: Optional status filter.
            severity: Optional severity filter.

        Returns:
            List of Vulnerability objects.
        """
        with self.db.get_session() as session:
            query = session.query(FindingModel).filter(FindingModel.session_id == session_id)

            if status:
                query = query.filter(FindingModel.status == status.value)
            if severity:
                query = query.filter(FindingModel.severity == severity.value)

            findings = query.order_by(FindingModel.score.desc()).all()

            return [
                Vulnerability(
                    id=f.id,
                    vuln_type=VulnerabilityType(f.vuln_type),
                    severity=VulnerabilitySeverity(f.severity),
                    score=f.score,
                    status=VulnerabilityStatus(f.status),
                    title=f.title,
                    description=f.description,
                    file_path=f.file_path,
                    line_number=f.line_number,
                    code_snippet=f.code_snippet,
                    cwe_id=f.cwe_id,
                    cvss=f.cvss,
                    tool_source=f.tool_source,
                    confidence=f.confidence,
                    remediation=f.remediation,
                    discovered_at=f.discovered_at,
                    verified_at=f.verified_at,
                )
                for f in findings
            ]

    def update_finding_status(self, finding_id: str, status: VulnerabilityStatus) -> bool:
        """Update a finding's status.

        Args:
            finding_id: Finding identifier.
            status: New status.

        Returns:
            True if updated, False if not found.
        """
        with self.db.get_session() as session:
            finding = session.query(FindingModel).filter(FindingModel.id == finding_id).first()

            if not finding:
                return False

            finding.status = status.value
            if status == VulnerabilityStatus.CONFIRMED:
                finding.verified_at = datetime.now()

            session.commit()
            return True
