"""SQLAlchemy models and async database session management (SQLite or PostgreSQL)."""

from __future__ import annotations

import datetime
import os
import pathlib
from enum import Enum

from sqlalchemy import JSON, DateTime, Integer, String, Text, func
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

DATA_DIR = pathlib.Path.home() / ".parascan"
DB_PATH = DATA_DIR / "parascan.db"

# database URL override from CLI (priority: CLI > env > default)
_database_url_override: str | None = None


class Base(DeclarativeBase):
    pass


class ScanStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    INTERRUPTED = "interrupted"
    FAILED = "failed"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_url: Mapped[str] = mapped_column(String(2048))
    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.RUNNING.value)
    started_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, server_default=func.now()
    )
    finished_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    config_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(Text, nullable=True)
    total_endpoints: Mapped[int] = mapped_column(Integer, default=0)
    scanned_endpoints: Mapped[int] = mapped_column(Integer, default=0)
    retest_of: Mapped[int | None] = mapped_column(Integer, nullable=True)


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, index=True)
    url: Mapped[str] = mapped_column(String(2048))
    method: Mapped[str] = mapped_column(String(10), default="GET")
    params: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    scanned: Mapped[int] = mapped_column(Integer, default=0)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, index=True)
    endpoint_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    module: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(10))
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    soc2_criteria: Mapped[str | None] = mapped_column(String(50), nullable=True)
    retest_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    found_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, server_default=func.now()
    )


class ScanRequest(Base):
    """HTTP request/response log for audit trail."""
    __tablename__ = "scan_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, index=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(DateTime, server_default=func.now())
    method: Mapped[str] = mapped_column(String(10))
    url: Mapped[str] = mapped_column(String(2048))
    request_headers: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_headers: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    module: Mapped[str | None] = mapped_column(String(50), nullable=True)
    finding_id: Mapped[int | None] = mapped_column(Integer, nullable=True)


_engine = None
_session_factory = None

# columns added after initial release — migrated at startup
_MIGRATION_COLUMNS = {
    "findings": [
        ("remediation", "TEXT"),
        ("soc2_criteria", "VARCHAR(50)"),
        ("retest_status", "VARCHAR(20)"),
    ],
    "scans": [
        ("retest_of", "INTEGER"),
    ],
}


def set_database_url(url: str | None) -> None:
    """set database URL override from CLI (must be called before get_engine)."""
    global _database_url_override, _engine, _session_factory
    _database_url_override = url
    # reset engine and session factory so next get_engine() call uses new URL
    _engine = None
    _session_factory = None


def _get_database_url() -> str:
    """get database URL with priority: CLI param > env var > local SQLite."""
    # 1. CLI parameter (highest priority)
    if _database_url_override:
        return _normalize_postgres_url(_database_url_override)
    
    # 2. environment variable
    env_url = os.getenv("DATABASE_URL")
    if env_url:
        return _normalize_postgres_url(env_url)
    
    # 3. default: local SQLite
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return f"sqlite+aiosqlite:///{DB_PATH}"


def _normalize_postgres_url(url: str) -> str:
    """normalize PostgreSQL URL to use asyncpg driver."""
    if "postgresql" not in url and "postgres" not in url:
        return url  # not a postgres URL, return as-is
    
    # some providers use postgres://, SQLAlchemy prefers postgresql://
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    
    # ensure asyncpg driver for async support
    if url.startswith("postgresql://") and "+asyncpg" not in url:
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    
    return url


def _run_migrations(conn) -> None:
    """add any missing columns to existing tables (synchronous — used with run_sync)."""
    import sqlalchemy

    for table, columns in _MIGRATION_COLUMNS.items():
        for col_name, col_type in columns:
            try:
                conn.execute(
                    sqlalchemy.text(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}")
                )
            except Exception:
                pass  # column already exists


async def get_engine():
    global _engine
    if _engine is None:
        db_url = _get_database_url()
        is_postgres = "postgresql" in db_url
        
        # configure engine based on database type
        engine_kwargs = {"echo": False}
        if is_postgres:
            engine_kwargs["pool_size"] = 10
            engine_kwargs["max_overflow"] = 20
        
        _engine = create_async_engine(db_url, **engine_kwargs)
        async with _engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            # only run migrations on SQLite (PostgreSQL uses proper migrations)
            if not is_postgres:
                await conn.run_sync(_run_migrations)
    return _engine


async def get_session() -> AsyncSession:
    global _session_factory
    engine = await get_engine()
    if _session_factory is None:
        _session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return _session_factory()
