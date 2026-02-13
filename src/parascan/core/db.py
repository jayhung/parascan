"""SQLAlchemy models and async SQLite session management."""

from __future__ import annotations

import datetime
import pathlib
from enum import Enum

from sqlalchemy import JSON, DateTime, Integer, String, Text, func
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

DATA_DIR = pathlib.Path.home() / ".parascan"
DB_PATH = DATA_DIR / "parascan.db"


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
    found_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, server_default=func.now()
    )


_engine = None
_session_factory = None


async def get_engine():
    global _engine
    if _engine is None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        _engine = create_async_engine(f"sqlite+aiosqlite:///{DB_PATH}", echo=False)
        async with _engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    return _engine


async def get_session() -> AsyncSession:
    global _session_factory
    engine = await get_engine()
    if _session_factory is None:
        _session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return _session_factory()
