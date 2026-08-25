"""Database session management for M7 and audit_log."""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings

# In-memory SQLite for demo/fixture mode, PostgreSQL for production
engine = None
SessionLocal = None


def init_db():
    """Initialize database engine and session factory."""
    global engine, SessionLocal

    config = settings()
    if config.fixture_mode:
        # In-memory SQLite for tests/demo
        db_url = "sqlite:///:memory:"
    else:
        # PostgreSQL for production
        db_url = config.database_url or "postgresql://localhost/mailtrace"

    engine = create_engine(
        db_url,
        echo=False,
        pool_pre_ping=True,
    )
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

    # Create tables
    from app.db.models import Base
    Base.metadata.create_all(engine)


def get_session() -> Session:
    """Get a new database session."""
    if SessionLocal is None:
        init_db()
    return SessionLocal()
