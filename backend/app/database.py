import logging
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import settings

logger = logging.getLogger("securesbom.database")

db_url = settings.DATABASE_URL
connect_args = {}

if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(db_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _migrate_sqlite_missing_columns():
    """Safely add new columns to existing SQLite tables for backward-compatible upgrades."""
    if not db_url.startswith("sqlite"):
        return
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    alter_statements = {
        "projects": [
            ("owner_id", "INTEGER"),
        ],
        "scans": [
            ("owner_id", "INTEGER"),
            ("manifest_format", "VARCHAR(50) DEFAULT 'requirements.txt'"),
            ("resolution_completeness", "VARCHAR(50) DEFAULT 'complete'"),
            ("coverage_status", "VARCHAR(50) DEFAULT 'complete'"),
        ],
        "components": [
            ("declared_specifier", "VARCHAR(255)"),
            ("resolved_version", "VARCHAR(100)"),
            ("installed_version", "VARCHAR(100)"),
            ("resolution_status", "VARCHAR(50) DEFAULT 'resolved'"),
        ],
        "vulnerabilities": [
            ("is_kev", "BOOLEAN DEFAULT 0"),
            ("kev_date_added", "VARCHAR(50)"),
            ("epss_score", "FLOAT"),
            ("epss_percentile", "FLOAT"),
        ],
        "ai_findings": [
            ("owner_id", "INTEGER"),
            ("finding_category", "VARCHAR(20) DEFAULT 'B'"),
        ],
    }

    with engine.begin() as conn:
        for table, cols in alter_statements.items():
            if table not in existing_tables:
                continue
            existing_cols = {c["name"] for c in inspector.get_columns(table)}
            for col_name, col_type in cols:
                if col_name not in existing_cols:
                    try:
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}"))
                    except Exception as exc:
                        logger.debug("Column migration skipped for %s.%s: %s", table, col_name, exc)


def init_db():
    # Ensure all models are imported before create_all
    import app.models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    _migrate_sqlite_missing_columns()
