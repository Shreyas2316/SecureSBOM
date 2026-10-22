import os
import json
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./output/securesbom.db")

# Ensure output directory exists for database file
os.makedirs("output", exist_ok=True)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScanRecord(Base):
    """Database model for storing scan metadata, results, and artifacts."""
    __tablename__ = "scans"

    id = Column(String(64), primary_key=True, index=True)
    manifest_name = Column(String(255), default="requirements.txt")
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    status = Column(String(32), default="completed") # 'completed', 'failed', 'partial'
    total_scanned = Column(Integer, default=0)
    direct_deps_count = Column(Integer, default=0)
    transitive_deps_count = Column(Integer, default=0)
    raw_advisories_count = Column(Integer, default=0)
    canonical_vulns_count = Column(Integer, default=0)
    vulnerable_components_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    unknown_count = Column(Integer, default=0)
    cyclonedx_valid = Column(Boolean, default=True)
    user_id = Column(String(64), default="default_user", index=True)
    
    # Serialized JSON blobs
    report_json = Column(Text, nullable=False)
    bom_json = Column(Text, nullable=False)


# Initialize schema automatically
Base.metadata.create_all(bind=engine)


def save_scan_record(
    scan_id: str,
    manifest_name: str,
    report_data: Dict[str, Any],
    bom_data: Dict[str, Any],
    user_id: str = "default_user"
) -> ScanRecord:
    """Persists a completed scan record and its artifacts to the database."""
    session = SessionLocal()
    try:
        summary = report_data.get("summary", {})
        sev_counts = summary.get("vulnerabilities_by_severity", {})

        record = ScanRecord(
            id=scan_id,
            manifest_name=manifest_name,
            status="completed",
            total_scanned=summary.get("total_scanned", 0),
            direct_deps_count=summary.get("total_direct_deps", 0),
            transitive_deps_count=summary.get("total_transitive_deps", 0),
            raw_advisories_count=summary.get("total_raw_advisories", summary.get("total_vulnerabilities", 0)),
            canonical_vulns_count=summary.get("total_canonical_vulnerabilities", 0),
            vulnerable_components_count=summary.get("vulnerable_components_count", 0),
            critical_count=sev_counts.get("CRITICAL", 0),
            high_count=sev_counts.get("HIGH", 0),
            medium_count=sev_counts.get("MEDIUM", 0),
            low_count=sev_counts.get("LOW", 0),
            info_count=sev_counts.get("INFORMATIONAL", 0),
            unknown_count=sev_counts.get("UNKNOWN", 0),
            cyclonedx_valid=report_data.get("cyclonedx_valid", True),
            user_id=user_id,
            report_json=json.dumps(report_data),
            bom_json=json.dumps(bom_data)
        )
        session.merge(record)
        session.commit()
        return record
    finally:
        session.close()


def get_scan_records(user_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves scan history list sorted by recency."""
    session = SessionLocal()
    try:
        query = session.query(ScanRecord)
        if user_id:
            query = query.filter(ScanRecord.user_id == user_id)
        records = query.order_by(ScanRecord.timestamp.desc()).limit(limit).all()

        return [
            {
                "id": r.id,
                "manifest_name": r.manifest_name,
                "timestamp": r.timestamp.isoformat() if r.timestamp else "",
                "status": r.status,
                "total_scanned": r.total_scanned,
                "direct_deps_count": r.direct_deps_count,
                "transitive_deps_count": r.transitive_deps_count,
                "raw_advisories_count": r.raw_advisories_count,
                "canonical_vulns_count": r.canonical_vulns_count,
                "vulnerable_components_count": r.vulnerable_components_count,
                "severity_counts": {
                    "CRITICAL": r.critical_count,
                    "HIGH": r.high_count,
                    "MEDIUM": r.medium_count,
                    "LOW": r.low_count,
                    "INFORMATIONAL": r.info_count,
                    "UNKNOWN": r.unknown_count
                },
                "cyclonedx_valid": r.cyclonedx_valid
            }
            for r in records
        ]
    finally:
        session.close()


def get_scan_by_id(scan_id: str, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieves full scan report by ID with user authorization check."""
    session = SessionLocal()
    try:
        query = session.query(ScanRecord).filter(ScanRecord.id == scan_id)
        if user_id:
            query = query.filter(ScanRecord.user_id == user_id)
        record = query.first()
        if not record:
            return None
        return json.loads(record.report_json)
    finally:
        session.close()


def get_scan_bom_by_id(scan_id: str, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieves CycloneDX SBOM JSON document by scan ID."""
    session = SessionLocal()
    try:
        query = session.query(ScanRecord).filter(ScanRecord.id == scan_id)
        if user_id:
            query = query.filter(ScanRecord.user_id == user_id)
        record = query.first()
        if not record:
            return None
        return json.loads(record.bom_json)
    finally:
        session.close()
