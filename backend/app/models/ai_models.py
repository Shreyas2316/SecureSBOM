"""
AI Assessment Database Models
Separate from verified OSV/NVD vulnerability findings (Category A).
These represent Category B: AI-Assessed Emerging Vulnerabilities.
"""
import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime,
    ForeignKey, Text, JSON, Enum as SAEnum
)
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.models import Project, Scan, Component, Vulnerability, ScanVulnerability
import enum


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


class AIAssessmentStatus(str, enum.Enum):
    NEW = "new_ai_assessment"
    NEEDS_VERIFICATION = "needs_verification"
    UNDER_INVESTIGATION = "under_investigation"
    CORROBORATED = "corroborated_by_authoritative_advisory"
    REJECTED = "rejected_after_review"
    RESOLVED = "resolved"


class AIAssessmentType(str, enum.Enum):
    EMERGING_ADVISORY = "emerging_advisory_analysis"
    POTENTIAL_WEAKNESS = "potential_weakness_analysis"


class AIFinding(Base):
    """
    AI-generated vulnerability assessment record.
    MUST remain separate from verified OSV/NVD findings (Vulnerability table).
    Never automatically merged into confirmed vulnerability counts.
    """
    __tablename__ = "ai_findings"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(String(100), unique=True, index=True, nullable=False)

    # Package identification
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    package_name = Column(String(255), nullable=False, index=True)
    package_version = Column(String(100), nullable=False)
    ecosystem = Column(String(100), default="PyPI")

    # Assessment content
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    assessment_type = Column(String(100), nullable=False, default=AIAssessmentType.EMERGING_ADVISORY.value)

    # Evidence
    evidence_json = Column(JSON, nullable=True)         # List of evidence items
    evidence_sources_json = Column(JSON, nullable=True)  # Source URLs/descriptions

    # Impact and confidence
    potential_impact = Column(Text, nullable=True)
    confidence = Column(String(50), nullable=True)       # Low/Medium/High/Insufficient
    confidence_explanation = Column(Text, nullable=True)

    # Remediation
    verification_steps_json = Column(JSON, nullable=True)
    suggested_mitigations_json = Column(JSON, nullable=True)

    # Advisory linkage (NOT auto-merged with Vulnerability table)
    related_advisory_ids_json = Column(JSON, nullable=True)
    linked_verified_vuln_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=True)

    # Model metadata
    model_name = Column(String(200), nullable=True)
    analysis_method = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=utc_now, index=True)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    # Status (NOT confirmed vulnerability)
    status = Column(String(100), default=AIAssessmentStatus.NEW.value, index=True)

    # Limitations disclaimer (always present)
    limitations = Column(Text, nullable=False, default=(
        "AI-generated assessment. This finding is not a confirmed vulnerability unless "
        "independently verified. The AI model may produce inaccurate or incomplete results. "
        "Review the supporting evidence before taking any action."
    ))

    # Relationships
    scan = relationship("Scan", foreign_keys=[scan_id])
    linked_verified_vuln = relationship("Vulnerability", foreign_keys=[linked_verified_vuln_id])
    review_history = relationship("AIFindingReview", back_populates="finding", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<AIFinding {self.finding_id} [{self.status}] {self.package_name}@{self.package_version}>"


class AIFindingReview(Base):
    """
    Audit trail for human review actions on AI findings.
    Preserves history even after rejection or resolution.
    """
    __tablename__ = "ai_finding_reviews"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    finding_id_ref = Column(Integer, ForeignKey("ai_findings.id"), nullable=False)
    reviewer_id = Column(String(255), nullable=True)    # User identity where available
    action = Column(String(100), nullable=False)         # Status transition
    previous_status = Column(String(100), nullable=True)
    new_status = Column(String(100), nullable=False)
    notes = Column(Text, nullable=True)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)

    finding = relationship("AIFinding", back_populates="review_history")


class DependencyAlternative(Base):
    """
    Safe dependency upgrade or replacement recommendations.
    These are NOT automatically applied — require user review.
    Separate from AI findings; may reference verified vulnerabilities.
    """
    __tablename__ = "dependency_alternatives"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    vulnerability_canonical_id = Column(String(100), nullable=True, index=True)

    # Affected package
    package_name = Column(String(255), nullable=False, index=True)
    package_version = Column(String(100), nullable=False)
    ecosystem = Column(String(100), default="PyPI")

    # Recommendation type
    recommendation_type = Column(String(100), nullable=False)  # upgrade / replacement / no_alternative
    label = Column(String(200), nullable=True)  # human-readable label

    # Fixed/alternative package details
    recommended_version = Column(String(100), nullable=True)
    alternative_package = Column(String(255), nullable=True)
    alternative_version = Column(String(100), nullable=True)

    # Compatibility and safety assessment
    compatibility_info = Column(Text, nullable=True)
    known_vulns_in_alternative = Column(Text, nullable=True)
    migration_complexity = Column(String(50), nullable=True)  # low/medium/high
    breaking_change_risk = Column(String(50), nullable=True)  # none/low/high/unknown
    license_info = Column(String(200), nullable=True)
    maintenance_evidence = Column(Text, nullable=True)

    # Rationale and evidence
    rationale = Column(Text, nullable=True)
    evidence_links_json = Column(JSON, nullable=True)
    verification_status = Column(String(100), nullable=True)  # verified/candidate/insufficient_evidence

    # Source
    source = Column(String(100), nullable=True)  # pypi_metadata / ai_suggested / authoritative_advisory
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    scan = relationship("Scan", foreign_keys=[scan_id])


class MonitoringSource(Base):
    """
    Advisory feed monitoring configuration and sync state.
    Tracks last checked time, errors, and processed advisory IDs.
    """
    __tablename__ = "monitoring_sources"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    url = Column(String(500), nullable=False)
    source_type = Column(String(50), nullable=False, default="osv")  # osv / nvd / github
    is_enabled = Column(Boolean, default=True)

    last_checked_at = Column(DateTime, nullable=True)
    last_successful_sync_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    advisories_processed = Column(Integer, default=0)
    affected_dependencies_found = Column(Integer, default=0)

    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    alerts = relationship("MonitoringAlert", back_populates="source", cascade="all, delete-orphan")


class ProcessedAdvisory(Base):
    """
    Tracks advisory IDs already processed to avoid re-processing.
    """
    __tablename__ = "processed_advisories"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    source_id = Column(Integer, ForeignKey("monitoring_sources.id"), nullable=False)
    advisory_id = Column(String(200), nullable=False, index=True)
    processed_at = Column(DateTime, default=utc_now)
    affected_packages_json = Column(JSON, nullable=True)

    source = relationship("MonitoringSource")


class MonitoringAlert(Base):
    """
    Alert generated when a new advisory matches a saved SBOM component.
    """
    __tablename__ = "monitoring_alerts"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    source_id = Column(Integer, ForeignKey("monitoring_sources.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    advisory_id = Column(String(200), nullable=False)
    package_name = Column(String(255), nullable=False)
    package_version = Column(String(100), nullable=False)
    severity = Column(String(50), nullable=True)
    summary = Column(Text, nullable=True)
    is_acknowledged = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utc_now)

    source = relationship("MonitoringSource", back_populates="alerts")
    scan = relationship("Scan", foreign_keys=[scan_id])


class GeneratedReport(Base):
    """
    Metadata for generated vulnerability reports (PDF/JSON/CSV).
    Actual report bytes stored as files in output dir.
    """
    __tablename__ = "generated_reports"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(String(100), unique=True, index=True, nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    ai_finding_id = Column(Integer, ForeignKey("ai_findings.id"), nullable=True)

    report_type = Column(String(50), nullable=False)  # full_scan / individual_vuln / ai_finding
    format = Column(String(20), nullable=False)        # pdf / json / csv

    file_path = Column(String(1000), nullable=True)
    file_size_bytes = Column(Integer, nullable=True)

    generated_by = Column(String(255), nullable=True)
    generated_at = Column(DateTime, default=utc_now)

    scan = relationship("Scan", foreign_keys=[scan_id])
    ai_finding = relationship("AIFinding", foreign_keys=[ai_finding_id])
