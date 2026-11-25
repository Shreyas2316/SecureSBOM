"""
Local Security Intelligence Dataset & Vulnerability Lifecycle Models.
Supports Category A (confirmed), Category B (emerging intelligence), and Category C (potential weaknesses).
"""
import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text, JSON
)
from sqlalchemy.orm import relationship
from app.database import Base


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


class IntelligenceSource(Base):
    __tablename__ = "intelligence_sources"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    source_key = Column(String(100), unique=True, index=True, nullable=False)
    name = Column(String(200), nullable=False)
    source_type = Column(String(50), nullable=False)  # ghsa, pypa, cve_v5, security_lab, oss_security, maintainer, research_feed, rss
    url = Column(String(500), nullable=False)
    reliability_tier = Column(String(50), default="high")  # authoritative, high, medium, community
    sync_interval_minutes = Column(Integer, default=60)
    is_enabled = Column(Boolean, default=True)

    etag = Column(String(255), nullable=True)
    last_modified = Column(String(255), nullable=True)
    last_checkpoint = Column(String(255), nullable=True)
    last_checked_at = Column(DateTime, nullable=True)
    last_successful_sync_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    documents_indexed = Column(Integer, default=0)

    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    documents = relationship("IntelligenceDocument", back_populates="source", cascade="all, delete-orphan")
    sync_runs = relationship("IntelligenceSyncRun", back_populates="source", cascade="all, delete-orphan")


class IntelligenceDocument(Base):
    __tablename__ = "intelligence_documents"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    doc_uid = Column(String(128), unique=True, index=True, nullable=False)
    source_id = Column(Integer, ForeignKey("intelligence_sources.id"), nullable=False, index=True)
    external_id = Column(String(200), nullable=True, index=True)
    url = Column(String(1000), nullable=False)
    title = Column(String(500), nullable=False)
    summary = Column(Text, nullable=True)
    excerpt = Column(Text, nullable=True)

    published_at = Column(DateTime, nullable=True, index=True)
    updated_at = Column(DateTime, nullable=True)
    retrieved_at = Column(DateTime, default=utc_now, index=True)

    package_names_json = Column(JSON, nullable=True)
    ecosystem = Column(String(50), default="PyPI")
    aliases_json = Column(JSON, nullable=True)
    affected_ranges_json = Column(JSON, nullable=True)
    fixed_versions_json = Column(JSON, nullable=True)
    content_hash = Column(String(64), index=True, nullable=False)
    evidence_refs_json = Column(JSON, nullable=True)
    source_reliability = Column(String(50), default="high")

    review_status = Column(String(50), default="active")  # active, corrected, withdrawn
    is_withdrawn = Column(Boolean, default=False)
    withdrawal_reason = Column(Text, nullable=True)

    source = relationship("IntelligenceSource", back_populates="documents")
    evidence_items = relationship("AdvisoryEvidence", back_populates="document", cascade="all, delete-orphan")


class IntelligenceSyncRun(Base):
    __tablename__ = "intelligence_sync_runs"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    source_id = Column(Integer, ForeignKey("intelligence_sources.id"), nullable=False, index=True)
    started_at = Column(DateTime, default=utc_now)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String(30), default="running")  # running, success, partial, failed
    items_fetched = Column(Integer, default=0)
    items_new = Column(Integer, default=0)
    items_updated = Column(Integer, default=0)
    items_withdrawn = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    checkpoint_used = Column(String(255), nullable=True)

    source = relationship("IntelligenceSource", back_populates="sync_runs")


class AdvisoryEvidence(Base):
    __tablename__ = "advisory_evidence"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("intelligence_documents.id"), nullable=False, index=True)
    evidence_type = Column(String(50), default="advisory")
    url = Column(String(1000), nullable=False)
    excerpt = Column(Text, nullable=True)
    content_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=utc_now)

    document = relationship("IntelligenceDocument", back_populates="evidence_items")


class PackageIntelligenceMatch(Base):
    __tablename__ = "package_intelligence_matches"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("intelligence_documents.id"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    package_name = Column(String(255), nullable=False, index=True)
    package_version = Column(String(100), nullable=False)
    ecosystem = Column(String(50), default="PyPI")
    version_applicable = Column(String(50), default="unverified")  # applicable, not_applicable, unverified
    match_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)


class EmergingFinding(Base):
    """Category B: Emerging Vulnerability Intelligence."""
    __tablename__ = "emerging_findings"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(String(100), unique=True, index=True, nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)

    package_name = Column(String(255), nullable=False, index=True)
    package_version = Column(String(100), nullable=False)
    ecosystem = Column(String(50), default="PyPI")

    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    potential_impact = Column(Text, nullable=True)
    affected_version_status = Column(String(50), default="unverified")  # verified_affected, potentially_applicable, unverified, not_affected

    evidence_doc_ids_json = Column(JSON, nullable=True)
    source_urls_json = Column(JSON, nullable=True)
    evidence_excerpts_json = Column(JSON, nullable=True)
    published_at = Column(DateTime, nullable=True)
    retrieved_at = Column(DateTime, default=utc_now)

    ai_provider = Column(String(100), nullable=True)
    model_name = Column(String(200), nullable=True)
    confidence = Column(String(50), default="insufficient_evidence")
    confidence_explanation = Column(Text, nullable=True)
    reasoning_summary = Column(Text, nullable=True)
    limitations = Column(Text, nullable=False)
    suggested_remediation = Column(Text, nullable=True)

    status = Column(String(50), default="new", index=True)  # new, under_review, emerging, confirmed, rejected, withdrawn, remediated
    promoted_to_vuln_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=True)

    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class PotentialWeakness(Base):
    """Category C: Potential Security Weaknesses (hypotheses, static analysis, metadata anomalies)."""
    __tablename__ = "potential_weaknesses"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    weakness_id = Column(String(100), unique=True, index=True, nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)

    package_name = Column(String(255), nullable=False, index=True)
    package_version = Column(String(100), nullable=False)
    ecosystem = Column(String(50), default="PyPI")

    title = Column(String(500), nullable=False)
    weakness_class = Column(String(150), nullable=True)
    description = Column(Text, nullable=True)
    evidence_excerpts_json = Column(JSON, nullable=True)
    source_urls_json = Column(JSON, nullable=True)

    ai_provider = Column(String(100), nullable=True)
    model_name = Column(String(200), nullable=True)
    confidence = Column(String(50), default="low")
    confidence_explanation = Column(Text, nullable=True)
    limitations = Column(Text, nullable=False)
    suggested_remediation = Column(Text, nullable=True)

    status = Column(String(50), default="potential", index=True)  # new, under_review, potential, rejected, remediated
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class FindingReview(Base):
    __tablename__ = "finding_reviews"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    finding_type = Column(String(30), nullable=False)  # emerging, potential
    finding_ref_id = Column(String(100), nullable=False, index=True)
    reviewer_id = Column(String(255), nullable=False)
    action = Column(String(50), nullable=False)
    previous_status = Column(String(50), nullable=True)
    new_status = Column(String(50), nullable=False)
    notes = Column(Text, nullable=True)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)


class FindingStatusHistory(Base):
    __tablename__ = "finding_status_history"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    finding_type = Column(String(30), nullable=False)
    finding_ref_id = Column(String(100), nullable=False, index=True)
    from_status = Column(String(50), nullable=True)
    to_status = Column(String(50), nullable=False)
    changed_by = Column(String(255), nullable=False)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)


class StaticAnalysisResult(Base):
    __tablename__ = "static_analysis_results"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    filename = Column(String(255), nullable=False)
    tool = Column(String(50), nullable=False)
    rule_id = Column(String(100), nullable=False)
    severity = Column(String(30), nullable=False)
    confidence = Column(String(30), nullable=False)
    line_number = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utc_now)
