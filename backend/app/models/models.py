import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from app.database import Base

def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)

class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=utc_now)

    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    timestamp = Column(DateTime, default=utc_now)
    total_deps = Column(Integer, default=0)
    direct_deps = Column(Integer, default=0)
    transitive_deps = Column(Integer, default=0)
    
    unique_vuln_count = Column(Integer, default=0)
    advisory_record_count = Column(Integer, default=0)
    affected_components_count = Column(Integer, default=0)
    vuln_count = Column(Integer, default=0)  # Maintained for legacy backward compatibility

    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    unknown_count = Column(Integer, default=0)

    scan_duration_seconds = Column(Float, default=0.0)

    project = relationship("Project", back_populates="scans")
    components = relationship("Component", back_populates="scan", cascade="all, delete-orphan")
    scan_vulnerabilities = relationship("ScanVulnerability", back_populates="scan", cascade="all, delete-orphan")

class Component(Base):
    __tablename__ = "components"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    name = Column(String(255), nullable=False)
    version = Column(String(100), nullable=False)
    ecosystem = Column(String(100), default="PyPI")
    is_direct = Column(Boolean, default=True)
    purl = Column(String(500), nullable=True)
    dependency_depth = Column(Integer, default=0)

    scan = relationship("Scan", back_populates="components")
    scan_vulnerabilities = relationship("ScanVulnerability", back_populates="component", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    canonical_id = Column(String(100), unique=True, index=True, nullable=False)
    osv_id = Column(String(100), nullable=True)
    cve_id = Column(String(100), nullable=True)
    aliases_json = Column(JSON, nullable=True)
    sources_json = Column(JSON, nullable=True)
    summary = Column(Text, nullable=True)
    details = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(255), nullable=True)
    severity = Column(String(50), default="UNKNOWN")
    severity_sources_json = Column(JSON, nullable=True)
    priority_tier = Column(String(50), default="P-Unknown")
    affected_range = Column(String(255), nullable=True)
    fixed_version = Column(String(100), nullable=True)
    references_json = Column(JSON, nullable=True)

    scan_vulnerabilities = relationship("ScanVulnerability", back_populates="vulnerability")

class ScanVulnerability(Base):
    __tablename__ = "scan_vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    component_id = Column(Integer, ForeignKey("components.id"), nullable=False)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)

    scan = relationship("Scan", back_populates="scan_vulnerabilities")
    component = relationship("Component", back_populates="scan_vulnerabilities")
    vulnerability = relationship("Vulnerability", back_populates="scan_vulnerabilities")
