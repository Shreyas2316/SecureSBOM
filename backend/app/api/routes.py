import time
import json
import os
import datetime
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Project, Scan, Component, Vulnerability, ScanVulnerability
from app.schemas import (
    ScanRequest, ScanResponse, ScanSummarySchema, ComponentSchema,
    VulnerabilitySchema, ScanHistoryItem, SbomResponse
)
from app.services.dependency_parser import parse_requirements
from app.services.transitive_resolver import resolve_transitive_dependencies
from app.services.sbom_generator import generate_cyclonedx_sbom
from app.services.correlation_service import correlate_vulnerabilities
from app.config import settings

router = APIRouter()

@router.get("/")
def api_root():
    return {
        "message": "SecureSBOM API Service",
        "version": "1.0.0",
        "status": "online",
        "documentation": "/docs"
    }

@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception:
        db_status = "unhealthy"
    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "database": db_status,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

@router.post("/api/v1/scan", response_model=ScanResponse)
async def run_scan(request: ScanRequest, db: Session = Depends(get_db)):
    """
    Run complete dependency scan, SBOM generation, and vulnerability correlation.
    """
    content = request.requirements_content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Requirements file content cannot be empty.")

    start_time = time.time()

    # 1. Parse direct dependencies
    direct_deps = parse_requirements(content)
    if not direct_deps:
        raise HTTPException(
            status_code=400,
            detail="No valid Python dependencies could be parsed from the provided requirements.txt content."
        )

    # 2. Resolve transitive dependencies
    all_components_data = await resolve_transitive_dependencies(direct_deps, max_depth=2)

    # 3. Generate CycloneDX SBOM
    bom_dict = generate_cyclonedx_sbom(request.project_name, all_components_data)

    # 4. Query OSV API & NVD enrichment with graph deduplication
    correlation_res = await correlate_vulnerabilities(all_components_data)
    vulns_data = correlation_res["canonical_vulnerabilities"]
    metrics = correlation_res["metrics"]

    duration = round(time.time() - start_time, 2)

    direct_count = sum(1 for c in all_components_data if c.get("is_direct", True))
    transitive_count = len(all_components_data) - direct_count

    # 5. Database Persistence
    project = db.query(Project).filter(Project.name == request.project_name).first()
    if not project:
        project = Project(name=request.project_name)
        db.add(project)
        db.commit()
        db.refresh(project)

    scan = Scan(
        project_id=project.id,
        timestamp=datetime.datetime.now(datetime.timezone.utc),
        total_deps=len(all_components_data),
        direct_deps=direct_count,
        transitive_deps=transitive_count,
        unique_vuln_count=metrics["unique_vuln_count"],
        advisory_record_count=metrics["advisory_record_count"],
        affected_components_count=metrics["affected_components_count"],
        vuln_count=metrics["unique_vuln_count"],
        critical_count=metrics["critical_count"],
        high_count=metrics["high_count"],
        medium_count=metrics["medium_count"],
        low_count=metrics["low_count"],
        info_count=metrics["info_count"],
        unknown_count=metrics["unknown_count"],
        scan_duration_seconds=duration
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Save components to DB
    component_orm_map = {}
    db_components = []
    for comp in all_components_data:
        c_orm = Component(
            scan_id=scan.id,
            name=comp["name"],
            version=comp["version"],
            ecosystem="PyPI",
            is_direct=comp.get("is_direct", True),
            purl=comp.get("purl"),
            dependency_depth=comp.get("dependency_depth", 0)
        )
        db.add(c_orm)
        db_components.append(c_orm)

    db.commit()

    for c_orm in db_components:
        component_orm_map[c_orm.name.lower()] = c_orm.id

    # Save vulnerabilities to DB
    db_vuln_schemas = []
    for v in vulns_data:
        canonical_id = v["canonical_id"]
        # Scoped lookup per canonical_id
        vuln_orm = db.query(Vulnerability).filter(Vulnerability.canonical_id == canonical_id).first()
        if not vuln_orm:
            vuln_orm = Vulnerability(
                canonical_id=canonical_id,
                osv_id=v.get("osv_id") or canonical_id,
                cve_id=v.get("cve_id"),
                aliases_json=v.get("aliases", []),
                sources_json=v.get("sources", []),
                summary=v.get("summary"),
                details=v.get("details"),
                cvss_score=v.get("cvss_score"),
                cvss_vector=v.get("cvss_vector"),
                severity=v.get("severity", "UNKNOWN"),
                severity_sources_json=v.get("severity_sources", []),
                priority_tier=v.get("priority_tier", "P-Unknown"),
                affected_range=v.get("affected_range"),
                fixed_version=v.get("fixed_version"),
                references_json=v.get("references", [])
            )
            db.add(vuln_orm)
            db.commit()
            db.refresh(vuln_orm)
        else:
            # Update mutable fields if needed
            vuln_orm.aliases_json = v.get("aliases", [])
            vuln_orm.sources_json = v.get("sources", [])
            vuln_orm.severity_sources_json = v.get("severity_sources", [])
            vuln_orm.affected_range = v.get("affected_range")
            vuln_orm.fixed_version = v.get("fixed_version")
            db.commit()

        # Link to Scan & Component
        comp_norm = v["component_normalized_name"]
        comp_id = component_orm_map.get(comp_norm) or list(component_orm_map.values())[0]

        scan_v = ScanVulnerability(
            scan_id=scan.id,
            component_id=comp_id,
            vulnerability_id=vuln_orm.id
        )
        db.add(scan_v)

        db_vuln_schemas.append(VulnerabilitySchema(
            id=vuln_orm.id,
            canonical_id=vuln_orm.canonical_id,
            osv_id=vuln_orm.osv_id or vuln_orm.canonical_id,
            cve_id=vuln_orm.cve_id,
            aliases=v.get("aliases", []),
            sources=v.get("sources", []),
            summary=vuln_orm.summary,
            details=vuln_orm.details,
            cvss_score=vuln_orm.cvss_score,
            cvss_vector=vuln_orm.cvss_vector,
            severity=vuln_orm.severity,
            severity_sources=v.get("severity_sources", []),
            priority_tier=vuln_orm.priority_tier,
            affected_component_name=v["affected_component_name"],
            affected_component_version=v["affected_component_version"],
            affected_range=v.get("affected_range"),
            fixed_version=v.get("fixed_version"),
            references=vuln_orm.references_json or []
        ))

    db.commit()

    # Form response schemas
    summary_schema = ScanSummarySchema(
        scan_id=scan.id,
        project_name=project.name,
        timestamp=scan.timestamp,
        total_deps=scan.total_deps,
        direct_deps=scan.direct_deps,
        transitive_deps=scan.transitive_deps,
        unique_vuln_count=scan.unique_vuln_count,
        advisory_record_count=scan.advisory_record_count,
        affected_components_count=scan.affected_components_count,
        vuln_count=scan.unique_vuln_count,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        info_count=scan.info_count,
        unknown_count=scan.unknown_count,
        scan_duration_seconds=scan.scan_duration_seconds
    )

    component_schemas = [
        ComponentSchema(
            id=c.id,
            name=c.name,
            version=c.version,
            ecosystem=c.ecosystem,
            is_direct=c.is_direct,
            purl=c.purl,
            dependency_depth=c.dependency_depth
        ) for c in db_components
    ]

    return ScanResponse(
        summary=summary_schema,
        components=component_schemas,
        vulnerabilities=db_vuln_schemas
    )

@router.get("/api/v1/scans", response_model=List[ScanHistoryItem])
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.timestamp.desc()).all()
    history = []
    for s in scans:
        history.append(ScanHistoryItem(
            scan_id=s.id,
            project_name=s.project.name if s.project else "Unknown Project",
            timestamp=s.timestamp,
            total_deps=s.total_deps,
            unique_vuln_count=s.unique_vuln_count or s.vuln_count,
            advisory_record_count=s.advisory_record_count or s.vuln_count,
            affected_components_count=s.affected_components_count or 0,
            vuln_count=s.unique_vuln_count or s.vuln_count,
            critical_count=s.critical_count,
            high_count=s.high_count,
            medium_count=s.medium_count,
            low_count=s.low_count,
            info_count=s.info_count,
            unknown_count=s.unknown_count
        ))
    return history

@router.get("/api/v1/scans/{scan_id}", response_model=ScanResponse)
def get_scan_by_id(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    summary_schema = ScanSummarySchema(
        scan_id=scan.id,
        project_name=scan.project.name if scan.project else "Project",
        timestamp=scan.timestamp,
        total_deps=scan.total_deps,
        direct_deps=scan.direct_deps,
        transitive_deps=scan.transitive_deps,
        unique_vuln_count=scan.unique_vuln_count or scan.vuln_count,
        advisory_record_count=scan.advisory_record_count or scan.vuln_count,
        affected_components_count=scan.affected_components_count or 0,
        vuln_count=scan.unique_vuln_count or scan.vuln_count,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        info_count=scan.info_count,
        unknown_count=scan.unknown_count,
        scan_duration_seconds=scan.scan_duration_seconds
    )

    component_schemas = [
        ComponentSchema(
            id=c.id,
            name=c.name,
            version=c.version,
            ecosystem=c.ecosystem,
            is_direct=c.is_direct,
            purl=c.purl,
            dependency_depth=c.dependency_depth
        ) for c in scan.components
    ]

    vuln_schemas = []
    for sv in scan.scan_vulnerabilities:
        v = sv.vulnerability
        c = sv.component
        vuln_schemas.append(VulnerabilitySchema(
            id=v.id,
            canonical_id=v.canonical_id,
            osv_id=v.osv_id or v.canonical_id,
            cve_id=v.cve_id,
            aliases=v.aliases_json or [],
            sources=v.sources_json or [],
            summary=v.summary,
            details=v.details,
            cvss_score=v.cvss_score,
            cvss_vector=v.cvss_vector,
            severity=v.severity,
            severity_sources=v.severity_sources_json or [],
            priority_tier=v.priority_tier,
            affected_component_name=c.name if c else None,
            affected_component_version=c.version if c else None,
            affected_range=v.affected_range,
            fixed_version=v.fixed_version,
            references=v.references_json or []
        ))

    return ScanResponse(
        summary=summary_schema,
        components=component_schemas,
        vulnerabilities=vuln_schemas
    )

@router.get("/api/v1/scans/{scan_id}/vulnerabilities", response_model=List[VulnerabilitySchema])
def get_scan_vulnerabilities(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    vuln_schemas = []
    for sv in scan.scan_vulnerabilities:
        v = sv.vulnerability
        c = sv.component
        vuln_schemas.append(VulnerabilitySchema(
            id=v.id,
            canonical_id=v.canonical_id,
            osv_id=v.osv_id or v.canonical_id,
            cve_id=v.cve_id,
            aliases=v.aliases_json or [],
            sources=v.sources_json or [],
            summary=v.summary,
            details=v.details,
            cvss_score=v.cvss_score,
            cvss_vector=v.cvss_vector,
            severity=v.severity,
            severity_sources=v.severity_sources_json or [],
            priority_tier=v.priority_tier,
            affected_component_name=c.name if c else None,
            affected_component_version=c.version if c else None,
            affected_range=v.affected_range,
            fixed_version=v.fixed_version,
            references=v.references_json or []
        ))

    return vuln_schemas

@router.get("/api/v1/scans/{scan_id}/sbom", response_model=SbomResponse)
def get_scan_sbom(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    target_path = os.path.join(settings.OUTPUT_DIR, "bom.json")
    bom_dict = {}
    if os.path.exists(target_path):
        with open(target_path, "r", encoding="utf-8") as f:
            bom_dict = json.load(f)
    else:
        comp_data = [{"name": c.name, "version": c.version, "is_direct": c.is_direct, "normalized_name": c.name.lower()} for c in scan.components]
        bom_dict = generate_cyclonedx_sbom(scan.project.name if scan.project else "Project", comp_data)

    return SbomResponse(scan_id=scan.id, bom_json=bom_dict)
