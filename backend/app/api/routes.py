import time
import json
import os
import datetime
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.security import get_current_user
from app.database import get_db
from app.models import Project, Scan, Component, Vulnerability, ScanVulnerability, User
from app.schemas import (
    ScanRequest, ScanResponse, ScanSummarySchema, ComponentSchema,
    VulnerabilitySchema, ScanHistoryItem, SbomResponse
)
from app.services.dependency_parser import parse_manifest
from app.services.transitive_resolver import resolve_transitive_dependencies
from app.services.sbom_generator import generate_cyclonedx_sbom
from app.services.correlation_service import correlate_vulnerabilities
from app.config import settings

router = APIRouter()


def _assert_scan_access(scan: Scan, current_user: User) -> None:
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if current_user.role == "admin":
        return
    if scan.owner_id is not None and scan.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Scan not found")


@router.get("/")
def api_root():
    return {
        "service": "SecureSBOM API",
        "message": "SecureSBOM API Service",
        "version": "2.1.0",
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


@router.get("/ready")
def readiness_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Database not ready: {exc}")
    return {"ready": True, "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}


@router.post("/api/v1/scan", response_model=ScanResponse)
async def run_scan(
    request: ScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Run complete dependency scan, SBOM generation, and vulnerability correlation.
    Authenticated & scoped to the current user.
    """
    content = request.requirements_content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Requirements file content cannot be empty.")

    start_time = time.time()

    # 1. Parse direct dependencies (supports requirements.txt, pyproject.toml, poetry.lock, Pipfile.lock, CycloneDX JSON)
    try:
        parsed = parse_manifest(content, filename=request.manifest_filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    direct_deps = parsed["dependencies"]
    if not direct_deps:
        raise HTTPException(
            status_code=400,
            detail="No valid Python dependencies could be parsed from the provided manifest content."
        )

    # 2. Resolve transitive dependencies
    all_components_data = await resolve_transitive_dependencies(direct_deps)
    unresolved_count = sum(1 for c in all_components_data if c.get("resolution_status") == "unresolved")
    resolution_completeness = "partial" if unresolved_count > 0 else "complete"

    # 3. Generate CycloneDX SBOM
    generate_cyclonedx_sbom(request.project_name, all_components_data)

    # 4. Query OSV API, NVD, CISA KEV & FIRST EPSS with graph deduplication
    correlation_res = await correlate_vulnerabilities(all_components_data)
    vulns_data = correlation_res["canonical_vulnerabilities"]
    metrics = correlation_res["metrics"]

    duration = round(time.time() - start_time, 2)
    direct_count = sum(1 for c in all_components_data if c.get("is_direct", True))
    transitive_count = len(all_components_data) - direct_count

    # 5. Database Persistence (scoped to owner_id)
    project = db.query(Project).filter(
        Project.name == request.project_name,
        Project.owner_id == current_user.id,
    ).first()
    if not project:
        project = Project(name=request.project_name, owner_id=current_user.id)
        db.add(project)
        db.commit()
        db.refresh(project)

    scan = Scan(
        project_id=project.id,
        owner_id=current_user.id,
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
        scan_duration_seconds=duration,
        manifest_format=parsed.get("format", "requirements.txt"),
        resolution_completeness=resolution_completeness,
        coverage_status=metrics.get("coverage_status", "complete"),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    component_orm_map = {}
    db_components = []
    for comp in all_components_data:
        c_orm = Component(
            scan_id=scan.id,
            name=comp["name"],
            version=comp["version"],
            declared_specifier=comp.get("declared_specifier"),
            resolved_version=comp.get("resolved_version"),
            installed_version=comp.get("installed_version"),
            resolution_status=comp.get("resolution_status", "resolved"),
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

    db_vuln_schemas = []
    for v in vulns_data:
        canonical_id = v["canonical_id"]
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
                references_json=v.get("references", []),
                is_kev=bool(v.get("is_kev", False)),
                kev_date_added=v.get("kev_date_added"),
                epss_score=v.get("epss_score"),
                epss_percentile=v.get("epss_percentile"),
            )
            db.add(vuln_orm)
            db.flush()
            db.refresh(vuln_orm)
        else:
            if v.get("cve_id"):
                vuln_orm.cve_id = v.get("cve_id")
            vuln_orm.aliases_json = v.get("aliases", []) or vuln_orm.aliases_json
            vuln_orm.sources_json = v.get("sources", []) or vuln_orm.sources_json
            if v.get("summary") and (not vuln_orm.summary or vuln_orm.summary == "Security advisory for component"):
                vuln_orm.summary = v.get("summary")
            if v.get("details"):
                vuln_orm.details = v.get("details")
            if v.get("cvss_score") is not None:
                vuln_orm.cvss_score = v.get("cvss_score")
            if v.get("cvss_vector"):
                vuln_orm.cvss_vector = v.get("cvss_vector")
            if v.get("severity") and v.get("severity") != "UNKNOWN":
                vuln_orm.severity = v.get("severity")
            vuln_orm.severity_sources_json = v.get("severity_sources", []) or vuln_orm.severity_sources_json
            if v.get("priority_tier"):
                vuln_orm.priority_tier = v.get("priority_tier")
            if v.get("affected_range"):
                vuln_orm.affected_range = v.get("affected_range")
            if v.get("fixed_version"):
                vuln_orm.fixed_version = v.get("fixed_version")
            if v.get("references"):
                vuln_orm.references_json = v.get("references")
            if v.get("is_kev"):
                vuln_orm.is_kev = True
                vuln_orm.kev_date_added = v.get("kev_date_added")
            if v.get("epss_score") is not None:
                vuln_orm.epss_score = v.get("epss_score")
                vuln_orm.epss_percentile = v.get("epss_percentile")
            db.flush()

        comp_norm = v.get("component_normalized_name", "").lower().replace("_", "-")
        comp_id = None
        for c_orm in db_components:
            if c_orm.name.lower().replace("_", "-") == comp_norm or c_orm.name.lower() == v.get("affected_component_name", "").lower():
                comp_id = c_orm.id
                break
        if comp_id is None:
            comp_id = component_orm_map.get(comp_norm) or list(component_orm_map.values())[0]

        db.add(ScanVulnerability(
            scan_id=scan.id,
            component_id=comp_id,
            vulnerability_id=vuln_orm.id
        ))

        db_vuln_schemas.append(VulnerabilitySchema(
            id=vuln_orm.id,
            canonical_id=vuln_orm.canonical_id,
            osv_id=vuln_orm.osv_id or vuln_orm.canonical_id,
            cve_id=vuln_orm.cve_id,
            aliases=v.get("aliases", []) or vuln_orm.aliases_json or [],
            sources=v.get("sources", []) or vuln_orm.sources_json or [],
            summary=v.get("summary") or vuln_orm.summary,
            details=v.get("details") or vuln_orm.details,
            cvss_score=v.get("cvss_score") if v.get("cvss_score") is not None else vuln_orm.cvss_score,
            cvss_vector=v.get("cvss_vector") or vuln_orm.cvss_vector,
            severity=v.get("severity") if v.get("severity") != "UNKNOWN" else vuln_orm.severity,
            severity_sources=v.get("severity_sources", []) or vuln_orm.severity_sources_json or [],
            priority_tier=v.get("priority_tier") or vuln_orm.priority_tier,
            affected_component_name=v.get("affected_component_name"),
            affected_component_version=v.get("affected_component_version"),
            affected_range=v.get("affected_range") or vuln_orm.affected_range,
            fixed_version=v.get("fixed_version") or vuln_orm.fixed_version,
            references=v.get("references", []) or vuln_orm.references_json or [],
            is_kev=bool(vuln_orm.is_kev),
            kev_date_added=vuln_orm.kev_date_added,
            epss_score=vuln_orm.epss_score,
            epss_percentile=vuln_orm.epss_percentile,
        ))

    db.commit()

    summary_schema = ScanSummarySchema(
        scan_id=scan.id,
        project_name=project.name,
        timestamp=scan.timestamp,
        total_deps=scan.total_deps,
        direct_deps=scan.direct_deps,
        transitive_deps=scan.transitive_deps,
        total_scanned=scan.total_deps,
        total_direct_deps=scan.direct_deps,
        total_transitive_deps=scan.transitive_deps,
        direct_deps_count=scan.direct_deps,
        transitive_deps_count=scan.transitive_deps,
        total_canonical_vulnerabilities=scan.unique_vuln_count,
        total_raw_advisories=scan.advisory_record_count,
        vulnerable_components_count=scan.affected_components_count,
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
        scan_duration_seconds=scan.scan_duration_seconds,
        coverage_status=scan.coverage_status or "complete",
        manifest_format=scan.manifest_format or "requirements.txt",
        resolution_completeness=scan.resolution_completeness or "complete",
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
def list_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = db.query(Scan)
    if current_user.role != "admin":
        q = q.filter(Scan.owner_id == current_user.id)
    scans = q.order_by(Scan.timestamp.desc()).all()
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
def get_scan_by_id(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    _assert_scan_access(scan, current_user)

    summary_schema = ScanSummarySchema(
        scan_id=scan.id,
        project_name=scan.project.name if scan.project else "Project",
        timestamp=scan.timestamp,
        total_deps=scan.total_deps,
        direct_deps=scan.direct_deps,
        transitive_deps=scan.transitive_deps,
        total_scanned=scan.total_deps,
        total_direct_deps=scan.direct_deps,
        total_transitive_deps=scan.transitive_deps,
        direct_deps_count=scan.direct_deps,
        transitive_deps_count=scan.transitive_deps,
        total_canonical_vulnerabilities=scan.unique_vuln_count or scan.vuln_count,
        total_raw_advisories=scan.advisory_record_count or scan.vuln_count,
        vulnerable_components_count=scan.affected_components_count or 0,
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
        scan_duration_seconds=scan.scan_duration_seconds,
        coverage_status=scan.coverage_status or "complete",
        manifest_format=scan.manifest_format or "requirements.txt",
        resolution_completeness=scan.resolution_completeness or "complete",
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
            references=v.references_json or [],
            is_kev=bool(v.is_kev),
            kev_date_added=v.kev_date_added,
            epss_score=v.epss_score,
            epss_percentile=v.epss_percentile,
        ))

    return ScanResponse(
        summary=summary_schema,
        components=component_schemas,
        vulnerabilities=vuln_schemas
    )


@router.get("/api/v1/scans/{scan_id}/vulnerabilities", response_model=List[VulnerabilitySchema])
def get_scan_vulnerabilities(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    _assert_scan_access(scan, current_user)

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
            references=v.references_json or [],
            is_kev=bool(v.is_kev),
            kev_date_added=v.kev_date_added,
            epss_score=v.epss_score,
            epss_percentile=v.epss_percentile,
        ))

    return vuln_schemas


@router.get("/api/v1/scans/{scan_id}/sbom", response_model=SbomResponse)
def get_scan_sbom(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    _assert_scan_access(scan, current_user)

    comp_data = [
        {"name": c.name, "version": c.version, "is_direct": c.is_direct, "normalized_name": c.name.lower(), "purl": c.purl, "dependency_depth": c.dependency_depth}
        for c in scan.components
    ]
    bom_dict = generate_cyclonedx_sbom(scan.project.name if scan.project else "Project", comp_data)
    return SbomResponse(scan_id=scan.id, bom_json=bom_dict)


@router.get("/api/v1/scans/{scan_id}/live-references")
async def get_scan_live_references(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Automatically fetch live open-source security advisories (GitHub Advisory Database,
    OSV, and local Intelligence Dataset) for scanned packages and UNKNOWN vulnerabilities
    as a client reference feed.
    """
    import httpx
    from app.models.intelligence_models import IntelligenceDocument

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    _assert_scan_access(scan, current_user)

    pkg_names = sorted({c.name.lower().replace("_", "-") for c in scan.components})
    unknown_vulns = [
        {
            "canonical_id": sv.vulnerability.canonical_id,
            "package_name": sv.component.name if sv.component else "unknown",
            "package_version": sv.component.version if sv.component else "unknown",
            "summary": sv.vulnerability.summary,
            "references": sv.vulnerability.references_json or [],
        }
        for sv in scan.scan_vulnerabilities
        if (sv.vulnerability.severity or "UNKNOWN").upper() == "UNKNOWN"
    ]

    live_advisories: List[Dict[str, Any]] = []
    seen_ids = set()

    # 1. Include matched documents from local Intelligence Dataset
    docs = db.query(IntelligenceDocument).filter(
        IntelligenceDocument.is_withdrawn == False  # noqa: E712
    ).order_by(IntelligenceDocument.published_at.desc()).limit(100).all()

    for doc in docs:
        doc_pkgs = {p.lower().replace("_", "-") for p in (doc.package_names_json or [])}
        matched = doc_pkgs.intersection(pkg_names)
        if matched:
            adv_id = doc.external_id or doc.doc_uid
            seen_ids.add(adv_id)
            live_advisories.append({
                "advisory_id": adv_id,
                "title": doc.title,
                "source": "Local Intelligence Dataset",
                "package_name": ", ".join(sorted(matched)),
                "severity": doc.source_reliability.upper() if doc.source_reliability else "INFO",
                "published_at": doc.published_at.isoformat() if doc.published_at else None,
                "summary": doc.excerpt or doc.summary or doc.title,
                "url": doc.url,
            })

    # 2. Fetch latest public pip advisories from GitHub Advisory Database API
    headers = {"User-Agent": "SecureSBOM/2.1"}
    if settings.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                "https://api.github.com/advisories?ecosystem=pip&per_page=20",
                headers=headers,
            )
            if resp.status_code == 200:
                for adv in resp.json():
                    ghsa_id = adv.get("ghsa_id")
                    if not ghsa_id or ghsa_id in seen_ids:
                        continue
                    adv_pkgs = [
                        v.get("package", {}).get("name", "").lower().replace("_", "-")
                        for v in (adv.get("vulnerabilities") or [])
                        if v.get("package", {}).get("name")
                    ]
                    matched = [p for p in adv_pkgs if p in pkg_names]
                    # Include package matches first, plus latest general PyPI advisories as live open-source feed
                    if matched or len(live_advisories) < 8:
                        seen_ids.add(ghsa_id)
                        live_advisories.append({
                            "advisory_id": adv.get("cve_id") or ghsa_id,
                            "title": adv.get("summary") or ghsa_id,
                            "source": "GitHub Advisory Database (Live)",
                            "package_name": ", ".join(matched) if matched else (", ".join(adv_pkgs[:2]) or "PyPI"),
                            "severity": (adv.get("severity") or "UNKNOWN").upper(),
                            "published_at": adv.get("published_at"),
                            "summary": (adv.get("description") or adv.get("summary") or "")[:320],
                            "url": adv.get("html_url") or f"https://github.com/advisories/{ghsa_id}",
                            "matched_project": bool(matched),
                        })
    except Exception:
        pass

    return {
        "scan_id": scan_id,
        "unknown_vulnerabilities": unknown_vulns,
        "live_advisories": live_advisories[:12],
        "reference_sources": [
            {"name": "GitHub Advisory Database (pip)", "url": "https://github.com/advisories?query=ecosystem%3Apip"},
            {"name": "OSV Vulnerability Database", "url": "https://osv.dev/list?ecosystem=PyPI"},
            {"name": "PyPA Advisory Database", "url": "https://github.com/pypa/advisory-database"},
            {"name": "CISA KEV Catalog", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
        ],
    }
