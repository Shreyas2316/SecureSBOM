"""
AI Vulnerability Assessment API Routes
All endpoints are prefixed /api/v1/ai/...
AI findings are NEVER merged with the verified Vulnerability table (OSV/NVD results).
"""
import datetime
import json
import logging
import uuid
import os
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query, Header
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field, validator, ConfigDict
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import settings
from app.models import (
    Scan, Component, Vulnerability, ScanVulnerability,
    AIFinding, AIFindingReview, DependencyAlternative,
    MonitoringSource, MonitoringAlert, GeneratedReport,
    AIAssessmentStatus,
)
from app.services.ai_analysis import (
    analyze_emerging_advisory, analyze_potential_weakness,
)
from app.services.alternatives_service import get_alternatives_for_scan, build_alternatives
from app.services.monitoring_service import run_monitoring_cycle, get_monitoring_status
from app.services.report_service import (
    generate_json_report, generate_csv_report, generate_pdf_report,
    save_report_to_disk,
)

logger = logging.getLogger("securesbom.ai_routes")
router = APIRouter()

# ─────────────────────────────────────────────────────────────
# Request / Response Schemas
# ─────────────────────────────────────────────────────────────

class AIAnalysisRequest(BaseModel):
    package_name: str = Field(..., min_length=1, max_length=255)
    package_version: str = Field(..., min_length=1, max_length=100)
    ecosystem: str = Field(default="PyPI", max_length=50)
    analysis_mode: str = Field(
        default="emerging_advisory",
        description="emerging_advisory | potential_weakness"
    )
    scan_id: Optional[int] = None


class AIFindingReviewRequest(BaseModel):
    action: str = Field(..., description="new_ai_assessment|needs_verification|under_investigation|corroborated_by_authoritative_advisory|rejected_after_review|resolved")
    notes: Optional[str] = Field(None, max_length=4000)
    reason: Optional[str] = Field(None, max_length=2000)
    reviewer_id: Optional[str] = Field(None, max_length=255)


class AIFindingResponse(BaseModel):
    id: int
    finding_id: str
    scan_id: Optional[int]
    package_name: str
    package_version: str
    ecosystem: str
    title: str
    description: Optional[str]
    assessment_type: str
    evidence: Optional[List[Any]]
    evidence_sources: Optional[List[Any]]
    potential_impact: Optional[str]
    confidence: Optional[str]
    confidence_explanation: Optional[str]
    verification_steps: Optional[List[Any]]
    suggested_mitigations: Optional[List[Any]]
    related_advisory_ids: Optional[List[Any]]
    model_name: Optional[str]
    analysis_method: Optional[str]
    created_at: datetime.datetime
    status: str
    limitations: str
    linked_verified_vuln_id: Optional[int]

    model_config = ConfigDict(from_attributes=True)


# ─────────────────────────────────────────────────────────────
# Helper: get user identity from header
# ─────────────────────────────────────────────────────────────

def get_user_id(x_user_id: Optional[str] = Header(None)) -> str:
    return x_user_id or "anonymous"


# ─────────────────────────────────────────────────────────────
# AI Status endpoint
# ─────────────────────────────────────────────────────────────

@router.get("/api/v1/ai/status")
def ai_status():
    """Return AI provider configuration status (no credentials exposed)."""
    return {
        "ai_enabled": settings.AI_ENABLED,
        "provider": settings.AI_PROVIDER if settings.AI_ENABLED else None,
        "model": settings.AI_MODEL_NAME if settings.AI_ENABLED and settings.AI_MODEL_NAME else None,
        "note": (
            "AI analysis is available." if settings.AI_ENABLED
            else "AI analysis is disabled. Set AI_ENABLED=True and configure provider credentials."
        ),
    }


# ─────────────────────────────────────────────────────────────
# Trigger AI analysis
# ─────────────────────────────────────────────────────────────

@router.post("/api/v1/ai/analyze")
async def trigger_ai_analysis(
    request: AIAnalysisRequest,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_user_id),
):
    """
    Run AI assessment for a package.
    Result is stored as an AIFinding (Category B) — separate from verified vulnerabilities.
    """
    if not settings.AI_ENABLED:
        raise HTTPException(
            status_code=503,
            detail="AI analysis is not enabled. Configure AI_ENABLED and provider credentials in server environment."
        )

    # Input validation
    pkg = request.package_name.strip()
    ver = request.package_version.strip()
    mode = request.analysis_mode.strip()

    if mode == "emerging_advisory":
        result = await analyze_emerging_advisory(pkg, ver, request.ecosystem)
    elif mode == "potential_weakness":
        result = await analyze_potential_weakness(pkg, ver, request.ecosystem)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown analysis mode: {mode}")

    # Persist to DB as AIFinding (Category B)
    finding = AIFinding(
        finding_id=result["finding_id"],
        scan_id=request.scan_id,
        package_name=result["package_name"],
        package_version=result["package_version"],
        ecosystem=result["ecosystem"],
        title=result["title"],
        description=result["description"],
        assessment_type=result["assessment_type"],
        evidence_json=result["evidence"],
        evidence_sources_json=result["evidence_sources"],
        potential_impact=result["potential_impact"],
        confidence=result["confidence"],
        confidence_explanation=result["confidence_explanation"],
        verification_steps_json=result["verification_steps"],
        suggested_mitigations_json=result["suggested_mitigations"],
        related_advisory_ids_json=result["related_advisory_ids"],
        model_name=result["model_name"],
        analysis_method=result["analysis_method"],
        status=result["status"],
        limitations=result["limitations"],
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    return {
        "finding_id": finding.finding_id,
        "db_id": finding.id,
        "status": finding.status,
        "confidence": finding.confidence,
        "title": finding.title,
        "assessment_type": finding.assessment_type,
        "limitations": finding.limitations,
        "note": "This is an AI-generated assessment. NOT a confirmed vulnerability.",
        "error": result.get("error"),
    }


# ─────────────────────────────────────────────────────────────
# List AI findings
# ─────────────────────────────────────────────────────────────

@router.get("/api/v1/ai/findings")
def list_ai_findings(
    scan_id: Optional[int] = Query(None),
    package: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    confidence: Optional[str] = Query(None),
    assessment_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """
    List AI assessments with filtering and pagination.
    Results are separate from verified vulnerability findings.
    """
    q = db.query(AIFinding)
    if scan_id:
        q = q.filter(AIFinding.scan_id == scan_id)
    if package:
        q = q.filter(AIFinding.package_name.ilike(f"%{package}%"))
    if status:
        q = q.filter(AIFinding.status == status)
    if confidence:
        q = q.filter(AIFinding.confidence == confidence)
    if assessment_type:
        q = q.filter(AIFinding.assessment_type == assessment_type)

    total = q.count()
    findings = q.order_by(AIFinding.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
        "findings": [_serialize_finding(f) for f in findings],
        "note": "AI-generated assessments only. These are separate from verified vulnerability findings.",
    }


# ─────────────────────────────────────────────────────────────
# Get single AI finding
# ─────────────────────────────────────────────────────────────

@router.get("/api/v1/ai/findings/{finding_id}")
def get_ai_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(AIFinding).filter(AIFinding.finding_id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="AI finding not found")

    reviews = [
        {
            "id": r.id,
            "action": r.action,
            "reviewer_id": r.reviewer_id,
            "previous_status": r.previous_status,
            "new_status": r.new_status,
            "notes": r.notes,
            "reason": r.reason,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in finding.review_history
    ]

    return {
        **_serialize_finding(finding),
        "review_history": reviews,
        "disclaimer": finding.limitations,
    }


# ─────────────────────────────────────────────────────────────
# Update AI finding review status
# ─────────────────────────────────────────────────────────────

@router.patch("/api/v1/ai/findings/{finding_id}/review")
def review_ai_finding(
    finding_id: str,
    request: AIFindingReviewRequest,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_user_id),
):
    """
    Update the review status of an AI finding.
    Preserves audit history. Rejected findings are retained with history.
    """
    finding = db.query(AIFinding).filter(AIFinding.finding_id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="AI finding not found")

    # Validate transition
    valid_statuses = {s.value for s in AIAssessmentStatus}
    if request.action not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Valid values: {sorted(valid_statuses)}"
        )

    previous_status = finding.status

    # Create review record (audit trail preserved even for rejections)
    review = AIFindingReview(
        finding_id_ref=finding.id,
        reviewer_id=user_id,
        action=request.action,
        previous_status=previous_status,
        new_status=request.action,
        notes=request.notes,
        reason=request.reason,
    )
    db.add(review)

    finding.status = request.action
    finding.updated_at = datetime.datetime.now(datetime.timezone.utc)

    db.commit()
    db.refresh(finding)

    return {
        "finding_id": finding.finding_id,
        "previous_status": previous_status,
        "new_status": finding.status,
        "reviewer_id": user_id,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


# ─────────────────────────────────────────────────────────────
# Link AI finding to verified vulnerability
# ─────────────────────────────────────────────────────────────

@router.post("/api/v1/ai/findings/{finding_id}/link-verified/{vuln_id}")
def link_finding_to_verified(
    finding_id: str,
    vuln_id: int,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_user_id),
):
    """
    Link an AI finding to a verified vulnerability.
    The original AI record and its history are PRESERVED; not deleted or merged.
    """
    finding = db.query(AIFinding).filter(AIFinding.finding_id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="AI finding not found")

    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Verified vulnerability not found")

    finding.linked_verified_vuln_id = vuln_id

    review = AIFindingReview(
        finding_id_ref=finding.id,
        reviewer_id=user_id,
        action="corroborated_by_authoritative_advisory",
        previous_status=finding.status,
        new_status="corroborated_by_authoritative_advisory",
        notes=f"Linked to verified finding {vuln.canonical_id}",
    )
    db.add(review)
    finding.status = "corroborated_by_authoritative_advisory"
    finding.updated_at = datetime.datetime.now(datetime.timezone.utc)

    db.commit()

    return {
        "finding_id": finding_id,
        "linked_to": vuln.canonical_id,
        "note": "Original AI record preserved with audit history. Counts remain separate.",
    }


# ─────────────────────────────────────────────────────────────
# Dependency alternatives
# ─────────────────────────────────────────────────────────────

@router.get("/api/v1/scans/{scan_id}/alternatives")
async def get_scan_alternatives(
    scan_id: int,
    db: Session = Depends(get_db),
):
    """Get safer dependency alternatives for vulnerabilities in a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Fetch verified vulnerabilities for this scan
    vuln_data = []
    for sv in scan.scan_vulnerabilities:
        v = sv.vulnerability
        c = sv.component
        vuln_data.append({
            "canonical_id": v.canonical_id,
            "affected_component_name": c.name if c else None,
            "affected_component_version": c.version if c else None,
            "fixed_version": v.fixed_version,
        })

    if not vuln_data:
        return {"alternatives": [], "note": "No verified vulnerabilities to generate alternatives for."}

    alternatives = await get_alternatives_for_scan(vuln_data)

    # Persist alternatives to DB
    for alt in alternatives:
        existing = db.query(DependencyAlternative).filter(
            DependencyAlternative.scan_id == scan_id,
            DependencyAlternative.package_name == alt.get("package_name"),
            DependencyAlternative.vulnerability_canonical_id == alt.get("vulnerability_canonical_id"),
            DependencyAlternative.recommendation_type == alt.get("recommendation_type"),
        ).first()
        if not existing:
            da = DependencyAlternative(
                scan_id=scan_id,
                vulnerability_canonical_id=alt.get("vulnerability_canonical_id"),
                package_name=alt.get("package_name", ""),
                package_version=alt.get("package_version", ""),
                ecosystem="PyPI",
                recommendation_type=alt.get("recommendation_type", ""),
                label=alt.get("label"),
                recommended_version=alt.get("recommended_version"),
                alternative_package=alt.get("alternative_package"),
                alternative_version=alt.get("alternative_version"),
                compatibility_info=alt.get("compatibility_info"),
                known_vulns_in_alternative=alt.get("known_vulns_in_alternative"),
                migration_complexity=alt.get("migration_complexity"),
                breaking_change_risk=alt.get("breaking_change_risk"),
                license_info=alt.get("license_info"),
                maintenance_evidence=alt.get("maintenance_evidence"),
                rationale=alt.get("rationale"),
                evidence_links_json=alt.get("evidence_links", []),
                verification_status=alt.get("verification_status"),
                source=alt.get("source", "pypi_metadata"),
            )
            db.add(da)
    db.commit()

    return {
        "scan_id": scan_id,
        "alternatives": alternatives,
        "note": "Recommendations require manual review. Do NOT apply automatically.",
    }


# ─────────────────────────────────────────────────────────────
# Report generation
# ─────────────────────────────────────────────────────────────

def _build_scan_data_dict(scan_id: Any, db: Session) -> Dict[str, Any]:
    """Serialize scan data for report generation, supporting both Scan and ScanRecord."""
    scan = None
    try:
        int_id = int(scan_id)
        scan = db.query(Scan).filter(Scan.id == int_id).first()
    except (ValueError, TypeError):
        scan = None

    if scan:
        summary = {
            "scan_id": scan.id,
            "project_name": scan.project.name if scan.project else "Unknown",
            "timestamp": scan.timestamp.isoformat() if scan.timestamp else "",
            "total_deps": scan.total_deps,
            "direct_deps": scan.direct_deps,
            "transitive_deps": scan.transitive_deps,
            "unique_vuln_count": scan.unique_vuln_count or scan.vuln_count or len(scan.scan_vulnerabilities),
            "advisory_record_count": scan.advisory_record_count or scan.vuln_count,
            "affected_components_count": scan.affected_components_count or 0,
            "critical_count": scan.critical_count,
            "high_count": scan.high_count,
            "medium_count": scan.medium_count,
            "low_count": scan.low_count,
            "info_count": scan.info_count,
            "unknown_count": scan.unknown_count,
            "scan_duration_seconds": scan.scan_duration_seconds,
        }

        components = [
            {"name": c.name, "version": c.version, "ecosystem": c.ecosystem,
             "is_direct": c.is_direct, "purl": c.purl}
            for c in scan.components
        ]

        vulnerabilities = []
        for sv in scan.scan_vulnerabilities:
            v = sv.vulnerability
            c = sv.component
            vulnerabilities.append({
                "canonical_id": v.canonical_id,
                "cve_id": v.cve_id,
                "aliases": v.aliases_json or [],
                "sources": v.sources_json or [],
                "summary": v.summary,
                "details": v.details,
                "cvss_score": v.cvss_score,
                "cvss_vector": v.cvss_vector,
                "severity": v.severity,
                "priority_tier": v.priority_tier,
                "affected_component_name": c.name if c else None,
                "affected_component_version": c.version if c else None,
                "fixed_version": v.fixed_version,
                "affected_range": v.affected_range,
                "references": v.references_json or [],
            })

        return {"summary": summary, "components": components, "vulnerabilities": vulnerabilities}

    # Fallback to backend.database ScanRecord
    try:
        from backend.database import get_scan_by_id
        raw_report = get_scan_by_id(str(scan_id))
        if raw_report:
            s = raw_report.get("summary", {})
            sev = s.get("vulnerabilities_by_severity", {})
            summary = {
                "scan_id": raw_report.get("scan_id", scan_id),
                "project_name": raw_report.get("manifest_name", "requirements.txt"),
                "timestamp": raw_report.get("timestamp", ""),
                "total_deps": s.get("total_scanned", 0),
                "direct_deps": s.get("total_direct_deps", 0),
                "transitive_deps": s.get("total_transitive_deps", 0),
                "unique_vuln_count": s.get("total_canonical_vulnerabilities", len(raw_report.get("canonical_vulnerabilities", []))),
                "advisory_record_count": s.get("total_raw_advisories", 0),
                "affected_components_count": s.get("vulnerable_components_count", 0),
                "critical_count": sev.get("CRITICAL", 0),
                "high_count": sev.get("HIGH", 0),
                "medium_count": sev.get("MEDIUM", 0),
                "low_count": sev.get("LOW", 0),
                "info_count": sev.get("INFORMATIONAL", 0),
                "unknown_count": sev.get("UNKNOWN", 0),
                "scan_duration_seconds": s.get("scan_duration_seconds", 0),
            }
            components = raw_report.get("dependencies", [])
            vulnerabilities = raw_report.get("canonical_vulnerabilities", [])
            return {"summary": summary, "components": components, "vulnerabilities": vulnerabilities}
    except Exception:
        pass

    raise HTTPException(status_code=404, detail="Scan not found")


@router.get("/api/v1/scans/{scan_id}/report/json")
async def download_scan_report_json(
    scan_id: str,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_user_id),
):
    """Download JSON vulnerability report for a scan."""
    scan_data = _build_scan_data_dict(scan_id, db)
    report_id = uuid.uuid4().hex[:12].upper()

    try:
        int_id = int(scan_id)
        ai_findings = [
            _serialize_finding(f)
            for f in db.query(AIFinding).filter(AIFinding.scan_id == int_id).all()
        ]
        alternatives_q = db.query(DependencyAlternative).filter(
            DependencyAlternative.scan_id == int_id
        ).all()
        alternatives = [_serialize_alternative(a) for a in alternatives_q]
    except Exception:
        ai_findings = []
        alternatives = []

    content = generate_json_report(scan_data, ai_findings, alternatives, report_id)

    return Response(
        content=content,
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="securesbom_report_{report_id}.json"'}
    )


@router.get("/api/v1/scans/{scan_id}/report/csv")
async def download_scan_report_csv(
    scan_id: str,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_user_id),
):
    """Download CSV vulnerability report for a scan."""
    scan_data = _build_scan_data_dict(scan_id, db)
    report_id = uuid.uuid4().hex[:12].upper()

    try:
        int_id = int(scan_id)
        ai_findings = [
            _serialize_finding(f)
            for f in db.query(AIFinding).filter(AIFinding.scan_id == int_id).all()
        ]
    except Exception:
        ai_findings = []

    content = generate_csv_report(scan_data, ai_findings)

    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="securesbom_report_{report_id}.csv"'}
    )


@router.get("/api/v1/scans/{scan_id}/report/pdf")
async def download_scan_report_pdf(
    scan_id: str,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_user_id),
):
    """Download PDF vulnerability report for a scan."""
    scan_data = _build_scan_data_dict(scan_id, db)
    report_id = uuid.uuid4().hex[:12].upper()

    try:
        int_id = int(scan_id)
        ai_findings = [
            _serialize_finding(f)
            for f in db.query(AIFinding).filter(AIFinding.scan_id == int_id).all()
        ]
        alternatives_q = db.query(DependencyAlternative).filter(
            DependencyAlternative.scan_id == int_id
        ).all()
        alternatives = [_serialize_alternative(a) for a in alternatives_q]
    except Exception:
        ai_findings = []
        alternatives = []

    content = generate_pdf_report(scan_data, ai_findings, alternatives, report_id)

    media_type = "application/pdf" if content[:4] == b"%PDF" else "text/plain; charset=utf-8"
    filename_ext = "pdf" if media_type == "application/pdf" else "txt"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="securesbom_report_{report_id}.{filename_ext}"'}
    )


# ─────────────────────────────────────────────────────────────
# Monitoring
# ─────────────────────────────────────────────────────────────

@router.get("/api/v1/monitoring/status")
def monitoring_status(db: Session = Depends(get_db)):
    """Get current monitoring source status and last sync info."""
    return get_monitoring_status(db)


@router.post("/api/v1/monitoring/run")
async def trigger_monitoring(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_user_id),
):
    """
    Trigger a monitoring cycle. Runs synchronously and returns results.
    Note: monitoring is periodic, not real-time continuous.
    """
    results = await run_monitoring_cycle(db)
    return {
        "status": "completed",
        "results": results,
        "note": "Monitoring is periodic, not real-time. Results reflect current OSV data.",
    }


@router.get("/api/v1/monitoring/alerts")
def list_monitoring_alerts(
    acknowledged: Optional[bool] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """List monitoring alerts for new advisories affecting saved dependencies."""
    q = db.query(MonitoringAlert)
    if acknowledged is not None:
        q = q.filter(MonitoringAlert.is_acknowledged == acknowledged)

    total = q.count()
    alerts = q.order_by(MonitoringAlert.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "alerts": [
            {
                "id": a.id,
                "advisory_id": a.advisory_id,
                "package_name": a.package_name,
                "package_version": a.package_version,
                "severity": a.severity,
                "summary": a.summary,
                "scan_id": a.scan_id,
                "is_acknowledged": a.is_acknowledged,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in alerts
        ],
    }


@router.patch("/api/v1/monitoring/alerts/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_user_id),
):
    alert = db.query(MonitoringAlert).filter(MonitoringAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_acknowledged = True
    db.commit()
    return {"alert_id": alert_id, "acknowledged": True}


# ─────────────────────────────────────────────────────────────
# Dashboard summary for AI findings
# ─────────────────────────────────────────────────────────────

@router.get("/api/v1/ai/dashboard")
def ai_dashboard_summary(db: Session = Depends(get_db)):
    """
    Dashboard summary cards for AI-Detected Emerging Vulnerabilities.
    Counts are SEPARATE from verified vulnerability counts.
    """
    total = db.query(AIFinding).count()
    new = db.query(AIFinding).filter(AIFinding.status == AIAssessmentStatus.NEW.value).count()
    needs_verification = db.query(AIFinding).filter(
        AIFinding.status == AIAssessmentStatus.NEEDS_VERIFICATION.value
    ).count()
    under_investigation = db.query(AIFinding).filter(
        AIFinding.status == AIAssessmentStatus.UNDER_INVESTIGATION.value
    ).count()
    corroborated = db.query(AIFinding).filter(
        AIFinding.status == AIAssessmentStatus.CORROBORATED.value
    ).count()
    rejected = db.query(AIFinding).filter(
        AIFinding.status == AIAssessmentStatus.REJECTED.value
    ).count()
    resolved = db.query(AIFinding).filter(
        AIFinding.status == AIAssessmentStatus.RESOLVED.value
    ).count()

    # Unacknowledged monitoring alerts
    unack_alerts = db.query(MonitoringAlert).filter(
        MonitoringAlert.is_acknowledged == False
    ).count()

    return {
        "total_ai_assessments": total,
        "new_awaiting_review": new,
        "needs_verification": needs_verification,
        "under_investigation": under_investigation,
        "corroborated_by_advisory": corroborated,
        "rejected": rejected,
        "resolved": resolved,
        "unacknowledged_monitoring_alerts": unack_alerts,
        "note": "These counts are SEPARATE from verified OSV/NVD vulnerability counts.",
        "ai_enabled": settings.AI_ENABLED,
    }


# ─────────────────────────────────────────────────────────────
# Serialization helpers
# ─────────────────────────────────────────────────────────────

def _serialize_finding(f: AIFinding) -> Dict[str, Any]:
    return {
        "id": f.id,
        "finding_id": f.finding_id,
        "scan_id": f.scan_id,
        "package_name": f.package_name,
        "package_version": f.package_version,
        "ecosystem": f.ecosystem,
        "title": f.title,
        "description": f.description,
        "assessment_type": f.assessment_type,
        "evidence": f.evidence_json or [],
        "evidence_sources": f.evidence_sources_json or [],
        "potential_impact": f.potential_impact,
        "confidence": f.confidence,
        "confidence_explanation": f.confidence_explanation,
        "verification_steps": f.verification_steps_json or [],
        "suggested_mitigations": f.suggested_mitigations_json or [],
        "related_advisory_ids": f.related_advisory_ids_json or [],
        "model_name": f.model_name,
        "analysis_method": f.analysis_method,
        "created_at": f.created_at.isoformat() if f.created_at else None,
        "updated_at": f.updated_at.isoformat() if f.updated_at else None,
        "status": f.status,
        "limitations": f.limitations,
        "linked_verified_vuln_id": f.linked_verified_vuln_id,
    }


def _serialize_alternative(a: DependencyAlternative) -> Dict[str, Any]:
    return {
        "id": a.id,
        "scan_id": a.scan_id,
        "vulnerability_canonical_id": a.vulnerability_canonical_id,
        "package_name": a.package_name,
        "package_version": a.package_version,
        "ecosystem": a.ecosystem,
        "recommendation_type": a.recommendation_type,
        "label": a.label,
        "recommended_version": a.recommended_version,
        "alternative_package": a.alternative_package,
        "alternative_version": a.alternative_version,
        "compatibility_info": a.compatibility_info,
        "known_vulns_in_alternative": a.known_vulns_in_alternative,
        "migration_complexity": a.migration_complexity,
        "breaking_change_risk": a.breaking_change_risk,
        "license_info": a.license_info,
        "maintenance_evidence": a.maintenance_evidence,
        "rationale": a.rationale,
        "evidence_links": a.evidence_links_json or [],
        "verification_status": a.verification_status,
        "source": a.source,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }
