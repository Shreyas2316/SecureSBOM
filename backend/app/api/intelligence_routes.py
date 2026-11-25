"""
Intelligence Dataset, Evidence-Grounded RAG, Category B/C Lifecycle,
Reassessment, and Opt-In Static Analysis API Routes.
"""
import datetime
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.security import get_current_user
from app.database import get_db
from app.models.auth_models import User
from app.models.intelligence_models import (
    EmergingFinding, FindingReview, FindingStatusHistory,
    IntelligenceDocument, IntelligenceSource, IntelligenceSyncRun,
    PackageIntelligenceMatch, PotentialWeakness
)
from app.models.models import Scan, Vulnerability
from app.services.intelligence_adapters import ensure_default_sources, sync_all_intelligence_sources
from app.services.intelligence_search import hybrid_search_intelligence, check_version_applicability
from app.services.rag_engine import (
    promote_emerging_to_confirmed, run_evidence_grounded_rag, run_static_security_analysis
)

router = APIRouter(prefix="/api/v1/intelligence", tags=["Intelligence & RAG"])


class SyncRequest(BaseModel):
    source_keys: Optional[List[str]] = None


class RAGAssessRequest(BaseModel):
    package_name: str = Field(..., min_length=1, max_length=255)
    package_version: str = Field(..., min_length=1, max_length=100)
    ecosystem: str = Field(default="PyPI", max_length=50)
    scan_id: Optional[int] = None


class EmergingReviewRequest(BaseModel):
    action: str = Field(..., description="new | under_review | emerging | confirmed | rejected | withdrawn | remediated")
    notes: Optional[str] = Field(None, max_length=4000)
    reason: Optional[str] = Field(None, max_length=2000)


class StaticAnalyzeRequest(BaseModel):
    filename: str = Field(default="snippet.py", max_length=255)
    source_code: str = Field(..., min_length=1, max_length=524288)
    scan_id: Optional[int] = None


@router.get("/sources")
def list_intelligence_sources(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    sources = ensure_default_sources(db)
    total_docs = db.query(IntelligenceDocument).filter(IntelligenceDocument.is_withdrawn == False).count()  # noqa: E712
    return {
        "total_documents": total_docs,
        "active_sources": sum(1 for s in sources if s.is_enabled),
        "sources": [
            {
                "id": s.id,
                "source_key": s.source_key,
                "name": s.name,
                "source_type": s.source_type,
                "url": s.url,
                "reliability_tier": s.reliability_tier,
                "sync_interval_minutes": s.sync_interval_minutes,
                "is_enabled": s.is_enabled,
                "last_checked_at": s.last_checked_at.isoformat() if s.last_checked_at else None,
                "last_successful_sync_at": s.last_successful_sync_at.isoformat() if s.last_successful_sync_at else None,
                "last_error": s.last_error,
                "documents_indexed": s.documents_indexed,
            }
            for s in sources
        ],
    }


@router.post("/sync")
async def trigger_intelligence_sync(
    payload: Optional[SyncRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    keys = payload.source_keys if payload else None
    result = await sync_all_intelligence_sources(db, source_keys=keys)
    return result


@router.get("/documents")
def search_intelligence_documents(
    q: Optional[str] = Query(None),
    package: Optional[str] = Query(None),
    source_key: Optional[str] = Query(None),
    include_withdrawn: bool = Query(False),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if q and q.strip():
        hits = hybrid_search_intelligence(db, query_text=q.strip(), package_name=package, top_k=page_size)
        return {"total": len(hits), "page": 1, "page_size": page_size, "documents": hits}

    query = db.query(IntelligenceDocument)
    if not include_withdrawn:
        query = query.filter(IntelligenceDocument.is_withdrawn == False)  # noqa: E712
    if source_key:
        src = db.query(IntelligenceSource).filter(IntelligenceSource.source_key == source_key).first()
        if src:
            query = query.filter(IntelligenceDocument.source_id == src.id)
    if package:
        query = query.filter(IntelligenceDocument.title.ilike(f"%{package}%") | IntelligenceDocument.summary.ilike(f"%{package}%"))

    total = query.count()
    docs = query.order_by(IntelligenceDocument.retrieved_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "documents": [
            {
                "doc_uid": d.doc_uid,
                "external_id": d.external_id,
                "source_id": d.source_id,
                "title": d.title,
                "summary": d.summary,
                "excerpt": d.excerpt,
                "url": d.url,
                "published_at": d.published_at.isoformat() if d.published_at else None,
                "retrieved_at": d.retrieved_at.isoformat() if d.retrieved_at else None,
                "package_names": d.package_names_json or [],
                "aliases": d.aliases_json or [],
                "affected_ranges": d.affected_ranges_json or [],
                "fixed_versions": d.fixed_versions_json or [],
                "source_reliability": d.source_reliability,
                "review_status": d.review_status,
                "is_withdrawn": d.is_withdrawn,
            }
            for d in docs
        ],
    }


@router.post("/rag-assess")
async def rag_assess_package(
    payload: RAGAssessRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if payload.scan_id is not None:
        scan = db.query(Scan).filter(Scan.id == payload.scan_id).first()
        if not scan or (current_user.role != "admin" and scan.owner_id not in (None, current_user.id)):
            raise HTTPException(status_code=404, detail="Scan not found")

    return await run_evidence_grounded_rag(
        db=db,
        package_name=payload.package_name.strip(),
        package_version=payload.package_version.strip(),
        ecosystem=payload.ecosystem.strip(),
        scan_id=payload.scan_id,
        owner_id=current_user.id,
    )


@router.get("/emerging")
def list_emerging_findings(
    scan_id: Optional[int] = Query(None),
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = db.query(EmergingFinding)
    if current_user.role != "admin":
        q = q.filter((EmergingFinding.owner_id == current_user.id) | (EmergingFinding.owner_id == None))  # noqa: E711
    if scan_id is not None:
        q = q.filter(EmergingFinding.scan_id == scan_id)
    if status:
        q = q.filter(EmergingFinding.status == status)

    rows = q.order_by(EmergingFinding.created_at.desc()).limit(100).all()
    return {
        "total": len(rows),
        "category": "B_EMERGING_INTELLIGENCE",
        "findings": [
            {
                "finding_id": r.finding_id,
                "scan_id": r.scan_id,
                "package_name": r.package_name,
                "package_version": r.package_version,
                "ecosystem": r.ecosystem,
                "title": r.title,
                "description": r.description,
                "affected_version_status": r.affected_version_status,
                "evidence_doc_ids": r.evidence_doc_ids_json or [],
                "source_urls": r.source_urls_json or [],
                "evidence_excerpts": r.evidence_excerpts_json or [],
                "published_at": r.published_at.isoformat() if r.published_at else None,
                "retrieved_at": r.retrieved_at.isoformat() if r.retrieved_at else None,
                "ai_provider": r.ai_provider,
                "model_name": r.model_name,
                "confidence": r.confidence,
                "confidence_explanation": r.confidence_explanation,
                "limitations": r.limitations,
                "suggested_remediation": r.suggested_remediation,
                "status": r.status,
                "promoted_to_vuln_id": r.promoted_to_vuln_id,
            }
            for r in rows
        ],
    }


@router.patch("/emerging/{finding_id}/review")
def review_emerging_finding(
    finding_id: str,
    payload: EmergingReviewRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    valid = {"new", "under_review", "emerging", "confirmed", "rejected", "withdrawn", "remediated"}
    if payload.action not in valid:
        raise HTTPException(status_code=400, detail=f"Invalid status. Valid: {sorted(valid)}")

    finding = db.query(EmergingFinding).filter(EmergingFinding.finding_id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Emerging finding not found")
    if current_user.role != "admin" and finding.owner_id not in (None, current_user.id):
        raise HTTPException(status_code=403, detail="Not authorized to review this finding")

    prev = finding.status
    finding.status = payload.action
    db.add(FindingReview(
        finding_type="emerging",
        finding_ref_id=finding.finding_id,
        reviewer_id=current_user.username,
        action=payload.action,
        previous_status=prev,
        new_status=payload.action,
        notes=payload.notes,
        reason=payload.reason,
    ))
    db.add(FindingStatusHistory(
        finding_type="emerging",
        finding_ref_id=finding.finding_id,
        from_status=prev,
        to_status=payload.action,
        changed_by=current_user.username,
        reason=payload.reason or payload.notes,
    ))
    db.commit()
    return {"finding_id": finding.finding_id, "previous_status": prev, "new_status": finding.status}


@router.post("/emerging/{finding_id}/promote/{vuln_id}")
def promote_finding(
    finding_id: str,
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        updated = promote_emerging_to_confirmed(db, finding_id, vuln_id, current_user.username)
        return {"finding_id": updated.finding_id, "status": updated.status, "promoted_to_vuln_id": updated.promoted_to_vuln_id}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/weaknesses")
def list_potential_weaknesses(
    scan_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = db.query(PotentialWeakness)
    if current_user.role != "admin":
        q = q.filter((PotentialWeakness.owner_id == current_user.id) | (PotentialWeakness.owner_id == None))  # noqa: E711
    if scan_id is not None:
        q = q.filter(PotentialWeakness.scan_id == scan_id)
    rows = q.order_by(PotentialWeakness.created_at.desc()).limit(100).all()
    return {
        "total": len(rows),
        "category": "C_POTENTIAL_WEAKNESSES",
        "weaknesses": [
            {
                "weakness_id": r.weakness_id,
                "scan_id": r.scan_id,
                "package_name": r.package_name,
                "package_version": r.package_version,
                "title": r.title,
                "weakness_class": r.weakness_class,
                "description": r.description,
                "confidence": r.confidence,
                "confidence_explanation": r.confidence_explanation,
                "limitations": r.limitations,
                "suggested_remediation": r.suggested_remediation,
                "status": r.status,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }


@router.post("/static-analyze")
def static_analyze(
    payload: StaticAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        results = run_static_security_analysis(
            db=db,
            filename=payload.filename,
            source_code=payload.source_code,
            scan_id=payload.scan_id,
            owner_id=current_user.id,
        )
        return {"filename": payload.filename, "findings_count": len(results), "findings": results}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/reassess")
async def reassess_projects(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Reevaluate previously scanned projects of the current user against
    newly synchronized IntelligenceDocuments (idempotent).
    """
    q = db.query(Scan)
    if current_user.role != "admin":
        q = q.filter(Scan.owner_id == current_user.id)
    scans = q.order_by(Scan.timestamp.desc()).limit(20).all()

    docs = db.query(IntelligenceDocument).filter(IntelligenceDocument.is_withdrawn == False).all()  # noqa: E712
    new_matches = 0
    for scan in scans:
        for comp in scan.components:
            comp_norm = comp.name.lower().replace("_", "-")
            for doc in docs:
                pkgs = [p.lower().replace("_", "-") for p in (doc.package_names_json or [])]
                if comp_norm in pkgs:
                    existing = db.query(PackageIntelligenceMatch).filter(
                        PackageIntelligenceMatch.document_id == doc.id,
                        PackageIntelligenceMatch.scan_id == scan.id,
                        PackageIntelligenceMatch.package_name == comp.name,
                    ).first()
                    if not existing:
                        app_status = check_version_applicability(comp.version, doc.affected_ranges_json or [])
                        db.add(PackageIntelligenceMatch(
                            document_id=doc.id,
                            scan_id=scan.id,
                            package_name=comp.name,
                            package_version=comp.version,
                            ecosystem=comp.ecosystem or "PyPI",
                            version_applicable=app_status,
                            match_reason="Automated intelligence reassessment",
                        ))
                        new_matches += 1
    db.commit()
    return {"scans_reassessed": len(scans), "new_intelligence_matches": new_matches}
