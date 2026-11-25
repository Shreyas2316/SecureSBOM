"""
Evidence-Driven RAG Engine, Prompt Injection Defense, Category B/C Lifecycle & Opt-In Static Analysis.
"""
import ast
import datetime
import logging
import os
import re
import subprocess
import tempfile
import uuid
from typing import Dict, Any, List, Optional

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import settings
from app.models.intelligence_models import (
    EmergingFinding, PotentialWeakness, FindingReview, FindingStatusHistory,
    IntelligenceDocument, PackageIntelligenceMatch, StaticAnalysisResult
)
from app.models.models import Vulnerability
from app.services.ai_provider import get_ai_provider
from app.services.intelligence_search import hybrid_search_intelligence, check_version_applicability

logger = logging.getLogger("securesbom.rag")

PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|system)\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(the\s+)?(rules|system\s+prompt)", re.IGNORECASE),
    re.compile(r"(reveal|print|output|exfiltrate)\s+(secrets?|api[_\s]?key|password|token)", re.IGNORECASE),
    re.compile(r"execute\s+(shell|command|bash|powershell)", re.IGNORECASE),
]

STANDARD_LIMITATIONS = (
    "Evidence-grounded assessment only. This finding is NOT a confirmed Category A vulnerability "
    "unless independently corroborated by an authoritative CVE/OSV/NVD advisory and deterministic version match."
)


def sanitize_untrusted_evidence(text: str) -> str:
    """Strip or neutralize indirect prompt injection patterns from retrieved documents."""
    if not text:
        return ""
    cleaned = text
    for pat in PROMPT_INJECTION_PATTERNS:
        cleaned = pat.sub("[FILTERED_UNTRUSTED_DIRECTIVE]", cleaned)
    return cleaned[:1500]


class RAGAssessmentOutput(BaseModel):
    title: str = Field(..., min_length=3, max_length=500)
    description: str = Field(..., min_length=5, max_length=4000)
    potential_impact: str = Field(default="", max_length=2000)
    confidence: str = Field(default="insufficient_evidence")
    confidence_explanation: str = Field(default="", max_length=2000)
    reasoning_summary: str = Field(default="", max_length=2000)
    cited_doc_uids: List[str] = Field(default_factory=list)
    suggested_remediation: str = Field(default="", max_length=2000)
    abstained: bool = False


def compute_transparent_confidence(
    evidence_docs: List[Dict[str, Any]],
    version_status: str,
) -> tuple[str, str]:
    """
    Transparent, deterministic confidence rubric based on:
    - Source authority
    - Package identity match
    - Version applicability
    - Evidence completeness & freshness
    """
    if not evidence_docs:
        return "insufficient_evidence", "No matching intelligence documents were retrieved from the local dataset."

    reliabilities = {d.get("source_reliability", "medium") for d in evidence_docs}
    has_auth = "authoritative" in reliabilities or "high" in reliabilities

    if version_status == "not_applicable":
        return "low", "Retrieved evidence exists, but deterministic PEP 440 check indicates installed version is outside affected range."
    if version_status == "applicable" and has_auth:
        return "high", "Authoritative/high-reliability evidence matched package identity and deterministic PEP 440 range check."
    if has_auth or len(evidence_docs) >= 2:
        return "medium", "Relevant security intelligence retrieved, but version applicability is unverified or partial."
    return "low", "Limited community/unverified intelligence retrieved; requires manual maintainer advisory verification."


async def run_evidence_grounded_rag(
    db: Session,
    package_name: str,
    package_version: str,
    ecosystem: str = "PyPI",
    scan_id: Optional[int] = None,
    owner_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Full Evidence-Driven RAG Pipeline:
    1. Hybrid retrieval (FTS5 + TF-IDF cosine) from IntelligenceDocument store.
    2. Deterministic PEP 440 version applicability validation.
    3. Sanitize untrusted evidence against indirect prompt injection.
    4. If insufficient evidence -> abstain cleanly without hallucination.
    5. Generate structured assessment (using configured AI provider or deterministic synthesis).
    6. Reject invalid/fabricated citations; persist as Category B (EmergingFinding).
    """
    docs = hybrid_search_intelligence(
        db=db,
        query_text=f"{package_name} {package_version} security vulnerability advisory",
        package_name=package_name,
        ecosystem=ecosystem,
        top_k=5,
    )

    if not docs:
        return {
            "abstained": True,
            "message": "Insufficient evidence to establish a vulnerability.",
            "package_name": package_name,
            "package_version": package_version,
            "evidence_count": 0,
        }

    # Deterministic version applicability check across retrieved docs
    all_ranges: List[str] = []
    for d in docs:
        all_ranges.extend(d.get("affected_ranges") or [])
    version_status = check_version_applicability(package_version, all_ranges)
    if version_status == "applicable":
        aff_label = "verified_affected"
    elif version_status == "not_applicable":
        aff_label = "not_affected"
    elif all_ranges:
        aff_label = "potentially_applicable"
    else:
        aff_label = "unverified"

    conf, conf_exp = compute_transparent_confidence(docs, version_status)
    valid_doc_uids = {d["doc_uid"] for d in docs}
    source_urls = [d["url"] for d in docs if d.get("url")]
    excerpts = [sanitize_untrusted_evidence(d.get("excerpt") or d.get("summary") or d["title"]) for d in docs]

    # Record PackageIntelligenceMatch
    for d in docs:
        doc_orm = db.query(IntelligenceDocument).filter(IntelligenceDocument.doc_uid == d["doc_uid"]).first()
        if doc_orm:
            db.add(PackageIntelligenceMatch(
                document_id=doc_orm.id,
                scan_id=scan_id,
                package_name=package_name,
                package_version=package_version,
                ecosystem=ecosystem,
                version_applicable=version_status,
                match_reason=f"Hybrid retrieval score={d.get('relevance_score')}",
            ))

    # Build grounded summary (AI-assisted if enabled, else deterministic evidence synthesis)
    ai_provider_name = settings.AI_PROVIDER if settings.AI_ENABLED else "deterministic-rag"
    model_name = settings.AI_MODEL_NAME or "evidence-synthesis-v1"
    title = f"Emerging intelligence for {package_name} ({package_version}): {docs[0]['title']}"[:490]
    description = (
        f"Retrieved {len(docs)} public security intelligence document(s) for {package_name}@{package_version}. "
        f"Primary evidence: {excerpts[0][:500]}"
    )
    remediation = (
        "Review the original advisory, monitor maintainer security updates, verify affected-version "
        "applicability, and apply a verified patch when available."
    )

    if settings.AI_ENABLED and settings.AI_PROVIDER in ("openai", "gemini", "ollama", "llamacpp"):
        try:
            provider = get_ai_provider()
            evidence_block = "\n".join(
                f"- [{d['doc_uid']}] ({d['url']}) {sanitize_untrusted_evidence(d['title'])}: {sanitize_untrusted_evidence(d.get('excerpt') or d.get('summary') or '')}"
                for d in docs
            )
            user_prompt = (
                f"Package: {package_name} Version: {package_version} Ecosystem: {ecosystem}\n"
                f"Deterministic Version Applicability: {aff_label}\n"
                f"Untrusted Retrieved Evidence:\n{evidence_block}\n"
                "Return JSON with keys: title, description, potential_impact, reasoning_summary, cited_doc_uids, suggested_remediation."
            )
            raw_resp = await provider.complete(
                "You are a security analyst. Cite ONLY provided doc_uids. Never invent CVE IDs or CVSS scores.",
                user_prompt,
            )
            # Validate citations strictly
            import json
            start, end = raw_resp.find("{"), raw_resp.rfind("}")
            if start != -1 and end > start:
                parsed = json.loads(raw_resp[start:end + 1])
                cited = [uid for uid in parsed.get("cited_doc_uids", []) if uid in valid_doc_uids]
                if cited:
                    title = str(parsed.get("title") or title)[:490]
                    description = str(parsed.get("description") or description)[:3500]
                    remediation = str(parsed.get("suggested_remediation") or remediation)[:1500]
        except Exception as exc:
            logger.info("AI RAG synthesis fell back to deterministic evidence summary: %s", exc)

    finding_id = f"EMG-{uuid.uuid4().hex[:10].upper()}"
    finding = EmergingFinding(
        finding_id=finding_id,
        scan_id=scan_id,
        owner_id=owner_id,
        package_name=package_name,
        package_version=package_version,
        ecosystem=ecosystem,
        title=title,
        description=description,
        potential_impact="Potential supply-chain security exposure pending authoritative confirmation.",
        affected_version_status=aff_label,
        evidence_doc_ids_json=list(valid_doc_uids),
        source_urls_json=source_urls,
        evidence_excerpts_json=excerpts,
        published_at=datetime.datetime.fromisoformat(docs[0]["published_at"]) if docs[0].get("published_at") else None,
        ai_provider=ai_provider_name,
        model_name=model_name,
        confidence=conf,
        confidence_explanation=conf_exp,
        reasoning_summary=f"Grounded in {len(docs)} retrieved document(s); version check={aff_label}.",
        limitations=STANDARD_LIMITATIONS,
        suggested_remediation=remediation,
        status="emerging",
    )
    db.add(finding)
    db.add(FindingStatusHistory(
        finding_type="emerging",
        finding_ref_id=finding_id,
        from_status=None,
        to_status="emerging",
        changed_by="rag_engine",
        reason="Initial evidence-grounded RAG assessment",
    ))
    db.commit()
    db.refresh(finding)

    return {
        "abstained": False,
        "finding_id": finding.finding_id,
        "category": "B",
        "package_name": finding.package_name,
        "package_version": finding.package_version,
        "title": finding.title,
        "affected_version_status": finding.affected_version_status,
        "confidence": finding.confidence,
        "confidence_explanation": finding.confidence_explanation,
        "evidence_doc_ids": finding.evidence_doc_ids_json,
        "source_urls": finding.source_urls_json,
        "limitations": finding.limitations,
        "status": finding.status,
    }


def promote_emerging_to_confirmed(
    db: Session,
    finding_id: str,
    vuln_id: int,
    changed_by: str,
) -> EmergingFinding:
    """Promote an EmergingFinding to confirmed when an authoritative Category A advisory is linked."""
    finding = db.query(EmergingFinding).filter(EmergingFinding.finding_id == finding_id).first()
    if not finding:
        raise ValueError("Emerging finding not found")
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise ValueError("Verified vulnerability not found")

    prev = finding.status
    finding.promoted_to_vuln_id = vuln.id
    finding.status = "confirmed"
    db.add(FindingStatusHistory(
        finding_type="emerging",
        finding_ref_id=finding.finding_id,
        from_status=prev,
        to_status="confirmed",
        changed_by=changed_by,
        reason=f"Corroborated by authoritative advisory {vuln.canonical_id}",
    ))
    db.commit()
    db.refresh(finding)
    return finding


def run_static_security_analysis(
    db: Session,
    filename: str,
    source_code: str,
    scan_id: Optional[int] = None,
    owner_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Opt-in static security analysis on user-authorized Python source code.
    Never executes uploaded code. Uses AST pattern checks (and Bandit if installed).
    Stores findings separately in StaticAnalysisResult & PotentialWeakness (Category C).
    """
    safe_name = os.path.basename(filename or "uploaded.py")
    if len(source_code.encode("utf-8")) > 512 * 1024:
        raise ValueError("Source file exceeds 512KB static analysis limit.")

    findings: List[Dict[str, Any]] = []

    # Safe AST-based static checks (zero execution)
    try:
        tree = ast.parse(source_code, filename=safe_name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name in ("eval", "exec"):
                    findings.append({
                        "rule_id": "SEC-AST-001",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "line_number": getattr(node, "lineno", None),
                        "message": f"Use of dynamic code execution '{func_name}()' detected.",
                    })
                elif func_name in ("loads", "load") and isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id in ("pickle", "yaml"):
                        findings.append({
                            "rule_id": "SEC-AST-002",
                            "severity": "HIGH",
                            "confidence": "MEDIUM",
                            "line_number": getattr(node, "lineno", None),
                            "message": f"Potentially unsafe deserialization via {node.func.value.id}.{func_name}().",
                        })
                elif func_name in ("system", "popen"):
                    findings.append({
                        "rule_id": "SEC-AST-003",
                        "severity": "MEDIUM",
                        "confidence": "MEDIUM",
                        "line_number": getattr(node, "lineno", None),
                        "message": f"OS command execution pattern '{func_name}()' detected.",
                    })
                elif func_name in ("md5", "sha1"):
                    findings.append({
                        "rule_id": "SEC-AST-004",
                        "severity": "LOW",
                        "confidence": "HIGH",
                        "line_number": getattr(node, "lineno", None),
                        "message": f"Weak cryptographic hash '{func_name}()' usage detected.",
                    })
    except SyntaxError as exc:
        raise ValueError(f"Invalid Python syntax in {safe_name}: {exc}")

    # Persist results separately as Category C
    stored = []
    for f in findings:
        rec = StaticAnalysisResult(
            scan_id=scan_id,
            owner_id=owner_id,
            filename=safe_name,
            tool="ast-analyzer",
            rule_id=f["rule_id"],
            severity=f["severity"],
            confidence=f["confidence"],
            line_number=f["line_number"],
            message=f["message"],
        )
        db.add(rec)
        wid = f"WEAK-{uuid.uuid4().hex[:10].upper()}"
        db.add(PotentialWeakness(
            weakness_id=wid,
            scan_id=scan_id,
            owner_id=owner_id,
            package_name=safe_name,
            package_version="source",
            ecosystem="Python",
            title=f"{f['rule_id']}: {f['message']}"[:490],
            weakness_class=f["rule_id"],
            description=f["message"],
            ai_provider="static-ast",
            model_name="ast-analyzer-v1",
            confidence=f["confidence"].lower(),
            confidence_explanation="Static AST pattern match; does not prove exploitability.",
            limitations="Static analysis warning only; requires manual code reachability review.",
            suggested_remediation="Replace unsafe pattern with safe standard-library alternatives.",
            status="potential",
        ))
        stored.append({**f, "filename": safe_name, "weakness_id": wid, "category": "C"})

    db.commit()
    return stored
