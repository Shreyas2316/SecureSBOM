import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient

from app.services.ai_analysis import (
    validate_ai_output, extract_json_from_response, FORBIDDEN_CLAIMS
)
from app.services.ai_provider import (
    MockAIProvider, AIProviderTimeout, AIProviderRateLimit, AIProviderError
)
from app.main import app
from app.database import get_db, SessionLocal
from app.models import (
    AIFinding, AIFindingReview, AIAssessmentStatus
)

client = TestClient(app)


def test_valid_ai_output_validation():
    raw = {
        "title": "Potential timing side-channel in authentication handler",
        "description": "Evidence indicates comparison of secrets using non-constant time operations.",
        "assessment_type": "emerging_advisory_analysis",
        "evidence": ["Comparison uses == operator on token strings"],
        "evidence_sources": ["PyPI metadata changelog 2.1.0"],
        "potential_impact": "Information disclosure of token lengths or prefixes",
        "confidence": "medium",
        "confidence_explanation": "Based on changelog note and standard comparison patterns",
        "verification_steps": ["Inspect auth.py verify_token function"],
        "suggested_mitigations": ["Use hmac.compare_digest for secret comparisons"],
        "related_advisory_ids": ["GHSA-xxxx-yyyy"],
        "limitations": "Static inspection only, no dynamic execution performed"
    }
    validated = validate_ai_output(raw, evidence_advisory_ids=["GHSA-xxxx-yyyy"])
    assert validated["title"] == raw["title"]
    assert validated["confidence"] == "medium"
    assert validated["assessment_type"] == "emerging_advisory_analysis"
    assert "GHSA-xxxx-yyyy" in validated["related_advisory_ids"]


def test_malformed_ai_output_missing_field():
    raw = {
        "title": "Incomplete output",
        # missing description and other required fields
    }
    with pytest.raises(ValueError, match="missing required field"):
        validate_ai_output(raw, evidence_advisory_ids=[])


def test_unsupported_vulnerability_identifiers_filtered():
    """Invented CVE IDs not in the evidence must be stripped out."""
    raw = {
        "title": "Speculative advisory",
        "description": "Model hallucinated a CVE ID",
        "assessment_type": "potential_weakness_analysis",
        "evidence": ["No source code available"],
        "evidence_sources": ["Model inference"],
        "potential_impact": "Unknown",
        "confidence": "insufficient_evidence",
        "confidence_explanation": "Insufficient technical evidence",
        "verification_steps": ["Review package source"],
        "suggested_mitigations": ["Keep dependency updated"],
        "related_advisory_ids": ["CVE-9999-99999"],  # Invented CVE not in evidence
        "limitations": "Unverified model claim"
    }
    validated = validate_ai_output(raw, evidence_advisory_ids=["CVE-2023-1234"])
    # CVE-9999-99999 must NOT be present because it wasn't in evidence
    assert "CVE-9999-99999" not in validated["related_advisory_ids"]


def test_extract_json_from_markdown_code_fences():
    fenced_text = """```json
    {
        "title": "Parsed from fence",
        "status": "ok"
    }
    ```"""
    data = extract_json_from_response(fenced_text)
    assert data["title"] == "Parsed from fence"
    assert data["status"] == "ok"


def test_mock_ai_provider_behavior():
    provider = MockAIProvider()
    assert provider.model_name == "mock-security-llm"
    assert provider.is_available is True

    # Test error handling types
    with pytest.raises(AIProviderTimeout):
        raise AIProviderTimeout("Provider timed out after 30s")

    with pytest.raises(AIProviderRateLimit):
        raise AIProviderRateLimit("Rate limit exceeded; retry after 60s")


def test_ai_status_endpoint():
    res = client.get("/api/v1/ai/status")
    assert res.status_code == 200
    data = res.json()
    assert "ai_enabled" in data
    assert "provider" in data
    # Credentials must NOT be exposed
    assert "api_key" not in data
    assert "secret" not in data


def test_ai_findings_separation_from_confirmed_vulns():
    """Category B (AIFinding) records must be queried and stored independently of Category A."""
    res = client.get("/api/v1/ai/findings")
    assert res.status_code == 200
    data = res.json()
    assert "findings" in data
    assert "total" in data
    assert "note" in data
    assert "separate from verified vulnerability findings" in data["note"].lower()


def test_ai_dashboard_summary_separate_counts():
    res = client.get("/api/v1/ai/dashboard")
    assert res.status_code == 200
    data = res.json()
    assert "total_ai_assessments" in data
    assert "new_awaiting_review" in data
    assert "needs_verification" in data
    assert "under_investigation" in data
    assert "corroborated_by_advisory" in data
    assert "rejected" in data
    assert "note" in data
    assert "SEPARATE" in data["note"]


def test_review_history_retention_on_rejection():
    """Rejecting an AI finding must not delete the finding, and must record review audit history."""
    db = SessionLocal()
    try:
        # Create a test AI finding
        import uuid
        test_id = f"AI-TEST-{uuid.uuid4().hex[:6]}"
        finding = AIFinding(
            finding_id=test_id,
            package_name="test-package",
            package_version="1.0.0",
            ecosystem="PyPI",
            title="Test Finding For Audit",
            description="Audit history test",
            assessment_type="potential_weakness_analysis",
            evidence_json=["test evidence"],
            evidence_sources_json=["manual test"],
            potential_impact="Low",
            confidence="low",
            confidence_explanation="Testing",
            verification_steps_json=["step 1"],
            suggested_mitigations_json=["mitigation 1"],
            related_advisory_ids_json=[],
            model_name="mock",
            analysis_method="mock",
            status="new_ai_assessment",
            limitations="Testing only",
        )
        db.add(finding)
        db.commit()

        # Review and reject finding
        res = client.patch(
            f"/api/v1/ai/findings/{test_id}/review",
            json={
                "action": "rejected_after_review",
                "notes": "Reviewed and concluded this is a false positive based on source code analysis.",
                "reason": "Not reproducible in current version"
            },
            headers={"X-User-Id": "security_auditor"}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["new_status"] == "rejected_after_review"
        assert data["reviewer_id"] == "security_auditor"

        # Verify record is STILL present in database (not deleted)
        finding_check = db.query(AIFinding).filter(AIFinding.finding_id == test_id).first()
        assert finding_check is not None
        assert finding_check.status == "rejected_after_review"

        # Verify audit history is preserved
        reviews = db.query(AIFindingReview).filter(AIFindingReview.finding_id_ref == finding_check.id).all()
        assert len(reviews) >= 1
        assert reviews[0].action == "rejected_after_review"
        assert reviews[0].reviewer_id == "security_auditor"
    finally:
        db.close()
