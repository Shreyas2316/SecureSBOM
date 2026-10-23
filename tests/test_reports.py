import json
import io
import pytest
from app.services.report_service import (
    generate_json_report, generate_csv_report, generate_pdf_report
)


@pytest.fixture
def sample_scan_data():
    return {
        "summary": {
            "scan_id": 99,
            "project_name": "Compliance Project",
            "timestamp": "2026-10-22T00:00:00Z",
            "total_deps": 5,
            "direct_deps": 3,
            "transitive_deps": 2,
            "unique_vuln_count": 1,
            "advisory_record_count": 2,
            "affected_components_count": 1,
            "critical_count": 1,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "unknown_count": 0,
            "scan_duration_seconds": 1.25,
        },
        "components": [
            {"name": "requests", "version": "2.25.0", "ecosystem": "PyPI", "is_direct": True, "purl": "pkg:pypi/requests@2.25.0"},
            {"name": "urllib3", "version": "1.26.4", "ecosystem": "PyPI", "is_direct": False, "purl": "pkg:pypi/urllib3@1.26.4"},
        ],
        "vulnerabilities": [
            {
                "canonical_id": "CAN-TEST-1234",
                "cve_id": "CVE-2023-32681",
                "aliases": ["GHSA-j8r2-6x86-q33q"],
                "sources": ["OSV", "NVD"],
                "summary": "Requests Session object does not verify proxy URLs strictly in certain configurations.",
                "details": "A detailed technical breakdown of the issue spanning multiple lines for test verification.",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "severity": "HIGH",
                "priority_tier": 2,
                "affected_component_name": "requests",
                "affected_component_version": "2.25.0",
                "fixed_version": "2.31.0",
                "affected_range": "<2.31.0",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-32681"],
            }
        ]
    }


@pytest.fixture
def sample_ai_findings():
    return [
        {
            "finding_id": "AI-TEST-9001",
            "package_name": "requests",
            "package_version": "2.25.0",
            "ecosystem": "PyPI",
            "title": "Unpinned sub-dependency certificate validation inquiry",
            "description": "Suspicious interaction between urllib3 and custom transport adapters.",
            "assessment_type": "emerging_advisory_analysis",
            "evidence": ["Custom SSLContext instantiation without hostname verification flags"],
            "evidence_sources": ["Source static inspection"],
            "potential_impact": "Potential Man-In-The-Middle condition if untrusted proxies are configured",
            "confidence": "medium",
            "confidence_explanation": "Inferred from configuration patterns",
            "verification_steps": ["Check verify=True parameter in session requests"],
            "suggested_mitigations": ["Enforce certifi CA bundle and upgrade requests to 2.31.0"],
            "related_advisory_ids": [],
            "model_name": "mock-security-llm",
            "created_at": "2026-10-22T01:00:00Z",
            "status": "needs_verification",
            "limitations": "AI-generated assessment. Not an authoritative vulnerability.",
        }
    ]


@pytest.fixture
def sample_alternatives():
    return [
        {
            "package_name": "requests",
            "package_version": "2.25.0",
            "recommendation_type": "version_upgrade",
            "label": "Recommended fixed version",
            "recommended_version": "2.31.0",
            "compatibility_info": "Same major version upgrade. Lower compatibility risk.",
            "migration_complexity": "low",
            "rationale": "Directly resolves CVE-2023-32681 with minimal breaking changes.",
            "verification_status": "verified_available",
        }
    ]


def test_generate_json_report_separation(sample_scan_data, sample_ai_findings, sample_alternatives):
    """Test that JSON report retains strict separation between verified findings and AI findings."""
    raw_bytes = generate_json_report(sample_scan_data, sample_ai_findings, sample_alternatives, "REP-UNIT-01")
    report = json.loads(raw_bytes.decode("utf-8"))

    assert report["report_id"] == "REP-UNIT-01"
    assert "disclaimer" in report
    assert "verified_findings" in report
    assert "ai_findings" in report
    assert "safer_alternatives" in report

    # Verified findings must contain CAN-TEST-1234
    verified = report["verified_findings"]
    assert verified["count"] == 1
    assert verified["findings"][0]["canonical_id"] == "CAN-TEST-1234"

    # AI findings must be in separate key and NOT mixed with verified findings
    ai = report["ai_findings"]
    assert ai["count"] == 1
    assert ai["findings"][0]["finding_id"] == "AI-TEST-9001"
    assert "AI-generated assessment" in ai["note"]


def test_generate_csv_report_sections(sample_scan_data, sample_ai_findings):
    csv_bytes = generate_csv_report(sample_scan_data, sample_ai_findings)
    text = csv_bytes.decode("utf-8")

    # Must contain both distinct section headers
    assert "SECTION A: VERIFIED VULNERABILITY FINDINGS" in text
    assert "SECTION B: AI-ASSESSED EMERGING VULNERABILITIES" in text
    assert "CAN-TEST-1234" in text
    assert "AI-TEST-9001" in text


def test_generate_pdf_report_bytes(sample_scan_data, sample_ai_findings, sample_alternatives):
    pdf_bytes = generate_pdf_report(sample_scan_data, sample_ai_findings, sample_alternatives, "REP-PDF-01")
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    # Valid PDF magic bytes
    assert pdf_bytes[:4] == b"%PDF"
