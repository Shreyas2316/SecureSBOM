import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.correlation_service import correlate_vulnerabilities, pick_canonical_id
from app.services.prioritization import determine_priority_from_severity, resolve_canonical_severity
from app.services.osv_service import extract_remediation_info, clean_summary_and_details, OSV_CACHE

@pytest.fixture(autouse=True)
def clear_cache():
    OSV_CACHE.clear()
    yield
    OSV_CACHE.clear()

def test_pick_canonical_id_order():
    # Prefer CVE over GHSA/PYSEC/OSV
    assert pick_canonical_id({"GHSA-123", "CVE-2024-9999", "PYSEC-456"}) == "CVE-2024-9999"
    # Prefer GHSA over PYSEC/OSV when no CVE
    assert pick_canonical_id({"GHSA-123", "PYSEC-456", "OSV-789"}) == "GHSA-123"
    # Prefer PYSEC over OSV when no CVE/GHSA
    assert pick_canonical_id({"PYSEC-456", "OSV-789"}) == "PYSEC-456"

@pytest.mark.asyncio
async def test_deduplication_cve_ghsa_pysec_single_vuln():
    """Fix 15.1, 15.2, 15.3, 15.10: CVE+GHSA+PYSEC alias graph produces 1 unique vuln retaining all aliases."""
    raw_osv_hits = [
        {
            "id": "GHSA-9hjg-9r4m-mvj7",
            "summary": "Requests credential leak",
            "aliases": ["CVE-2024-47081", "PYSEC-2026-1872"],
            "database_specific": {"severity": "HIGH"}
        },
        {
            "id": "PYSEC-2026-1872",
            "summary": "Requests credential leak advisory",
            "aliases": ["CVE-2024-47081", "GHSA-9hjg-9r4m-mvj7"],
            "database_specific": {"severity": "UNKNOWN"}
        }
    ]

    components = [{"name": "requests", "normalized_name": "requests", "version": "2.25.1", "is_direct": True}]

    with patch("app.services.correlation_service.query_osv_for_package", AsyncMock(return_value=raw_osv_hits)), \
         patch("app.services.correlation_service.enrich_vulnerability_with_nvd", AsyncMock(return_value=None)):

        result = await correlate_vulnerabilities(components)
        vulns = result["canonical_vulnerabilities"]
        metrics = result["metrics"]

        assert len(vulns) == 1
        v = vulns[0]
        assert v["canonical_id"] == "CVE-2024-47081"
        assert "GHSA-9hjg-9r4m-mvj7" in v["aliases"]
        assert "PYSEC-2026-1872" in v["aliases"]
        assert metrics["unique_vuln_count"] == 1
        assert metrics["advisory_record_count"] == 2
        assert metrics["advisory_record_count"] > metrics["unique_vuln_count"]

@pytest.mark.asyncio
async def test_distinct_cves_same_package_not_overmerged():
    """Fix 15.4: Two distinct CVEs on the same package stay as 2 unique vulnerabilities."""
    raw_osv_hits = [
        {
            "id": "GHSA-1111",
            "summary": "Vuln A",
            "aliases": ["CVE-2024-0001"],
            "database_specific": {"severity": "HIGH"}
        },
        {
            "id": "GHSA-2222",
            "summary": "Vuln B",
            "aliases": ["CVE-2024-0002"],
            "database_specific": {"severity": "MEDIUM"}
        }
    ]

    components = [{"name": "urllib3", "normalized_name": "urllib3", "version": "1.26.4", "is_direct": True}]

    with patch("app.services.correlation_service.query_osv_for_package", AsyncMock(return_value=raw_osv_hits)), \
         patch("app.services.correlation_service.enrich_vulnerability_with_nvd", AsyncMock(return_value=None)):

        result = await correlate_vulnerabilities(components)
        vulns = result["canonical_vulnerabilities"]
        metrics = result["metrics"]

        assert len(vulns) == 2
        ids = [v["canonical_id"] for v in vulns]
        assert "CVE-2024-0001" in ids
        assert "CVE-2024-0002" in ids
        assert metrics["unique_vuln_count"] == 2
        assert metrics["advisory_record_count"] == 2

@pytest.mark.asyncio
async def test_overmerge_guard_no_shared_identifiers():
    """Fix 15.17: Same package/version, two records without shared identifiers → NOT merged."""
    raw_osv_hits = [
        {
            "id": "GHSA-aaaa-1111",
            "summary": "Advisory 1",
            "aliases": ["CVE-2021-1111"],
        },
        {
            "id": "GHSA-bbbb-2222",
            "summary": "Advisory 2",
            "aliases": ["CVE-2021-2222"],
        }
    ]

    components = [{"name": "flask", "normalized_name": "flask", "version": "1.1.2", "is_direct": True}]

    with patch("app.services.correlation_service.query_osv_for_package", AsyncMock(return_value=raw_osv_hits)), \
         patch("app.services.correlation_service.enrich_vulnerability_with_nvd", AsyncMock(return_value=None)):

        result = await correlate_vulnerabilities(components)
        vulns = result["canonical_vulnerabilities"]
        assert len(vulns) == 2

def test_severity_resolution_nvd_high_osv_unknown():
    """Fix 15.5: NVD=HIGH, OSV=UNKNOWN → resolved severity = HIGH."""
    sources = [
        {"source": "OSV", "severity": "UNKNOWN", "cvss_score": None},
        {"source": "NVD", "severity": "HIGH", "cvss_score": 7.5}
    ]
    sev, cvss, vector, priority = resolve_canonical_severity(sources)
    assert sev == "HIGH"
    assert cvss == 7.5
    assert priority == "P2-High"

def test_severity_resolution_no_severity_anywhere():
    """Fix 15.6 & 15.7: No severity anywhere → UNKNOWN and priority P-Unknown."""
    sources = [
        {"source": "OSV", "severity": "UNKNOWN", "cvss_score": None}
    ]
    sev, cvss, vector, priority = resolve_canonical_severity(sources)
    assert sev == "UNKNOWN"
    assert cvss is None
    assert priority == "P-Unknown"
    assert priority != "P5-Info"

def test_explicit_info_from_source():
    """Fix 15.8: Explicit INFO from source → INFO / P5-Info."""
    sources = [
        {"source": "OSV", "severity": "INFO", "cvss_score": None}
    ]
    sev, cvss, vector, priority = resolve_canonical_severity(sources)
    assert sev == "INFO"
    assert priority == "P5-Info"

def test_generic_package_description_filtered():
    """Fix 15.9: Generic package blurb is not surfaced as vulnerability summary."""
    raw = {
        "summary": "Jinja2 is a user-friendly and powerful template engine for Python.",
        "details": "Jinja2 is a user-friendly and powerful template engine for Python."
    }
    summary, details = clean_summary_and_details(raw, "jinja2")
    assert "user-friendly" not in summary
    assert summary == "Security advisory for component"

def test_fixed_version_extraction():
    """Fix 15.13 & 15.14: Fixed version extracted from OSV events; no fabrication when absent."""
    raw_with_fix = {
        "affected": [
            {
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.32.4"}]
                    }
                ]
            }
        ]
    }
    aff_r, fix_v = extract_remediation_info(raw_with_fix)
    assert fix_v == "2.32.4"
    assert aff_r == ">=0, <2.32.4"

    raw_no_fix = {"affected": []}
    aff_r2, fix_v2 = extract_remediation_info(raw_no_fix)
    assert fix_v2 is None
    assert aff_r2 is None

@pytest.mark.asyncio
async def test_affected_components_count_calculation():
    """Fix 15.11 & 15.12: Affected components count distinct packages and transitive vulns appear."""
    raw_hits_pkg1 = [{"id": "CVE-2024-9001", "aliases": []}]
    raw_hits_pkg2 = [{"id": "CVE-2024-9002", "aliases": []}]
    
    async def mock_query(client, name, ver):
        if name == "requests":
            return raw_hits_pkg1
        elif name == "urllib3":
            return raw_hits_pkg2
        return []

    components = [
        {"name": "requests", "normalized_name": "requests", "version": "2.25.1", "is_direct": True},
        {"name": "urllib3", "normalized_name": "urllib3", "version": "1.26.4", "is_direct": False, "dependency_depth": 1},
        {"name": "clean-pkg", "normalized_name": "clean-pkg", "version": "1.0.0", "is_direct": False}
    ]

    with patch("app.services.correlation_service.query_osv_for_package", AsyncMock(side_effect=mock_query)), \
         patch("app.services.correlation_service.enrich_vulnerability_with_nvd", AsyncMock(return_value=None)):

        result = await correlate_vulnerabilities(components)
        vulns = result["canonical_vulnerabilities"]
        metrics = result["metrics"]

        assert len(vulns) == 2
        assert metrics["unique_vuln_count"] == 2
        assert metrics["affected_components_count"] == 2  # requests and urllib3
        # Check transitive vulnerability appears
        transitive_vulns = [v for v in vulns if not v["is_direct"]]
        assert len(transitive_vulns) == 1
        assert transitive_vulns[0]["affected_component_name"] == "urllib3"
