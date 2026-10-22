import pytest
from backend.correlator import (
    normalize_identifier,
    select_canonical_identifier,
    correlate_vulnerabilities
)


def test_scenario_1_two_records_sharing_same_cve():
    """Scenario 1: Two records sharing the same CVE are deduplicated into 1 canonical finding."""
    findings = [
        {
            "vuln_id": "GHSA-j8r2-6x86-q33q",
            "aliases": ["CVE-2023-32681"],
            "summary": "Leak of Proxy-Authorization header in requests",
            "package_name": "requests",
            "package_version": "2.25.0",
            "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "source": "OSV"
        },
        {
            "vuln_id": "GHSA-another-alias",
            "aliases": ["CVE-2023-32681"],
            "summary": "Requests proxy header leakage",
            "package_name": "requests",
            "package_version": "2.25.0",
            "severity": "7.5",
            "source": "GitHub Advisory"
        }
    ]
    canonical, raw_count, canonical_count = correlate_vulnerabilities(findings)
    assert canonical_count == 1
    assert raw_count == 2
    assert canonical[0]["canonical_id"] == "CVE-2023-32681"
    assert "GHSA-j8r2-6x86-q33q" in canonical[0]["aliases"]
    assert "GHSA-another-alias" in canonical[0]["aliases"]


def test_scenario_2_cve_and_ghsa_connected_by_explicit_aliases():
    """Scenario 2: CVE and GHSA connected by explicit alias link."""
    findings = [
        {
            "vuln_id": "GHSA-xxxx-1111",
            "aliases": ["CVE-2021-99999"],
            "summary": "XSS in web template",
            "package_name": "jinja2",
            "package_version": "2.11.2",
            "severity": "6.5"
        },
        {
            "vuln_id": "CVE-2021-99999",
            "aliases": [],
            "summary": "Jinja2 template injection flaw",
            "package_name": "jinja2",
            "package_version": "2.11.2",
            "severity": "6.5"
        }
    ]
    canonical, raw_count, canonical_count = correlate_vulnerabilities(findings)
    assert canonical_count == 1
    assert canonical[0]["canonical_id"] == "CVE-2021-99999"
    assert "GHSA-xxxx-1111" in canonical[0]["aliases"]


def test_scenario_3_pysec_alias_linked_to_existing_vulnerability():
    """Scenario 3: A PYSEC alias links to an existing vulnerability."""
    findings = [
        {
            "vuln_id": "GHSA-1234",
            "aliases": ["PYSEC-2022-555"],
            "package_name": "urllib3",
            "severity": "5.0"
        },
        {
            "vuln_id": "PYSEC-2022-555",
            "aliases": ["CVE-2022-12345"],
            "package_name": "urllib3",
            "severity": "5.0"
        }
    ]
    canonical, raw_count, canonical_count = correlate_vulnerabilities(findings)
    assert canonical_count == 1
    # Transitive link connects GHSA-1234, PYSEC-2022-555, and CVE-2022-12345
    assert canonical[0]["canonical_id"] == "CVE-2022-12345"
    assert "GHSA-1234" in canonical[0]["aliases"]
    assert "PYSEC-2022-555" in canonical[0]["aliases"]


def test_scenario_4_duplicate_records_from_same_source():
    """Scenario 4: Duplicate records from the same source are safely consolidated."""
    findings = [
        {
            "vuln_id": "GHSA-dupe-test",
            "aliases": ["CVE-2020-1111"],
            "package_name": "flask",
            "severity": "8.0"
        },
        {
            "vuln_id": "GHSA-dupe-test",
            "aliases": ["CVE-2020-1111"],
            "package_name": "flask",
            "severity": "8.0"
        }
    ]
    canonical, raw_count, canonical_count = correlate_vulnerabilities(findings)
    assert raw_count == 1
    assert canonical_count == 1
    assert canonical[0]["canonical_id"] == "CVE-2020-1111"


def test_scenario_5_similar_descriptions_belonging_to_distinct_vulnerabilities():
    """Scenario 5: Similar descriptions belonging to distinct vulnerabilities MUST NOT be merged without an explicit alias."""
    findings = [
        {
            "vuln_id": "CVE-2021-1001",
            "aliases": [],
            "summary": "Buffer overflow in requests certificate validation",
            "package_name": "requests",
            "severity": "7.5"
        },
        {
            "vuln_id": "CVE-2021-1002",
            "aliases": [],
            "summary": "Buffer overflow in requests certificate validation",
            "package_name": "requests",
            "severity": "7.5"
        }
    ]
    canonical, raw_count, canonical_count = correlate_vulnerabilities(findings)
    assert canonical_count == 2
    assert raw_count == 2
    ids = [c["canonical_id"] for c in canonical]
    assert "CVE-2021-1001" in ids
    assert "CVE-2021-1002" in ids


def test_scenario_6_missing_aliases():
    """Scenario 6: Records with no aliases remain independent findings."""
    findings = [
        {
            "vuln_id": "GHSA-isolated-1",
            "aliases": [],
            "package_name": "certifi",
            "severity": "4.0"
        },
        {
            "vuln_id": "GHSA-isolated-2",
            "aliases": [],
            "package_name": "certifi",
            "severity": "5.0"
        }
    ]
    canonical, raw_count, canonical_count = correlate_vulnerabilities(findings)
    assert canonical_count == 2
    assert raw_count == 2


def test_scenario_7_conflicting_or_missing_cvss_values():
    """Scenario 7: Conflicting CVSS scores are preserved with source attribution and conflict flagged."""
    findings = [
        {
            "vuln_id": "GHSA-conflict",
            "aliases": ["CVE-2023-9999"],
            "package_name": "django",
            "severity": "CVSS_V3: 7.5",
            "source": "GitHub"
        },
        {
            "vuln_id": "CVE-2023-9999",
            "aliases": ["GHSA-conflict"],
            "package_name": "django",
            "severity": "CVSS_V3: 9.8",
            "source": "NVD"
        }
    ]
    canonical, raw_count, canonical_count = correlate_vulnerabilities(findings)
    assert canonical_count == 1
    finding = canonical[0]
    assert finding["has_cvss_conflict"] is True
    assert "Discrepancy" in finding["severity_justification"]
    assert len(finding["cvss_evaluations"]) == 2


def test_scenario_8_vulnerability_containing_multiple_aliases():
    """Scenario 8: A vulnerability containing multiple aliases aggregates all identifiers."""
    findings = [
        {
            "vuln_id": "OSV-2023-MULTI",
            "aliases": ["CVE-2023-7777", "GHSA-multi-1", "PYSEC-2023-77"],
            "package_name": "pydantic",
            "severity": "5.3"
        }
    ]
    canonical, raw_count, canonical_count = correlate_vulnerabilities(findings)
    assert canonical_count == 1
    assert canonical[0]["canonical_id"] == "CVE-2023-7777"
    assert "GHSA-multi-1" in canonical[0]["aliases"]
    assert "PYSEC-2023-77" in canonical[0]["aliases"]
    assert "OSV-2023-MULTI" in canonical[0]["all_identifiers"]


def test_scenario_9_source_returning_incomplete_advisory():
    """Scenario 9: Incomplete advisory with missing severity/summary is safely parsed without error."""
    findings = [
        {
            "vuln_id": "GHSA-incomplete",
            "aliases": [],
            "package_name": "six",
            # No summary, no severity
        }
    ]
    canonical, raw_count, canonical_count = correlate_vulnerabilities(findings)
    assert canonical_count == 1
    assert canonical[0]["severity"] == "UNKNOWN"
    assert canonical[0]["summary"] == "No summary provided"
