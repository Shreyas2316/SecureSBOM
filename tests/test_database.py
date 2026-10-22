import pytest
from backend.database import (
    save_scan_record,
    get_scan_records,
    get_scan_by_id,
    get_scan_bom_by_id
)


def test_database_crud():
    scan_id = "test-scan-uuid-12345"
    manifest_name = "test_requirements.txt"
    report_data = {
        "scan_id": scan_id,
        "manifest_name": manifest_name,
        "summary": {
            "total_scanned": 5,
            "total_direct_deps": 3,
            "total_transitive_deps": 2,
            "total_raw_advisories": 4,
            "total_canonical_vulnerabilities": 2,
            "vulnerable_components_count": 2,
            "vulnerabilities_by_severity": {
                "CRITICAL": 1,
                "HIGH": 1
            }
        },
        "cyclonedx_valid": True
    }
    bom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": []
    }

    # 1. Save
    record = save_scan_record(
        scan_id=scan_id,
        manifest_name=manifest_name,
        report_data=report_data,
        bom_data=bom_data,
        user_id="test_user"
    )
    assert record.id == scan_id
    assert record.canonical_vulns_count == 2
    assert record.critical_count == 1

    # 2. Get list
    scans = get_scan_records(user_id="test_user")
    ids = [s["id"] for s in scans]
    assert scan_id in ids

    # 3. Get by ID
    loaded_report = get_scan_by_id(scan_id, user_id="test_user")
    assert loaded_report is not None
    assert loaded_report["scan_id"] == scan_id

    # 4. Get SBOM by ID
    loaded_bom = get_scan_bom_by_id(scan_id, user_id="test_user")
    assert loaded_bom is not None
    assert loaded_bom["bomFormat"] == "CycloneDX"

    # 5. Isolation: different user cannot read
    other_user_report = get_scan_by_id(scan_id, user_id="unauthorized_user")
    assert other_user_report is None
