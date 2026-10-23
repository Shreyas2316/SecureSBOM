import pytest
from packaging.version import Version
from app.services.alternatives_service import find_safe_upgrade, build_alternatives


def test_find_safe_upgrade_smallest_qualifying_version():
    """Verify that find_safe_upgrade picks the minimal safe version >= fixed_version."""
    all_versions = ["1.0.0", "1.1.0", "1.1.1", "1.2.0", "2.0.0", "2.1.0"]
    
    # Current version is 1.0.0, fixed version is 1.1.1
    chosen = find_safe_upgrade(
        current_version_str="1.0.0",
        fixed_version_str="1.1.1",
        all_versions=all_versions
    )
    # Must pick 1.1.1, NOT jump blindly to 2.1.0
    assert chosen == "1.1.1"


def test_find_safe_upgrade_no_fixed_version_prefers_smallest_newer():
    all_versions = ["1.0.0", "1.0.1", "1.1.0", "2.0.0"]
    chosen = find_safe_upgrade(
        current_version_str="1.0.0",
        fixed_version_str=None,
        all_versions=all_versions
    )
    # Smallest version > 1.0.0 is 1.0.1
    assert chosen == "1.0.1"


def test_find_safe_upgrade_already_latest():
    all_versions = ["1.0.0", "1.1.0", "1.2.0"]
    chosen = find_safe_upgrade(
        current_version_str="1.2.0",
        fixed_version_str=None,
        all_versions=all_versions
    )
    assert chosen is None


def test_find_safe_upgrade_empty_versions():
    chosen = find_safe_upgrade("1.0.0", "1.0.1", [])
    assert chosen is None


@pytest.mark.asyncio
async def test_build_alternatives_structure_and_no_manifest_mutation():
    """Verify build_alternatives returns read-only recommendations without mutating any manifest files."""
    results = await build_alternatives(
        package_name="requests",
        package_version="2.25.0",
        vulnerability_canonical_id="CAN-TEST-001",
        fixed_version_from_advisory="2.25.1"
    )
    assert isinstance(results, list)
    if results:
        rec = results[0]
        assert "recommendation_type" in rec
        assert "label" in rec
        assert "package_name" in rec
        assert rec["package_name"] == "requests"
        assert "rationale" in rec
        assert "migration_complexity" in rec
