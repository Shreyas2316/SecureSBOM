import pytest
from backend.models import ResolvedDependency
from backend.sbom_generator import (
    generate_cyclonedx_sbom,
    save_sbom_to_file,
    validate_cyclonedx_sbom
)


def test_generate_cyclonedx_sbom_and_validate():
    deps = [
        ResolvedDependency(
            name="requests",
            version="2.25.0",
            purl="pkg:pypi/requests@2.25.0",
            is_direct=True,
            transitive_dependencies=["urllib3"]
        ),
        ResolvedDependency(
            name="urllib3",
            version="1.26.4",
            purl="pkg:pypi/urllib3@1.26.4",
            is_direct=False,
            transitive_dependencies=[]
        )
    ]
    
    sbom = generate_cyclonedx_sbom(deps)
    
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["serialNumber"].startswith("urn:uuid:")
    assert "metadata" in sbom
    assert len(sbom["components"]) == 2
    
    # Run official schema validation
    is_valid, error = validate_cyclonedx_sbom(sbom)
    assert is_valid is True
    assert error is None


def test_empty_project_sbom_validation():
    """CycloneDX generation for an empty requirements inventory must produce valid schema."""
    sbom = generate_cyclonedx_sbom([])
    assert sbom["components"] == []
    is_valid, error = validate_cyclonedx_sbom(sbom)
    assert is_valid is True
    assert error is None


def test_missing_or_unresolved_version_sbom_validation():
    """Components with missing/unpinned versions should still produce valid schema."""
    deps = [
        ResolvedDependency(
            name="unpinned-pkg",
            version="unpinned",
            purl="pkg:pypi/unpinned-pkg@unpinned",
            is_direct=True,
            transitive_dependencies=[]
        )
    ]
    sbom = generate_cyclonedx_sbom(deps)
    is_valid, error = validate_cyclonedx_sbom(sbom)
    assert is_valid is True
    assert error is None


def test_invalid_sbom_detected():
    """Arbitrary/corrupted JSON must fail CycloneDX schema validation."""
    invalid_doc = {"not_a_bom": True, "components": 123}
    is_valid, error = validate_cyclonedx_sbom(invalid_doc)
    assert is_valid is False
    assert error is not None


def test_save_sbom_to_file(tmp_path):
    sbom = generate_cyclonedx_sbom([])
    output_file = tmp_path / "bom.json"
    saved_path = save_sbom_to_file(sbom, str(output_file))
    
    assert saved_path == str(output_file)
    assert output_file.exists()
