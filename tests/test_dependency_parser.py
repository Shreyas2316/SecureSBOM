import pytest
from backend.models import DependencySpec
from backend.dependency_parser import (
    parse_requirements_txt,
    validate_and_parse_requirements_txt,
    normalize_package_name,
    build_purl,
    resolve_dependencies
)


def test_parse_requirements_txt_basic():
    content = """
    # Comment line
    requests==2.25.0 # inline comment
    jinja2>=2.11.0
    fastapi
    
    --extra-index-url https://example.com/pypi
    invalid_line_%%%$$
    """
    specs = parse_requirements_txt(content)
    
    assert len(specs) == 3
    names = [s.name for s in specs]
    assert "requests" in names
    assert "jinja2" in names
    assert "fastapi" in names

    req_spec = next(s for s in specs if s.name == "requests")
    assert req_spec.specifier == "==2.25.0"


def test_normalize_package_name():
    assert normalize_package_name("Requests") == "requests"
    assert normalize_package_name("Foo_Bar.Baz") == "foo-bar-baz"


def test_build_purl():
    purl = build_purl("requests", "2.25.0")
    assert purl == "pkg:pypi/requests@2.25.0"
    
    purl_unpinned = build_purl("fastapi", "unpinned")
    assert purl_unpinned == "pkg:pypi/fastapi@unpinned"


def test_resolve_dependencies():
    content = "requests==2.25.0\nfastapi"
    specs = parse_requirements_txt(content)
    resolved = resolve_dependencies(specs)
    
    assert len(resolved) >= 2
    req_dep = next(d for d in resolved if d.name == "requests")
    assert req_dep.version == "2.25.0"
    assert req_dep.purl == "pkg:pypi/requests@2.25.0"


def test_parse_requirements_txt_validation_errors():
    content = """
    valid-pkg==1.0.0
    bad:::line%%%
    another_valid>=2.0
    """
    specs, errors = validate_and_parse_requirements_txt(content)
    assert len(specs) == 2
    assert len(errors) == 1
    assert "Line 3" in errors[0]


def test_parse_requirements_txt_size_limit():
    huge_content = "a" * (3 * 1024 * 1024)
    with pytest.raises(ValueError) as excinfo:
        validate_and_parse_requirements_txt(huge_content)
    assert "exceeds maximum allowed size" in str(excinfo.value)


@pytest.mark.asyncio
async def test_resolve_dependencies_unresolved_package():
    from backend.dependency_parser import resolve_dependencies_async
    # Non-existent package should be safely marked as unresolved, NOT faking the constraint as version
    specs = [DependencySpec(name="non-existent-pkg-xyz-12345", specifier=">=99.0", raw_line="non-existent-pkg-xyz-12345>=99.0")]
    resolved, warnings = await resolve_dependencies_async(specs)
    assert len(resolved) == 1
    dep = resolved[0]
    assert dep.is_resolved is False
    assert dep.version == "unresolved"
    assert dep.resolution_status == "unresolved"
    assert len(warnings) == 1
