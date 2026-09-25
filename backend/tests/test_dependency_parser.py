import pytest
from app.services.dependency_parser import parse_requirements, normalize_package_name

def test_normalize_package_name():
    assert normalize_package_name("PyYAML") == "pyyaml"
    assert normalize_package_name("Flask_SQLAlchemy") == "flask-sqlalchemy"
    assert normalize_package_name("cyclonedx-python-lib") == "cyclonedx-python-lib"

def test_parse_valid_requirements():
    content = """
    # Sample requirements
    requests==2.25.1
    urllib3>=1.26.4
    jinja2~=2.11.2
    flask
    """
    deps = parse_requirements(content)
    assert len(deps) == 4
    
    names = [d["normalized_name"] for d in deps]
    assert "requests" in names
    assert "urllib3" in names
    assert "jinja2" in names
    assert "flask" in names

    req_dep = next(d for d in deps if d["normalized_name"] == "requests")
    assert req_dep["version"] == "2.25.1"
    assert req_dep["is_direct"] is True

def test_parse_comments_and_options():
    content = """
    --index-url https://pypi.org/simple
    -r base.txt
    requests==2.25.1 # inline comment
    # Full line comment
    
    pyyaml==5.3.1
    """
    deps = parse_requirements(content)
    assert len(deps) == 2
    assert deps[0]["normalized_name"] == "requests"
    assert deps[1]["normalized_name"] == "pyyaml"
