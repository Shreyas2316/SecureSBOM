import pytest
from app.services.prioritization import determine_priority_from_severity, resolve_canonical_severity

def test_prioritization_matrix():
    assert determine_priority_from_severity("CRITICAL", 9.8) == "P1-Critical"
    assert determine_priority_from_severity("HIGH", 7.5) == "P2-High"
    assert determine_priority_from_severity("MEDIUM", 5.3) == "P3-Medium"
    assert determine_priority_from_severity("LOW", 2.1) == "P4-Low"
    assert determine_priority_from_severity("INFO", None) == "P5-Info"
    assert determine_priority_from_severity("UNKNOWN", None) == "P-Unknown"

def test_resolve_canonical_severity():
    sources = [{"source": "OSV", "severity": "HIGH", "cvss_score": 7.5}]
    sev, score, vector, tier = resolve_canonical_severity(sources)
    assert sev == "HIGH"
    assert score == 7.5
    assert tier == "P2-High"
