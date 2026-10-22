import pytest
from backend.severity import (
    score_to_severity,
    parse_cvss_vector_or_score,
    evaluate_severity,
    SeverityLevel
)


def test_score_to_severity_thresholds():
    assert score_to_severity(10.0) == SeverityLevel.CRITICAL
    assert score_to_severity(9.0) == SeverityLevel.CRITICAL
    assert score_to_severity(8.9) == SeverityLevel.HIGH
    assert score_to_severity(7.0) == SeverityLevel.HIGH
    assert score_to_severity(6.9) == SeverityLevel.MEDIUM
    assert score_to_severity(4.0) == SeverityLevel.MEDIUM
    assert score_to_severity(3.9) == SeverityLevel.LOW
    assert score_to_severity(0.1) == SeverityLevel.LOW
    assert score_to_severity(0.0) == SeverityLevel.INFORMATIONAL
    assert score_to_severity(None) == SeverityLevel.UNKNOWN
    assert score_to_severity(-1.0) == SeverityLevel.UNKNOWN
    assert score_to_severity(11.0) == SeverityLevel.UNKNOWN


def test_parse_cvss_vector():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    score, version, vec = parse_cvss_vector_or_score(vector)
    assert version == "3.1"
    assert vec == vector
    assert score is not None
    assert score >= 7.0  # High impact network vector


def test_parse_cvss_score_string():
    score, version, vec = parse_cvss_vector_or_score("CVSS_V3: 7.5")
    assert score == 7.5
    assert version == "3.1"


def test_missing_or_unavailable_severity():
    res = evaluate_severity(score=None, raw_severity_str="severity unavailable", source="OSV")
    assert res["severity"] == "UNKNOWN"
    assert res["score"] is None
    assert "marked UNKNOWN" in res["justification"]


def test_qualitative_severity_fallback():
    res = evaluate_severity(score=None, raw_severity_str="MODERATE", source="GitHub")
    assert res["severity"] == "MEDIUM"
    assert "qualitative advisory rating" in res["justification"]
