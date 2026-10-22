import re
from typing import Optional, Tuple, Dict, Any
from enum import Enum


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    UNKNOWN = "UNKNOWN"


def score_to_severity(score: Optional[float]) -> SeverityLevel:
    """
    Converts a numeric CVSS score to a standardized SeverityLevel per FIRST CVSS v3.x specification.
    
    Thresholds:
    - 9.0 - 10.0 : CRITICAL
    - 7.0 - 8.9  : HIGH
    - 4.0 - 6.9  : MEDIUM
    - 0.1 - 3.9  : LOW
    - 0.0        : INFORMATIONAL
    - None       : UNKNOWN
    """
    if score is None:
        return SeverityLevel.UNKNOWN
    
    try:
        val = float(score)
    except (ValueError, TypeError):
        return SeverityLevel.UNKNOWN

    if val < 0.0 or val > 10.0:
        return SeverityLevel.UNKNOWN

    if val >= 9.0:
        return SeverityLevel.CRITICAL
    elif val >= 7.0:
        return SeverityLevel.HIGH
    elif val >= 4.0:
        return SeverityLevel.MEDIUM
    elif val >= 0.1:
        return SeverityLevel.LOW
    else:
        return SeverityLevel.INFORMATIONAL


def parse_cvss_vector_or_score(raw_str: str) -> Tuple[Optional[float], Optional[str], Optional[str]]:
    """
    Parses a raw severity or CVSS string.
    Returns: (score: Optional[float], version: Optional[str], vector: Optional[str])
    
    Handles strings like:
    - "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    - "CVSS_V3: 7.5"
    - "7.5"
    - "HIGH"
    - "CVSS:3.0/..."
    - "CVSS:2.0/..."
    """
    if not raw_str or not isinstance(raw_str, str):
        return None, None, None
        
    s = raw_str.strip()
    if s.lower() in ("severity unavailable", "unknown", "n/a", "none"):
        return None, None, None

    # Detect CVSS vector first
    cvss_vector: Optional[str] = None
    vector_match = re.search(r"(CVSS:(?:3\.1|3\.0|2\.0)/[A-Za-z0-9:/._\-]+)", s)
    if vector_match:
        cvss_vector = vector_match.group(1)

    # Detect CVSS version
    cvss_version: Optional[str] = None
    if "CVSS:3.1" in s or ("CVSS_V3" in s and "3.1" in s):
        cvss_version = "3.1"
    elif "CVSS:3.0" in s:
        cvss_version = "3.0"
    elif "CVSS:2.0" in s or "CVSS_V2" in s:
        cvss_version = "2.0"
    elif "CVSS_V3" in s or "CVSS v3" in s:
        cvss_version = "3.1"

    # Search for numeric score, but exclude the version string 'CVSS:3.1', 'CVSS:3.0', 'CVSS:2.0'
    text_without_cvss_prefix = re.sub(r"CVSS:(?:3\.1|3\.0|2\.0)", "", s)
    # Check for patterns like 'score: 7.5', '7.5 / 10', or standalone number
    direct_num = re.search(r"(?:score[:\s]+)?\b([0-9]\.[0-9]|10\.0)\b", text_without_cvss_prefix, re.IGNORECASE)
    detected_score: Optional[float] = None
    if direct_num:
        try:
            detected_score = float(direct_num.group(1))
        except ValueError:
            pass

    # If we have a vector but no explicit score, approximate from vector
    if detected_score is None and cvss_vector:
        detected_score = approximate_cvss3_score(cvss_vector)

    return detected_score, cvss_version, cvss_vector


def approximate_cvss3_score(vector: str) -> Optional[float]:
    """
    Approximates CVSS v3 base score from standard vector metrics when score is not supplied.
    Ensures safe, deterministic valuation.
    """
    if not vector or "AV:" not in vector:
        return None
        
    parts = dict(re.findall(r"([A-Z]+):([A-Z]+)", vector))
    
    # Impact metrics: Confidentiality (C), Integrity (I), Availability (A)
    c = parts.get("C", "N")
    i = parts.get("I", "N")
    a = parts.get("A", "N")
    av = parts.get("AV", "N") # Network, Adjacent, Local, Physical
    pr = parts.get("PR", "N") # Privileges Required: None, Low, High
    ui = parts.get("UI", "N") # User Interaction: None, Required
    
    # Calculate impact sub-score
    impact_map = {"H": 0.56, "L": 0.22, "N": 0.0}
    iss = 1.0 - ((1.0 - impact_map.get(c, 0.0)) * (1.0 - impact_map.get(i, 0.0)) * (1.0 - impact_map.get(a, 0.0)))
    if iss <= 0:
        return 0.0
        
    impact = 6.42 * iss
    
    # Exploitability sub-score
    av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    pr_weights = {"N": 0.85, "L": 0.62, "H": 0.27}
    ui_weights = {"N": 0.85, "R": 0.62}
    
    exploitability = 8.22 * av_weights.get(av, 0.85) * pr_weights.get(pr, 0.85) * ui_weights.get(ui, 0.85)
    
    base_score = min(10.0, round(impact + exploitability, 1))
    return max(0.1, base_score)


def normalize_qualitative_severity(text: str) -> SeverityLevel:
    """Normalizes string ratings (e.g. 'CRITICAL', 'MODERATE') into SeverityLevel."""
    if not text:
        return SeverityLevel.UNKNOWN
    t = text.strip().upper()
    if "CRITICAL" in t:
        return SeverityLevel.CRITICAL
    elif "HIGH" in t:
        return SeverityLevel.HIGH
    elif "MEDIUM" in t or "MODERATE" in t:
        return SeverityLevel.MEDIUM
    elif "LOW" in t:
        return SeverityLevel.LOW
    elif "INFO" in t:
        return SeverityLevel.INFORMATIONAL
    return SeverityLevel.UNKNOWN


def evaluate_severity(
    score: Optional[float] = None,
    raw_severity_str: Optional[str] = None,
    source: str = "OSV"
) -> Dict[str, Any]:
    """
    Evaluates severity with full justification and source preservation.
    
    Returns dictionary with:
    - severity: SeverityLevel (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, UNKNOWN)
    - score: Optional[float]
    - version: Optional[str]
    - vector: Optional[str]
    - justification: str explaining the determination
    """
    cvss_score = score
    cvss_version = None
    cvss_vector = None
    
    if raw_severity_str:
        parsed_score, parsed_ver, parsed_vec = parse_cvss_vector_or_score(raw_severity_str)
        if cvss_score is None:
            cvss_score = parsed_score
        cvss_version = parsed_ver
        cvss_vector = parsed_vec

    if cvss_score is not None:
        level = score_to_severity(cvss_score)
        v_str = f"CVSS v{cvss_version}" if cvss_version else "CVSS"
        justification = (
            f"Assigned {level.value} based on source-provided {v_str} base score {cvss_score:.1f} from {source}."
        )
    elif raw_severity_str:
        level = normalize_qualitative_severity(raw_severity_str)
        if level != SeverityLevel.UNKNOWN:
            justification = f"Assigned {level.value} based on qualitative advisory rating '{raw_severity_str}' from {source}."
        else:
            justification = f"No standard CVSS score or valid rating provided by {source}; marked UNKNOWN."
    else:
        level = SeverityLevel.UNKNOWN
        justification = f"No vulnerability severity data available from {source}; marked UNKNOWN."

    return {
        "severity": level.value,
        "score": cvss_score,
        "version": cvss_version,
        "vector": cvss_vector,
        "justification": justification
    }
