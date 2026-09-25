from typing import Optional, Tuple, List, Dict, Any

SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "UNKNOWN": 0
}

def determine_priority_from_severity(severity: str, cvss_score: Optional[float] = None) -> str:
    """
    Map normalized severity and optional CVSS score to priority tier.
    Sole source of truth for priority calculation.
    
    CRITICAL -> P1-Critical
    HIGH     -> P2-High
    MEDIUM   -> P3-Medium
    LOW      -> P4-Low
    INFO     -> P5-Info
    UNKNOWN  -> P-Unknown
    """
    sev_upper = severity.upper() if severity else "UNKNOWN"
    
    if cvss_score is not None:
        if cvss_score >= 9.0:
            return "P1-Critical"
        elif cvss_score >= 7.0:
            return "P2-High"
        elif cvss_score >= 4.0:
            return "P3-Medium"
        elif cvss_score > 0:
            return "P4-Low"

    if sev_upper == "CRITICAL":
        return "P1-Critical"
    elif sev_upper == "HIGH":
        return "P2-High"
    elif sev_upper == "MEDIUM":
        return "P3-Medium"
    elif sev_upper == "LOW":
        return "P4-Low"
    elif sev_upper == "INFO":
        return "P5-Info"
    else:
        return "P-Unknown"

def resolve_canonical_severity(severity_sources: List[Dict[str, Any]]) -> Tuple[str, Optional[float], Optional[str], str]:
    """
    Deterministically resolve single canonical severity & CVSS from multiple source payloads.
    
    Resolution order:
    1. Highest numeric CVSS score across all sources.
    2. Else, highest named severity rank over UNKNOWN.
    3. Default to UNKNOWN / P-Unknown.
    
    Returns (resolved_severity, best_cvss_score, best_cvss_vector, priority_tier).
    """
    best_cvss_score: Optional[float] = None
    best_cvss_vector: Optional[str] = None
    best_severity: str = "UNKNOWN"

    # Step 1: Collect highest numeric CVSS score & vector
    for src in severity_sources:
        score = src.get("cvss_score")
        vector = src.get("cvss_vector")
        if score is not None:
            if best_cvss_score is None or score > best_cvss_score:
                best_cvss_score = score
                best_cvss_vector = vector or best_cvss_vector

    # Step 2: Determine severity string
    if best_cvss_score is not None:
        if best_cvss_score >= 9.0:
            best_severity = "CRITICAL"
        elif best_cvss_score >= 7.0:
            best_severity = "HIGH"
        elif best_cvss_score >= 4.0:
            best_severity = "MEDIUM"
        elif best_cvss_score > 0:
            best_severity = "LOW"
    else:
        # Evaluate highest severity rank among named sources
        highest_rank = 0
        for src in severity_sources:
            src_sev = (src.get("severity") or "UNKNOWN").upper()
            rank = SEVERITY_RANK.get(src_sev, 0)
            if rank > highest_rank:
                highest_rank = rank
                best_severity = src_sev

    priority_tier = determine_priority_from_severity(best_severity, best_cvss_score)
    return best_severity, best_cvss_score, best_cvss_vector, priority_tier
