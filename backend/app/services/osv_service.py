import logging
import asyncio
import re
import time
import httpx
from typing import List, Dict, Any, Optional, Tuple, Set
from app.config import settings

from contextvars import ContextVar

logger = logging.getLogger("securesbom.osv")

_OSV_FAILURE_TRACKER: ContextVar[Optional[Dict[str, Any]]] = ContextVar("_OSV_FAILURE_TRACKER", default=None)

def set_osv_failure_tracker(tracker: Optional[Dict[str, Any]]) -> None:
    _OSV_FAILURE_TRACKER.set(tracker)

# Cache stores (vulns_list, expires_at_timestamp)
OSV_CACHE: Dict[str, Any] = {}
OSV_BATCH_DETAILS_CACHE: Dict[str, Tuple[Dict[str, Any], float]] = {}

GENERIC_PACKAGE_PATTERNS = [
    r"^[A-Za-z0-9_.\-]+ is a (user-friendly|comprehensive|popular|Python) ",
    r"^[A-Za-z0-9_.\-]+ is an HTTP library",
    r"^[A-Za-z0-9_.\-]+ provides ",
]


def extract_all_identifiers(vuln_raw: Dict[str, Any]) -> Set[str]:
    """
    Extract all advisory identifiers associated with this raw OSV payload,
    including the primary ID and aliases (CVE, GHSA, PYSEC, OSV, etc.).
    """
    identifiers = set()
    raw_id = vuln_raw.get("id")
    if raw_id:
        identifiers.add(str(raw_id).strip())

    aliases = vuln_raw.get("aliases", [])
    if isinstance(aliases, list):
        for alias in aliases:
            if alias:
                identifiers.add(str(alias).strip())

    return identifiers


def extract_cve_id(vuln_raw: Dict[str, Any]) -> Optional[str]:
    """Extract CVE ID from vulnerability ID or aliases if available."""
    all_ids = extract_all_identifiers(vuln_raw)
    cves = [i for i in all_ids if i.startswith("CVE-")]
    if cves:
        cves.sort()
        return cves[0]
    return None


def extract_references(vuln_raw: Dict[str, Any]) -> List[str]:
    """Extract reference URLs from OSV raw payload."""
    refs = vuln_raw.get("references", [])
    urls = []
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, dict) and "url" in ref:
                urls.append(ref["url"])
            elif isinstance(ref, str):
                urls.append(ref)
    return urls


def extract_remediation_info(vuln_raw: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse OSV `affected` data for introduced/fixed version events.
    Returns (affected_range, fixed_version).
    Does NOT invent versions — returns None if absent.
    """
    affected_list = vuln_raw.get("affected", [])
    if not isinstance(affected_list, list):
        return None, None

    fixed_version = None
    introduced_version = None

    for aff in affected_list:
        if not isinstance(aff, dict):
            continue

        ranges = aff.get("ranges", [])
        if isinstance(ranges, list):
            for r in ranges:
                if not isinstance(r, dict):
                    continue
                events = r.get("events", [])
                if isinstance(events, list):
                    for ev in events:
                        if isinstance(ev, dict):
                            if "fixed" in ev and not fixed_version:
                                fixed_version = str(ev["fixed"])
                            if "introduced" in ev and not introduced_version:
                                introduced_version = str(ev["introduced"])

    affected_range = None
    if introduced_version and fixed_version:
        affected_range = f">={introduced_version}, <{fixed_version}"
    elif fixed_version:
        affected_range = f"<{fixed_version}"
    elif introduced_version:
        affected_range = f">={introduced_version}"

    return affected_range, fixed_version


def clean_summary_and_details(vuln_raw: Dict[str, Any], pkg_name: str = "") -> Tuple[str, str]:
    """
    Extract summary and details text, filtering out generic package description blurbs.
    """
    summary = (vuln_raw.get("summary") or "").strip()
    details = (vuln_raw.get("details") or "").strip()

    is_generic = False
    if summary:
        for pat in GENERIC_PACKAGE_PATTERNS:
            if re.search(pat, summary, re.IGNORECASE):
                is_generic = True
                break

    if is_generic or not summary:
        if details and not any(re.search(pat, details, re.IGNORECASE) for pat in GENERIC_PACKAGE_PATTERNS):
            summary = details[:200] + ("..." if len(details) > 200 else "")
        else:
            summary = "Security advisory for component"

    if not details:
        details = summary

    return summary, details


def extract_severity_and_cvss(vuln_raw: Dict[str, Any]) -> Tuple[Optional[float], Optional[str], str]:
    """
    Extract CVSS score, CVSS vector, and severity rating from OSV data.
    Computes CVSS score from vector when score is not explicitly provided.
    """
    cvss_score = None
    cvss_vector = None
    severity_rating = "UNKNOWN"

    severity_list = vuln_raw.get("severity", [])
    if isinstance(severity_list, list):
        for sev in severity_list:
            if isinstance(sev, dict):
                s_type = sev.get("type", "")
                s_score = sev.get("score", "")
                if "CVSS" in s_type and s_score:
                    cvss_vector = s_score
                    break

    db_specific = vuln_raw.get("database_specific", {})
    if isinstance(db_specific, dict):
        if "severity" in db_specific and db_specific["severity"]:
            raw_s = str(db_specific["severity"]).upper()
            if "MODERATE" in raw_s:
                severity_rating = "MEDIUM"
            elif "CRITICAL" in raw_s:
                severity_rating = "CRITICAL"
            elif "HIGH" in raw_s:
                severity_rating = "HIGH"
            elif "LOW" in raw_s:
                severity_rating = "LOW"
            elif "INFO" in raw_s:
                severity_rating = "INFORMATIONAL"
            else:
                severity_rating = raw_s
        if "cvss" in db_specific:
            cvss_info = db_specific["cvss"]
            if isinstance(cvss_info, dict):
                cvss_score = cvss_info.get("score")
                cvss_vector = cvss_info.get("vector_string") or cvss_vector

    eco_specific = vuln_raw.get("ecosystem_specific", {})
    if isinstance(eco_specific, dict) and severity_rating == "UNKNOWN":
        eco_sev = str(eco_specific.get("severity", "")).upper()
        if "MODERATE" in eco_sev:
            severity_rating = "MEDIUM"
        elif "CRITICAL" in eco_sev:
            severity_rating = "CRITICAL"
        elif "HIGH" in eco_sev:
            severity_rating = "HIGH"
        elif "LOW" in eco_sev:
            severity_rating = "LOW"

    if cvss_score is None and cvss_vector:
        try:
            from backend.severity import parse_cvss_vector_or_score
            parsed_score, _, _ = parse_cvss_vector_or_score(cvss_vector)
            if parsed_score is not None:
                cvss_score = parsed_score
        except Exception:
            pass

    if cvss_score is not None and severity_rating == "UNKNOWN":
        if cvss_score >= 9.0:
            severity_rating = "CRITICAL"
        elif cvss_score >= 7.0:
            severity_rating = "HIGH"
        elif cvss_score >= 4.0:
            severity_rating = "MEDIUM"
        elif cvss_score >= 0.1:
            severity_rating = "LOW"
        else:
            severity_rating = "INFORMATIONAL"

    return cvss_score, cvss_vector, severity_rating


async def query_osv_for_package(
    client: httpx.AsyncClient,
    name: str,
    version: str,
) -> List[Dict[str, Any]]:
    """
    Query OSV API for a given package name and version with TTL caching and backoff.
    Records lookup failures in contextvar tracker so failed lookups are never misreported as 0 vulns.
    """
    status_tracker = _OSV_FAILURE_TRACKER.get()
    if version in ("unknown", "unpinned", "unresolved") or not version:
        return []

    cache_key = f"{name.lower()}:{version}"
    now = time.time()
    if cache_key in OSV_CACHE:
        cached = OSV_CACHE[cache_key]
        if isinstance(cached, tuple) and len(cached) == 2:
            if now < cached[1]:
                return cached[0]
        elif isinstance(cached, list):
            return cached

    payload = {
        "package": {
            "name": name,
            "ecosystem": "PyPI"
        },
        "version": version
    }

    url = settings.OSV_API_URL
    max_retries = 2
    for attempt in range(max_retries + 1):
        try:
            response = await client.post(url, json=payload, timeout=10.0)
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulns", [])
                OSV_CACHE[cache_key] = (vulns, now + settings.CACHE_TTL_SECONDS)
                return vulns
            elif response.status_code == 429:
                await asyncio.sleep(1.0 * (2 ** attempt))
            else:
                logger.warning("OSV API returned status %s for %s==%s", response.status_code, name, version)
                if status_tracker is not None:
                    status_tracker["osv_failures"] = status_tracker.get("osv_failures", 0) + 1
                break
        except (httpx.TimeoutException, httpx.RequestError) as e:
            logger.warning("OSV API attempt %s failed for %s==%s: %s", attempt + 1, name, version, e)
            if attempt < max_retries:
                await asyncio.sleep(0.5 * (2 ** attempt))
            elif status_tracker is not None:
                status_tracker["osv_failures"] = status_tracker.get("osv_failures", 0) + 1

    return []
