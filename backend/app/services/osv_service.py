import logging
import asyncio
import re
import httpx
from typing import List, Dict, Any, Optional, Tuple, Set
from app.config import settings

logger = logging.getLogger("securesbom.osv")

OSV_CACHE: Dict[str, List[Dict[str, Any]]] = {}

# Patterns matching generic package description blurbs rather than vulnerability advisories
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
        # Sort to be deterministic (e.g. CVE-2024-...)
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

    # Check if summary is a generic package description blurb
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
    Does NOT invent scores — returns None if not present in OSV payload.
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
                if "CVSS" in s_type:
                    cvss_vector = s_score
                    break

    db_specific = vuln_raw.get("database_specific", {})
    if isinstance(db_specific, dict):
        if "severity" in db_specific and db_specific["severity"]:
            severity_rating = str(db_specific["severity"]).upper()
        if "cvss" in db_specific:
            cvss_info = db_specific["cvss"]
            if isinstance(cvss_info, dict):
                cvss_score = cvss_info.get("score")
                cvss_vector = cvss_info.get("vector_string") or cvss_vector

    return cvss_score, cvss_vector, severity_rating

async def query_osv_for_package(client: httpx.AsyncClient, name: str, version: str) -> List[Dict[str, Any]]:
    """
    Query OSV API for a given package name and version.
    Returns raw vulnerability objects from OSV API.
    """
    if version == "unknown" or not version:
        return []

    cache_key = f"{name.lower()}:{version}"
    if cache_key in OSV_CACHE:
        return OSV_CACHE[cache_key]

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
                OSV_CACHE[cache_key] = vulns
                return vulns
            elif response.status_code == 429:
                await asyncio.sleep(1.0 * (attempt + 1))
            else:
                logger.warning(f"OSV API returned status {response.status_code} for {name}=={version}")
                break
        except (httpx.TimeoutException, httpx.RequestError) as e:
            logger.warning(f"OSV API attempt {attempt+1} failed for {name}=={version}: {str(e)}")
            if attempt < max_retries:
                await asyncio.sleep(0.5)

    OSV_CACHE[cache_key] = []
    return []
