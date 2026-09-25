import logging
import asyncio
import httpx
from typing import Dict, Any, Optional, Tuple
from app.config import settings

logger = logging.getLogger("securesbom.nvd")

NVD_CACHE: Dict[str, Dict[str, Any]] = {}
_last_request_time = 0.0

async def enrich_vulnerability_with_nvd(client: httpx.AsyncClient, cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Enrich vulnerability details using the official NVD API 2.0.
    Returns dict containing cvss_score, cvss_vector, base_severity if found.
    Never fails scanner — returns None on timeout/error/missing key.
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        return None

    if cve_id in NVD_CACHE:
        return NVD_CACHE[cve_id]

    headers = {}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    url = f"{settings.NVD_API_URL}?cveId={cve_id}"

    try:
        response = await client.get(url, headers=headers, timeout=6.0)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve_data = vulns[0].get("cve", {})
                metrics = cve_data.get("metrics", {})
                
                cvss_score = None
                cvss_vector = None
                base_severity = "UNKNOWN"

                # Check CVSS v3.1, then v3.0, then v2.0
                for v_key in ["cvssMetricV31", "cvssMetricV30"]:
                    if v_key in metrics and metrics[v_key]:
                        cvss_obj = metrics[v_key][0].get("cvssData", {})
                        cvss_score = cvss_obj.get("baseScore")
                        cvss_vector = cvss_obj.get("vectorString")
                        base_severity = metrics[v_key][0].get("baseSeverity") or cvss_obj.get("baseSeverity") or "UNKNOWN"
                        break

                if cvss_score is None and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    cvss_obj = metrics["cvssMetricV2"][0].get("cvssData", {})
                    cvss_score = cvss_obj.get("baseScore")
                    cvss_vector = cvss_obj.get("vectorString")
                    base_severity = metrics["cvssMetricV2"][0].get("baseSeverity") or "UNKNOWN"

                result = {
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "severity": base_severity.upper() if base_severity else "UNKNOWN"
                }
                NVD_CACHE[cve_id] = result
                return result
    except Exception as e:
        logger.info(f"NVD enrichment skipped/failed for {cve_id}: {str(e)}")

    NVD_CACHE[cve_id] = None
    return None
