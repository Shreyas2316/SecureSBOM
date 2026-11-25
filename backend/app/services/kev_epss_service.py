"""
CISA KEV (Known Exploited Vulnerabilities) & FIRST EPSS Enrichment Service.
Enriches confirmed CVE findings with exploitation status and EPSS probability.
NEVER counts KEV or EPSS records as additional vulnerabilities.
"""
import time
import logging
from typing import Dict, Any, List, Optional
import httpx

from app.config import settings

logger = logging.getLogger("securesbom.kev_epss")

_KEV_CACHE: Dict[str, Any] = {"data": {}, "expires_at": 0.0}
_EPSS_CACHE: Dict[str, Any] = {}


async def load_cisa_kev_catalog(client: httpx.AsyncClient) -> Dict[str, Dict[str, Any]]:
    """Fetch and cache the CISA KEV catalog keyed by CVE ID (24h TTL)."""
    now = time.time()
    if _KEV_CACHE["data"] and now < _KEV_CACHE["expires_at"]:
        return _KEV_CACHE["data"]

    try:
        resp = await client.get(settings.CISA_KEV_URL, timeout=10.0)
        if resp.status_code == 200:
            payload = resp.json()
            vulns = payload.get("vulnerabilities", [])
            catalog = {}
            for item in vulns:
                cve = item.get("cveID")
                if cve:
                    catalog[cve] = {
                        "is_kev": True,
                        "kev_date_added": item.get("dateAdded"),
                        "kev_due_date": item.get("dueDate"),
                        "kev_ransomware_use": item.get("knownRansomwareCampaignUse"),
                        "kev_vendor_project": item.get("vendorProject"),
                        "kev_product": item.get("product"),
                    }
            _KEV_CACHE["data"] = catalog
            _KEV_CACHE["expires_at"] = now + 86400  # 24h
            return catalog
    except Exception as exc:
        logger.warning("CISA KEV fetch failed (non-fatal): %s", exc)

    return _KEV_CACHE.get("data", {})


async def query_epss_batch(client: httpx.AsyncClient, cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """Query FIRST EPSS API for a batch of CVE IDs with caching."""
    results: Dict[str, Dict[str, Any]] = {}
    now = time.time()
    missing: List[str] = []

    for cve in cve_ids:
        if not cve or not cve.startswith("CVE-"):
            continue
        cached = _EPSS_CACHE.get(cve)
        if cached and now < cached[1]:
            results[cve] = cached[0]
        else:
            missing.append(cve)

    if not missing:
        return results

    # FIRST EPSS supports comma-separated cve query up to ~100 at a time
    for i in range(0, len(missing), 50):
        chunk = missing[i:i + 50]
        try:
            resp = await client.get(
                settings.EPSS_API_URL,
                params={"cve": ",".join(chunk)},
                timeout=8.0,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", [])
                for row in data:
                    cve = row.get("cve")
                    if cve:
                        entry = {
                            "epss_score": float(row["epss"]) if row.get("epss") is not None else None,
                            "epss_percentile": float(row["percentile"]) if row.get("percentile") is not None else None,
                        }
                        _EPSS_CACHE[cve] = (entry, now + settings.CACHE_TTL_SECONDS)
                        results[cve] = entry
        except Exception as exc:
            logger.warning("FIRST EPSS batch query failed (non-fatal): %s", exc)

    return results
