"""
Continuous Vulnerability Intelligence Ingestion Adapters & Sync Engine.
Implements incremental synchronization (ETag, Last-Modified, since timestamps, content hashes)
across public security advisory and research feeds without full-dataset re-downloads.
"""
import datetime
import hashlib
import logging
import re
from typing import List, Dict, Any, Optional, Tuple

import defusedxml.ElementTree as ET
import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.models.intelligence_models import (
    IntelligenceSource, IntelligenceDocument, IntelligenceSyncRun, AdvisoryEvidence
)
from app.services.dependency_parser import normalize_package_name
from app.services.intelligence_search import upsert_fts5_document

logger = logging.getLogger("securesbom.intel_adapters")


def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def compute_content_hash(*parts: Optional[str]) -> str:
    joined = "|".join(p or "" for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _parse_iso_dt(val: Optional[str]) -> Optional[datetime.datetime]:
    if not val:
        return None
    try:
        cleaned = val.strip().replace("Z", "+00:00")
        return datetime.datetime.fromisoformat(cleaned)
    except Exception:
        return None


DEFAULT_SOURCES: List[Dict[str, Any]] = [
    {
        "source_key": "github_advisories",
        "name": "GitHub Security Advisories (pip)",
        "source_type": "ghsa",
        "url": "https://api.github.com/advisories?ecosystem=pip&per_page=30",
        "reliability_tier": "authoritative",
        "sync_interval_minutes": 60,
    },
    {
        "source_key": "pypa_advisory_db",
        "name": "PyPA Advisory Database",
        "source_type": "pypa",
        "url": "https://api.github.com/repos/pypa/advisory-database/commits?per_page=15",
        "reliability_tier": "authoritative",
        "sync_interval_minutes": 60,
    },
    {
        "source_key": "cve_list_v5",
        "name": "CVE List V5 (CVEProject)",
        "source_type": "cve_v5",
        "url": "https://api.github.com/repos/CVEProject/cvelistV5/commits?per_page=10",
        "reliability_tier": "authoritative",
        "sync_interval_minutes": 60,
    },
    {
        "source_key": "github_security_lab",
        "name": "GitHub Security Lab Advisories",
        "source_type": "security_lab",
        "url": "https://securitylab.github.com/advisories/index.xml",
        "reliability_tier": "high",
        "sync_interval_minutes": 180,
    },
    {
        "source_key": "oss_security",
        "name": "Openwall oss-security Mailing List",
        "source_type": "oss_security",
        "url": "https://www.openwall.com/lists/oss-security/feed.xml",
        "reliability_tier": "medium",
        "sync_interval_minutes": 180,
    },
    {
        "source_key": "cisa_kev_feed",
        "name": "CISA Known Exploited Vulnerabilities",
        "source_type": "research_feed",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "reliability_tier": "authoritative",
        "sync_interval_minutes": 60,
    },
    {
        "source_key": "pypi_security_releases",
        "name": "PyPI Security Release Notes Feed",
        "source_type": "maintainer",
        "url": "https://pypi.org/rss/updates.xml",
        "reliability_tier": "medium",
        "sync_interval_minutes": 180,
    },
]


def ensure_default_sources(db: Session) -> List[IntelligenceSource]:
    """Seed default intelligence sources if not already present, plus any custom RSS feeds."""
    sources = []
    for cfg in DEFAULT_SOURCES:
        src = db.query(IntelligenceSource).filter(IntelligenceSource.source_key == cfg["source_key"]).first()
        if not src:
            src = IntelligenceSource(**cfg)
            db.add(src)
        sources.append(src)

    if settings.CUSTOM_RSS_FEEDS:
        for idx, feed_url in enumerate([u.strip() for u in settings.CUSTOM_RSS_FEEDS.split(",") if u.strip()], 1):
            key = f"custom_rss_{idx}"
            src = db.query(IntelligenceSource).filter(IntelligenceSource.source_key == key).first()
            if not src:
                src = IntelligenceSource(
                    source_key=key,
                    name=f"Trusted RSS Feed #{idx}",
                    source_type="rss",
                    url=feed_url,
                    reliability_tier="medium",
                    sync_interval_minutes=180,
                )
                db.add(src)
            sources.append(src)

    db.commit()
    return db.query(IntelligenceSource).all()


def _parse_rss_or_atom(xml_text: str, source_url: str) -> List[Dict[str, Any]]:
    """Safely parse RSS 2.0 or Atom XML using defusedxml (XXE-safe)."""
    items: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return items

    # Handle Atom <entry> or RSS <item>
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    entries = root.findall(".//item")
    is_atom = False
    if not entries:
        entries = root.findall(".//atom:entry", ns) or root.findall(".//entry")
        is_atom = True

    for entry in entries[:30]:
        if is_atom:
            title = (entry.findtext("atom:title", default="", namespaces=ns) or entry.findtext("title", default="")).strip()
            link_el = entry.find("atom:link", ns) or entry.find("link")
            link = (link_el.attrib.get("href") if link_el is not None else "") or source_url
            summary = (entry.findtext("atom:summary", default="", namespaces=ns) or entry.findtext("summary", default="") or "").strip()
            pub = entry.findtext("atom:published", default="", namespaces=ns) or entry.findtext("atom:updated", default="", namespaces=ns) or entry.findtext("updated", default="")
            ext_id = (entry.findtext("atom:id", default="", namespaces=ns) or entry.findtext("id", default="") or link).strip()
        else:
            title = (entry.findtext("title") or "").strip()
            link = (entry.findtext("link") or source_url).strip()
            summary = (entry.findtext("description") or "").strip()
            pub = (entry.findtext("pubDate") or "").strip()
            ext_id = (entry.findtext("guid") or link).strip()

        if not title:
            continue

        # Extract any CVE/GHSA/PYSEC IDs mentioned
        combined = f"{title} {summary}"
        aliases = sorted(set(re.findall(r"(?:CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|PYSEC-\d{4}-\d+)", combined, re.IGNORECASE)))
        # Heuristic package name extraction from title/summary
        pkg_matches = re.findall(r"\b(?:python-|py)?([a-zA-Z0-9_\-]{3,32})\b", title)
        pkgs = [normalize_package_name(p) for p in pkg_matches[:3] if p.lower() not in {"security", "advisory", "vulnerability", "update", "release", "cve"}]

        items.append({
            "external_id": ext_id[:190],
            "url": link[:990],
            "title": title[:490],
            "summary": re.sub(r"<[^>]+>", " ", summary)[:1500].strip(),
            "excerpt": re.sub(r"<[^>]+>", " ", summary)[:600].strip(),
            "published_at": _parse_iso_dt(pub) or utc_now(),
            "updated_at": utc_now(),
            "package_names": pkgs,
            "aliases": [a.upper() for a in aliases],
            "affected_ranges": [],
            "fixed_versions": [],
            "is_withdrawn": False,
        })
    return items


async def fetch_source_items(client: httpx.AsyncClient, source: IntelligenceSource) -> Tuple[List[Dict[str, Any]], Optional[str], Optional[str], bool]:
    """
    Fetch incremental items from a configured IntelligenceSource.
    Returns (items, new_etag, new_last_modified, not_modified_304).
    """
    headers: Dict[str, str] = {"User-Agent": "SecureSBOM-Intelligence/2.0"}
    if source.etag:
        headers["If-None-Match"] = source.etag
    if source.last_modified:
        headers["If-Modified-Since"] = source.last_modified
    if settings.GITHUB_TOKEN and "api.github.com" in source.url:
        headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"

    resp = await client.get(source.url, headers=headers, timeout=15.0, follow_redirects=True)
    if resp.status_code == 304:
        return [], source.etag, source.last_modified, True

    resp.raise_for_status()
    new_etag = resp.headers.get("ETag")
    new_last_mod = resp.headers.get("Last-Modified")

    items: List[Dict[str, Any]] = []
    if source.source_type == "ghsa":
        data = resp.json()
        for adv in (data if isinstance(data, list) else []):
            ghsa_id = adv.get("ghsa_id") or ""
            cve_id = adv.get("cve_id")
            aliases = [a for a in ([ghsa_id, cve_id] + [i.get("value") for i in adv.get("identifiers", []) if isinstance(i, dict)]) if a]
            pkgs = []
            ranges = []
            fixes = []
            for v in adv.get("vulnerabilities", []) or []:
                pkg_obj = v.get("package", {})
                if pkg_obj.get("ecosystem", "").lower() == "pip" and pkg_obj.get("name"):
                    pkgs.append(normalize_package_name(pkg_obj["name"]))
                if v.get("vulnerable_version_range"):
                    ranges.append(v["vulnerable_version_range"].replace(" ", ""))
                if v.get("first_patched_version"):
                    fixes.append(str(v["first_patched_version"]))
            items.append({
                "external_id": ghsa_id,
                "url": adv.get("html_url") or source.url,
                "title": (adv.get("summary") or ghsa_id)[:490],
                "summary": (adv.get("description") or adv.get("summary") or "")[:1500],
                "excerpt": (adv.get("description") or adv.get("summary") or "")[:600],
                "published_at": _parse_iso_dt(adv.get("published_at")),
                "updated_at": _parse_iso_dt(adv.get("updated_at")),
                "package_names": sorted(set(pkgs)),
                "aliases": sorted(set(aliases)),
                "affected_ranges": ranges,
                "fixed_versions": fixes,
                "is_withdrawn": bool(adv.get("withdrawn_at")),
            })
    elif source.source_type in ("pypa", "cve_v5"):
        commits = resp.json()
        for c in (commits if isinstance(commits, list) else [])[:15]:
            sha = c.get("sha", "")
            commit_obj = c.get("commit", {})
            msg = (commit_obj.get("message") or "").splitlines()[0]
            date_str = commit_obj.get("author", {}).get("date")
            aliases = re.findall(r"(?:CVE-\d{4}-\d{4,7}|PYSEC-\d{4}-\d+|GHSA-[a-z0-9\-]+)", commit_obj.get("message") or "", re.IGNORECASE)
            items.append({
                "external_id": sha[:24],
                "url": c.get("html_url") or source.url,
                "title": msg[:490] or f"Advisory update {sha[:8]}",
                "summary": (commit_obj.get("message") or "")[:1500],
                "excerpt": (commit_obj.get("message") or "")[:600],
                "published_at": _parse_iso_dt(date_str) or utc_now(),
                "updated_at": _parse_iso_dt(date_str) or utc_now(),
                "package_names": [],
                "aliases": [a.upper() for a in aliases],
                "affected_ranges": [],
                "fixed_versions": [],
                "is_withdrawn": "withdraw" in (commit_obj.get("message") or "").lower(),
            })
    elif source.source_type == "research_feed" and "known_exploited_vulnerabilities" in source.url:
        payload = resp.json()
        for v in (payload.get("vulnerabilities", []) or [])[-25:]:
            cve = v.get("cveID")
            if not cve:
                continue
            items.append({
                "external_id": cve,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                "title": f"{cve}: {v.get('vulnerabilityName', 'CISA KEV Entry')}"[:490],
                "summary": (v.get("shortDescription") or "")[:1500],
                "excerpt": (v.get("shortDescription") or "")[:600],
                "published_at": _parse_iso_dt(v.get("dateAdded")) or utc_now(),
                "updated_at": utc_now(),
                "package_names": [normalize_package_name(v["product"])] if v.get("product") else [],
                "aliases": [cve],
                "affected_ranges": [],
                "fixed_versions": [],
                "is_withdrawn": False,
            })
    else:
        items = _parse_rss_or_atom(resp.text, source.url)

    return items, new_etag, new_last_mod, False


def ingest_intelligence_items(db: Session, source: IntelligenceSource, items: List[Dict[str, Any]]) -> Dict[str, int]:
    """Deduplicate, store, or withdraw IntelligenceDocuments from normalized adapter items."""
    new_count = 0
    updated_count = 0
    withdrawn_count = 0

    for item in items:
        ext_id = item.get("external_id") or item.get("url")
        c_hash = compute_content_hash(source.source_key, ext_id, item.get("title"), item.get("summary"))
        doc_uid = compute_content_hash(source.source_key, ext_id)[:32]

        existing = db.query(IntelligenceDocument).filter(
            (IntelligenceDocument.doc_uid == doc_uid) |
            ((IntelligenceDocument.content_hash == c_hash) & (IntelligenceDocument.source_id == source.id))
        ).first()

        if existing:
            if item.get("is_withdrawn") and not existing.is_withdrawn:
                existing.is_withdrawn = True
                existing.review_status = "withdrawn"
                existing.withdrawal_reason = "Marked withdrawn by upstream source"
                withdrawn_count += 1
            elif existing.content_hash != c_hash:
                existing.title = item["title"]
                existing.summary = item.get("summary")
                existing.excerpt = item.get("excerpt")
                existing.updated_at = item.get("updated_at") or utc_now()
                existing.package_names_json = item.get("package_names", [])
                existing.aliases_json = item.get("aliases", [])
                existing.affected_ranges_json = item.get("affected_ranges", [])
                existing.fixed_versions_json = item.get("fixed_versions", [])
                existing.content_hash = c_hash
                existing.review_status = "corrected"
                updated_count += 1
                upsert_fts5_document(existing)
            continue

        doc = IntelligenceDocument(
            doc_uid=doc_uid,
            source_id=source.id,
            external_id=ext_id,
            url=item.get("url") or source.url,
            title=item["title"],
            summary=item.get("summary"),
            excerpt=item.get("excerpt"),
            published_at=item.get("published_at"),
            updated_at=item.get("updated_at"),
            retrieved_at=utc_now(),
            package_names_json=item.get("package_names", []),
            ecosystem="PyPI",
            aliases_json=item.get("aliases", []),
            affected_ranges_json=item.get("affected_ranges", []),
            fixed_versions_json=item.get("fixed_versions", []),
            content_hash=c_hash,
            evidence_refs_json=[item.get("url") or source.url],
            source_reliability=source.reliability_tier,
            review_status="withdrawn" if item.get("is_withdrawn") else "active",
            is_withdrawn=bool(item.get("is_withdrawn")),
        )
        db.add(doc)
        db.flush()

        db.add(AdvisoryEvidence(
            document_id=doc.id,
            evidence_type=source.source_type,
            url=doc.url,
            excerpt=doc.excerpt,
            content_hash=c_hash,
        ))
        upsert_fts5_document(doc)
        new_count += 1

    source.documents_indexed = db.query(IntelligenceDocument).filter(
        IntelligenceDocument.source_id == source.id
    ).count()
    db.commit()
    return {"new": new_count, "updated": updated_count, "withdrawn": withdrawn_count}


async def sync_all_intelligence_sources(db: Session, source_keys: Optional[List[str]] = None) -> Dict[str, Any]:
    """Run incremental synchronization across enabled IntelligenceSources."""
    sources = ensure_default_sources(db)
    if source_keys:
        sources = [s for s in sources if s.source_key in source_keys]

    summary = {"synced_sources": 0, "failed_sources": 0, "new_documents": 0, "updated_documents": 0, "details": []}

    async with httpx.AsyncClient() as client:
        for src in sources:
            if not src.is_enabled:
                continue
            run = IntelligenceSyncRun(source_id=src.id, started_at=utc_now(), status="running", checkpoint_used=src.etag or src.last_modified)
            db.add(run)
            db.commit()
            db.refresh(run)

            try:
                items, new_etag, new_lm, not_modified = await fetch_source_items(client, src)
                src.last_checked_at = utc_now()
                if not_modified:
                    run.status = "success"
                    run.finished_at = utc_now()
                    src.last_successful_sync_at = utc_now()
                    src.last_error = None
                    summary["synced_sources"] += 1
                    summary["details"].append({"source": src.source_key, "status": "not_modified", "new": 0})
                else:
                    counts = ingest_intelligence_items(db, src, items)
                    src.etag = new_etag or src.etag
                    src.last_modified = new_lm or src.last_modified
                    src.last_successful_sync_at = utc_now()
                    src.last_error = None
                    run.status = "success"
                    run.finished_at = utc_now()
                    run.items_fetched = len(items)
                    run.items_new = counts["new"]
                    run.items_updated = counts["updated"]
                    run.items_withdrawn = counts["withdrawn"]
                    summary["synced_sources"] += 1
                    summary["new_documents"] += counts["new"]
                    summary["updated_documents"] += counts["updated"]
                    summary["details"].append({"source": src.source_key, "status": "success", **counts})
                db.commit()
            except Exception as exc:
                err_msg = str(exc)[:500]
                src.last_checked_at = utc_now()
                src.last_error = err_msg
                run.status = "failed"
                run.finished_at = utc_now()
                run.error_message = err_msg
                db.commit()
                summary["failed_sources"] += 1
                summary["details"].append({"source": src.source_key, "status": "failed", "error": err_msg})

    return summary
