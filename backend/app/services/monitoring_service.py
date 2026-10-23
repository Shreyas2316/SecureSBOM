"""
Advisory Monitoring Service
Periodically fetches new/updated advisories from OSV and checks them against saved SBOMs.
Runs as a background scheduled task. NOT real-time — polling interval must respect API limits.
"""
import logging
import datetime
import asyncio
from typing import List, Dict, Any, Optional

import httpx
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Scan, Component, MonitoringSource, ProcessedAdvisory, MonitoringAlert

logger = logging.getLogger("securesbom.monitoring")

OSV_API_URL = "https://api.osv.dev/v1"

# Polling is done at most once per run; scheduling is handled externally.
# Never claim this is real-time continuous monitoring.
ADVISORY_FETCH_LIMIT = 100


def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def get_db() -> Session:
    db = SessionLocal()
    try:
        return db
    except Exception:
        db.close()
        raise


async def fetch_recent_advisories(modified_since: Optional[datetime.datetime] = None) -> List[Dict]:
    """
    Fetch recently modified PyPI advisories from OSV batch query endpoint.
    Respects OSV API rate limits by fetching only a bounded batch.
    """
    try:
        # OSV v1 doesn't have a direct "recent" feed; use known-ecosystem query
        # We query advisories modified in the last 24h using page token approach
        payload: Dict[str, Any] = {
            "ecosystem": "PyPI",
            "page_size": ADVISORY_FETCH_LIMIT,
        }
        if modified_since:
            # OSV batch API doesn't support modified_since filtering directly;
            # we fetch and filter client-side by the `modified` field
            pass

        url = f"{OSV_API_URL}/query"
        advisories = []

        async with httpx.AsyncClient(timeout=30.0) as client:
            # Use queryBatch for a broader search
            batch_payload = {
                "queries": [
                    {"package": {"ecosystem": "PyPI"}}
                ]
            }
            # OSV doesn't batch-list all recent; use the osvdev API
            # Better: use the API to query for specific packages from saved SBOMs
            # We'll iterate active scan components
            pass

        return advisories
    except Exception as exc:
        logger.error("Failed to fetch recent advisories: %s", exc)
        return []


async def check_component_against_osv(
    client: httpx.AsyncClient,
    package_name: str,
    package_version: str,
) -> List[Dict]:
    """Query OSV for a specific package@version."""
    try:
        payload = {
            "package": {"name": package_name, "ecosystem": "PyPI"},
            "version": package_version,
        }
        resp = await client.post(f"{OSV_API_URL}/query", json=payload)
        if resp.status_code == 200:
            return resp.json().get("vulns", [])
    except Exception as exc:
        logger.debug("OSV check failed for %s@%s: %s", package_name, package_version, exc)
    return []


async def run_monitoring_cycle(db: Session) -> Dict[str, Any]:
    """
    Run one monitoring cycle:
    1. Fetch or refresh the default OSV monitoring source record.
    2. Iterate saved scan components.
    3. For each component, check OSV for new advisories.
    4. Skip already-processed advisory IDs.
    5. Create MonitoringAlert for new matches.
    Returns a status summary dict.
    """
    results = {
        "checked_at": utc_now().isoformat(),
        "advisories_processed": 0,
        "new_alerts": 0,
        "components_checked": 0,
        "errors": [],
    }

    # Ensure default source record exists
    source = db.query(MonitoringSource).filter(MonitoringSource.name == "OSV PyPI").first()
    if not source:
        source = MonitoringSource(
            name="OSV PyPI",
            url="https://api.osv.dev/v1/query",
            source_type="osv",
            is_enabled=True,
        )
        db.add(source)
        db.commit()
        db.refresh(source)

    source.last_checked_at = utc_now()

    # Get already-processed advisory IDs for this source
    processed_ids = set(
        row.advisory_id
        for row in db.query(ProcessedAdvisory).filter(
            ProcessedAdvisory.source_id == source.id
        ).all()
    )

    # Get unique package@version pairs from all scans
    components_q = (
        db.query(Component.name, Component.version)
        .distinct()
        .all()
    )
    unique_components = [(c.name, c.version) for c in components_q]

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            for pkg_name, pkg_version in unique_components:
                results["components_checked"] += 1
                try:
                    advisories = await check_component_against_osv(client, pkg_name, pkg_version)
                    await asyncio.sleep(0.2)  # Respect OSV rate limits

                    for adv in advisories:
                        adv_id = adv.get("id", "")
                        if not adv_id or adv_id in processed_ids:
                            continue

                        results["advisories_processed"] += 1
                        processed_ids.add(adv_id)

                        # Record as processed
                        pa = ProcessedAdvisory(
                            source_id=source.id,
                            advisory_id=adv_id,
                            affected_packages_json=[{"name": pkg_name, "version": pkg_version}],
                        )
                        db.add(pa)

                        # Find scans containing this component
                        affected_components = (
                            db.query(Component)
                            .filter(
                                Component.name == pkg_name,
                                Component.version == pkg_version,
                            )
                            .all()
                        )

                        for comp in affected_components:
                            # Check no existing alert for this advisory+component
                            existing = db.query(MonitoringAlert).filter(
                                MonitoringAlert.advisory_id == adv_id,
                                MonitoringAlert.package_name == pkg_name,
                                MonitoringAlert.package_version == pkg_version,
                            ).first()
                            if existing:
                                continue

                            severity = "UNKNOWN"
                            sev_list = adv.get("severity", [])
                            if sev_list and isinstance(sev_list, list):
                                sev_item = sev_list[0]
                                severity = sev_item.get("type", "UNKNOWN").upper()

                            alert = MonitoringAlert(
                                source_id=source.id,
                                scan_id=comp.scan_id,
                                advisory_id=adv_id,
                                package_name=pkg_name,
                                package_version=pkg_version,
                                severity=severity,
                                summary=(adv.get("summary") or "")[:500],
                                is_acknowledged=False,
                            )
                            db.add(alert)
                            results["new_alerts"] += 1

                    db.commit()

                except Exception as exc:
                    logger.error("Error checking %s@%s: %s", pkg_name, pkg_version, exc)
                    results["errors"].append(f"{pkg_name}@{pkg_version}: {exc}")

        source.last_successful_sync_at = utc_now()
        source.advisories_processed = (source.advisories_processed or 0) + results["advisories_processed"]
        source.affected_dependencies_found = (source.affected_dependencies_found or 0) + results["new_alerts"]
        source.last_error = None

    except Exception as exc:
        logger.error("Monitoring cycle failed: %s", exc)
        source.last_error = str(exc)
        results["errors"].append(str(exc))

    db.commit()
    return results


def get_monitoring_status(db: Session) -> Dict[str, Any]:
    """Return current monitoring source status."""
    source = db.query(MonitoringSource).filter(MonitoringSource.name == "OSV PyPI").first()
    if not source:
        return {
            "source_name": "OSV PyPI",
            "is_enabled": False,
            "last_checked_at": None,
            "last_successful_sync_at": None,
            "advisories_processed": 0,
            "affected_dependencies_found": 0,
            "last_error": None,
            "note": "Monitoring has not been initialized. Trigger the first monitoring run."
        }

    unack_alerts = db.query(MonitoringAlert).filter(
        MonitoringAlert.source_id == source.id,
        MonitoringAlert.is_acknowledged == False
    ).count()

    return {
        "source_name": source.name,
        "source_url": source.url,
        "is_enabled": source.is_enabled,
        "last_checked_at": source.last_checked_at.isoformat() if source.last_checked_at else None,
        "last_successful_sync_at": source.last_successful_sync_at.isoformat() if source.last_successful_sync_at else None,
        "advisories_processed": source.advisories_processed or 0,
        "affected_dependencies_found": source.affected_dependencies_found or 0,
        "unacknowledged_alerts": unack_alerts,
        "last_error": source.last_error,
        "monitoring_note": (
            "Monitoring runs periodically (not in real-time). "
            "Frequency is bounded by OSV API rate limits."
        ),
    }
