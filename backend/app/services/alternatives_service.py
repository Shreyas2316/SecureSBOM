"""
Dependency Alternatives Service
Identifies safer versions or replacement packages for vulnerable dependencies.
Uses PyPI metadata and authoritative fixed-version data only.
Does NOT automatically change project files.
"""
import asyncio
import logging
from typing import Optional, List, Dict, Any

import httpx
from packaging.version import Version, InvalidVersion

logger = logging.getLogger("securesbom.alternatives")

PYPI_BASE = "https://pypi.org/pypi"


async def fetch_all_versions(
    package_name: str,
    client: Optional[httpx.AsyncClient] = None,
) -> List[str]:
    """Fetch all released stable non-yanked versions of a package from PyPI."""
    url = f"{PYPI_BASE}/{package_name}/json"
    try:
        if client is not None:
            resp = await client.get(url, timeout=8.0)
        else:
            async with httpx.AsyncClient(timeout=8.0) as local_client:
                resp = await local_client.get(url)

        if resp.status_code == 200:
            releases = resp.json().get("releases", {})
            stable = []
            for ver_str, files in releases.items():
                try:
                    v = Version(ver_str)
                    if not v.is_prerelease and not v.is_devrelease:
                        if not any(f.get("yanked", False) for f in files):
                            stable.append(ver_str)
                except InvalidVersion:
                    continue
            return stable
    except Exception as exc:
        logger.debug("PyPI versions fetch failed for %s: %s", package_name, exc)
    return []


async def fetch_package_info(
    package_name: str,
    version: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
) -> Optional[Dict[str, Any]]:
    """Fetch PyPI package info for a specific version or latest."""
    url = f"{PYPI_BASE}/{package_name}/{version}/json" if version else f"{PYPI_BASE}/{package_name}/json"
    try:
        if client is not None:
            resp = await client.get(url, timeout=8.0)
        else:
            async with httpx.AsyncClient(timeout=8.0) as local_client:
                resp = await local_client.get(url)

        if resp.status_code == 200:
            data = resp.json()
            info = data.get("info", {})
            return {
                "name": info.get("name", package_name),
                "version": info.get("version", ""),
                "summary": (info.get("summary") or "")[:300],
                "license": info.get("license") or "Unknown",
                "requires_python": info.get("requires_python") or "",
                "home_page": info.get("home_page") or "",
                "project_urls": info.get("project_urls") or {},
                "yanked": info.get("yanked", False),
                "yanked_reason": info.get("yanked_reason") or "",
                "release_url": f"https://pypi.org/project/{package_name}/{info.get('version', '')}/",
            }
    except Exception as exc:
        logger.debug("PyPI info fetch failed for %s@%s: %s", package_name, version, exc)
    return None


def find_safe_upgrade(
    current_version_str: str,
    fixed_version_str: Optional[str],
    all_versions: List[str],
) -> Optional[str]:
    """
    Find the smallest stable version >= fixed_version that is > current.
    If current_version_str is 'unknown' or invalid, falls back to fixed_version_str or latest stable.
    """
    if not all_versions:
        return None

    current = None
    try:
        if current_version_str and current_version_str not in ("unknown", "unpinned", "unresolved"):
            current = Version(current_version_str)
    except InvalidVersion:
        current = None

    candidates = []
    for vs in all_versions:
        try:
            v = Version(vs)
            if current is not None and v <= current:
                continue
            if fixed_version_str:
                try:
                    fixed = Version(fixed_version_str)
                    if v < fixed:
                        continue
                except InvalidVersion:
                    pass
            candidates.append(v)
        except InvalidVersion:
            continue

    if not candidates:
        return None

    return str(min(candidates))


async def build_alternatives(
    package_name: str,
    package_version: str,
    vulnerability_canonical_id: Optional[str],
    fixed_version_from_advisory: Optional[str],
    versions_cache: Optional[Dict[str, List[str]]] = None,
    info_cache: Optional[Dict[str, Dict[str, Any]]] = None,
    client: Optional[httpx.AsyncClient] = None,
) -> List[Dict[str, Any]]:
    """
    Build a list of alternative recommendations for a vulnerable dependency.
    Returns a list of recommendation dicts, never modifying project files.
    """
    alternatives = []

    if versions_cache is not None and package_name in versions_cache:
        all_versions = versions_cache[package_name]
    else:
        all_versions = await fetch_all_versions(package_name, client=client)
        if versions_cache is not None:
            versions_cache[package_name] = all_versions

    safe_upgrade = find_safe_upgrade(package_version, fixed_version_from_advisory, all_versions)

    if safe_upgrade:
        cache_key = f"{package_name}@{safe_upgrade}"
        if info_cache is not None and cache_key in info_cache:
            upgrade_info = info_cache[cache_key]
        else:
            upgrade_info = await fetch_package_info(package_name, safe_upgrade, client=client)
            if info_cache is not None and upgrade_info:
                info_cache[cache_key] = upgrade_info
        try:
            cur_v = Version(package_version)
            safe_v = Version(safe_upgrade)
            is_major_bump = safe_v.major > cur_v.major
        except InvalidVersion:
            is_major_bump = False

        alternatives.append({
            "recommendation_type": "version_upgrade",
            "label": "Recommended fixed version" if fixed_version_from_advisory else "Newer stable version",
            "package_name": package_name,
            "package_version": package_version,
            "recommended_version": safe_upgrade,
            "alternative_package": None,
            "alternative_version": None,
            "compatibility_info": (
                "Major version upgrade — breaking changes possible. Review changelog before applying."
                if is_major_bump
                else "Same major version upgrade. Lower compatibility risk."
            ),
            "known_vulns_in_alternative": "Not checked — verify against OSV/NVD before applying.",
            "migration_complexity": "high" if is_major_bump else "low",
            "breaking_change_risk": "high" if is_major_bump else "low",
            "license_info": upgrade_info.get("license") if upgrade_info else "Unknown",
            "maintenance_evidence": f"Latest stable release: {safe_upgrade}" if upgrade_info else "Unknown",
            "rationale": (
                f"Upgrade from {package_version} to {safe_upgrade} to address {vulnerability_canonical_id or 'the vulnerability'}."
                if fixed_version_from_advisory
                else f"Upgrade to latest stable {safe_upgrade}. Verify this addresses the vulnerability."
            ),
            "evidence_links": [
                f"https://pypi.org/project/{package_name}/{safe_upgrade}/",
                f"https://osv.dev/list?q={package_name}",
            ],
            "verification_status": "verified" if fixed_version_from_advisory else "candidate",
            "source": "pypi_metadata",
        })
    else:
        alternatives.append({
            "recommendation_type": "no_upgrade_available",
            "label": "No suitable fixed version identified",
            "package_name": package_name,
            "package_version": package_version,
            "recommended_version": None,
            "alternative_package": None,
            "alternative_version": None,
            "compatibility_info": "No stable version newer than the current was found on PyPI.",
            "known_vulns_in_alternative": None,
            "migration_complexity": "unknown",
            "breaking_change_risk": "unknown",
            "license_info": None,
            "maintenance_evidence": None,
            "rationale": (
                "No fixed version could be identified from available metadata. "
                "Check the upstream repository and advisory for patch availability."
            ),
            "evidence_links": [
                f"https://pypi.org/project/{package_name}/",
                f"https://osv.dev/list?q={package_name}",
            ],
            "verification_status": "insufficient_evidence",
            "source": "pypi_metadata",
        })

    return alternatives


async def get_alternatives_for_scan(
    vulnerabilities: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Generate and OSV-verify alternatives for all vulnerabilities in a scan.
    Pre-fetches PyPI versions once per unique package using a single shared HTTP client.
    """
    unique_items = []
    seen = set()
    unique_packages = set()

    for vuln in vulnerabilities:
        pkg = vuln.get("affected_component_name") or vuln.get("package_name", "")
        ver = vuln.get("affected_component_version") or vuln.get("package_version", "")
        canonical_id = vuln.get("canonical_id") or vuln.get("vulnerability_canonical_id")
        fixed_ver = vuln.get("fixed_version")
        key = f"{pkg}@{ver}@{canonical_id}"
        if pkg and ver and key not in seen:
            seen.add(key)
            unique_packages.add(pkg)
            unique_items.append((pkg, ver, canonical_id, fixed_ver))

    if not unique_items:
        return []

    versions_cache: Dict[str, List[str]] = {}
    info_cache: Dict[str, Dict[str, Any]] = {}

    async with httpx.AsyncClient(timeout=8.0) as client:
        sem = asyncio.Semaphore(10)

        # 1. Pre-fetch PyPI release lists ONCE per unique package
        async def _prefetch_versions(pkg_name: str):
            async with sem:
                versions_cache[pkg_name] = await fetch_all_versions(pkg_name, client=client)

        await asyncio.gather(*[_prefetch_versions(p) for p in unique_packages])

        # 2. Pre-fetch info ONCE per unique (pkg, recommended_ver)
        target_info_pairs = set()
        for pkg, ver, _, fixed_ver in unique_items:
            rv = find_safe_upgrade(ver, fixed_ver, versions_cache.get(pkg, []))
            if rv:
                target_info_pairs.add((pkg, rv))

        async def _prefetch_info(pair):
            p_name, p_ver = pair
            async with sem:
                info = await fetch_package_info(p_name, p_ver, client=client)
                if info:
                    info_cache[f"{p_name}@{p_ver}"] = info

        if target_info_pairs:
            await asyncio.gather(*[_prefetch_info(p) for p in target_info_pairs])

        # 3. Build alternatives instantaneously from caches
        all_alternatives: List[Dict[str, Any]] = []
        for pkg, ver, canonical_id, fixed_ver in unique_items:
            try:
                alts = await build_alternatives(
                    pkg, ver, canonical_id, fixed_ver,
                    versions_cache=versions_cache,
                    info_cache=info_cache,
                    client=client,
                )
                for a in alts:
                    a["vulnerability_canonical_id"] = canonical_id
                    all_alternatives.append(a)
            except Exception as exc:
                logger.error("Failed to build alternatives for %s@%s: %s", pkg, ver, exc)

        # 4. Verify recommended versions against OSV ONCE per unique (pkg, recommended_ver)
        if target_info_pairs:
            async def _check_osv(pair):
                p_name, p_ver = pair
                async with sem:
                    try:
                        resp = await client.post(
                            "https://api.osv.dev/v1/query",
                            json={"package": {"name": p_name, "ecosystem": "PyPI"}, "version": p_ver},
                        )
                        if resp.status_code == 200:
                            return pair, len(resp.json().get("vulns", []))
                    except Exception:
                        pass
                    return pair, None

            checked = dict(await asyncio.gather(*[_check_osv(p) for p in target_info_pairs]))
            for a in all_alternatives:
                rv = a.get("recommended_version")
                if rv:
                    cnt = checked.get((a["package_name"], rv))
                    if cnt == 0:
                        a["known_vulns_in_alternative"] = "0 known OSV advisories (verified clean at check time)."
                    elif isinstance(cnt, int) and cnt > 0:
                        a["known_vulns_in_alternative"] = f"Warning: {cnt} OSV advisory/advisories still affect v{rv}; consider latest stable."

    return all_alternatives
