import asyncio
import logging
import httpx
from typing import List, Dict, Any, Set, Tuple, Optional

from packaging.requirements import Requirement, InvalidRequirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version, InvalidVersion

from app.config import settings
from app.services.dependency_parser import normalize_package_name

logger = logging.getLogger("securesbom.transitive")

PYPI_CACHE: Dict[str, Dict[str, Any]] = {}


def parse_requires_dist(req_str: str, active_extras: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
    """
    Parse PyPI requires_dist string using PEP 508.
    Evaluates environment markers accurately instead of silently discarding them.
    Returns None if marker is not satisfied for current environment/extras.
    """
    try:
        req = Requirement(req_str)
    except InvalidRequirement:
        return None

    if req.marker is not None:
        # Evaluate against each active extra or default environment
        if active_extras:
            matched = any(req.marker.evaluate({"extra": ex}) for ex in active_extras)
            if not matched and not req.marker.evaluate({"extra": ""}):
                return None
        else:
            try:
                if not req.marker.evaluate():
                    return None
            except Exception:
                # Marker may reference 'extra' without default; skip optional extra
                if "extra" in str(req.marker):
                    return None

    spec_str = str(req.specifier) if req.specifier else ""
    return {
        "name": req.name,
        "normalized_name": normalize_package_name(req.name),
        "specifier": spec_str,
        "extras": sorted(list(req.extras)) if req.extras else [],
        "marker": str(req.marker) if req.marker else None,
    }


async def fetch_pypi_metadata(client: httpx.AsyncClient, name: str, version: str = "unknown") -> Dict[str, Any]:
    """Fetch version-specific PyPI metadata without executing any code."""
    norm = normalize_package_name(name)
    is_exact = bool(version and version not in ("unknown", "unpinned", "unresolved"))
    cache_key = f"{norm}:{version if is_exact else 'latest'}"
    if cache_key in PYPI_CACHE:
        return PYPI_CACHE[cache_key]

    url = (
        f"https://pypi.org/pypi/{norm}/{version}/json"
        if is_exact
        else f"https://pypi.org/pypi/{norm}/json"
    )

    try:
        response = await client.get(url, timeout=6.0, follow_redirects=True)
        if response.status_code == 200:
            data = response.json()
            PYPI_CACHE[cache_key] = data
            return data
        if is_exact and response.status_code == 404:
            # Fallback to package-level JSON if exact version URL 404s
            fallback_resp = await client.get(f"https://pypi.org/pypi/{norm}/json", timeout=6.0, follow_redirects=True)
            if fallback_resp.status_code == 200:
                data = fallback_resp.json()
                PYPI_CACHE[cache_key] = data
                return data
    except Exception as e:
        logger.warning("PyPI API metadata fetch failed for %s@%s: %s", name, version, e)

    PYPI_CACHE[cache_key] = {}
    return {}


def resolve_version_from_pypi_releases(pkg_data: Dict[str, Any], specifier_str: str) -> Optional[str]:
    """
    Given PyPI package JSON and a PEP 440 specifier, select the highest matching
    non-yanked, non-prerelease version.
    """
    releases = pkg_data.get("releases", {})
    if not releases:
        return pkg_data.get("info", {}).get("version")

    try:
        spec = SpecifierSet(specifier_str) if specifier_str else SpecifierSet("")
    except Exception:
        return pkg_data.get("info", {}).get("version")

    candidates: List[Version] = []
    for ver_str, files in releases.items():
        try:
            v = Version(ver_str)
            if v.is_prerelease or v.is_devrelease:
                continue
            if files and all(f.get("yanked", False) for f in files):
                continue
            if v in spec:
                candidates.append(v)
        except InvalidVersion:
            continue

    if candidates:
        return str(max(candidates))
    return None


async def resolve_transitive_dependencies(
    direct_deps: List[Dict[str, Any]],
    max_depth: Optional[int] = None,
    max_components: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Resolve transitive dependencies by parsing PyPI JSON metadata `requires_dist`.
    Uses version-specific metadata, PEP 440 specifier resolution, cycle detection,
    and configurable depth/component limits. Guarantees zero code execution.
    """
    depth_limit = max_depth if max_depth is not None else settings.TRANSITIVE_MAX_DEPTH
    comp_limit = max_components if max_components is not None else settings.TRANSITIVE_MAX_COMPONENTS

    all_components: List[Dict[str, Any]] = []
    visited: Set[str] = set()
    active_path: Set[str] = set()

    for dep in direct_deps:
        norm_name = normalize_package_name(dep["name"])
        if not norm_name or norm_name in visited:
            continue
        visited.add(norm_name)

        ver = dep.get("version") or "unknown"
        dep.setdefault("normalized_name", norm_name)
        dep.setdefault("declared_specifier", dep.get("raw_line", ""))
        dep.setdefault("resolution_status", "resolved" if ver != "unknown" else "pending")
        dep["purl"] = f"pkg:pypi/{norm_name}@{ver}" if ver != "unknown" else f"pkg:pypi/{norm_name}"
        all_components.append(dep)
        if len(all_components) >= comp_limit:
            break

    # Skip network resolution if already pre-resolved from lockfile or SBOM import
    if all(d.get("source_format") in ("poetry.lock", "Pipfile.lock", "cyclonedx") for d in all_components) and all_components:
        for d in all_components:
            d["resolution_status"] = "resolved" if d.get("version") != "unknown" else "unresolved"
        return all_components

    async with httpx.AsyncClient() as client:
        sem = asyncio.Semaphore(10)

        async def _bounded_fetch(p_name: str, p_ver: str) -> Dict[str, Any]:
            async with sem:
                return await fetch_pypi_metadata(client, p_name, p_ver)

        current_level = list(all_components)
        for depth in range(1, depth_limit + 1):
            if len(all_components) >= comp_limit:
                break
            next_level: List[Dict[str, Any]] = []

            # Pre-fetch package metadata in parallel for this level
            await asyncio.gather(*[
                _bounded_fetch(d["name"], "unknown" if (d.get("operator", "==") != "==" or d.get("version", "unknown") == "unknown") else d["version"])
                for d in current_level
            ])

            for dep in current_level:
                if len(all_components) >= comp_limit:
                    break

                dep_norm = dep["normalized_name"]
                active_path.add(dep_norm)

                # If range specifier (not exact ==), resolve concrete version from PyPI first
                query_ver = dep.get("version", "unknown")
                operator = dep.get("operator", "==")
                declared_spec = dep.get("declared_specifier", "")

                if operator != "==" or query_ver == "unknown":
                    pkg_meta = await fetch_pypi_metadata(client, dep["name"], "unknown")
                    if pkg_meta:
                        resolved_ver = resolve_version_from_pypi_releases(pkg_meta, declared_spec if declared_spec != "unpinned" else "")
                        if resolved_ver:
                            dep["version"] = resolved_ver
                            dep["resolved_version"] = resolved_ver
                            dep["resolution_status"] = "resolved"
                            dep["purl"] = f"pkg:pypi/{dep_norm}@{resolved_ver}"
                            query_ver = resolved_ver
                        else:
                            dep["resolution_status"] = "unresolved"
                    else:
                        dep["resolution_status"] = "unresolved"

                meta = await fetch_pypi_metadata(client, dep["name"], query_ver)
                info = meta.get("info", {})
                if not info:
                    if dep.get("resolution_status") == "pending":
                        dep["resolution_status"] = "unresolved"
                    active_path.discard(dep_norm)
                    continue

                if dep.get("version") == "unknown" and info.get("version"):
                    dep["version"] = info["version"]
                    dep["resolved_version"] = info["version"]
                    dep["resolution_status"] = "resolved"
                    dep["purl"] = f"pkg:pypi/{dep_norm}@{dep['version']}"
                elif dep.get("resolution_status") == "pending":
                    dep["resolution_status"] = "resolved"

                requires_dist = info.get("requires_dist") or []
                for req_str in requires_dist:
                    if len(all_components) >= comp_limit:
                        break
                    parsed_sub = parse_requires_dist(req_str, active_extras=dep.get("extras"))
                    if not parsed_sub:
                        continue

                    sub_norm = parsed_sub["normalized_name"]
                    if not sub_norm:
                        continue
                    if sub_norm in active_path:
                        # Cycle detected; do not recurse infinitely
                        continue
                    if sub_norm in visited:
                        continue

                    visited.add(sub_norm)
                    sub_meta = await fetch_pypi_metadata(client, parsed_sub["name"], "unknown")
                    sub_ver = "unknown"
                    sub_status = "unresolved"
                    if sub_meta:
                        rv = resolve_version_from_pypi_releases(sub_meta, parsed_sub["specifier"])
                        if rv:
                            sub_ver = rv
                            sub_status = "resolved"

                    transitive_item = {
                        "raw_line": f"{parsed_sub['name']}{parsed_sub['specifier']}",
                        "name": parsed_sub["name"],
                        "normalized_name": sub_norm,
                        "version": sub_ver,
                        "declared_specifier": parsed_sub["specifier"] or "unpinned",
                        "resolved_version": sub_ver if sub_ver != "unknown" else None,
                        "installed_version": None,
                        "operator": "==",
                        "extras": parsed_sub["extras"],
                        "marker": parsed_sub["marker"],
                        "marker_satisfied": True,
                        "is_direct": False,
                        "dependency_depth": depth,
                        "resolution_status": sub_status,
                        "purl": f"pkg:pypi/{sub_norm}@{sub_ver}" if sub_ver != "unknown" else f"pkg:pypi/{sub_norm}",
                    }
                    all_components.append(transitive_item)
                    next_level.append(transitive_item)

                active_path.discard(dep_norm)

            current_level = next_level
            if not current_level:
                break

    return all_components
