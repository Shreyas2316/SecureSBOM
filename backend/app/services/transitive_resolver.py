import re
import logging
import httpx
from typing import List, Dict, Any, Set, Tuple
from app.services.dependency_parser import normalize_package_name

logger = logging.getLogger("securesbom.transitive")

PYPI_CACHE: Dict[str, Dict[str, Any]] = {}

def parse_requires_dist(req_str: str) -> Tuple[str, str]:
    """Parse PyPI requires_dist string into (package_name, version_specifier)."""
    # Remove environment markers like ; extra == 'security' or ; python_version < '3.8'
    clean_req = req_str.split(";")[0].strip()
    match = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(.*)$", clean_req)
    if match:
        name = match.group(1).strip()
        spec = match.group(2).strip()
        # Extract version if pinned like (==1.2.3) or ==1.2.3
        v_match = re.search(r"(?:==|>=|~=)\s*([A-Za-z0-9_.\-+*]+)", spec)
        version = v_match.group(1) if v_match else "unknown"
        return name, version
    return clean_req, "unknown"

async def fetch_pypi_metadata(client: httpx.AsyncClient, name: str, version: str) -> Dict[str, Any]:
    """Fetch PyPI metadata for a package/version without executing any code."""
    cache_key = f"{normalize_package_name(name)}:{version}"
    if cache_key in PYPI_CACHE:
        return PYPI_CACHE[cache_key]

    url = f"https://pypi.org/pypi/{name}/json" if version == "unknown" or not version else f"https://pypi.org/pypi/{name}/{version}/json"
    
    try:
        response = await client.get(url, timeout=5.0, follow_redirects=True)
        if response.status_code == 200:
            data = response.json()
            PYPI_CACHE[cache_key] = data
            return data
    except Exception as e:
        logger.warning(f"PyPI API metadata fetch failed for {name}=={version}: {str(e)}")

    PYPI_CACHE[cache_key] = {}
    return {}

async def resolve_transitive_dependencies(direct_deps: List[Dict[str, Any]], max_depth: int = 2) -> List[Dict[str, Any]]:
    """
    Resolve transitive dependencies by parsing PyPI JSON metadata `requires_dist`.
    Returns complete list of direct and transitive components with PURL and depth.
    Guarantees no external code execution.
    """
    all_components: List[Dict[str, Any]] = []
    visited: Set[str] = set()

    # Step 1: Add direct dependencies
    for dep in direct_deps:
        norm_name = normalize_package_name(dep["name"])
        key = f"{norm_name}:{dep['version']}"
        visited.add(norm_name)
        
        dep["purl"] = f"pkg:pypi/{norm_name}@{dep['version']}" if dep['version'] != "unknown" else f"pkg:pypi/{norm_name}"
        all_components.append(dep)

    # Step 2: Fetch transitive dependencies via PyPI metadata
    async with httpx.AsyncClient() as client:
        current_level = list(direct_deps)
        for depth in range(1, max_depth + 1):
            next_level = []
            for dep in current_level:
                meta = await fetch_pypi_metadata(client, dep["name"], dep["version"])
                info = meta.get("info", {})
                
                # Update version if was unknown
                if dep["version"] == "unknown" and info.get("version"):
                    dep["version"] = info.get("version")
                    dep["purl"] = f"pkg:pypi/{dep['normalized_name']}@{dep['version']}"

                requires_dist = info.get("requires_dist") or []
                for req in requires_dist:
                    # Ignore optional extras requirement
                    if "extra ==" in req:
                        continue
                    
                    sub_name, sub_ver = parse_requires_dist(req)
                    sub_norm = normalize_package_name(sub_name)

                    if sub_norm not in visited and sub_norm:
                        visited.add(sub_norm)
                        transitive_item = {
                            "raw_line": f"{sub_name}=={sub_ver}",
                            "name": sub_name,
                            "normalized_name": sub_norm,
                            "version": sub_ver,
                            "operator": "==",
                            "is_direct": False,
                            "dependency_depth": depth,
                            "purl": f"pkg:pypi/{sub_norm}@{sub_ver}" if sub_ver != "unknown" else f"pkg:pypi/{sub_norm}"
                        }
                        all_components.append(transitive_item)
                        next_level.append(transitive_item)

            current_level = next_level
            if not current_level:
                break

    return all_components
