import re
import importlib.metadata
import logging
from typing import List, Tuple, Set, Optional, Dict, Any
from packaging.requirements import Requirement, InvalidRequirement
from packaging.specifiers import SpecifierSet
from packaging.version import parse as parse_version, InvalidVersion
import httpx

from backend.models import DependencySpec, ResolvedDependency

logger = logging.getLogger(__name__)

MAX_MANIFEST_SIZE_BYTES = 2 * 1024 * 1024  # 2MB
MAX_LINE_LENGTH = 1000

# In-memory cache for PyPI queries to prevent duplicate network requests
_PYPI_CACHE: Dict[str, Dict[str, Any]] = {}


def normalize_package_name(name: str) -> str:
    """Normalizes PyPI package names per PEP 503 (lowercase, dashes for underscores/dots)."""
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def build_purl(name: str, version: str) -> str:
    """Constructs a standard Package URL (PURL) for PyPI ecosystem."""
    norm_name = normalize_package_name(name)
    ver = version if version and version != "unknown" else "unpinned"
    return f"pkg:pypi/{norm_name}@{ver}"


def validate_and_parse_requirements_txt(content: str) -> Tuple[List[DependencySpec], List[str]]:
    """
    Parses raw content of a requirements.txt file into structured DependencySpec items
    and returns detected validation warnings or syntax errors.
    
    Returns:
    - specs: List[DependencySpec]
    - validation_errors: List[str]
    """
    if len(content.encode("utf-8")) > MAX_MANIFEST_SIZE_BYTES:
        raise ValueError(f"Uploaded manifest exceeds maximum allowed size of {MAX_MANIFEST_SIZE_BYTES // (1024*1024)}MB.")

    specs: List[DependencySpec] = []
    validation_errors: List[str] = []
    
    lines = content.splitlines()
    for idx, raw_line in enumerate(lines, start=1):
        if len(raw_line) > MAX_LINE_LENGTH:
            validation_errors.append(f"Line {idx}: Exceeds maximum line length of {MAX_LINE_LENGTH} characters.")
            continue

        line = raw_line.strip()
        
        # Skip empty lines and comment lines
        if not line or line.startswith("#"):
            continue
            
        # Ignore pip flag options safely
        if line.startswith("-") or line.startswith("--"):
            continue
            
        # Strip inline comments
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        elif "\t#" in line:
            line = line.split("\t#", 1)[0].strip()
            
        try:
            req = Requirement(line)
            pkg_name = req.name
            specifier = str(req.specifier) if req.specifier else ""
            
            specs.append(DependencySpec(
                name=pkg_name,
                specifier=specifier,
                raw_line=raw_line,
                is_direct=True,
                line_number=idx
            ))
        except InvalidRequirement as e:
            # Fallback regex parser for lines PEP 508 parser might reject
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([~=><!]=?.*)?$", line)
            if match:
                pkg_name = match.group(1)
                specifier = match.group(2) if match.group(2) else ""
                specs.append(DependencySpec(
                    name=pkg_name,
                    specifier=specifier,
                    raw_line=raw_line,
                    is_direct=True,
                    line_number=idx
                ))
            else:
                validation_errors.append(f"Line {idx}: Invalid dependency specification '{line}': {str(e)}")

    return specs, validation_errors


def parse_requirements_txt(content: str, return_errors: bool = False) -> Any:
    """
    Parses raw content of a requirements.txt file.
    If return_errors is False (default), returns List[DependencySpec] for backward compatibility.
    If return_errors is True, returns Tuple[List[DependencySpec], List[str]].
    """
    specs, errors = validate_and_parse_requirements_txt(content)
    if return_errors:
        return specs, errors
    return specs


def resolve_local_environment(pkg_name: str) -> Tuple[Optional[str], List[str]]:
    """Checks if a package is installed in the local Python environment."""
    norm_name = normalize_package_name(pkg_name)
    try:
        installed_ver = importlib.metadata.version(norm_name)
        transitive_req_names: List[str] = []
        requires = importlib.metadata.requires(norm_name)
        if requires:
            for req_str in requires:
                try:
                    req_clean = req_str.split(";")[0].strip()
                    parsed_req = Requirement(req_clean)
                    transitive_req_names.append(parsed_req.name)
                except InvalidRequirement:
                    continue
        return installed_ver, transitive_req_names
    except (importlib.metadata.PackageNotFoundError, ValueError):
        return None, []


async def fetch_pypi_metadata(client: httpx.AsyncClient, pkg_name: str) -> Optional[Dict[str, Any]]:
    """Fetches package metadata and release info from official PyPI JSON API with caching."""
    norm_name = normalize_package_name(pkg_name)
    if norm_name in _PYPI_CACHE:
        return _PYPI_CACHE[norm_name]

    url = f"https://pypi.org/pypi/{norm_name}/json"
    try:
        resp = await client.get(url, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            _PYPI_CACHE[norm_name] = data
            return data
    except Exception as e:
        logger.debug(f"PyPI JSON API fetch failed for {norm_name}: {str(e)}")
        
    return None


def select_best_pypi_version(pypi_data: Dict[str, Any], specifier_str: str) -> Tuple[Optional[str], List[str]]:
    """
    Selects the best matching release version and its requirements from PyPI metadata.
    """
    info = pypi_data.get("info", {})
    releases = list(pypi_data.get("releases", {}).keys())
    
    # Extract requires_dist for transitive requirements
    raw_requires = info.get("requires_dist") or []
    transitive_names: List[str] = []
    for req_str in raw_requires:
        try:
            req_clean = req_str.split(";")[0].strip()
            parsed = Requirement(req_clean)
            transitive_names.append(parsed.name)
        except Exception:
            continue

    if not specifier_str:
        # Return latest stable version
        latest_ver = info.get("version")
        return latest_ver, transitive_names

    try:
        spec_set = SpecifierSet(specifier_str)
        # Sort valid versions descending
        valid_versions = []
        for r in releases:
            try:
                v = parse_version(r)
                if not v.is_prerelease and v in spec_set:
                    valid_versions.append(v)
            except InvalidVersion:
                continue
                
        if valid_versions:
            valid_versions.sort(reverse=True)
            return str(valid_versions[0]), transitive_names
            
    except Exception:
        pass

    # Fallback to info version
    return info.get("version"), transitive_names


async def resolve_dependencies_async(
    specs: List[DependencySpec]
) -> Tuple[List[ResolvedDependency], List[str]]:
    """
    Resolves dependencies using local environment + live PyPI metadata resolution.
    
    Guarantees:
    - Never presents an unresolved constraint (e.g. '>=2.11.0') as a concrete installed version.
    - Accurately tags resolution status and direct vs transitive.
    - Preserves dependency tree relationships.
    - Returns resolution warnings for unresolvable packages.
    """
    resolved_map: Dict[str, ResolvedDependency] = {}
    pending_transitive: Set[str] = set()
    resolution_warnings: List[str] = []

    async with httpx.AsyncClient() as client:
        # 1. Process direct dependencies
        for spec in specs:
            norm_name = normalize_package_name(spec.name)
            version = "unresolved"
            is_resolved = False
            resolution_status = "unresolved"
            transitive_children: List[str] = []

            # Case A: pinned exact version ==X.Y.Z
            if spec.specifier and spec.specifier.startswith("=="):
                version = spec.specifier.lstrip("=").strip()
                is_resolved = True
                resolution_status = "resolved"
                # Check transitive locally or on PyPI
                local_v, local_trans = resolve_local_environment(spec.name)
                if local_trans:
                    transitive_children = local_trans
                else:
                    pypi_data = await fetch_pypi_metadata(client, spec.name)
                    if pypi_data:
                        _, pypi_trans = select_best_pypi_version(pypi_data, spec.specifier)
                        transitive_children = pypi_trans

            # Case B: Ranged or unpinned - check local installed first
            else:
                local_v, local_trans = resolve_local_environment(spec.name)
                if local_v:
                    # Verify if installed version satisfies specifier
                    if spec.specifier:
                        try:
                            if parse_version(local_v) in SpecifierSet(spec.specifier):
                                version = local_v
                                is_resolved = True
                                resolution_status = "local_environment"
                                transitive_children = local_trans
                        except Exception:
                            version = local_v
                            is_resolved = True
                            resolution_status = "local_environment"
                            transitive_children = local_trans
                    else:
                        version = local_v
                        is_resolved = True
                        resolution_status = "local_environment"
                        transitive_children = local_trans

                # Case C: Not local - query PyPI JSON API
                if not is_resolved:
                    pypi_data = await fetch_pypi_metadata(client, spec.name)
                    if pypi_data:
                        best_v, pypi_trans = select_best_pypi_version(pypi_data, spec.specifier)
                        if best_v:
                            version = best_v
                            is_resolved = True
                            resolution_status = "resolved"
                            transitive_children = pypi_trans

                if not is_resolved:
                    resolution_warnings.append(
                        f"Could not resolve concrete version for '{spec.name}' with constraint '{spec.specifier}'. Marked as unresolved."
                    )

            purl = build_purl(spec.name, version if is_resolved else "")
            
            resolved_map[norm_name] = ResolvedDependency(
                name=spec.name,
                version=version,
                purl=purl,
                is_direct=True,
                transitive_dependencies=transitive_children,
                declared_specifier=spec.specifier,
                is_resolved=is_resolved,
                resolution_status=resolution_status
            )

            for t_name in transitive_children:
                norm_t = normalize_package_name(t_name)
                if norm_t not in resolved_map:
                    pending_transitive.add(t_name)

        # 2. Process discovered transitive dependencies
        for t_name in pending_transitive:
            norm_t = normalize_package_name(t_name)
            if norm_t in resolved_map:
                continue

            local_v, local_trans = resolve_local_environment(t_name)
            if local_v:
                t_ver = local_v
                t_resolved = True
                t_status = "local_environment"
                sub_trans = local_trans
            else:
                pypi_data = await fetch_pypi_metadata(client, t_name)
                if pypi_data:
                    best_v, pypi_trans = select_best_pypi_version(pypi_data, "")
                    t_ver = best_v or "unresolved"
                    t_resolved = bool(best_v)
                    t_status = "resolved" if best_v else "unresolved"
                    sub_trans = pypi_trans
                else:
                    t_ver = "unresolved"
                    t_resolved = False
                    t_status = "unresolved"
                    sub_trans = []

            t_purl = build_purl(t_name, t_ver if t_resolved else "")
            resolved_map[norm_t] = ResolvedDependency(
                name=t_name,
                version=t_ver,
                purl=t_purl,
                is_direct=False,
                transitive_dependencies=sub_trans,
                declared_specifier="",
                is_resolved=t_resolved,
                resolution_status=t_status
            )

    return list(resolved_map.values()), resolution_warnings


def resolve_dependencies(specs: List[DependencySpec]) -> List[ResolvedDependency]:
    """
    Synchronous resolution helper preserved for backward compatibility.
    """
    import asyncio
    try:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import nest_asyncio
            nest_asyncio.apply()
            deps, _ = loop.run_until_complete(resolve_dependencies_async(specs))
            return deps
        else:
            deps, _ = asyncio.run(resolve_dependencies_async(specs))
            return deps
    except Exception:
        # Synchronous fallback without network
        resolved: List[ResolvedDependency] = []
        for spec in specs:
            norm_name = normalize_package_name(spec.name)
            if spec.specifier and spec.specifier.startswith("=="):
                ver = spec.specifier.lstrip("=").strip()
                status = "resolved"
                is_res = True
            else:
                loc_v, loc_trans = resolve_local_environment(spec.name)
                if loc_v:
                    ver = loc_v
                    status = "local_environment"
                    is_res = True
                else:
                    ver = "unresolved"
                    status = "unresolved"
                    is_res = False

            resolved.append(ResolvedDependency(
                name=spec.name,
                version=ver,
                purl=build_purl(spec.name, ver if is_res else ""),
                is_direct=True,
                transitive_dependencies=[],
                declared_specifier=spec.specifier,
                is_resolved=is_res,
                resolution_status=status
            ))
        return resolved
