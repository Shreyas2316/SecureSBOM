import json
import re
import tomllib
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urlparse

from packaging.requirements import Requirement, InvalidRequirement
from packaging.utils import canonicalize_name
from packaging.specifiers import SpecifierSet

from app.config import settings


def normalize_package_name(name: str) -> str:
    """Normalize package name according to PEP 503."""
    if not name:
        return ""
    return canonicalize_name(name)


def _is_untrusted_url(line: str) -> bool:
    """Detect direct URLs or VCS references that could be untrusted."""
    lower = line.lower()
    if any(proto in lower for proto in ("http://", "https://", "git+", "hg+", "svn+", "bzr+", "file://")):
        return True
    return False


def _extract_version_and_operator(spec_str: str) -> Tuple[str, str]:
    """Extract primary operator and clean version from a PEP 440 specifier string."""
    if not spec_str:
        return "==", "unknown"
    spec_str = spec_str.strip()
    m = re.match(r"^(===|==|~=|>=|<=|!=|>|<)\s*([A-Za-z0-9_.\-+*!]+)", spec_str)
    if m:
        return m.group(1), m.group(2).strip()
    return "==", "unknown"


def parse_pep508_line(raw_line: str, line_num: int = 0) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Safely parse a single PEP 508 requirement line without executing any code.
    Returns (dependency_dict, warning_or_error_str).
    """
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None, None
    if len(line) > settings.MAX_LINE_LENGTH:
        return None, f"Line {line_num}: exceeds max line length ({settings.MAX_LINE_LENGTH} chars)"
    if line.startswith("-") or line.startswith("--"):
        return None, f"Line {line_num}: pip option '{line.split()[0]}' skipped (not executed)"

    # Strip inline comments
    if " #" in line or line.startswith("#"):
        line = line.split("#", 1)[0].strip()
    elif "#" in line and "://" not in line:
        line = line.split("#", 1)[0].strip()
    if not line:
        return None, None

    # Check untrusted URLs before parsing
    if _is_untrusted_url(line):
        # Allow parsing package name if formatted as `pkg @ https://...` but flag untrusted URL
        if "@" in line:
            pkg_part = line.split("@", 1)[0].strip()
            url_part = line.split("@", 1)[1].strip()
            parsed_url = urlparse(url_part)
            if parsed_url.scheme not in ("https",):
                return None, f"Line {line_num}: rejected untrusted non-HTTPS URL '{url_part}'"
            norm = normalize_package_name(pkg_part)
            return {
                "raw_line": line,
                "name": pkg_part,
                "normalized_name": norm,
                "version": "unknown",
                "declared_specifier": f"@ {url_part}",
                "resolved_version": None,
                "installed_version": None,
                "operator": "@",
                "extras": [],
                "marker": None,
                "marker_satisfied": True,
                "is_direct": True,
                "dependency_depth": 0,
                "source_format": "requirements.txt",
                "warning": "Direct URL dependency; version cannot be deterministically resolved without execution",
            }, f"Line {line_num}: direct URL dependency '{pkg_part}' flagged for manual review"
        return None, f"Line {line_num}: rejected bare URL/VCS requirement '{line}'"

    try:
        req = Requirement(line)
    except InvalidRequirement as exc:
        return None, f"Line {line_num}: malformed requirement '{line}' ({exc})"

    marker_str = str(req.marker) if req.marker else None
    marker_satisfied = True
    if req.marker is not None:
        try:
            marker_satisfied = bool(req.marker.evaluate())
        except Exception:
            marker_satisfied = True

    spec_str = str(req.specifier) if req.specifier else ""
    operator, clean_version = _extract_version_and_operator(spec_str)
    norm_name = normalize_package_name(req.name)

    return {
        "raw_line": line,
        "name": req.name,
        "normalized_name": norm_name,
        "version": clean_version,
        "declared_specifier": spec_str or "unpinned",
        "resolved_version": clean_version if operator in ("==", "===") and clean_version != "unknown" else None,
        "installed_version": None,
        "operator": operator,
        "extras": sorted(list(req.extras)) if req.extras else [],
        "marker": marker_str,
        "marker_satisfied": marker_satisfied,
        "is_direct": True,
        "dependency_depth": 0,
        "source_format": "requirements.txt",
    }, None


def parse_requirements_with_diagnostics(content: str) -> Dict[str, Any]:
    """
    Parse requirements.txt string content safely using PEP 508.
    Returns dict with `dependencies`, `warnings`, `skipped_by_marker`, `format`.
    """
    if len(content.encode("utf-8")) > settings.MAX_MANIFEST_BYTES:
        raise ValueError(f"Manifest exceeds maximum allowed size of {settings.MAX_MANIFEST_BYTES} bytes.")

    dependencies: List[Dict[str, Any]] = []
    warnings: List[str] = []
    skipped_by_marker: List[Dict[str, Any]] = []
    seen: Dict[str, Dict[str, Any]] = {}

    for line_num, raw_line in enumerate(content.splitlines(), 1):
        dep, warn = parse_pep508_line(raw_line, line_num)
        if warn:
            warnings.append(warn)
        if not dep:
            continue

        if not dep["marker_satisfied"]:
            skipped_by_marker.append(dep)
            continue

        norm = dep["normalized_name"]
        if norm in seen:
            # Merge/prefer pinned specifier over unpinned
            existing = seen[norm]
            if existing["version"] == "unknown" and dep["version"] != "unknown":
                seen[norm] = dep
            warnings.append(f"Line {line_num}: duplicate dependency '{dep['name']}' merged")
        else:
            seen[norm] = dep

    dependencies = list(seen.values())
    return {
        "dependencies": dependencies,
        "warnings": warnings,
        "skipped_by_marker": skipped_by_marker,
        "format": "requirements.txt",
    }


def parse_requirements(content: str) -> List[Dict[str, Any]]:
    """
    Backward-compatible requirements.txt parser returning list of dependency dicts.
    """
    return parse_requirements_with_diagnostics(content)["dependencies"]


def _poetry_spec_to_pep508(name: str, spec: Any) -> str:
    if isinstance(spec, str):
        s = spec.strip()
        if s == "*" or not s:
            return name
        if s.startswith("^"):
            ver = s[1:].strip()
            parts = ver.split(".")
            if len(parts) >= 1 and parts[0].isdigit():
                major = int(parts[0])
                if major > 0:
                    return f"{name}>={ver},<{major + 1}.0.0"
                elif len(parts) >= 2 and parts[1].isdigit():
                    minor = int(parts[1])
                    return f"{name}>={ver},<0.{minor + 1}.0"
            return f"{name}>={ver}"
        if s.startswith("~"):
            ver = s[1:].strip()
            return f"{name}~={ver}"
        if re.match(r"^[0-9]", s):
            return f"{name}=={s}"
        return f"{name}{s}"
    if isinstance(spec, dict):
        ver = spec.get("version", "")
        return _poetry_spec_to_pep508(name, ver) if isinstance(ver, str) else name
    return name


def parse_pyproject_toml(content: str) -> Dict[str, Any]:
    """Parse PEP 621 [project.dependencies] and [tool.poetry.dependencies] from pyproject.toml."""
    data = tomllib.loads(content)
    lines: List[str] = []

    project = data.get("project", {})
    for req_str in project.get("dependencies", []) or []:
        if isinstance(req_str, str):
            lines.append(req_str)

    poetry = data.get("tool", {}).get("poetry", {})
    for pkg_name, spec in (poetry.get("dependencies", {}) or {}).items():
        if pkg_name.lower() == "python":
            continue
        lines.append(_poetry_spec_to_pep508(pkg_name, spec))

    res = parse_requirements_with_diagnostics("\n".join(lines))
    for d in res["dependencies"]:
        d["source_format"] = "pyproject.toml"
    res["format"] = "pyproject.toml"
    return res


def parse_poetry_lock(content: str) -> Dict[str, Any]:
    """Parse poetry.lock TOML file with exact locked package versions."""
    data = tomllib.loads(content)
    packages = data.get("package", []) or []
    dependencies: List[Dict[str, Any]] = []
    warnings: List[str] = []

    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version:
            continue
        norm = normalize_package_name(name)
        category = pkg.get("category", "main")
        dependencies.append({
            "raw_line": f"{name}=={version}",
            "name": name,
            "normalized_name": norm,
            "version": str(version),
            "declared_specifier": f"=={version}",
            "resolved_version": str(version),
            "installed_version": None,
            "operator": "==",
            "extras": [],
            "marker": None,
            "marker_satisfied": True,
            "is_direct": category == "main",
            "dependency_depth": 0 if category == "main" else 1,
            "purl": f"pkg:pypi/{norm}@{version}",
            "source_format": "poetry.lock",
        })

    return {
        "dependencies": dependencies,
        "warnings": warnings,
        "skipped_by_marker": [],
        "format": "poetry.lock",
    }


def parse_pipfile_lock(content: str) -> Dict[str, Any]:
    """Parse Pipfile.lock JSON file with exact locked package versions."""
    data = json.loads(content)
    dependencies: List[Dict[str, Any]] = []
    warnings: List[str] = []

    for section in ("default", "develop"):
        pkgs = data.get(section, {}) or {}
        for name, meta in pkgs.items():
            ver_spec = (meta or {}).get("version", "")
            ver = ver_spec.lstrip("=").strip() if ver_spec else "unknown"
            norm = normalize_package_name(name)
            dependencies.append({
                "raw_line": f"{name}{ver_spec}",
                "name": name,
                "normalized_name": norm,
                "version": ver,
                "declared_specifier": ver_spec or "unpinned",
                "resolved_version": ver if ver != "unknown" else None,
                "installed_version": None,
                "operator": "==",
                "extras": (meta or {}).get("extras", []),
                "marker": (meta or {}).get("markers"),
                "marker_satisfied": True,
                "is_direct": section == "default",
                "dependency_depth": 0 if section == "default" else 1,
                "purl": f"pkg:pypi/{norm}@{ver}" if ver != "unknown" else f"pkg:pypi/{norm}",
                "source_format": "Pipfile.lock",
            })

    return {
        "dependencies": dependencies,
        "warnings": warnings,
        "skipped_by_marker": [],
        "format": "Pipfile.lock",
    }


def parse_cyclonedx_sbom_import(content: str) -> Dict[str, Any]:
    """Import an existing CycloneDX JSON SBOM document."""
    data = json.loads(content)
    if data.get("bomFormat") != "CycloneDX":
        raise ValueError("Invalid CycloneDX SBOM: missing bomFormat == 'CycloneDX'")

    dependencies: List[Dict[str, Any]] = []
    warnings: List[str] = []

    for comp in data.get("components", []) or []:
        name = comp.get("name")
        if not name:
            continue
        version = comp.get("version") or "unknown"
        norm = normalize_package_name(name)
        purl = comp.get("purl") or (f"pkg:pypi/{norm}@{version}" if version != "unknown" else f"pkg:pypi/{norm}")
        props = {p.get("name"): p.get("value") for p in comp.get("properties", []) or [] if isinstance(p, dict)}
        is_direct = props.get("securesbom:is_direct", "true").lower() == "true"
        depth = int(props.get("securesbom:depth", 0)) if str(props.get("securesbom:depth", "0")).isdigit() else 0

        dependencies.append({
            "raw_line": f"{name}=={version}",
            "name": name,
            "normalized_name": norm,
            "version": version,
            "declared_specifier": f"=={version}" if version != "unknown" else "unpinned",
            "resolved_version": version if version != "unknown" else None,
            "installed_version": version if version != "unknown" else None,
            "operator": "==",
            "extras": [],
            "marker": None,
            "marker_satisfied": True,
            "is_direct": is_direct,
            "dependency_depth": depth,
            "purl": purl,
            "source_format": "cyclonedx",
        })

    return {
        "dependencies": dependencies,
        "warnings": warnings,
        "skipped_by_marker": [],
        "format": "cyclonedx",
    }


def parse_manifest(content: str, filename: str = "requirements.txt") -> Dict[str, Any]:
    """
    Auto-detect or dispatch manifest parsing based on filename and content.
    Supports requirements.txt, pyproject.toml, poetry.lock, Pipfile.lock, and CycloneDX JSON.
    """
    if len(content.encode("utf-8")) > settings.MAX_MANIFEST_BYTES:
        raise ValueError(f"Manifest exceeds maximum allowed size of {settings.MAX_MANIFEST_BYTES} bytes.")

    fname = (filename or "requirements.txt").lower().strip()
    stripped = content.lstrip()

    if fname.endswith("pyproject.toml"):
        return parse_pyproject_toml(content)
    if fname.endswith("poetry.lock"):
        return parse_poetry_lock(content)
    if fname.endswith("pipfile.lock"):
        return parse_pipfile_lock(content)
    if fname.endswith(".json") or stripped.startswith("{"):
        try:
            data = json.loads(content)
            if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
                return parse_cyclonedx_sbom_import(content)
            if isinstance(data, dict) and ("default" in data or "_meta" in data):
                return parse_pipfile_lock(content)
        except json.JSONDecodeError:
            pass

    return parse_requirements_with_diagnostics(content)
