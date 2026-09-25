import re
from typing import List, Dict, Any, Tuple

def normalize_package_name(name: str) -> str:
    """Normalize package name according to PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()

def parse_requirements(content: str) -> List[Dict[str, Any]]:
    """
    Parse requirements.txt string content safely.
    Extracts direct dependencies: name, normalized_name, version, specifier.
    Does NOT execute any code or shell commands.
    """
    dependencies = []
    lines = content.splitlines()

    for line_num, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        # Skip empty lines, comments, and pip options
        if not line or line.startswith("#") or line.startswith("-") or line.startswith("--"):
            continue
        
        # Remove inline comments
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if not line:
            continue

        # Remove environment markers like ; python_version >= '3.8'
        if ";" in line:
            line = line.split(";", 1)[0].strip()

        # Parse package name and version specifier
        # Regexp for package name with optional extras [extra]
        pattern = r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9_.\-+*]+)?"
        match = re.match(pattern, line)
        
        if match:
            pkg_name = match.group(1).strip()
            operator = match.group(2)
            version = match.group(3)

            norm_name = normalize_package_name(pkg_name)
            
            clean_version = version.strip() if version else "unknown"
            
            dependencies.append({
                "raw_line": line,
                "name": pkg_name,
                "normalized_name": norm_name,
                "version": clean_version,
                "operator": operator or "==",
                "is_direct": True,
                "dependency_depth": 0
            })

    return dependencies
