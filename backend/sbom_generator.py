import os
import json
import uuid
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional, Union

from cyclonedx.validation import make_schemabased_validator
from cyclonedx.schema import SchemaVersion, OutputFormat
from backend.models import ResolvedDependency
from backend.dependency_parser import normalize_package_name, build_purl

logger = logging.getLogger(__name__)


def validate_cyclonedx_sbom(sbom_data: Union[Dict[str, Any], str]) -> Tuple[bool, Optional[str]]:
    """
    Validates a CycloneDX JSON document against official CycloneDX v1.5 JSON schema.
    
    Returns:
    - (True, None) if validation succeeds
    - (False, error_message) if validation fails
    """
    try:
        validator = make_schemabased_validator(OutputFormat.JSON, SchemaVersion.V1_5)
        raw_json = json.dumps(sbom_data) if isinstance(sbom_data, dict) else sbom_data
        validation_error = validator.validate_str(raw_json)
        if validation_error is None:
            return True, None
        return False, str(validation_error)
    except Exception as e:
        logger.error(f"CycloneDX validation execution error: {str(e)}")
        return False, str(e)


def generate_cyclonedx_sbom(
    resolved_deps: List[ResolvedDependency],
    project_name: str = "Python Application Requirements",
    project_version: str = "0.1.0"
) -> Dict[str, Any]:
    """
    Generates a valid CycloneDX v1.5 JSON Software Bill of Materials (SBOM).
    
    Structure adheres to the official OWASP CycloneDX v1.5 Specification:
    - bomFormat: "CycloneDX"
    - specVersion: "1.5"
    - serialNumber: urn:uuid format (RFC 4122)
    - metadata: tool info, timestamp, root application component
    - components: package details with PURLs and bom-refs
    - dependencies: dependency graph linking parent and transitive components
    """
    bom_ref_map: Dict[str, str] = {}
    components: List[Dict[str, Any]] = []
    
    # First pass: map components and assign unique bom-refs
    for dep in resolved_deps:
        norm_name = normalize_package_name(dep.name)
        ver_str = dep.version if dep.version and dep.version not in ("unknown", "unpinned", "unresolved") else ""
        purl = build_purl(dep.name, dep.version)
        bom_ref = purl
        bom_ref_map[norm_name] = bom_ref
        
        comp_dict: Dict[str, Any] = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": dep.name,
            "version": ver_str or "0.0.0",
            "purl": purl,
            "scope": "required" if dep.is_direct else "optional",
            "description": f"Python package {dep.name}",
            "properties": [
                {
                    "name": "dependency:direct",
                    "value": "true" if dep.is_direct else "false"
                }
            ]
        }
        components.append(comp_dict)
        
    # Second pass: construct dependency graph array
    dependencies_graph: List[Dict[str, Any]] = []
    for dep in resolved_deps:
        norm_name = normalize_package_name(dep.name)
        parent_ref = bom_ref_map.get(norm_name, dep.purl)
        
        child_refs: List[str] = []
        for child_name in dep.transitive_dependencies:
            norm_child = normalize_package_name(child_name)
            if norm_child in bom_ref_map and bom_ref_map[norm_child] != parent_ref:
                child_refs.append(bom_ref_map[norm_child])
                
        dependencies_graph.append({
            "ref": parent_ref,
            "dependsOn": sorted(list(set(child_refs)))
        })

    root_bom_ref = "scanned-application-root"
    direct_refs = [
        bom_ref_map[normalize_package_name(d.name)]
        for d in resolved_deps
        if d.is_direct and normalize_package_name(d.name) in bom_ref_map
    ]
    dependencies_graph.insert(0, {
        "ref": root_bom_ref,
        "dependsOn": sorted(direct_refs)
    })

    sbom_doc: Dict[str, Any] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "SecureSBOM",
                    "name": "SecureSBOM Scanner Engine",
                    "version": "1.0.0"
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": root_bom_ref,
                "name": project_name,
                "version": project_version
            }
        },
        "components": components,
        "dependencies": dependencies_graph
    }
    
    return sbom_doc


def save_sbom_to_file(sbom: Dict[str, Any], output_path: str = "output/bom.json") -> str:
    """Saves the CycloneDX SBOM dictionary to a formatted JSON file."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2)
    return output_path
