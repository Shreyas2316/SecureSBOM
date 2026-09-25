import json
import os
import datetime
from typing import List, Dict, Any
from pathlib import Path
from packageurl import PackageURL

from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component as CdxComponent, ComponentType, Property
from cyclonedx.model.tool import Tool
from cyclonedx.model.dependency import Dependency
from cyclonedx.output.json import JsonV1Dot4
from app.config import settings

def generate_cyclonedx_sbom(project_name: str, components_data: List[Dict[str, Any]], save_filepath: str = None) -> Dict[str, Any]:
    """
    Generate a valid CycloneDX 1.4 JSON SBOM document from resolved component metadata.
    Saves to output/bom.json and returns parsed dictionary.
    """
    bom = Bom()
    
    # Metadata
    metadata = BomMetaData()
    tool = Tool(vendor="SecureSBOM", name="SecureSBOM Scanner", version="1.0.0")
    metadata.tools.tools.add(tool)
    
    root_comp = CdxComponent(
        name=project_name,
        version="1.0.0",
        type=ComponentType.APPLICATION
    )
    metadata.component = root_comp
    bom.metadata = metadata

    cdx_components_map = {}

    for comp in components_data:
        purl_str = comp.get("purl")
        purl_obj = None
        if purl_str:
            try:
                purl_obj = PackageURL.from_string(purl_str)
            except Exception:
                purl_obj = PackageURL(type="pypi", name=comp["name"], version=comp["version"])
        else:
            purl_obj = PackageURL(type="pypi", name=comp["name"], version=comp.get("version", "unknown"))

        cdx_comp = CdxComponent(
            name=comp["name"],
            version=comp.get("version", "unknown"),
            type=ComponentType.LIBRARY,
            purl=purl_obj,
            bom_ref=purl_obj.to_string()
        )
        
        # Add property for direct vs transitive
        is_direct_str = "true" if comp.get("is_direct", True) else "false"
        cdx_comp.properties.add(Property(name="securesbom:is_direct", value=is_direct_str))
        cdx_comp.properties.add(Property(name="securesbom:depth", value=str(comp.get("dependency_depth", 0))))

        bom.components.add(cdx_comp)
        cdx_components_map[comp["normalized_name"]] = cdx_comp

    # Build dependency graph
    root_dep = Dependency(ref=root_comp.bom_ref)
    for comp in components_data:
        if comp.get("is_direct", True) and comp["normalized_name"] in cdx_components_map:
            root_dep.dependencies.add(Dependency(ref=cdx_components_map[comp["normalized_name"]].bom_ref))
    
    bom.dependencies.add(root_dep)

    # Serialize to JSON
    outputter = JsonV1Dot4(bom)
    json_str = outputter.output_as_string()
    bom_dict = json.loads(json_str)

    # Save to file
    target_path = save_filepath or os.path.join(settings.OUTPUT_DIR, "bom.json")
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(bom_dict, f, indent=2)

    return bom_dict
