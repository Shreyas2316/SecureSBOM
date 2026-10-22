import pytest
import os
import json
from app.services.sbom_generator import generate_cyclonedx_sbom
from app.config import settings

def test_generate_cyclonedx_sbom(tmp_path):
    components = [
        {
            "name": "requests",
            "normalized_name": "requests",
            "version": "2.25.1",
            "is_direct": True,
            "dependency_depth": 0,
            "purl": "pkg:pypi/requests@2.25.1"
        },
        {
            "name": "urllib3",
            "normalized_name": "urllib3",
            "version": "1.26.4",
            "is_direct": False,
            "dependency_depth": 1,
            "purl": "pkg:pypi/urllib3@1.26.4"
        }
    ]

    out_file = tmp_path / "bom.json"
    bom_dict = generate_cyclonedx_sbom("TestApp", components, save_filepath=str(out_file))

    assert "bomFormat" in bom_dict or "metadata" in bom_dict
    assert bom_dict.get("bomFormat") == "CycloneDX"
    
    comp_list = bom_dict.get("components", [])
    assert len(comp_list) == 2
    comp_names = [c["name"] for c in comp_list]
    assert "requests" in comp_names
    assert "urllib3" in comp_names

    # Check file written
    assert os.path.exists(out_file)
    with open(out_file, "r") as f:
        data = json.load(f)
        assert data["bomFormat"] == "CycloneDX"
