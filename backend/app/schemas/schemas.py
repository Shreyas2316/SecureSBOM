from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field
from datetime import datetime

class ScanRequest(BaseModel):
    project_name: str = Field(default="My Python Project", description="Name of the project being scanned")
    requirements_content: str = Field(..., description="Raw content of manifest or CycloneDX SBOM")
    manifest_filename: str = Field(default="requirements.txt", description="Original manifest filename for format detection")

class ComponentSchema(BaseModel):
    id: Optional[int] = None
    name: str
    version: str
    ecosystem: str = "PyPI"
    is_direct: bool = True
    purl: Optional[str] = None
    dependency_depth: int = 0

class VulnerabilitySchema(BaseModel):
    id: Optional[int] = None
    canonical_id: str
    osv_id: str
    cve_id: Optional[str] = None
    aliases: List[str] = []
    sources: List[str] = []
    summary: Optional[str] = "No summary available"
    details: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    severity: str = "UNKNOWN"
    severity_sources: List[Dict[str, Any]] = []
    priority_tier: str = "P-Unknown"
    affected_component_name: Optional[str] = None
    affected_component_version: Optional[str] = None
    affected_range: Optional[str] = None
    fixed_version: Optional[str] = None
    references: List[str] = []
    is_kev: bool = False
    kev_date_added: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None

class ScanSummarySchema(BaseModel):
    scan_id: int
    project_name: str
    timestamp: datetime
    total_deps: int
    direct_deps: int
    transitive_deps: int
    total_scanned: Optional[int] = None
    total_direct_deps: Optional[int] = None
    total_transitive_deps: Optional[int] = None
    direct_deps_count: Optional[int] = None
    transitive_deps_count: Optional[int] = None
    total_canonical_vulnerabilities: Optional[int] = None
    total_raw_advisories: Optional[int] = None
    vulnerable_components_count: Optional[int] = None
    unique_vuln_count: int
    advisory_record_count: int
    affected_components_count: int
    vuln_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    unknown_count: int
    scan_duration_seconds: float
    coverage_status: str = "complete"
    manifest_format: str = "requirements.txt"
    resolution_completeness: str = "complete"

class ScanResponse(BaseModel):
    summary: ScanSummarySchema
    components: List[ComponentSchema]
    vulnerabilities: List[VulnerabilitySchema]

class ScanHistoryItem(BaseModel):
    scan_id: int
    project_name: str
    timestamp: datetime
    total_deps: int
    unique_vuln_count: int
    advisory_record_count: int
    affected_components_count: int
    vuln_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    unknown_count: int

class SbomResponse(BaseModel):
    scan_id: int
    bom_json: Dict[str, Any]
