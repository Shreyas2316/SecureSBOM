from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field
from datetime import datetime

class ScanRequest(BaseModel):
    project_name: str = Field(default="My Python Project", description="Name of the project being scanned")
    requirements_content: str = Field(..., description="Raw content of requirements.txt")

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

class ScanSummarySchema(BaseModel):
    scan_id: int
    project_name: str
    timestamp: datetime
    total_deps: int
    direct_deps: int
    transitive_deps: int
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
