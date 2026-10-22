from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class DependencySpec(BaseModel):
    """Parsed specifier from requirements.txt."""
    name: str = Field(..., description="Normalized Python package name")
    specifier: str = Field(default="", description="Version constraint specifier (e.g. '==2.25.0', '>=1.0.0')")
    raw_line: str = Field(..., description="Original raw line from requirements.txt")
    is_direct: bool = Field(default=True, description="True if parsed directly from requirements.txt")
    line_number: int = Field(default=0, description="Line number in the manifest")


class ResolvedDependency(BaseModel):
    """Resolved package dependency with version and package URL (PURL)."""
    name: str = Field(..., description="Package name")
    version: str = Field(..., description="Resolved version string (e.g. '2.25.0' or 'unknown')")
    purl: str = Field(..., description="Package URL specification (PURL)")
    is_direct: bool = Field(default=True, description="True for direct dependencies, False for transitive")
    transitive_dependencies: List[str] = Field(default_factory=list, description="List of package names required by this package")
    declared_specifier: str = Field(default="", description="Declared constraint from manifest")
    is_resolved: bool = Field(default=True, description="True if version was successfully resolved to a concrete release")
    resolution_status: str = Field(default="resolved", description="'resolved', 'unresolved', or 'local_environment'")


class VulnerabilityDetail(BaseModel):
    """Extracted vulnerability information from advisory databases."""
    vuln_id: str = Field(..., description="OSV/NVD Vulnerability Identifier (e.g. GHSA-xxx, PYSEC-xxx, CVE-xxx)")
    aliases: List[str] = Field(default_factory=list, description="CVE or other vulnerability aliases")
    summary: str = Field(default="No summary provided", description="Short description of the vulnerability")
    affected_versions: List[str] = Field(default_factory=list, description="Affected version ranges or versions")
    severity: str = Field(..., description="CVSS score/vector or severity rating. 'severity unavailable' if absent.")
    source: str = Field(default="OSV", description="Source database name")
    source_url: str = Field(default="", description="Web URL to advisory")


class PackageVulnerabilities(BaseModel):
    """Vulnerabilities associated with a specific package and version."""
    package_name: str = Field(..., description="Package name")
    version: str = Field(..., description="Package version")
    purl: str = Field(..., description="Package URL specification (PURL)")
    vulnerabilities: List[VulnerabilityDetail] = Field(default_factory=list, description="List of raw vulnerabilities affecting this package version")


class CanonicalVulnerability(BaseModel):
    """Deduplicated, canonical security finding correlated across OSV, NVD, and GHSA."""
    canonical_id: str = Field(..., description="Authoritative identifier (preferring CVE > GHSA > PYSEC)")
    aliases: List[str] = Field(default_factory=list, description="Correlated alternative advisory identifiers")
    all_identifiers: List[str] = Field(default_factory=list, description="All associated identifiers in the cluster")
    summary: str = Field(default="No summary provided", description="Consolidated vulnerability summary")
    severity: str = Field(..., description="Standardized severity: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, UNKNOWN")
    cvss_score: Optional[float] = Field(default=None, description="Authoritative numeric CVSS score (0.0 - 10.0)")
    cvss_version: Optional[str] = Field(default=None, description="CVSS specification version (e.g. '3.1', '3.0')")
    cvss_vector: Optional[str] = Field(default=None, description="Standard CVSS vector string")
    severity_justification: str = Field(default="", description="Detailed reason for assigned severity")
    has_cvss_conflict: bool = Field(default=False, description="True if different sources reported conflicting CVSS scores")
    affected_packages: List[Dict[str, Any]] = Field(default_factory=list, description="List of affected packages and ranges")
    fixed_versions: List[str] = Field(default_factory=list, description="List of versions containing the remediation")
    sources: List[str] = Field(default_factory=list, description="Sources contributing to this canonical finding")
    source_urls: List[str] = Field(default_factory=list, description="Advisory URLs")
    raw_advisories_count: int = Field(default=1, description="Number of raw advisories merged into this finding")
    raw_advisories: List[Dict[str, Any]] = Field(default_factory=list, description="Raw advisory records for traceability")


class ScanSummary(BaseModel):
    """High-level metrics for the scan run."""
    total_direct_deps: int = Field(..., description="Number of direct dependencies parsed from file")
    total_transitive_deps: int = Field(..., description="Number of transitive dependencies discovered")
    total_scanned: int = Field(..., description="Total unique package dependencies scanned")
    total_vulnerabilities: int = Field(..., description="Total raw vulnerability advisory instances")
    total_raw_advisories: int = Field(default=0, description="Total raw advisory records prior to deduplication")
    total_canonical_vulnerabilities: int = Field(default=0, description="Deduplicated canonical vulnerability count")
    vulnerable_components_count: int = Field(default=0, description="Count of distinct packages affected by vulnerabilities")
    unresolved_dependencies_count: int = Field(default=0, description="Count of packages where version could not be resolved")
    vulnerabilities_by_severity: Dict[str, int] = Field(default_factory=dict, description="Count of canonical vulnerabilities grouped by severity rating")


class ScanReport(BaseModel):
    """Complete scan report schema saved to JSON and returned by API."""
    scan_id: str = Field(default="", description="Unique identifier for this scan session")
    manifest_name: str = Field(default="requirements.txt", description="Name of the scanned manifest")
    timestamp: str = Field(..., description="ISO 8601 timestamp of scan execution")
    summary: ScanSummary = Field(..., description="Summary statistics")
    dependencies: List[ResolvedDependency] = Field(default_factory=list, description="Scanned dependencies")
    vulnerabilities: List[PackageVulnerabilities] = Field(default_factory=list, description="Raw vulnerability records per package")
    canonical_vulnerabilities: List[CanonicalVulnerability] = Field(default_factory=list, description="Deduplicated canonical findings")
    source_status: Dict[str, str] = Field(default_factory=dict, description="Status of advisory sources (e.g. {'osv': 'ok', 'nvd': 'ok'})")
    validation_errors: List[str] = Field(default_factory=list, description="Manifest validation warnings or non-fatal errors")
    cyclonedx_valid: bool = Field(default=True, description="True if generated CycloneDX SBOM passed official schema validation")


class ScanResponse(BaseModel):
    """API response model for POST /scan endpoint."""
    status: str = Field(default="success", description="Status of the scan operation")
    message: str = Field(..., description="Human readable summary message")
    scan_id: Optional[str] = Field(default=None, description="Scan ID for historical lookup and retrieval")
    report: ScanReport = Field(..., description="Detailed scan report object")
    bom_path: str = Field(..., description="Path to generated CycloneDX bom.json file")
    scan_report_path: str = Field(..., description="Path to generated scan_report.json file")
