import os
import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional
from backend.models import (
    ScanReport,
    ScanSummary,
    ResolvedDependency,
    PackageVulnerabilities,
    CanonicalVulnerability
)
from backend.dependency_parser import (
    validate_and_parse_requirements_txt,
    resolve_dependencies_async
)
from backend.sbom_generator import (
    generate_cyclonedx_sbom,
    save_sbom_to_file,
    validate_cyclonedx_sbom
)
from backend.vulnerability_scanner import scan_dependencies_vulnerabilities
from backend.correlator import correlate_vulnerabilities
from backend.database import save_scan_record


def compute_scan_summary(
    resolved_deps: List[ResolvedDependency],
    package_vulns: List[PackageVulnerabilities],
    canonical_findings: List[Dict[str, Any]],
    raw_count: int
) -> ScanSummary:
    """Calculates aggregate metrics for the scan run, distinguishing canonical from raw."""
    total_direct = sum(1 for d in resolved_deps if d.is_direct)
    total_transitive = sum(1 for d in resolved_deps if not d.is_direct)
    total_scanned = len(resolved_deps)
    unresolved_count = sum(1 for d in resolved_deps if not d.is_resolved)
    
    # Severity distribution across canonical findings
    severity_counts: Dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFORMATIONAL": 0,
        "UNKNOWN": 0
    }
    for cf in canonical_findings:
        sev = cf.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Count packages with at least one vulnerability
    vulnerable_packages = set()
    for pv in package_vulns:
        if pv.vulnerabilities:
            vulnerable_packages.add(pv.package_name)
    for cf in canonical_findings:
        for ap in cf.get("affected_packages", []):
            if ap.get("package_name"):
                vulnerable_packages.add(ap["package_name"])

    return ScanSummary(
        total_direct_deps=total_direct,
        total_transitive_deps=total_transitive,
        total_scanned=total_scanned,
        total_vulnerabilities=raw_count,
        total_raw_advisories=raw_count,
        total_canonical_vulnerabilities=len(canonical_findings),
        vulnerable_components_count=len(vulnerable_packages),
        unresolved_dependencies_count=unresolved_count,
        vulnerabilities_by_severity=severity_counts
    )


def save_scan_report_to_file(report: ScanReport, output_path: str = "output/scan_report.json") -> str:
    """Saves the scan report object to output/scan_report.json."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report.model_dump(), f, indent=2)
    return output_path


def print_terminal_report(report: ScanReport) -> None:
    """Prints a clean, formatted ASCII scan report summary to stdout."""
    print("\n" + "=" * 76)
    print("                      SecureSBOM SCAN REPORT                      ")
    print("=" * 76)
    print(f" Scan ID             : {report.scan_id}")
    print(f" Timestamp           : {report.timestamp}")
    print(f" Direct Dependencies : {report.summary.total_direct_deps}")
    print(f" Transitive Deps     : {report.summary.total_transitive_deps}")
    print(f" Total Scanned       : {report.summary.total_scanned}")
    print(f" Raw Advisories      : {report.summary.total_raw_advisories}")
    print(f" Canonical Vulns     : {report.summary.total_canonical_vulnerabilities}")
    print(f" CycloneDX Valid     : {'[VALID]' if report.cyclonedx_valid else '[INVALID]'}")
    print("-" * 76)
    
    # Severity breakdown
    sev_str = ", ".join(f"{k}: {v}" for k, v in report.summary.vulnerabilities_by_severity.items() if v > 0)
    if sev_str:
        print(f" Severity Breakdown  : {sev_str}")
    print("-" * 76)

    print("\n[DEPENDENCIES SCANNED]")
    for dep in report.dependencies:
        dep_type = "DIRECT" if dep.is_direct else "TRANSITIVE"
        status_tag = f"[{dep.resolution_status.upper()}]" if dep.resolution_status != "resolved" else ""
        print(f" * {dep.name:<25} {dep.version:<15} [{dep_type}] {status_tag} -> {dep.purl}")
        
    print("\n[CANONICAL VULNERABILITY FINDINGS]")
    if report.canonical_vulnerabilities:
        for cv in report.canonical_vulnerabilities:
            aliases_str = f" (Aliases: {', '.join(cv.aliases[:3])})" if cv.aliases else ""
            cvss_tag = f" | CVSS: {cv.cvss_score}" if cv.cvss_score is not None else ""
            print(f"\n [!] [{cv.canonical_id}]{aliases_str} | Severity: {cv.severity}{cvss_tag}")
            print(f"    Summary       : {cv.summary}")
            print(f"    Justification : {cv.severity_justification}")
            if cv.affected_packages:
                pkgs = [f"{p.get('package_name')}@{p.get('version')}" for p in cv.affected_packages]
                print(f"    Affected      : {', '.join(pkgs)}")
            if cv.fixed_versions:
                print(f"    Fixed In      : {', '.join(cv.fixed_versions)}")
    else:
        print("  [CLEAN] No vulnerabilities identified in scanned packages via OSV & NVD.")
        
    print("\n" + "=" * 76 + "\n")


async def run_full_scan(
    requirements_content: str,
    output_dir: str = "output",
    manifest_name: str = "requirements.txt",
    user_id: str = "default_user"
) -> Tuple[ScanReport, str, str]:
    """
    Executes the complete SecureSBOM scanning pipeline:
    1. Validates and parses requirements.txt
    2. Resolves dependencies (direct & transitive with PyPI metadata)
    3. Generates CycloneDX SBOM JSON -> output/bom.json and validates schema
    4. Queries OSV & NVD databases
    5. Deduplicates & correlates findings into canonical vulnerabilities
    6. Computes metrics and persists to SQLite database
    7. Displays formatted terminal summary
    """
    scan_id = str(uuid.uuid4())
    
    # 1. Parse & Validate
    specs, validation_errors = validate_and_parse_requirements_txt(requirements_content)
    
    # 2. Resolve
    resolved_deps, resolution_warnings = await resolve_dependencies_async(specs)
    all_validation_notes = validation_errors + resolution_warnings

    # 3. CycloneDX SBOM
    sbom_dict = generate_cyclonedx_sbom(resolved_deps)
    is_valid_sbom, sbom_err = validate_cyclonedx_sbom(sbom_dict)
    bom_path = save_sbom_to_file(sbom_dict, os.path.join(output_dir, "bom.json"))
    
    # Also save scan-specific SBOM
    scan_bom_dir = os.path.join(output_dir, "scans", scan_id)
    os.makedirs(scan_bom_dir, exist_ok=True)
    save_sbom_to_file(sbom_dict, os.path.join(scan_bom_dir, "bom.json"))

    # 4. Vulnerability Scanner (OSV + NVD)
    package_vulns, raw_findings, source_status = await scan_dependencies_vulnerabilities(resolved_deps)
    
    # 5. Canonical Vulnerability Correlation & Deduplication
    canonical_findings, total_raw_count, total_canonical_count = correlate_vulnerabilities(raw_findings)
    
    # 6. Build Summary & Report
    summary = compute_scan_summary(resolved_deps, package_vulns, canonical_findings, total_raw_count)
    
    # Build typed canonical models
    canonical_models = [
        CanonicalVulnerability(
            canonical_id=cf["canonical_id"],
            aliases=cf["aliases"],
            all_identifiers=cf["all_identifiers"],
            summary=cf["summary"],
            severity=cf["severity"],
            cvss_score=cf["cvss_score"],
            cvss_version=cf["cvss_version"],
            cvss_vector=cf["cvss_vector"],
            severity_justification=cf["severity_justification"],
            has_cvss_conflict=cf["has_cvss_conflict"],
            affected_packages=cf["affected_packages"],
            fixed_versions=cf["fixed_versions"],
            sources=cf["sources"],
            source_urls=cf["source_urls"],
            raw_advisories_count=cf["raw_advisories_count"],
            raw_advisories=cf["raw_advisories"]
        )
        for cf in canonical_findings
    ]

    report = ScanReport(
        scan_id=scan_id,
        manifest_name=manifest_name,
        timestamp=datetime.now(timezone.utc).isoformat(),
        summary=summary,
        dependencies=resolved_deps,
        vulnerabilities=package_vulns,
        canonical_vulnerabilities=canonical_models,
        source_status=source_status,
        validation_errors=all_validation_notes,
        cyclonedx_valid=is_valid_sbom
    )
    
    # 7. Persist to file and SQLite database
    scan_report_path = save_scan_report_to_file(report, os.path.join(output_dir, "scan_report.json"))
    save_scan_report_to_file(report, os.path.join(scan_bom_dir, "scan_report.json"))
    save_scan_record(
        scan_id=scan_id,
        manifest_name=manifest_name,
        report_data=report.model_dump(),
        bom_data=sbom_dict,
        user_id=user_id
    )

    # 8. Terminal Display
    print_terminal_report(report)
    
    return report, bom_path, scan_report_path
