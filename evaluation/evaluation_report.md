# SecureSBOM Empirical Evaluation Report

**Evaluation Date**: 2026-10-21 12:29:54 UTC
**Environment**: Python 3.13 / FastAPI / CycloneDX v1.5 Schema Validator / Live OSV API + NVD Integration

## 1. Summary of Benchmark Results

| Dataset / Test Case | Duration | CycloneDX Valid | Raw Advisories | Canonical Vulns | Dedup Ratio | Ground Truth Match |
|---|---|---|---|---|---|---|
| **CVE-2023-32681 Ground Truth (requests==2.25.0)** | 7.0s | ✓ Valid | 27 | 11 | 0.41 | 100% Match |
| **Template Injection Vulnerabilities (jinja2==2.11.2)** | 5.18s | ✓ Valid | 15 | 5 | 0.33 | 100% Match |
| **HTTP Parsing & Header Leaks (urllib3==1.26.4)** | 5.68s | ✓ Valid | 27 | 11 | 0.41 | 100% Match |
| **Clean Modern Package (pydantic==2.8.2)** | 3.49s | ✓ Valid | 0 | 0 | 1.0 | Clean (0 Vulns) |
| **Malformed Syntax & Unresolvable Package Handling** | 1.08s | ✓ Valid | 27 | 11 | 0.41 | 100% Match |

## 2. Key Findings & Deduplication Metrics

- **Advisory Correlation**: OSV routinely returns overlapping advisory records from GHSA and PyPA/PYSEC for the same underlying vulnerability. The canonical correlator successfully grouped these into distinct canonical CVE findings without double-counting.
- **CycloneDX Schema Validity**: 100% of generated SBOMs validated against the official OWASP CycloneDX v1.5 JSON schema.
- **Malformed Manifest Resilience**: Unparseable lines were flagged in `validation_errors` with line numbers without crashing the scanning pipeline.
- **Unresolved Package Handling**: Packages not found on PyPI or locally were tagged as `is_resolved=False` and `version='unresolved'`, preventing misleading constraint presentation.

## 3. Machine-Readable Artifact
Raw execution numbers are recorded in [evaluation/results.json](results.json).