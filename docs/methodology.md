# SecureSBOM Methodology & Technical Design

## 1. Phase Pipeline Methodology

SecureSBOM operates through a deterministic 7-stage scanning and correlation pipeline designed for student-scale academic transparency, zero false metric inflation, and reproducible local execution.

### Stage 1: Manifest Ingestion & Parsing
- Input manifests (`requirements.txt`) are validated for size and encoding.
- Lines starting with comments (`#`) or pip flags (`-r`, `--index-url`) are filtered out.
- Package names are normalized according to PEP 503 standards (replacing `_` and `.` with `-` and converting to lowercase).
- Version specifiers are extracted using regular expressions into structured tuples (`name`, `version`, `operator`).

### Stage 2: Safe Transitive Dependency Graph Construction
- Direct dependencies are assigned depth level 0 (`is_direct=True`).
- Transitive dependencies are discovered by querying the PyPI JSON metadata endpoint (`https://pypi.org/pypi/{name}/{version}/json`) to extract declared `requires_dist` fields.
- Dependency depth is bounded to `max_depth=2` to prevent circular dependencies or excessive API latency.
- Crucially, package setup scripts (`setup.py`) or wheel install hooks are **never executed**.

### Stage 3: Standardized CycloneDX SBOM Synthesis
- Components are converted into OWASP CycloneDX 1.4 objects using `cyclonedx-python-lib`.
- Package URLs (`purl`) are generated in standard format: `pkg:pypi/name@version`.
- Dependency relationships between the root project and direct components are rendered into the dependency graph.
- Output is written to [`output/bom.json`](file:///c:/Users/shrey/OneDrive/Documents/Project/output/bom.json).

### Stage 4: Multi-Source Vulnerability Correlation
- Component package names and versions are submitted to the Google Open Source Vulnerability (OSV) API (`https://api.osv.dev/v1/query`).
- OSV responses are parsed for OSV IDs (e.g. `GHSA-...`), CVE aliases, summaries, advisory details, and reference URLs.
- For matched findings containing a valid CVE alias (e.g. `CVE-2023-32681`), an optional enrichment call is made to the NIST NVD API 2.0 (`https://services.nvd.nist.gov/rest/json/cves/2.0`).

### Stage 5: Non-Fabricated CVSS & Severity Processing
- CVSS scores and vector strings are extracted strictly from source payloads (NVD or OSV).
- If neither database provides a numerical CVSS score, the field remains `None` (`CVSS: Not Available`). Scores are **never calculated or invented**.

### Stage 6: Deterministic Risk Prioritization
- Findings are mapped into 5 priority tiers using a deterministic rule matrix:
  - `P1-Critical` (CVSS >= 9.0 or CRITICAL severity)
  - `P2-High` (CVSS 7.0 - 8.9 or HIGH severity)
  - `P3-Medium` (CVSS 4.0 - 6.9 or MEDIUM severity)
  - `P4-Low` (CVSS 0.1 - 3.9 or LOW severity)
  - `P5-Info` (UNKNOWN severity)

### Stage 7: Database Persistence & Dashboard Rendering
- Scan metrics, components, vulnerabilities, and relational mappings are stored via SQLAlchemy in PostgreSQL/SQLite.
- Results are served over FastAPI REST endpoints and rendered interactively on the React Vite dashboard.

---

## 2. Technical Limitations & Trade-offs

1. **Static Version Association:** A matched vulnerability indicates that the scanned dependency version has a published CVE. It does not prove that the vulnerable code function or method is executed by the host application.
2. **Metadata-Based Transitive Discovery:** Relying on PyPI JSON `requires_dist` metadata avoids code execution risks but may miss non-standard or dynamically computed package requirements.
3. **API Rate Limiting & Network Dependency:** Scanner execution speed depends on public OSV/NVD network response times. In-memory caching mitigates redundant calls during batch scans.
