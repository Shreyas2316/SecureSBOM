# SecureSBOM — Software Supply Chain Dependency Vulnerability Scanner

> **Milestone Status**: 85%+ Implementation Milestone (Validated FastAPI Backend, CycloneDX v1.5 Schema Validation, Canonical Vulnerability Correlation, Dual-Route Motion Design Frontend, Automated Testing, and Empirical Evaluation Benchmark).

---

## 🎯 1. Project Overview

**SecureSBOM** is an enterprise-grade software supply chain security platform for Python projects. It ingests dependency manifests (`requirements.txt`), resolves direct and transitive dependencies (with PyPI metadata fallback), generates standard-compliant **OWASP CycloneDX v1.5 JSON Software Bill of Materials (SBOMs)**, queries live vulnerability databases (**OSV** and **NVD**), and performs **deterministic canonical correlation and deduplication** to eliminate double-counting of multi-source advisories.

The system features:
- **Cinematic Landing Page (`/`)**: A scroll-driven, motion-rich narrative explaining supply chain risk, featuring an interactive HTML5 dependency graph canvas with vulnerability breach wavefront propagation.
- **Interactive Scanner Console (`/app`)**: A dark cybersecurity console (`#05070A`) with live terminal stage tracking, Recharts severity distribution donut charts, searchable CVE findings with expandable drawers, dual-mode table/tree dependency inventory, and CycloneDX JSON downloads.
- **600ms Page Transition**: Fluid page wipe animation powered by Framer Motion between marketing and operational surfaces.
- **Enterprise Security & Reliability**: Persistent SQLite audit history, schema validation, tenant isolation, and 44/44 passing automated verification tests.

---

## 🏗️ 2. System Architecture

```
                               ┌─────────────────────────────────────────────────────────┐
                               │                    FRONTEND ROUTING                     │
                               │  ┌─────────────────────────┐   ┌─────────────────────┐  │
                               │  │   Landing Page ('/')    │   │ Scanner App ('/app')│  │
                               │  │  Scroll-Motion Narrative│   │ Dark Cyber Console  │  │
                               │  └───────────┬─────────────┘   └──────────┬──────────┘  │
                               │              │  600ms Page Wipe Transition│             │
                               │              └──────────────┬─────────────┘             │
                               └─────────────────────────────┼───────────────────────────┘
                                                             │ HTTP REST Calls (Isolated to /app)
                                                             ▼
                                              ┌───────────────────────────────┐
                                              │    FastAPI Application Core   │
                                              └──────────────┬────────────────┘
                                                             │
                 ┌───────────────────────────────────────────┼───────────────────────────────────────────┐
                 ▼                                           ▼                                           ▼
   ┌───────────────────────────┐               ┌───────────────────────────┐               ┌───────────────────────────┐
   │     Dependency Engine     │               │     CycloneDX Generator   │               │   Vulnerability Scanner   │
   │ (PEP 508 + PyPI JSON API) │               │   (OWASP Schema Valid)    │               │  (Async OSV & NVD API 2.0)│
   └─────────────┬─────────────┘               └─────────────┬─────────────┘               └─────────────┬─────────────┘
                 │                                           │                                           │
                 ▼                                           ▼                                           ▼
        [Resolved Components]                       [Validated bom.json]                        [Raw Advisories]
                 │                                           │                                           │
                 └───────────────────────────────────────────┼───────────────────────────────────────────┘
                                                             ▼
                                              ┌───────────────────────────────┐
                                              │ Canonical Correlator & Graph  │
                                              │  (Disjoint-Set Union & CVSS)  │
                                              └──────────────┬────────────────┘
                                                             │
                                                             ▼
                                              ┌───────────────────────────────┐
                                              │  SQLite Database Persistence  │
                                              │ (Audit Trail & Per-Scan SBOM) │
                                              └───────────────────────────────┘
```

---

## 🎨 3. Front-End Design & User Experience

The front-end is split into two distinct surfaces connected by a **600ms page wipe transition** (`TRANSITION_EASE: [0.16, 1, 0.3, 1]`):

### A. Cinematic Landing Page (`/`)
1. **Hero Section**:
   - Headline: *"Every Transitive Dependency is an Attack Surface."*
   - Interactive HTML5 canvas rendering a dynamic multi-tiered dependency graph.
   - Red breach wavefront particle propagation animating latent vulnerability traversal from leaf to root.
   - Primary CTA &rarr; `/app`, secondary smooth-scroll anchor.
2. **Problem Section (Pinned Scroll)**:
   - Live transitive package explosion counter (`1` &rarr; `1,284` packages; `350` &rarr; `480,000` lines of code).
   - Graphical breakdown illustrating the 85% transitive dependency blindspot.
3. **How It Works Pipeline**:
   - 4 synchronized steps: *Manifest Ingestion*, *Deterministic DAG Resolution*, *NVD & OSV Vulnerability Correlation*, *Standardized SBOM Delivery*.
   - Live mock terminal showing JSON/CycloneDX payloads and CLI outputs.
4. **Live Risk Preview**:
   - Parallax results dashboard mockup featuring Recharts severity donut and CVE triage table.
5. **Features Grid**:
   - Glassmorphic 3D cards with glowing border highlights.
6. **Stats Strip**:
   - Animated count-up metrics via `MetricTicker.jsx`.
7. **Final CTA & Minimal Footer**:
   - Magnetic launch button, project metadata (`SecureSBOM`, `PRJ_56`), and GitHub link.
- **Lenis Smooth Scroll**: Buttery 60fps scrolling with `prefers-reduced-motion` detection.
- **Backend Isolation**: Landing page makes zero backend API calls (pure client-side performance).

### B. Scanner Web Console (`/app`)
- **Aesthetic**: Unified `#05070A` abyss surface, `#0B0E14` elevated glass cards, electric cyan (`#00F5FF`) and neon green (`#00FF88`) accents.
- **New Scan View**: Dark dropzone with drag-and-drop, one-click preset loader, and real-time terminal stage progress tracker.
- **Active Results View**: Interactive Recharts severity donut chart, CVSS score filters, search toolbar, and expandable inline details drawers.
- **Dependency Inventory View**: Dual-mode toggle between **Table View** and **Hierarchical Dependency Tree View** (direct packages with transitive branches).
- **Vulnerability Detail Modal**: Dark glass dialog with CVSS v3.1 vector breakdown, conflicting advisory detection, and raw record tabs.
- **Exports**: Instant downloads for standardized CycloneDX 1.5 JSON SBOMs and comprehensive audit reports.

---

## ✨ 4. Feature Matrix

| Feature | Status | Description |
|---|---|---|
| **PEP 508 Requirements Parsing** | **Implemented** | Strips comments, parses constraints (`==`, `>=`, `~=`), detects unpinned packages, enforces line length and 2MB file size limits. |
| **Manifest Syntax Validation** | **Implemented** | Flags syntax errors and unparseable lines with exact line numbers without halting valid dependencies. |
| **Transitive & PyPI Resolution** | **Implemented** | Local `importlib.metadata` inspection + live PyPI JSON API resolution. Differentiates `resolved` from `unresolved`. |
| **CycloneDX v1.5 SBOM Generation** | **Implemented** | Generates components, PURLs (`pkg:pypi/name@version`), metadata, root application node, and dependency graphs. |
| **Official SBOM Schema Validation** | **Implemented** | Validated against the official OWASP CycloneDX v1.5 JSON schema via `cyclonedx.validation`. |
| **Live OSV API Integration** | **Implemented** | Async queries to `api.osv.dev` with retry backoff, timeouts, and in-memory caching. |
| **Live NVD API Integration** | **Implemented** | Async REST queries to NIST NVD 2.0 API with rate limit detection and CVSS v3.1 base score enrichment. |
| **Canonical Advisory Correlation** | **Implemented** | Graph-based connected component clustering across CVE, GHSA, and PYSEC aliases; eliminates duplicate vulnerability counts. |
| **CVSS v3.1 Severity Prioritization** | **Implemented** | Deterministic thresholds (Critical, High, Medium, Low, Informational, Unknown) with source attribution and conflict detection. |
| **Database Persistence & History** | **Implemented** | SQLAlchemy + SQLite backend storing all scans, reports, and per-scan downloadable SBOMs with tenant isolation. |
| **Cinematic Landing Page (`/`)** | **Implemented** | 7 motion-driven storytelling sections, animated dependency graph canvas, and Lenis smooth scrolling. |
| **Dark Cyber Scanner Console (`/app`)** | **Implemented** | Recharts donut charts, terminal stage tracker, dual table/tree dependency inventory, and expandable CVE drawers. |
| **Automated Testing Suite** | **Implemented** | 44 automated tests covering unit logic, correlation scenarios, schema validation, security limits, and full E2E journeys. |
| **Empirical Evaluation Benchmark** | **Implemented** | Repeatable benchmark evaluating precision, recall, deduplication ratio, and runtime duration on ground-truth datasets. |
| **Multi-Ecosystem (npm, Cargo, etc.)** | *Pending* | Python/PyPI ecosystem prioritized for current milestone. |
| **Automated PR Remediation Engine** | *Pending* | Recommended upgrade versions displayed; automated Git PR creation planned for future milestones. |

---

## 🛠️ 5. Tech Stack

- **Backend**: Python 3.12+ / 3.13, FastAPI, Uvicorn ASGI server
- **HTTP Engine**: `httpx` (async HTTP client with timeouts and bounded retries)
- **Packaging & PURL**: `packaging`, `packageurl-python` (PEP 503 & PEP 508 compliance)
- **SBOM Standard**: OWASP CycloneDX v1.5 (`cyclonedx-python-lib`, `jsonschema`)
- **Vulnerability Databases**: Google OSV REST API (`api.osv.dev`), NIST NVD API 2.0 (`services.nvd.nist.gov`)
- **Database & Storage**: SQLAlchemy 2.0, SQLite / aiosqlite (PostgreSQL compatible)
- **Frontend Core**: React 18, Vite 8, React Router DOM v7
- **Motion & Storytelling**: Framer Motion, Lenis Smooth Scroll, HTML5 Canvas API
- **Charts & UI**: Recharts (Pie & Donut), Lucide React Icons, Vanilla CSS Design System with Tailwind v4 engine
- **Testing**: `pytest`, `pytest-asyncio`, FastAPI `TestClient`

---

## 💻 6. Installation & Setup Instructions

### Prerequisites
- Python 3.12+ (or 3.13)
- Node.js v18+ and npm v9+

### Step 1: Clone and Environment Setup
```bash
# Clone or navigate to the repository
cd SecureSBOM

# Create and activate Python virtual environment
python -m venv venv

# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On macOS/Linux:
source venv/bin/activate

# Install Python backend dependencies
pip install -r requirements.txt
```

### Step 2: Install Frontend Dependencies
```bash
cd frontend
npm install
npm run build
cd ..
```

---

## 🚀 7. Running the Application

### Option A: Development Mode (Concurrent Hot-Reload)
Run both backend and frontend servers simultaneously for active development:

1. **Terminal 1: Start Backend API**
   ```bash
   uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
   ```
   - Swagger API Docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

2. **Terminal 2: Start Frontend Dev Server**
   ```bash
   cd frontend
   npm run dev
   ```
   - Landing Page: [http://localhost:5173/](http://localhost:5173/)
   - Scanner Console: [http://localhost:5173/app](http://localhost:5173/app)

### Option B: Production Mode (Single Port via FastAPI)
Build the frontend bundle and serve everything directly through FastAPI:
```bash
cd frontend && npm run build && cd ..
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```
Open [http://127.0.0.1:8000/](http://127.0.0.1:8000/) in your browser.

---

## 🧪 8. Automated Testing Suite

Run all 44 automated tests:
```bash
pytest tests/ -v
```

### Specific Test Modules:
```bash
# 1. Canonical vulnerability correlation (9 scenarios)
pytest tests/test_correlator.py -v

# 2. CycloneDX SBOM generation & schema validation
pytest tests/test_sbom_generator.py -v

# 3. Severity classification & CVSS boundary thresholds
pytest tests/test_severity.py -v

# 4. Dependency parser & PyPI resolution
pytest tests/test_dependency_parser.py -v

# 5. OSV & NVD vulnerability queries
pytest tests/test_vulnerability_scanner.py -v

# 6. Database persistence & history
pytest tests/test_database.py -v

# 7. Security hardening (size limits, path traversal, isolation)
pytest tests/test_security.py -v

# 8. Complete main user journey E2E test
pytest tests/test_e2e.py -v
```

---

## 📊 9. Empirical Evaluation Benchmark

A repeatable evaluation benchmark evaluates precision, recall, deduplication ratio, and runtime duration on ground-truth datasets:

```bash
python evaluation/run_evaluation.py
```

### Measured Benchmark Highlights:
- **requests==2.25.0**: 27 raw advisory records correlated into **11 canonical vulnerabilities** (Deduplication ratio: **0.41**; 100% ground-truth match on CVE-2023-32681).
- **jinja2==2.11.2**: 15 raw advisory records correlated into **5 canonical vulnerabilities** (Deduplication ratio: **0.33**; 100% ground-truth match).
- **pydantic==2.8.2**: Clean package verified with 0 false positives.
- **CycloneDX Schema Validity**: 100% of generated SBOMs validated against official schema.

Machine-readable metrics are saved in [`evaluation/results.json`](file:///c:/Users/shrey/OneDrive/Documents/SBOM/evaluation/results.json), and the Markdown report is in [`evaluation/evaluation_report.md`](file:///c:/Users/shrey/OneDrive/Documents/SBOM/evaluation/evaluation_report.md).

---

## 🔒 10. Security Hardening

1. **Upload Limits**: Enforces a strict 2MB maximum payload limit and 1000-character line length to prevent denial-of-service (DoS) attacks.
2. **Path Traversal Protection**: Uploaded filenames are sanitized with `os.path.basename` to prevent directory traversal.
3. **Execution Safety**: Untrusted manifest content is parsed using strict PEP 508 grammar; uploaded files are never evaluated or passed to shell processes.
4. **Tenant Isolation**: Cross-user authorization checks via `X-User-Id` headers prevent unauthorized access to other tenants' scans or downloadable SBOM artifacts.
5. **Secret Protection**: No API keys, passwords, or secrets are exposed in logs, responses, or client artifacts.
6. **Zero Client Telemetry**: Landing page makes zero requests to backend endpoints.
