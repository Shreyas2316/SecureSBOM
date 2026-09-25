# SecureSBOM — Software Supply Chain Dependency Vulnerability Scanner

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-1.0.0-009688.svg)](https://fastapi.tiangolo.com/)
[![React + Vite](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev/)
[![CycloneDX](https://img.shields.io/badge/SBOM-CycloneDX_1.4-0052CC.svg)](https://cyclonedx.org/)
[![OSV API](https://img.shields.io/badge/Vulnerability_Source-OSV_API-orange.svg)](https://osv.dev/)

> **Academic Disclaimer:** *SecureSBOM is a student-scale open-source prototype integrating dependency analysis, SBOM generation, vulnerability correlation, and risk prioritization into a single workflow.*

---

## 1. Problem Statement & Objectives

Modern software applications heavily rely on open-source dependencies. Security vulnerabilities embedded deep within direct and transitive dependencies expose applications to supply chain risks. SecureSBOM provides an automated, local security pipeline that parses Python project manifests, extracts transitive dependency graphs, produces standardized **CycloneDX 1.4 JSON SBOMs**, queries public vulnerability databases (**OSV API & NVD API enrichment**), computes deterministic risk prioritization, and visualizes findings in a modern React security dashboard.

---

## 2. Architecture & Workflow

```
React (Vite) ──▶ FastAPI REST API ──▶ Scanning Service
                                          │
                     ┌────────────────────┼────────────────────┐
                     ▼                    ▼                    ▼
             Dependency Analysis    SBOM Generation    Vulnerability Correlation
             (direct + transitive)    (CycloneDX)         (OSV → NVD enrich)
                     └────────────────────┼────────────────────┘
                                          ▼
                                   Risk Prioritization
                                          ▼
                                Database (PostgreSQL / SQLite)
                                          ▼
                                  React Security Dashboard
```

1. **Input Layer:** Safe parsing of `requirements.txt` manifests without executing application or setup code.
2. **Resolution Layer:** Extraction of direct dependencies and depth-bounded transitive dependencies via PyPI release metadata.
3. **SBOM Layer:** Generation of OWASP CycloneDX 1.4 compliant JSON document (`output/bom.json`) featuring Package URLs (`purl`).
4. **Correlation Layer:** Asynchronous batch/individual queries to OSV API (`https://api.osv.dev/v1/query`) and optional NVD API enrichment (`cves/2.0`).
5. **Prioritization Layer:** Deterministic rule-based risk classification into Priority Tiers (`P1-Critical`, `P2-High`, `P3-Medium`, `P4-Low`, `P5-Info`).
6. **Persistence Layer:** Structured storage of projects, scans, components, vulnerabilities, and relationships in PostgreSQL / SQLite via SQLAlchemy.
7. **Presentation Layer:** Glassmorphic dark-theme React dashboard with live metrics, filterable vulnerability tables, detail modals, SBOM viewer, and historical scan investigation.

---

## 3. Technology Stack

- **Backend:** Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy 2.0, HTTPX
- **SBOM:** `cyclonedx-python-lib`, `packageurl-python`
- **Vulnerability Data:** OSV API (primary, free/no key required), NVD API 2.0 (enrichment layer, optional `NVD_API_KEY`)
- **Database:** PostgreSQL (production string configurable via `DATABASE_URL`), SQLite (zero-config local dev fallback)
- **Frontend:** React 18, Vite, Lucide Icons, Vanilla CSS Design System
- **Testing:** Pytest, FastAPI TestClient

---

## 4. Module Implementation Status (Review-2 Milestone)

| Module | Status | Description |
|---|---|---|
| M1: Input Validation & Parsing | **IMPLEMENTED** | Safe manifest parsing, path sanitization, zero code execution |
| M2: Dependency & Transitive Extraction | **IMPLEMENTED** | Direct parsing + safe PyPI metadata graph traversal (depth=2) |
| M3: CycloneDX SBOM Generator | **IMPLEMENTED** | OWASP CycloneDX 1.4 compliant JSON output with `purl` and depth attributes |
| M4: OSV Vulnerability Query | **IMPLEMENTED** | Asynchronous HTTPX client with caching, retry logic, and fallback handling |
| M5: NVD API Enrichment | **IMPLEMENTED** | Secondary enrichment layer with rate limiting and optional API key support |
| M6: Vulnerability Correlation Layer | **IMPLEMENTED** | Correlates components to CVE/GHSA IDs, affected ranges, and reference URLs |
| M7: CVSS & Severity Processing | **IMPLEMENTED** | Extracts official CVSS scores/vectors; never invents synthetic scores |
| M8: Rule-Based Risk Prioritization | **IMPLEMENTED** | Deterministic severity and priority tier mapping (P1-Critical to P5-Info) |
| M9: FastAPI REST API | **IMPLEMENTED** | `/health`, `/api/v1/scan`, `/api/v1/scans`, `/api/v1/scans/{id}`, `/docs` |
| M10: Database Persistence | **IMPLEMENTED** | SQLAlchemy models for `projects`, `scans`, `components`, `vulnerabilities` |
| M11: React Security Dashboard | **IMPLEMENTED** | Sleek dark-mode dashboard with metrics, search filters, detail modals |
| M12: Scan History & Re-investigation | **IMPLEMENTED** | Historical scan list with click-through complete result re-opening |
| M13: SBOM Viewer & Exporter | **IMPLEMENTED** | Component table, raw JSON inspect, and `bom.json` export download |
| M14: Automated Test Suite | **IMPLEMENTED** | 11 Pytest unit & integration tests passing with 100% success rate |
| M15: Code Reachability / False Positives | **PLANNED** | Scheduled for Review-3 milestone |

---

## 5. Quickstart & Installation

### Prerequisites
- Python 3.10+
- Node.js v18+ & npm

### Setup Instructions

1. **Clone & Configure Environment:**
   ```bash
   cp .env.example .env
   ```

2. **Backend Setup & Execution:**
   ```bash
   # Install backend dependencies
   pip install -r backend/requirements.txt

   # Run automated test suite
   python -m pytest backend/tests -v

   # Launch FastAPI Dev Server
   python -m uvicorn app.main:app --app-dir backend --port 8000 --reload
   ```
   *FastAPI Swagger documentation will be live at:* `http://localhost:8000/docs`

3. **Frontend Setup & Execution:**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
   *React Dashboard will be live at:* `http://localhost:5173`

---

## 6. Real Empirical Evaluation Results (Section 10)

Evaluated on 3 real test cases using live OSV/NVD API queries:

| Metric | Test Case 1 (Small Project) | Test Case 2 (Medium Project) | Test Case 3 (Controlled Fixture) |
|---|---|---|---|
| **Manifest** | `requests==2.31.0`, `pyyaml==6.0.1` | `fastapi`, `uvicorn`, `pydantic`, `sqlalchemy`, `httpx`, `jinja2`, `python-dotenv` | `requests==2.25.1`, `urllib3==1.26.4`, `jinja2==2.11.2`, `flask==1.1.2`, `pyyaml==5.3.1` |
| **Dependencies Scanned** | 6 | 23 | 12 |
| **Direct / Transitive** | 2 / 4 | 7 / 16 | 5 / 7 |
| **SBOM Components** | 6 | 23 | 12 |
| **Vulnerabilities Detected** | **33** | **27** | **70** |
| **Critical / High / Med / Low / Unknown** | 1 / 8 / 16 / 0 / 8 | 1 / 11 / 8 / 2 / 5 | 2 / 23 / 28 / 1 / 16 |
| **Scan Time** | 19.12 s | 28.16 s | 28.49 s |
| **API Failures** | 0 | 0 | 0 |

---

## 7. Honest Limitations & Future Work

- **Static Version Association Only:** A vulnerability match indicates a known CVE associated with a declared package version in public database records. It does not prove that the vulnerable code path is reachable or executed by the host application.
- **Python Ecosystem Focus:** Current implementation parses Python PyPI dependencies. Multi-ecosystem support (npm, Maven, Go) is planned for future work.
- **No Zero-Day Detection:** The system relies on published public advisories (OSV/NVD) and cannot detect unannounced zero-day vulnerabilities.

---

## 8. License & Academic Citation

Developed as a B.Tech Mini Project (PRJ_56 — SecureSBOM). Distributed under the MIT Open Source License.
