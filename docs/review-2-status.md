# SecureSBOM — Review-2 Milestone Status Report (Updated)

**Project:** PRJ_56 — SecureSBOM: Software Supply Chain Dependency Vulnerability Scanner  
**Milestone:** Review-2 Implementation Status  
**Completion Percentage:** **75.0%** (12 out of 16 core roadmap modules fully implemented and verified)

---

## 1. Implemented & Functional Modules

| Module ID | Module Description | Functional Status | Verification Method |
|---|---|---|---|
| **M1** | Project Setup & Input Parsing | **Complete** | Unit tests in [`test_dependency_parser.py`](file:///c:/Users/shrey/OneDrive/Documents/Project/backend/tests/test_dependency_parser.py) |
| **M2** | Direct Dependency Extraction | **Complete** | Tested with PEP 503 normalization |
| **M3** | Transitive Dependency Resolution | **Working** | PyPI JSON metadata resolution (depth=2) |
| **M4** | CycloneDX 1.4 SBOM Generator | **Complete** | OWASP schema validation in [`test_sbom_generator.py`](file:///c:/Users/shrey/OneDrive/Documents/Project/backend/tests/test_sbom_generator.py) |
| **M5** | OSV API Integration | **Complete** | Real API queries & unit tests in [`test_osv_service.py`](file:///c:/Users/shrey/OneDrive/Documents/Project/backend/tests/test_osv_service.py) |
| **M6** | NVD API 2.0 Enrichment | **Working** | Enrichment layer with optional `NVD_API_KEY` |
| **M7** | Alias Graph Deduplication Engine | **Complete** | Connected component graph deduplication in [`correlation_service.py`](file:///c:/Users/shrey/OneDrive/Documents/Project/backend/app/services/correlation_service.py) |
| **M8** | Deterministic Severity & Priority Engine | **Complete** | Six severity states (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `UNKNOWN`) in [`prioritization.py`](file:///c:/Users/shrey/OneDrive/Documents/Project/backend/app/services/prioritization.py) |
| **M9** | Remediation / Fixed Version Extraction | **Complete** | OSV event range parsing in [`osv_service.py`](file:///c:/Users/shrey/OneDrive/Documents/Project/backend/app/services/osv_service.py) |
| **M10** | FastAPI REST API Backend | **Complete** | Endpoints live (`/health`, `/scan`, `/scans`, `/docs`) |
| **M11** | Database Persistence Layer | **Complete** | SQLAlchemy ORM models (PostgreSQL / SQLite) |
| **M12** | React Security Dashboard | **Complete** | Dark-mode dashboard displaying Unique, Advisory, and Affected Component metrics |
| **M13** | Scan History & Re-investigation | **Complete** | Historical scan list with click-through details |
| **M14** | CycloneDX SBOM Viewer & Export | **Complete** | Component tree, JSON view, `bom.json` export |
| **M15** | Automated Test Suite | **Complete** | 22/22 Pytest tests passing cleanly |
| **M16** | Code Reachability / False Positive Analysis | **Planned** | Out of scope for Review-2; scheduled for Review-3 |

---

## 2. Real Empirical Evaluation Measurements

All numbers represent empirical measurements recorded from live execution against public OSV/NVD APIs:

### Test Case 1 — Small Python Project
- **Total Components Scanned:** 6 (Direct: 2, Transitive: 4)
- **Unique Vulnerabilities:** 17
- **Advisory Records (Before Dedup):** 33
- **Affected Components:** 4
- **Severity Breakdown (Critical / High / Med / Low / Info / Unknown):** 1 / 5 / 8 / 0 / 0 / 3
- **Scan Execution Time:** 9.50 s

### Test Case 2 — Medium Python Project
- **Total Components Scanned:** 23 (Direct: 7, Transitive: 16)
- **Unique Vulnerabilities:** 14
- **Advisory Records (Before Dedup):** 27
- **Affected Components:** 5
- **Severity Breakdown (Critical / High / Med / Low / Info / Unknown):** 1 / 6 / 4 / 1 / 0 / 2
- **Scan Execution Time:** 17.80 s

### Test Case 3 — Controlled Demo Fixture (`sample_project/requirements.txt`)
- **Total Components Scanned:** 12 (Direct: 5, Transitive: 7)
- **Unique Vulnerabilities:** 37
- **Advisory Records (Before Dedup):** 70
- **Affected Components:** 9
- **Severity Breakdown (Critical / High / Med / Low / Info / Unknown):** 1 / 14 / 14 / 1 / 0 / 7
- **Scan Execution Time:** 16.33 s

---

## 3. Known Academic Limitations

> *"Our current implementation focuses on Python projects and known vulnerabilities available through the integrated vulnerability sources. A vulnerability match does not necessarily mean the vulnerable code path is reachable or exploitable. The system does not protect against zero-day vulnerabilities."*
