# SecureSBOM (PRJ_56) — Complete Repository Audit & Baseline Verification

**Audit Date:** 2026-11-25  
**Scope:** Full-stack repository inspection (`backend/`, `frontend/`, `tests/`, configuration, security, and deployment readiness).

---

## 1. Baseline Verification Results

| Check | Command | Result | Notes |
|---|---|---|---|
| **Backend Tests (with `DEBUG=True`)** | `$env:DEBUG="True"; pytest tests/ backend/tests/ -q` | **85 passed** in 44.77s | Fails at collection without `DEBUG=True` because Windows host has `DEBUG=release` env var which breaks `Settings.DEBUG: bool`. |
| **Frontend Production Build** | `npm --prefix frontend run build` | **Passed** (2.13s) | Outputs `dist/assets/index-*.js` (916 kB chunk warning). |
| **Frontend Linter** | `npm --prefix frontend run lint` | **0 errors**, warnings | Unused imports/variables across components (`oxlint`). |
| **Frontend Unit Tests** | N/A | **None configured** | No Vitest/Jest test suite exists in `frontend/package.json`. |

---

## 2. Current Architecture

SecureSBOM currently has **two overlapping backend entrypoints** and **two overlapping frontend API clients**:

1. **Backend Entrypoint A (Legacy/Root):** `backend/main.py`, `backend/database.py`, `backend/models.py`, `backend/scanner.py` — uses a separate SQLite schema (`ScanRecord`) and mounts `backend/app/api/*` routers.
2. **Backend Entrypoint B (Modular App):** `backend/app/main.py`, `backend/app/database.py`, `backend/app/models/models.py`, `backend/app/models/ai_models.py` — SQLAlchemy 2.0 ORM (`Project`, `Scan`, `Component`, `Vulnerability`, `ScanVulnerability`, `AIFinding`, `AIFindingReview`, `DependencyAlternative`, `MonitoringSource`, `ProcessedAdvisory`, `MonitoringAlert`, `GeneratedReport`).
3. **Frontend (`frontend/src/`):**
   - `frontend/src/api.js` (used by `ScannerApp.jsx` and most views; reads `VITE_API_URL` with `http://127.0.0.1:8000` fallback, sends spoofable `X-User-Id` header).
   - `frontend/src/services/api.js` (unused/duplicate client hardcoding `http://localhost:8000`).

---

## 3. Existing Features (Verified)

- **Dependency Parsing (`backend/app/services/dependency_parser.py`):** Basic regex parsing of `requirements.txt` (`==`, `>=`, `<=`, `~=`, `!=`, `>`, `<`). Strips comments and environment markers.
- **Transitive Resolution (`backend/app/services/transitive_resolver.py`):** Queries PyPI JSON API up to hardcoded `max_depth=2`.
- **CycloneDX SBOM Generation (`backend/app/services/sbom_generator.py`):** Generates CycloneDX 1.4/1.5 JSON with PURLs.
- **OSV & NVD Scanning (`osv_service.py`, `nvd_service.py`, `correlation_service.py`):** Queries OSV `/v1/query`, enriches CVEs via NVD 2.0, deduplicates aliases via connected components, assigns P1–P5 priority tiers.
- **AI Vulnerability Assessment (`ai_analysis.py`, `ai_provider.py`):** Mock, OpenAI, and Gemini providers; Category B isolation (`AIFinding` table); review history (`AIFindingReview`).
- **Safer Alternatives (`alternatives_service.py`):** PyPI release inspection for minimal safe upgrades.
- **Monitoring (`monitoring_service.py`):** Periodic OSV polling for saved scan components and alert generation.
- **Reports (`report_service.py`):** JSON, CSV, and ReportLab PDF exports.

---

## 4. Missing Features & Deficiencies

### 4.1 Security & Authentication Deficiencies (CRITICAL)
1. **No Authentication:** No `User` model, no Argon2id password hashing, no JWT access/refresh tokens, no token revocation, no login/register endpoints, no protected routes.
2. **Spoofable Identity:** `Navbar.jsx` has a hardcoded `<select>` dropdown (`default_user`, `security_lead`, `developer_workspace`) sent via `X-User-Id`, trusted blindly by `ai_routes.py`.
3. **No Cross-User Isolation in `app/api/routes.py`:** `Project` and `Scan` models have no `owner_id`/`user_id` foreign key. Any caller can read any scan or SBOM.
4. **No Encryption:** No field-level authenticated encryption (`Fernet`/AES-GCM) for sensitive user-provided AI API keys or private notes; no key rotation strategy; no security headers middleware.
5. **Wildcard CORS:** `allow_origins=["*"]` with `allow_credentials=True` in both `backend/main.py` and `backend/app/main.py`.
6. **Secret Management:** `.gitignore` does not exclude `.env`, `*.db`, `frontend/dist/`, or `frontend/node_modules/`.

### 4.2 Scanner & Vulnerability Engine Gaps (HIGH)
1. **Manifest Formats:** Only `requirements.txt` is supported in `app/services/dependency_parser.py`. Missing `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, and CycloneDX JSON SBOM import.
2. **Environment Markers & PEP 440:** `dependency_parser.py` and `transitive_resolver.py` silently strip environment markers (`; python_version < '3.8'`) instead of evaluating/recording them, and `transitive_resolver.py` uses regex instead of `packaging.requirements.Requirement` and `packaging.specifiers.SpecifierSet`.
3. **Hardcoded Depth & Version Resolution:** `routes.py` hardcodes `max_depth=2`; `transitive_resolver.py` picks `version` via regex on `>=` rather than resolving the actual matching release from PyPI.
4. **Vulnerability Coverage Gaps:** Missing batch OSV querying (`querybatch`), persistent SQLite/DB caching with TTL, CISA KEV catalog enrichment, FIRST EPSS probability enrichment, and explicit `coverage_status` when external APIs fail.

### 4.3 Intelligence, RAG & Lifecycle Gaps (HIGH)
1. **No Continuous Intelligence Pipeline:** No adapters for GitHub Security Advisories, PyPA Advisory DB, CVE List V5, GitHub Security Lab, oss-security, maintainer advisories, or RSS/Atom feeds.
2. **No Local Intelligence Dataset:** Missing `IntelligenceSource`, `IntelligenceDocument`, `IntelligenceSyncRun`, `AdvisoryEvidence`, `PackageIntelligenceMatch`, `EmergingFinding`, `PotentialWeakness`, `FindingReview`, `FindingStatusHistory`.
3. **No Evidence-Driven RAG:** `ai_analysis.py` only fetches PyPI metadata and OSV raw hits—it does not perform hybrid semantic + keyword retrieval (e.g., TF-IDF/embeddings + SQLite FTS5) over a local intelligence dataset, nor does it support Ollama/llama.cpp explicitly with indirect prompt-injection sanitization.
4. **No Category A / B / C Separation:** Only Category A (`Vulnerability`) and Category B (`AIFinding`) exist; Category C (`PotentialWeakness`) and automatic finding promotion/reassessment are missing.
5. **No Optional Static Analysis:** No opt-in Bandit/AST static analyzer for user-authorized code.

### 4.4 Deployment & Configuration Bugs (HIGH)
1. **Windows `DEBUG=release` Crash:** `backend/app/config.py` defines `DEBUG: bool = True`, which crashes on Windows when `DEBUG=release` is set in the OS environment.
2. **Relative SQLite Path:** `sqlite:///./securesbom.db` creates duplicate DBs (`./securesbom.db` vs `backend/securesbom.db`).
3. **No Alembic Migrations:** Schema changes rely on `Base.metadata.create_all()`.
4. **No Docker / Production Config:** Missing `Dockerfile`s, `docker-compose.yml`, `nginx.conf`, readiness probe, and graceful shutdown.

---

## 5. Prioritized Implementation Plan

1. **Phase 1:** Fix `config.py` (`DEBUG` parsing, absolute DB path, secret/CORS/env settings), upgrade `dependency_parser.py` & `transitive_resolver.py` (PEP 508/440, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, CycloneDX import, cycle/explosion guards), and upgrade `osv_service.py` / `nvd_service.py` / `correlation_service.py` (batch OSV, persistent cache, CISA KEV, FIRST EPSS, coverage tracking).
2. **Phase 2:** Implement Alembic migrations, `User` & `RefreshToken` models, Argon2id hashing, JWT access + rotating refresh tokens, RBAC (`user`, `admin`), ownership isolation on all routes, and field-level Fernet encryption.
3. **Phase 3–4:** Build `IntelligenceSource`, `IntelligenceDocument`, `IntelligenceSyncRun`, `AdvisoryEvidence`, `PackageIntelligenceMatch`, SQLite FTS5 + vector/hybrid search, and incremental source adapters (GitHub Advisories, PyPA, CVE List V5, oss-security, RSS/Atom, etc.).
4. **Phase 5–6:** Build Evidence-Driven RAG Engine, Category A/B/C separation (`EmergingFinding`, `PotentialWeakness`, `FindingReview`, `FindingStatusHistory`), deterministic confidence rubric, abstention, prompt-injection defense, finding promotion, and opt-in static security analysis.
5. **Phase 7–9:** Extend React frontend with Auth (`LoginPage`, `AuthContext`, `ProtectedRoute`), consolidate `api.js`, add all 11 dashboard tabs (`Overview`, `Dependencies`, `Confirmed Vulnerabilities`, `Emerging Vulnerabilities`, `AI Security Assessment`, `Intelligence Dataset`, `Remediation`, `Monitoring and Alerts`, `Scan History`, `Reports`, `Settings`), enhance remediation and PDF/CSV/JSON reports, and wire background reassessment.
6. **Phase 10–12:** Add security headers, rate limiting, Dockerfiles, `docker-compose.yml`, Nginx HTTPS config, comprehensive pytest + evaluation suite (including temporal holdout), and full documentation suite.
