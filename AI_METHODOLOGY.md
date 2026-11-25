# SecureSBOM — Intelligence Sources & AI Methodology

## 1. Continuous Intelligence Sources (`backend/app/services/intelligence_adapters.py`)
| Source Key | Name | Reliability Tier | Sync Mechanism |
|---|---|---|---|
| `github_advisories` | GitHub Security Advisories (`pip`) | `authoritative` | REST API + `ETag` / `Last-Modified` |
| `pypa_advisory_db` | PyPA Advisory Database | `authoritative` | GitHub Commits API + `ETag` |
| `cve_list_v5` | CVE List V5 (`CVEProject`) | `authoritative` | GitHub Commits API + `ETag` |
| `cisa_kev_feed` | CISA Known Exploited Vulnerabilities | `authoritative` | JSON Feed + `ETag` |
| `github_security_lab` | GitHub Security Lab Advisories | `high` | XXE-safe Atom/RSS (`defusedxml`) |
| `oss_security` | Openwall `oss-security` | `medium` | XXE-safe RSS/Atom (`defusedxml`) |
| `pypi_security_releases` | PyPI Release Updates | `medium` | XXE-safe RSS (`defusedxml`) |
| `custom_rss_*` | Configurable `CUSTOM_RSS_FEEDS` | `medium` | XXE-safe RSS/Atom (`defusedxml`) |

## 2. Evidence-Driven RAG Pipeline (`backend/app/services/rag_engine.py`)
1. **Hybrid Retrieval:** SQLite FTS5 BM25 keyword search + TF-IDF cosine similarity fused via Reciprocal Rank Fusion (RRF).
2. **Deterministic Version Check:** PEP 440 `SpecifierSet` validation marks applicability as `verified_affected`, `not_affected`, `potentially_applicable`, or `unverified`.
3. **Indirect Prompt Injection Defense:** `sanitize_untrusted_evidence()` strips embedded instruction-override directives before any AI synthesis.
4. **Abstention:** If zero relevant documents are retrieved, the engine returns `"Insufficient evidence to establish a vulnerability."` (`abstained: true`).
5. **Three-Category Separation:**
   - **Category A (`vulnerabilities`):** Confirmed OSV/NVD/KEV/EPSS records.
   - **Category B (`emerging_findings`):** Evidence-grounded emerging advisories.
   - **Category C (`potential_weaknesses`):** Static AST checks & heuristic hypotheses.
