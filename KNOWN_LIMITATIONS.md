# SecureSBOM — Known Limitations

1. **Ecosystem Scope:** Primary dependency parsing and vulnerability correlation target the Python/PyPI ecosystem (`requirements.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, CycloneDX JSON).
2. **Transitive Resolution Completeness:** Resolution relies on PyPI JSON `requires_dist` metadata up to configurable `TRANSITIVE_MAX_DEPTH` (default 3) and `TRANSITIVE_MAX_COMPONENTS` (default 500) without executing `setup.py`. Packages requiring dynamic build-time execution or private PyPI indexes without credentials are marked `unresolved`.
3. **Database-at-Rest:** Local SQLite (`securesbom.db`) is not full-disk encrypted; sensitive credentials use MultiFernet field-level encryption. Production deployments should use PostgreSQL on encrypted volumes.
4. **Reachability:** Matching a vulnerable package version does not prove the vulnerable function is reachable in the application's call graph.
5. **External Feed Rate Limits:** Unauthenticated GitHub Advisory API requests are subject to GitHub's public rate limits; configure `GITHUB_TOKEN` and `NVD_API_KEY` for higher throughput.
6. **AI & Static Analysis:** Category B (Emerging Intelligence) and Category C (Potential Weaknesses) are non-authoritative assessments requiring human review and never substitute for confirmed CVE/OSV advisories.
