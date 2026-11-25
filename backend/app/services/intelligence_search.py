"""
Hybrid Semantic + Keyword Search over the Local Security Intelligence Dataset.
Uses SQLite FTS5 for BM25 keyword retrieval + deterministic TF-IDF cosine similarity
for semantic matching, fused via Reciprocal Rank Fusion (RRF).
Also provides deterministic PEP 440 affected-version verification.
"""
import logging
from typing import List, Dict, Any, Optional
from sqlalchemy import text
from sqlalchemy.orm import Session
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from packaging.version import Version, InvalidVersion

from app.database import engine, db_url
from app.models.intelligence_models import IntelligenceDocument
from app.services.dependency_parser import normalize_package_name

logger = logging.getLogger("securesbom.intel_search")


def ensure_fts5_index() -> None:
    """Create SQLite FTS5 virtual table if running on SQLite."""
    if not db_url.startswith("sqlite"):
        return
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE VIRTUAL TABLE IF NOT EXISTS intelligence_fts USING fts5(
                    doc_uid UNINDEXED,
                    title,
                    summary,
                    package_names,
                    aliases
                )
            """))
    except Exception as exc:
        logger.warning("FTS5 setup skipped: %s", exc)


def upsert_fts5_document(doc: IntelligenceDocument) -> None:
    """Insert or update a document in the SQLite FTS5 index."""
    if not db_url.startswith("sqlite"):
        return
    ensure_fts5_index()
    pkgs = " ".join(doc.package_names_json or [])
    aliases = " ".join(doc.aliases_json or [])
    try:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM intelligence_fts WHERE doc_uid = :uid"), {"uid": doc.doc_uid})
            conn.execute(
                text("""
                    INSERT INTO intelligence_fts (doc_uid, title, summary, package_names, aliases)
                    VALUES (:uid, :title, :summary, :pkgs, :aliases)
                """),
                {
                    "uid": doc.doc_uid,
                    "title": doc.title or "",
                    "summary": (doc.summary or "") + " " + (doc.excerpt or ""),
                    "pkgs": pkgs,
                    "aliases": aliases,
                },
            )
    except Exception as exc:
        logger.debug("FTS5 upsert failed for %s: %s", doc.doc_uid, exc)


def check_version_applicability(package_version: str, affected_ranges: List[str]) -> str:
    """
    Deterministically check whether `package_version` falls inside any PEP 440 affected range.
    Returns: 'applicable', 'not_applicable', or 'unverified'.
    """
    if not package_version or package_version in ("unknown", "unpinned", "unresolved"):
        return "unverified"
    if not affected_ranges:
        return "unverified"

    try:
        v = Version(package_version)
    except InvalidVersion:
        return "unverified"

    parsed_any = False
    for r_str in affected_ranges:
        if not r_str or not isinstance(r_str, str):
            continue
        try:
            spec = SpecifierSet(r_str)
            parsed_any = True
            if v in spec:
                return "applicable"
        except InvalidSpecifier:
            continue

    return "not_applicable" if parsed_any else "unverified"


def hybrid_search_intelligence(
    db: Session,
    query_text: str,
    package_name: Optional[str] = None,
    ecosystem: str = "PyPI",
    top_k: int = 10,
) -> List[Dict[str, Any]]:
    """
    Perform hybrid keyword (FTS5/SQL) + semantic (TF-IDF cosine) retrieval
    over active IntelligenceDocuments.
    """
    q = db.query(IntelligenceDocument).filter(
        IntelligenceDocument.is_withdrawn == False  # noqa: E712
    )
    if ecosystem:
        q = q.filter(IntelligenceDocument.ecosystem == ecosystem)

    all_docs = q.all()
    if not all_docs:
        return []

    norm_pkg = normalize_package_name(package_name) if package_name else None

    # Filter by package identity if specified
    candidate_docs = []
    for doc in all_docs:
        pkgs = [normalize_package_name(p) for p in (doc.package_names_json or [])]
        if norm_pkg:
            if norm_pkg in pkgs or norm_pkg in (doc.title or "").lower() or norm_pkg in (doc.summary or "").lower():
                candidate_docs.append(doc)
        else:
            candidate_docs.append(doc)

    if not candidate_docs:
        return []

    # Keyword scores via FTS5 or token overlap
    keyword_ranks: Dict[str, int] = {}
    if db_url.startswith("sqlite") and query_text.strip():
        ensure_fts5_index()
        safe_q = " ".join(w for w in query_text.replace('"', " ").split() if w.isalnum() or "-" in w)
        if safe_q:
            try:
                fts_query = " OR ".join(f'"{t}"' for t in safe_q.split()[:8])
                with engine.connect() as conn:
                    rows = conn.execute(
                        text("SELECT doc_uid FROM intelligence_fts WHERE intelligence_fts MATCH :q LIMIT 50"),
                        {"q": fts_query},
                    ).fetchall()
                    for idx, row in enumerate(rows):
                        keyword_ranks[row[0]] = idx + 1
            except Exception:
                pass

    # Semantic scores via TF-IDF cosine similarity
    corpus = [
        f"{d.title or ''} {d.summary or ''} {d.excerpt or ''} {' '.join(d.package_names_json or [])} {' '.join(d.aliases_json or [])}"
        for d in candidate_docs
    ]
    semantic_scores: Dict[str, float] = {}
    try:
        vec = TfidfVectorizer(stop_words="english", max_features=5000)
        matrix = vec.fit_transform(corpus + [query_text or (package_name or "")])
        q_vec = matrix[-1]
        doc_vecs = matrix[:-1]
        sims = cosine_similarity(q_vec, doc_vecs).flatten()
        for doc, sim in zip(candidate_docs, sims):
            semantic_scores[doc.doc_uid] = float(sim)
    except Exception:
        for doc in candidate_docs:
            semantic_scores[doc.doc_uid] = 0.0

    # Rank by Reciprocal Rank Fusion (RRF) + reliability weight
    reliability_weight = {"authoritative": 1.3, "high": 1.15, "medium": 1.0, "community": 0.9}
    sem_sorted = sorted(candidate_docs, key=lambda d: semantic_scores.get(d.doc_uid, 0.0), reverse=True)
    sem_ranks = {d.doc_uid: idx + 1 for idx, d in enumerate(sem_sorted)}

    scored: List[tuple] = []
    for doc in candidate_docs:
        k_rank = keyword_ranks.get(doc.doc_uid, len(candidate_docs) + 1)
        s_rank = sem_ranks.get(doc.doc_uid, len(candidate_docs) + 1)
        rrf = (1.0 / (60 + k_rank)) + (1.0 / (60 + s_rank))
        rel = reliability_weight.get(doc.source_reliability or "medium", 1.0)
        # Boost exact package match
        pkgs = [normalize_package_name(p) for p in (doc.package_names_json or [])]
        pkg_boost = 1.25 if (norm_pkg and norm_pkg in pkgs) else 1.0
        final_score = rrf * rel * pkg_boost
        scored.append((final_score, doc))

    scored.sort(key=lambda x: x[0], reverse=True)
    results = []
    for score, doc in scored[:top_k]:
        results.append({
            "doc_uid": doc.doc_uid,
            "external_id": doc.external_id,
            "title": doc.title,
            "summary": doc.summary,
            "excerpt": doc.excerpt,
            "url": doc.url,
            "published_at": doc.published_at.isoformat() if doc.published_at else None,
            "retrieved_at": doc.retrieved_at.isoformat() if doc.retrieved_at else None,
            "package_names": doc.package_names_json or [],
            "ecosystem": doc.ecosystem,
            "aliases": doc.aliases_json or [],
            "affected_ranges": doc.affected_ranges_json or [],
            "fixed_versions": doc.fixed_versions_json or [],
            "source_reliability": doc.source_reliability,
            "relevance_score": round(score, 5),
        })
    return results
