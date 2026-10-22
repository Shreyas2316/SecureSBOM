import re
from typing import List, Dict, Any, Optional, Set, Tuple
from backend.severity import evaluate_severity, SeverityLevel


def normalize_identifier(identifier: str) -> str:
    """Normalizes vulnerability identifier (CVE, GHSA, PYSEC) to standard ecosystem casing."""
    if not identifier:
        return ""
    clean = identifier.strip()
    if clean.upper().startswith("CVE-"):
        return clean.upper()
    if clean.upper().startswith("GHSA-"):
        return "GHSA-" + clean[5:].lower()
    if clean.upper().startswith("PYSEC-"):
        return clean.upper()
    return clean


class DisjointSet:
    """Union-Find data structure with path compression for deterministic graph correlation."""
    def __init__(self):
        self.parent: Dict[str, str] = {}

    def find(self, item: str) -> str:
        if item not in self.parent:
            self.parent[item] = item
            return item
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def union(self, a: str, b: str) -> None:
        root_a = self.find(a)
        root_b = self.find(b)
        if root_a != root_b:
            # Deterministic ordering for stable canonical root
            if root_a < root_b:
                self.parent[root_b] = root_a
            else:
                self.parent[root_a] = root_b


def select_canonical_identifier(identifiers: Set[str]) -> str:
    """
    Selects the most authoritative identifier as the canonical finding ID.
    Precedence:
    1. CVE identifier (e.g. CVE-2023-32681) - industry universal standard
    2. GHSA identifier (e.g. GHSA-j8r2-6x86-q33q)
    3. PYSEC identifier (e.g. PYSEC-2023-99)
    4. Any other identifier (lexicographically smallest)
    """
    if not identifiers:
        return "UNKNOWN-VULN"

    cves = sorted([i for i in identifiers if i.startswith("CVE-")])
    if cves:
        return cves[0]

    ghsas = sorted([i for i in identifiers if i.startswith("GHSA-")])
    if ghsas:
        return ghsas[0]

    pysecs = sorted([i for i in identifiers if i.startswith("PYSEC-")])
    if pysecs:
        return pysecs[0]

    return sorted(list(identifiers))[0]


def extract_fixed_versions(raw_advisories: List[Dict[str, Any]]) -> List[str]:
    """Extracts all unique fixed version numbers from advisory records."""
    fixed_versions: Set[str] = set()
    for adv in raw_advisories:
        # Check affected ranges
        for item in adv.get("affected_versions", []):
            if isinstance(item, str):
                fixed_match = re.search(r"<\s*([0-9a-zA-Z._\-]+)", item)
                if fixed_match:
                    fixed_versions.add(fixed_match.group(1))
        # Check explicit fixed field if present
        if "fixed_version" in adv and adv["fixed_version"]:
            fixed_versions.add(str(adv["fixed_version"]))
    return sorted(list(fixed_versions))


def correlate_vulnerabilities(
    raw_findings: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], int, int]:
    """
    Correlates raw vulnerability advisory records into canonical deduplicated vulnerability findings.
    
    Correlation Rules:
    1. Extracts primary ID and all aliases for each record.
    2. Builds an equivalence graph between IDs that share an explicit alias link.
    3. Groups connected components into single canonical findings.
    4. Distinct vulnerabilities without shared identifiers are NOT merged, even if descriptions match.
    5. Selects canonical identifier (preferring CVE > GHSA > PYSEC).
    6. Resolves severity and CVSS scores transparently, recording any conflicts.
    7. Retains all source advisories, URLs, and package references.
    
    Returns:
    - canonical_findings: List[Dict[str, Any]]
    - total_raw_count: int
    - total_canonical_count: int
    """
    from typing import Tuple

    if not raw_findings:
        return [], 0, 0

    # Step 1: Normalize all records and deduplicate identical raw records (same id + same package)
    seen_raw_keys = set()
    normalized_records: List[Dict[str, Any]] = []

    for raw in raw_findings:
        vuln_id = normalize_identifier(raw.get("vuln_id") or raw.get("id") or "UNKNOWN")
        package = raw.get("package_name", "")
        key = (vuln_id, package)
        
        # Check duplicate records from same source
        if key in seen_raw_keys:
            continue
        seen_raw_keys.add(key)

        aliases = [normalize_identifier(a) for a in raw.get("aliases", []) if a]
        all_ids = set([vuln_id] + aliases)

        record = {
            "primary_id": vuln_id,
            "aliases": aliases,
            "all_ids": all_ids,
            "package_name": package,
            "package_version": raw.get("version", raw.get("package_version", "")),
            "purl": raw.get("purl", ""),
            "summary": raw.get("summary", "No summary provided"),
            "severity_raw": raw.get("severity", "severity unavailable"),
            "affected_versions": raw.get("affected_versions", []),
            "source": raw.get("source", "OSV"),
            "source_url": raw.get("source_url") or f"https://osv.dev/vulnerability/{vuln_id}" if "UNKNOWN" not in vuln_id else "",
            "raw_payload": raw
        }
        normalized_records.append(record)

    total_raw_count = len(normalized_records)

    # Step 2: Use Union-Find to group records sharing at least one common identifier
    uf = DisjointSet()
    for rec in normalized_records:
        ids_list = list(rec["all_ids"])
        first_id = ids_list[0]
        for other_id in ids_list[1:]:
            uf.union(first_id, other_id)

    # Step 3: Cluster records by component root
    clusters: Dict[str, List[Dict[str, Any]]] = {}
    for rec in normalized_records:
        first_id = list(rec["all_ids"])[0]
        root = uf.find(first_id)
        if root not in clusters:
            clusters[root] = []
        clusters[root].append(rec)

    # Step 4: Construct canonical findings from clusters
    canonical_findings: List[Dict[str, Any]] = []

    for root, cluster_records in clusters.items():
        # Aggregate all identifiers across the cluster
        all_cluster_ids: Set[str] = set()
        all_sources: Set[str] = set()
        all_source_urls: Set[str] = set()
        affected_packages_map: Dict[str, Dict[str, Any]] = {}
        all_summaries: List[str] = []

        # Severity resolution
        severity_evaluations: List[Dict[str, Any]] = []

        for rec in cluster_records:
            all_cluster_ids.update(rec["all_ids"])
            all_sources.add(rec["source"])
            if rec["source_url"]:
                all_source_urls.add(rec["source_url"])
            if rec["summary"] and rec["summary"] != "No summary provided":
                all_summaries.append(rec["summary"])

            # Map affected package
            pkg_name = rec["package_name"]
            if pkg_name:
                if pkg_name not in affected_packages_map:
                    affected_packages_map[pkg_name] = {
                        "package_name": pkg_name,
                        "version": rec["package_version"],
                        "purl": rec["purl"],
                        "affected_ranges": rec["affected_versions"]
                    }

            # Evaluate severity for this advisory record
            sev_eval = evaluate_severity(
                raw_severity_str=rec["severity_raw"],
                source=rec["source"]
            )
            sev_eval["source_id"] = rec["primary_id"]
            severity_evaluations.append(sev_eval)

        # Select canonical identifier
        canonical_id = select_canonical_identifier(all_cluster_ids)
        aliases = sorted([i for i in all_cluster_ids if i != canonical_id])

        # Pick the most informative summary (longest or first non-empty)
        summary = "No summary provided"
        if all_summaries:
            summary = max(all_summaries, key=len)

        # Extract fixed versions
        fixed_versions = extract_fixed_versions(cluster_records)

        # Aggregate CVSS and determine canonical severity
        # Pick authoritative score: prefer valid numeric scores, prefer v3.1, or highest verified
        valid_scores = [se for se in severity_evaluations if se["score"] is not None]
        
        has_cvss_conflict = False
        if len(valid_scores) > 1:
            scores_vals = [s["score"] for s in valid_scores]
            if max(scores_vals) - min(scores_vals) > 0.5:
                has_cvss_conflict = True

        if valid_scores:
            # Sort by version (3.1 preferred) and score (higher preferred if multiple)
            best_sev = sorted(
                valid_scores,
                key=lambda x: (1 if x.get("version") == "3.1" else 0, x["score"]),
                reverse=True
            )[0]
        elif severity_evaluations:
            best_sev = severity_evaluations[0]
        else:
            best_sev = evaluate_severity(score=None, source="Unknown")

        justification = best_sev["justification"]
        if has_cvss_conflict:
            all_scores_str = ", ".join(f"{se['source_id']}: {se['score']}" for se in valid_scores)
            justification += f" (Note: Discrepancy observed across sources: [{all_scores_str}])"

        canonical_finding = {
            "canonical_id": canonical_id,
            "aliases": aliases,
            "all_identifiers": sorted(list(all_cluster_ids)),
            "summary": summary,
            "severity": best_sev["severity"],
            "cvss_score": best_sev["score"],
            "cvss_version": best_sev.get("version"),
            "cvss_vector": best_sev.get("vector"),
            "severity_justification": justification,
            "has_cvss_conflict": has_cvss_conflict,
            "cvss_evaluations": severity_evaluations,
            "affected_packages": list(affected_packages_map.values()),
            "fixed_versions": fixed_versions,
            "sources": sorted(list(all_sources)),
            "source_urls": sorted(list(all_source_urls)),
            "raw_advisories_count": len(cluster_records),
            "raw_advisories": [
                {
                    "vuln_id": r["primary_id"],
                    "source": r["source"],
                    "severity": r["severity_raw"],
                    "summary": r["summary"],
                    "url": r["source_url"]
                }
                for r in cluster_records
            ]
        }
        canonical_findings.append(canonical_finding)

    # Deterministic sort: Critical -> High -> Medium -> Low -> Info -> Unknown, then by canonical_id
    sev_rank = {
        SeverityLevel.CRITICAL.value: 0,
        SeverityLevel.HIGH.value: 1,
        SeverityLevel.MEDIUM.value: 2,
        SeverityLevel.LOW.value: 3,
        SeverityLevel.INFORMATIONAL.value: 4,
        SeverityLevel.UNKNOWN.value: 5
    }
    canonical_findings.sort(key=lambda f: (sev_rank.get(f["severity"], 99), f["canonical_id"]))

    return canonical_findings, total_raw_count, len(canonical_findings)
