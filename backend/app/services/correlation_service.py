import asyncio
import logging
import httpx
from typing import List, Dict, Any, Set
from collections import defaultdict
from app.config import settings
from app.services.osv_service import (
    query_osv_for_package,
    set_osv_failure_tracker,
    extract_all_identifiers,
    extract_references,
    extract_remediation_info,
    clean_summary_and_details,
    extract_severity_and_cvss
)
from app.services.nvd_service import enrich_vulnerability_with_nvd
from app.services.kev_epss_service import load_cisa_kev_catalog, query_epss_batch
from app.services.prioritization import resolve_canonical_severity

logger = logging.getLogger("securesbom.correlation")


def pick_canonical_id(id_set: Set[str]) -> str:
    """
    Select deterministic canonical identifier from a set of co-occurring advisory IDs.

    Tie-break order:
    1. CVE-* (sorted lexicographically)
    2. GHSA-*
    3. PYSEC-*
    4. OSV-*
    5. Any remaining identifier
    """
    cves = sorted([i for i in id_set if i.startswith("CVE-")])
    if cves:
        return cves[0]

    ghsas = sorted([i for i in id_set if i.startswith("GHSA-")])
    if ghsas:
        return ghsas[0]

    pysecs = sorted([i for i in id_set if i.startswith("PYSEC-")])
    if pysecs:
        return pysecs[0]

    osvs = sorted([i for i in id_set if i.startswith("OSV-")])
    if osvs:
        return osvs[0]

    return sorted(list(id_set))[0]


async def _enrich_unknown_from_opensource(
    client: httpx.AsyncClient,
    canonical_id: str,
    aliases: List[str],
) -> Dict[str, Any]:
    """
    When a vulnerability has UNKNOWN severity or missing CVSS, automatically query
    OSV full record (/v1/vulns/{id}) and GitHub Advisory API (/advisories/{ghsa_id})
    to retrieve missing severity, CVSS, summary, and reference URLs.
    """
    headers = {"User-Agent": "SecureSBOM/2.1"}
    if settings.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"

    # 1. Try GitHub Security Advisory API if GHSA alias exists
    ghsa_id = next((a for a in ([canonical_id] + aliases) if str(a).startswith("GHSA-")), None)
    if ghsa_id:
        try:
            resp = await client.get(f"https://api.github.com/advisories/{ghsa_id}", headers=headers, timeout=5.0)
            if resp.status_code == 200:
                adv = resp.json()
                cvss_obj = adv.get("cvss") or {}
                sev = (adv.get("severity") or "").upper()
                if sev == "MODERATE":
                    sev = "MEDIUM"
                return {
                    "source": "GitHub-Advisory",
                    "severity": sev or "UNKNOWN",
                    "cvss_score": cvss_obj.get("score"),
                    "cvss_vector": cvss_obj.get("vector_string"),
                    "summary": adv.get("summary"),
                    "details": adv.get("description"),
                    "reference_url": adv.get("html_url"),
                }
        except Exception:
            pass

    # 2. Fallback to OSV full vulnerability endpoint
    try:
        resp = await client.get(f"https://api.osv.dev/v1/vulns/{canonical_id}", timeout=5.0)
        if resp.status_code == 200:
            raw = resp.json()
            score, vec, sev = extract_severity_and_cvss(raw)
            refs = extract_references(raw)
            return {
                "source": "OSV-Detail",
                "severity": sev,
                "cvss_score": score,
                "cvss_vector": vec,
                "summary": raw.get("summary"),
                "details": raw.get("details"),
                "reference_url": refs[0] if refs else f"https://osv.dev/vulnerability/{canonical_id}",
            }
    except Exception:
        pass

    return {}


async def correlate_vulnerabilities(components: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Correlate components against OSV API, NVD API enrichment, CISA KEV, FIRST EPSS,
    and automatic open-source enrichment for UNKNOWN vulnerabilities.
    """
    canonical_vulnerabilities: List[Dict[str, Any]] = []
    total_advisory_records = 0
    affected_components = set()
    status_tracker: Dict[str, Any] = {"osv_failures": 0, "nvd_failures": 0}
    set_osv_failure_tracker(status_tracker)

    sev_distribution = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "UNKNOWN": 0
    }

    async with httpx.AsyncClient() as client:
        # Parallelize OSV queries across all components
        osv_sem = asyncio.Semaphore(10)

        async def _bounded_osv(c: Dict[str, Any]):
            async with osv_sem:
                return c, await query_osv_for_package(client, c["name"], c["version"])

        osv_results = await asyncio.gather(*[_bounded_osv(c) for c in components])

        for comp, raw_osv_hits in osv_results:
            name = comp["name"]
            version = comp["version"]
            norm_name = comp["normalized_name"]

            if not raw_osv_hits:
                continue

            total_advisory_records += len(raw_osv_hits)

            # Step 1: Build graph of co-occurring identifiers for this component:version
            adj_graph = defaultdict(set)
            record_map = {}

            for idx, raw_rec in enumerate(raw_osv_hits):
                ids = extract_all_identifiers(raw_rec)
                if not ids:
                    raw_id = f"RAW-{norm_name}-{idx}"
                    ids = {raw_id}
                    raw_rec["id"] = raw_id

                record_map[idx] = (raw_rec, ids)

                id_list = list(ids)
                for i in range(len(id_list)):
                    adj_graph[id_list[i]].add(id_list[i])
                    for j in range(i + 1, len(id_list)):
                        adj_graph[id_list[i]].add(id_list[j])
                        adj_graph[id_list[j]].add(id_list[i])

            # Step 2: Extract connected components from the alias graph
            visited_nodes = set()
            id_to_component_group = {}

            for node in list(adj_graph.keys()):
                if node not in visited_nodes:
                    group = set()
                    queue = [node]
                    visited_nodes.add(node)
                    while queue:
                        curr = queue.pop(0)
                        group.add(curr)
                        for neighbor in adj_graph[curr]:
                            if neighbor not in visited_nodes:
                                visited_nodes.add(neighbor)
                                queue.append(neighbor)

                    canonical_id = pick_canonical_id(group)
                    for member in group:
                        id_to_component_group[member] = (canonical_id, group)

            # Step 3: Group raw records into canonical vulnerability buckets
            canonical_buckets = defaultdict(list)
            for idx, (raw_rec, ids) in record_map.items():
                first_id = list(ids)[0]
                canonical_id, full_group = id_to_component_group[first_id]
                canonical_buckets[canonical_id].append((raw_rec, ids, full_group))

            # Step 4: Synthesize one Canonical Vulnerability per bucket
            if canonical_buckets:
                affected_components.add(norm_name)

            for canonical_id, bucket in canonical_buckets.items():
                merged_aliases = set()
                all_references = set()
                sources_set = set(["OSV"])
                severity_sources = []

                summary = ""
                details = ""
                affected_range = None
                fixed_version = None

                for raw_rec, ids, full_group in bucket:
                    merged_aliases.update(full_group)

                    for r in extract_references(raw_rec):
                        all_references.add(r)

                    osv_cvss_score, osv_cvss_vector, osv_sev = extract_severity_and_cvss(raw_rec)
                    severity_sources.append({
                        "source": "OSV",
                        "severity": osv_sev,
                        "cvss_score": osv_cvss_score,
                        "cvss_vector": osv_cvss_vector
                    })

                    s_text, d_text = clean_summary_and_details(raw_rec, name)
                    if not summary or summary == "Security advisory for component":
                        summary = s_text
                    if not details or details == summary:
                        details = d_text

                    # Extract remediation scoped to the current package
                    aff_r, fix_v = extract_remediation_info(raw_rec, pkg_name=name)
                    if fix_v and not fixed_version:
                        fixed_version = fix_v
                    if aff_r and not affected_range:
                        affected_range = aff_r

                cve_alias = next((i for i in merged_aliases if i.startswith("CVE-")), None)
                if cve_alias:
                    sources_set.add("NVD")
                    nvd_data = await enrich_vulnerability_with_nvd(client, cve_alias)
                    if nvd_data:
                        severity_sources.append({
                            "source": "NVD",
                            "severity": nvd_data.get("severity", "UNKNOWN"),
                            "cvss_score": nvd_data.get("cvss_score"),
                            "cvss_vector": nvd_data.get("cvss_vector")
                        })

                final_severity, best_cvss, best_vector, priority_tier = resolve_canonical_severity(severity_sources)
                aliases_list = sorted([a for a in merged_aliases if a != canonical_id])

                # Auto-enrich UNKNOWN vulnerabilities from open-source advisory feeds (GHSA / OSV Detail)
                if final_severity == "UNKNOWN" or best_cvss is None:
                    ext_info = await _enrich_unknown_from_opensource(client, canonical_id, aliases_list)
                    if ext_info:
                        if ext_info.get("reference_url"):
                            all_references.add(ext_info["reference_url"])
                        if ext_info.get("summary") and (not summary or summary == "Security advisory for component"):
                            summary = ext_info["summary"]
                        if ext_info.get("details") and (not details or details == summary):
                            details = ext_info["details"]
                        if ext_info.get("severity") != "UNKNOWN" or ext_info.get("cvss_score") is not None:
                            sources_set.add(ext_info.get("source", "OpenSource"))
                            severity_sources.append({
                                "source": ext_info.get("source", "OpenSource"),
                                "severity": ext_info.get("severity", "UNKNOWN"),
                                "cvss_score": ext_info.get("cvss_score"),
                                "cvss_vector": ext_info.get("cvss_vector"),
                            })
                            final_severity, best_cvss, best_vector, priority_tier = resolve_canonical_severity(severity_sources)

                sev_key = final_severity.upper() if final_severity.upper() in sev_distribution else "UNKNOWN"
                sev_distribution[sev_key] += 1

                canonical_vulnerabilities.append({
                    "canonical_id": canonical_id,
                    "osv_id": canonical_id,
                    "cve_id": cve_alias or (canonical_id if canonical_id.startswith("CVE-") else None),
                    "aliases": aliases_list,
                    "sources": sorted(list(sources_set)),
                    "summary": summary or "Security advisory for component",
                    "details": details or summary or "Security advisory for component",
                    "cvss_score": best_cvss,
                    "cvss_vector": best_vector,
                    "severity": final_severity,
                    "severity_sources": severity_sources,
                    "priority_tier": priority_tier,
                    "affected_component_name": comp["name"],
                    "affected_component_version": comp["version"],
                    "component_normalized_name": norm_name,
                    "is_direct": comp.get("is_direct", True),
                    "affected_range": affected_range,
                    "fixed_version": fixed_version,
                    "references": sorted(list(all_references)),
                    "is_kev": False,
                    "epss_score": None,
                    "epss_percentile": None,
                })

        # Step 5: Enrich with CISA KEV and FIRST EPSS (separate fields, never altering counts)
        cves_to_enrich = [v["cve_id"] for v in canonical_vulnerabilities if v.get("cve_id")]
        if cves_to_enrich:
            kev_catalog = await load_cisa_kev_catalog(client)
            epss_map = await query_epss_batch(client, cves_to_enrich)
            for v in canonical_vulnerabilities:
                cid = v.get("cve_id")
                if not cid:
                    continue
                if cid in kev_catalog:
                    v.update(kev_catalog[cid])
                    if "CISA-KEV" not in v["sources"]:
                        v["sources"].append("CISA-KEV")
                if cid in epss_map:
                    v.update(epss_map[cid])
                    if "EPSS" not in v["sources"]:
                        v["sources"].append("EPSS")

    coverage_status = "complete"
    if status_tracker["osv_failures"] > 0:
        coverage_status = "incomplete_coverage"

    metrics = {
        "unique_vuln_count": len(canonical_vulnerabilities),
        "advisory_record_count": total_advisory_records,
        "affected_components_count": len(affected_components),
        "critical_count": sev_distribution["CRITICAL"],
        "high_count": sev_distribution["HIGH"],
        "medium_count": sev_distribution["MEDIUM"],
        "low_count": sev_distribution["LOW"],
        "info_count": sev_distribution["INFO"],
        "unknown_count": sev_distribution["UNKNOWN"],
        "coverage_status": coverage_status,
        "osv_failures": status_tracker["osv_failures"],
    }

    return {
        "canonical_vulnerabilities": canonical_vulnerabilities,
        "metrics": metrics
    }
