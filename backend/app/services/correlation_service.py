import logging
import httpx
from typing import List, Dict, Any, Set, Tuple
from collections import defaultdict
from app.services.osv_service import (
    query_osv_for_package,
    extract_all_identifiers,
    extract_cve_id,
    extract_references,
    extract_remediation_info,
    clean_summary_and_details,
    extract_severity_and_cvss
)
from app.services.nvd_service import enrich_vulnerability_with_nvd
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

async def correlate_vulnerabilities(components: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Correlate components against OSV API and NVD API enrichment.
    Builds alias graphs per component to merge duplicate advisory records into canonical vulnerabilities.
    
    Returns dictionary with:
      - canonical_vulnerabilities: List of normalized vulnerability findings
      - metrics: {
          unique_vuln_count,
          advisory_record_count,
          affected_components_count,
          critical_count, high_count, medium_count, low_count, info_count, unknown_count
        }
    """
    canonical_vulnerabilities: List[Dict[str, Any]] = []
    total_advisory_records = 0
    affected_components = set()

    sev_distribution = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
        "UNKNOWN": 0
    }

    async with httpx.AsyncClient() as client:
        for comp in components:
            name = comp["name"]
            version = comp["version"]
            norm_name = comp["normalized_name"]

            raw_osv_hits = await query_osv_for_package(client, name, version)
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

                # Add nodes and edges between all co-occurring IDs in this raw record
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
                    # BFS/DFS to find all connected identifiers
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
                    
                    # Extract references
                    for r in extract_references(raw_rec):
                        all_references.add(r)

                    # Extract OSV severity & CVSS
                    osv_cvss_score, osv_cvss_vector, osv_sev = extract_severity_and_cvss(raw_rec)
                    severity_sources.append({
                        "source": "OSV",
                        "severity": osv_sev,
                        "cvss_score": osv_cvss_score,
                        "cvss_vector": osv_cvss_vector
                    })

                    # Clean summary & details
                    s_text, d_text = clean_summary_and_details(raw_rec, name)
                    if not summary or summary == "Security advisory for component":
                        summary = s_text
                    if not details or details == summary:
                        details = d_text

                    # Extract remediation
                    aff_r, fix_v = extract_remediation_info(raw_rec)
                    if fix_v and not fixed_version:
                        fixed_version = fix_v
                    if aff_r and not affected_range:
                        affected_range = aff_r

                # Check if bucket has CVE alias to query NVD
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

                # Deterministic severity and priority resolution
                final_severity, best_cvss, best_vector, priority_tier = resolve_canonical_severity(severity_sources)

                # Format aliases (excluding canonical ID itself)
                aliases_list = sorted([a for a in merged_aliases if a != canonical_id])

                # Update severity distribution counts
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
                    "references": sorted(list(all_references))
                })

    metrics = {
        "unique_vuln_count": len(canonical_vulnerabilities),
        "advisory_record_count": total_advisory_records,
        "affected_components_count": len(affected_components),
        "critical_count": sev_distribution["CRITICAL"],
        "high_count": sev_distribution["HIGH"],
        "medium_count": sev_distribution["MEDIUM"],
        "low_count": sev_distribution["LOW"],
        "info_count": sev_distribution["INFO"],
        "unknown_count": sev_distribution["UNKNOWN"]
    }

    return {
        "canonical_vulnerabilities": canonical_vulnerabilities,
        "metrics": metrics
    }
