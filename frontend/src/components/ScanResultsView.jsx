import React, { useState, useMemo } from "react";
import { 
  Download, 
  Search, 
  Filter, 
  ExternalLink, 
  ShieldAlert, 
  CheckCircle, 
  AlertTriangle, 
  Info, 
  Boxes, 
  FileCode,
  ChevronDown,
  ChevronRight
} from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { getDownloadBomUrl, getDownloadReportUrl, downloadFileAsJson } from "../api";
import SeverityBadge from "./ui/SeverityBadge";

export default function ScanResultsView({ scanData, onOpenVulnDetail, onNavigate }) {
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [hasFixFilter, setHasFixFilter] = useState(false);
  const [sourceFilter, setSourceFilter] = useState("ALL");
  const [expandedRows, setExpandedRows] = useState(new Set());

  const report = scanData?.report || scanData;
  if (!report) {
    return (
      <div className="card" style={{ textAlign: "center", padding: "64px" }}>
        <p style={{ color: "var(--text-muted)", marginBottom: "16px" }}>No active scan results loaded.</p>
        <button className="btn btn-primary" onClick={() => onNavigate("new_scan")}>
          Initiate New Scan
        </button>
      </div>
    );
  }

  const scanId = report.scan_id || scanData?.scan_id || "";
  const summary = report.summary || {};
  const canonicalVulns = report.canonical_vulnerabilities || [];
  const sevCounts = summary.vulnerabilities_by_severity || {};
  const sourceStatus = report.source_status || {};

  // Donut chart dataset
  const chartData = [
    { name: "CRITICAL", value: sevCounts.CRITICAL || 0, color: "#FF2E4D" },
    { name: "HIGH", value: sevCounts.HIGH || 0, color: "#FF6B00" },
    { name: "MEDIUM", value: sevCounts.MEDIUM || 0, color: "#FFB800" },
    { name: "LOW", value: sevCounts.LOW || 0, color: "#00B4D8" },
    { name: "INFO", value: sevCounts.INFORMATIONAL || 0, color: "#64748B" },
  ].filter((d) => d.value > 0);

  const toggleRow = (id) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // Filter vulnerabilities
  const filteredVulns = useMemo(() => {
    return canonicalVulns.filter((vuln) => {
      // Severity filter
      if (severityFilter !== "ALL" && vuln.severity !== severityFilter) {
        return false;
      }
      // Has fix filter
      if (hasFixFilter && (!vuln.fixed_versions || vuln.fixed_versions.length === 0)) {
        return false;
      }
      // Source filter
      if (sourceFilter !== "ALL" && !vuln.sources?.includes(sourceFilter)) {
        return false;
      }
      // Text search
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesId = vuln.canonical_id?.toLowerCase().includes(query);
        const matchesAlias = vuln.aliases?.some((a) => a.toLowerCase().includes(query));
        const matchesSummary = vuln.summary?.toLowerCase().includes(query);
        const matchesPkg = vuln.affected_packages?.some((p) =>
          p.package_name?.toLowerCase().includes(query)
        );
        return matchesId || matchesAlias || matchesSummary || matchesPkg;
      }
      return true;
    });
  }, [canonicalVulns, severityFilter, hasFixFilter, sourceFilter, searchQuery]);

  return (
    <div>
      {/* Top Banner / Actions */}
      <div className="page-header">
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "6px" }}>
            <span className="badge badge-success">✓ Scan Completed</span>
            <span style={{ fontSize: "0.82rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
              {report.timestamp ? new Date(report.timestamp).toLocaleString() : ""}
            </span>
          </div>
          <h2 className="page-title">{report.manifest_name || "requirements.txt"} Scan Results</h2>
          <p className="page-subtitle">
            CycloneDX v1.5 JSON SBOM generated and verified against OWASP specification.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => downloadFileAsJson(getDownloadBomUrl(scanId), `cyclonedx-bom-${scanId ? scanId.slice(0, 8) : "latest"}.json`)}
          >
            <Download size={16} />
            <span>Download CycloneDX SBOM</span>
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => downloadFileAsJson(getDownloadReportUrl(scanId), `securesbom-report-${scanId ? scanId.slice(0, 8) : "latest"}.json`)}
          >
            <Download size={16} />
            <span>Download Report JSON</span>
          </button>
        </div>
      </div>

      {/* Metrics Header Cards with Donut Chart */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: "18px",
          marginBottom: "28px",
        }}
      >
        <div className="stat-card stat-accent">
          <span className="stat-label">Scanned Packages</span>
          <div className="stat-value">{summary.total_scanned || 0}</div>
          <span className="stat-sub">{summary.total_direct_deps || 0} Direct · {summary.total_transitive_deps || 0} Transitive</span>
        </div>

        <div className="stat-card stat-danger">
          <span className="stat-label">Canonical Findings</span>
          <div className="stat-value">{summary.total_canonical_vulnerabilities || canonicalVulns.length}</div>
          <span className="stat-sub">From {summary.total_raw_advisories || summary.total_vulnerabilities || 0} raw advisories</span>
        </div>

        <div className="stat-card stat-warning">
          <span className="stat-label">Affected Components</span>
          <div className="stat-value">{summary.vulnerable_components_count || 0}</div>
          <span className="stat-sub">Unique vulnerable libraries</span>
        </div>

        <div className="stat-card">
          <span className="stat-label">Advisory Sources</span>
          <div style={{ marginTop: "10px", display: "flex", flexDirection: "column", gap: "4px" }}>
            <span style={{ fontSize: "0.82rem", fontWeight: 600 }}>
              OSV Database: <span style={{ color: "#00FF88" }}>● {sourceStatus.osv || "OK"}</span>
            </span>
            <span style={{ fontSize: "0.82rem", fontWeight: 600 }}>
              NVD (CVSS v3.1): <span style={{ color: "#00FF88" }}>● {sourceStatus.nvd || "OK"}</span>
            </span>
          </div>
        </div>
      </div>

      {/* Severity Breakdown Bar & Donut Row */}
      <div className="card" style={{ padding: "20px 24px" }}>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: chartData.length > 0 ? "140px 1fr" : "1fr",
            gap: "24px",
            alignItems: "center",
          }}
        >
          {chartData.length > 0 && (
            <div style={{ width: "120px", height: "120px" }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={chartData}
                    innerRadius={36}
                    outerRadius={54}
                    paddingAngle={4}
                    dataKey="value"
                    stroke="none"
                  >
                    {chartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0B0E14",
                      borderColor: "rgba(255, 255, 255, 0.15)",
                      borderRadius: "8px",
                      fontSize: "0.8rem",
                      color: "#fff",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}

          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
              <span style={{ fontSize: "0.88rem", fontWeight: 700, fontFamily: "var(--font-mono)" }}>
                SEVERITY DISTRIBUTION (CVSS v3.1)
              </span>
              <span style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>
                Click badge to filter findings
              </span>
            </div>

            <div className="sev-pills-row">
              <button
                className={`badge badge-critical`}
                style={{ cursor: "pointer", opacity: severityFilter === "CRITICAL" ? 1 : 0.7 }}
                onClick={() => setSeverityFilter(severityFilter === "CRITICAL" ? "ALL" : "CRITICAL")}
              >
                CRITICAL: {sevCounts.CRITICAL || 0}
              </button>
              <button
                className={`badge badge-high`}
                style={{ cursor: "pointer", opacity: severityFilter === "HIGH" ? 1 : 0.7 }}
                onClick={() => setSeverityFilter(severityFilter === "HIGH" ? "ALL" : "HIGH")}
              >
                HIGH: {sevCounts.HIGH || 0}
              </button>
              <button
                className={`badge badge-medium`}
                style={{ cursor: "pointer", opacity: severityFilter === "MEDIUM" ? 1 : 0.7 }}
                onClick={() => setSeverityFilter(severityFilter === "MEDIUM" ? "ALL" : "MEDIUM")}
              >
                MEDIUM: {sevCounts.MEDIUM || 0}
              </button>
              <button
                className={`badge badge-low`}
                style={{ cursor: "pointer", opacity: severityFilter === "LOW" ? 1 : 0.7 }}
                onClick={() => setSeverityFilter(severityFilter === "LOW" ? "ALL" : "LOW")}
              >
                LOW: {sevCounts.LOW || 0}
              </button>
              <button
                className={`badge badge-info`}
                style={{ cursor: "pointer", opacity: severityFilter === "INFORMATIONAL" ? 1 : 0.7 }}
                onClick={() => setSeverityFilter(severityFilter === "INFORMATIONAL" ? "ALL" : "INFORMATIONAL")}
              >
                INFO: {sevCounts.INFORMATIONAL || 0}
              </button>
              <button
                className={`badge badge-unknown`}
                style={{ cursor: "pointer", opacity: severityFilter === "UNKNOWN" ? 1 : 0.7 }}
                onClick={() => setSeverityFilter(severityFilter === "UNKNOWN" ? "ALL" : "UNKNOWN")}
              >
                UNKNOWN: {sevCounts.UNKNOWN || 0}
              </button>
              {severityFilter !== "ALL" && (
                <button
                  className="btn btn-secondary btn-sm"
                  style={{ padding: "2px 8px", fontSize: "0.72rem" }}
                  onClick={() => setSeverityFilter("ALL")}
                >
                  Reset Filter
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Search & Filter Toolbar */}
      <div className="card" style={{ padding: "16px 20px" }}>
        <div style={{ display: "flex", gap: "12px", alignItems: "center", flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: "260px", position: "relative" }}>
            <Search size={16} style={{ position: "absolute", left: "12px", top: "11px", color: "var(--text-muted)" }} />
            <input
              type="text"
              className="input-text"
              style={{ paddingLeft: "36px" }}
              placeholder="Search by CVE, GHSA, package name, or keyword..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
            <select
              className="select"
              style={{ width: "auto" }}
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFORMATIONAL">Informational</option>
              <option value="UNKNOWN">Unknown</option>
            </select>

            <label style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "0.82rem", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={hasFixFilter}
                onChange={(e) => setHasFixFilter(e.target.checked)}
              />
              <span>Fix Available</span>
            </label>
          </div>
        </div>
      </div>

      {/* Canonical Findings Table with Expandable Rows */}
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
          <h3 style={{ fontSize: "1.05rem", fontWeight: 700, fontFamily: "var(--font-display)" }}>
            Canonical Vulnerabilities ({filteredVulns.length})
          </h3>
          <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
            Showing deduplicated findings across sources
          </span>
        </div>

        {filteredVulns.length === 0 ? (
          <div style={{ padding: "48px", textAlign: "center", color: "var(--text-muted)" }}>
            <CheckCircle size={36} style={{ color: "#00FF88", marginBottom: "10px" }} />
            <p style={{ fontWeight: 600 }}>No vulnerabilities match your filter criteria.</p>
          </div>
        ) : (
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: "32px" }}></th>
                  <th>Vulnerability</th>
                  <th>Severity</th>
                  <th>CVSS</th>
                  <th>Affected Component</th>
                  <th>Fixed Version</th>
                  <th>Summary</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredVulns.map((vuln, idx) => {
                  const rowId = vuln.canonical_id || vuln.vuln_id || `vuln-${idx}`;
                  const isExpanded = expandedRows.has(rowId);
                  const pkgs = Array.isArray(vuln.affected_packages) ? vuln.affected_packages : [];
                  const pkgText = pkgs.map((p) => `${p.package_name || p.name || "Component"}@${p.version || ""}`).join(", ") || (vuln.package_name ? `${vuln.package_name}@${vuln.version || ""}` : "Component");

                  const displayCvss = () => {
                    if (vuln.cvss_score === null || vuln.cvss_score === undefined || vuln.cvss_score === "") {
                      return "N/A";
                    }
                    const n = Number(vuln.cvss_score);
                    return !isNaN(n) ? n.toFixed(1) : String(vuln.cvss_score);
                  };

                  return (
                    <React.Fragment key={`${rowId}-${idx}`}>
                      <tr
                        style={{ cursor: "pointer" }}
                        onClick={() => toggleRow(rowId)}
                      >
                        <td style={{ textAlign: "center", paddingRight: 0 }}>
                          {isExpanded ? (
                            <ChevronDown size={15} color="var(--accent-cyan)" />
                          ) : (
                            <ChevronRight size={15} color="var(--text-muted)" />
                          )}
                        </td>
                        <td>
                          <div>
                            <span 
                              style={{ 
                                fontWeight: 700, 
                                fontFamily: "var(--font-mono)", 
                                color: "var(--primary)",
                                textDecoration: "underline",
                                textUnderlineOffset: "3px"
                              }}
                              onClick={(e) => {
                                e.stopPropagation();
                                onOpenVulnDetail(vuln);
                              }}
                              title="Click to view full advisory modal"
                            >
                              {vuln.canonical_id || vuln.vuln_id}
                            </span>
                            {vuln.aliases && Array.isArray(vuln.aliases) && vuln.aliases.length > 0 && (
                              <div style={{ fontSize: "0.74rem", color: "var(--text-muted)", marginTop: "2px", fontFamily: "var(--font-mono)" }}>
                                {vuln.aliases.slice(0, 2).join(", ")}
                                {vuln.aliases.length > 2 ? ` +${vuln.aliases.length - 2}` : ""}
                              </div>
                            )}
                          </div>
                        </td>
                        <td>
                          <SeverityBadge severity={vuln.severity} />
                        </td>
                        <td>
                          <span style={{ fontWeight: 700, fontSize: "0.88rem", fontFamily: "var(--font-mono)" }}>
                            {displayCvss()}
                            {vuln.cvss_version && (
                              <span style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginLeft: "4px" }}>
                                (v{vuln.cvss_version})
                              </span>
                            )}
                          </span>
                        </td>
                        <td>
                          <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.84rem", fontWeight: 600 }}>
                            {pkgText}
                          </span>
                        </td>
                        <td>
                          {vuln.fixed_versions && Array.isArray(vuln.fixed_versions) && vuln.fixed_versions.length > 0 ? (
                            <span className="badge badge-success">
                              &gt;= {vuln.fixed_versions[0]}
                            </span>
                          ) : (
                            <span style={{ color: "var(--text-light)", fontSize: "0.78rem" }}>None documented</span>
                          )}
                        </td>
                        <td style={{ maxWidth: "340px" }}>
                          <p style={{
                            fontSize: "0.82rem",
                            color: "var(--text-main)",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                            margin: 0
                          }}>
                            {vuln.summary || vuln.details || "Consolidated security advisory"}
                          </p>
                        </td>
                        <td onClick={(e) => e.stopPropagation()}>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              onOpenVulnDetail(vuln);
                            }}
                          >
                            Details
                          </button>
                        </td>
                      </tr>

                      {/* Expandable Details Drawer */}
                      {isExpanded && (
                        <tr style={{ backgroundColor: "rgba(0, 245, 255, 0.02)" }}>
                          <td colSpan={8} style={{ padding: "16px 24px", borderBottom: "1px solid var(--border-color)" }}>
                            <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: "20px", fontSize: "0.84rem" }}>
                              <div>
                                <span style={{ fontWeight: 600, color: "var(--text-muted)", display: "block", marginBottom: "4px" }}>
                                  Full Advisory Description:
                                </span>
                                <p style={{ color: "var(--text-secondary)", lineHeight: 1.5, margin: "0 0 12px 0" }}>
                                  {vuln.details || vuln.summary || "No extended description provided."}
                                </p>
                                <button
                                  type="button"
                                  className="btn btn-primary btn-sm"
                                  onClick={() => onOpenVulnDetail(vuln)}
                                >
                                  Open Full Security Advisory Modal
                                </button>
                              </div>
                              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                                <div>
                                  <span style={{ fontWeight: 600, color: "var(--text-muted)" }}>Correlated Sources: </span>
                                  <span style={{ fontFamily: "var(--font-mono)", color: "var(--accent-cyan)" }}>
                                    {Array.isArray(vuln.sources) ? vuln.sources.join(", ") : (vuln.source || "OSV / NVD")}
                                  </span>
                                </div>
                                {vuln.references && Array.isArray(vuln.references) && vuln.references.length > 0 && (
                                  <div>
                                    <span style={{ fontWeight: 600, color: "var(--text-muted)" }}>Reference Link: </span>
                                    <a
                                      href={vuln.references[0]}
                                      target="_blank"
                                      rel="noreferrer"
                                      style={{ color: "var(--accent-cyan)", textDecoration: "none", wordBreak: "break-all" }}
                                    >
                                      {vuln.references[0]}
                                    </a>
                                  </div>
                                )}
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
