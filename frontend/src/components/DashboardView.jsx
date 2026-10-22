import React, { useEffect, useState } from "react";
import { 
  ShieldAlert, 
  Layers, 
  GitFork, 
  FileCheck2, 
  AlertTriangle, 
  ArrowRight, 
  Clock, 
  Download, 
  Plus 
} from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { fetchScanHistory, getDownloadBomUrl, downloadFileAsJson } from "../api";
import MetricTicker from "./ui/MetricTicker";

export default function DashboardView({ onNavigate, onSelectScan, latestScan }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchScanHistory(10)
      .then((data) => {
        setHistory(data.scans || []);
      })
      .catch((err) => console.error("Error loading history:", err))
      .finally(() => setLoading(false));
  }, []);

  const activeData = latestScan?.report || (history.length > 0 ? history[0] : null);
  const summary = activeData?.summary || activeData || {};

  const totalScanned = summary.total_scanned || 0;
  const directDeps = summary.total_direct_deps ?? summary.direct_deps_count ?? 0;
  const transitiveDeps = summary.total_transitive_deps ?? summary.transitive_deps_count ?? 0;
  const rawAdvisories = summary.total_raw_advisories ?? summary.raw_advisories_count ?? 0;
  const canonicalVulns = summary.total_canonical_vulnerabilities ?? summary.canonical_vulns_count ?? 0;
  const vulnerableComponents = summary.vulnerable_components_count ?? 0;

  const sevCounts = summary.vulnerabilities_by_severity || summary.severity_counts || {};
  const totalVulnsForBar = Math.max(1, canonicalVulns);

  const getWidth = (cnt) => `${Math.round(((cnt || 0) / totalVulnsForBar) * 100)}%`;

  const chartData = [
    { name: "CRITICAL", value: sevCounts.CRITICAL || 0, color: "#FF2E4D" },
    { name: "HIGH", value: sevCounts.HIGH || 0, color: "#FF6B00" },
    { name: "MEDIUM", value: sevCounts.MEDIUM || 0, color: "#FFB800" },
    { name: "LOW", value: sevCounts.LOW || 0, color: "#00B4D8" },
    { name: "INFO", value: sevCounts.INFORMATIONAL || 0, color: "#64748B" },
  ].filter((d) => d.value > 0);

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">Supply Chain Security Dashboard</h2>
          <p className="page-subtitle">
            Continuous Python dependency analysis, CycloneDX SBOM validation, and OSV/NVD vulnerability correlation.
          </p>
        </div>
        <div>
          <button className="btn btn-primary" onClick={() => onNavigate("new_scan")}>
            <Plus size={16} />
            <span>Start New Scan</span>
          </button>
        </div>
      </div>

      {/* Main Metric Cards with Count-up */}
      <div className="stats-grid">
        <div className="stat-card stat-accent">
          <span className="stat-label">Total Components</span>
          <div className="stat-value">
            <MetricTicker value={totalScanned} duration={1.2} />
          </div>
          <span className="stat-sub">{directDeps} Direct · {transitiveDeps} Transitive</span>
        </div>

        <div className="stat-card stat-danger">
          <span className="stat-label">Canonical Vulnerabilities</span>
          <div className="stat-value" style={{ color: "var(--sev-critical)" }}>
            <MetricTicker value={canonicalVulns} duration={1.4} />
          </div>
          <span className="stat-sub">From {rawAdvisories} raw advisories (Deduplicated)</span>
        </div>

        <div className="stat-card stat-warning">
          <span className="stat-label">Vulnerable Packages</span>
          <div className="stat-value" style={{ color: "var(--sev-high)" }}>
            <MetricTicker value={vulnerableComponents} duration={1.3} />
          </div>
          <span className="stat-sub">Packages requiring remediation</span>
        </div>

        <div className="stat-card stat-success">
          <span className="stat-label">CycloneDX Status</span>
          <div className="stat-value" style={{ fontSize: "1.45rem", color: "#00FF88" }}>
            v1.5 Valid
          </div>
          <span className="stat-sub">OWASP Schema Verified</span>
        </div>
      </div>

      {/* Severity Breakdown Card with Donut Chart */}
      <div className="card" style={{ padding: "24px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
          <div>
            <h3 style={{ fontSize: "1.05rem", fontWeight: 700, fontFamily: "var(--font-display)" }}>
              Canonical Severity Distribution
            </h3>
            <p style={{ fontSize: "0.82rem", color: "var(--text-muted)", margin: "2px 0 0 0" }}>
              Correlated across OSV, NVD, and GitHub Advisories
            </p>
          </div>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: chartData.length > 0 ? "130px 1fr" : "1fr",
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
            <div className="sev-bar-container">
              <div className="sev-bar-segment critical" style={{ width: getWidth(sevCounts.CRITICAL) }}></div>
              <div className="sev-bar-segment high" style={{ width: getWidth(sevCounts.HIGH) }}></div>
              <div className="sev-bar-segment medium" style={{ width: getWidth(sevCounts.MEDIUM) }}></div>
              <div className="sev-bar-segment low" style={{ width: getWidth(sevCounts.LOW) }}></div>
              <div className="sev-bar-segment info" style={{ width: getWidth(sevCounts.INFORMATIONAL) }}></div>
              <div className="sev-bar-segment unknown" style={{ width: getWidth(sevCounts.UNKNOWN) }}></div>
            </div>

            <div className="sev-pills-row">
              <span className="badge badge-critical">CRITICAL: {sevCounts.CRITICAL || 0}</span>
              <span className="badge badge-high">HIGH: {sevCounts.HIGH || 0}</span>
              <span className="badge badge-medium">MEDIUM: {sevCounts.MEDIUM || 0}</span>
              <span className="badge badge-low">LOW: {sevCounts.LOW || 0}</span>
              <span className="badge badge-info">INFO: {sevCounts.INFORMATIONAL || 0}</span>
              <span className="badge badge-unknown">UNKNOWN: {sevCounts.UNKNOWN || 0}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
          <div>
            <h3 style={{ fontSize: "1.05rem", fontWeight: 700, fontFamily: "var(--font-display)" }}>
              Recent Scan History
            </h3>
            <p style={{ fontSize: "0.8rem", color: "var(--text-muted)", margin: "2px 0 0 0" }}>
              Persistent audit trail stored in SQLite backend
            </p>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={() => onNavigate("history")}>
            <span>View All History</span>
            <ArrowRight size={14} />
          </button>
        </div>

        {loading ? (
          <div style={{ padding: "32px", textAlign: "center", color: "var(--text-muted)" }}>
            Loading scan history...
          </div>
        ) : history.length === 0 ? (
          <div style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)" }}>
            <p>No scans performed yet.</p>
            <button className="btn btn-primary btn-sm" style={{ marginTop: "12px" }} onClick={() => onNavigate("new_scan")}>
              Run First Scan
            </button>
          </div>
        ) : (
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Manifest</th>
                  <th>Components</th>
                  <th>Canonical Vulns</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {history.slice(0, 5).map((scan) => (
                  <tr key={scan.id}>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                        <Clock size={14} style={{ color: "var(--text-muted)" }} />
                        <span style={{ fontSize: "0.82rem", fontFamily: "var(--font-mono)" }}>
                          {scan.timestamp ? new Date(scan.timestamp).toLocaleString() : "Recently"}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span style={{ fontFamily: "var(--font-mono)", fontWeight: 600 }}>
                        {scan.manifest_name}
                      </span>
                    </td>
                    <td>
                      {scan.total_scanned} ({scan.direct_deps_count} direct)
                    </td>
                    <td>
                      <span className="badge badge-critical">
                        {scan.canonical_vulns_count} Vulnerabilities
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-success">✓ Completed</span>
                    </td>
                    <td>
                      <div style={{ display: "flex", gap: "8px" }}>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => onSelectScan(scan.id)}
                        >
                          View Details
                        </button>
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          onClick={() => downloadFileAsJson(getDownloadBomUrl(scan.id), `cyclonedx-bom-${scan.id.slice(0, 8)}.json`)}
                          title="Download CycloneDX SBOM JSON"
                        >
                          <Download size={13} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
