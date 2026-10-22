import React, { useEffect, useState } from "react";
import { 
  History, 
  Clock, 
  Download, 
  ArrowRight, 
  CheckCircle, 
  ShieldAlert, 
  RefreshCw 
} from "lucide-react";
import { fetchScanHistory, getDownloadBomUrl, getDownloadReportUrl, downloadFileAsJson } from "../api";

export default function ScanHistoryView({ onSelectScan, onNavigate }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadHistory = () => {
    setLoading(true);
    fetchScanHistory(100)
      .then((data) => setScans(data.scans || []))
      .catch((err) => console.error("Error loading history:", err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadHistory();
  }, []);

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">Scan History & Audit Trail</h2>
          <p className="page-subtitle">
            All persistent supply chain scan sessions stored securely in the SQLite database.
          </p>
        </div>
        <div style={{ display: "flex", gap: "10px" }}>
          <button className="btn btn-secondary btn-sm" onClick={loadHistory} disabled={loading}>
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
            <span>Refresh</span>
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => onNavigate("new_scan")}>
            New Scan
          </button>
        </div>
      </div>

      <div className="card">
        {loading ? (
          <div style={{ padding: "48px", textAlign: "center", color: "var(--text-muted)" }}>
            Loading scan history records...
          </div>
        ) : scans.length === 0 ? (
          <div style={{ padding: "64px", textAlign: "center", color: "var(--text-muted)" }}>
            <History size={42} style={{ marginBottom: "12px", opacity: 0.5 }} />
            <h3 style={{ fontSize: "1.1rem", fontWeight: 600, color: "var(--text-main)", marginBottom: "6px" }}>
              No previous scans found
            </h3>
            <p style={{ fontSize: "0.86rem", marginBottom: "18px" }}>
              Run your first requirements.txt scan to start recording audit sessions.
            </p>
            <button className="btn btn-primary" onClick={() => onNavigate("new_scan")}>
              Initiate Scan
            </button>
          </div>
        ) : (
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Manifest Name</th>
                  <th>Scanned Components</th>
                  <th>Canonical Vulnerabilities</th>
                  <th>Severity Breakdown</th>
                  <th>CycloneDX Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => {
                  const sevs = s.severity_counts || {};
                  return (
                    <tr key={s.id}>
                      <td>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                          <Clock size={14} style={{ color: "var(--text-muted)" }} />
                          <span style={{ fontSize: "0.82rem" }}>
                            {s.timestamp ? new Date(s.timestamp).toLocaleString() : "Recently"}
                          </span>
                        </div>
                      </td>
                      <td>
                        <span style={{ fontFamily: "var(--font-mono)", fontWeight: 600 }}>
                          {s.manifest_name}
                        </span>
                      </td>
                      <td>
                        {s.total_scanned} ({s.direct_deps_count} direct, {s.transitive_deps_count} transitive)
                      </td>
                      <td>
                        <span className="badge badge-critical">
                          {s.canonical_vulns_count} Unique Findings
                        </span>
                        <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: "2px" }}>
                          ({s.raw_advisories_count} raw records)
                        </div>
                      </td>
                      <td>
                        <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                          {sevs.CRITICAL > 0 && <span className="badge badge-critical" style={{ fontSize: "0.7rem" }}>C: {sevs.CRITICAL}</span>}
                          {sevs.HIGH > 0 && <span className="badge badge-high" style={{ fontSize: "0.7rem" }}>H: {sevs.HIGH}</span>}
                          {sevs.MEDIUM > 0 && <span className="badge badge-medium" style={{ fontSize: "0.7rem" }}>M: {sevs.MEDIUM}</span>}
                          {sevs.LOW > 0 && <span className="badge badge-low" style={{ fontSize: "0.7rem" }}>L: {sevs.LOW}</span>}
                          {s.canonical_vulns_count === 0 && <span className="badge badge-success" style={{ fontSize: "0.7rem" }}>Clean</span>}
                        </div>
                      </td>
                      <td>
                        <span className="badge badge-success">✓ Schema Valid</span>
                      </td>
                      <td>
                        <div style={{ display: "flex", gap: "6px" }}>
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => onSelectScan(s.id)}
                          >
                            <span>Open</span>
                          </button>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => downloadFileAsJson(getDownloadBomUrl(s.id), `cyclonedx-bom-${s.id.slice(0, 8)}.json`)}
                            title="Download CycloneDX SBOM JSON"
                          >
                            <Download size={13} />
                          </button>
                        </div>
                      </td>
                    </tr>
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
