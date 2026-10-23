import React, { useState, useEffect } from "react";
import { ArrowUp, AlertTriangle, CheckCircle2, HelpCircle, ExternalLink, Download, RefreshCw, Package, ShieldCheck, ShieldAlert } from "lucide-react";
import { fetchAlternatives, downloadReport } from "../api";

const RECOMMENDATION_COLORS = {
  version_upgrade: { color: "#00FF88", label: "Recommended Fixed Version" },
  no_upgrade_available: { color: "#64748B", label: "No Suitable Alternative" },
  replacement: { color: "#00B4D8", label: "Potential Replacement" },
};

const COMPLEXITY_CONFIG = {
  low: { color: "#00FF88", label: "Low" },
  medium: { color: "#FFB800", label: "Medium" },
  high: { color: "#FF6B00", label: "High" },
  unknown: { color: "#64748B", label: "Unknown" },
};

const VERIFICATION_CONFIG = {
  verified: { color: "#00FF88", label: "Verified" },
  candidate: { color: "#FFB800", label: "Candidate" },
  insufficient_evidence: { color: "#64748B", label: "Insufficient Evidence" },
};

function VerificationBadge({ status }) {
  const cfg = VERIFICATION_CONFIG[status] || VERIFICATION_CONFIG["insufficient_evidence"];
  return (
    <span style={{
      padding: "3px 8px", borderRadius: 9999,
      fontSize: "0.72rem", fontWeight: 700,
      fontFamily: "var(--font-mono)",
      background: `${cfg.color}18`,
      color: cfg.color,
      border: `1px solid ${cfg.color}55`,
    }}>
      {cfg.label}
    </span>
  );
}

function ComplexityBadge({ complexity }) {
  const cfg = COMPLEXITY_CONFIG[complexity] || COMPLEXITY_CONFIG["unknown"];
  return (
    <span style={{ color: cfg.color, fontWeight: 700, fontSize: "0.8rem", fontFamily: "var(--font-mono)" }}>
      {cfg.label}
    </span>
  );
}

function AlternativeCard({ alt }) {
  const [expanded, setExpanded] = useState(false);
  const rec = RECOMMENDATION_COLORS[alt.recommendation_type] || { color: "#94A3B8", label: alt.recommendation_type };

  return (
    <div style={{
      background: "var(--bg-card)", border: "1px solid rgba(255,255,255,0.08)",
      borderRadius: 12, overflow: "hidden", marginBottom: 12,
      borderLeft: `3px solid ${rec.color}`,
    }}>
      <div
        style={{ padding: "16px 20px", cursor: "pointer", display: "flex", justifyContent: "space-between", alignItems: "center" }}
        onClick={() => setExpanded(!expanded)}
      >
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
            <Package size={16} style={{ color: rec.color }} />
            <span style={{ fontWeight: 700, fontSize: "0.95rem" }}>{alt.package_name}</span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.78rem", color: "var(--text-muted)" }}>
              v{alt.package_version}
            </span>
            <span style={{ fontSize: "0.75rem", fontWeight: 700, color: rec.color, background: `${rec.color}15`, border: `1px solid ${rec.color}40`, borderRadius: 6, padding: "2px 8px" }}>
              {rec.label}
            </span>
          </div>
          {alt.vulnerability_canonical_id && (
            <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
              Addresses: {alt.vulnerability_canonical_id}
            </div>
          )}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          {alt.recommended_version && (
            <div style={{ textAlign: "right" }}>
              <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Recommended</div>
              <div style={{ fontFamily: "var(--font-mono)", fontWeight: 700, color: "#00FF88", fontSize: "0.9rem" }}>
                v{alt.recommended_version}
              </div>
            </div>
          )}
          <VerificationBadge status={alt.verification_status} />
          <span style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>{expanded ? "▲" : "▼"}</span>
        </div>
      </div>

      {expanded && (
        <div style={{ padding: "0 20px 18px", borderTop: "1px solid rgba(255,255,255,0.05)" }}>
          <div style={{ paddingTop: 16, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <div>
              <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginBottom: 4, fontFamily: "var(--font-mono)", textTransform: "uppercase" }}>Migration Complexity</div>
              <ComplexityBadge complexity={alt.migration_complexity} />
            </div>
            <div>
              <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginBottom: 4, fontFamily: "var(--font-mono)", textTransform: "uppercase" }}>Breaking Change Risk</div>
              <ComplexityBadge complexity={alt.breaking_change_risk} />
            </div>
            {alt.license_info && (
              <div>
                <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginBottom: 4, fontFamily: "var(--font-mono)", textTransform: "uppercase" }}>License</div>
                <span style={{ fontSize: "0.82rem", color: "var(--text-main)" }}>{alt.license_info}</span>
              </div>
            )}
            {alt.compatibility_info && (
              <div style={{ gridColumn: "1 / -1" }}>
                <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginBottom: 4, fontFamily: "var(--font-mono)", textTransform: "uppercase" }}>Compatibility</div>
                <div style={{ fontSize: "0.82rem", color: "var(--text-muted)", lineHeight: 1.5 }}>{alt.compatibility_info}</div>
              </div>
            )}
          </div>

          {alt.rationale && (
            <div style={{ marginTop: 14, padding: "10px 14px", background: "rgba(255,255,255,0.02)", borderRadius: 8, border: "1px solid rgba(255,255,255,0.06)" }}>
              <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginBottom: 4, fontFamily: "var(--font-mono)", textTransform: "uppercase" }}>Rationale</div>
              <div style={{ fontSize: "0.85rem", color: "var(--text-muted)", lineHeight: 1.5 }}>{alt.rationale}</div>
            </div>
          )}

          {alt.known_vulns_in_alternative && (
            <div style={{ marginTop: 12, padding: "8px 14px", background: "rgba(255,184,0,0.05)", border: "1px solid rgba(255,184,0,0.2)", borderRadius: 8 }}>
              <div style={{ fontSize: "0.72rem", color: "#FFB800", marginBottom: 3, fontFamily: "var(--font-mono)", textTransform: "uppercase" }}>Known Vulnerabilities in Recommended Version</div>
              <div style={{ fontSize: "0.82rem", color: "#FFB800" }}>{alt.known_vulns_in_alternative}</div>
            </div>
          )}

          {alt.evidence_links && alt.evidence_links.length > 0 && (
            <div style={{ marginTop: 12, display: "flex", flexWrap: "wrap", gap: 8 }}>
              {alt.evidence_links.map((link, i) => (
                <a key={i} href={link} target="_blank" rel="noreferrer" style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: "0.75rem", color: "#00F5FF", textDecoration: "none", border: "1px solid rgba(0,245,255,0.2)", padding: "3px 8px", borderRadius: 6 }}>
                  <ExternalLink size={11} />
                  {link.length > 50 ? link.slice(0, 50) + "…" : link}
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function SaferAlternativesView({ activeScan }) {
  const [alternatives, setAlternatives] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [downloadingReport, setDownloadingReport] = useState(null);

  const scanId = activeScan?.report?.summary?.scan_id || activeScan?.summary?.scan_id || activeScan?.scan_id || activeScan?.report?.scan_id;

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    setError(null);
    fetchAlternatives(scanId)
      .then(data => setAlternatives(data.alternatives || []))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, [scanId]);

  const handleDownload = async (format) => {
    if (!scanId) return;
    setDownloadingReport(format);
    try {
      await downloadReport(scanId, format);
    } catch (err) {
      alert("Download failed: " + err.message);
    } finally {
      setDownloadingReport(null);
    }
  };

  if (!scanId) {
    return (
      <div>
        <div className="page-header">
          <div>
            <h2 className="page-title">Safer Dependency Alternatives</h2>
            <p className="page-subtitle">Upgrade recommendations and replacement packages for vulnerable dependencies.</p>
          </div>
        </div>
        <div className="card" style={{ textAlign: "center", padding: 48, color: "var(--text-muted)" }}>
          <Package size={40} style={{ marginBottom: 14, opacity: 0.3 }} />
          <div>No active scan available. Run a scan first.</div>
        </div>
      </div>
    );
  }

  const upgradeCount = alternatives.filter(a => a.recommendation_type === "version_upgrade").length;
  const noAltCount = alternatives.filter(a => a.recommendation_type === "no_upgrade_available").length;

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">Safer Dependency Alternatives</h2>
          <p className="page-subtitle">Evidence-based upgrade recommendations. Manual review required before applying changes.</p>
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <button className="btn btn-secondary btn-sm" onClick={() => handleDownload("json")} disabled={!!downloadingReport}>
            <Download size={14} />
            <span>{downloadingReport === "json" ? "Downloading…" : "JSON Report"}</span>
          </button>
          <button className="btn btn-secondary btn-sm" onClick={() => handleDownload("csv")} disabled={!!downloadingReport}>
            <Download size={14} />
            <span>{downloadingReport === "csv" ? "Downloading…" : "CSV Report"}</span>
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => handleDownload("pdf")} disabled={!!downloadingReport}>
            <Download size={14} />
            <span>{downloadingReport === "pdf" ? "Downloading…" : "PDF Report"}</span>
          </button>
        </div>
      </div>

      {/* Disclaimer */}
      <div style={{ background: "rgba(0,245,255,0.04)", border: "1px solid rgba(0,245,255,0.15)", borderRadius: 10, padding: "12px 18px", marginBottom: 24, display: "flex", gap: 12, alignItems: "flex-start" }}>
        <ShieldCheck size={18} style={{ color: "#00F5FF", marginTop: 1, flexShrink: 0 }} />
        <div style={{ fontSize: "0.82rem", color: "var(--text-muted)", lineHeight: 1.5 }}>
          <strong style={{ color: "var(--text-main)" }}>Manual review required.</strong> These recommendations are based on PyPI metadata and authoritative advisory data.
          Always verify compatibility, run your test suite, and check for known vulnerabilities in the recommended version before applying.
          Recommendations are <strong style={{ color: "var(--text-main)" }}>NOT applied automatically</strong>.
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16, marginBottom: 24 }}>
        <div className="stat-card stat-success">
          <span className="stat-label">Available Upgrades</span>
          <div className="stat-value">{upgradeCount}</div>
          <span className="stat-sub">Fixed versions identified</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">No Alternative Found</span>
          <div className="stat-value">{noAltCount}</div>
          <span className="stat-sub">Manual investigation needed</span>
        </div>
        <div className="stat-card stat-accent">
          <span className="stat-label">Total Recommendations</span>
          <div className="stat-value">{alternatives.length}</div>
          <span className="stat-sub">Across all vulnerabilities</span>
        </div>
      </div>

      {loading && (
        <div style={{ padding: 48, textAlign: "center", color: "var(--text-muted)" }}>
          <RefreshCw size={28} style={{ marginBottom: 12, opacity: 0.4, animation: "spin 1s linear infinite" }} />
          <div>Fetching PyPI metadata and building recommendations…</div>
        </div>
      )}

      {error && (
        <div style={{ background: "rgba(255,46,77,0.08)", border: "1px solid rgba(255,46,77,0.3)", borderRadius: 10, padding: "14px 18px", color: "#FF2E4D", marginBottom: 20 }}>
          Failed to load alternatives: {error}
        </div>
      )}

      {!loading && !error && alternatives.length === 0 && (
        <div className="card" style={{ textAlign: "center", padding: 48, color: "var(--text-muted)" }}>
          <ShieldCheck size={40} style={{ marginBottom: 14, color: "#00FF88", opacity: 0.5 }} />
          <div style={{ marginBottom: 8, fontWeight: 600 }}>No vulnerable dependencies requiring alternatives</div>
          <div style={{ fontSize: "0.85rem" }}>Great — no verified vulnerabilities were found in this scan that need remediation.</div>
        </div>
      )}

      {alternatives.map((alt, i) => <AlternativeCard key={i} alt={alt} />)}
    </div>
  );
}
