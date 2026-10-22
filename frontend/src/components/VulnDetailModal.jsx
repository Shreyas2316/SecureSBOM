import React, { useState, useEffect } from "react";
import { createPortal } from "react-dom";
import { 
  X, 
  ExternalLink, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle, 
  Copy, 
  Layers, 
  Info 
} from "lucide-react";
import SeverityBadge from "./ui/SeverityBadge";

export default function VulnDetailModal({ vuln, onClose }) {
  const [activeTab, setActiveTab] = useState("overview"); // 'overview' | 'raw'
  const [copied, setCopied] = useState(false);

  // Lock body scroll and handle ESC key to keep screen completely still
  useEffect(() => {
    if (!vuln) return;

    const originalOverflow = document.body.style.overflow;
    const originalPaddingRight = document.body.style.paddingRight;
    const scrollbarWidth = window.innerWidth - document.documentElement.clientWidth;

    document.body.style.overflow = "hidden";
    if (scrollbarWidth > 0) {
      document.body.style.paddingRight = `${scrollbarWidth}px`;
    }

    const handleKeyDown = (e) => {
      if (e.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);

    return () => {
      document.body.style.overflow = originalOverflow;
      document.body.style.paddingRight = originalPaddingRight;
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [vuln, onClose]);

  if (!vuln) return null;

  const canonicalId = vuln.canonical_id || vuln.vuln_id || "Vulnerability Advisory";

  const handleCopyId = () => {
    if (canonicalId) {
      navigator.clipboard.writeText(canonicalId);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  // Safe numeric CVSS formatting
  const getCvssScoreDisplay = () => {
    if (vuln.cvss_score === null || vuln.cvss_score === undefined || vuln.cvss_score === "") {
      return "N/A";
    }
    const num = Number(vuln.cvss_score);
    return !isNaN(num) ? num.toFixed(1) : String(vuln.cvss_score);
  };

  // Safe aliases list
  const aliases = Array.isArray(vuln.aliases) && vuln.aliases.length > 0
    ? vuln.aliases
    : Array.isArray(vuln.all_identifiers)
      ? vuln.all_identifiers.filter((id) => id !== canonicalId)
      : [];

  // Safe affected packages list
  const affectedPkgs = Array.isArray(vuln.affected_packages) && vuln.affected_packages.length > 0
    ? vuln.affected_packages
    : vuln.package_name
      ? [{ package_name: vuln.package_name, version: vuln.version || "All versions", affected_ranges: vuln.affected_versions || [] }]
      : [];

  // Safe fixed versions list
  const fixedVersions = Array.isArray(vuln.fixed_versions) && vuln.fixed_versions.length > 0
    ? vuln.fixed_versions
    : vuln.fixed_version
      ? [vuln.fixed_version]
      : [];

  // Safe references / URLs
  const sourceUrls = Array.isArray(vuln.source_urls) && vuln.source_urls.length > 0
    ? vuln.source_urls
    : Array.isArray(vuln.references) && vuln.references.length > 0
      ? vuln.references
      : vuln.source_url
        ? [vuln.source_url]
        : [];

  // Safe raw advisories
  const rawAdvisories = Array.isArray(vuln.raw_advisories) && vuln.raw_advisories.length > 0
    ? vuln.raw_advisories
    : [{
        vuln_id: canonicalId,
        source: vuln.source || (Array.isArray(vuln.sources) && vuln.sources[0]) || "OSV",
        severity: vuln.severity || "UNKNOWN",
        summary: vuln.summary || vuln.details || "Consolidated canonical advisory record",
        url: sourceUrls[0] || ""
      }];

  const modalContent = (
    <div 
      className="modal-overlay" 
      onClick={onClose}
      onWheel={(e) => {
        // Prevent scroll leak to document background
        if (e.target === e.currentTarget) {
          e.preventDefault();
        }
      }}
    >
      <div 
        className="modal-dialog" 
        onClick={(e) => e.stopPropagation()}
        style={{
          maxHeight: "88vh",
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
          overscrollBehavior: "contain"
        }}
      >
        {/* Header */}
        <div className="modal-header">
          <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
            <SeverityBadge severity={vuln.severity} />
            <h3 style={{ fontSize: "1.15rem", fontWeight: 700, fontFamily: "var(--font-mono)", color: "#FFFFFF", margin: 0 }}>
              {canonicalId}
            </h3>
            <button
              onClick={handleCopyId}
              style={{
                background: "rgba(255, 255, 255, 0.05)",
                border: "1px solid var(--border-color)",
                borderRadius: "6px",
                padding: "4px 8px",
                cursor: "pointer",
                color: "var(--text-muted)",
                display: "inline-flex",
                alignItems: "center",
                gap: "4px",
                fontSize: "0.75rem"
              }}
              title="Copy identifier"
            >
              <Copy size={13} />
              <span>{copied ? "Copied!" : "Copy ID"}</span>
            </button>
          </div>
          <button
            onClick={onClose}
            style={{
              background: "none",
              border: "none",
              cursor: "pointer",
              color: "var(--text-muted)",
              padding: "4px",
              display: "flex",
              alignItems: "center"
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Tab Switcher */}
        <div style={{ display: "flex", borderBottom: "1px solid var(--border-color)", padding: "0 24px", backgroundColor: "#080B10" }}>
          <button
            onClick={() => setActiveTab("overview")}
            style={{
              padding: "12px 18px",
              background: "transparent",
              border: "none",
              borderBottom: activeTab === "overview" ? "2px solid var(--primary)" : "2px solid transparent",
              color: activeTab === "overview" ? "var(--primary)" : "var(--text-muted)",
              fontWeight: 600,
              fontSize: "0.85rem",
              fontFamily: "var(--font-mono)",
              cursor: "pointer",
            }}
          >
            Canonical Overview
          </button>
          <button
            onClick={() => setActiveTab("raw")}
            style={{
              padding: "12px 18px",
              background: "transparent",
              border: "none",
              borderBottom: activeTab === "raw" ? "2px solid var(--primary)" : "2px solid transparent",
              color: activeTab === "raw" ? "var(--primary)" : "var(--text-muted)",
              fontWeight: 600,
              fontSize: "0.85rem",
              fontFamily: "var(--font-mono)",
              cursor: "pointer",
            }}
          >
            Raw Advisories ({rawAdvisories.length})
          </button>
        </div>

        {/* Scrollable Body - Still & Contained */}
        <div 
          className="modal-body"
          style={{
            padding: "24px",
            overflowY: "auto",
            overscrollBehavior: "contain",
            maxHeight: "calc(88vh - 130px)",
            backgroundColor: "#0B0E14"
          }}
        >
          {activeTab === "overview" ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "22px" }}>
              {/* Conflict warning if present */}
              {vuln.has_cvss_conflict && (
                <div style={{
                  backgroundColor: "rgba(255, 184, 0, 0.12)",
                  border: "1px solid rgba(255, 184, 0, 0.35)",
                  color: "var(--sev-medium)",
                  padding: "12px 16px",
                  borderRadius: "var(--radius-md)",
                  fontSize: "0.84rem",
                  display: "flex",
                  alignItems: "center",
                  gap: "10px"
                }}>
                  <AlertTriangle size={18} />
                  <span>
                    <strong>Source Discrepancy:</strong> Correlated advisory sources reported differing CVSS severity evaluations. The authoritative evaluation is presented below.
                  </span>
                </div>
              )}

              {/* Summary */}
              <div>
                <h4 style={{ fontSize: "0.8rem", fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginBottom: "8px" }}>
                  Advisory Summary
                </h4>
                <p style={{ fontSize: "0.92rem", lineHeight: 1.6, color: "var(--text-main)", margin: 0 }}>
                  {vuln.summary || vuln.details || "No extended summary provided in advisory record."}
                </p>
              </div>

              {/* CVSS & Severity Box */}
              <div style={{ backgroundColor: "rgba(255, 255, 255, 0.03)", padding: "18px", borderRadius: "var(--radius-md)", border: "1px solid var(--border-color)" }}>
                <h4 style={{ fontSize: "0.78rem", fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginBottom: "10px" }}>
                  CVSS v3.1 Severity Scoring
                </h4>
                <div style={{ display: "flex", alignItems: "baseline", gap: "12px", marginBottom: "8px" }}>
                  <span style={{ fontSize: "1.8rem", fontWeight: 800, fontFamily: "var(--font-mono)", color: "#FFFFFF" }}>
                    {getCvssScoreDisplay()}
                  </span>
                  <SeverityBadge severity={vuln.severity} />
                  {vuln.cvss_version && (
                    <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                      Specification v{vuln.cvss_version}
                    </span>
                  )}
                </div>
                {vuln.cvss_vector && (
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.78rem", color: "var(--accent-cyan)", marginBottom: "8px", wordBreak: "break-all" }}>
                    Vector: {vuln.cvss_vector}
                  </div>
                )}
                {vuln.severity_justification && (
                  <p style={{ fontSize: "0.82rem", color: "var(--text-muted)", margin: 0, fontStyle: "italic" }}>
                    {vuln.severity_justification}
                  </p>
                )}
              </div>

              {/* Correlated Aliases */}
              {aliases.length > 0 && (
                <div>
                  <h4 style={{ fontSize: "0.78rem", fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginBottom: "8px" }}>
                    Correlated Alternative Identifiers
                  </h4>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                    {aliases.map((alias) => (
                      <span key={alias} style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: "0.78rem",
                        backgroundColor: "rgba(0, 245, 255, 0.06)",
                        padding: "3px 8px",
                        borderRadius: "var(--radius-sm)",
                        border: "1px solid rgba(0, 245, 255, 0.2)",
                        color: "var(--accent-cyan)"
                      }}>
                        {alias}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Affected Packages & Remediation */}
              <div>
                <h4 style={{ fontSize: "0.78rem", fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginBottom: "8px" }}>
                  Affected Packages & Remediation Targets
                </h4>
                {affectedPkgs.length === 0 ? (
                  <p style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>Component details unavailable.</p>
                ) : (
                  <div className="table-responsive">
                    <table className="data-table" style={{ fontSize: "0.84rem" }}>
                      <thead>
                        <tr>
                          <th>Package</th>
                          <th>Scanned Version</th>
                          <th>Affected Ranges</th>
                          <th>Remediation Target</th>
                        </tr>
                      </thead>
                      <tbody>
                        {affectedPkgs.map((pkg, idx) => {
                          const pName = pkg.package_name || pkg.name || "Component";
                          const pVer = pkg.version || "All versions";
                          let affRanges = "See advisory";
                          if (Array.isArray(pkg.affected_ranges) && pkg.affected_ranges.length > 0) {
                            affRanges = pkg.affected_ranges.join("; ");
                          } else if (typeof pkg.affected_ranges === "string" && pkg.affected_ranges.trim()) {
                            affRanges = pkg.affected_ranges;
                          }

                          return (
                            <tr key={idx}>
                              <td style={{ fontWeight: 700, fontFamily: "var(--font-mono)", color: "#FFFFFF" }}>{pName}</td>
                              <td style={{ fontFamily: "var(--font-mono)" }}>{pVer}</td>
                              <td style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>{affRanges}</td>
                              <td>
                                {fixedVersions.length > 0 ? (
                                  <span className="badge badge-success">
                                    Upgrade to &gt;= {fixedVersions[0]}
                                  </span>
                                ) : (
                                  <span style={{ color: "var(--text-muted)", fontSize: "0.78rem" }}>No patch recorded</span>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* External References */}
              {sourceUrls.length > 0 && (
                <div>
                  <h4 style={{ fontSize: "0.78rem", fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginBottom: "8px" }}>
                    Official References & Upstream Bulletins
                  </h4>
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                    {sourceUrls.map((url, idx) => (
                      <a
                        key={idx}
                        href={url}
                        target="_blank"
                        rel="noreferrer"
                        style={{
                          fontSize: "0.82rem",
                          color: "var(--primary)",
                          display: "inline-flex",
                          alignItems: "center",
                          gap: "6px",
                          textDecoration: "none",
                          wordBreak: "break-all"
                        }}
                      >
                        <ExternalLink size={13} />
                        <span>{url}</span>
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            /* Raw Advisories Tab */
            <div>
              <p style={{ fontSize: "0.84rem", color: "var(--text-muted)", marginBottom: "16px" }}>
                Consolidated across {rawAdvisories.length} upstream advisory record{rawAdvisories.length > 1 ? "s" : ""}:
              </p>
              <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                {rawAdvisories.map((raw, idx) => (
                  <div key={idx} style={{
                    padding: "16px",
                    borderRadius: "var(--radius-md)",
                    border: "1px solid var(--border-color)",
                    backgroundColor: "rgba(255, 255, 255, 0.02)"
                  }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                      <span style={{ fontWeight: 700, fontFamily: "var(--font-mono)", color: "var(--primary)" }}>
                        {raw.vuln_id || canonicalId}
                      </span>
                      <span className="badge badge-info">{raw.source || "OSV"}</span>
                    </div>
                    {raw.severity && (
                      <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "6px", fontFamily: "var(--font-mono)" }}>
                        Raw Severity: {raw.severity}
                      </div>
                    )}
                    <p style={{ fontSize: "0.84rem", color: "var(--text-main)", margin: 0, lineHeight: 1.5 }}>
                      {raw.summary || "No description provided."}
                    </p>
                    {raw.url && (
                      <a
                        href={raw.url}
                        target="_blank"
                        rel="noreferrer"
                        style={{ fontSize: "0.78rem", color: "var(--primary)", marginTop: "10px", display: "inline-flex", alignItems: "center", gap: "4px", textDecoration: "none" }}
                      >
                        <ExternalLink size={11} />
                        <span>View Source Record</span>
                      </a>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="modal-footer">
          <button className="btn btn-secondary btn-sm" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );

  return createPortal(modalContent, document.body);
}
