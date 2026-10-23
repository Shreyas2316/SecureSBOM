import React, { useState } from "react";
import { FileText, Download, Eye, Info, CheckCircle2, AlertTriangle, Brain, Shield } from "lucide-react";
import { downloadReport, fetchScanById } from "../api";

const REPORT_FORMATS = [
  {
    id: "pdf",
    label: "PDF Report",
    description: "Full formatted report with charts, tables, and page numbers. Includes both verified and AI findings with clear separation.",
    icon: FileText,
    color: "#FF6B00",
    mime: "PDF",
  },
  {
    id: "json",
    label: "JSON Report",
    description: "Machine-readable structured JSON with complete data. Ideal for CI/CD pipelines and integrations.",
    icon: FileText,
    color: "#00F5FF",
    mime: "JSON",
  },
  {
    id: "csv",
    label: "CSV Summary",
    description: "Spreadsheet-compatible CSV with two sections: verified findings and AI assessments. Import into Excel or Sheets.",
    icon: FileText,
    color: "#00FF88",
    mime: "CSV",
  },
];

function ReportCard({ format, scanId, disabled }) {
  const [downloading, setDownloading] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState(null);
  const Icon = format.icon;

  const handleDownload = async () => {
    setDownloading(true);
    setError(null);
    try {
      await downloadReport(scanId, format.id);
      setDone(true);
      setTimeout(() => setDone(false), 3000);
    } catch (err) {
      setError(err.message);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div style={{
      background: "var(--bg-card)", border: "1px solid rgba(255,255,255,0.08)",
      borderRadius: 14, padding: "24px",
      borderTop: `3px solid ${format.color}`,
      display: "flex", flexDirection: "column", gap: 14,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ width: 40, height: 40, borderRadius: 10, background: `${format.color}18`, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <Icon size={20} style={{ color: format.color }} />
        </div>
        <div>
          <div style={{ fontWeight: 700, fontSize: "1rem" }}>{format.label}</div>
          <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>{format.mime}</div>
        </div>
      </div>

      <p style={{ fontSize: "0.85rem", color: "var(--text-muted)", lineHeight: 1.6, flex: 1 }}>
        {format.description}
      </p>

      {error && (
        <div style={{ color: "#FF2E4D", fontSize: "0.8rem", background: "rgba(255,46,77,0.06)", padding: "8px 12px", borderRadius: 6 }}>
          {error}
        </div>
      )}

      <button
        className={`btn ${done ? "btn-secondary" : "btn-primary"}`}
        onClick={handleDownload}
        disabled={downloading || disabled}
        style={{ width: "100%", justifyContent: "center" }}
      >
        {done ? <CheckCircle2 size={15} style={{ color: "#00FF88" }} /> : <Download size={15} />}
        <span>{downloading ? "Generating…" : done ? "Downloaded!" : `Download ${format.mime}`}</span>
      </button>
    </div>
  );
}

function ReportSectionGuide() {
  const sections = [
    {
      icon: Shield,
      color: "#00F5FF",
      label: "Section A: Verified Findings",
      desc: "Deterministic OSV/NVD matches. Canonical IDs, CVSS scores, affected ranges, fixed versions. Authoritative data only.",
    },
    {
      icon: Brain,
      color: "#FFB800",
      label: "Section B: AI Assessments",
      desc: "AI-generated assessments. Clearly labeled as unverified. Separate counts from verified findings. Each finding includes confidence level and limitations.",
    },
    {
      icon: CheckCircle2,
      color: "#00FF88",
      label: "Safer Alternatives",
      desc: "PyPI-metadata-based upgrade recommendations. Includes migration complexity and breaking change risk. Not applied automatically.",
    },
  ];

  return (
    <div className="card" style={{ marginBottom: 24 }}>
      <h3 style={{ fontWeight: 700, fontSize: "1rem", marginBottom: 16 }}>Report Structure</h3>
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {sections.map((s) => {
          const Icon = s.icon;
          return (
            <div key={s.label} style={{ display: "flex", gap: 12, alignItems: "flex-start", padding: "12px", background: "rgba(255,255,255,0.02)", borderRadius: 8, border: "1px solid rgba(255,255,255,0.05)" }}>
              <div style={{ width: 32, height: 32, borderRadius: 8, background: `${s.color}15`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                <Icon size={16} style={{ color: s.color }} />
              </div>
              <div>
                <div style={{ fontWeight: 600, fontSize: "0.88rem", marginBottom: 3 }}>{s.label}</div>
                <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", lineHeight: 1.5 }}>{s.desc}</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function ReportsView({ activeScan }) {
  const scanId = activeScan?.report?.summary?.scan_id || activeScan?.summary?.scan_id || activeScan?.scan_id || activeScan?.report?.scan_id;
  const projectName = activeScan?.report?.summary?.project_name || activeScan?.summary?.project_name || activeScan?.report?.manifest_name || activeScan?.manifest_name;

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">Security Reports</h2>
          <p className="page-subtitle">
            Generate downloadable reports combining verified vulnerability findings and AI assessments with clear separation.
          </p>
        </div>
      </div>

      {/* Disclaimer */}
      <div style={{ background: "rgba(255,184,0,0.05)", border: "1px solid rgba(255,184,0,0.2)", borderRadius: 10, padding: "12px 18px", marginBottom: 24, display: "flex", gap: 12, alignItems: "flex-start" }}>
        <AlertTriangle size={16} style={{ color: "#FFB800", marginTop: 2, flexShrink: 0 }} />
        <div style={{ fontSize: "0.82rem", color: "var(--text-muted)", lineHeight: 1.5 }}>
          Reports clearly distinguish <strong style={{ color: "var(--text-main)" }}>verified advisory findings</strong> (Category A, from OSV/NVD) from
          <strong style={{ color: "#FFB800" }}> AI-generated assessments</strong> (Category B). AI findings are labelled as unverified.
          Verified and AI counts are never combined.
        </div>
      </div>

      {!scanId ? (
        <div className="card" style={{ textAlign: "center", padding: 48, color: "var(--text-muted)" }}>
          <FileText size={40} style={{ marginBottom: 14, opacity: 0.3 }} />
          <div style={{ marginBottom: 8, fontWeight: 600 }}>No active scan</div>
          <div style={{ fontSize: "0.85rem" }}>Run a scan first to generate reports.</div>
        </div>
      ) : (
        <>
          <div style={{ padding: "14px 18px", background: "rgba(0,245,255,0.05)", border: "1px solid rgba(0,245,255,0.15)", borderRadius: 10, marginBottom: 24, display: "flex", gap: 10, alignItems: "center" }}>
            <Info size={16} style={{ color: "#00F5FF", flexShrink: 0 }} />
            <div style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
              Generating report for: <strong style={{ color: "var(--text-main)" }}>{projectName || "Unknown Project"}</strong>
              {" "} (Scan #{scanId})
            </div>
          </div>

          <ReportSectionGuide />

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 18 }}>
            {REPORT_FORMATS.map(fmt => (
              <ReportCard key={fmt.id} format={fmt} scanId={scanId} disabled={false} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}
