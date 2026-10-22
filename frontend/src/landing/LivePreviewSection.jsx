import React from "react";
import { motion } from "framer-motion";
import { ShieldCheck, AlertCircle, ArrowUpRight, GitCommit, FileText, CheckCircle2 } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import SeverityBadge from "../components/ui/SeverityBadge";

const SEVERITY_DATA = [
  { name: "CRITICAL", value: 1, color: "#FF2E4D" },
  { name: "HIGH", value: 3, color: "#FF6B00" },
  { name: "MEDIUM", value: 5, color: "#FFB800" },
  { name: "LOW", value: 2, color: "#00B4D8" },
];

const PREVIEW_CVES = [
  {
    id: "CVE-2023-32681",
    pkg: "urllib3@1.26.4",
    path: "requests -> urllib3",
    severity: "HIGH",
    cvss: 7.5,
    fix: "Upgrade to >= 1.26.18",
  },
  {
    id: "CVE-2023-38325",
    pkg: "cryptography@40.0.1",
    path: "pyjwt -> cryptography",
    severity: "CRITICAL",
    cvss: 9.1,
    fix: "Upgrade to >= 41.0.2",
  },
  {
    id: "CVE-2023-46136",
    pkg: "werkzeug@2.2.3",
    path: "flask -> werkzeug",
    severity: "HIGH",
    cvss: 7.5,
    fix: "Upgrade to >= 3.0.1",
  },
];

export default function LivePreviewSection() {
  return (
    <section
      id="preview"
      style={{
        position: "relative",
        padding: "120px 24px",
        backgroundColor: "var(--bg-surface)",
        borderBottom: "1px solid var(--border-subtle)",
        overflow: "hidden",
      }}
    >
      <div style={{ maxWidth: "1140px", margin: "0 auto" }}>
        {/* Section Header */}
        <div style={{ textAlign: "center", marginBottom: "56px" }}>
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "8px",
              padding: "6px 14px",
              borderRadius: "999px",
              backgroundColor: "rgba(0, 255, 136, 0.08)",
              border: "1px solid rgba(0, 255, 136, 0.3)",
              fontSize: "0.78rem",
              fontFamily: "var(--font-mono)",
              color: "var(--accent-green)",
              marginBottom: "16px",
            }}
          >
            <ShieldCheck size={14} />
            <span>OPERATIONAL SCANNER UI</span>
          </div>

          <h2
            style={{
              fontFamily: "var(--font-display)",
              fontSize: "clamp(2rem, 4vw, 3rem)",
              fontWeight: 800,
              letterSpacing: "-0.03em",
              color: "#FFFFFF",
              margin: 0,
            }}
          >
            Live Risk Intelligence Report
          </h2>
          <p
            style={{
              color: "var(--text-secondary)",
              fontSize: "1.05rem",
              maxWidth: "600px",
              margin: "12px auto 0 auto",
            }}
          >
            Instant triage with CVSS breakdowns, affected dependency paths, and automated remediation targets.
          </p>
        </div>

        {/* Dashboard Mockup Container */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-100px" }}
          transition={{ duration: 0.6 }}
          className="glass-panel"
          style={{
            padding: "32px",
            background: "linear-gradient(180deg, rgba(11, 14, 20, 0.85) 0%, rgba(5, 7, 10, 0.95) 100%)",
            border: "1px solid var(--border-medium)",
            boxShadow: "0 25px 60px -15px rgba(0, 0, 0, 0.8), 0 0 35px -10px var(--accent-cyan-glow)",
          }}
        >
          {/* Mock Dashboard Topbar */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              paddingBottom: "24px",
              borderBottom: "1px solid var(--border-subtle)",
              marginBottom: "28px",
              flexWrap: "wrap",
              gap: "16px",
            }}
          >
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <span style={{ fontSize: "1.2rem", fontWeight: 700, color: "#fff" }}>
                  production-backend-v2.1
                </span>
                <span
                  style={{
                    backgroundColor: "rgba(255, 46, 77, 0.15)",
                    border: "1px solid rgba(255, 46, 77, 0.35)",
                    color: "var(--sev-critical)",
                    fontSize: "0.72rem",
                    fontFamily: "var(--font-mono)",
                    padding: "2px 8px",
                    borderRadius: "4px",
                  }}
                >
                  HIGH RISK (SCORE: 8.4)
                </span>
              </div>
              <div style={{ fontSize: "0.82rem", color: "var(--text-muted)", marginTop: "4px", fontFamily: "var(--font-mono)" }}>
                CycloneDX 1.4 · 128 Dependencies Analyzed · Scanned 12s ago
              </div>
            </div>

            <div style={{ display: "flex", gap: "12px" }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  fontSize: "0.82rem",
                  fontFamily: "var(--font-mono)",
                  padding: "6px 12px",
                  borderRadius: "6px",
                  backgroundColor: "rgba(255, 255, 255, 0.04)",
                  border: "1px solid var(--border-subtle)",
                  color: "var(--text-secondary)",
                }}
              >
                <FileText size={14} />
                <span>SPDX Export Ready</span>
              </div>
            </div>
          </div>

          {/* Top Metrics + Donut Row */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1.2fr 2fr",
              gap: "28px",
              alignItems: "center",
              marginBottom: "32px",
            }}
          >
            {/* Severity Distribution Donut */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "16px",
                padding: "20px",
                borderRadius: "10px",
                backgroundColor: "rgba(255, 255, 255, 0.02)",
                border: "1px solid var(--border-subtle)",
              }}
            >
              <div style={{ width: "120px", height: "120px" }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={SEVERITY_DATA}
                      innerRadius={36}
                      outerRadius={54}
                      paddingAngle={4}
                      dataKey="value"
                      stroke="none"
                    >
                      {SEVERITY_DATA.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: "6px", fontSize: "0.78rem", fontFamily: "var(--font-mono)" }}>
                {SEVERITY_DATA.map((s) => (
                  <div key={s.name} style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: s.color }} />
                    <span style={{ color: "var(--text-muted)" }}>{s.name}:</span>
                    <span style={{ color: "#fff", fontWeight: 700 }}>{s.value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Quick Metrics Cards */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "14px" }}>
              <div
                style={{
                  padding: "16px",
                  borderRadius: "8px",
                  backgroundColor: "rgba(255, 255, 255, 0.02)",
                  border: "1px solid var(--border-subtle)",
                }}
              >
                <div style={{ fontSize: "0.74rem", fontFamily: "var(--font-mono)", color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Max CVSS
                </div>
                <div style={{ fontSize: "1.8rem", fontWeight: 800, color: "var(--sev-critical)", fontFamily: "var(--font-mono)", marginTop: "4px" }}>
                  9.1
                </div>
                <div style={{ fontSize: "0.72rem", color: "var(--sev-critical)", marginTop: "2px" }}>Remote Code Execution</div>
              </div>

              <div
                style={{
                  padding: "16px",
                  borderRadius: "8px",
                  backgroundColor: "rgba(255, 255, 255, 0.02)",
                  border: "1px solid var(--border-subtle)",
                }}
              >
                <div style={{ fontSize: "0.74rem", fontFamily: "var(--font-mono)", color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Total Findings
                </div>
                <div style={{ fontSize: "1.8rem", fontWeight: 800, color: "var(--accent-cyan)", fontFamily: "var(--font-mono)", marginTop: "4px" }}>
                  11
                </div>
                <div style={{ fontSize: "0.72rem", color: "var(--accent-cyan)", marginTop: "2px" }}>4 Active Patches Available</div>
              </div>

              <div
                style={{
                  padding: "16px",
                  borderRadius: "8px",
                  backgroundColor: "rgba(255, 255, 255, 0.02)",
                  border: "1px solid var(--border-subtle)",
                }}
              >
                <div style={{ fontSize: "0.74rem", fontFamily: "var(--font-mono)", color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Tree Depth
                </div>
                <div style={{ fontSize: "1.8rem", fontWeight: 800, color: "#fff", fontFamily: "var(--font-mono)", marginTop: "4px" }}>
                  4
                </div>
                <div style={{ fontSize: "0.72rem", color: "var(--accent-green)", marginTop: "2px" }}>Resolved in 184ms</div>
              </div>
            </div>
          </div>

          {/* Staggered CVE Table Preview */}
          <div style={{ borderRadius: "8px", overflow: "hidden", border: "1px solid var(--border-subtle)" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem", textAlign: "left" }}>
              <thead style={{ backgroundColor: "rgba(255, 255, 255, 0.03)", fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--text-muted)" }}>
                <tr>
                  <th style={{ padding: "12px 16px" }}>VULNERABILITY</th>
                  <th style={{ padding: "12px 16px" }}>SEVERITY</th>
                  <th style={{ padding: "12px 16px" }}>COMPONENT</th>
                  <th style={{ padding: "12px 16px" }}>DEPENDENCY CHAIN</th>
                  <th style={{ padding: "12px 16px" }}>REMEDIATION</th>
                </tr>
              </thead>
              <tbody style={{ divideY: "1px solid var(--border-subtle)" }}>
                {PREVIEW_CVES.map((cve, idx) => (
                  <tr
                    key={cve.id}
                    style={{
                      borderTop: "1px solid var(--border-subtle)",
                      backgroundColor: idx === 0 ? "rgba(255, 46, 77, 0.04)" : "transparent",
                    }}
                  >
                    <td style={{ padding: "14px 16px", fontFamily: "var(--font-mono)", fontWeight: 600, color: "#fff" }}>
                      {cve.id}
                    </td>
                    <td style={{ padding: "14px 16px" }}>
                      <SeverityBadge severity={cve.severity} score={cve.cvss} />
                    </td>
                    <td style={{ padding: "14px 16px", fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>
                      {cve.pkg}
                    </td>
                    <td style={{ padding: "14px 16px", fontFamily: "var(--font-mono)", fontSize: "0.78rem", color: "var(--accent-cyan)" }}>
                      {cve.path}
                    </td>
                    <td style={{ padding: "14px 16px" }}>
                      <span
                        style={{
                          fontSize: "0.78rem",
                          fontFamily: "var(--font-mono)",
                          padding: "3px 8px",
                          borderRadius: "4px",
                          backgroundColor: "rgba(0, 255, 136, 0.1)",
                          color: "var(--accent-green)",
                          border: "1px solid rgba(0, 255, 136, 0.3)",
                        }}
                      >
                        {cve.fix}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
