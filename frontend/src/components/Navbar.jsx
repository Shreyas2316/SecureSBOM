import React from "react";
import { ShieldCheck } from "lucide-react";

export default function Navbar({ activeTab }) {
  const titles = {
    dashboard: "Security Overview",
    new_scan: "Initiate Dependency Scan",
    results: "Verified Vulnerabilities (OSV / NVD / KEV / EPSS)",
    inventory: "Software Bill of Materials (SBOM) Inventory",
    alternatives: "Remediation & Safer Dependency Alternatives",
    reports: "Security & Vulnerability Compliance Reports",
    history: "Scan History & Persistence Log",
  };

  return (
    <header className="top-navbar">
      <div className="breadcrumb-area">
        <span>SecureSBOM</span>
        <span>/</span>
        <span className="active-crumb">{titles[activeTab] || "Overview"}</span>
      </div>

      <div className="nav-actions" style={{ display: "flex", alignItems: "center", gap: "12px" }}>
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          fontSize: "0.8rem",
          padding: "4px 12px",
          borderRadius: "6px",
          border: "1px solid var(--border-color)",
          background: "rgba(0, 245, 255, 0.06)",
          color: "#00F5FF",
          fontFamily: "var(--font-mono)",
        }}>
          <ShieldCheck size={14} />
          <span>SBOM Scanner Active</span>
        </div>
      </div>
    </header>
  );
}
