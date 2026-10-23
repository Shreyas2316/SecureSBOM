import React from "react";
import { User, ShieldAlert, Sparkles } from "lucide-react";
import { getUserId, setUserId } from "../api";

export default function Navbar({ activeTab, onUserChange }) {
  const titles = {
    dashboard: "Security Overview",
    new_scan: "Initiate Dependency Scan",
    results: "Verified Vulnerability Findings (Deterministic OSV/NVD)",
    inventory: "Software Bill of Materials (SBOM) Inventory",
    ai_vulns: "AI-Detected Emerging Vulnerabilities (Separate AI Category)",
    alternatives: "Safer Dependency Alternatives & Remediation Guidance",
    reports: "Security & Vulnerability Compliance Reports",
    history: "Scan History & Persistence Log",
    monitoring: "Continuous Vulnerability Monitoring & Advisory Feeds",
  };

  const handleUserSelect = (e) => {
    const val = e.target.value;
    setUserId(val);
    if (onUserChange) onUserChange(val);
  };

  return (
    <header className="top-navbar">
      <div className="breadcrumb-area">
        <span>SecureSBOM</span>
        <span>/</span>
        <span className="active-crumb">{titles[activeTab] || "Overview"}</span>
      </div>

      <div className="nav-actions">
        <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "0.82rem" }}>
          <User size={15} style={{ color: "var(--text-muted)" }} />
          <span style={{ color: "var(--text-muted)" }}>Tenant/User:</span>
          <select
            className="select"
            style={{ width: "auto", padding: "4px 8px", fontSize: "0.8rem", height: "30px" }}
            value={getUserId()}
            onChange={handleUserSelect}
          >
            <option value="default_user">default_user (Production)</option>
            <option value="security_lead">security_lead (Audit)</option>
            <option value="developer_workspace">developer_workspace (CI/CD)</option>
          </select>
        </div>
      </div>
    </header>
  );
}
