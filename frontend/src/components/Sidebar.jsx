import React from "react";
import { Link } from "react-router-dom";
import { 
  ShieldCheck, 
  LayoutDashboard, 
  PlusCircle, 
  History, 
  Boxes, 
  FileText, 
  ExternalLink,
  ArrowLeft,
  Brain,
  GitCompare,
  FileSpreadsheet,
  Activity
} from "lucide-react";

export default function Sidebar({ activeTab, onSelectTab, lastScanAvailable }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <Link to="/" style={{ display: "flex", alignItems: "center", gap: "12px", textDecoration: "none" }}>
          <div className="logo-badge">
            <ShieldCheck size={22} />
          </div>
          <div className="brand-text">
            <h1>SecureSBOM</h1>
            <span>Supply Chain Scanner</span>
          </div>
        </Link>
      </div>

      <nav className="sidebar-nav">
        <button
          className={`nav-item ${activeTab === "dashboard" ? "active" : ""}`}
          onClick={() => onSelectTab("dashboard")}
        >
          <LayoutDashboard size={18} />
          <span>Overview</span>
        </button>

        <button
          className={`nav-item ${activeTab === "new_scan" ? "active" : ""}`}
          onClick={() => onSelectTab("new_scan")}
        >
          <PlusCircle size={18} />
          <span>New Scan</span>
        </button>

        <button
          className={`nav-item ${activeTab === "results" ? "active" : ""}`}
          onClick={() => onSelectTab("results")}
          disabled={!lastScanAvailable}
          style={{ opacity: lastScanAvailable ? 1 : 0.6 }}
        >
          <FileText size={18} />
          <span>Verified Vulnerabilities</span>
        </button>

        <button
          className={`nav-item ${activeTab === "ai_vulns" ? "active" : ""}`}
          onClick={() => onSelectTab("ai_vulns")}
          style={{
            borderLeft: activeTab === "ai_vulns" ? "3px solid #00F5FF" : "none",
          }}
        >
          <Brain size={18} style={{ color: "#00F5FF" }} />
          <span style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            AI Emerging Vulns
            <span style={{
              fontSize: "0.65rem",
              background: "rgba(0,245,255,0.15)",
              color: "#00F5FF",
              padding: "1px 5px",
              borderRadius: "4px",
              fontWeight: 700
            }}>AI</span>
          </span>
        </button>

        <button
          className={`nav-item ${activeTab === "inventory" ? "active" : ""}`}
          onClick={() => onSelectTab("inventory")}
          disabled={!lastScanAvailable}
          style={{ opacity: lastScanAvailable ? 1 : 0.6 }}
        >
          <Boxes size={18} />
          <span>Dependency Inventory</span>
        </button>

        <button
          className={`nav-item ${activeTab === "alternatives" ? "active" : ""}`}
          onClick={() => onSelectTab("alternatives")}
          disabled={!lastScanAvailable}
          style={{ opacity: lastScanAvailable ? 1 : 0.6 }}
        >
          <GitCompare size={18} />
          <span>Safer Alternatives</span>
        </button>

        <button
          className={`nav-item ${activeTab === "reports" ? "active" : ""}`}
          onClick={() => onSelectTab("reports")}
          disabled={!lastScanAvailable}
          style={{ opacity: lastScanAvailable ? 1 : 0.6 }}
        >
          <FileSpreadsheet size={18} />
          <span>Reports</span>
        </button>

        <button
          className={`nav-item ${activeTab === "history" ? "active" : ""}`}
          onClick={() => onSelectTab("history")}
        >
          <History size={18} />
          <span>Scan History</span>
        </button>

        <button
          className={`nav-item ${activeTab === "monitoring" ? "active" : ""}`}
          onClick={() => onSelectTab("monitoring")}
        >
          <Activity size={18} style={{ color: "#00FF88" }} />
          <span>Monitoring Status</span>
        </button>

        <div style={{ marginTop: "12px", paddingTop: "12px", borderTop: "1px solid var(--border-sidebar)" }}>
          <Link
            to="/"
            className="nav-item"
            style={{ color: "var(--accent-cyan)", fontSize: "0.85rem", gap: "8px" }}
          >
            <ArrowLeft size={16} />
            <span>Back to Landing Page</span>
          </Link>
        </div>
      </nav>

      <div className="sidebar-footer">
        <div style={{ marginBottom: "10px" }}>
          <div className="sidebar-status-pill">
            <span className="status-dot"></span>
            <span>CycloneDX 1.5 Validated</span>
          </div>
        </div>
        <a
          href="http://127.0.0.1:8000/docs"
          target="_blank"
          rel="noreferrer"
          className="nav-item"
          style={{ padding: "8px 10px", fontSize: "0.8rem", color: "var(--text-light)" }}
        >
          <ExternalLink size={14} />
          <span>FastAPI Swagger UI</span>
        </a>
      </div>
    </aside>
  );
}
