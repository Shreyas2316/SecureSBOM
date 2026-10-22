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
  ArrowLeft
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
          <span>Dashboard</span>
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
          <span>Active Results</span>
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
          className={`nav-item ${activeTab === "history" ? "active" : ""}`}
          onClick={() => onSelectTab("history")}
        >
          <History size={18} />
          <span>Scan History</span>
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
