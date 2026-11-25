import React, { useState, useEffect } from "react";
import { Database, RefreshCw, Search, ExternalLink, AlertTriangle, CheckCircle2 } from "lucide-react";
import {
  fetchIntelligenceSources,
  syncIntelligenceSources,
  searchIntelligenceDocuments,
  reassessProjects,
} from "../api";

export default function IntelligenceDatasetView() {
  const [sourcesData, setSourcesData] = useState({ total_documents: 0, active_sources: 0, sources: [] });
  const [docs, setDocs] = useState([]);
  const [query, setQuery] = useState("");
  const [pkgFilter, setPkgFilter] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [statusMsg, setStatusMsg] = useState("");
  const [error, setError] = useState("");

  const loadAll = async () => {
    setLoading(true);
    setError("");
    try {
      const [srcRes, docRes] = await Promise.all([
        fetchIntelligenceSources(),
        searchIntelligenceDocuments({ q: query || undefined, package: pkgFilter || undefined, sourceKey: sourceFilter || undefined }),
      ]);
      setSourcesData(srcRes);
      setDocs(docRes.documents || []);
    } catch (err) {
      setError(err.message || "Failed to load intelligence dataset.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAll();
  }, []);

  const handleSync = async () => {
    setSyncing(true);
    setStatusMsg("");
    setError("");
    try {
      const res = await syncIntelligenceSources();
      const reassessed = await reassessProjects();
      setStatusMsg(
        `Synced ${res.synced_sources} source(s): ${res.new_documents} new, ${res.updated_documents} updated. ` +
        `Reassessed ${reassessed.scans_reassessed} scan(s) (${reassessed.new_intelligence_matches} new match(es)).`
      );
      await loadAll();
    } catch (err) {
      setError(err.message || "Synchronization failed.");
    } finally {
      setSyncing(false);
    }
  };

  const handleSearch = (e) => {
    e.preventDefault();
    loadAll();
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <div className="glass-panel" style={{ padding: "1.5rem", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem" }}>
        <div>
          <h2 style={{ fontSize: "1.2rem", display: "flex", alignItems: "center", gap: "8px", margin: 0 }}>
            <Database size={20} color="#00F5FF" />
            Local Security Intelligence Dataset
          </h2>
          <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginTop: "4px" }}>
            Continuously synchronized public advisories, GHSA, PyPA, CVE List V5, and security feeds indexed for hybrid RAG retrieval.
          </p>
        </div>
        <button className="btn btn-primary" onClick={handleSync} disabled={syncing}>
          <RefreshCw size={15} className={syncing ? "spin" : ""} />
          <span>{syncing ? "Synchronizing..." : "Sync Intelligence Now"}</span>
        </button>
      </div>

      {statusMsg && (
        <div className="glass-panel" style={{ padding: "0.9rem 1.2rem", borderColor: "rgba(0,255,136,0.4)", color: "#00FF88", display: "flex", alignItems: "center", gap: "8px", fontSize: "0.85rem" }}>
          <CheckCircle2 size={16} />
          <span>{statusMsg}</span>
        </div>
      )}
      {error && (
        <div className="glass-panel" style={{ padding: "0.9rem 1.2rem", borderColor: "rgba(255,46,77,0.4)", color: "#FF6B81", display: "flex", alignItems: "center", gap: "8px", fontSize: "0.85rem" }}>
          <AlertTriangle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* Summary Metrics */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "1rem" }}>
        <div className="glass-panel" style={{ padding: "1rem" }}>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>INDEXED DOCUMENTS</div>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "#00F5FF" }}>{sourcesData.total_documents}</div>
        </div>
        <div className="glass-panel" style={{ padding: "1rem" }}>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>ACTIVE SOURCES</div>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "#00FF88" }}>{sourcesData.active_sources}</div>
        </div>
        <div className="glass-panel" style={{ padding: "1rem" }}>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>FAILED SOURCES</div>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "#F59E0B" }}>
            {sourcesData.sources.filter((s) => Boolean(s.last_error)).length}
          </div>
        </div>
      </div>

      {/* Sources Health Table */}
      <div className="glass-panel" style={{ padding: "1.25rem", overflowX: "auto" }}>
        <h3 style={{ fontSize: "1rem", marginBottom: "0.75rem" }}>Source Health & Freshness</h3>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.82rem" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid var(--border-color)", color: "var(--text-muted)", textAlign: "left" }}>
              <th style={{ padding: "0.6rem" }}>Source</th>
              <th style={{ padding: "0.6rem" }}>Reliability</th>
              <th style={{ padding: "0.6rem" }}>Docs</th>
              <th style={{ padding: "0.6rem" }}>Last Successful Sync</th>
              <th style={{ padding: "0.6rem" }}>Status</th>
            </tr>
          </thead>
          <tbody>
            {sourcesData.sources.map((s) => (
              <tr key={s.source_key} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                <td style={{ padding: "0.6rem", fontWeight: 600 }}>{s.name}</td>
                <td style={{ padding: "0.6rem" }}>{s.reliability_tier}</td>
                <td style={{ padding: "0.6rem" }}>{s.documents_indexed}</td>
                <td style={{ padding: "0.6rem", fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>
                  {s.last_successful_sync_at ? new Date(s.last_successful_sync_at).toLocaleString() : "Not synced yet"}
                </td>
                <td style={{ padding: "0.6rem" }}>
                  {s.last_error ? (
                    <span style={{ color: "#F59E0B" }} title={s.last_error}>Warning: Sync Error</span>
                  ) : (
                    <span style={{ color: "#00FF88" }}>Healthy</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Search & Documents */}
      <div className="glass-panel" style={{ padding: "1.25rem" }}>
        <form onSubmit={handleSearch} style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap", marginBottom: "1rem" }}>
          <input
            className="input"
            placeholder="Hybrid search (keywords, CVE, GHSA, description)..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{ flex: 2, minWidth: "220px" }}
          />
          <input
            className="input"
            placeholder="Package filter (e.g. requests)"
            value={pkgFilter}
            onChange={(e) => setPkgFilter(e.target.value)}
            style={{ flex: 1, minWidth: "150px" }}
          />
          <select className="select" value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)} style={{ width: "auto" }}>
            <option value="">All Sources</option>
            {sourcesData.sources.map((s) => (
              <option key={s.source_key} value={s.source_key}>{s.name}</option>
            ))}
          </select>
          <button type="submit" className="btn btn-secondary">
            <Search size={15} />
            <span>Search</span>
          </button>
        </form>

        {loading ? (
          <p style={{ color: "var(--text-muted)" }}>Loading intelligence documents...</p>
        ) : docs.length === 0 ? (
          <p style={{ color: "var(--text-muted)" }}>No intelligence documents indexed yet. Click "Sync Intelligence Now" above to populate the local dataset.</p>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            {docs.map((d) => (
              <div key={d.doc_uid} style={{ padding: "0.9rem", borderRadius: "8px", border: "1px solid var(--border-color)", background: "rgba(255,255,255,0.02)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "1rem" }}>
                  <div>
                    <div style={{ fontWeight: 600, color: "#fff" }}>{d.title}</div>
                    <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginTop: "4px" }}>
                      Packages: {(d.package_names || []).join(", ") || "Unspecified"} · Aliases: {(d.aliases || []).join(", ") || "None"} · Reliability: {d.source_reliability}
                    </div>
                  </div>
                  <a href={d.url} target="_blank" rel="noreferrer" className="btn btn-secondary" style={{ fontSize: "0.75rem", padding: "4px 10px" }}>
                    <span>Evidence</span>
                    <ExternalLink size={12} />
                  </a>
                </div>
                {d.excerpt && (
                  <p style={{ fontSize: "0.82rem", color: "#CBD5E1", marginTop: "0.5rem", marginBottom: 0 }}>{d.excerpt}</p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
