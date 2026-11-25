import React, { useState, useEffect } from "react";
import { Sparkles, ExternalLink, Check, X, ShieldAlert, Play } from "lucide-react";
import {
  fetchEmergingFindings,
  reviewEmergingFinding,
  runRagAssessment,
} from "../api";

export default function EmergingVulnsView({ activeScan }) {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [pkgName, setPkgName] = useState("");
  const [pkgVersion, setPkgVersion] = useState("");
  const [running, setRunning] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const load = async () => {
    setLoading(true);
    try {
      const res = await fetchEmergingFindings();
      setFindings(res.findings || []);
    } catch (e) {
      setErr(e.message || "Failed to load emerging findings.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleAssess = async (e) => {
    e.preventDefault();
    if (!pkgName.trim()) return;
    setRunning(true);
    setMsg("");
    setErr("");
    try {
      const scanId = activeScan?.report?.summary?.scan_id || activeScan?.summary?.scan_id;
      const res = await runRagAssessment({
        packageName: pkgName.trim(),
        packageVersion: pkgVersion.trim() || "unknown",
        scanId,
      });
      if (res.abstained) {
        setMsg(`RAG Abstained: ${res.message}`);
      } else {
        setMsg(`Created Emerging Finding ${res.finding_id} (${res.confidence} confidence).`);
        await load();
      }
    } catch (e2) {
      setErr(e2.message || "RAG assessment failed.");
    } finally {
      setRunning(false);
    }
  };

  const handleReview = async (findingId, action) => {
    try {
      await reviewEmergingFinding(findingId, { action, reason: `Analyst marked as ${action}` });
      await load();
    } catch (e) {
      setErr(e.message || "Review update failed.");
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <div className="glass-panel" style={{ padding: "1.5rem" }}>
        <h2 style={{ fontSize: "1.2rem", display: "flex", alignItems: "center", gap: "8px", margin: 0 }}>
          <Sparkles size={20} color="#00F5FF" />
          Category B — Emerging Vulnerability Intelligence
        </h2>
        <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginTop: "4px" }}>
          Evidence-grounded emerging disclosures retrieved from the local intelligence dataset. Strictly separated from confirmed Category A vulnerability totals.
        </p>

        <form onSubmit={handleAssess} style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap", marginTop: "1rem" }}>
          <input
            className="input"
            placeholder="Package name (e.g. requests)"
            value={pkgName}
            onChange={(e) => setPkgName(e.target.value)}
            required
            style={{ flex: 1, minWidth: "180px" }}
          />
          <input
            className="input"
            placeholder="Version (e.g. 2.25.0)"
            value={pkgVersion}
            onChange={(e) => setPkgVersion(e.target.value)}
            style={{ flex: 1, minWidth: "140px" }}
          />
          <button type="submit" className="btn btn-primary" disabled={running}>
            <Play size={14} />
            <span>{running ? "Running RAG..." : "Run Evidence RAG Assessment"}</span>
          </button>
        </form>

        {msg && <p style={{ color: "#00F5FF", fontSize: "0.85rem", marginTop: "0.75rem" }}>{msg}</p>}
        {err && <p style={{ color: "#FF6B81", fontSize: "0.85rem", marginTop: "0.75rem" }}>{err}</p>}
      </div>

      {loading ? (
        <div className="glass-panel" style={{ padding: "2rem", color: "var(--text-muted)" }}>Loading emerging findings...</div>
      ) : findings.length === 0 ? (
        <div className="glass-panel" style={{ padding: "2rem", textAlign: "center", color: "var(--text-muted)" }}>
          <ShieldAlert size={30} color="#00F5FF" style={{ margin: "0 auto 0.75rem" }} />
          <div>No Category B emerging findings recorded yet. Sync the Intelligence Dataset and run an Evidence RAG Assessment above.</div>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          {findings.map((f) => (
            <div key={f.finding_id} className="glass-panel" style={{ padding: "1.25rem", borderLeft: "3px solid #00F5FF" }}>
              <div style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: "0.75rem" }}>
                <div>
                  <span style={{ fontSize: "0.72rem", fontFamily: "var(--font-mono)", color: "#00F5FF" }}>
                    {f.finding_id} · {f.package_name}@{f.package_version} · Version Status: {f.affected_version_status}
                  </span>
                  <h3 style={{ fontSize: "1rem", margin: "4px 0" }}>{f.title}</h3>
                </div>
                <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                  <span className="badge badge-info">Confidence: {f.confidence}</span>
                  <span className="badge badge-medium">Status: {f.status}</span>
                </div>
              </div>
              <p style={{ fontSize: "0.85rem", color: "#CBD5E1", margin: "0.5rem 0" }}>{f.description}</p>
              <p style={{ fontSize: "0.78rem", color: "var(--text-muted)", margin: "0.25rem 0" }}>
                <strong>Limitations:</strong> {f.limitations}
              </p>
              <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginTop: "0.75rem" }}>
                {(f.source_urls || []).slice(0, 3).map((u, i) => (
                  <a key={i} href={u} target="_blank" rel="noreferrer" className="btn btn-secondary" style={{ fontSize: "0.75rem", padding: "4px 10px" }}>
                    <span>Source #{i + 1}</span>
                    <ExternalLink size={12} />
                  </a>
                ))}
                <button className="btn btn-secondary" style={{ fontSize: "0.75rem", padding: "4px 10px" }} onClick={() => handleReview(f.finding_id, "under_review")}>
                  <Check size={12} /> Mark Under Review
                </button>
                <button className="btn btn-secondary" style={{ fontSize: "0.75rem", padding: "4px 10px", color: "#FF6B81" }} onClick={() => handleReview(f.finding_id, "rejected")}>
                  <X size={12} /> Reject
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
