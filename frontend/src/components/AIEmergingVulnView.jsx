import React, { useState, useEffect, useCallback } from "react";
import {
  Brain, AlertTriangle, CheckCircle2, Clock, Search,
  Filter, ChevronDown, ChevronRight, ExternalLink,
  Shield, Eye, RefreshCw, Info, X, FileSearch,
  ZapOff, Activity
} from "lucide-react";
import {
  fetchAIDashboard, fetchAIFindings, fetchAIFindingById, reviewAIFinding,
  fetchAIStatus, triggerAIAnalysis
} from "../api";

// ─── Status badge config ────────────────────────────────────
const STATUS_CONFIG = {
  new_ai_assessment: { label: "New", color: "#00F5FF", bg: "rgba(0,245,255,0.12)", border: "rgba(0,245,255,0.35)" },
  needs_verification: { label: "Needs Verification", color: "#FFB800", bg: "rgba(255,184,0,0.12)", border: "rgba(255,184,0,0.40)" },
  under_investigation: { label: "Under Investigation", color: "#FF6B00", bg: "rgba(255,107,0,0.12)", border: "rgba(255,107,0,0.40)" },
  corroborated_by_authoritative_advisory: { label: "Corroborated", color: "#00FF88", bg: "rgba(0,255,136,0.12)", border: "rgba(0,255,136,0.40)" },
  rejected_after_review: { label: "Rejected", color: "#64748B", bg: "rgba(100,116,139,0.12)", border: "rgba(100,116,139,0.35)" },
  resolved: { label: "Resolved", color: "#94A3B8", bg: "rgba(148,163,184,0.12)", border: "rgba(148,163,184,0.35)" },
};

const CONFIDENCE_CONFIG = {
  high: { label: "High", color: "#FF6B00" },
  medium: { label: "Medium", color: "#FFB800" },
  low: { label: "Low", color: "#00B4D8" },
  insufficient_evidence: { label: "Insufficient", color: "#64748B" },
};

function StatusBadge({ status }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG["new_ai_assessment"];
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      padding: "3px 9px", borderRadius: 9999,
      fontSize: "0.72rem", fontWeight: 700,
      fontFamily: "var(--font-mono)",
      background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.border}`,
    }}>
      {cfg.label}
    </span>
  );
}

function ConfidencePill({ confidence }) {
  const cfg = CONFIDENCE_CONFIG[confidence] || CONFIDENCE_CONFIG["insufficient_evidence"];
  return (
    <span style={{ color: cfg.color, fontWeight: 700, fontFamily: "var(--font-mono)", fontSize: "0.8rem" }}>
      {cfg.label}
    </span>
  );
}

// ─── AI Disclaimer Banner ────────────────────────────────────
function AIDisclaimerBanner() {
  return (
    <div style={{
      background: "rgba(255,184,0,0.06)",
      border: "1px solid rgba(255,184,0,0.3)",
      borderRadius: 10, padding: "12px 18px",
      display: "flex", alignItems: "flex-start", gap: 12,
      marginBottom: 24,
    }}>
      <AlertTriangle size={18} style={{ color: "#FFB800", marginTop: 1, flexShrink: 0 }} />
      <div>
        <div style={{ fontWeight: 700, color: "#FFB800", fontSize: "0.88rem", marginBottom: 3 }}>
          AI-Generated Assessments — Not Confirmed Vulnerabilities
        </div>
        <div style={{ color: "var(--text-muted)", fontSize: "0.82rem", lineHeight: 1.5 }}>
          These findings are produced by AI analysis and require independent verification before taking action.
          AI assessment counts are <strong style={{ color: "var(--text-main)" }}>kept separate</strong> from
          verified OSV/NVD vulnerability findings. Review the supporting evidence before acting.
        </div>
      </div>
    </div>
  );
}

// ─── Dashboard Summary Cards ─────────────────────────────────
function DashboardCards({ stats, aiEnabled }) {
  const cards = [
    { label: "Total AI Assessments", value: stats.total_ai_assessments ?? 0, variant: "accent" },
    { label: "Awaiting Review", value: stats.new_awaiting_review ?? 0, variant: "warning" },
    { label: "Under Investigation", value: stats.under_investigation ?? 0, variant: "warning" },
    { label: "Corroborated", value: stats.corroborated_by_advisory ?? 0, variant: "success" },
    { label: "Rejected", value: stats.rejected ?? 0, variant: "muted" },
    { label: "Monitoring Alerts", value: stats.unacknowledged_monitoring_alerts ?? 0, variant: "danger" },
  ];

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 16, marginBottom: 24 }}>
      {cards.map((c) => (
        <div key={c.label} className={`stat-card ${c.variant === "danger" ? "stat-danger" : c.variant === "warning" ? "stat-warning" : c.variant === "success" ? "stat-success" : c.variant === "accent" ? "stat-accent" : ""}`}>
          <span className="stat-label">{c.label}</span>
          <div className="stat-value">{c.value}</div>
          {!aiEnabled && <span className="stat-sub" style={{ color: "#FFB800", fontSize: "0.72rem" }}>AI disabled</span>}
        </div>
      ))}
    </div>
  );
}

// ─── Finding Detail Panel ─────────────────────────────────────
function FindingDetailPanel({ finding, onClose, onReview }) {
  const [reviewAction, setReviewAction] = useState("");
  const [notes, setNotes] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const handleReview = async () => {
    if (!reviewAction) return;
    setSubmitting(true);
    try {
      await reviewAIFinding(finding.finding_id, { action: reviewAction, notes });
      onReview();
      onClose();
    } catch (err) {
      alert("Review failed: " + err.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 9999,
      background: "rgba(5,7,10,0.88)", backdropFilter: "blur(8px)",
      display: "flex", alignItems: "center", justifyContent: "center",
      padding: 20,
    }} onClick={onClose}>
      <div style={{
        background: "#0B0E14", border: "1px solid rgba(255,255,255,0.1)",
        borderRadius: 14, maxWidth: 840, width: "100%",
        maxHeight: "90vh", display: "flex", flexDirection: "column",
        overflow: "hidden",
        boxShadow: "0 25px 50px rgba(0,0,0,0.8), 0 0 30px rgba(0,245,255,0.06)",
      }} onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div style={{ padding: "20px 24px", borderBottom: "1px solid rgba(255,255,255,0.08)", background: "#080B10", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
              <Brain size={18} style={{ color: "#00F5FF" }} />
              <span style={{ color: "#00F5FF", fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>AI ASSESSMENT</span>
              <StatusBadge status={finding.status} />
            </div>
            <h3 style={{ fontSize: "1.05rem", fontWeight: 700, color: "var(--text-main)", lineHeight: 1.3 }}>
              {finding.title}
            </h3>
            <div style={{ fontSize: "0.82rem", color: "var(--text-muted)", marginTop: 4 }}>
              {finding.package_name} @ {finding.package_version} · {finding.ecosystem}
            </div>
          </div>
          <button onClick={onClose} style={{ background: "transparent", border: "none", cursor: "pointer", color: "var(--text-muted)", padding: 4 }}>
            <X size={20} />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: "24px", overflowY: "auto", flex: 1 }}>
          {/* Disclaimer */}
          <div style={{ background: "rgba(255,184,0,0.07)", border: "1px solid rgba(255,184,0,0.25)", borderRadius: 8, padding: "10px 14px", marginBottom: 20, fontSize: "0.8rem", color: "#FFB800" }}>
            ⚠ AI-generated assessment. This finding is not a confirmed vulnerability unless independently verified. Review the supporting evidence before taking action.
          </div>

          {/* Meta grid */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 20 }}>
            <div className="card" style={{ padding: 14, margin: 0 }}>
              <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginBottom: 4 }}>CONFIDENCE</div>
              <ConfidencePill confidence={finding.confidence} />
              {finding.confidence_explanation && (
                <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginTop: 6 }}>{finding.confidence_explanation}</div>
              )}
            </div>
            <div className="card" style={{ padding: 14, margin: 0 }}>
              <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginBottom: 4 }}>ASSESSMENT TYPE</div>
              <span style={{ color: "#00F5FF", fontSize: "0.82rem", fontWeight: 600 }}>
                {finding.assessment_type === "emerging_advisory_analysis" ? "Emerging Advisory" : "Potential Weakness"}
              </span>
              {finding.model_name && (
                <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: 4 }}>Model: {finding.model_name}</div>
              )}
            </div>
          </div>

          {/* Description */}
          {finding.description && (
            <section style={{ marginBottom: 20 }}>
              <h4 style={{ fontSize: "0.85rem", fontWeight: 700, color: "var(--text-main)", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "var(--font-mono)" }}>Description</h4>
              <p style={{ color: "var(--text-muted)", fontSize: "0.88rem", lineHeight: 1.6 }}>{finding.description}</p>
            </section>
          )}

          {/* Potential Impact */}
          {finding.potential_impact && (
            <section style={{ marginBottom: 20 }}>
              <h4 style={{ fontSize: "0.85rem", fontWeight: 700, color: "#FF6B00", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "var(--font-mono)" }}>Potential Impact</h4>
              <p style={{ color: "var(--text-muted)", fontSize: "0.88rem", lineHeight: 1.6 }}>{finding.potential_impact}</p>
            </section>
          )}

          {/* Evidence */}
          {finding.evidence && finding.evidence.length > 0 && (
            <section style={{ marginBottom: 20 }}>
              <h4 style={{ fontSize: "0.85rem", fontWeight: 700, color: "var(--text-main)", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "var(--font-mono)" }}>Evidence Considered</h4>
              <ul style={{ listStyle: "none", padding: 0, display: "flex", flexDirection: "column", gap: 6 }}>
                {finding.evidence.map((e, i) => (
                  <li key={i} style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 6, padding: "8px 12px", fontSize: "0.82rem", color: "var(--text-muted)" }}>
                    {e}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* Evidence Sources */}
          {finding.evidence_sources && finding.evidence_sources.length > 0 && (
            <section style={{ marginBottom: 20 }}>
              <h4 style={{ fontSize: "0.85rem", fontWeight: 700, color: "var(--text-main)", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "var(--font-mono)" }}>Evidence Sources</h4>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {finding.evidence_sources.map((s, i) => (
                  <span key={i} style={{ background: "rgba(0,245,255,0.08)", border: "1px solid rgba(0,245,255,0.2)", borderRadius: 6, padding: "4px 10px", fontSize: "0.75rem", color: "#00F5FF" }}>{s}</span>
                ))}
              </div>
            </section>
          )}

          {/* Verification Steps */}
          {finding.verification_steps && finding.verification_steps.length > 0 && (
            <section style={{ marginBottom: 20 }}>
              <h4 style={{ fontSize: "0.85rem", fontWeight: 700, color: "#00FF88", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "var(--font-mono)" }}>Verification Steps</h4>
              <ol style={{ paddingLeft: 20, display: "flex", flexDirection: "column", gap: 6 }}>
                {finding.verification_steps.map((s, i) => (
                  <li key={i} style={{ color: "var(--text-muted)", fontSize: "0.85rem", lineHeight: 1.5 }}>{s}</li>
                ))}
              </ol>
            </section>
          )}

          {/* Suggested Mitigations */}
          {finding.suggested_mitigations && finding.suggested_mitigations.length > 0 && (
            <section style={{ marginBottom: 20 }}>
              <h4 style={{ fontSize: "0.85rem", fontWeight: 700, color: "var(--text-main)", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "var(--font-mono)" }}>Suggested Mitigations</h4>
              <ul style={{ paddingLeft: 20, display: "flex", flexDirection: "column", gap: 6 }}>
                {finding.suggested_mitigations.map((m, i) => (
                  <li key={i} style={{ color: "var(--text-muted)", fontSize: "0.85rem", lineHeight: 1.5 }}>{m}</li>
                ))}
              </ul>
            </section>
          )}

          {/* Limitations */}
          {finding.limitations && (
            <section style={{ marginBottom: 20 }}>
              <div style={{ background: "rgba(100,116,139,0.08)", border: "1px solid rgba(100,116,139,0.2)", borderRadius: 8, padding: "12px 14px" }}>
                <h4 style={{ fontSize: "0.75rem", fontWeight: 700, color: "#64748B", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "var(--font-mono)" }}>Limitations</h4>
                <p style={{ color: "#64748B", fontSize: "0.82rem", lineHeight: 1.5 }}>{finding.limitations}</p>
              </div>
            </section>
          )}

          {/* Review History */}
          {finding.review_history && finding.review_history.length > 0 && (
            <section style={{ marginBottom: 20 }}>
              <h4 style={{ fontSize: "0.85rem", fontWeight: 700, color: "var(--text-main)", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "var(--font-mono)" }}>Review History</h4>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {finding.review_history.map((r) => (
                  <div key={r.id} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 8, padding: "10px 14px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                      <span style={{ fontSize: "0.78rem", fontWeight: 600, color: "var(--text-main)" }}>{r.action}</span>
                      <span style={{ fontSize: "0.72rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>{r.created_at ? new Date(r.created_at).toLocaleString() : ""}</span>
                    </div>
                    {r.notes && <div style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>{r.notes}</div>}
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Review Controls */}
          <div style={{ borderTop: "1px solid rgba(255,255,255,0.08)", paddingTop: 20 }}>
            <h4 style={{ fontSize: "0.85rem", fontWeight: 700, color: "var(--text-main)", marginBottom: 12, textTransform: "uppercase", letterSpacing: "0.05em", fontFamily: "var(--font-mono)" }}>Update Review Status</h4>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 12 }}>
              {Object.entries(STATUS_CONFIG).map(([val, cfg]) => (
                <button
                  key={val}
                  onClick={() => setReviewAction(val)}
                  style={{
                    padding: "5px 12px", borderRadius: 6, cursor: "pointer",
                    fontSize: "0.78rem", fontWeight: 600, fontFamily: "var(--font-mono)",
                    background: reviewAction === val ? cfg.bg : "transparent",
                    color: reviewAction === val ? cfg.color : "var(--text-muted)",
                    border: `1px solid ${reviewAction === val ? cfg.border : "rgba(255,255,255,0.1)"}`,
                    transition: "all 0.15s",
                  }}
                >
                  {cfg.label}
                </button>
              ))}
            </div>
            <textarea
              className="textarea"
              placeholder="Reviewer notes (optional)"
              value={notes}
              onChange={e => setNotes(e.target.value)}
              style={{ height: 72, marginBottom: 12 }}
            />
            <button
              className="btn btn-primary"
              onClick={handleReview}
              disabled={!reviewAction || submitting}
              style={{ opacity: reviewAction ? 1 : 0.5 }}
            >
              {submitting ? "Saving..." : "Submit Review"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Main Dashboard ──────────────────────────────────────────
export default function AIEmergingVulnView({ onNavigate }) {
  const [stats, setStats] = useState({});
  const [findings, setFindings] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [aiEnabled, setAIEnabled] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [detailFinding, setDetailFinding] = useState(null);

  // Filters
  const [filterStatus, setFilterStatus] = useState("");
  const [filterConfidence, setFilterConfidence] = useState("");
  const [filterType, setFilterType] = useState("");
  const [searchPkg, setSearchPkg] = useState("");

  const PAGE_SIZE = 15;

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [dashRes, findRes, statusRes] = await Promise.all([
        fetchAIDashboard().catch(() => ({})),
        fetchAIFindings({
          status: filterStatus || undefined,
          confidence: filterConfidence || undefined,
          assessmentType: filterType || undefined,
          package: searchPkg || undefined,
          page, pageSize: PAGE_SIZE,
        }).catch(() => ({ findings: [], total: 0 })),
        fetchAIStatus().catch(() => ({ ai_enabled: false })),
      ]);
      setStats(dashRes);
      setFindings(findRes.findings || []);
      setTotal(findRes.total || 0);
      setAIEnabled(statusRes.ai_enabled || false);
    } finally {
      setLoading(false);
    }
  }, [filterStatus, filterConfidence, filterType, searchPkg, page]);

  useEffect(() => { loadData(); }, [loadData]);

  const openDetail = async (finding) => {
    try {
      const full = await fetchAIFindingById(finding.finding_id);
      setDetailFinding(full);
    } catch {
      setDetailFinding(finding);
    }
  };

  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div>
      <div className="page-header">
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
            <Brain size={22} style={{ color: "#00F5FF" }} />
            <h2 className="page-title">AI-Detected Emerging Vulnerabilities</h2>
          </div>
          <p className="page-subtitle">
            AI assessments of potential security concerns — separate from verified OSV/NVD findings.
          </p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button className="btn btn-secondary btn-sm" onClick={loadData} disabled={loading}>
            <RefreshCw size={14} className={loading ? "spin" : ""} />
            <span>Refresh</span>
          </button>
          {!aiEnabled && (
            <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "0.8rem", color: "#FFB800", border: "1px solid rgba(255,184,0,0.3)", borderRadius: 8, padding: "6px 12px" }}>
              <ZapOff size={14} />
              <span>AI disabled — configure AI_ENABLED</span>
            </div>
          )}
        </div>
      </div>

      <AIDisclaimerBanner />
      <DashboardCards stats={stats} aiEnabled={aiEnabled} />

      {/* Filters */}
      <div className="card" style={{ padding: 16, marginBottom: 20 }}>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
          <div style={{ position: "relative", flex: "1 1 200px" }}>
            <Search size={14} style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)" }} />
            <input
              className="input-text"
              placeholder="Search package..."
              value={searchPkg}
              onChange={e => { setSearchPkg(e.target.value); setPage(1); }}
              style={{ paddingLeft: 32 }}
            />
          </div>

          <select className="select" value={filterStatus} onChange={e => { setFilterStatus(e.target.value); setPage(1); }} style={{ flex: "0 1 200px" }}>
            <option value="">All Statuses</option>
            {Object.entries(STATUS_CONFIG).map(([val, cfg]) => <option key={val} value={val}>{cfg.label}</option>)}
          </select>

          <select className="select" value={filterConfidence} onChange={e => { setFilterConfidence(e.target.value); setPage(1); }} style={{ flex: "0 1 170px" }}>
            <option value="">All Confidence</option>
            {Object.entries(CONFIDENCE_CONFIG).map(([val, cfg]) => <option key={val} value={val}>{cfg.label}</option>)}
          </select>

          <select className="select" value={filterType} onChange={e => { setFilterType(e.target.value); setPage(1); }} style={{ flex: "0 1 200px" }}>
            <option value="">All Types</option>
            <option value="emerging_advisory_analysis">Emerging Advisory</option>
            <option value="potential_weakness_analysis">Potential Weakness</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        {loading ? (
          <div style={{ padding: 48, textAlign: "center", color: "var(--text-muted)" }}>
            <Brain size={32} style={{ marginBottom: 12, opacity: 0.4 }} />
            <div>Loading AI assessments...</div>
          </div>
        ) : findings.length === 0 ? (
          <div style={{ padding: 48, textAlign: "center", color: "var(--text-muted)" }}>
            <FileSearch size={40} style={{ marginBottom: 14, opacity: 0.3 }} />
            <div style={{ marginBottom: 8, fontSize: "1rem", fontWeight: 600 }}>No AI assessments found</div>
            <div style={{ fontSize: "0.85rem" }}>
              {aiEnabled
                ? "Trigger an AI analysis from the scan results view to generate assessments."
                : "Enable AI analysis by configuring AI_ENABLED=True in server environment."}
            </div>
          </div>
        ) : (
          <>
            <div className="table-responsive" style={{ border: "none" }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Finding ID</th>
                    <th>Package</th>
                    <th>Title</th>
                    <th>Type</th>
                    <th>Confidence</th>
                    <th>Status</th>
                    <th>Date</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f) => (
                    <tr key={f.finding_id} style={{ cursor: "pointer" }} onClick={() => openDetail(f)}>
                      <td>
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.78rem", color: "#00F5FF" }}>
                          {f.finding_id}
                        </span>
                      </td>
                      <td>
                        <div style={{ fontWeight: 600, fontSize: "0.88rem" }}>{f.package_name}</div>
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>v{f.package_version}</div>
                      </td>
                      <td style={{ maxWidth: 260 }}>
                        <div style={{ fontSize: "0.85rem", color: "var(--text-main)", lineHeight: 1.4 }}>
                          {f.title.length > 60 ? f.title.slice(0, 60) + "…" : f.title}
                        </div>
                      </td>
                      <td>
                        <span style={{ fontSize: "0.75rem", color: "#00F5FF", fontFamily: "var(--font-mono)" }}>
                          {f.assessment_type === "emerging_advisory_analysis" ? "Advisory" : "Weakness"}
                        </span>
                      </td>
                      <td><ConfidencePill confidence={f.confidence} /></td>
                      <td><StatusBadge status={f.status} /></td>
                      <td>
                        <span style={{ fontSize: "0.78rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                          {f.created_at ? new Date(f.created_at).toLocaleDateString() : "—"}
                        </span>
                      </td>
                      <td onClick={e => e.stopPropagation()}>
                        <button className="btn btn-secondary btn-sm" onClick={() => openDetail(f)}>
                          <Eye size={13} />
                          <span>View</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {pages > 1 && (
              <div style={{ padding: "14px 20px", borderTop: "1px solid rgba(255,255,255,0.06)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                  Page {page} of {pages} · {total} total
                </span>
                <div style={{ display: "flex", gap: 8 }}>
                  <button className="btn btn-secondary btn-sm" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}>← Prev</button>
                  <button className="btn btn-secondary btn-sm" onClick={() => setPage(p => Math.min(pages, p + 1))} disabled={page === pages}>Next →</button>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {detailFinding && (
        <FindingDetailPanel
          finding={detailFinding}
          onClose={() => setDetailFinding(null)}
          onReview={loadData}
        />
      )}
    </div>
  );
}
