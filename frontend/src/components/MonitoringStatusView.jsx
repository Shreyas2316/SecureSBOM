import React, { useState, useEffect } from "react";
import { Activity, RefreshCw, Bell, CheckCircle2, AlertTriangle, Clock, Info, BellOff } from "lucide-react";
import { fetchMonitoringStatus, triggerMonitoringRun, fetchMonitoringAlerts, acknowledgeAlert } from "../api";

function StatusIndicator({ isOnline, last_error }) {
  const color = last_error ? "#FF6B00" : isOnline ? "#00FF88" : "#64748B";
  const label = last_error ? "Error" : isOnline ? "Operational" : "Not initialized";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{
        width: 8, height: 8, borderRadius: "50%",
        background: color, boxShadow: `0 0 6px ${color}`,
        animation: isOnline && !last_error ? "pulse-dot 2s infinite" : "none",
      }} />
      <span style={{ color, fontWeight: 600, fontSize: "0.82rem" }}>{label}</span>
    </div>
  );
}

function AlertRow({ alert, onAck }) {
  const sevColors = {
    CRITICAL: "#FF2E4D", HIGH: "#FF6B00", MEDIUM: "#FFB800",
    LOW: "#00B4D8", UNKNOWN: "#64748B",
  };
  const color = sevColors[alert.severity?.toUpperCase()] || "#64748B";

  return (
    <tr style={{ opacity: alert.is_acknowledged ? 0.5 : 1 }}>
      <td>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.78rem", color: "#00F5FF" }}>{alert.advisory_id}</span>
      </td>
      <td>
        <div style={{ fontWeight: 600 }}>{alert.package_name}</div>
        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>v{alert.package_version}</div>
      </td>
      <td>
        <span style={{ color, fontWeight: 700, fontSize: "0.8rem", fontFamily: "var(--font-mono)" }}>{alert.severity || "UNKNOWN"}</span>
      </td>
      <td style={{ maxWidth: 300 }}>
        <div style={{ fontSize: "0.82rem", color: "var(--text-muted)", lineHeight: 1.4 }}>
          {(alert.summary || "").slice(0, 100)}{alert.summary?.length > 100 ? "…" : ""}
        </div>
      </td>
      <td>
        <span style={{ fontSize: "0.78rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
          {alert.created_at ? new Date(alert.created_at).toLocaleDateString() : "—"}
        </span>
      </td>
      <td>
        {alert.is_acknowledged ? (
          <span style={{ fontSize: "0.75rem", color: "#64748B" }}>Acknowledged</span>
        ) : (
          <button className="btn btn-secondary btn-sm" onClick={() => onAck(alert.id)}>
            <CheckCircle2 size={13} />
            <span>Ack</span>
          </button>
        )}
      </td>
    </tr>
  );
}

export default function MonitoringStatusView() {
  const [status, setStatus] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [runResult, setRunResult] = useState(null);

  const load = async () => {
    setLoading(true);
    try {
      const [s, a] = await Promise.all([
        fetchMonitoringStatus().catch(() => null),
        fetchMonitoringAlerts({ acknowledged: false }).catch(() => ({ alerts: [], total: 0 })),
      ]);
      setStatus(s);
      setAlerts(a.alerts || []);
      setTotalAlerts(a.total || 0);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const handleRunMonitoring = async () => {
    setRunning(true);
    setRunResult(null);
    try {
      const res = await triggerMonitoringRun();
      setRunResult(res);
      await load();
    } catch (err) {
      setRunResult({ error: err.message });
    } finally {
      setRunning(false);
    }
  };

  const handleAck = async (alertId) => {
    await acknowledgeAlert(alertId).catch(() => {});
    await load();
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
            <Activity size={22} style={{ color: "#00F5FF" }} />
            <h2 className="page-title">Advisory Monitoring Status</h2>
          </div>
          <p className="page-subtitle">
            Periodic advisory feed monitoring — checks saved SBOM components against OSV for new findings.
          </p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button className="btn btn-secondary btn-sm" onClick={load} disabled={loading}>
            <RefreshCw size={14} className={loading ? "spin" : ""} />
            <span>Refresh</span>
          </button>
          <button className="btn btn-primary" onClick={handleRunMonitoring} disabled={running}>
            <Activity size={15} />
            <span>{running ? "Running…" : "Run Monitoring Cycle"}</span>
          </button>
        </div>
      </div>

      {/* Important note */}
      <div style={{ background: "rgba(0,245,255,0.04)", border: "1px solid rgba(0,245,255,0.15)", borderRadius: 10, padding: "12px 18px", marginBottom: 24, display: "flex", gap: 12, alignItems: "flex-start" }}>
        <Info size={16} style={{ color: "#00F5FF", marginTop: 2, flexShrink: 0 }} />
        <div style={{ fontSize: "0.82rem", color: "var(--text-muted)", lineHeight: 1.5 }}>
          <strong style={{ color: "var(--text-main)" }}>Periodic monitoring only.</strong> This system runs on-demand or scheduled checks — it is not real-time continuous monitoring.
          Each run queries OSV for all saved SBOM packages. Alerts are generated only for new advisories not previously processed.
          Monitoring frequency must respect OSV API rate limits.
        </div>
      </div>

      {/* Run result */}
      {runResult && (
        <div style={{
          background: runResult.error ? "rgba(255,46,77,0.06)" : "rgba(0,255,136,0.06)",
          border: `1px solid ${runResult.error ? "rgba(255,46,77,0.25)" : "rgba(0,255,136,0.25)"}`,
          borderRadius: 10, padding: "14px 18px", marginBottom: 20,
        }}>
          {runResult.error ? (
            <div style={{ color: "#FF2E4D" }}>Monitoring failed: {runResult.error}</div>
          ) : (
            <div>
              <div style={{ color: "#00FF88", fontWeight: 700, marginBottom: 6 }}>✓ Monitoring cycle completed</div>
              <div style={{ color: "var(--text-muted)", fontSize: "0.82rem" }}>
                Components checked: {runResult.results?.components_checked} ·
                Advisories processed: {runResult.results?.advisories_processed} ·
                New alerts: {runResult.results?.new_alerts}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Status Cards */}
      {status && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
            <h3 style={{ fontWeight: 700, fontSize: "1rem" }}>OSV PyPI Monitoring Source</h3>
            <StatusIndicator isOnline={!!status.last_successful_sync_at} last_error={status.last_error} />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16 }}>
            {[
              { label: "Last Checked", value: status.last_checked_at ? new Date(status.last_checked_at).toLocaleString() : "Never" },
              { label: "Last Successful Sync", value: status.last_successful_sync_at ? new Date(status.last_successful_sync_at).toLocaleString() : "Never" },
              { label: "Advisories Processed", value: status.advisories_processed ?? 0 },
              { label: "Affected Dependencies Found", value: status.affected_dependencies_found ?? 0 },
              { label: "Unacknowledged Alerts", value: status.unacknowledged_alerts ?? 0 },
            ].map(({ label, value }) => (
              <div key={label} style={{ background: "rgba(255,255,255,0.02)", borderRadius: 8, padding: "12px 16px" }}>
                <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginBottom: 4, textTransform: "uppercase" }}>{label}</div>
                <div style={{ fontWeight: 700, fontFamily: "var(--font-mono)", color: "var(--text-main)" }}>{value}</div>
              </div>
            ))}
          </div>

          {status.last_error && (
            <div style={{ marginTop: 16, padding: "10px 14px", background: "rgba(255,107,0,0.08)", border: "1px solid rgba(255,107,0,0.3)", borderRadius: 8, color: "#FF6B00", fontSize: "0.82rem" }}>
              Last Error: {status.last_error}
            </div>
          )}
        </div>
      )}

      {/* Alerts Table */}
      <div className="card" style={{ padding: 0 }}>
        <div style={{ padding: "16px 20px", borderBottom: "1px solid rgba(255,255,255,0.06)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <h3 style={{ fontWeight: 700, fontSize: "1rem" }}>Unacknowledged Monitoring Alerts</h3>
            <p style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: 2 }}>
              New advisories affecting saved SBOM dependencies
            </p>
          </div>
          {totalAlerts > 0 && (
            <span style={{ background: "rgba(255,46,77,0.12)", color: "#FF2E4D", border: "1px solid rgba(255,46,77,0.35)", borderRadius: 9999, padding: "3px 10px", fontSize: "0.8rem", fontWeight: 700 }}>
              {totalAlerts} alerts
            </span>
          )}
        </div>

        {loading ? (
          <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)" }}>Loading alerts…</div>
        ) : alerts.length === 0 ? (
          <div style={{ padding: 48, textAlign: "center", color: "var(--text-muted)" }}>
            <BellOff size={36} style={{ marginBottom: 12, opacity: 0.3 }} />
            <div style={{ fontWeight: 600 }}>No unacknowledged alerts</div>
            <div style={{ fontSize: "0.85rem", marginTop: 4 }}>Run a monitoring cycle to check for new advisories.</div>
          </div>
        ) : (
          <div className="table-responsive" style={{ border: "none" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Advisory ID</th>
                  <th>Package</th>
                  <th>Severity</th>
                  <th>Summary</th>
                  <th>Detected</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map(a => <AlertRow key={a.id} alert={a} onAck={handleAck} />)}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
