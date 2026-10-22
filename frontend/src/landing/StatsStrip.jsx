import React from "react";
import { ShieldCheck, Zap, Layers, Activity } from "lucide-react";
import MetricTicker from "../components/ui/MetricTicker";

// TODO: Metric baseline figures are derived from local benchmark suite evaluation results
const STATS = [
  {
    icon: ShieldCheck,
    value: 100,
    suffix: "%",
    label: "NTIA Minimum Elements",
    desc: "100% compliance across all 7 NTIA minimum standard data fields",
  },
  {
    icon: Zap,
    value: 120,
    suffix: "ms",
    label: "Avg Graph Resolution",
    desc: "Deterministic in-memory DAG traversal without network lag",
  },
  {
    icon: Layers,
    value: 44,
    suffix: "/44",
    label: "Test Suites Passing",
    desc: "Rigorous unit, security, correlator, and E2E coverage",
  },
  {
    icon: Activity,
    value: 0,
    suffix: "",
    label: "Telemetry Exfiltrations",
    desc: "Strictly air-gapped local execution and cryptographic hashing",
  },
];

export default function StatsStrip() {
  return (
    <section
      id="stats"
      style={{
        position: "relative",
        padding: "80px 24px",
        backgroundColor: "var(--bg-surface)",
        borderBottom: "1px solid var(--border-subtle)",
      }}
    >
      <div style={{ maxWidth: "1140px", margin: "0 auto" }}>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
            gap: "28px",
          }}
        >
          {STATS.map((stat) => {
            const Icon = stat.icon;
            return (
              <div
                key={stat.label}
                style={{
                  display: "flex",
                  flexDirection: "column",
                  padding: "24px",
                  borderRadius: "12px",
                  backgroundColor: "rgba(255, 255, 255, 0.02)",
                  border: "1px solid var(--border-subtle)",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "10px", color: "var(--accent-cyan)", marginBottom: "14px" }}>
                  <Icon size={18} />
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem", color: "var(--text-muted)" }}>
                    BENCHMARK
                  </span>
                </div>

                <div
                  style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: "2.5rem",
                    fontWeight: 800,
                    color: "#FFFFFF",
                    lineHeight: 1,
                    marginBottom: "8px",
                    display: "flex",
                    alignItems: "baseline",
                  }}
                >
                  <MetricTicker value={stat.value} duration={1.8} />
                  <span style={{ color: "var(--accent-cyan)", marginLeft: "4px" }}>{stat.suffix}</span>
                </div>

                <div style={{ fontSize: "1rem", fontWeight: 700, color: "#FFFFFF", marginBottom: "4px" }}>
                  {stat.label}
                </div>
                <div style={{ fontSize: "0.82rem", color: "var(--text-muted)", lineHeight: 1.5 }}>
                  {stat.desc}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
