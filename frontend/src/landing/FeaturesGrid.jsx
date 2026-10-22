import React from "react";
import { motion } from "framer-motion";
import { Network, FileCode, Database, RefreshCw, Lock, Terminal, ShieldAlert, Cpu } from "lucide-react";
import GlassCard from "../components/ui/GlassCard";

const FEATURES = [
  {
    icon: Network,
    title: "Full-Depth Graph Engine",
    desc: "Unrolls direct manifests into complete multi-tiered dependency trees. Handles circular references and diamond dependency conflicts gracefully.",
    badge: "DAG RESOLUTION",
  },
  {
    icon: FileCode,
    title: "CycloneDX & SPDX Standards",
    desc: "Produces NTIA-compliant Software Bills of Materials in CycloneDX 1.4 JSON and SPDX 2.3 tags, ready for regulatory audits.",
    badge: "STANDARDS COMPLIANT",
  },
  {
    icon: Database,
    title: "Real-Time NVD & OSV Matching",
    desc: "Correlates package versions against the National Vulnerability Database and OSV feeds with CVSS v3.1 vector metric parsing.",
    badge: "THREAT INTELLIGENCE",
  },
  {
    icon: RefreshCw,
    title: "Surgical Remediation Paths",
    desc: "Calculates the least-breaking upgrade version for parent packages to eliminate transitive child vulnerabilities.",
    badge: "AUTO-TRIAGE",
  },
  {
    icon: Lock,
    title: "Zero-Telemetry Architecture",
    desc: "Your source code and manifests never leave your infrastructure. Local deterministic hashing ensures strict privacy compliance.",
    badge: "AIR-GAPPED READY",
  },
  {
    icon: Terminal,
    title: "CLI & CI/CD Pipeline Gates",
    desc: "Return strict non-zero exit codes when vulnerabilities exceed CVSS thresholds to halt deployment pipelines before release.",
    badge: "DEVOPS AUTOMATION",
  },
];

export default function FeaturesGrid() {
  return (
    <section
      id="features"
      style={{
        position: "relative",
        padding: "120px 24px",
        backgroundColor: "var(--bg-abyss)",
        borderBottom: "1px solid var(--border-subtle)",
      }}
    >
      <div style={{ maxWidth: "1140px", margin: "0 auto" }}>
        {/* Section Header */}
        <div style={{ textAlign: "center", marginBottom: "64px" }}>
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "8px",
              padding: "6px 14px",
              borderRadius: "999px",
              backgroundColor: "rgba(0, 245, 255, 0.08)",
              border: "1px solid rgba(0, 245, 255, 0.3)",
              fontSize: "0.78rem",
              fontFamily: "var(--font-mono)",
              color: "var(--accent-cyan)",
              marginBottom: "16px",
            }}
          >
            <Cpu size={14} />
            <span>CORE CAPABILITIES</span>
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
            Engineered for High-Assurance Supply Chains
          </h2>
          <p
            style={{
              color: "var(--text-secondary)",
              fontSize: "1.05rem",
              maxWidth: "600px",
              margin: "12px auto 0 auto",
            }}
          >
            Built from the ground up to protect enterprise software pipelines against silent transitive dependency compromise.
          </p>
        </div>

        {/* Feature Cards Grid */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
            gap: "24px",
          }}
        >
          {FEATURES.map((feat, index) => {
            const Icon = feat.icon;
            return (
              <GlassCard
                key={feat.title}
                hoverGlow={true}
                style={{
                  padding: "32px",
                  display: "flex",
                  flexDirection: "column",
                  justifyContent: "space-between",
                }}
              >
                <div>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "20px" }}>
                    <div
                      style={{
                        width: "44px",
                        height: "44px",
                        borderRadius: "10px",
                        backgroundColor: "rgba(0, 245, 255, 0.08)",
                        border: "1px solid rgba(0, 245, 255, 0.25)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        color: "var(--accent-cyan)",
                      }}
                    >
                      <Icon size={22} />
                    </div>
                    <span
                      style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: "0.7rem",
                        padding: "3px 8px",
                        borderRadius: "4px",
                        backgroundColor: "rgba(255, 255, 255, 0.04)",
                        color: "var(--text-muted)",
                      }}
                    >
                      {feat.badge}
                    </span>
                  </div>

                  <h3
                    style={{
                      fontFamily: "var(--font-display)",
                      fontSize: "1.22rem",
                      fontWeight: 700,
                      color: "#FFFFFF",
                      margin: "0 0 10px 0",
                    }}
                  >
                    {feat.title}
                  </h3>

                  <p
                    style={{
                      fontSize: "0.92rem",
                      color: "var(--text-secondary)",
                      lineHeight: 1.6,
                      margin: 0,
                    }}
                  >
                    {feat.desc}
                  </p>
                </div>
              </GlassCard>
            );
          })}
        </div>
      </div>
    </section>
  );
}
