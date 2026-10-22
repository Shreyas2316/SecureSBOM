import React, { useRef } from "react";
import { motion, useScroll, useTransform } from "framer-motion";
import { AlertTriangle, Layers, GitBranch, ShieldX, EyeOff } from "lucide-react";

export default function ProblemSection() {
  const containerRef = useRef(null);
  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ["start end", "end start"],
  });

  const packageCount = useTransform(scrollYProgress, [0.15, 0.55], [4, 1284]);
  const formattedCount = useTransform(packageCount, (v) => Math.round(v).toLocaleString());

  const directLines = useTransform(scrollYProgress, [0.15, 0.55], [350, 480000]);
  const formattedLines = useTransform(directLines, (v) => Math.round(v).toLocaleString());

  return (
    <section
      id="problem"
      ref={containerRef}
      style={{
        position: "relative",
        minHeight: "100vh",
        backgroundColor: "var(--bg-surface)",
        padding: "120px 24px",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        borderTop: "1px solid var(--border-subtle)",
        borderBottom: "1px solid var(--border-subtle)",
      }}
    >
      <div style={{ maxWidth: "1140px", width: "100%", margin: "0 auto" }}>
        {/* Section Header Tag */}
        <div style={{ textAlign: "center", marginBottom: "48px" }}>
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "8px",
              padding: "6px 14px",
              borderRadius: "999px",
              backgroundColor: "rgba(255, 46, 77, 0.1)",
              border: "1px solid rgba(255, 46, 77, 0.3)",
              fontSize: "0.78rem",
              fontFamily: "var(--font-mono)",
              color: "var(--sev-critical)",
              marginBottom: "16px",
            }}
          >
            <AlertTriangle size={14} />
            <span>THE SOFTWARE SUPPLY CHAIN DILEMMA</span>
          </div>

          <h2
            style={{
              fontFamily: "var(--font-display)",
              fontSize: "clamp(2rem, 4vw, 3.2rem)",
              fontWeight: 800,
              lineHeight: 1.15,
              letterSpacing: "-0.03em",
              color: "#FFFFFF",
              margin: 0,
            }}
          >
            You Ship Code <span style={{ color: "var(--sev-critical)" }}>You Never Wrote.</span>
          </h2>
          <p
            style={{
              color: "var(--text-secondary)",
              fontSize: "1.1rem",
              maxWidth: "640px",
              margin: "16px auto 0 auto",
              lineHeight: 1.6,
            }}
          >
            Your manifest imports 4 direct libraries. Under the surface, package managers resolve hundreds of unvetted nested dependencies deep in the tree.
          </p>
        </div>

        {/* Transitive Explosion Counter Card */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
            gap: "24px",
            marginBottom: "48px",
          }}
        >
          {/* Card 1: Direct vs Transitive */}
          <div
            className="glass-panel"
            style={{
              padding: "36px",
              display: "flex",
              flexDirection: "column",
              justifyContent: "space-between",
              background: "linear-gradient(180deg, rgba(17, 22, 34, 0.7) 0%, rgba(11, 14, 20, 0.95) 100%)",
            }}
          >
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", color: "var(--accent-cyan)", marginBottom: "16px" }}>
                <Layers size={20} />
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                  Transitive Explosion
                </span>
              </div>
              <p style={{ color: "var(--text-muted)", fontSize: "0.92rem", lineHeight: 1.5 }}>
                Scroll down to witness how your dependency surface compounds across transitive graph resolution:
              </p>
            </div>

            <div style={{ marginTop: "32px" }}>
              <div style={{ display: "flex", alignItems: "baseline", gap: "12px" }}>
                <motion.span
                  style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: "clamp(3rem, 6vw, 4.5rem)",
                    fontWeight: 800,
                    color: "var(--sev-critical)",
                    lineHeight: 1,
                  }}
                >
                  {formattedCount}
                </motion.span>
                <span style={{ fontFamily: "var(--font-mono)", color: "var(--text-secondary)", fontSize: "1.1rem" }}>
                  packages loaded
                </span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "12px", marginTop: "12px", fontSize: "0.86rem", color: "var(--text-muted)" }}>
                <span>Across 11 dependency layers</span>
                <span>•</span>
                <span><motion.span>{formattedLines}</motion.span> lines of 3rd party code</span>
              </div>
            </div>
          </div>

          {/* Card 2: Iceberg breakdown */}
          <div
            className="glass-panel"
            style={{
              padding: "36px",
              display: "flex",
              flexDirection: "column",
              justifyContent: "space-between",
              background: "linear-gradient(180deg, rgba(17, 22, 34, 0.7) 0%, rgba(11, 14, 20, 0.95) 100%)",
            }}
          >
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", color: "var(--sev-high)", marginBottom: "16px" }}>
                <EyeOff size={20} />
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                  The 85% Blindspot
                </span>
              </div>

              {/* Graphical Bar */}
              <div style={{ marginTop: "16px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.82rem", marginBottom: "8px", fontFamily: "var(--font-mono)" }}>
                  <span style={{ color: "var(--accent-cyan)" }}>Direct Manifest (15%)</span>
                  <span style={{ color: "var(--sev-critical)" }}>Transitive Dep Tree (85%)</span>
                </div>
                <div style={{ width: "100%", height: "14px", backgroundColor: "rgba(255,255,255,0.06)", borderRadius: "6px", overflow: "hidden", display: "flex" }}>
                  <div style={{ width: "15%", backgroundColor: "var(--accent-cyan)", boxShadow: "0 0 10px var(--accent-cyan-glow)" }} />
                  <div style={{ width: "85%", backgroundColor: "var(--sev-critical)", boxShadow: "0 0 10px var(--sev-critical-glow)" }} />
                </div>
              </div>

              <div style={{ marginTop: "28px", display: "flex", flexDirection: "column", gap: "14px" }}>
                <div style={{ display: "flex", alignItems: "flex-start", gap: "12px" }}>
                  <div style={{ padding: "6px", borderRadius: "6px", backgroundColor: "rgba(255, 46, 77, 0.15)", color: "var(--sev-critical)" }}>
                    <ShieldX size={16} />
                  </div>
                  <div>
                    <div style={{ fontSize: "0.92rem", fontWeight: 600, color: "#fff" }}>Unreviewed Maintainer Commits</div>
                    <div style={{ fontSize: "0.82rem", color: "var(--text-muted)" }}>A rogue PR on a 5-tier nested dependency can execute arbitrary code inside your CI runner.</div>
                  </div>
                </div>

                <div style={{ display: "flex", alignItems: "flex-start", gap: "12px" }}>
                  <div style={{ padding: "6px", borderRadius: "6px", backgroundColor: "rgba(0, 245, 255, 0.15)", color: "var(--accent-cyan)" }}>
                    <GitBranch size={16} />
                  </div>
                  <div>
                    <div style={{ fontSize: "0.92rem", fontWeight: 600, color: "#fff" }}>Zero SBOM Visibility</div>
                    <div style={{ fontSize: "0.82rem", color: "var(--text-muted)" }}>Without machine-readable CycloneDX / SPDX metadata, audits miss transient vulnerabilities.</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
