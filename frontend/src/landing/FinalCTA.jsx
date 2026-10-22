import React from "react";
import { useNavigate } from "react-router-dom";
import { Terminal, ArrowRight, ShieldAlert, Heart } from "lucide-react";
import { motion } from "framer-motion";

export default function FinalCTA() {
  const navigate = useNavigate();

  return (
    <section
      id="cta"
      style={{
        position: "relative",
        padding: "140px 24px 60px 24px",
        backgroundColor: "var(--bg-abyss)",
        overflow: "hidden",
      }}
      className="bg-cyber-grid bg-cyber-radial"
    >
      <div style={{ maxWidth: "860px", margin: "0 auto", textAlign: "center", position: "relative", zIndex: 10 }}>
        {/* Glow backdrop */}
        <div
          style={{
            position: "absolute",
            top: "30%",
            left: "50%",
            transform: "translate(-50%, -50%)",
            width: "350px",
            height: "350px",
            background: "radial-gradient(circle, rgba(0, 245, 255, 0.15) 0%, transparent 70%)",
            filter: "blur(50px)",
            pointerEvents: "none",
            zIndex: -1,
          }}
        />

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
            marginBottom: "20px",
          }}
        >
          <Terminal size={14} />
          <span>ZERO SETUP REQUIRED</span>
        </div>

        <h2
          style={{
            fontFamily: "var(--font-display)",
            fontSize: "clamp(2.4rem, 5vw, 3.8rem)",
            fontWeight: 800,
            letterSpacing: "-0.03em",
            color: "#FFFFFF",
            lineHeight: 1.15,
            margin: "0 0 20px 0",
          }}
        >
          Secure Your Dependencies Today.
        </h2>

        <p
          style={{
            color: "var(--text-secondary)",
            fontSize: "1.15rem",
            lineHeight: 1.6,
            maxWidth: "600px",
            margin: "0 auto 36px auto",
          }}
        >
          Drop your dependency manifest and inspect your transitive supply chain attack surface in seconds.
        </p>

        {/* Magnetic CTA Button */}
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.98 }}
          onClick={() => navigate("/app")}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "12px",
            padding: "18px 36px",
            borderRadius: "12px",
            backgroundColor: "var(--accent-cyan)",
            color: "#05070A",
            border: "none",
            fontSize: "1.05rem",
            fontWeight: 800,
            fontFamily: "var(--font-mono)",
            cursor: "pointer",
            boxShadow: "0 0 35px var(--accent-cyan-glow)",
            transition: "box-shadow 0.25s ease",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.boxShadow = "0 0 50px rgba(0, 245, 255, 0.7)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.boxShadow = "0 0 35px var(--accent-cyan-glow)";
          }}
        >
          <Terminal size={20} />
          <span>Launch Scanner Console</span>
          <ArrowRight size={20} />
        </motion.button>

        {/* Minimal Footer */}
        <div
          style={{
            marginTop: "120px",
            paddingTop: "32px",
            borderTop: "1px solid var(--border-subtle)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: "16px",
            fontSize: "0.85rem",
            color: "var(--text-muted)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <div
              style={{
                width: "24px",
                height: "24px",
                borderRadius: "6px",
                background: "linear-gradient(135deg, #00F5FF, #2563EB)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#05070A",
              }}
            >
              <ShieldAlert size={14} />
            </div>
            <span style={{ fontFamily: "var(--font-display)", fontWeight: 700, color: "#fff" }}>
              SecureSBOM
            </span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--accent-cyan)" }}>
              PRJ_56
            </span>
          </div>

          <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem" }}>
            Deterministic Supply Chain Security Engine · NTIA & CycloneDX Compliant
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
            <a
              href="https://github.com"
              target="_blank"
              rel="noreferrer"
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                color: "var(--text-secondary)",
                textDecoration: "none",
                transition: "color 0.2s ease",
              }}
              onMouseEnter={(e) => (e.currentTarget.style.color = "#ffffff")}
              onMouseLeave={(e) => (e.currentTarget.style.color = "var(--text-secondary)")}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
              </svg>
              <span>GitHub</span>
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}
