import React, { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRight, ShieldCheck, Terminal, Cpu, ChevronDown } from "lucide-react";
import { motion } from "framer-motion";

export default function HeroSection() {
  const navigate = useNavigate();
  const canvasRef = useRef(null);

  // Canvas Dependency Tree Animation with Vulnerability Propagation
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    let animationFrameId;

    let width = (canvas.width = canvas.parentElement.offsetWidth);
    let height = (canvas.height = canvas.parentElement.offsetHeight);

    const handleResize = () => {
      if (!canvas.parentElement) return;
      width = canvas.width = canvas.parentElement.offsetWidth;
      height = canvas.height = canvas.parentElement.offsetHeight;
      initNodes();
    };
    window.addEventListener("resize", handleResize);

    // Nodes structure
    let nodes = [];
    let edges = [];

    const initNodes = () => {
      const cx = width / 2;
      const cy = height * 0.46;
      nodes = [
        // Root node
        { id: "root", label: "App Root", x: cx, y: cy - 120, r: 14, color: "#00F5FF", isRoot: true },
        // Direct dependencies
        { id: "d1", label: "requests v2.28", x: cx - 180, y: cy - 30, r: 10, color: "#94A3B8" },
        { id: "d2", label: "fastapi v0.104", x: cx - 60, y: cy - 40, r: 10, color: "#94A3B8" },
        { id: "d3", label: "cryptography v41", x: cx + 70, y: cy - 35, r: 10, color: "#94A3B8" },
        { id: "d4", label: "celery v5.3", x: cx + 190, y: cy - 25, r: 10, color: "#94A3B8" },
        // Transitive dependencies (depth 2)
        { id: "t1", label: "urllib3 v1.26.4", x: cx - 240, y: cy + 60, r: 8, color: "#64748B" },
        { id: "t2", label: "certifi v2022", x: cx - 160, y: cy + 70, r: 8, color: "#64748B" },
        { id: "t3", label: "pydantic-core", x: cx - 80, y: cy + 85, r: 8, color: "#64748B" },
        { id: "t4", label: "cffi v1.15.1", x: cx + 30, y: cy + 80, r: 8, color: "#64748B" },
        { id: "t5", label: "openssl-shim", x: cx + 110, y: cy + 75, r: 8, color: "#64748B" },
        { id: "t6", label: "kombu v5.3", x: cx + 180, y: cy + 85, r: 8, color: "#64748B" },
        { id: "t7", label: "billiard v4.1", x: cx + 250, y: cy + 65, r: 8, color: "#64748B" },
        // Transitive leaf (depth 3 - The vulnerable node)
        { id: "vuln", label: "CVE-2023-32681", x: cx - 270, y: cy + 150, r: 11, color: "#FF2E4D", isVuln: true },
        { id: "t8", label: "pycparser v2.21", x: cx + 35, y: cy + 145, r: 7, color: "#64748B" },
        { id: "t9", label: "amqp v5.1", x: cx + 180, y: cy + 150, r: 7, color: "#64748B" },
      ];

      edges = [
        { from: "root", to: "d1" },
        { from: "root", to: "d2" },
        { from: "root", to: "d3" },
        { from: "root", to: "d4" },
        { from: "d1", to: "t1" },
        { from: "d1", to: "t2" },
        { from: "d2", to: "t3" },
        { from: "d3", to: "t4" },
        { from: "d3", to: "t5" },
        { from: "d4", to: "t6" },
        { from: "d4", to: "t7" },
        { from: "t1", to: "vuln" },
        { from: "t4", to: "t8" },
        { from: "t6", to: "t9" },
      ];
    };

    initNodes();

    let step = 0;
    const compromisedPath = ["vuln", "t1", "d1", "root"];

    const render = () => {
      step += 0.02;
      ctx.clearRect(0, 0, width, height);

      // Traversal pulse timing: 0 -> 1 -> 2 -> 3
      const cycle = (step % 5); // 0 to 5 seconds loop

      // Draw Edges
      edges.forEach((edge) => {
        const source = nodes.find((n) => n.id === edge.from);
        const target = nodes.find((n) => n.id === edge.to);
        if (!source || !target) return;

        const isCompromisedEdge =
          (edge.from === "t1" && edge.to === "vuln") ||
          (edge.from === "d1" && edge.to === "t1") ||
          (edge.from === "root" && edge.to === "d1");

        ctx.beginPath();
        ctx.moveTo(source.x, source.y);
        ctx.lineTo(target.x, target.y);

        if (isCompromisedEdge && cycle > 1.2) {
          // Compromised glowing red edge
          ctx.strokeStyle = "rgba(255, 46, 77, 0.75)";
          ctx.lineWidth = 2.5;
          ctx.shadowColor = "#FF2E4D";
          ctx.shadowBlur = 8;
        } else {
          ctx.strokeStyle = "rgba(255, 255, 255, 0.12)";
          ctx.lineWidth = 1;
          ctx.shadowBlur = 0;
        }
        ctx.stroke();
        ctx.shadowBlur = 0;
      });

      // Draw Propagation Wave Particle along compromised path
      if (cycle > 0.8 && cycle < 3.8) {
        const progress = (cycle - 0.8) / 3.0; // 0 to 1
        // Path: vuln (0) -> t1 (0.33) -> d1 (0.66) -> root (1.0)
        let px, py;
        const nVuln = nodes.find((n) => n.id === "vuln");
        const nT1 = nodes.find((n) => n.id === "t1");
        const nD1 = nodes.find((n) => n.id === "d1");
        const nRoot = nodes.find((n) => n.id === "root");

        if (progress < 0.33) {
          const t = progress / 0.33;
          px = nVuln.x + (nT1.x - nVuln.x) * t;
          py = nVuln.y + (nT1.y - nVuln.y) * t;
        } else if (progress < 0.66) {
          const t = (progress - 0.33) / 0.33;
          px = nT1.x + (nD1.x - nT1.x) * t;
          py = nT1.y + (nD1.y - nT1.y) * t;
        } else {
          const t = (progress - 0.66) / 0.34;
          px = nD1.x + (nRoot.x - nD1.x) * t;
          py = nD1.y + (nRoot.y - nD1.y) * t;
        }

        ctx.beginPath();
        ctx.arc(px, py, 5, 0, Math.PI * 2);
        ctx.fillStyle = "#FF2E4D";
        ctx.shadowColor = "#FF2E4D";
        ctx.shadowBlur = 15;
        ctx.fill();
        ctx.shadowBlur = 0;
      }

      // Draw Nodes
      nodes.forEach((node) => {
        const isCompromised = compromisedPath.includes(node.id) && cycle > 1.2;
        const nodeColor = isCompromised ? "#FF2E4D" : node.color;

        // Outer glow
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.r + 4, 0, Math.PI * 2);
        ctx.fillStyle = isCompromised
          ? "rgba(255, 46, 77, 0.22)"
          : node.isRoot
          ? "rgba(0, 245, 255, 0.2)"
          : "rgba(255, 255, 255, 0.03)";
        ctx.fill();

        // Node circle
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
        ctx.fillStyle = "#0B0E14";
        ctx.strokeStyle = nodeColor;
        ctx.lineWidth = node.isVuln || node.isRoot ? 2.5 : 1.5;
        ctx.stroke();
        ctx.fill();

        // Inner core
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.r * 0.45, 0, Math.PI * 2);
        ctx.fillStyle = nodeColor;
        ctx.fill();

        // Label
        ctx.font = "10px 'JetBrains Mono', monospace";
        ctx.fillStyle = isCompromised ? "#FF8DA1" : "#94A3B8";
        ctx.textAlign = "center";
        ctx.fillText(node.label, node.x, node.y + node.r + 14);
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("resize", handleResize);
    };
  }, []);

  return (
    <section
      id="hero"
      style={{
        position: "relative",
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "120px 24px 60px 24px",
        overflow: "hidden",
      }}
      className="bg-cyber-grid bg-cyber-radial"
    >
      {/* Background canvas for dependency propagation */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          opacity: 0.85,
          pointerEvents: "none",
          zIndex: 1,
        }}
      >
        <canvas ref={canvasRef} style={{ width: "100%", height: "100%" }} />
      </div>

      {/* Hero Content Overlay */}
      <div
        style={{
          position: "relative",
          zIndex: 10,
          maxWidth: "880px",
          textAlign: "center",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: "24px",
          marginTop: "-40px",
        }}
      >
        {/* Release / Status Pill */}
        <motion.div
          initial={{ opacity: 0, y: -16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.1 }}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "8px",
            padding: "6px 14px",
            borderRadius: "999px",
            backgroundColor: "rgba(0, 245, 255, 0.08)",
            border: "1px solid rgba(0, 245, 255, 0.35)",
            fontSize: "0.78rem",
            fontFamily: "var(--font-mono)",
            color: "var(--accent-cyan)",
            backdropFilter: "blur(8px)",
          }}
        >
          <span style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: "#00FF88", boxShadow: "0 0 8px #00FF88" }} />
          <span>CYBER SUPPLY CHAIN ENGINE · PRJ_56 ACTIVE</span>
        </motion.div>

        {/* Cinematic Headline */}
        <motion.h1
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          style={{
            fontFamily: "var(--font-display)",
            fontSize: "clamp(2.5rem, 5.5vw, 4.2rem)",
            fontWeight: 800,
            lineHeight: 1.08,
            letterSpacing: "-0.035em",
            color: "#FFFFFF",
            margin: 0,
            textShadow: "0 4px 30px rgba(0, 0, 0, 0.7)",
          }}
        >
          Every Transitive Dependency is an{" "}
          <span
            style={{
              background: "linear-gradient(135deg, #00F5FF 0%, #3B82F6 50%, #FF2E4D 100%)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
            }}
          >
            Attack Surface.
          </span>
        </motion.h1>

        {/* Subtitle */}
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.3 }}
          style={{
            fontSize: "clamp(1.05rem, 1.8vw, 1.25rem)",
            color: "var(--text-secondary)",
            lineHeight: 1.6,
            maxWidth: "680px",
            margin: 0,
          }}
        >
          Generate deterministic Software Bills of Materials (SBOM), resolve full-depth dependency graphs, and detect latent CVEs before your release artifacts ship.
        </motion.p>

        {/* Action Buttons */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.4 }}
          style={{
            display: "flex",
            alignItems: "center",
            gap: "16px",
            flexWrap: "wrap",
            justifyContent: "center",
            marginTop: "12px",
          }}
        >
          <button
            onClick={() => navigate("/app")}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
              padding: "14px 28px",
              borderRadius: "10px",
              backgroundColor: "var(--accent-cyan)",
              color: "#05070A",
              border: "none",
              fontSize: "0.95rem",
              fontWeight: 700,
              fontFamily: "var(--font-mono)",
              cursor: "pointer",
              boxShadow: "0 0 25px var(--accent-cyan-glow)",
              transition: "transform 0.2s ease, box-shadow 0.2s ease",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = "translateY(-2px)";
              e.currentTarget.style.boxShadow = "0 0 35px rgba(0, 245, 255, 0.6)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = "translateY(0)";
              e.currentTarget.style.boxShadow = "0 0 25px var(--accent-cyan-glow)";
            }}
          >
            <Terminal size={18} />
            <span>Launch Scanner</span>
            <ArrowRight size={18} />
          </button>

          <button
            onClick={() => {
              document.getElementById("problem")?.scrollIntoView({ behavior: "smooth" });
            }}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              padding: "14px 24px",
              borderRadius: "10px",
              backgroundColor: "rgba(255, 255, 255, 0.05)",
              color: "var(--text-primary)",
              border: "1px solid var(--border-medium)",
              fontSize: "0.95rem",
              fontWeight: 600,
              cursor: "pointer",
              backdropFilter: "blur(10px)",
              transition: "all 0.2s ease",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = "var(--accent-cyan)";
              e.currentTarget.style.backgroundColor = "rgba(0, 245, 255, 0.08)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = "var(--border-medium)";
              e.currentTarget.style.backgroundColor = "rgba(255, 255, 255, 0.05)";
            }}
          >
            <span>See The Threat Vector</span>
            <ChevronDown size={16} />
          </button>
        </motion.div>

        {/* Feature Highlights Ticker */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.55 }}
          style={{
            display: "flex",
            alignItems: "center",
            gap: "28px",
            fontSize: "0.82rem",
            color: "var(--text-muted)",
            fontFamily: "var(--font-mono)",
            marginTop: "16px",
          }}
        >
          <span style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <Cpu size={14} color="var(--accent-cyan)" /> CycloneDX & SPDX
          </span>
          <span>•</span>
          <span style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <ShieldCheck size={14} color="#00FF88" /> Zero-Telemetry Engine
          </span>
          <span>•</span>
          <span>NVD CVE & EPSS Correlation</span>
        </motion.div>
      </div>
    </section>
  );
}
