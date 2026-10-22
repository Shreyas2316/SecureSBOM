import React, { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ShieldAlert, ArrowRight, Terminal } from "lucide-react";
import { motion, useScroll, useSpring } from "framer-motion";

export default function LandingNav() {
  const navigate = useNavigate();
  const { scrollY, scrollYProgress } = useScroll();
  const scaleX = useSpring(scrollYProgress, { stiffness: 200, damping: 25, restDelta: 0.001 });

  const [hidden, setHidden] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    let lastY = window.scrollY;
    const handleScroll = () => {
      const currentY = window.scrollY;
      setScrolled(currentY > 40);
      if (currentY > 120 && currentY > lastY) {
        setHidden(true);
      } else {
        setHidden(false);
      }
      lastY = currentY;
    };

    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const scrollToSection = (id) => {
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: "smooth" });
    }
  };

  return (
    <>
      {/* Top Scroll Progress Bar */}
      <motion.div
        style={{
          scaleX,
          transformOrigin: "0%",
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          height: "2px",
          backgroundColor: "var(--accent-cyan)",
          boxShadow: "0 0 10px var(--accent-cyan)",
          zIndex: 100,
        }}
      />

      {/* Sticky Translucent Navbar */}
      <motion.header
        variants={{
          visible: { y: 0, opacity: 1 },
          hidden: { y: -80, opacity: 0 },
        }}
        animate={hidden ? "hidden" : "visible"}
        transition={{ duration: 0.25, ease: "easeInOut" }}
        style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          zIndex: 90,
          padding: scrolled ? "14px 32px" : "22px 32px",
          backgroundColor: scrolled ? "rgba(5, 7, 10, 0.82)" : "transparent",
          backdropFilter: scrolled ? "blur(16px)" : "none",
          WebkitBackdropFilter: scrolled ? "blur(16px)" : "none",
          borderBottom: scrolled ? "1px solid var(--border-subtle)" : "1px solid transparent",
          transition: "padding 0.2s ease, background-color 0.2s ease, border-color 0.2s ease",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        {/* Brand Logo */}
        <Link
          to="/"
          style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
            textDecoration: "none",
            color: "#ffffff",
          }}
        >
          <div
            style={{
              width: "36px",
              height: "36px",
              borderRadius: "8px",
              background: "linear-gradient(135deg, #00F5FF, #2563EB)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: "#05070A",
              fontWeight: 800,
              boxShadow: "0 0 15px var(--accent-cyan-glow)",
            }}
          >
            <ShieldAlert size={20} />
          </div>
          <div style={{ display: "flex", flexDirection: "column" }}>
            <span style={{ fontFamily: "var(--font-display)", fontWeight: 800, fontSize: "1.1rem", letterSpacing: "-0.02em" }}>
              SecureSBOM
            </span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.68rem", color: "var(--accent-cyan)" }}>
              PRJ_56 · SUPPLY CHAIN DEFENSE
            </span>
          </div>
        </Link>

        {/* Anchors */}
        <nav style={{ display: "flex", alignItems: "center", gap: "28px" }}>
          <button
            onClick={() => scrollToSection("problem")}
            style={{ background: "none", border: "none", color: "var(--text-secondary)", fontSize: "0.88rem", fontWeight: 500, cursor: "pointer" }}
          >
            The Risk
          </button>
          <button
            onClick={() => scrollToSection("how-it-works")}
            style={{ background: "none", border: "none", color: "var(--text-secondary)", fontSize: "0.88rem", fontWeight: 500, cursor: "pointer" }}
          >
            How it works
          </button>
          <button
            onClick={() => scrollToSection("preview")}
            style={{ background: "none", border: "none", color: "var(--text-secondary)", fontSize: "0.88rem", fontWeight: 500, cursor: "pointer" }}
          >
            Live Preview
          </button>
          <button
            onClick={() => scrollToSection("features")}
            style={{ background: "none", border: "none", color: "var(--text-secondary)", fontSize: "0.88rem", fontWeight: 500, cursor: "pointer" }}
          >
            Features
          </button>
        </nav>

        {/* Action Button */}
        <div>
          <button
            onClick={() => navigate("/app")}
            className="btn-launch-scanner"
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              backgroundColor: "rgba(0, 245, 255, 0.1)",
              border: "1px solid var(--accent-cyan)",
              color: "var(--accent-cyan)",
              padding: "8px 16px",
              borderRadius: "8px",
              fontFamily: "var(--font-mono)",
              fontSize: "0.84rem",
              fontWeight: 700,
              cursor: "pointer",
              transition: "all 0.2s ease",
            }}
          >
            <Terminal size={14} />
            <span>Launch Scanner</span>
            <ArrowRight size={14} />
          </button>
        </div>
      </motion.header>
    </>
  );
}
