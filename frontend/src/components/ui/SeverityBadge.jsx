import React from "react";

const SEVERITY_CONFIG = {
  CRITICAL: {
    label: "CRITICAL",
    bg: "rgba(255, 46, 77, 0.15)",
    border: "rgba(255, 46, 77, 0.5)",
    text: "#FF2E4D",
    glow: "0 0 10px rgba(255, 46, 77, 0.3)",
    dot: "#FF2E4D",
  },
  HIGH: {
    label: "HIGH",
    bg: "rgba(255, 107, 0, 0.15)",
    border: "rgba(255, 107, 0, 0.5)",
    text: "#FF6B00",
    glow: "0 0 10px rgba(255, 107, 0, 0.3)",
    dot: "#FF6B00",
  },
  MEDIUM: {
    label: "MEDIUM",
    bg: "rgba(255, 184, 0, 0.15)",
    border: "rgba(255, 184, 0, 0.5)",
    text: "#FFB800",
    glow: "0 0 10px rgba(255, 184, 0, 0.3)",
    dot: "#FFB800",
  },
  LOW: {
    label: "LOW",
    bg: "rgba(0, 180, 216, 0.15)",
    border: "rgba(0, 180, 216, 0.5)",
    text: "#00B4D8",
    glow: "0 0 10px rgba(0, 180, 216, 0.3)",
    dot: "#00B4D8",
  },
  INFORMATIONAL: {
    label: "INFO",
    bg: "rgba(100, 116, 139, 0.15)",
    border: "rgba(100, 116, 139, 0.4)",
    text: "#94A3B8",
    glow: "none",
    dot: "#94A3B8",
  },
  UNKNOWN: {
    label: "UNKNOWN",
    bg: "rgba(71, 85, 105, 0.15)",
    border: "rgba(71, 85, 105, 0.4)",
    text: "#64748B",
    glow: "none",
    dot: "#64748B",
  },
};

export default function SeverityBadge({ severity, score, showDot = true, size = "md" }) {
  const norm = (severity || "UNKNOWN").toUpperCase();
  const config = SEVERITY_CONFIG[norm] || SEVERITY_CONFIG.UNKNOWN;

  const sizeStyles = {
    sm: { padding: "2px 8px", fontSize: "0.70rem" },
    md: { padding: "4px 10px", fontSize: "0.76rem" },
    lg: { padding: "6px 14px", fontSize: "0.85rem" },
  }[size] || { padding: "4px 10px", fontSize: "0.76rem" };

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
        borderRadius: "9999px",
        fontFamily: "var(--font-mono)",
        fontWeight: 700,
        letterSpacing: "0.04em",
        backgroundColor: config.bg,
        border: `1px solid ${config.border}`,
        color: config.text,
        boxShadow: config.glow,
        ...sizeStyles,
      }}
    >
      {showDot && (
        <span
          style={{
            width: "6px",
            height: "6px",
            borderRadius: "50%",
            backgroundColor: config.dot,
            boxShadow: `0 0 6px ${config.dot}`,
          }}
        />
      )}
      <span>{config.label}</span>
      {score !== undefined && score !== null && (
        <span style={{ opacity: 0.8, fontSize: "0.85em", marginLeft: "2px" }}>
          {Number(score).toFixed(1)}
        </span>
      )}
    </span>
  );
}
