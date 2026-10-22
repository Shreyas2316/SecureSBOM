import React from "react";
import { motion } from "framer-motion";

export default function GlassCard({
  children,
  className = "",
  glow = false,
  hoverGlow = true,
  onClick,
  style = {},
  ...props
}) {
  return (
    <motion.div
      onClick={onClick}
      className={`glass-panel ${hoverGlow ? "glass-panel-glow" : ""} ${className}`}
      style={{
        padding: "24px",
        boxShadow: glow ? "0 0 30px -5px var(--accent-cyan-glow)" : "none",
        ...style,
      }}
      whileHover={hoverGlow ? { y: -2, transition: { duration: 0.2 } } : undefined}
      {...props}
    >
      {children}
    </motion.div>
  );
}
