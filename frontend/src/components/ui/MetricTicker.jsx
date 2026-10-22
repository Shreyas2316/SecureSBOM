import React, { useEffect, useState } from "react";
import { useMotionValue, useSpring } from "framer-motion";

export default function MetricTicker({ value = 0, duration = 1.2, prefix = "", suffix = "" }) {
  const numericVal = typeof value === "number" ? value : parseInt(value, 10) || 0;
  const motionVal = useMotionValue(0);
  const springVal = useSpring(motionVal, {
    duration: duration * 1000,
    bounce: 0,
  });

  const [displayVal, setDisplayVal] = useState("0");

  useEffect(() => {
    motionVal.set(numericVal);
  }, [numericVal, motionVal]);

  useEffect(() => {
    const unsubscribe = springVal.on("change", (latest) => {
      setDisplayVal(Math.round(latest).toLocaleString());
    });
    return () => unsubscribe();
  }, [springVal]);

  return (
    <span style={{ fontFamily: "var(--font-display)", fontVariantNumeric: "tabular-nums" }}>
      {prefix}
      {displayVal}
      {suffix}
    </span>
  );
}
