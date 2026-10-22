import React, { useEffect } from "react";
import Lenis from "lenis";
import LandingNav from "./LandingNav";
import HeroSection from "./HeroSection";
import ProblemSection from "./ProblemSection";
import HowItWorksSection from "./HowItWorksSection";
import LivePreviewSection from "./LivePreviewSection";
import FeaturesGrid from "./FeaturesGrid";
import StatsStrip from "./StatsStrip";
import FinalCTA from "./FinalCTA";

export default function LandingPage() {
  // Initialize Lenis smooth scroll
  useEffect(() => {
    // Check if user prefers reduced motion
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (prefersReducedMotion) return;

    const lenis = new Lenis({
      duration: 1.2,
      easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
      smoothWheel: true,
      wheelMultiplier: 1,
    });

    function raf(time) {
      lenis.raf(time);
      requestAnimationFrame(raf);
    }
    const reqId = requestAnimationFrame(raf);

    return () => {
      cancelAnimationFrame(reqId);
      lenis.destroy();
    };
  }, []);

  return (
    <div style={{ backgroundColor: "var(--bg-abyss)", minHeight: "100vh", color: "var(--text-primary)" }}>
      <LandingNav />
      <main>
        <HeroSection />
        <ProblemSection />
        <HowItWorksSection />
        <LivePreviewSection />
        <FeaturesGrid />
        <StatsStrip />
        <FinalCTA />
      </main>
    </div>
  );
}
