import React, { useState } from "react";
import { motion } from "framer-motion";
import { UploadCloud, Network, Database, FileCheck2, Terminal, CheckCircle2 } from "lucide-react";

const STEPS = [
  {
    step: "01",
    title: "Manifest Ingestion",
    icon: UploadCloud,
    badge: "INPUT LAYER",
    desc: "Feed requirements.txt, package.json, pom.xml, or CycloneDX SBOM manifests. SecureSBOM normalizes package purls across Python, Node, and Java ecosystems.",
    code: `// Parser recognizes ecosystem specs
const manifest = await parseManifest("requirements.txt");
// [
//   { name: "urllib3", version: "1.26.4", purl: "pkg:pypi/urllib3@1.26.4" },
//   { name: "cryptography", version: "41.0.0", purl: "pkg:pypi/cryptography@41.0.0" }
// ]`,
  },
  {
    step: "02",
    title: "Deterministic DAG Resolution",
    icon: Network,
    badge: "GRAPH ENGINE",
    desc: "Traverses depth levels to map parent-child relationships. Resolves transitive version pins and identifies unpinned floating dependencies.",
    code: `Graph Resolving depth: 3
├── requests@2.28.1
│   ├── urllib3@1.26.4  --> [TRAVERSAL DEPTH: 2]
│   └── certifi@2022.12.07
└── fastapi@0.104.1
    └── pydantic@2.4.2
DAG Verified: 14 nodes, 13 directed edges`,
  },
  {
    step: "03",
    title: "NVD & OSV Vulnerability Correlation",
    icon: Database,
    badge: "CORRELATION PIPELINE",
    desc: "Queries real-time CVE feeds, matching version ranges, CPE signatures, CVSS v3.1 vector metrics, and EPSS exploit probability scores.",
    code: `[MATCH] urllib3@1.26.4 matches CVE-2023-32681
- Severity: HIGH (CVSS 7.5)
- Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
- Fixed in: >= 1.26.18, >= 2.0.7
- Exploitable in wild: EPSS 0.041`,
  },
  {
    step: "04",
    title: "Standardized SBOM & Risk Report",
    icon: FileCheck2,
    badge: "DELIVERY",
    desc: "Generates cryptographic CycloneDX 1.4 & SPDX 2.3 standard output. Provides prioritised patch recommendations and actionable upgrade paths.",
    code: `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "serialNumber": "urn:uuid:7f3a-4e2b-88a1",
  "metadata": { "timestamp": "2026-10-21T18:00:00Z" },
  "vulnerabilities": [ { "id": "CVE-2023-32681", "affects": "urllib3" } ]
}`,
  },
];

export default function HowItWorksSection() {
  const [activeStep, setActiveStep] = useState(0);

  return (
    <section
      id="how-it-works"
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
            <span>ANALYSIS PIPELINE</span>
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
            How SecureSBOM Works
          </h2>
          <p
            style={{
              color: "var(--text-secondary)",
              fontSize: "1.05rem",
              maxWidth: "580px",
              margin: "12px auto 0 auto",
            }}
          >
            Four synchronized phases from raw manifest parsing to cryptographically signed bill of materials.
          </p>
        </div>

        {/* Interactive Steps Grid */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1.2fr",
            gap: "36px",
            alignItems: "center",
          }}
        >
          {/* Left: Step selectors */}
          <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            {STEPS.map((item, index) => {
              const Icon = item.icon;
              const isActive = activeStep === index;

              return (
                <div
                  key={item.step}
                  onClick={() => setActiveStep(index)}
                  className="glass-panel"
                  style={{
                    padding: "20px 24px",
                    cursor: "pointer",
                    borderColor: isActive ? "var(--accent-cyan)" : "var(--border-subtle)",
                    backgroundColor: isActive ? "rgba(0, 245, 255, 0.06)" : "rgba(11, 14, 20, 0.6)",
                    boxShadow: isActive ? "0 0 20px -4px var(--accent-cyan-glow)" : "none",
                    transition: "all 0.25s ease",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "8px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                      <span
                        style={{
                          fontFamily: "var(--font-mono)",
                          fontWeight: 700,
                          fontSize: "0.85rem",
                          color: isActive ? "var(--accent-cyan)" : "var(--text-muted)",
                        }}
                      >
                        {item.step}
                      </span>
                      <h3
                        style={{
                          margin: 0,
                          fontSize: "1.1rem",
                          fontWeight: 700,
                          color: isActive ? "#ffffff" : "var(--text-secondary)",
                          display: "flex",
                          alignItems: "center",
                          gap: "8px",
                        }}
                      >
                        <Icon size={18} color={isActive ? "var(--accent-cyan)" : "var(--text-muted)"} />
                        {item.title}
                      </h3>
                    </div>
                    <span
                      style={{
                        fontSize: "0.68rem",
                        fontFamily: "var(--font-mono)",
                        padding: "3px 8px",
                        borderRadius: "4px",
                        backgroundColor: isActive ? "rgba(0, 245, 255, 0.15)" : "rgba(255, 255, 255, 0.05)",
                        color: isActive ? "var(--accent-cyan)" : "var(--text-muted)",
                      }}
                    >
                      {item.badge}
                    </span>
                  </div>
                  <p style={{ margin: 0, fontSize: "0.88rem", color: "var(--text-muted)", lineHeight: 1.5 }}>
                    {item.desc}
                  </p>
                </div>
              );
            })}
          </div>

          {/* Right: Live Mock Terminal / Output Viewer */}
          <div
            className="glass-panel"
            style={{
              overflow: "hidden",
              border: "1px solid var(--border-medium)",
              background: "#080B10",
              boxShadow: "0 20px 50px rgba(0, 0, 0, 0.6)",
            }}
          >
            {/* Terminal Header */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "12px 18px",
                borderBottom: "1px solid var(--border-subtle)",
                backgroundColor: "rgba(5, 7, 10, 0.7)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ width: "10px", height: "10px", borderRadius: "50%", backgroundColor: "#FF2E4D" }} />
                <span style={{ width: "10px", height: "10px", borderRadius: "50%", backgroundColor: "#FFB800" }} />
                <span style={{ width: "10px", height: "10px", borderRadius: "50%", backgroundColor: "#00FF88" }} />
                <span style={{ fontSize: "0.78rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginLeft: "8px" }}>
                  pipeline_stage_{STEPS[activeStep].step}.log
                </span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "var(--accent-green)", fontSize: "0.75rem", fontFamily: "var(--font-mono)" }}>
                <CheckCircle2 size={13} />
                <span>STATE_OK</span>
              </div>
            </div>

            {/* Terminal Code Body */}
            <div style={{ padding: "24px", minHeight: "260px", overflowX: "auto" }}>
              <pre
                style={{
                  margin: 0,
                  fontFamily: "var(--font-mono)",
                  fontSize: "0.84rem",
                  color: "#E2E8F0",
                  lineHeight: 1.6,
                  whiteSpace: "pre-wrap",
                }}
              >
                {STEPS[activeStep].code}
              </pre>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
