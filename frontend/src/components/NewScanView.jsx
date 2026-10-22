import React, { useState, useRef } from "react";
import { 
  UploadCloud, 
  FileText, 
  CheckCircle2, 
  AlertCircle, 
  Play, 
  Loader2, 
  Sparkles, 
  Terminal,
  FileCode 
} from "lucide-react";
import { submitScan } from "../api";

const SAMPLE_VULNERABLE = `# Sample Python Requirements with Known Vulnerabilities
requests==2.25.0
jinja2==2.11.2
urllib3==1.26.4
fastapi
`;

export default function NewScanView({ onScanComplete }) {
  const [activeTab, setActiveTab] = useState("upload"); // 'upload' | 'text'
  const [file, setFile] = useState(null);
  const [rawText, setRawText] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [currentStage, setCurrentStage] = useState(0);
  const [errorMsg, setErrorMsg] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  
  const fileInputRef = useRef(null);

  const stages = [
    "Validating manifest syntax & package specifications",
    "Resolving direct & transitive dependencies via PyPI",
    "Generating CycloneDX v1.5 JSON SBOM & validating schema",
    "Executing vulnerability lookups against OSV & NVD databases",
    "Performing canonical advisory correlation & CVSS prioritization",
    "Persisting session to database & compiling audit report",
  ];

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    setErrorMsg(null);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const droppedFile = e.dataTransfer.files[0];
      if (!droppedFile.name.endsWith(".txt")) {
        setErrorMsg("Please upload a valid .txt file (e.g. requirements.txt)");
        return;
      }
      setFile(droppedFile);
    }
  };

  const handleFileChange = (e) => {
    setErrorMsg(null);
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
    }
  };

  const handleLoadPreset = () => {
    setActiveTab("text");
    setRawText(SAMPLE_VULNERABLE);
    setErrorMsg(null);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg(null);

    if (activeTab === "upload" && !file) {
      setErrorMsg("Please select or drop a requirements.txt file to begin scanning.");
      return;
    }
    if (activeTab === "text" && !rawText.trim()) {
      setErrorMsg("Please enter at least one Python dependency requirement.");
      return;
    }

    setIsScanning(true);
    setCurrentStage(0);

    // Progress interval reflecting the active pipeline
    const interval = setInterval(() => {
      setCurrentStage((prev) => {
        if (prev < stages.length - 1) return prev + 1;
        return prev;
      });
    }, 1800);

    try {
      const payload = activeTab === "upload" ? { file } : { rawContent: rawText };
      const res = await submitScan(payload);
      clearInterval(interval);
      setCurrentStage(stages.length);
      setTimeout(() => {
        setIsScanning(false);
        if (onScanComplete) {
          onScanComplete(res);
        }
      }, 500);
    } catch (err) {
      clearInterval(interval);
      setIsScanning(false);
      setErrorMsg(err.message || "An unexpected error occurred during scan execution.");
    }
  };

  return (
    <div style={{ maxWidth: "860px", margin: "0 auto" }}>
      <div className="page-header">
        <div>
          <h2 className="page-title">Initiate Dependency Security Scan</h2>
          <p className="page-subtitle">
            Upload your Python <code style={{ fontFamily: "var(--font-mono)", color: "var(--accent-cyan)" }}>requirements.txt</code> to generate an OWASP CycloneDX SBOM and discover correlated CVE/GHSA advisories.
          </p>
        </div>
      </div>

      {errorMsg && (
        <div style={{
          backgroundColor: "var(--sev-critical-bg)",
          border: "1px solid var(--sev-critical-border)",
          color: "var(--sev-critical)",
          borderRadius: "var(--radius-md)",
          padding: "14px 18px",
          display: "flex",
          alignItems: "center",
          gap: "10px",
          marginBottom: "20px",
          fontSize: "0.88rem"
        }}>
          <AlertCircle size={18} />
          <span>{errorMsg}</span>
        </div>
      )}

      <div className="card">
        {/* Tab switch */}
        <div style={{ display: "flex", gap: "10px", marginBottom: "20px", borderBottom: "1px solid var(--border-color)", paddingBottom: "14px" }}>
          <button
            type="button"
            className={`btn ${activeTab === "upload" ? "btn-primary" : "btn-secondary"}`}
            onClick={() => { setActiveTab("upload"); setErrorMsg(null); }}
          >
            <UploadCloud size={16} />
            <span>Upload Manifest File</span>
          </button>
          <button
            type="button"
            className={`btn ${activeTab === "text" ? "btn-primary" : "btn-secondary"}`}
            onClick={() => { setActiveTab("text"); setErrorMsg(null); }}
          >
            <FileCode size={16} />
            <span>Paste Requirements Text</span>
          </button>
        </div>

        {activeTab === "upload" ? (
          <div>
            <div
              className={`dropzone ${isDragging ? "active" : ""}`}
              onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <UploadCloud className="dropzone-icon" />
              <h3 style={{ fontSize: "1.05rem", fontWeight: 700, marginBottom: "6px", fontFamily: "var(--font-display)" }}>
                {file ? file.name : "Drag & Drop requirements.txt here"}
              </h3>
              <p style={{ fontSize: "0.84rem", color: "var(--text-muted)", marginBottom: "16px" }}>
                {file 
                  ? `${(file.size / 1024).toFixed(1)} KB · Click to change file` 
                  : "Supports Python pip requirements.txt format"}
              </p>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={(e) => { e.stopPropagation(); fileInputRef.current?.click(); }}
              >
                Choose File
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept=".txt"
                style={{ display: "none" }}
                onChange={handleFileChange}
              />
            </div>
          </div>
        ) : (
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
              <label style={{ fontSize: "0.82rem", fontWeight: 600, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                Paste requirements.txt Content
              </label>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={handleLoadPreset}
                style={{ fontSize: "0.75rem", padding: "4px 8px", color: "var(--accent-cyan)" }}
              >
                <Sparkles size={12} />
                <span>Load Vulnerable Preset (requests, jinja2, urllib3)</span>
              </button>
            </div>
            <textarea
              className="textarea"
              rows={8}
              placeholder="e.g.&#10;requests==2.25.0&#10;jinja2==2.11.2&#10;fastapi>=0.100.0"
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
            />
          </div>
        )}

        {/* Scanning Animated Terminal Stage Tracker */}
        {isScanning && (
          <div style={{
            marginTop: "24px",
            backgroundColor: "#05070A",
            borderRadius: "var(--radius-md)",
            border: "1px solid var(--border-medium)",
            boxShadow: "0 10px 30px rgba(0, 0, 0, 0.8)",
            overflow: "hidden"
          }}>
            {/* Terminal Topbar */}
            <div style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "10px 16px",
              backgroundColor: "rgba(255, 255, 255, 0.03)",
              borderBottom: "1px solid var(--border-color)",
              fontFamily: "var(--font-mono)",
              fontSize: "0.75rem"
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ width: "9px", height: "9px", borderRadius: "50%", backgroundColor: "#FF2E4D" }} />
                <span style={{ width: "9px", height: "9px", borderRadius: "50%", backgroundColor: "#FFB800" }} />
                <span style={{ width: "9px", height: "9px", borderRadius: "50%", backgroundColor: "#00FF88" }} />
                <span style={{ color: "var(--text-muted)", marginLeft: "8px" }}>scanner_pipeline_active.sh</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "var(--accent-cyan)" }}>
                <Terminal size={13} />
                <span>ACTIVE STAGE {currentStage + 1}/{stages.length}</span>
              </div>
            </div>

            {/* Stages Content */}
            <div style={{ padding: "20px" }}>
              <div className="stage-tracker">
                {stages.map((stageName, idx) => {
                  const isDone = idx < currentStage;
                  const isCurr = idx === currentStage;
                  return (
                    <div key={idx} className={`stage-step ${isDone ? "completed" : isCurr ? "active" : ""}`} style={{ fontFamily: "var(--font-mono)", fontSize: "0.82rem" }}>
                      <div className="step-circle">
                        {isDone ? "✓" : idx + 1}
                      </div>
                      <span style={{ color: isDone ? "#00FF88" : isCurr ? "var(--accent-cyan)" : "var(--text-muted)" }}>
                        {stageName}
                        {isCurr && " ..."}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* Action Button */}
        <div style={{ marginTop: "24px", display: "flex", justifyContent: "flex-end", gap: "12px" }}>
          <button
            className="btn btn-primary"
            onClick={handleSubmit}
            disabled={isScanning}
          >
            {isScanning ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                <span>Scanning Pipeline Active...</span>
              </>
            ) : (
              <>
                <Play size={16} />
                <span>Run SecureSBOM Scan</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
