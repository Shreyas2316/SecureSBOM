import React, { useState, useMemo } from "react";
import { 
  Boxes, 
  Search, 
  Download, 
  CheckCircle, 
  AlertCircle, 
  Copy, 
  CornerDownRight,
  GitBranch,
  List
} from "lucide-react";
import { getDownloadBomUrl, downloadFileAsJson } from "../api";

export default function DependencyInventoryView({ scanData, onNavigate }) {
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("ALL"); // 'ALL' | 'DIRECT' | 'TRANSITIVE'
  const [viewMode, setViewMode] = useState("table"); // 'table' | 'tree'
  const [copiedPurl, setCopiedPurl] = useState(null);

  const report = scanData?.report || scanData;
  if (!report) {
    return (
      <div className="card" style={{ textAlign: "center", padding: "64px" }}>
        <p style={{ color: "var(--text-muted)", marginBottom: "16px" }}>No dependency inventory available.</p>
        <button className="btn btn-primary" onClick={() => onNavigate("new_scan")}>
          Initiate Scan
        </button>
      </div>
    );
  }

  const scanId = report.scan_id || scanData?.scan_id || "";
  const dependencies = report.dependencies || [];
  const packageVulns = report.vulnerabilities || [];

  // Map package vulnerabilities
  const vulnCountsByPkg = useMemo(() => {
    const map = {};
    for (const pv of packageVulns) {
      map[pv.package_name] = (pv.vulnerabilities || []).length;
    }
    for (const cv of report.canonical_vulnerabilities || []) {
      for (const ap of cv.affected_packages || []) {
        if (ap.package_name) {
          map[ap.package_name] = (map[ap.package_name] || 0) + 1;
        }
      }
    }
    return map;
  }, [packageVulns, report]);

  const filteredDeps = useMemo(() => {
    return dependencies.filter((dep) => {
      if (typeFilter === "DIRECT" && !dep.is_direct) return false;
      if (typeFilter === "TRANSITIVE" && dep.is_direct) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return dep.name.toLowerCase().includes(q) || dep.purl?.toLowerCase().includes(q);
      }
      return true;
    });
  }, [dependencies, typeFilter, searchQuery]);

  const handleCopyPurl = (purl) => {
    navigator.clipboard.writeText(purl);
    setCopiedPurl(purl);
    setTimeout(() => setCopiedPurl(null), 2000);
  };

  const directDeps = dependencies.filter((d) => d.is_direct);

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">Dependency Inventory & Component Bill of Materials</h2>
          <p className="page-subtitle">
            All direct and resolved transitive libraries embedded in CycloneDX v1.5 JSON SBOM.
          </p>
        </div>
        <div style={{ display: "flex", gap: "10px" }}>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => downloadFileAsJson(getDownloadBomUrl(scanId), `cyclonedx-bom-${scanId ? scanId.slice(0, 8) : "latest"}.json`)}
          >
            <Download size={16} />
            <span>Export CycloneDX SBOM</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="card" style={{ padding: "16px 20px" }}>
        <div style={{ display: "flex", gap: "14px", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: "260px", position: "relative" }}>
            <Search size={16} style={{ position: "absolute", left: "12px", top: "11px", color: "var(--text-muted)" }} />
            <input
              type="text"
              className="input-text"
              style={{ paddingLeft: "36px" }}
              placeholder="Search components by package name or PURL..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div style={{ display: "flex", gap: "14px", alignItems: "center" }}>
            {/* View Mode Toggle */}
            <div style={{ display: "flex", backgroundColor: "rgba(255, 255, 255, 0.04)", borderRadius: "var(--radius-md)", padding: "2px", border: "1px solid var(--border-color)" }}>
              <button
                className={`btn btn-sm ${viewMode === "table" ? "btn-primary" : "btn-secondary"}`}
                style={{ border: "none", padding: "4px 10px", fontSize: "0.78rem" }}
                onClick={() => setViewMode("table")}
              >
                <List size={14} />
                <span>Table</span>
              </button>
              <button
                className={`btn btn-sm ${viewMode === "tree" ? "btn-primary" : "btn-secondary"}`}
                style={{ border: "none", padding: "4px 10px", fontSize: "0.78rem" }}
                onClick={() => setViewMode("tree")}
              >
                <GitBranch size={14} />
                <span>Tree</span>
              </button>
            </div>

            {/* Type Filters */}
            <div style={{ display: "flex", gap: "6px" }}>
              <button
                className={`btn btn-sm ${typeFilter === "ALL" ? "btn-primary" : "btn-secondary"}`}
                onClick={() => setTypeFilter("ALL")}
              >
                All ({dependencies.length})
              </button>
              <button
                className={`btn btn-sm ${typeFilter === "DIRECT" ? "btn-primary" : "btn-secondary"}`}
                onClick={() => setTypeFilter("DIRECT")}
              >
                Direct ({dependencies.filter((d) => d.is_direct).length})
              </button>
              <button
                className={`btn btn-sm ${typeFilter === "TRANSITIVE" ? "btn-primary" : "btn-secondary"}`}
                onClick={() => setTypeFilter("TRANSITIVE")}
              >
                Transitive ({dependencies.filter((d) => !d.is_direct).length})
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Component Table or Tree */}
      {viewMode === "table" ? (
        <div className="card">
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Component Name</th>
                  <th>Type</th>
                  <th>Declared Specifier</th>
                  <th>Resolved Version</th>
                  <th>Package URL (PURL)</th>
                  <th>Vulnerabilities</th>
                  <th>SBOM Inclusion</th>
                </tr>
              </thead>
              <tbody>
                {filteredDeps.map((dep) => {
                  const vulnCount = vulnCountsByPkg[dep.name] || 0;
                  return (
                    <tr key={dep.purl || dep.name}>
                      <td>
                        <div>
                          <span style={{ fontWeight: 700, fontSize: "0.9rem" }}>{dep.name}</span>
                          {dep.transitive_dependencies && dep.transitive_dependencies.length > 0 && (
                            <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: "3px", display: "flex", alignItems: "center", gap: "4px" }}>
                              <CornerDownRight size={11} />
                              <span>Requires: {dep.transitive_dependencies.slice(0, 3).join(", ")}{dep.transitive_dependencies.length > 3 ? "..." : ""}</span>
                            </div>
                          )}
                        </div>
                      </td>
                      <td>
                        <span className={`badge ${dep.is_direct ? "badge-primary" : "badge-info"}`}>
                          {dep.is_direct ? "DIRECT" : "TRANSITIVE"}
                        </span>
                      </td>
                      <td>
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem", color: "var(--text-muted)" }}>
                          {dep.declared_specifier || (dep.is_direct ? "unpinned" : "transitive")}
                        </span>
                      </td>
                      <td>
                        <span style={{
                          fontFamily: "var(--font-mono)",
                          fontWeight: 600,
                          color: dep.is_resolved ? "var(--text-main)" : "var(--sev-critical)"
                        }}>
                          {dep.version}
                        </span>
                        {dep.resolution_status && dep.resolution_status !== "resolved" && (
                          <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>
                            ({dep.resolution_status})
                          </div>
                        )}
                      </td>
                      <td>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                          <code style={{ fontSize: "0.76rem", color: "var(--accent-cyan)", maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {dep.purl}
                          </code>
                          <button
                            onClick={() => handleCopyPurl(dep.purl)}
                            style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)" }}
                            title="Copy PURL"
                          >
                            <Copy size={13} />
                          </button>
                          {copiedPurl === dep.purl && <span style={{ fontSize: "0.7rem", color: "#00FF88" }}>Copied</span>}
                        </div>
                      </td>
                      <td>
                        {vulnCount > 0 ? (
                          <span className="badge badge-critical">
                            {vulnCount} Vuln{vulnCount > 1 ? "s" : ""}
                          </span>
                        ) : (
                          <span className="badge badge-success">✓ Clean</span>
                        )}
                      </td>
                      <td>
                        <span className="badge badge-success">✓ CycloneDX v1.5</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        /* Hierarchical Dependency Tree View */
        <div className="card" style={{ padding: "28px" }}>
          <h3 style={{ fontSize: "1.05rem", fontWeight: 700, marginBottom: "16px", fontFamily: "var(--font-display)" }}>
            Root-to-Leaf Traversal Graph
          </h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            {directDeps.map((direct) => {
              const children = direct.transitive_dependencies || [];
              const directVulns = vulnCountsByPkg[direct.name] || 0;

              return (
                <div
                  key={direct.name}
                  style={{
                    backgroundColor: "rgba(255, 255, 255, 0.02)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "10px",
                    padding: "16px 20px",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                      <span style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: "var(--accent-cyan)", boxShadow: "0 0 8px var(--accent-cyan)" }} />
                      <span style={{ fontWeight: 700, fontFamily: "var(--font-mono)", color: "#FFFFFF" }}>
                        {direct.name}
                      </span>
                      <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                        @{direct.version}
                      </span>
                      <span className="badge badge-primary">DIRECT</span>
                    </div>
                    {directVulns > 0 ? (
                      <span className="badge badge-critical">{directVulns} Vuln</span>
                    ) : (
                      <span className="badge badge-success">Clean</span>
                    )}
                  </div>

                  {/* Transitive children */}
                  {children.length > 0 && (
                    <div style={{ marginTop: "12px", marginLeft: "14px", paddingLeft: "14px", borderLeft: "2px dashed rgba(0, 245, 255, 0.25)", display: "flex", flexDirection: "column", gap: "8px" }}>
                      {children.map((childName) => {
                        const childDep = dependencies.find((d) => d.name === childName);
                        const childVulns = vulnCountsByPkg[childName] || 0;

                        return (
                          <div key={childName} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: "0.85rem" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                              <CornerDownRight size={13} color="var(--accent-cyan)" />
                              <span style={{ fontFamily: "var(--font-mono)", color: childVulns > 0 ? "var(--sev-critical)" : "var(--text-secondary)" }}>
                                {childName}
                              </span>
                              {childDep && (
                                <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                                  @{childDep.version}
                                </span>
                              )}
                              <span className="badge badge-info" style={{ fontSize: "0.68rem" }}>TRANSITIVE</span>
                            </div>
                            {childVulns > 0 && (
                              <span className="badge badge-critical" style={{ fontSize: "0.7rem" }}>
                                {childVulns} Vuln
                              </span>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
