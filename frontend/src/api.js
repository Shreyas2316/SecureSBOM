const API_BASE_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

let currentUserId = "default_user";

export function setUserId(id) {
  currentUserId = id || "default_user";
}

export function getUserId() {
  return currentUserId;
}

const headers = () => ({ "X-User-Id": currentUserId, "Content-Type": "application/json" });

async function apiFetch(path, opts = {}) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    headers: { "X-User-Id": currentUserId, ...(opts.headers || {}) },
    ...opts,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `Request failed: ${res.status}`);
  }
  return res.json();
}

// ── Existing API ──────────────────────────────────────────────

export async function fetchHealth() {
  const res = await fetch(`${API_BASE_URL}/`);
  if (!res.ok) throw new Error("Backend service is offline");
  return res.json();
}

export async function submitScan(options = {}) {
  let projectName = "My Python Project";
  let content = "";

  if (typeof options === "string") {
    content = options;
  } else if (options instanceof File) {
    projectName = options.name;
    content = await options.text();
  } else if (options?.file instanceof File) {
    projectName = options.file.name;
    content = await options.file.text();
  } else if (options) {
    projectName = options.projectName || options.project_name || "My Python Project";
    content = options.requirementsContent || options.rawContent || options.raw_content || options.requirements_content || "";
    if (!content && options.file) {
      if (typeof options.file.text === "function") {
        content = await options.file.text();
        projectName = options.file.name || projectName;
      }
    }
  }

  content = (content || "").trim();
  if (!content) {
    throw new Error("Requirements manifest cannot be empty. Please select a valid requirements.txt or enter dependencies.");
  }

  try {
    return await apiFetch("/api/v1/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-User-Id": currentUserId },
      body: JSON.stringify({
        project_name: projectName,
        requirements_content: content,
      }),
    });
  } catch (err) {
    // Fallback to /scan multipart/form
    try {
      const formData = new FormData();
      formData.append("raw_content", content);
      const res = await fetch(`${API_BASE_URL}/scan`, {
        method: "POST",
        headers: { "X-User-Id": currentUserId },
        body: formData,
      });
      if (res.ok) {
        return await res.json();
      }
    } catch {
      // Fallback failed, rethrow original
    }
    throw err;
  }
}

export async function fetchScanHistory(limit = 50) {
  try {
    let data;
    try {
      data = await apiFetch(`/api/v1/scans?limit=${limit}`);
    } catch {
      data = await apiFetch(`/api/scans?limit=${limit}`);
    }
    const rawList = Array.isArray(data) ? data : (data.scans || []);
    const normalized = rawList.map((s) => {
      const scanId = s.scan_id || s.id;
      const idStr = String(scanId || "");
      return {
        ...s,
        id: idStr,
        scan_id: scanId,
        manifest_name: s.manifest_name || s.project_name || "requirements.txt",
        project_name: s.project_name || s.manifest_name || "Python Project",
        total_scanned: s.total_scanned ?? s.total_deps ?? 0,
        total_deps: s.total_deps ?? s.total_scanned ?? 0,
        direct_deps_count: s.direct_deps_count ?? s.direct_deps ?? 0,
        direct_deps: s.direct_deps ?? s.direct_deps_count ?? 0,
        transitive_deps_count: s.transitive_deps_count ?? s.transitive_deps ?? 0,
        transitive_deps: s.transitive_deps ?? s.transitive_deps_count ?? 0,
        canonical_vulns_count: s.canonical_vulns_count ?? s.unique_vuln_count ?? s.vuln_count ?? 0,
        raw_advisories_count: s.raw_advisories_count ?? s.advisory_record_count ?? 0,
        severity_counts: s.severity_counts || {
          CRITICAL: s.critical_count || 0,
          HIGH: s.high_count || 0,
          MEDIUM: s.medium_count || 0,
          LOW: s.low_count || 0,
          INFORMATIONAL: s.info_count || 0,
          UNKNOWN: s.unknown_count || 0,
        },
      };
    });
    return { scans: normalized };
  } catch {
    return { scans: [] };
  }
}

export async function fetchScanById(scanId) {
  if (!scanId) throw new Error("scanId is required");
  try {
    return await apiFetch(`/api/v1/scans/${scanId}`);
  } catch {
    return await apiFetch(`/api/scans/${scanId}`);
  }
}

export function getDownloadBomUrl(scanId) {
  if (!scanId) return `${API_BASE_URL}/output/bom`;
  return `${API_BASE_URL}/api/v1/scans/${scanId}/sbom`;
}

export function getDownloadReportUrl(scanId, format = "json") {
  if (!scanId) return `${API_BASE_URL}/output/scan_report`;
  return `${API_BASE_URL}/api/v1/scans/${scanId}/report/${format}`;
}

export async function downloadFileAsJson(url, filename) {
  try {
    const res = await fetch(url, { headers: { "X-User-Id": currentUserId } });
    if (!res.ok) throw new Error("Download request failed");
    const data = await res.json();
    const content = (data && data.bom_json) ? data.bom_json : data;
    const blob = new Blob([JSON.stringify(content, null, 2)], { type: "application/json;charset=utf-8" });
    const safeFilename = filename && filename.endsWith(".json") ? filename : `${filename || "export"}.json`;
    _triggerDownload(blob, safeFilename);
  } catch {
    window.open(url, "_blank");
  }
}

function _triggerDownload(blob, filename) {
  const blobUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = blobUrl;
  link.setAttribute("download", filename);
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  setTimeout(() => {
    try {
      document.body.removeChild(link);
    } catch {
      // ignore
    }
    URL.revokeObjectURL(blobUrl);
  }, 4000);
}

// ── AI Findings API ───────────────────────────────────────────

export async function fetchAIStatus() {
  return apiFetch("/api/v1/ai/status");
}

export async function fetchAIDashboard() {
  return apiFetch("/api/v1/ai/dashboard");
}

export async function fetchAIFindings({ scanId, status, confidence, assessmentType, package: pkg, page = 1, pageSize = 20 } = {}) {
  const params = new URLSearchParams();
  if (scanId) params.set("scan_id", scanId);
  if (status) params.set("status", status);
  if (confidence) params.set("confidence", confidence);
  if (assessmentType) params.set("assessment_type", assessmentType);
  if (pkg) params.set("package", pkg);
  params.set("page", page);
  params.set("page_size", pageSize);
  return apiFetch(`/api/v1/ai/findings?${params}`);
}

export async function fetchAIFindingById(findingId) {
  return apiFetch(`/api/v1/ai/findings/${findingId}`);
}

export async function triggerAIAnalysis({ packageName, packageVersion, ecosystem = "PyPI", mode = "emerging_advisory", scanId }) {
  return apiFetch("/api/v1/ai/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-User-Id": currentUserId },
    body: JSON.stringify({
      package_name: packageName,
      package_version: packageVersion,
      ecosystem,
      analysis_mode: mode,
      scan_id: scanId || null,
    }),
  });
}

export async function reviewAIFinding(findingId, { action, notes, reason }) {
  return apiFetch(`/api/v1/ai/findings/${findingId}/review`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json", "X-User-Id": currentUserId },
    body: JSON.stringify({ action, notes, reason }),
  });
}

// ── Dependency Alternatives ───────────────────────────────────

export async function fetchAlternatives(scanId) {
  return apiFetch(`/api/v1/scans/${scanId}/alternatives`);
}

// ── Monitoring ────────────────────────────────────────────────

export async function fetchMonitoringStatus() {
  return apiFetch("/api/v1/monitoring/status");
}

export async function triggerMonitoringRun() {
  return apiFetch("/api/v1/monitoring/run", { method: "POST", headers: { "X-User-Id": currentUserId } });
}

export async function fetchMonitoringAlerts({ acknowledged, page = 1 } = {}) {
  const params = new URLSearchParams({ page, page_size: 20 });
  if (acknowledged !== undefined) params.set("acknowledged", acknowledged);
  return apiFetch(`/api/v1/monitoring/alerts?${params}`);
}

export async function acknowledgeAlert(alertId) {
  return apiFetch(`/api/v1/monitoring/alerts/${alertId}/acknowledge`, {
    method: "PATCH",
    headers: { "X-User-Id": currentUserId },
  });
}

// ── Reports ───────────────────────────────────────────────────

export function getReportDownloadUrl(scanId, format) {
  return `${API_BASE_URL}/api/v1/scans/${scanId}/report/${format}`;
}

export async function downloadReport(scanId, format) {
  const url = getReportDownloadUrl(scanId, format);
  const res = await fetch(url, { headers: { "X-User-Id": currentUserId } });
  if (!res.ok) throw new Error(`Report download failed: ${res.status}`);
  const rawBlob = await res.blob();
  const mimeTypes = {
    pdf: "application/pdf",
    csv: "text/csv;charset=utf-8",
    json: "application/json;charset=utf-8",
  };
  const mimeType = mimeTypes[format] || "application/octet-stream";
  const blob = new Blob([rawBlob], { type: mimeType });
  const ext = format === "pdf" ? "pdf" : format === "csv" ? "csv" : "json";
  const cleanId = String(scanId || "scan").replace(/[^a-zA-Z0-9_-]/g, "_");
  _triggerDownload(blob, `securesbom-report-${cleanId}.${ext}`);
}
