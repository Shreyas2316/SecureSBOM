const API_BASE_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

const TOKEN_STORAGE_KEY = "securesbom_access_token";
const REFRESH_STORAGE_KEY = "securesbom_refresh_token";

export function getAccessToken() {
  return localStorage.getItem(TOKEN_STORAGE_KEY) || "";
}

export function setTokens(accessToken, refreshToken) {
  if (accessToken) localStorage.setItem(TOKEN_STORAGE_KEY, accessToken);
  if (refreshToken) localStorage.setItem(REFRESH_STORAGE_KEY, refreshToken);
}

export function clearTokens() {
  localStorage.removeItem(TOKEN_STORAGE_KEY);
  localStorage.removeItem(REFRESH_STORAGE_KEY);
}

async function refreshAccessToken() {
  const refreshToken = localStorage.getItem(REFRESH_STORAGE_KEY);
  if (!refreshToken) return null;
  const res = await fetch(`${API_BASE_URL}/api/v1/auth/refresh`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
  if (!res.ok) {
    clearTokens();
    return null;
  }
  const data = await res.json();
  setTokens(data.access_token, data.refresh_token);
  return data.access_token;
}

async function apiFetch(path, opts = {}, retryOn401 = true) {
  const token = getAccessToken();
  const headers = {
    ...(opts.headers || {}),
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE_URL}${path}`, {
    credentials: "include",
    ...opts,
    headers,
  });

  if (res.status === 401 && retryOn401 && !path.startsWith("/api/v1/auth/")) {
    const newToken = await refreshAccessToken();
    if (newToken) {
      return apiFetch(path, opts, false);
    }
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `Request failed: ${res.status}`);
  }
  return res.json();
}

// ── Authentication API ────────────────────────────────────────

export async function registerUser({ username, email, password }) {
  const data = await apiFetch("/api/v1/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, email, password }),
  }, false);
  setTokens(data.access_token, data.refresh_token);
  return data;
}

export async function loginUser({ usernameOrEmail, password }) {
  const data = await apiFetch("/api/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username_or_email: usernameOrEmail, password }),
  }, false);
  setTokens(data.access_token, data.refresh_token);
  return data;
}

export async function logoutUser() {
  try {
    await apiFetch("/api/v1/auth/logout", { method: "POST" }, false);
  } finally {
    clearTokens();
  }
}

export async function fetchCurrentUser() {
  return apiFetch("/api/v1/auth/me");
}

export async function updateAICredentials({ aiApiKey, aiProviderConsent }) {
  return apiFetch("/api/v1/auth/ai-credentials", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ai_api_key: aiApiKey,
      ai_provider_consent: aiProviderConsent,
    }),
  });
}

export async function changePassword({ currentPassword, newPassword }) {
  return apiFetch("/api/v1/auth/change-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      current_password: currentPassword,
      new_password: newPassword,
    }),
  });
}

// ── Health & Scanning API ─────────────────────────────────────

export async function fetchHealth() {
  const res = await fetch(`${API_BASE_URL}/health`);
  if (!res.ok) throw new Error("Backend service is offline");
  return res.json();
}

export async function submitScan(options = {}) {
  let projectName = "My Python Project";
  let manifestFilename = "requirements.txt";
  let content = "";

  if (typeof options === "string") {
    content = options;
  } else if (options instanceof File) {
    projectName = options.name;
    manifestFilename = options.name;
    content = await options.text();
  } else if (options?.file instanceof File) {
    projectName = options.projectName || options.file.name;
    manifestFilename = options.file.name;
    content = await options.file.text();
  } else if (options) {
    projectName = options.projectName || options.project_name || "My Python Project";
    manifestFilename = options.manifestFilename || options.manifest_filename || "requirements.txt";
    content = options.requirementsContent || options.rawContent || options.raw_content || options.requirements_content || "";
    if (!content && options.file && typeof options.file.text === "function") {
      content = await options.file.text();
      manifestFilename = options.file.name || manifestFilename;
      projectName = options.file.name || projectName;
    }
  }

  content = (content || "").trim();
  if (!content) {
    throw new Error("Manifest cannot be empty. Please select a valid requirements.txt, pyproject.toml, poetry.lock, Pipfile.lock, or CycloneDX JSON.");
  }

  const data = await apiFetch("/api/v1/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      project_name: projectName,
      requirements_content: content,
      manifest_filename: manifestFilename,
    }),
  });

  if (data && data.summary) {
    const s = data.summary;
    s.total_scanned = s.total_scanned ?? s.total_deps ?? 0;
    s.total_direct_deps = s.total_direct_deps ?? s.direct_deps ?? 0;
    s.total_transitive_deps = s.total_transitive_deps ?? s.transitive_deps ?? 0;
    s.total_canonical_vulnerabilities = s.total_canonical_vulnerabilities ?? s.unique_vuln_count ?? s.vuln_count ?? 0;
    s.total_raw_advisories = s.total_raw_advisories ?? s.advisory_record_count ?? 0;
    s.vulnerable_components_count = s.vulnerable_components_count ?? s.affected_components_count ?? 0;
  }
  return data;
}

export async function fetchScanHistory(limit = 50) {
  try {
    const data = await apiFetch(`/api/v1/scans?limit=${limit}`);
    const rawList = Array.isArray(data) ? data : (data.scans || []);
    const normalized = rawList.map((s) => {
      const scanId = s.scan_id || s.id;
      return {
        ...s,
        id: String(scanId || ""),
        scan_id: scanId,
        manifest_name: s.manifest_name || s.project_name || "requirements.txt",
        project_name: s.project_name || s.manifest_name || "Python Project",
        total_scanned: s.total_scanned ?? s.total_deps ?? 0,
        total_deps: s.total_deps ?? s.total_scanned ?? 0,
        direct_deps_count: s.direct_deps_count ?? s.direct_deps ?? 0,
        transitive_deps_count: s.transitive_deps_count ?? s.transitive_deps ?? 0,
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
  return apiFetch(`/api/v1/scans/${scanId}`);
}

export async function fetchLiveReferences(scanId) {
  if (!scanId) return { unknown_vulnerabilities: [], live_advisories: [], reference_sources: [] };
  return apiFetch(`/api/v1/scans/${scanId}/live-references`);
}

export function getDownloadBomUrl(scanId) {
  return `${API_BASE_URL}/api/v1/scans/${scanId}/sbom`;
}

export function getDownloadReportUrl(scanId, format = "json") {
  return `${API_BASE_URL}/api/v1/scans/${scanId}/report/${format}`;
}

export async function downloadFileAsJson(url, filename) {
  const token = getAccessToken();
  const res = await fetch(url, {
    credentials: "include",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new Error("Download request failed");
  const data = await res.json();
  const content = (data && data.bom_json) ? data.bom_json : data;
  const blob = new Blob([JSON.stringify(content, null, 2)], { type: "application/json;charset=utf-8" });
  const safeFilename = filename && filename.endsWith(".json") ? filename : `${filename || "export"}.json`;
  _triggerDownload(blob, safeFilename);
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
    headers: { "Content-Type": "application/json" },
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
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, notes, reason }),
  });
}

// ── Intelligence Dataset & RAG API ────────────────────────────

export async function fetchIntelligenceSources() {
  return apiFetch("/api/v1/intelligence/sources");
}

export async function syncIntelligenceSources(sourceKeys = null) {
  return apiFetch("/api/v1/intelligence/sync", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(sourceKeys ? { source_keys: sourceKeys } : {}),
  });
}

export async function searchIntelligenceDocuments({ q, package: pkg, sourceKey, page = 1, pageSize = 20 } = {}) {
  const params = new URLSearchParams({ page, page_size: pageSize });
  if (q) params.set("q", q);
  if (pkg) params.set("package", pkg);
  if (sourceKey) params.set("source_key", sourceKey);
  return apiFetch(`/api/v1/intelligence/documents?${params}`);
}

export async function runRagAssessment({ packageName, packageVersion, ecosystem = "PyPI", scanId }) {
  return apiFetch("/api/v1/intelligence/rag-assess", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      package_name: packageName,
      package_version: packageVersion,
      ecosystem,
      scan_id: scanId || null,
    }),
  });
}

export async function fetchEmergingFindings({ scanId, status } = {}) {
  const params = new URLSearchParams();
  if (scanId) params.set("scan_id", scanId);
  if (status) params.set("status", status);
  return apiFetch(`/api/v1/intelligence/emerging?${params}`);
}

export async function reviewEmergingFinding(findingId, { action, notes, reason }) {
  return apiFetch(`/api/v1/intelligence/emerging/${findingId}/review`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, notes, reason }),
  });
}

export async function fetchPotentialWeaknesses({ scanId } = {}) {
  const params = new URLSearchParams();
  if (scanId) params.set("scan_id", scanId);
  return apiFetch(`/api/v1/intelligence/weaknesses?${params}`);
}

export async function runStaticAnalysis({ filename, sourceCode, scanId }) {
  return apiFetch("/api/v1/intelligence/static-analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ filename, source_code: sourceCode, scan_id: scanId || null }),
  });
}

export async function reassessProjects() {
  return apiFetch("/api/v1/intelligence/reassess", { method: "POST" });
}

// ── Dependency Alternatives ───────────────────────────────────

export async function fetchAlternatives(scanId) {
  return apiFetch(`/api/v1/scans/${scanId}/alternatives`);
}

export async function runAIDependencyCheck(scanId) {
  return apiFetch(`/api/v1/scans/${scanId}/ai-dependency-check`, { method: "POST" });
}

// ── Monitoring ────────────────────────────────────────────────

export async function fetchMonitoringStatus() {
  return apiFetch("/api/v1/monitoring/status");
}

export async function triggerMonitoringRun() {
  return apiFetch("/api/v1/monitoring/run", { method: "POST" });
}

export async function fetchMonitoringAlerts({ acknowledged, page = 1 } = {}) {
  const params = new URLSearchParams({ page, page_size: 20 });
  if (acknowledged !== undefined) params.set("acknowledged", acknowledged);
  return apiFetch(`/api/v1/monitoring/alerts?${params}`);
}

export async function acknowledgeAlert(alertId) {
  return apiFetch(`/api/v1/monitoring/alerts/${alertId}/acknowledge`, { method: "PATCH" });
}

// ── Reports ───────────────────────────────────────────────────

export function getReportDownloadUrl(scanId, format) {
  return `${API_BASE_URL}/api/v1/scans/${scanId}/report/${format}`;
}

export async function downloadReport(scanId, format) {
  const url = getReportDownloadUrl(scanId, format);
  const token = getAccessToken();
  const res = await fetch(url, {
    credentials: "include",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
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
