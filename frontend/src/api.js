const API_BASE_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

let currentUserId = "default_user";

export function setUserId(id) {
  currentUserId = id || "default_user";
}

export function getUserId() {
  return currentUserId;
}

export async function fetchHealth() {
  const res = await fetch(`${API_BASE_URL}/`);
  if (!res.ok) throw new Error("Backend service is offline");
  return res.json();
}

export async function submitScan({ file, rawContent }) {
  const formData = new FormData();
  if (file) {
    formData.append("file", file);
  } else if (rawContent) {
    formData.append("raw_content", rawContent);
  } else {
    throw new Error("Please provide a requirements.txt file or text content");
  }

  const res = await fetch(`${API_BASE_URL}/scan`, {
    method: "POST",
    headers: {
      "X-User-Id": currentUserId,
    },
    body: formData,
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || "Scan request failed");
  }
  return data;
}

export async function fetchScanHistory(limit = 50) {
  const res = await fetch(`${API_BASE_URL}/api/scans?limit=${limit}`, {
    headers: { "X-User-Id": currentUserId },
  });
  if (!res.ok) throw new Error("Failed to load scan history");
  return res.json();
}

export async function fetchScanById(scanId) {
  const res = await fetch(`${API_BASE_URL}/api/scans/${scanId}`, {
    headers: { "X-User-Id": currentUserId },
  });
  if (!res.ok) throw new Error(`Failed to load scan '${scanId}'`);
  return res.json();
}

export function getDownloadBomUrl(scanId) {
  if (scanId) {
    return `${API_BASE_URL}/api/scans/${scanId}/bom?user_id=${encodeURIComponent(currentUserId)}`;
  }
  return `${API_BASE_URL}/output/bom`;
}

export function getDownloadReportUrl(scanId) {
  if (scanId) {
    return `${API_BASE_URL}/api/scans/${scanId}/report?user_id=${encodeURIComponent(currentUserId)}`;
  }
  return `${API_BASE_URL}/output/scan_report`;
}

export async function downloadFileAsJson(url, filename) {
  try {
    const res = await fetch(url, {
      headers: { "X-User-Id": currentUserId },
    });
    if (!res.ok) throw new Error("Download request failed");
    const data = await res.json();
    const formatted = JSON.stringify(data, null, 2);
    const blob = new Blob([formatted], { type: "application/json;charset=utf-8" });
    const blobUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = blobUrl;
    link.download = filename || "export.json";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(blobUrl);
  } catch (err) {
    window.open(url, "_blank");
  }
}

