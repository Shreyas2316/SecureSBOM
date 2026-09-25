const API_BASE_URL = 'http://localhost:8000';

export async function checkHealth() {
  try {
    const res = await fetch(`${API_BASE_URL}/health`);
    if (!res.ok) throw new Error('Health check failed');
    return await res.json();
  } catch (err) {
    return { status: 'offline', database: 'unhealthy', error: err.message };
  }
}

export async function startScan(projectName, requirementsContent) {
  const res = await fetch(`${API_BASE_URL}/api/v1/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      project_name: projectName,
      requirements_content: requirementsContent
    })
  });
  
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Scan failed with status ${res.status}`);
  }

  return await res.json();
}

export async function fetchScanHistory() {
  const res = await fetch(`${API_BASE_URL}/api/v1/scans`);
  if (!res.ok) throw new Error('Failed to fetch scan history');
  return await res.json();
}

export async function fetchScanDetails(scanId) {
  const res = await fetch(`${API_BASE_URL}/api/v1/scans/${scanId}`);
  if (!res.ok) throw new Error('Failed to fetch scan details');
  return await res.json();
}

export async function fetchScanSbom(scanId) {
  const res = await fetch(`${API_BASE_URL}/api/v1/scans/${scanId}/sbom`);
  if (!res.ok) throw new Error('Failed to fetch SBOM data');
  return await res.json();
}
