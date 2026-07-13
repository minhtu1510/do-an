const API_BASE = "/api";

export async function fetchStatus() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

export async function fetchPlcStatus() {
  const res = await fetch(`${API_BASE}/plc/status`);
  return res.json();
}

export async function fetchAllTags() {
  const res = await fetch(`${API_BASE}/tags`);
  return res.json();
}

export async function fetchTag(key) {
  const res = await fetch(`${API_BASE}/tags/${key}`);
  return res.json();
}
