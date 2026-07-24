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

export async function fetchEvents(limit = 100) {
  const res = await fetch(`${API_BASE}/events?limit=${limit}`);
  return res.json();
}

export async function fetchSecurityStatus() {
  const res = await fetch(`${API_BASE}/security/status`);
  return res.json();
}

export async function fetchScenarioResults(limit = 50) {
  const res = await fetch(`${API_BASE}/security/scenarios?limit=${limit}`);
  return res.json();
}

export async function fetchSecurityModeComparator(group = "opcua") {
  const res = await fetch(`${API_BASE}/security/comparator?group=${encodeURIComponent(group)}`);
  return res.json();
}

export async function fetchProcessHistory() {
  const res = await fetch(`${API_BASE}/history/process`);
  return res.json();
}

export async function fetchMlStatus() {
  const res = await fetch(`${API_BASE}/ml/status`);
  return res.json();
}

export async function fetchMlSummary() {
  const res = await fetch(`${API_BASE}/ml/summary`);
  return res.json();
}

export async function fetchMlRuns(experiment) {
  const res = await fetch(`${API_BASE}/ml/experiments/${encodeURIComponent(experiment)}/runs`);
  return res.json();
}

export async function fetchMlConfusionMatrix(experiment, run) {
  const res = await fetch(`${API_BASE}/ml/experiments/${encodeURIComponent(experiment)}/runs/${encodeURIComponent(run)}/confusion-matrix`);
  return res.json();
}

export async function fetchMlFeatureImportance(experiment, run) {
  const res = await fetch(`${API_BASE}/ml/experiments/${encodeURIComponent(experiment)}/runs/${encodeURIComponent(run)}/feature-importance`);
  return res.json();
}
