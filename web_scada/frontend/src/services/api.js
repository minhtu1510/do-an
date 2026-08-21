import { getToken, notifyUnauthorized } from "./authToken";

const API_BASE = "/api";

export async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = { ...(options.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (res.status === 401) {
    notifyUnauthorized();
  }
  return res;
}

export async function fetchStatus() {
  const res = await apiFetch("/health");
  return res.json();
}

export async function fetchSystemResources() {
  const res = await apiFetch("/system/resources");
  return res.json();
}

export async function fetchPlcStatus() {
  const res = await apiFetch("/plc/status");
  return res.json();
}

export async function fetchAllTags() {
  const res = await apiFetch("/tags");
  return res.json();
}

export async function fetchTag(key) {
  const res = await apiFetch(`/tags/${key}`);
  return res.json();
}

export async function writeTag(key, value) {
  const res = await apiFetch(`/tags/${key}/write`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ value }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.message || body.detail || "Ghi lệnh thất bại");
  return body;
}

export async function fetchEvents(limit = 100) {
  const res = await apiFetch(`/events?limit=${limit}`);
  return res.json();
}

export async function fetchSecurityStatus() {
  const res = await apiFetch("/security/status");
  return res.json();
}

export async function fetchScenarioResults(limit = 50) {
  const res = await apiFetch(`/security/scenarios?limit=${limit}`);
  return res.json();
}

export async function fetchSecurityModeComparator(group = "opcua") {
  const res = await apiFetch(`/security/comparator?group=${encodeURIComponent(group)}`);
  return res.json();
}

export async function fetchProcessHistory() {
  const res = await apiFetch("/history/process");
  return res.json();
}

export async function fetchAttackEvents() {
  const res = await apiFetch("/history/attack-events");
  return res.json();
}

export async function ackEvent(eventId) {
  const res = await apiFetch(`/events/${eventId}/ack`, { method: "POST" });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || "Failed to ack event");
  return res.json();
}

export async function fetchMlStatus() {
  const res = await apiFetch("/ml/status");
  return res.json();
}

export async function fetchMlSummary() {
  const res = await apiFetch("/ml/summary");
  return res.json();
}

export async function fetchMlRuns(experiment) {
  const res = await apiFetch(`/ml/experiments/${encodeURIComponent(experiment)}/runs`);
  return res.json();
}

export async function fetchMlConfusionMatrix(experiment, run) {
  const res = await apiFetch(`/ml/experiments/${encodeURIComponent(experiment)}/runs/${encodeURIComponent(run)}/confusion-matrix`);
  return res.json();
}

export async function fetchMlFeatureImportance(experiment, run) {
  const res = await apiFetch(`/ml/experiments/${encodeURIComponent(experiment)}/runs/${encodeURIComponent(run)}/feature-importance`);
  return res.json();
}

// Returns an object URL (or null if not found) — the endpoint is
// role-gated, so a plain <img src> can't hit it directly (no Authorization
// header on image requests); fetch the bytes ourselves and hand the <img> a
// blob: URL instead.
export async function fetchMlPrCurveUrl(experiment, run) {
  const res = await apiFetch(`/ml/experiments/${encodeURIComponent(experiment)}/runs/${encodeURIComponent(run)}/pr-curve.png`);
  if (!res.ok) return null;
  const blob = await res.blob();
  return URL.createObjectURL(blob);
}

export async function fetchUsers() {
  const res = await apiFetch("/auth/users");
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || "Failed to load users");
  return res.json();
}

export async function createUser(username, password, role) {
  const res = await apiFetch("/auth/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, role }),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || "Failed to create user");
  return res.json();
}

export async function changeUserRole(userId, role) {
  const res = await apiFetch(`/auth/users/${userId}/role`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ role }),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || "Failed to change role");
  return res.json();
}

export async function deleteUser(userId) {
  const res = await apiFetch(`/auth/users/${userId}`, { method: "DELETE" });
  if (!res.ok && res.status !== 204) {
    throw new Error((await res.json().catch(() => ({}))).detail || "Failed to delete user");
  }
}

export async function fetchIdsStatus() {
  const res = await apiFetch("/ids/status");
  return res.json();
}

export async function analyzeIdsPcap(file, plcIp, window) {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("plc_ip", plcIp);
  formData.append("window", String(window));
  const res = await apiFetch("/ids/analyze", { method: "POST", body: formData });
  const body = await res.json();
  if (!res.ok) throw new Error(body.message || body.detail || "Phân tích thất bại");
  return body;
}

export async function fetchIdsStatusOpcua() {
  const res = await apiFetch("/ids/opcua/status");
  return res.json();
}

export async function analyzeIdsPcapOpcua(file, plcIp, window) {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("plc_ip", plcIp);
  formData.append("window", String(window));
  const res = await apiFetch("/ids/opcua/analyze", { method: "POST", body: formData });
  const body = await res.json();
  if (!res.ok) throw new Error(body.message || body.detail || "Phân tích thất bại");
  return body;
}

export async function fetchIdsHistory(limit = 100) {
  const res = await apiFetch(`/ids/history?limit=${limit}`);
  return res.json();
}

export async function fetchOpcuaConfig() {
  const res = await apiFetch("/admin/opcua-config");
  return res.json();
}

export async function setOpcuaConfig(endpoint) {
  const res = await apiFetch("/admin/opcua-config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ endpoint }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.message || body.detail || "Cập nhật cấu hình thất bại");
  return body;
}
