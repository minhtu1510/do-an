const STORAGE_KEY = "web_scada_auth";

export function getSession() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function setSession(session) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
  window.dispatchEvent(new Event("auth:changed"));
}

export function clearSession() {
  localStorage.removeItem(STORAGE_KEY);
  window.dispatchEvent(new Event("auth:changed"));
}

export function getToken() {
  return getSession()?.access_token || null;
}

export function notifyUnauthorized() {
  clearSession();
  window.dispatchEvent(new Event("auth:unauthorized"));
}
