import { createContext, useContext, useEffect, useState } from "react";
import { clearSession, getSession, setSession } from "../services/authToken";

const ROLE_RANK = { viewer: 0, operator: 1, admin: 2 };

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [session, setSessionState] = useState(() => getSession());

  useEffect(() => {
    const sync = () => setSessionState(getSession());
    window.addEventListener("auth:changed", sync);
    window.addEventListener("auth:unauthorized", sync);
    return () => {
      window.removeEventListener("auth:changed", sync);
      window.removeEventListener("auth:unauthorized", sync);
    };
  }, []);

  async function login(username, password) {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || "Login failed");
    }
    const data = await res.json();
    setSession(data);
    setSessionState(data);
    return data;
  }

  function logout() {
    clearSession();
    setSessionState(null);
  }

  function hasRole(minimum) {
    if (!session) return false;
    return ROLE_RANK[session.role] >= ROLE_RANK[minimum];
  }

  const value = {
    session,
    isAuthenticated: Boolean(session?.access_token),
    username: session?.username || null,
    role: session?.role || null,
    login,
    logout,
    hasRole,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
