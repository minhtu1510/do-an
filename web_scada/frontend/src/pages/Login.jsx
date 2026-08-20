import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { User, Lock, AlertTriangle, Loader2, ShieldCheck } from "lucide-react";
import { useAuth } from "../stores/authStore";

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const from = location.state?.from || "/";

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(username, password);
      navigate(from, { replace: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-slate-950 px-4 py-8">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_20%_20%,rgba(34,211,238,.08),transparent_28%),radial-gradient(circle_at_80%_80%,rgba(59,130,246,.06),transparent_30%)]" />
      <div className="pointer-events-none absolute inset-0 opacity-20" style={{ backgroundImage: "linear-gradient(rgba(148,163,184,.05) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,.05) 1px, transparent 1px)", backgroundSize: "32px 32px" }} />

      <div className="relative w-full max-w-sm overflow-hidden rounded-3xl border border-slate-800/80 bg-slate-900/65 p-8 shadow-[0_30px_100px_rgba(0,0,0,.45)] backdrop-blur-xl">
        <div className="ids-scanline pointer-events-none absolute left-0 right-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300 to-transparent" />

        <div className="mb-7 flex flex-col items-center text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">
            <ShieldCheck size={22} />
          </div>
          <div className="mt-3 text-lg font-semibold tracking-tight text-slate-100">WEB-SCADA <span className="text-cyan-300">IDS</span></div>
        </div>

        <form onSubmit={handleSubmit}>
          <label className="mb-4 block">
            <div className="mb-1.5 text-xs font-medium text-slate-500">Username</div>
            <div className="relative">
              <User size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-600" />
              <input
                autoFocus
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                className="w-full rounded-xl border border-slate-700/80 bg-slate-950/70 py-2.5 pl-9 pr-3 text-sm text-slate-200 outline-none transition-all placeholder:text-slate-700 focus:border-cyan-400/50 focus:ring-2 focus:ring-cyan-400/10"
              />
            </div>
          </label>

          <label className="mb-5 block">
            <div className="mb-1.5 text-xs font-medium text-slate-500">Password</div>
            <div className="relative">
              <Lock size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-600" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                className="w-full rounded-xl border border-slate-700/80 bg-slate-950/70 py-2.5 pl-9 pr-3 text-sm text-slate-200 outline-none transition-all placeholder:text-slate-700 focus:border-cyan-400/50 focus:ring-2 focus:ring-cyan-400/10"
              />
            </div>
          </label>

          {error && (
            <div className="mb-4 flex items-start gap-2.5 rounded-xl border border-red-400/15 bg-red-400/[0.07] px-3 py-2.5 text-xs text-red-300 animate-fade-in">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" />
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={busy || !username || !password}
            className="flex w-full items-center justify-center gap-2 rounded-xl border border-cyan-300/20 bg-cyan-400 px-3 py-2.5 text-sm font-semibold text-slate-950 shadow-[0_8px_30px_rgba(34,211,238,.15)] transition-all hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {busy && <Loader2 size={14} className="animate-spin" />}
            {busy ? "Đang xác thực..." : "Đăng nhập"}
          </button>
        </form>
      </div>
    </div>
  );
}
