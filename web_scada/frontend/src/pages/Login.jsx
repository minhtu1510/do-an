import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { User, Lock, AlertTriangle, Loader2, ShieldCheck, Radio, Activity } from "lucide-react";
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

      <div className="relative grid w-full max-w-4xl overflow-hidden rounded-3xl border border-slate-800/80 bg-slate-900/65 shadow-[0_30px_100px_rgba(0,0,0,.45)] backdrop-blur-xl md:grid-cols-[1.05fr_.95fr]">
        <div className="relative hidden overflow-hidden border-r border-slate-800/70 p-8 md:block">
          <div className="ids-scanline pointer-events-none absolute left-0 right-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300 to-transparent" />
          <div className="flex h-full flex-col justify-between">
            <div>
              <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">
                <ShieldCheck size={24} />
              </div>
              <div className="mt-6 text-[11px] font-semibold uppercase tracking-[0.22em] text-cyan-500/80">Industrial security platform</div>
              <h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-100">WEB-SCADA <span className="text-cyan-300">IDS</span></h1>
              <p className="mt-3 max-w-sm text-sm leading-relaxed text-slate-500">Theo dõi trạng thái PLC, OPC UA, cảnh báo bảo mật và bằng chứng kịch bản tấn công trong một giao diện vận hành thống nhất.</p>
            </div>

            <div className="space-y-2">
              <Feature icon={Radio} label="PLC / OPC UA telemetry" />
              <Feature icon={Activity} label="Live attack-event monitoring" />
              <Feature icon={ShieldCheck} label="Scenario evidence & MITRE ATT&CK" />
            </div>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="p-6 sm:p-8 md:p-10">
          <div className="mb-7 md:hidden">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300"><ShieldCheck size={21} /></div>
            <div className="mt-4 text-xl font-semibold text-slate-100">WEB-SCADA <span className="text-cyan-300">IDS</span></div>
          </div>

          <div className="mb-7">
            <div className="ids-label text-cyan-500/80">Secure access</div>
            <div className="mt-1 text-xl font-semibold tracking-tight text-slate-100">Đăng nhập hệ thống</div>
            <div className="mt-1.5 text-sm text-slate-500">Sử dụng tài khoản được phân quyền để truy cập dashboard.</div>
          </div>

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

          <div className="mt-5 flex items-center justify-center gap-2 text-[10px] uppercase tracking-[0.13em] text-slate-700">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            Security monitoring enabled
          </div>
        </form>
      </div>
    </div>
  );
}

function Feature({ icon: Icon, label }) {
  return (
    <div className="flex items-center gap-3 rounded-xl border border-slate-800/70 bg-slate-950/35 px-3 py-2.5 text-xs text-slate-500">
      <Icon size={14} className="text-cyan-500/70" />
      {label}
    </div>
  );
}
