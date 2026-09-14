import { useState, useEffect } from "react";
import { createPortal } from "react-dom";
import { Cpu, Radio, Wifi, LogOut, AlertTriangle, ShieldCheck, KeyRound, X } from "lucide-react";
import { apiFetch, fetchPlcStatus } from "../services/api";
import { connectWebSocket } from "../services/websocket";
import { useAuth } from "../stores/authStore";
import { useToast } from "./Toast";

export default function StatusBar() {
  const { username, role, logout } = useAuth();
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [plcStatus, setPlcStatus] = useState(null);
  const [tags, setTags] = useState({});
  const [wsOpen, setWsOpen] = useState(false);

  useEffect(() => {
    fetchPlcStatus().then(setPlcStatus);
    const unsub = connectWebSocket((data) => {
      if (data.type === "tag_update") setTags((prev) => ({ ...prev, [data.key]: data.data }));
      if (data.type === "full_state") {
        if (data.status) setPlcStatus(data.status);
        if (data.tags) {
          const map = {};
          data.tags.forEach((t) => (map[t.key] = t));
          setTags(map);
        }
      }
      if (data.type === "ws_open") setWsOpen(true);
      if (data.type === "ws_close") setWsOpen(false);
    });
    const timer = setInterval(() => fetchPlcStatus().then(setPlcStatus), 10000);
    return () => { unsub(); clearInterval(timer); };
  }, []);

  const plcConnected = plcStatus?.connected ?? null;
  const anyStale = Object.values(tags).length > 0 && Object.values(tags).some((t) => t.stale);
  const allStale = Object.values(tags).length > 0 && Object.values(tags).every((t) => t.stale);
  const plcDisconnected = plcConnected === false;
  const loading = plcConnected === null;
  const healthyTags = Object.values(tags).filter((t) => !t.stale).length;

  return (
    <header className="sticky top-0 z-40 flex min-h-[49px] items-center gap-3 border-b border-slate-800/90 bg-slate-950/95 px-4 text-xs shadow-[0_8px_30px_rgba(0,0,0,.16)] backdrop-blur-xl">
      <div className="mr-2 flex items-center gap-2.5">
        <div className="relative flex h-8 w-8 items-center justify-center rounded-lg border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">
          <ShieldCheck size={17} strokeWidth={2.3} />
          <span className="absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full border-2 border-slate-950 bg-emerald-400" />
        </div>
        <div className="hidden sm:block">
          <div className="text-[13px] font-semibold tracking-tight text-slate-100">WEB-SCADA <span className="text-cyan-400">IDS</span></div>
          <div className="text-[9px] uppercase tracking-[0.16em] text-slate-600">Industrial Security Monitor</div>
        </div>
      </div>

      <div className="hidden h-5 w-px bg-slate-800 md:block" />

      {loading ? (
        <span className="flex items-center gap-1.5 text-amber-300">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-amber-400" /> Connecting…
        </span>
      ) : (
        <div className="hidden items-center gap-3 md:flex">
          <Dot label="PLC" icon={Cpu} status={plcConnected ? "on" : "off"} />
          <Dot label="OPC UA" icon={Radio} status={plcDisconnected ? "off" : anyStale ? "warn" : "on"} />
          <Dot label="WebSocket" icon={Wifi} status={wsOpen ? "on" : "off"} />
        </div>
      )}

      <div className="ml-auto flex items-center gap-2">
        <div className="hidden items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-2.5 py-1.5 xl:flex">
          <span className="text-slate-600">Tag health</span>
          <span className={`font-mono font-semibold ${allStale ? "text-red-300" : "text-emerald-300"}`}>{healthyTags}/{Object.values(tags).length}</span>
        </div>

        {plcDisconnected && (
          <span className="flex animate-pulse items-center gap-1.5 rounded-lg border border-red-500/20 bg-red-500/10 px-2.5 py-1.5 text-[10px] font-bold text-red-300">
            <AlertTriangle size={11} /> PLC OFFLINE
          </span>
        )}
        {!plcDisconnected && anyStale && (
          <span className="flex items-center gap-1.5 rounded-lg border border-amber-500/20 bg-amber-500/10 px-2.5 py-1.5 text-[10px] text-amber-300">
            <AlertTriangle size={11} /> STALE TAGS
          </span>
        )}

        <div className="ml-1 flex items-center gap-2 border-l border-slate-800 pl-3">
          <div className="hidden text-right sm:block">
            <div className="text-[11px] font-medium text-slate-300">{username}</div>
            <div className="text-[9px] uppercase tracking-wider text-slate-600">{role}</div>
          </div>
          <button onClick={() => setShowPasswordModal(true)} title="Đổi mật khẩu" className="flex h-8 w-8 items-center justify-center rounded-lg text-slate-600 transition-colors hover:bg-cyan-500/10 hover:text-cyan-300">
            <KeyRound size={14} />
          </button>
          <button onClick={logout} title="Đăng xuất" className="flex h-8 w-8 items-center justify-center rounded-lg text-slate-600 transition-colors hover:bg-red-500/10 hover:text-red-300">
            <LogOut size={14} />
          </button>
        </div>
      </div>

      {showPasswordModal &&
        createPortal(<ChangePasswordModal onClose={() => setShowPasswordModal(false)} />, document.body)}
    </header>
  );
}

// Rendered via createPortal into document.body, not inline here — this
// component sits inside <header>, which is position:sticky. A sticky
// ancestor turned out to also constrain descendant position:fixed elements
// in testing (the modal's overlay was clipped to the header's own 49px
// height instead of covering the viewport) — verified by inspecting the
// overlay's bounding box before the portal fix (0,0,1440,48 instead of the
// full 1440x900 viewport). Portaling to body sidesteps that entirely,
// which is also just the standard way to build a modal in React regardless
// of what ancestor CSS might do.
function ChangePasswordModal({ onClose }) {
  const toast = useToast();
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    if (newPassword.length < 8) {
      toast("Mật khẩu mới cần tối thiểu 8 ký tự", { tone: "error" });
      return;
    }
    if (newPassword !== confirm) {
      toast("Xác nhận mật khẩu không khớp", { tone: "error" });
      return;
    }
    setBusy(true);
    try {
      const res = await apiFetch("/auth/me/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        toast(body.detail || "Đổi mật khẩu thất bại", { tone: "error" });
        return;
      }
      toast("Đã đổi mật khẩu thành công", { tone: "success" });
      onClose();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <form
        onSubmit={handleSubmit}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-sm rounded-2xl border border-slate-800 bg-slate-950 p-5 shadow-2xl"
      >
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-100">Đổi mật khẩu</h3>
          <button type="button" onClick={onClose} className="text-slate-600 hover:text-slate-300">
            <X size={16} />
          </button>
        </div>
        <div className="space-y-3">
          <label className="block">
            <div className="mb-1 text-xs text-slate-500">Mật khẩu hiện tại</div>
            <input
              type="password"
              autoFocus
              value={oldPassword}
              onChange={(e) => setOldPassword(e.target.value)}
              autoComplete="current-password"
              className="w-full rounded-lg border border-slate-700/80 bg-slate-900/70 px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyan-400/50"
            />
          </label>
          <label className="block">
            <div className="mb-1 text-xs text-slate-500">Mật khẩu mới (tối thiểu 8 ký tự)</div>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              autoComplete="new-password"
              className="w-full rounded-lg border border-slate-700/80 bg-slate-900/70 px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyan-400/50"
            />
          </label>
          <label className="block">
            <div className="mb-1 text-xs text-slate-500">Xác nhận mật khẩu mới</div>
            <input
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
              className="w-full rounded-lg border border-slate-700/80 bg-slate-900/70 px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyan-400/50"
            />
          </label>
        </div>
        <button
          type="submit"
          disabled={busy || !oldPassword || !newPassword}
          className="mt-4 w-full rounded-lg bg-cyan-500 px-3 py-2 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy ? "Đang lưu..." : "Lưu mật khẩu mới"}
        </button>
      </form>
    </div>
  );
}

function Dot({ label, icon: Icon, status }) {
  const cls = {
    on: ["bg-emerald-400", "text-slate-400"],
    off: ["bg-red-400", "text-red-300"],
    warn: ["bg-amber-400", "text-amber-300"],
  }[status];
  return (
    <div className={`flex items-center gap-1.5 ${cls[1]}`}>
      <span className="relative flex h-1.5 w-1.5">
        {status === "on" && <span className={`absolute inline-flex h-full w-full animate-ping rounded-full ${cls[0]} opacity-50`} />}
        <span className={`relative inline-flex h-1.5 w-1.5 rounded-full ${cls[0]}`} />
      </span>
      <Icon size={11} className="text-slate-600" />
      <span>{label}</span>
    </div>
  );
}
