import { Info } from "lucide-react";
import { useAuth } from "../stores/authStore";

// Honest "not configured" state, without leaking a local absolute filesystem
// path / exact CLI command into the primary UI text. The headline stays
// short and presentable; the actual remediation detail (path, command) is
// only shown to admin — the one role that would actually run setup commands
// — so a regular viewer/operator never sees internal paths or scripts.
// Shown directly (no expand/collapse click) once role allows it — an admin
// looking at this is already mid-setup, an extra click to reveal the exact
// command they need was just friction, not information hiding.
export default function NotConfiguredNotice({ title, message, detail, tone = "warn" }) {
  const { hasRole } = useAuth();
  const canSeeDetail = hasRole("admin");
  const toneCls =
    tone === "warn"
      ? "border-amber-400/25 bg-amber-400/[0.06] text-amber-300"
      : "border-slate-700 bg-slate-900/50 text-slate-400";

  return (
    <div className={`rounded-xl border p-4 ${toneCls}`}>
      <div className="flex items-start gap-2.5">
        <Info size={15} className="mt-0.5 shrink-0" />
        <div className="min-w-0">
          <div className="text-sm font-semibold">{title}</div>
          {message && <div className="mt-1 text-xs leading-relaxed opacity-80">{message}</div>}
        </div>
      </div>
      {detail && canSeeDetail && (
        <pre className="mt-2 ml-[26px] whitespace-pre-wrap break-all rounded-lg border border-black/20 bg-black/20 px-3 py-2 font-mono text-[11px] leading-relaxed opacity-90">
          {detail}
        </pre>
      )}
    </div>
  );
}
