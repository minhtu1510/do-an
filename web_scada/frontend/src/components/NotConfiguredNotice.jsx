import { useState } from "react";
import { ChevronDown, Info } from "lucide-react";
import { useAuth } from "../stores/authStore";

// Honest "not configured" state, without leaking a local absolute filesystem
// path / exact CLI command into the primary UI text. The headline stays
// short and presentable; the actual remediation detail (path, command) is
// only shown to admin — the one role that would actually run setup commands
// — so a regular viewer/operator never sees internal paths or scripts.
export default function NotConfiguredNotice({ title, message, detail, tone = "warn" }) {
  const { hasRole } = useAuth();
  const [open, setOpen] = useState(false);
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
        <div className="mt-2 pl-[26px]">
          <button
            onClick={() => setOpen((v) => !v)}
            className="flex items-center gap-1 text-[11px] font-medium opacity-70 transition-opacity hover:opacity-100"
          >
            <ChevronDown size={12} className={`transition-transform ${open ? "rotate-180" : ""}`} />
            {open ? "Ẩn chi tiết kỹ thuật" : "Xem chi tiết kỹ thuật"}
          </button>
          {open && (
            <pre className="mt-2 whitespace-pre-wrap break-all rounded-lg border border-black/20 bg-black/20 px-3 py-2 font-mono text-[11px] leading-relaxed opacity-90">
              {detail}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
