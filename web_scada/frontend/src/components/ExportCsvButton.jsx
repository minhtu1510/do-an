import { useState } from "react";
import { Download, Loader2 } from "lucide-react";
import { apiFetch } from "../services/api";

export default function ExportCsvButton({ severity, status, eventTypes, excludeEventTypes, label = "Export CSV" }) {
  const [busy, setBusy] = useState(false);

  async function handleClick() {
    const params = new URLSearchParams();
    if (severity) params.set("severity", severity);
    if (status) params.set("status", status);
    if (eventTypes) params.set("event_types", eventTypes.join(","));
    if (excludeEventTypes) params.set("exclude_event_types", excludeEventTypes.join(","));
    const query = params.toString();

    setBusy(true);
    try {
      const res = await apiFetch(`/events/export/csv${query ? `?${query}` : ""}`);
      if (!res.ok) return;
      const blob = await res.blob();
      const filename = res.headers.get("Content-Disposition")?.match(/filename=(.+)/)?.[1] || "web_scada_events.csv";
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setBusy(false);
    }
  }

  return (
    <button
      onClick={handleClick}
      disabled={busy}
      className="inline-flex items-center gap-2 rounded-xl border border-slate-700/80 bg-slate-900/70 px-3 py-2 text-xs font-medium text-slate-300 shadow-sm transition-all hover:border-cyan-400/30 hover:bg-cyan-400/[0.06] hover:text-cyan-200 disabled:cursor-not-allowed disabled:opacity-50"
    >
      {busy ? <Loader2 size={13} className="animate-spin" /> : <Download size={13} />}
      {label}
    </button>
  );
}
