import { useState } from "react";
import { apiFetch } from "../services/api";

export default function ExportCsvButton({ severity, status, label = "Export CSV" }) {
  const [busy, setBusy] = useState(false);

  async function handleClick() {
    const params = new URLSearchParams();
    if (severity) params.set("severity", severity);
    if (status) params.set("status", status);
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
      className="inline-flex items-center gap-1.5 rounded border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs font-semibold text-gray-300 hover:border-blue-600 hover:text-blue-300 disabled:opacity-50"
    >
      ⬇ {busy ? "..." : label}
    </button>
  );
}
