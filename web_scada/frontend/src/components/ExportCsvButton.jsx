const API_BASE = "/api";

export default function ExportCsvButton({ severity, status, label = "Export CSV" }) {
  const params = new URLSearchParams();
  if (severity) params.set("severity", severity);
  if (status) params.set("status", status);
  const query = params.toString();
  const href = `${API_BASE}/events/export/csv${query ? `?${query}` : ""}`;

  return (
    <a
      href={href}
      download
      className="inline-flex items-center gap-1.5 rounded border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs font-semibold text-gray-300 hover:border-blue-600 hover:text-blue-300"
    >
      ⬇ {label}
    </a>
  );
}
