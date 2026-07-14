import { useEffect, useState } from "react";
import { fetchSecurityStatus } from "../services/api";

export default function SecurityView() {
  const [status, setStatus] = useState(null);

  useEffect(() => {
    fetchSecurityStatus().then(setStatus);
    const timer = setInterval(() => fetchSecurityStatus().then(setStatus), 5000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-100">Security / IDS</h1>
        <p className="text-sm text-gray-500">Security view shows only metrics backed by the current backend. IDS collection fields remain explicit placeholders.</p>
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        <SecurityItem label="PLC connection" value={status?.plc_connection || "Loading"} tone={status?.plc_connection === "CONNECTED" ? "good" : "bad"} />
        <SecurityItem label="OPC UA connection" value={status?.opcua_connection || "Loading"} tone={status?.opcua_connection === "CONNECTED" ? "good" : "bad"} />
        <SecurityItem label="Reconnect count" value={status?.reconnect_count ?? "N/A"} />
        <SecurityItem label="Active alarm count" value={status?.active_alarm_count ?? "N/A"} />
        <SecurityItem label="Stale event count" value={status?.stale_event_count ?? "N/A"} />
        <SecurityItem label="Rejected operation count" value={status?.rejected_operation_count ?? "N/A"} />
        <SecurityItem label="Capture status" value={status?.capture_status || "Not configured"} tone="warn" />
        <SecurityItem label="Dataset session ID" value={status?.dataset_session_id || "No active collection"} tone="warn" />
        <SecurityItem label="Scenario ID" value={status?.scenario_id || "Not configured"} tone="warn" />
        <SecurityItem label="Current label" value={status?.current_label || "Not configured"} tone="warn" />
        <SecurityItem label="IDS module" value={status?.ids_module || "IDS module unavailable"} tone="warn" />
      </div>
    </div>
  );
}

function SecurityItem({ label, value, tone = "neutral" }) {
  const color = {
    good: "text-green-400",
    bad: "text-red-400",
    warn: "text-yellow-400",
    neutral: "text-gray-300",
  }[tone];

  return (
    <div className="rounded border border-gray-700 bg-gray-800 px-4 py-3">
      <div className="text-xs uppercase text-gray-500">{label}</div>
      <div className={`mt-1 font-mono text-sm font-bold ${color}`}>{value}</div>
    </div>
  );
}
