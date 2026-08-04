import { useEffect, useState } from "react";
import { fetchSecurityStatus, fetchScenarioResults, fetchEvents, fetchSecurityModeComparator } from "../services/api";
import { connectWebSocket } from "../services/websocket";
import PageHeader from "../components/PageHeader";
import ExportCsvButton from "../components/ExportCsvButton";

function isSecurityEvent(event) {
  return event.event_type?.startsWith("ATTACK_") || event.severity === "ERROR";
}

export default function SecurityView() {
  const [status, setStatus] = useState(null);
  const [results, setResults] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [comparator, setComparator] = useState(null);

  useEffect(() => {
    fetchSecurityStatus().then(setStatus);
    fetchScenarioResults().then((data) => setResults(data.results || []));
    fetchEvents().then((data) => setAlerts((data.events || []).filter(isSecurityEvent)));
    fetchSecurityModeComparator().then(setComparator);
    const timer = setInterval(() => {
      fetchSecurityStatus().then(setStatus);
      fetchScenarioResults().then((data) => setResults(data.results || []));
      fetchSecurityModeComparator().then(setComparator);
    }, 5000);

    const unsub = connectWebSocket((data) => {
      if (data.type === "scenario_result" && data.result) {
        setResults((prev) => [data.result, ...prev].slice(0, 50));
        fetchSecurityStatus().then(setStatus);
        if (data.result.security_mode) fetchSecurityModeComparator().then(setComparator);
      }
      if (data.type === "event" && data.event && isSecurityEvent(data.event)) {
        setAlerts((prev) => [data.event, ...prev].slice(0, 50));
      }
    });

    return () => {
      clearInterval(timer);
      unsub();
    };
  }, []);

  const hasScenarioData = Boolean(status?.scenario_id && status.scenario_id !== "Not configured");
  const activeAlarms = status?.active_alarm_count;
  const alarmAccent = activeAlarms > 0 ? "#e66767" : "#0ca30c";
  const connected = status?.plc_connection === "CONNECTED" && status?.opcua_connection === "CONNECTED";

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        title="Security / IDS"
        subtitle="Security view shows only metrics backed by the current backend. IDS collection fields remain explicit placeholders."
        right={<ExportCsvButton severity="ERROR" label="Export alerts CSV" />}
      />

      {/* Z-pattern: the number that matters most (active alarms) sits top-left,
          where the eye lands first, ahead of every secondary detail below. */}
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="overflow-hidden rounded border border-gray-700 bg-gray-800">
          <div className="h-1" style={{ backgroundColor: alarmAccent }} />
          <div className="p-4">
            <div className="text-xs uppercase text-gray-500">Active alarm count</div>
            <div className="mt-1 text-3xl font-bold" style={{ color: alarmAccent }}>{activeAlarms ?? "—"}</div>
          </div>
        </div>
        <div className="overflow-hidden rounded border border-gray-700 bg-gray-800">
          <div className="h-1" style={{ backgroundColor: connected ? "#0ca30c" : "#e66767" }} />
          <div className="p-4">
            <div className="text-xs uppercase text-gray-500">PLC / OPC UA connection</div>
            <div className="mt-1 text-lg font-bold" style={{ color: connected ? "#0ca30c" : "#e66767" }}>
              {status?.plc_connection || "Loading"}
            </div>
            <div className="text-xs text-gray-500">Reconnect count: {status?.reconnect_count ?? "N/A"}</div>
          </div>
        </div>
        <div className="overflow-hidden rounded border border-gray-700 bg-gray-800">
          <div className="h-1" style={{ backgroundColor: hasScenarioData ? "#3987e5" : "#c98500" }} />
          <div className="p-4">
            <div className="text-xs uppercase text-gray-500">Kịch bản gần nhất</div>
            <div className="mt-1 truncate text-lg font-bold text-gray-100">{status?.scenario_id || "Not configured"}</div>
            <div className="text-xs text-gray-500">{status?.current_label || "Not configured"}</div>
          </div>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        <SecurityItem label="Stale event count" value={status?.stale_event_count ?? "N/A"} />
        <SecurityItem label="Rejected operation count" value={status?.rejected_operation_count ?? "N/A"} />
        <SecurityItem label="Capture status" value={status?.capture_status || "Not configured"} tone="warn" />
        <SecurityItem label="Dataset session ID" value={status?.dataset_session_id || "No active collection"} tone="warn" />
        <SecurityItem label="IDS module" value={status?.ids_module || "IDS module unavailable"} tone="warn" />
      </div>

      <div className="bg-gray-800 rounded border border-gray-700 overflow-hidden">
        <div className="flex items-center justify-between border-b border-gray-700 px-4 py-3">
          <div>
            <div className="text-sm font-semibold text-gray-200">Live Security Alerts</div>
            <div className="text-xs text-gray-500">ATTACK_* and ERROR-severity events derived from live tag/connection state.</div>
          </div>
          <span className={`rounded border px-2 py-1 text-xs font-mono ${alerts.length > 0 ? "border-red-700 bg-red-950/40 text-red-300" : "border-gray-700 bg-gray-900 text-gray-400"}`}>
            {alerts.length} alert(s)
          </span>
        </div>

        {alerts.length === 0 ? (
          <div className="p-6 text-sm text-gray-500">No security alerts recorded yet.</div>
        ) : (
          <div className="divide-y divide-gray-700">
            {alerts.map((event) => (
              <div key={event.id} className="grid gap-3 px-4 py-3 md:grid-cols-[140px_1fr_100px] md:items-center">
                <div className="text-xs text-gray-500">{formatTime(event.timestamp)}</div>
                <div>
                  <div className="text-sm font-semibold text-red-300">{event.event_type}</div>
                  <div className="text-xs text-gray-500">{event.message}</div>
                </div>
                <div className={`text-xs font-bold ${event.status === "ACTIVE" ? "text-red-400" : "text-green-400"}`}>{event.status}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      <SecurityModeComparator comparator={comparator} />

      <div className="bg-gray-800 rounded border border-gray-700 overflow-hidden">
        <div className="flex items-center justify-between border-b border-gray-700 px-4 py-3">
          <div>
            <div className="text-sm font-semibold text-gray-200">Attack Scenario Console</div>
            <div className="text-xs text-gray-500">Live feed from tests/day8/run_day8.py — one row per finished scenario run.</div>
          </div>
          <span className="rounded bg-gray-900 border border-gray-700 px-2 py-1 text-xs font-mono text-gray-400">
            {status?.scenario_runs_executed ?? 0}/{status?.scenario_runs_total ?? 0} executed
          </span>
        </div>

        {results.length === 0 ? (
          <div className="p-6 text-sm text-gray-500">
            No scenario runs received yet. Run{" "}
            <code className="rounded bg-gray-900 px-1.5 py-0.5 text-gray-300">python tests/day8/run_day8.py --execute</code>{" "}
            while this backend is up to see results appear here live.
          </div>
        ) : (
          <div className="divide-y divide-gray-700">
            {results.map((r) => (
              <ScenarioRow key={r.id} result={r} />
            ))}
          </div>
        )}
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

const STATUS_STYLE = {
  EXECUTED: "text-green-300 bg-green-950/40",
  EXECUTED_GATED: "text-orange-300 bg-orange-950/40",
  FAILED: "text-red-300 bg-red-950/40",
  GATED: "text-yellow-300 bg-yellow-950/40",
  BLOCKED: "text-yellow-300 bg-yellow-950/40",
  DRY_RUN: "text-gray-300 bg-gray-900",
  NOT_CONFIGURED: "text-gray-400 bg-gray-900",
  NO_EXECUTOR: "text-gray-400 bg-gray-900",
};

function ScenarioRow({ result }) {
  const badge = STATUS_STYLE[result.status] || "text-gray-300 bg-gray-900";
  const showSublabel = result.label && result.label !== result.scenario_id;
  return (
    <div className="grid gap-3 px-4 py-3 md:grid-cols-[110px_1fr_90px_130px_1.4fr] md:items-start">
      <div className="text-xs text-gray-500 pt-0.5">{formatTime(result.received_at)}</div>
      <div>
        <div className="text-sm font-semibold text-gray-200">{result.scenario_id}</div>
        {showSublabel && <div className="text-[10px] text-gray-600">{result.label}</div>}
        {result.mitre_technique && (
          <a
            href={mitreUrl(result.mitre_technique)}
            target="_blank"
            rel="noreferrer"
            title={result.mitre_technique_name}
            className="mt-1 inline-block rounded border border-purple-800 bg-purple-950/40 px-1.5 py-0.5 text-[10px] font-mono text-purple-300 hover:border-purple-500"
          >
            ATT&CK {result.mitre_technique}
          </a>
        )}
      </div>
      <div className="text-xs text-gray-400 pt-0.5">{result.group}</div>
      <div>
        <span className={`rounded px-2 py-1 text-[10px] font-bold ${badge}`}>{result.status}</span>
      </div>
      <div className="text-xs text-gray-500">
        {result.evidence?.length ? `${result.evidence.length} evidence item(s)` : "—"}
        {result.notes?.length ? ` · ${result.notes[0]}` : ""}
      </div>
    </div>
  );
}

function SecurityModeComparator({ comparator }) {
  const modes = comparator?.security_modes || [];
  const rows = comparator?.rows || [];

  return (
    <div className="bg-gray-800 rounded border border-gray-700 overflow-hidden">
      <div className="border-b border-gray-700 px-4 py-3">
        <div className="text-sm font-semibold text-gray-200">OPC UA Security Mode Comparator</div>
        <div className="text-xs text-gray-500">
          Real outcomes only — grouped by the security_mode tag the operator sets via{" "}
          <code className="rounded bg-gray-900 px-1.5 py-0.5 text-gray-300">OPCUA_SECURITY_MODE</code> when running{" "}
          <code className="rounded bg-gray-900 px-1.5 py-0.5 text-gray-300">tests/day8/run_day8.py</code>. Nothing is hard-coded.
        </div>
      </div>

      {rows.length === 0 ? (
        <div className="p-6 text-sm text-gray-500">
          No tagged runs yet. Run the OPC UA scenarios once per mode, e.g.{" "}
          <code className="rounded bg-gray-900 px-1.5 py-0.5 text-gray-300">
            OPCUA_SECURITY_MODE=Anonymous python tests/day8/run_day8.py --group opcua --execute --allow-gated
          </code>
          , reconfigure the server to Basic256Sha256, then run again with that mode — this table fills in as real results arrive.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-gray-900/60 text-xs uppercase text-gray-500">
              <tr>
                <th className="px-4 py-2">Scenario</th>
                {modes.map((mode) => (
                  <th key={mode} className="px-4 py-2">{mode}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {rows.map((row) => (
                <tr key={row.scenario_id}>
                  <td className="px-4 py-2 font-mono text-xs text-gray-300">{row.scenario_id}</td>
                  {modes.map((mode) => (
                    <td key={mode} className="px-4 py-2">
                      <ComparatorCell result={row[mode]} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ComparatorCell({ result }) {
  if (!result) return <span className="text-xs text-gray-600">not run</span>;
  const badge = STATUS_STYLE[result.status] || "text-gray-300 bg-gray-900";
  return (
    <div>
      <span className={`rounded px-2 py-1 text-[10px] font-bold ${badge}`}>{result.status}</span>
      <div className="mt-1 text-[10px] text-gray-600">{formatTime(result.received_at)}</div>
    </div>
  );
}

function formatTime(value) {
  if (!value) return "N/A";
  return new Date(value).toLocaleTimeString();
}

function mitreUrl(techniqueId) {
  const [base, sub] = techniqueId.split(".");
  return sub ? `https://attack.mitre.org/techniques/${base}/${sub}/` : `https://attack.mitre.org/techniques/${base}/`;
}
