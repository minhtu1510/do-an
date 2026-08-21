import { useEffect, useMemo, useState } from "react";
import {
  ShieldCheck, ExternalLink, Radio, AlertTriangle, Activity,
  Radar, Terminal, LockKeyhole, RefreshCw, Clock3,
  CircleDot, CheckCircle2, XCircle, FileWarning, Network, ChevronDown,
} from "lucide-react";
import { fetchSecurityStatus, fetchScenarioResults, fetchEvents, fetchSecurityModeComparator } from "../services/api";
import { connectWebSocket } from "../services/websocket";
import PageHeader from "../components/PageHeader";
import ExportCsvButton from "../components/ExportCsvButton";
import NotConfiguredNotice from "../components/NotConfiguredNotice";

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

  const activeAlarms = status?.active_alarm_count;
  const connected = status?.plc_connection === "CONNECTED" && status?.opcua_connection === "CONNECTED";
  const hasScenarioData = Boolean(status?.scenario_id && status.scenario_id !== "Not configured");
  const executed = status?.scenario_runs_executed ?? 0;
  const total = status?.scenario_runs_total ?? 0;
  const runProgress = total > 0 ? Math.min(100, Math.round((executed / total) * 100)) : 0;

  const posture = activeAlarms > 0
    ? { label: "ATTENTION REQUIRED", tone: "danger", detail: `${activeAlarms} active alarm${activeAlarms === 1 ? "" : "s"} require review` }
    : connected
      ? { label: "MONITORING", tone: "good", detail: "PLC and OPC UA telemetry are connected" }
      : { label: "DEGRADED", tone: "warn", detail: "One or more monitored connections are unavailable" };

  const latestAlert = alerts[0];

  return (
    <div className="space-y-6 p-4 sm:p-6 xl:p-8">
      <PageHeader
        icon={ShieldCheck}
        eyebrow="Detection & Evidence"
        title="Security / IDS"
        subtitle="Industrial intrusion-detection workspace for live security events, attack-scenario evidence and OPC UA security-mode validation."
        right={<ExportCsvButton severity="ERROR" label="Export alerts CSV" />}
      />

      <ThreatPosture
        posture={posture}
        activeAlarms={activeAlarms}
        alertCount={alerts.length}
        connected={connected}
        latestAlert={latestAlert}
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          icon={AlertTriangle}
          label="Active alarms"
          value={activeAlarms ?? "—"}
          detail={activeAlarms > 0 ? "Needs operator review" : "No active alarm"}
          tone={activeAlarms > 0 ? "danger" : "good"}
        />
        <MetricCard
          icon={Network}
          label="PLC / OPC UA"
          value={connected ? "CONNECTED" : status?.plc_connection || "LOADING"}
          detail={`Reconnect count: ${status?.reconnect_count ?? "N/A"}`}
          tone={connected ? "good" : "danger"}
          compact
        />
        <MetricCard
          icon={Radar}
          label="Security events"
          value={alerts.length}
          detail="ATTACK_* + ERROR severity"
          tone={alerts.length > 0 ? "danger" : "neutral"}
        />
        <MetricCard
          icon={Terminal}
          label="Scenario progress"
          value={`${executed}/${total}`}
          detail={total > 0 ? `${runProgress}% of configured runs` : "No configured runs"}
          tone={hasScenarioData ? "info" : "warn"}
          progress={runProgress}
        />
      </div>

      <div className="grid gap-4 2xl:grid-cols-[1.35fr_.65fr]">
        <LiveAlerts alerts={alerts} />
        <TelemetryPanel status={status} />
      </div>

      <ScenarioConsole results={results} executed={executed} total={total} />

      <SecurityModeComparator comparator={comparator} />
    </div>
  );
}

function ThreatPosture({ posture, activeAlarms, alertCount, connected, latestAlert }) {
  const tone = {
    good: {
      border: "border-emerald-400/15",
      glow: "from-emerald-400/[0.10]",
      icon: "border-emerald-400/20 bg-emerald-400/10 text-emerald-300",
      badge: "border-emerald-400/20 bg-emerald-400/10 text-emerald-300",
      dot: "bg-emerald-400",
    },
    warn: {
      border: "border-amber-400/20",
      glow: "from-amber-400/[0.10]",
      icon: "border-amber-400/20 bg-amber-400/10 text-amber-300",
      badge: "border-amber-400/20 bg-amber-400/10 text-amber-300",
      dot: "bg-amber-400",
    },
    danger: {
      border: "border-red-400/20",
      glow: "from-red-400/[0.11]",
      icon: "border-red-400/25 bg-red-400/10 text-red-300",
      badge: "border-red-400/25 bg-red-400/10 text-red-300",
      dot: "bg-red-400",
    },
  }[posture.tone];

  return (
    <section className={`relative overflow-hidden rounded-2xl border bg-gradient-to-br ${tone.glow} via-slate-900/70 to-slate-950/70 ${tone.border}`}>
      <div className="pointer-events-none absolute inset-0 opacity-[0.12]" style={{ backgroundImage: "linear-gradient(rgba(148,163,184,.08) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,.08) 1px, transparent 1px)", backgroundSize: "26px 26px" }} />
      <div className="ids-scanline pointer-events-none absolute left-0 right-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300 to-transparent" />

      <div className="relative grid gap-5 p-5 lg:grid-cols-[1fr_auto] lg:items-center lg:p-6">
        <div className="flex items-start gap-4">
          <div className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border ${tone.icon}`}>
            <ShieldCheck size={24} strokeWidth={2.1} />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="ids-label">Current threat posture</span>
              <span className={`ids-badge ${tone.badge}`}>
                <span className={`h-1.5 w-1.5 rounded-full ${tone.dot}`} />
                {posture.label}
              </span>
            </div>
            <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-100 sm:text-xl">Industrial control environment security status</h2>
            <p className="mt-1.5 text-sm text-slate-500">{posture.detail}. Security events are derived from the current backend state and scenario execution feed.</p>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-2 lg:min-w-[360px]">
          <PostureDatum label="Active" value={activeAlarms ?? "—"} danger={activeAlarms > 0} />
          <PostureDatum label="Events" value={alertCount} danger={alertCount > 0} />
          <PostureDatum label="Link" value={connected ? "UP" : "DOWN"} danger={!connected} small />
        </div>
      </div>

      {latestAlert && (
        <div className="relative flex flex-col gap-2 border-t border-slate-800/70 bg-slate-950/25 px-5 py-3 text-xs sm:flex-row sm:items-center sm:justify-between lg:px-6">
          <div className="flex min-w-0 items-center gap-2 text-slate-500">
            <CircleDot size={12} className="shrink-0 text-red-400" />
            <span className="font-medium text-slate-300">Latest:</span>
            <span className="truncate text-red-300">{latestAlert.event_type}</span>
            <span className="hidden truncate text-slate-600 md:inline">— {latestAlert.message}</span>
          </div>
          <span className="shrink-0 font-mono text-[10px] text-slate-600">{formatTime(latestAlert.timestamp)}</span>
        </div>
      )}
    </section>
  );
}

function PostureDatum({ label, value, danger, small }) {
  return (
    <div className="rounded-xl border border-slate-800/80 bg-slate-950/45 px-3 py-3 text-center">
      <div className="ids-label">{label}</div>
      <div className={`mt-1 font-mono font-semibold ${small ? "text-sm" : "text-xl"} ${danger ? "text-red-300" : "text-emerald-300"}`}>{value}</div>
    </div>
  );
}

function MetricCard({ icon: Icon, label, value, detail, tone = "neutral", compact, progress }) {
  const styles = {
    good: ["text-emerald-300", "bg-emerald-400/10 border-emerald-400/15", "bg-emerald-400"],
    danger: ["text-red-300", "bg-red-400/10 border-red-400/15", "bg-red-400"],
    warn: ["text-amber-300", "bg-amber-400/10 border-amber-400/15", "bg-amber-400"],
    info: ["text-cyan-300", "bg-cyan-400/10 border-cyan-400/15", "bg-cyan-400"],
    neutral: ["text-slate-200", "bg-slate-800/60 border-slate-700/70", "bg-slate-500"],
  }[tone];

  return (
    <div className="ids-card ids-card-hover overflow-hidden p-4">
      <div className="flex items-center justify-between gap-3">
        <div className={`flex h-9 w-9 items-center justify-center rounded-xl border ${styles[1]}`}>
          <Icon size={17} className={styles[0]} />
        </div>
        <div className={`h-1.5 w-1.5 rounded-full ${styles[2]} shadow-[0_0_9px_currentColor]`} />
      </div>
      <div className="mt-4 ids-label">{label}</div>
      <div className={`mt-1 font-mono font-semibold tracking-tight ${compact ? "text-lg" : "text-2xl"} ${styles[0]}`}>{value}</div>
      <div className="mt-1 text-[11px] text-slate-600">{detail}</div>
      {typeof progress === "number" && (
        <div className="mt-3 h-1 overflow-hidden rounded-full bg-slate-800">
          <div className={`h-full rounded-full ${styles[2]} transition-all`} style={{ width: `${progress}%` }} />
        </div>
      )}
    </div>
  );
}

function LiveAlerts({ alerts }) {
  return (
    <section className="ids-card overflow-hidden">
      <PanelHeader
        icon={Radar}
        title="Live security alerts"
        subtitle="ATTACK_* and ERROR-severity events from live tag / connection state"
        right={
          <span className={`ids-badge ${alerts.length > 0 ? "border-red-400/20 bg-red-400/10 text-red-300" : "border-emerald-400/15 bg-emerald-400/10 text-emerald-300"}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${alerts.length > 0 ? "bg-red-400" : "bg-emerald-400"}`} />
            {alerts.length} event{alerts.length === 1 ? "" : "s"}
          </span>
        }
      />

      {alerts.length === 0 ? (
        <EmptyState icon={CheckCircle2} title="No security alerts recorded" text="The current event feed contains no ATTACK_* or ERROR-severity events." good />
      ) : (
        <div className="max-h-[420px] divide-y divide-slate-800/70 overflow-y-auto">
          {alerts.map((event) => <AlertRow key={event.id} event={event} />)}
        </div>
      )}
    </section>
  );
}

function AlertRow({ event }) {
  const active = event.status === "ACTIVE";
  return (
    <div className="group grid gap-3 px-4 py-3.5 transition-colors hover:bg-red-400/[0.025] sm:grid-cols-[88px_1fr_auto] sm:items-center">
      <div className="flex items-center gap-2 font-mono text-[10px] text-slate-600">
        <Clock3 size={11} />
        {formatTime(event.timestamp)}
      </div>
      <div className="min-w-0 border-l-2 border-red-400/40 pl-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-semibold tracking-wide text-red-300">{event.event_type}</span>
          <span className="rounded-md bg-red-400/[0.08] px-1.5 py-0.5 text-[9px] font-semibold uppercase text-red-400">{event.severity || "SECURITY"}</span>
        </div>
        <div className="mt-1 truncate text-xs text-slate-500 group-hover:text-slate-400">{event.message || "No event message"}</div>
      </div>
      <span className={`ids-badge w-fit ${active ? "border-red-400/20 bg-red-400/10 text-red-300" : "border-emerald-400/15 bg-emerald-400/10 text-emerald-300"}`}>
        {active ? <XCircle size={10} /> : <CheckCircle2 size={10} />}
        {event.status || "RECORDED"}
      </span>
    </div>
  );
}

function TelemetryPanel({ status }) {
  const items = [
    { icon: RefreshCw, label: "Stale events", value: status?.stale_event_count ?? "N/A", tone: "neutral" },
    { icon: XCircle, label: "Rejected ops", value: status?.rejected_operation_count ?? "N/A", tone: "neutral" },
    { icon: LockKeyhole, label: "IDS module", value: status?.ids_module || "Loading", tone: status?.ids_module === "Model loaded" ? "good" : "warn" },
    { icon: Radio, label: "OPC UA", value: status?.opcua_connection || "Loading", tone: status?.opcua_connection === "CONNECTED" ? "good" : "danger" },
  ];

  return (
    <section className="ids-card overflow-hidden">
      <PanelHeader icon={Activity} title="Detection telemetry" subtitle="Current backend-backed IDS and collection state" />
      <div className="divide-y divide-slate-800/70 px-4">
        {items.map((item) => <TelemetryRow key={item.label} {...item} />)}
      </div>
    </section>
  );
}

function TelemetryRow({ icon: Icon, label, value, tone }) {
  const color = { good: "text-emerald-300", danger: "text-red-300", warn: "text-amber-300", info: "text-cyan-300", neutral: "text-slate-300" }[tone];
  return (
    <div className="flex items-center gap-3 py-3">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-slate-800 bg-slate-950/55 text-slate-600"><Icon size={14} /></div>
      <div className="min-w-0 flex-1">
        <div className="text-[10px] uppercase tracking-wider text-slate-600">{label}</div>
        <div className={`mt-0.5 truncate font-mono text-xs font-semibold ${color}`} title={String(value)}>{value}</div>
      </div>
    </div>
  );
}

function ScenarioConsole({ results, executed, total }) {
  const hasData = results.length > 0;
  const [open, setOpen] = useState(hasData);
  useEffect(() => {
    if (hasData) setOpen(true);
  }, [hasData]);

  return (
    <section className="ids-card overflow-hidden">
      <PanelHeader
        icon={Terminal}
        title="Attack scenario evidence"
        subtitle="Live scenario outcomes with MITRE ATT&CK mapping and captured evidence"
        right={
          <div className="flex items-center gap-2">
            <span className="ids-badge border-cyan-400/15 bg-cyan-400/[0.07] font-mono text-cyan-300">{executed}/{total} executed</span>
            <CollapseToggle open={open} onClick={() => setOpen((v) => !v)} />
          </div>
        }
      />

      {open && (results.length === 0 ? (
        <div className="p-5">
          <NotConfiguredNotice
            title="Chưa nhận được kịch bản tấn công nào"
            message="Chạy bộ kịch bản Day 8 trong lúc backend đang bật để console này có dữ liệu thật."
            detail="Lệnh chạy: python tests/day8/run_day8.py --execute (chạy trong lúc backend đang bật để kết quả tự đẩy vào đây qua API)."
          />
        </div>
      ) : (
        <div className="overflow-x-auto">
          <div className="min-w-[880px]">
            <div className="grid grid-cols-[82px_1.25fr_.65fr_.65fr_1.35fr] gap-3 border-b border-slate-800/70 bg-slate-950/30 px-4 py-2.5 ids-label">
              <div>Time</div><div>Scenario / ATT&CK</div><div>Group</div><div>Status</div><div>Evidence / notes</div>
            </div>
            <div className="max-h-[520px] divide-y divide-slate-800/70 overflow-y-auto">
              {results.map((result) => <ScenarioRow key={result.id} result={result} />)}
            </div>
          </div>
        </div>
      ))}
    </section>
  );
}

function CollapseToggle({ open, onClick }) {
  return (
    <button
      onClick={onClick}
      className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md border border-slate-800 bg-slate-950/50 text-slate-500 transition-colors hover:border-slate-700 hover:text-slate-300"
      title={open ? "Thu gọn" : "Mở rộng"}
    >
      <ChevronDown size={13} className={`transition-transform ${open ? "" : "-rotate-90"}`} />
    </button>
  );
}

const STATUS_STYLE = {
  EXECUTED: "border-emerald-400/15 bg-emerald-400/10 text-emerald-300",
  EXECUTED_GATED: "border-orange-400/15 bg-orange-400/10 text-orange-300",
  FAILED: "border-red-400/20 bg-red-400/10 text-red-300",
  GATED: "border-amber-400/20 bg-amber-400/10 text-amber-300",
  BLOCKED: "border-amber-400/20 bg-amber-400/10 text-amber-300",
  DRY_RUN: "border-slate-700 bg-slate-800/70 text-slate-300",
  NOT_CONFIGURED: "border-slate-800 bg-slate-900 text-slate-500",
  NO_EXECUTOR: "border-slate-800 bg-slate-900 text-slate-500",
};

function ScenarioRow({ result }) {
  const badge = STATUS_STYLE[result.status] || "border-slate-700 bg-slate-800/70 text-slate-300";
  const showSublabel = result.label && result.label !== result.scenario_id;
  const evidenceCount = result.evidence?.length || 0;

  return (
    <div className="grid grid-cols-[82px_1.25fr_.65fr_.65fr_1.35fr] gap-3 px-4 py-3.5 text-xs transition-colors hover:bg-cyan-400/[0.02]">
      <div className="flex items-start gap-1.5 pt-0.5 font-mono text-[10px] text-slate-600"><Clock3 size={10} className="mt-0.5" />{formatTime(result.received_at)}</div>
      <div className="min-w-0">
        <div className="truncate font-semibold text-slate-200">{result.scenario_id}</div>
        {showSublabel && <div className="mt-0.5 truncate text-[10px] text-slate-600">{result.label}</div>}
        {result.mitre_technique && (
          <a href={mitreUrl(result.mitre_technique)} target="_blank" rel="noreferrer" title={result.mitre_technique_name} className="mt-1.5 inline-flex items-center gap-1 rounded-md border border-violet-400/15 bg-violet-400/[0.07] px-1.5 py-0.5 font-mono text-[9px] text-violet-300 transition hover:border-violet-400/30 hover:bg-violet-400/10">
            ATT&CK {result.mitre_technique}<ExternalLink size={8} />
          </a>
        )}
      </div>
      <div className="pt-0.5 text-slate-500">{result.group || "—"}</div>
      <div><span className={`ids-badge ${badge}`}>{result.status || "UNKNOWN"}</span></div>
      <div className="min-w-0 text-slate-500">
        <div className="flex items-center gap-1.5 text-slate-400"><FileWarning size={11} className="text-slate-600" />{evidenceCount ? `${evidenceCount} evidence item${evidenceCount === 1 ? "" : "s"}` : "No evidence item"}</div>
        {result.notes?.length > 0 && <div className="mt-1 truncate text-[10px] text-slate-600" title={result.notes[0]}>{result.notes[0]}</div>}
      </div>
    </div>
  );
}

function SecurityModeComparator({ comparator }) {
  const modes = comparator?.security_modes || [];
  const rows = comparator?.rows || [];

  const summary = useMemo(() => {
    let recorded = 0;
    rows.forEach((row) => modes.forEach((mode) => { if (row[mode]) recorded += 1; }));
    return recorded;
  }, [rows, modes]);

  const hasData = rows.length > 0;
  const [open, setOpen] = useState(hasData);
  useEffect(() => {
    if (hasData) setOpen(true);
  }, [hasData]);

  return (
    <section className="ids-card overflow-hidden">
      <PanelHeader
        icon={LockKeyhole}
        title="OPC UA security-mode comparator"
        subtitle="Real scenario outcomes grouped by the operator-provided OPCUA_SECURITY_MODE tag"
        right={
          <div className="flex items-center gap-2">
            <span className="ids-badge border-slate-700 bg-slate-950/50 text-slate-400">{summary} recorded outcome{summary === 1 ? "" : "s"}</span>
            <CollapseToggle open={open} onClick={() => setOpen((v) => !v)} />
          </div>
        }
      />

      {!open ? null : rows.length === 0 ? (
        <div className="p-5">
          <NotConfiguredNotice
            title="Chưa có dữ liệu so sánh theo security mode"
            message="Chạy cùng bộ kịch bản OPC UA ở từng chế độ bảo mật, gắn nhãn mode tương ứng, để bảng này so sánh được kết quả thật."
            detail={"Ví dụ chạy mode Anonymous:\nOPCUA_SECURITY_MODE=Anonymous python tests/day8/run_day8.py --group opcua --execute --allow-gated\n\nSau đó cấu hình lại server sang Basic256Sha256 và chạy lại với OPCUA_SECURITY_MODE=Basic256Sha256 để có dữ liệu đối chiếu."}
          />
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[680px] text-left text-xs">
            <thead className="border-b border-slate-800/70 bg-slate-950/30 ids-label">
              <tr>
                <th className="px-4 py-3">Scenario</th>
                {modes.map((mode) => <th key={mode} className="px-4 py-3">{mode}</th>)}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {rows.map((row) => (
                <tr key={row.scenario_id} className="transition-colors hover:bg-cyan-400/[0.02]">
                  <td className="px-4 py-3 font-mono text-[11px] font-medium text-slate-300">{row.scenario_id}</td>
                  {modes.map((mode) => <td key={mode} className="px-4 py-3"><ComparatorCell result={row[mode]} /></td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function ComparatorCell({ result }) {
  if (!result) return <span className="text-[10px] text-slate-700">NOT RUN</span>;
  const badge = STATUS_STYLE[result.status] || "border-slate-700 bg-slate-800/70 text-slate-300";
  return (
    <div>
      <span className={`ids-badge ${badge}`}>{result.status}</span>
      <div className="mt-1.5 flex items-center gap-1 font-mono text-[9px] text-slate-700"><Clock3 size={9} />{formatTime(result.received_at)}</div>
    </div>
  );
}

function PanelHeader({ icon: Icon, title, subtitle, right }) {
  return (
    <div className="flex flex-col gap-3 border-b border-slate-800/70 bg-slate-950/20 px-4 py-3.5 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex min-w-0 items-start gap-3">
        <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-slate-800 bg-slate-950/65 text-cyan-400"><Icon size={14} /></div>
        <div className="min-w-0">
          <div className="ids-section-title">{title}</div>
          {subtitle && <div className="ids-section-subtitle">{subtitle}</div>}
        </div>
      </div>
      {right && <div className="shrink-0">{right}</div>}
    </div>
  );
}

function EmptyState({ icon: Icon, title, text, good }) {
  return (
    <div className="flex min-h-[180px] flex-col items-center justify-center px-6 py-8 text-center">
      <div className={`flex h-11 w-11 items-center justify-center rounded-2xl border ${good ? "border-emerald-400/15 bg-emerald-400/[0.07] text-emerald-300" : "border-slate-800 bg-slate-950/50 text-slate-600"}`}><Icon size={19} /></div>
      <div className="mt-3 text-sm font-medium text-slate-300">{title}</div>
      <div className="mt-1 max-w-lg text-xs leading-relaxed text-slate-600">{text}</div>
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
