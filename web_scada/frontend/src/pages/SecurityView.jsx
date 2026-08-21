import { useEffect, useMemo, useState } from "react";
import { Terminal, ExternalLink, LockKeyhole, Clock3, FileWarning, ChevronDown } from "lucide-react";
import { fetchSecurityStatus, fetchScenarioResults, fetchSecurityModeComparator } from "../services/api";
import { connectWebSocket } from "../services/websocket";
import PageHeader from "../components/PageHeader";
import NotConfiguredNotice from "../components/NotConfiguredNotice";

// Scope of this page is deliberately narrow: it only holds what's unique to
// attack-scenario evidence (Day 8, OPC UA) — live security alerts and
// connection/IDS telemetry used to live here too, but that duplicated
// Alarms & Events / Process Monitor / System Status, so it now lives only in
// those pages.
export default function SecurityView() {
  const [status, setStatus] = useState(null);
  const [results, setResults] = useState([]);
  const [comparator, setComparator] = useState(null);

  useEffect(() => {
    fetchSecurityStatus().then(setStatus);
    fetchScenarioResults().then((data) => setResults(data.results || []));
    fetchSecurityModeComparator().then(setComparator);

    const timer = setInterval(() => {
      fetchSecurityStatus().then(setStatus);
      fetchSecurityModeComparator().then(setComparator);
    }, 5000);

    const unsub = connectWebSocket((data) => {
      if (data.type === "scenario_result" && data.result) {
        setResults((prev) => [data.result, ...prev].slice(0, 50));
        fetchSecurityStatus().then(setStatus);
        if (data.result.security_mode) fetchSecurityModeComparator().then(setComparator);
      }
    });

    return () => {
      clearInterval(timer);
      unsub();
    };
  }, []);

  const executed = status?.scenario_runs_executed ?? 0;
  const total = status?.scenario_runs_total ?? 0;
  const runProgress = total > 0 ? Math.min(100, Math.round((executed / total) * 100)) : 0;

  return (
    <div className="space-y-6 p-4 sm:p-6 xl:p-8">
      <PageHeader
        icon={Terminal}
        eyebrow="Lịch sử & báo cáo"
        title="Lịch sử kịch bản tấn công"
        subtitle="Kết quả các kịch bản tấn công đã chạy (Day 8, giao thức OPC UA) với ánh xạ MITRE ATT&CK, và so sánh hiệu quả theo chế độ bảo mật OPC UA."
      />

      <ScenarioConsole results={results} executed={executed} total={total} runProgress={runProgress} />

      <SecurityModeComparator comparator={comparator} />
    </div>
  );
}

function ScenarioConsole({ results, executed, total, runProgress }) {
  const hasData = results.length > 0;
  const [open, setOpen] = useState(hasData);
  useEffect(() => {
    if (hasData) setOpen(true);
  }, [hasData]);

  return (
    <section className="ids-card overflow-hidden">
      <PanelHeader
        icon={Terminal}
        title="Bằng chứng kịch bản tấn công"
        subtitle="Kết quả kịch bản tấn công thời gian thực, gắn kỹ thuật MITRE ATT&CK và bằng chứng thu thập được"
        right={
          <div className="flex items-center gap-2">
            <span className="ids-badge border-cyan-400/15 bg-cyan-400/[0.07] font-mono text-cyan-300">
              {executed}/{total} đã chạy{total > 0 ? ` (${runProgress}%)` : ""}
            </span>
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
              <div>Thời gian</div><div>Kịch bản / ATT&CK</div><div>Nhóm</div><div>Trạng thái</div><div>Bằng chứng / ghi chú</div>
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
        <div className="flex items-center gap-1.5 text-slate-400"><FileWarning size={11} className="text-slate-600" />{evidenceCount ? `${evidenceCount} bằng chứng` : "Chưa có bằng chứng"}</div>
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
        title="So sánh chế độ bảo mật OPC UA"
        subtitle="Kết quả kịch bản thật, nhóm theo tag OPCUA_SECURITY_MODE do người vận hành khai báo"
        right={
          <div className="flex items-center gap-2">
            <span className="ids-badge border-slate-700 bg-slate-950/50 text-slate-400">{summary} kết quả đã ghi nhận</span>
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
                <th className="px-4 py-3">Kịch bản</th>
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
  if (!result) return <span className="text-[10px] text-slate-700">CHƯA CHẠY</span>;
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

function formatTime(value) {
  if (!value) return "N/A";
  return new Date(value).toLocaleTimeString();
}

function mitreUrl(techniqueId) {
  const [base, sub] = techniqueId.split(".");
  return sub ? `https://attack.mitre.org/techniques/${base}/${sub}/` : `https://attack.mitre.org/techniques/${base}/`;
}
