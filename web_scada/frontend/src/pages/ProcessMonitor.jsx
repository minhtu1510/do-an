import { useState, useEffect } from "react";
import { Workflow, ChevronDown, AlertTriangle, Play, Square, Send } from "lucide-react";
import { connectWebSocket } from "../services/websocket";
import { fetchAllTags, writeTag } from "../services/api";
import { useAuth } from "../stores/authStore";
import TagCard from "../components/TagCard";
import PageHeader from "../components/PageHeader";

export default function ProcessMonitor() {
  const { hasRole } = useAuth();
  const [tags, setTags] = useState({});

  useEffect(() => {
    fetchAllTags().then((data) => {
      if (data.tags) {
        const map = {};
        data.tags.forEach((t) => (map[t.key] = t));
        setTags(map);
      }
    });
    const unsub = connectWebSocket((data) => {
      if (data.type === "tag_update") {
        setTags((prev) => ({ ...prev, [data.key]: data.data }));
      }
      if (data.type === "full_state" && data.tags) {
        const map = {};
        data.tags.forEach((t) => (map[t.key] = t));
        setTags(map);
      }
    });
    return unsub;
  }, []);

  const bangTai = tags.bang_tai;
  const isRunning = !bangTai?.stale && bangTai?.value === true;
  const offline = !bangTai || bangTai.stale;
  const conveyorLabel = offline ? "OFFLINE" : isRunning ? "RUNNING" : "STOPPED";

  const stageTagsFresh = ["vat_1", "vat_2", "vat_3"].every((k) => tags[k] && !tags[k].stale);
  const sensorSpoofSuspected =
    stageTagsFresh && tags.vat_1.value === true && tags.vat_2.value === true && tags.vat_3.value === true;

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        icon={Workflow}
        title="Process Monitor"
        subtitle="Motor/conveyor, internal stage bits, counters, and stage timers from live OPC UA tags."
      />

      <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
        <div className="rounded-lg border border-gray-700 bg-gray-800 p-6 shadow-sm shadow-black/20">
          <div className="mb-6 flex items-center justify-between">
            <div>
              <div className="text-sm font-semibold text-gray-200">Line flow</div>
              <div className="text-xs text-gray-500">No physical sensor is drawn unless a subscribed tag exists.</div>
            </div>
            <span className={`rounded px-2 py-1 text-xs font-bold ${offline ? "bg-red-950 text-red-400" : isRunning ? "bg-green-950 text-green-400" : "bg-yellow-950 text-yellow-400"}`}>
              {conveyorLabel}
            </span>
          </div>

          {sensorSpoofSuspected && (
            <div className="mb-4 flex items-start gap-2 rounded-lg border border-red-600 bg-red-950/40 px-4 py-3 text-sm font-semibold text-red-300 animate-fade-in">
              <AlertTriangle size={16} className="mt-0.5 shrink-0" />
              <span>
                Sensor spoof suspected — vat_1, vat_2 and vat_3 are all active at the same time,
                which is not physically possible on a single-lane conveyor.
              </span>
            </div>
          )}

          <div className="flex flex-col items-center gap-3">
            <FlowNode label="Motor / Conveyor" tag={bangTai} active={isRunning} offline={offline} value={conveyorLabel} />
            <Arrow />
            <FlowNode label="Stage 1" tag={tags.vat_1} active={!tags.vat_1?.stale && tags.vat_1?.value === true} value={stageValue(tags.vat_1)} danger={sensorSpoofSuspected} />
            <Arrow />
            <FlowNode label="Stage 2" tag={tags.vat_2} active={!tags.vat_2?.stale && tags.vat_2?.value === true} value={stageValue(tags.vat_2)} danger={sensorSpoofSuspected} />
            <Arrow />
            <FlowNode label="Stage 3" tag={tags.vat_3} active={!tags.vat_3?.stale && tags.vat_3?.value === true} value={stageValue(tags.vat_3)} danger={sensorSpoofSuspected} />
            <Arrow />
            <FlowNode label="Product counter" tag={tags.hien_thi} active={!tags.hien_thi?.stale} value={counterValue(tags.hien_thi)} />
          </div>

          {hasRole("controller") && (
            <ControlPanel bangTai={bangTai} isRunning={isRunning} offline={offline} nhap={tags.nhap} />
          )}
        </div>

        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            <TagCard label={tags.nhap?.display_name || "Target production quantity"} sublabel="nhap" value={tags.nhap?.value} quality={tags.nhap?.quality} stale={tags.nhap?.stale} />
            <TagCard label={tags.hien_thi?.display_name || "Completed production quantity"} sublabel="hien_thi" value={tags.hien_thi?.value} quality={tags.hien_thi?.quality} stale={tags.hien_thi?.stale} />
          </div>

          <div className="rounded-lg border border-gray-700 bg-gray-800 p-4 shadow-sm shadow-black/20">
            <div className="mb-3 text-sm font-semibold text-gray-200">Stage timers</div>
            <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-1">
              {["cd1", "cd2", "cd3"].map((key) => {
                const t = tags[key];
                return (
                  <TagCard key={key} label={t?.display_name || key} sublabel={key} value={t?.value} unit={t?.unit || "ms"} quality={t?.quality} stale={t?.stale} />
                );
              })}
            </div>
          </div>

          <div className="rounded-lg border border-gray-700 bg-gray-800 p-4 shadow-sm shadow-black/20">
            <div className="mb-3 text-sm font-semibold text-gray-200">Subscribed process tags</div>
            <div className="space-y-2">
              {["bang_tai", "vat_1", "vat_2", "vat_3", "nhap", "hien_thi", "cd1", "cd2", "cd3"].map((key) => {
                const t = tags[key];
                return <TagRow key={key} tag={t} fallbackKey={key} />;
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function ControlPanel({ bangTai, isRunning, offline, nhap }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [target, setTarget] = useState("");

  async function handleConveyorToggle() {
    const nextValue = !isRunning;
    const verb = nextValue ? "CHẠY (RUN)" : "DỪNG (STOP)";
    if (!window.confirm(`Gửi lệnh ${verb} băng tải xuống PLC thật? Hành động này có tác động vật lý ngay lập tức.`)) return;
    setError(null);
    setBusy(true);
    try {
      await writeTag("bang_tai", nextValue);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleSetTarget(e) {
    e.preventDefault();
    const value = Number(target);
    if (!Number.isFinite(value)) return;
    if (!window.confirm(`Gửi số lượng sản phẩm mục tiêu = ${value} xuống PLC thật?`)) return;
    setError(null);
    setBusy(true);
    try {
      await writeTag("nhap", value);
      setTarget("");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-lg border border-amber-700/40 bg-amber-950/10 p-4 shadow-sm shadow-black/20">
      <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-amber-300">
        <AlertTriangle size={14} />
        Control Panel — ghi lệnh trực tiếp xuống PLC thật
      </div>

      {error && (
        <div className="mb-3 rounded border border-red-900/50 bg-red-950/30 px-3 py-2 text-xs text-red-400">{error}</div>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <button
          onClick={handleConveyorToggle}
          disabled={busy || offline}
          className={`flex items-center gap-1.5 rounded px-4 py-1.5 text-sm font-semibold text-white shadow-sm transition-colors disabled:opacity-50 ${
            isRunning ? "bg-red-600 hover:bg-red-500" : "bg-green-600 hover:bg-green-500"
          }`}
        >
          {isRunning ? <Square size={14} /> : <Play size={14} />}
          {isRunning ? "Dừng băng tải" : "Chạy băng tải"}
        </button>

        <form onSubmit={handleSetTarget} className="flex items-center gap-2">
          <input
            type="number"
            min={0}
            max={9999}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={nhap?.value != null ? String(nhap.value) : "Số lượng"}
            className="w-28 rounded border border-gray-700 bg-gray-950 px-3 py-1.5 text-sm text-gray-200 outline-none transition-colors focus:border-amber-500"
          />
          <button
            type="submit"
            disabled={busy || target === ""}
            className="flex items-center gap-1.5 rounded border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs font-semibold text-gray-300 transition-colors hover:border-amber-500 hover:text-amber-300 disabled:opacity-50"
          >
            <Send size={12} />
            Set nhap
          </button>
        </form>
      </div>
    </div>
  );
}

function FlowNode({ label, tag, active, offline, value, danger }) {
  const stale = offline || !tag || tag.stale;
  const border = stale
    ? "border-gray-700 bg-gray-900/50"
    : danger
      ? "border-red-500 bg-red-950/30"
      : active
        ? "border-green-500 bg-green-950/30"
        : "border-gray-600 bg-gray-900/30";
  const text = stale ? "text-gray-600" : danger ? "text-red-300" : active ? "text-green-300" : "text-gray-300";

  return (
    <div className={`w-full max-w-md rounded-lg border px-5 py-4 transition-colors ${border}`}>
      <div className="flex items-center justify-between gap-4">
        <div>
          <div className="font-semibold text-gray-100">{label}</div>
          <div className="text-[10px] text-gray-600">{tag?.key || "not subscribed"}</div>
        </div>
        <div className={`font-mono text-sm font-bold ${text}`}>{stale ? "UNKNOWN" : value}</div>
      </div>
    </div>
  );
}

function Arrow() {
  return <ChevronDown size={18} className="text-gray-600" />;
}

function TagRow({ tag, fallbackKey }) {
  const stale = !tag || tag.stale;
  return (
    <div className={`flex items-center justify-between rounded-lg border px-3 py-2 transition-colors ${stale ? "border-red-900/40 bg-red-950/10" : "border-gray-700 bg-gray-900/40"}`}>
      <div>
        <div className="text-sm text-gray-200">{tag?.display_name || fallbackKey}</div>
        <div className="text-[10px] text-gray-600">{tag?.key || fallbackKey}</div>
      </div>
      <div className="text-right">
        <div className={`font-mono text-sm font-bold ${stale ? "text-gray-600" : "text-green-300"}`}>{stale ? "STALE" : formatValue(tag.value)}</div>
        <div className="text-[10px] text-gray-600">{tag?.quality || "—"}</div>
      </div>
    </div>
  );
}

function stageValue(tag) {
  if (!tag || tag.stale) return "UNKNOWN";
  return tag.value ? "ACTIVE" : "INACTIVE";
}

function counterValue(tag) {
  if (!tag || tag.stale) return "UNKNOWN";
  return String(tag.value ?? "—");
}

function formatValue(value) {
  if (typeof value === "boolean") return value ? "TRUE" : "FALSE";
  if (value === null || value === undefined) return "—";
  return String(value);
}
