import { useState, useEffect } from "react";
import { Workflow, ChevronDown, AlertTriangle, Play, Square } from "lucide-react";
import { connectWebSocket } from "../services/websocket";
import { fetchAllTags, writeTag } from "../services/api";
import { useAuth } from "../stores/authStore";
import { useConfirm } from "../components/ConfirmDialog";
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
  const conveyorLabel = offline ? "MẤT KẾT NỐI" : isRunning ? "ĐANG CHẠY" : "ĐÃ DỪNG";

  const stageTagsFresh = ["vat_1", "vat_2", "vat_3"].every((k) => tags[k] && !tags[k].stale);
  const sensorSpoofSuspected =
    stageTagsFresh && tags.vat_1.value === true && tags.vat_2.value === true && tags.vat_3.value === true;

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        icon={Workflow}
        title="Giám sát tiến trình"
        subtitle="Động cơ/băng tải, bit trạng thái công đoạn, bộ đếm, và timer công đoạn — đọc trực tiếp từ tag OPC UA."
      />

      <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
        <div className="rounded-lg border border-gray-700 bg-gray-800 p-6 shadow-sm shadow-black/20">
          <div className="mb-6 flex items-center justify-between">
            <div>
              <div className="text-sm font-semibold text-gray-200">Sơ đồ dây chuyền</div>
              <div className="text-xs text-gray-500">Chỉ vẽ cảm biến/thiết bị khi có tag OPC UA thật đã subscribe.</div>
            </div>
            <span className={`rounded px-2 py-1 text-xs font-bold ${offline ? "bg-red-950 text-red-400" : isRunning ? "bg-green-950 text-green-400" : "bg-yellow-950 text-yellow-400"}`}>
              {conveyorLabel}
            </span>
          </div>

          {sensorSpoofSuspected && (
            <div className="mb-4 flex items-start gap-2 rounded-lg border border-red-600 bg-red-950/40 px-4 py-3 text-sm font-semibold text-red-300 animate-fade-in">
              <AlertTriangle size={16} className="mt-0.5 shrink-0" />
              <span>
                Nghi ngờ giả mạo cảm biến — vat_1, vat_2 và vat_3 cùng lúc báo hoạt động,
                điều không thể xảy ra thật trên một băng tải một làn.
              </span>
            </div>
          )}

          <div className="mb-3 text-xs text-slate-600">
            Công đoạn 1–3 báo vị trí vật đang nằm ở đâu (cảm biến hiện diện) — không phải trạng thái động
            cơ. Băng tải dừng thì vật vẫn nằm nguyên chỗ, nên 1 công đoạn vẫn có thể HOẠT ĐỘNG dù băng tải ĐÃ DỪNG
            — đó là bình thường. Chỉ đáng ngờ khi &gt; 1 công đoạn cùng hoạt động một lúc.
          </div>

          <div className="flex flex-col items-center gap-3">
            <FlowNode label="Động cơ / Băng tải" tag={bangTai} active={isRunning} offline={offline} value={conveyorLabel} />
            <Arrow />
            <FlowNode label="Công đoạn 1" tag={tags.vat_1} active={!tags.vat_1?.stale && tags.vat_1?.value === true} value={stageValue(tags.vat_1)} danger={sensorSpoofSuspected} />
            <Arrow />
            <FlowNode label="Công đoạn 2" tag={tags.vat_2} active={!tags.vat_2?.stale && tags.vat_2?.value === true} value={stageValue(tags.vat_2)} danger={sensorSpoofSuspected} />
            <Arrow />
            <FlowNode label="Công đoạn 3" tag={tags.vat_3} active={!tags.vat_3?.stale && tags.vat_3?.value === true} value={stageValue(tags.vat_3)} danger={sensorSpoofSuspected} />
            <Arrow />
            <FlowNode label="Bộ đếm sản phẩm" tag={tags.hien_thi} active={!tags.hien_thi?.stale} value={counterValue(tags.hien_thi)} />
          </div>

          {hasRole("controller") && (
            <ControlPanel bangTai={bangTai} isRunning={isRunning} offline={offline} />
          )}
        </div>

        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            <TagCard label={tags.nhap?.display_name || "Sản lượng mục tiêu"} sublabel="nhap" value={tags.nhap?.value} quality={tags.nhap?.quality} stale={tags.nhap?.stale} />
            <TagCard label={tags.hien_thi?.display_name || "Sản lượng hoàn thành"} sublabel="hien_thi" value={tags.hien_thi?.value} quality={tags.hien_thi?.quality} stale={tags.hien_thi?.stale} />
          </div>

          <div className="rounded-lg border border-gray-700 bg-gray-800 p-4 shadow-sm shadow-black/20">
            <div className="mb-3 text-sm font-semibold text-gray-200">Timer công đoạn</div>
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
            <div className="mb-3 text-sm font-semibold text-gray-200">Tag tiến trình đã subscribe</div>
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

function ControlPanel({ bangTai, isRunning, offline }) {
  const confirm = useConfirm();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function handleConveyorToggle() {
    const nextValue = !isRunning;
    const verb = nextValue ? "CHẠY (RUN)" : "DỪNG (STOP)";
    const ok = await confirm({
      title: `${verb} băng tải?`,
      message: "Lệnh này gửi trực tiếp xuống PLC thật và có tác động vật lý ngay lập tức.",
      confirmLabel: verb,
    });
    if (!ok) return;
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
          <div className="text-[10px] text-gray-600">{tag?.key || "chưa subscribe"}</div>
        </div>
        <div className={`font-mono text-sm font-bold ${text}`}>{stale ? "CHƯA RÕ" : value}</div>
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
        <div className={`font-mono text-sm font-bold ${stale ? "text-gray-600" : "text-green-300"}`}>{stale ? "CŨ" : formatValue(tag.value)}</div>
        <div className="text-[10px] text-gray-600">{tag?.quality || "—"}</div>
      </div>
    </div>
  );
}

function stageValue(tag) {
  if (!tag || tag.stale) return "CHƯA RÕ";
  return tag.value ? "HOẠT ĐỘNG" : "KHÔNG HOẠT ĐỘNG";
}

function counterValue(tag) {
  if (!tag || tag.stale) return "CHƯA RÕ";
  return String(tag.value ?? "—");
}

function formatValue(value) {
  if (typeof value === "boolean") return value ? "TRUE" : "FALSE";
  if (value === null || value === undefined) return "—";
  return String(value);
}
