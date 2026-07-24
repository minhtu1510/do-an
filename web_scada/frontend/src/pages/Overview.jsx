import { useEffect, useRef, useState } from "react";
import { connectWebSocket } from "../services/websocket";
import { fetchAllTags, fetchPlcStatus } from "../services/api";
import TagCard from "../components/TagCard";
import PageHeader from "../components/PageHeader";

export default function Overview() {
  const [tags, setTags] = useState({});
  const [plcStatus, setPlcStatus] = useState(null);
  const [lastUpdate, setLastUpdate] = useState(null);
  const [runtimeSeconds, setRuntimeSeconds] = useState(0);
  const isRunningRef = useRef(false);
  const previousConveyorState = useRef(null);

  useEffect(() => {
    fetchPlcStatus().then(setPlcStatus);
    fetchAllTags().then((data) => {
      if (data.tags) {
        const map = {};
        data.tags.forEach((t) => (map[t.key] = t));
        setTags(map);
        setLastUpdate(data.timestamp);
      }
    });
    const unsub = connectWebSocket((data) => {
      if (data.type === "tag_update") {
        setTags((prev) => {
          return { ...prev, [data.key]: data.data };
        });
        setLastUpdate(new Date().toLocaleTimeString());
      }
      if (data.type === "full_state" && data.tags) {
        const map = {};
        data.tags.forEach((t) => (map[t.key] = t));
        setTags(map);
        if (data.status) setPlcStatus(data.status);
      }
    });
    return unsub;
  }, []);

  useEffect(() => {
    const timer = setInterval(() => {
      if (isRunningRef.current) {
        setRuntimeSeconds((seconds) => seconds + 1);
      }
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const conveyor = tags.bang_tai;
    const current = plcStatus?.connected !== false && !conveyor?.stale ? conveyor?.value === true : null;
    isRunningRef.current = current === true;
    if (previousConveyorState.current === false && current === true) {
      setRuntimeSeconds(0);
    }
    previousConveyorState.current = current;
  }, [plcStatus?.connected, tags.bang_tai]);

  const bangTai = tags.bang_tai;
  const plcConnected = plcStatus?.connected !== false;
  const noData = !bangTai || Object.keys(tags).length === 0;
  const conveyorStatus = noData
    ? "LOADING"
    : !plcConnected || bangTai.stale
      ? "OFFLINE"
      : bangTai.value
        ? "RUNNING"
        : "STOPPED";
  const isRunning = conveyorStatus === "RUNNING";
  const offline = conveyorStatus === "OFFLINE";

  const targetQuantity = readNumber(tags.nhap);
  const producedQuantity = readNumber(tags.hien_thi);
  const progress = targetQuantity > 0 ? Math.min((producedQuantity / targetQuantity) * 100, 100) : 0;
  const staleTags = Object.values(tags).filter((t) => t.stale);
  const activeAlarms = (plcConnected ? 0 : 1) + staleTags.length;

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        title="Production Overview"
        subtitle="Live summary from OPC UA tags. Internal stage bits are not treated as physical sensors."
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-6">
        <KPICard label="Conveyor status" value={conveyorStatus} color={statusColor(conveyorStatus)} />
        <KPICard label="Target quantity" value={formatCount(targetQuantity, tags.nhap)} />
        <KPICard label="Completed quantity" value={formatCount(producedQuantity, tags.hien_thi)} />
        <KPICard label="Progress" value={`${progress.toFixed(0)}%`} color="text-blue-300" />
        <KPICard label="Current runtime" value={formatRuntime(runtimeSeconds)} color={isRunning ? "text-green-300" : "text-gray-300"} />
        <KPICard label="Active alarms" value={activeAlarms} color={activeAlarms > 0 ? "text-red-400" : "text-green-400"} />
      </div>

      <div className="bg-gray-800 rounded border border-gray-700 p-6">
        <div className="flex items-center justify-between mb-3">
          <div>
            <div className="text-sm font-semibold text-gray-200">Production progress</div>
            <div className="text-xs text-gray-500">
              {formatCount(producedQuantity, tags.hien_thi)} / {formatCount(targetQuantity, tags.nhap)} products
            </div>
          </div>
          <div className={`text-sm font-bold ${statusColor(conveyorStatus)}`}>{conveyorStatus}</div>
        </div>
        <div className="h-4 rounded bg-gray-900 border border-gray-700 overflow-hidden">
          <div
            className={`h-full transition-all duration-500 ${offline ? "bg-gray-700" : isRunning ? "bg-green-500" : "bg-blue-600"}`}
            style={{ width: `${progress}%` }}
          />
        </div>
        <div className="mt-2 flex justify-between text-xs text-gray-500">
          <span>0%</span>
          <span>{progress.toFixed(1)}%</span>
          <span>100%</span>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
        <div className="bg-gray-800 rounded border border-gray-700 p-5">
          <div className="mb-4 text-sm font-semibold text-gray-200">Process stages</div>
          <div className="grid gap-3 sm:grid-cols-3">
            {["vat_1", "vat_2", "vat_3"].map((key, index) => {
            const t = tags[key];
            const active = !t?.stale && t?.value === true;
            const unknown = !t || t.stale;
            return (
              <div key={key} className={`rounded border p-4 ${active ? "border-blue-500 bg-blue-950/30" : unknown ? "border-gray-700 bg-gray-900/40" : "border-gray-700 bg-gray-900/20"}`}>
                <div className="text-xs text-gray-500">Stage {index + 1}</div>
                <div className={`mt-2 text-lg font-bold ${active ? "text-blue-300" : unknown ? "text-gray-600" : "text-gray-300"}`}>
                  {unknown ? "UNKNOWN" : active ? "ACTIVE" : "INACTIVE"}
                </div>
                <div className="mt-1 text-[10px] text-gray-600">{key}</div>
              </div>
            );
          })}
          </div>
        </div>

        <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-1">
          {["cd1", "cd2", "cd3"].map((key) => {
            const t = tags[key];
            return (
              <TagCard key={key} label={t?.display_name || key} sublabel={key} value={t?.value} unit={t?.unit || "ms"} quality={t?.quality} stale={t?.stale} />
            );
          })}
        </div>
      </div>

      {lastUpdate && (
        <div className="text-right text-xs text-gray-600">Last update: {lastUpdate}</div>
      )}
    </div>
  );
}

function KPICard({ label, value, color = "text-white" }) {
  return (
    <div className="bg-gray-800 rounded border border-gray-700 p-4 text-center">
      <div className="text-xs text-gray-500 uppercase">{label}</div>
      <div className={`text-2xl font-bold mt-1 ${color}`}>{value}</div>
    </div>
  );
}

function readNumber(tag) {
  if (!tag || tag.stale || tag.value === null || tag.value === undefined || tag.value === "") return 0;
  const value = Number(tag.value);
  return Number.isFinite(value) ? value : 0;
}

function formatCount(value, tag) {
  if (!tag || tag.stale) return "—";
  return String(value);
}

function formatRuntime(totalSeconds) {
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return `${hours}h ${minutes}m ${seconds}s`;
}

function statusColor(status) {
  if (status === "RUNNING") return "text-green-400";
  if (status === "STOPPED") return "text-yellow-400";
  if (status === "OFFLINE") return "text-red-400";
  return "text-gray-500";
}
