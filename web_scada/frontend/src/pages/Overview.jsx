import { useEffect, useRef, useState } from "react";
import { LayoutDashboard } from "lucide-react";
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
    ? "ĐANG TẢI"
    : !plcConnected || bangTai.stale
      ? "MẤT KẾT NỐI"
      : bangTai.value
        ? "ĐANG CHẠY"
        : "ĐÃ DỪNG";
  const isRunning = conveyorStatus === "ĐANG CHẠY";
  const offline = conveyorStatus === "MẤT KẾT NỐI";

  const targetQuantity = readNumber(tags.nhap);
  const producedQuantity = readNumber(tags.hien_thi);
  const progress = targetQuantity > 0 ? Math.min((producedQuantity / targetQuantity) * 100, 100) : 0;
  const staleTags = Object.values(tags).filter((t) => t.stale);
  const activeAlarms = (plcConnected ? 0 : 1) + staleTags.length;

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        icon={LayoutDashboard}
        title="Tổng quan sản xuất"
        subtitle="Tổng hợp trực tiếp từ tag OPC UA. Các bit trạng thái công đoạn nội bộ không được coi là cảm biến vật lý."
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-6">
        <KPICard label="Trạng thái băng tải" value={conveyorStatus} color={statusColor(conveyorStatus)} />
        <KPICard label="Sản lượng mục tiêu" value={formatCount(targetQuantity, tags.nhap)} />
        <KPICard label="Sản lượng hoàn thành" value={formatCount(producedQuantity, tags.hien_thi)} />
        <KPICard label="Tiến độ" value={`${progress.toFixed(0)}%`} color="text-blue-300" />
        <KPICard label="Thời gian chạy hiện tại" value={formatRuntime(runtimeSeconds)} color={isRunning ? "text-green-300" : "text-gray-300"} />
        <KPICard label="Cảnh báo đang hoạt động" value={activeAlarms} color={activeAlarms > 0 ? "text-red-400" : "text-green-400"} />
      </div>

      <div className="rounded-lg border border-gray-700 bg-gray-800 p-6 shadow-sm shadow-black/20">
        <div className="flex items-center justify-between mb-3">
          <div>
            <div className="text-sm font-semibold text-gray-200">Tiến độ sản xuất</div>
            <div className="text-xs text-gray-500">
              {formatCount(producedQuantity, tags.hien_thi)} / {formatCount(targetQuantity, tags.nhap)} sản phẩm
            </div>
          </div>
          <div className={`text-sm font-bold ${statusColor(conveyorStatus)}`}>{conveyorStatus}</div>
        </div>
        <div className="h-4 rounded-full bg-gray-900 border border-gray-700 overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-500 ${offline ? "bg-gray-700" : isRunning ? "bg-green-500" : "bg-blue-600"}`}
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
        <div className="rounded-lg border border-gray-700 bg-gray-800 p-5 shadow-sm shadow-black/20">
          <div className="mb-4 text-sm font-semibold text-gray-200">Công đoạn tiến trình</div>
          <div className="grid gap-3 sm:grid-cols-3">
            {["vat_1", "vat_2", "vat_3"].map((key, index) => {
            const t = tags[key];
            const active = !t?.stale && t?.value === true;
            const unknown = !t || t.stale;
            return (
              <div key={key} className={`rounded-lg border p-4 transition-colors ${active ? "border-blue-500 bg-blue-950/30" : unknown ? "border-gray-700 bg-gray-900/40" : "border-gray-700 bg-gray-900/20"}`}>
                <div className="text-xs text-gray-500">Công đoạn {index + 1}</div>
                <div className={`mt-2 break-words text-sm font-bold leading-tight ${active ? "text-blue-300" : unknown ? "text-gray-600" : "text-gray-300"}`}>
                  {unknown ? "CHƯA RÕ" : active ? "HOẠT ĐỘNG" : "KHÔNG HOẠT ĐỘNG"}
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
    <div className="rounded-lg border border-gray-700 bg-gray-800 p-4 text-center shadow-sm shadow-black/20 transition-colors hover:border-gray-600">
      <div className="text-xs uppercase tracking-wide text-gray-500">{label}</div>
      <div className={`mt-1 font-mono text-2xl font-bold ${color}`}>{value}</div>
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
  if (status === "ĐANG CHẠY") return "text-green-400";
  if (status === "ĐÃ DỪNG") return "text-yellow-400";
  if (status === "MẤT KẾT NỐI") return "text-red-400";
  return "text-gray-500";
}
