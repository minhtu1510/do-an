import { useState, useEffect } from "react";
import { connectWebSocket } from "../services/websocket";
import { fetchAllTags } from "../services/api";
import TagCard from "../components/TagCard";

export default function Overview() {
  const [tags, setTags] = useState({});
  const [lastUpdate, setLastUpdate] = useState(null);
  const [allStale, setAllStale] = useState(true);

  useEffect(() => {
    fetchAllTags().then((data) => {
      if (data.tags) {
        const map = {};
        data.tags.forEach((t) => (map[t.key] = t));
        setTags(map);
        setLastUpdate(data.timestamp);
        setAllStale(data.tags.length > 0 && data.tags.every((t) => t.stale));
      }
    });
    const unsub = connectWebSocket((data) => {
      if (data.type === "tag_update") {
        setTags((prev) => {
          const next = { ...prev, [data.key]: data.data };
          setAllStale(Object.values(next).length > 0 && Object.values(next).every((t) => t.stale));
          return next;
        });
        setLastUpdate(new Date().toLocaleTimeString());
      }
      if (data.type === "full_state" && data.tags) {
        const map = {};
        data.tags.forEach((t) => (map[t.key] = t));
        setTags(map);
        setAllStale(data.tags.length > 0 && data.tags.every((t) => t.stale));
      }
    });
    return unsub;
  }, []);

  const bangTai = tags.bang_tai;
  const noData = !bangTai || Object.keys(tags).length === 0;
  const isRunning = !noData && !bangTai.stale && bangTai.value === true;
  const offline = !noData && (bangTai.stale || bangTai.value === null);
  const isStopped = !noData && !bangTai.stale && bangTai.value === false;
  const nhap = !tags.nhap?.stale ? tags.nhap?.value : "—";
  const hienThi = !tags.hien_thi?.stale ? tags.hien_thi?.value : "—";

  return (
    <div className="p-6 space-y-6">
      <div className="grid grid-cols-3 gap-4">
        <KPICard label="Bang Tai" value={noData ? "..." : offline ? "OFFLINE" : isRunning ? "RUNNING" : "STOPPED"} color={noData ? "text-gray-500" : offline ? "text-gray-500" : isRunning ? "text-green-400" : "text-red-400"} />
        <KPICard label="San pham vao" value={nhap} />
        <KPICard label="San pham ra" value={hienThi} />
      </div>

      <div className="bg-gray-800 rounded border border-gray-700 p-6">
        <div className="flex justify-center items-center gap-8 mb-4">
          {["vat_1", "vat_2", "vat_3"].map((key) => {
            const t = tags[key];
            const active = !t?.stale && t?.value === true;
            const unknown = !t || t.stale;
            return (
              <div key={key} className="flex flex-col items-center">
                <span className="text-xs text-gray-500 mb-1">{t?.display_name || key}</span>
                <span className={`text-3xl ${active ? "text-blue-400 animate-pulse" : unknown ? "text-gray-700" : "text-gray-600"}`}>
                  {unknown ? "—" : active ? "●" : "○"}
                </span>
              </div>
            );
          })}
        </div>
        <div className={`h-3 rounded-full mb-2 transition-colors ${offline ? "bg-gray-700" : isRunning ? "bg-green-600 animate-pulse" : "bg-gray-600"}`} />
        <div className="text-center text-xs text-gray-500">
          {offline ? "OFFLINE" : isRunning ? "DANG CHAY" : "DUNG"}
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {["cd1", "cd2", "cd3"].map((key) => {
          const t = tags[key];
          return (
            <TagCard key={key} label={t?.display_name || key} value={t?.value} unit="ms" quality={t?.quality} stale={t?.stale} />
          );
        })}
      </div>

      <div className="grid grid-cols-3 gap-4">
        {["vat_1", "vat_2", "vat_3"].map((key) => {
          const t = tags[key];
          return (
            <TagCard key={key} label={t?.display_name || key} value={t?.value} quality={t?.quality} stale={t?.stale} />
          );
        })}
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
