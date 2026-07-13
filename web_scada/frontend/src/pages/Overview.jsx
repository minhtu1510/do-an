import { useState, useEffect } from "react";
import { connectWebSocket } from "../services/websocket";
import { fetchAllTags } from "../services/api";
import TagCard from "../components/TagCard";

export default function Overview() {
  const [tags, setTags] = useState({});
  const [lastUpdate, setLastUpdate] = useState(null);

  useEffect(() => {
    fetchAllTags().then((data) => {
      if (data.tags) {
        const map = {};
        data.tags.forEach((t) => (map[t.key] = t));
        setTags(map);
        setLastUpdate(new Date().toLocaleTimeString());
      }
    });

    const unsub = connectWebSocket((data) => {
      if (data.type === "tag_update") {
        setTags((prev) => ({ ...prev, [data.key]: data.data }));
        setLastUpdate(new Date().toLocaleTimeString());
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
  const isRunning = bangTai?.value === true;
  const nhap = tags.nhap?.value ?? 0;
  const hienThi = tags.hien_thi?.value ?? 0;

  return (
    <div className="p-6 space-y-6">
      {/* KPI Row */}
      <div className="grid grid-cols-3 gap-4">
        <KPICard label="Bang Tai" value={isRunning ? "RUNNING" : "STOPPED"} color={isRunning ? "text-green-400" : "text-red-400"} />
        <KPICard label="San pham vao" value={nhap} />
        <KPICard label="Canh bao" value={0} color="text-yellow-400" />
      </div>

      {/* Conveyor Visualization */}
      <div className="bg-gray-800 rounded border border-gray-700 p-6">
        <div className="flex justify-center items-center gap-8 mb-4">
          {["vat_1", "vat_2", "vat_3"].map((key) => {
            const t = tags[key];
            const active = t?.value === true;
            return (
              <div key={key} className="flex flex-col items-center">
                <span className="text-xs text-gray-500 mb-1">{t?.display_name || key}</span>
                <span className={`text-3xl ${active ? "text-blue-400 animate-pulse" : "text-gray-600"}`}>●</span>
              </div>
            );
          })}
        </div>
        <div className={`h-3 rounded-full mb-2 transition-colors ${isRunning ? "bg-green-600 animate-pulse" : "bg-gray-700"}`} />
        <div className="text-center text-xs text-gray-500">BANG TAI</div>
      </div>

      {/* Timer Row */}
      <div className="grid grid-cols-3 gap-4">
        {["cd1", "cd2", "cd3"].map((key) => (
          <TagCard key={key} label={tags[key]?.display_name || key} value={tags[key]?.value} unit="ms" quality={tags[key]?.quality} stale={tags[key]?.stale} updated={tags[key]?.received_timestamp} />
        ))}
      </div>

      {/* Sensors + Counters */}
      <div className="grid grid-cols-4 gap-4">
        {["vat_1", "vat_2", "vat_3", "nhap", "hien_thi"].map((key) => (
          <TagCard key={key} label={tags[key]?.display_name || key} value={tags[key]?.value} quality={tags[key]?.quality} stale={tags[key]?.stale} updated={tags[key]?.received_timestamp} />
        ))}
      </div>

      {lastUpdate && <div className="text-right text-xs text-gray-600">Last update: {lastUpdate}</div>}
    </div>
  );
}

function KPICard({ label, value, color = "text-white" }) {
  return (
    <div className="bg-gray-800 rounded border border-gray-700 p-4 text-center">
      <div className="text-xs text-gray-500 uppercase">{label}</div>
      <div className={`text-2xl font-bold mt-1 ${color}`}>
        {typeof value === "boolean" ? (value ? "TRUE" : "FALSE") : value}
      </div>
    </div>
  );
}
