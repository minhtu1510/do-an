import { useState, useEffect } from "react";
import { connectWebSocket } from "../services/websocket";
import { fetchAllTags } from "../services/api";

export default function ProcessMonitor() {
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

  return (
    <div className="p-6 space-y-4">
      <h2 className="text-lg font-bold">Giam sat qua trinh</h2>

      <div className="bg-gray-800 rounded border border-gray-700 p-6">
        <div className="flex justify-between items-center mb-6">
          {["vat_1", "vat_2", "vat_3"].map((key, i) => {
            const t = tags[key];
            const active = !t?.stale && t?.value === true;
            const unknown = !t || t.stale;
            return (
              <div key={key} className="flex flex-col items-center flex-1">
                <div className={`w-16 h-16 rounded-full flex items-center justify-center border-2 mb-2 ${
                  active ? "border-blue-400 bg-blue-900/30" : unknown ? "border-gray-700 bg-gray-800/50" : "border-gray-600 bg-gray-800"
                }`}>
                  <span className={`text-2xl ${active ? "text-blue-400" : unknown ? "text-gray-700" : "text-gray-600"}`}>
                    {unknown ? "—" : active ? "●" : "○"}
                  </span>
                </div>
                <span className="text-xs text-gray-500">Vat {i + 1}</span>
              </div>
            );
          })}
        </div>
        <div className={`h-4 rounded mb-2 transition-all duration-500 ${offline ? "bg-gray-700" : isRunning ? "bg-green-600" : "bg-gray-600"}`}>
          {isRunning && <div className="h-full w-1/3 bg-green-400 rounded animate-pulse" />}
        </div>
        <div className={`text-center text-sm ${offline ? "text-gray-500" : isRunning ? "text-green-400" : "text-red-400"}`}>
          {offline ? "OFFLINE" : isRunning ? "DANG CHAY" : "DUNG"}
        </div>
      </div>

      <div className="space-y-1">
        {Object.values(tags).map((t) => (
          <div key={t.key} className={`flex justify-between items-center rounded px-4 py-2 border ${
            t.stale ? "bg-red-950/10 border-red-900/30" : "bg-gray-800 border-gray-700"
          }`}>
            <div>
              <span className="text-sm">{t.display_name || t.key}</span>
              <span className="text-[10px] text-gray-500 ml-2">{t.key}</span>
            </div>
            <div className="flex items-center gap-4">
              <span className={`font-mono font-bold ${t.stale ? "text-gray-600" : "text-green-400"}`}>
                {t.stale ? "STALE" : typeof t.value === "boolean" ? (t.value ? "TRUE" : "FALSE") : String(t.value ?? "—")}
              </span>
              <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                t.stale ? "bg-red-900 text-red-400" : t.quality === "Good" ? "bg-green-900 text-green-400" : "bg-red-900 text-red-400"
              }`}>
                {t.stale ? "STALE" : t.quality || "—"}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
