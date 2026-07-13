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

  const bangTai = tags.bang_tai?.value === true;

  return (
    <div className="p-6 space-y-4">
      <h2 className="text-lg font-bold">Giam sat qua trinh</h2>

      {/* Conveyor diagram */}
      <div className="bg-gray-800 rounded border border-gray-700 p-6">
        <div className="flex justify-between items-center mb-6">
          {["vat_1", "vat_2", "vat_3"].map((key, i) => {
            const t = tags[key];
            return (
              <div key={key} className="flex flex-col items-center flex-1">
                <div className={`w-16 h-16 rounded-full flex items-center justify-center border-2 mb-2 ${
                  t?.value ? "border-blue-400 bg-blue-900/30" : "border-gray-600 bg-gray-800"
                }`}>
                  <span className={`text-2xl ${t?.value ? "text-blue-400" : "text-gray-600"}`}>
                    {t?.value ? "●" : "○"}
                  </span>
                </div>
                <span className="text-xs text-gray-500">Vat {i + 1}</span>
              </div>
            );
          })}
        </div>
        <div className={`h-4 rounded mb-2 transition-all duration-500 ${bangTai ? "bg-green-600" : "bg-gray-700"}`}>
          {bangTai && <div className="h-full w-1/3 bg-green-400 rounded animate-pulse" />}
        </div>
        <div className="text-center text-sm text-gray-400">
          {bangTai ? "DANG CHAY" : "DUNG"}
        </div>
      </div>

      {/* Tag details */}
      <div className="space-y-1">
        {Object.values(tags).map((t) => (
          <div key={t.key} className="flex justify-between items-center bg-gray-800 border border-gray-700 rounded px-4 py-2">
            <div>
              <span className="text-sm">{t.display_name || t.key}</span>
              <span className="text-[10px] text-gray-500 ml-2">{t.key}</span>
            </div>
            <div className="flex items-center gap-4">
              <span className={`font-mono font-bold ${t.stale ? "text-red-400" : "text-green-400"}`}>
                {typeof t.value === "boolean" ? (t.value ? "TRUE" : "FALSE") : String(t.value ?? "—")}
              </span>
              <span className={`text-[10px] px-1.5 py-0.5 rounded ${t.quality === "Good" ? "bg-green-900 text-green-400" : "bg-red-900 text-red-400"}`}>
                {t.quality || "—"}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
