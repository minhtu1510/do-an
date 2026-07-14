import { useState, useEffect } from "react";
import { fetchPlcStatus } from "../services/api";
import { connectWebSocket } from "../services/websocket";

export default function StatusBar() {
  const [plcStatus, setPlcStatus] = useState(null);
  const [tags, setTags] = useState({});
  const [wsOpen, setWsOpen] = useState(false);

  useEffect(() => {
    fetchPlcStatus().then(setPlcStatus);
    const unsub = connectWebSocket((data) => {
      if (data.type === "tag_update") {
        setTags((prev) => ({ ...prev, [data.key]: data.data }));
      }
      if (data.type === "full_state") {
        if (data.status) setPlcStatus(data.status);
        if (data.tags) {
          const map = {};
          data.tags.forEach((t) => (map[t.key] = t));
          setTags(map);
        }
      }
      if (data.type === "ws_open") setWsOpen(true);
      if (data.type === "ws_close") setWsOpen(false);
    });
    const timer = setInterval(() => fetchPlcStatus().then(setPlcStatus), 10000);
    return () => { unsub(); clearInterval(timer); };
  }, []);

  const plcConnected = plcStatus?.connected ?? null;
  const anyStale = Object.values(tags).length > 0 && Object.values(tags).some((t) => t.stale);
  const allStale = Object.values(tags).length > 0 && Object.values(tags).every((t) => t.stale);
  const plcDisconnected = plcConnected === false;
  const loading = plcConnected === null;

  return (
    <div className="flex items-center gap-4 px-4 py-1.5 bg-gray-900 border-b border-gray-800 text-xs">
      <span className="font-bold text-sm mr-2 text-blue-400">WEB-SCADA</span>

      {loading ? (
        <span className="flex items-center gap-1 text-yellow-400">
          <span className="w-2 h-2 rounded-full bg-yellow-500 animate-pulse" />
          Connecting...
        </span>
      ) : (
        <>
          <Dot label="PLC" status={plcConnected ? "on" : "off"} />
          <Dot label="OPC UA" status={plcDisconnected ? "off" : anyStale ? "warn" : "on"} />
          <Dot label="WS" status={wsOpen ? "on" : "off"} />
        </>
      )}

      <span className="ml-auto text-gray-500">
        Tags: <span className={allStale ? "text-red-400" : "text-green-400"}>
          {Object.values(tags).filter((t) => !t.stale).length}/{Object.values(tags).length}
        </span>
      </span>

      {plcDisconnected && (
        <span className="bg-red-900/60 text-red-400 px-2 py-0.5 rounded text-[10px] font-bold animate-pulse">
          PLC DISCONNECTED
        </span>
      )}
      {!plcDisconnected && anyStale && (
        <span className="bg-yellow-900/30 text-yellow-400 px-2 py-0.5 rounded text-[10px]">
          STALE TAGS
        </span>
      )}
    </div>
  );
}

function Dot({ label, status }) {
  const cls = {
    on: ["bg-green-500", "text-gray-300"],
    off: ["bg-red-500", "text-red-400"],
    warn: ["bg-yellow-500", "text-yellow-400"],
  }[status];
  return (
    <div className="flex items-center gap-1">
      <span className={`w-2 h-2 rounded-full ${cls[0]}`} />
      <span className={cls[1]}>{label}</span>
    </div>
  );
}
