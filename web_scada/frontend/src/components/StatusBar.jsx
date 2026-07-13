import { useState, useEffect } from "react";
import { fetchPlcStatus } from "../services/api";
import { connectWebSocket } from "../services/websocket";

export default function StatusBar() {
  const [plcStatus, setPlcStatus] = useState(null);
  const [tags, setTags] = useState({});
  const [wsOpen, setWsOpen] = useState(false);
  const [activeAlarms, setActiveAlarms] = useState(0);

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

  const plcConnected = plcStatus?.connected;
  const anyStale = Object.values(tags).some((t) => t.stale);
  const plcDisconnected = !plcConnected && plcStatus !== null;

  // Alarms: PLC disconnected = 1 active alarm
  useEffect(() => {
    setActiveAlarms(plcDisconnected ? 1 : 0);
  }, [plcDisconnected]);

  return (
    <div className="flex items-center gap-4 px-4 py-1.5 bg-gray-900 border-b border-gray-800 text-xs">
      <span className="font-bold text-sm mr-2 text-blue-400">WEB-SCADA</span>
      <StatusDot label="PLC" on={plcConnected} />
      <StatusDot label="OPC UA" on={plcConnected && !anyStale} warn={plcConnected && anyStale} />
      <StatusDot label="WS" on={wsOpen} />
      <span className="ml-auto text-gray-500">
        Active alarms: <span className={plcDisconnected ? "text-red-400 font-bold" : ""}>{activeAlarms}</span>
      </span>
      {plcDisconnected && (
        <span className="bg-red-900/50 text-red-400 px-2 py-0.5 rounded text-[10px] font-bold animate-pulse">
          DATA STALE — PLC DISCONNECTED
        </span>
      )}
      {anyStale && plcConnected && (
        <span className="bg-yellow-900/30 text-yellow-400 px-2 py-0.5 rounded text-[10px]">
          STALE DATA
        </span>
      )}
    </div>
  );
}

function StatusDot({ label, on, warn = false }) {
  const color = on ? (warn ? "bg-yellow-500" : "bg-green-500") : "bg-red-500";
  const textColor = on ? (warn ? "text-yellow-400" : "text-gray-300") : "text-red-400";
  return (
    <div className="flex items-center gap-1">
      <span className={`w-2 h-2 rounded-full ${color}`} />
      <span className={textColor}>{label}</span>
    </div>
  );
}
