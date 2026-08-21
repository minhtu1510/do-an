import { useEffect, useState } from "react";
import { ClipboardList, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { fetchEvents } from "../services/api";
import { connectWebSocket } from "../services/websocket";
import PageHeader from "../components/PageHeader";
import ExportCsvButton from "../components/ExportCsvButton";
import { COMMAND_EVENT_TYPES } from "../constants/events";

// Every PLC write command — accepted, rejected by validation, or failed at
// the OPC UA layer — logged by POST /tags/{key}/write in api/router.py.
// Separate from Alarms & Events (system-generated) so "who told the PLC to
// do what, and when" is its own clean trail, not mixed with tag alarms.
export default function AuditLog() {
  const [events, setEvents] = useState([]);
  const [lastUpdate, setLastUpdate] = useState(null);

  useEffect(() => {
    fetchEvents(500).then((data) => {
      setEvents((data.events || []).filter((e) => COMMAND_EVENT_TYPES.includes(e.event_type)));
      setLastUpdate(data.timestamp || null);
    });

    const unsub = connectWebSocket((data) => {
      if (data.type === "event" && data.event && COMMAND_EVENT_TYPES.includes(data.event.event_type)) {
        setEvents((prev) => [data.event, ...prev].slice(0, 500));
        setLastUpdate(data.event.timestamp);
      }
    });

    return unsub;
  }, []);

  const writeCount = events.filter((e) => e.event_type === "COMMAND_WRITE").length;
  const rejectedCount = events.filter((e) => e.event_type === "COMMAND_REJECTED").length;
  const failedCount = events.filter((e) => e.event_type === "COMMAND_FAILED").length;
  const blockedCount = events.filter((e) => e.event_type === "COMMAND_RATE_LIMITED" || e.event_type === "ACCESS_DENIED").length;

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        icon={ClipboardList}
        title="Audit Log"
        subtitle="Mọi lệnh ghi xuống PLC thật — thành công, bị từ chối, hoặc lỗi — tách riêng khỏi cảnh báo hệ thống."
        right={<ExportCsvButton eventTypes={COMMAND_EVENT_TYPES} label="Export audit CSV" />}
      />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <SummaryCard label="Lệnh thành công" value={writeCount} color="text-green-400" icon={ShieldCheck} />
        <SummaryCard label="Bị từ chối (validate)" value={rejectedCount} color="text-yellow-400" icon={ShieldAlert} />
        <SummaryCard label="Lỗi (không kết nối...)" value={failedCount} color="text-red-400" icon={ShieldX} />
        <SummaryCard label="Bị chặn (rate-limit / quyền)" value={blockedCount} color="text-orange-400" icon={ShieldAlert} />
      </div>

      <div className="overflow-hidden rounded-lg border border-gray-700 bg-gray-800 shadow-sm shadow-black/20">
        <div className="border-b border-gray-700 px-4 py-3 text-sm font-semibold text-gray-200">Lịch sử lệnh điều khiển</div>
        {events.length === 0 ? (
          <div className="flex flex-col items-center gap-2 p-10 text-sm text-gray-500">
            <ClipboardList size={28} className="text-gray-700" />
            Chưa có lệnh điều khiển nào được ghi nhận — trang này chỉ có dữ liệu sau khi ai đó (vai trò controller trở lên) gửi lệnh ở Process Monitor.
          </div>
        ) : (
          <div className="divide-y divide-gray-700">
            {events.map((event) => (
              <AuditRow key={event.id} event={event} />
            ))}
          </div>
        )}
      </div>

      {lastUpdate && <div className="text-right text-xs text-gray-600">Cập nhật gần nhất: {formatTime(lastUpdate)}</div>}
    </div>
  );
}

function SummaryCard({ label, value, color, icon: Icon }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-gray-700 bg-gray-800 p-4 shadow-sm shadow-black/20 transition-colors hover:border-gray-600">
      <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-gray-900 ${color}`}>
        <Icon size={16} />
      </div>
      <div>
        <div className="text-xs uppercase tracking-wide text-gray-500">{label}</div>
        <div className={`font-mono text-2xl font-bold ${color}`}>{value}</div>
      </div>
    </div>
  );
}

const TYPE_STYLE = {
  COMMAND_WRITE: { label: "WRITE", color: "text-green-300 bg-green-950/40" },
  COMMAND_REJECTED: { label: "REJECTED", color: "text-yellow-300 bg-yellow-950/40" },
  COMMAND_FAILED: { label: "FAILED", color: "text-red-300 bg-red-950/40" },
  COMMAND_RATE_LIMITED: { label: "RATE LIMITED", color: "text-orange-300 bg-orange-950/40" },
  ACCESS_DENIED: { label: "ACCESS DENIED", color: "text-orange-300 bg-orange-950/40" },
};

function AuditRow({ event }) {
  const style = TYPE_STYLE[event.event_type] || { label: event.event_type, color: "text-gray-300 bg-gray-900" };
  return (
    <div className="grid gap-3 px-4 py-3 text-xs transition-colors hover:bg-gray-900/40 md:grid-cols-[140px_100px_100px_140px_1fr] md:items-center">
      <div className="text-gray-500">{formatTime(event.timestamp)}</div>
      <span className={`w-fit rounded px-2 py-1 text-[10px] font-bold ${style.color}`}>{style.label}</span>
      <div className="text-gray-400">{event.tag_key || "—"}</div>
      <div className="font-mono text-gray-400">
        {event.old_value !== null && event.old_value !== undefined ? String(event.old_value) : "—"}
        {" → "}
        {event.new_value !== null && event.new_value !== undefined ? String(event.new_value) : "—"}
      </div>
      <div className="text-gray-500">{event.message}</div>
    </div>
  );
}

function formatTime(value) {
  if (!value) return "N/A";
  return new Date(value).toLocaleString();
}
