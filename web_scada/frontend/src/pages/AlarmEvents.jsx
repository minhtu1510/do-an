import { useEffect, useState } from "react";
import { Bell, Check, ClipboardList, Inbox, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { ackEvent, fetchEvents } from "../services/api";
import { connectWebSocket } from "../services/websocket";
import PageHeader from "../components/PageHeader";
import ExportCsvButton from "../components/ExportCsvButton";
import { useAuth } from "../stores/authStore";
import { COMMAND_EVENT_TYPES } from "../constants/events";

// Cảnh báo hệ thống và nhật ký lệnh điều khiển PLC dùng chung 1 nguồn
// (GET /events) — tách thành 2 mảng ngay từ 1 lần fetch/1 WS stream thay vì
// gọi 2 lần, và gộp chung 1 trang thay vì 2 trang riêng vì cả hai đều chỉ là
// "chuyện gì vừa xảy ra" và cùng yêu cầu role operator+ để thấy phần nhật ký.
export default function AlarmEvents() {
  const { hasRole } = useAuth();
  const [events, setEvents] = useState([]);
  const [commandEvents, setCommandEvents] = useState([]);
  const [lastUpdate, setLastUpdate] = useState(null);
  const activeCount = events.filter((e) => e.status === "ACTIVE").length;

  useEffect(() => {
    fetchEvents(500).then((data) => {
      const all = data.events || [];
      setEvents(all.filter((e) => !COMMAND_EVENT_TYPES.includes(e.event_type)));
      setCommandEvents(all.filter((e) => COMMAND_EVENT_TYPES.includes(e.event_type)));
      setLastUpdate(data.timestamp || null);
    });

    const unsub = connectWebSocket((data) => {
      if (data.type !== "event" || !data.event) return;
      const isCommand = COMMAND_EVENT_TYPES.includes(data.event.event_type);
      const setter = isCommand ? setCommandEvents : setEvents;
      setter((prev) => {
        const existingIndex = prev.findIndex((e) => e.id === data.event.id);
        if (existingIndex !== -1) {
          const next = [...prev];
          next[existingIndex] = data.event;
          return next;
        }
        return [data.event, ...prev].slice(0, 500);
      });
      setLastUpdate(data.event.timestamp);
    });

    return unsub;
  }, []);

  async function handleAck(eventId) {
    try {
      const updated = await ackEvent(eventId);
      setEvents((prev) => prev.map((e) => (e.id === eventId ? updated : e)));
    } catch (err) {
      // best-effort UI action; server state remains source of truth on next refresh
    }
  }

  const writeCount = commandEvents.filter((e) => e.event_type === "COMMAND_WRITE").length;
  const rejectedCount = commandEvents.filter((e) => e.event_type === "COMMAND_REJECTED").length;
  const failedCount = commandEvents.filter((e) => e.event_type === "COMMAND_FAILED").length;
  const blockedCount = commandEvents.filter((e) => e.event_type === "COMMAND_RATE_LIMITED" || e.event_type === "ACCESS_DENIED").length;

  return (
    <div className="p-6 space-y-8">
      <PageHeader
        icon={Bell}
        title="Cảnh báo & Sự kiện"
        subtitle="Cảnh báo hệ thống từ trạng thái tag/kết nối OPC UA thật, cùng nhật ký lệnh điều khiển PLC."
        right={<ExportCsvButton excludeEventTypes={COMMAND_EVENT_TYPES} />}
      />

      <div className="grid gap-4 sm:grid-cols-2">
        <SummaryCard label="Cảnh báo đang hoạt động" value={activeCount} color={activeCount > 0 ? "text-red-400" : "text-green-400"} icon={Bell} />
        <SummaryCard label="Sự kiện đã lưu" value={events.length} icon={Inbox} />
      </div>

      <div className="overflow-hidden rounded-lg border border-gray-700 bg-gray-800 shadow-sm shadow-black/20">
        <div className="border-b border-gray-700 px-4 py-3 text-sm font-semibold text-gray-200">Sự kiện gần đây</div>
        {events.length === 0 ? (
          <div className="flex flex-col items-center gap-2 p-10 text-sm text-gray-500">
            <Inbox size={28} className="text-gray-700" />
            Chưa có sự kiện nào được ghi nhận.
          </div>
        ) : (
          <div className="divide-y divide-gray-700">
            {events.map((event) => (
              <EventRow key={event.id} event={event} onAck={handleAck} />
            ))}
          </div>
        )}
      </div>

      {lastUpdate && <div className="text-right text-xs text-gray-600">Cập nhật sự kiện gần nhất: {lastUpdate}</div>}

      {hasRole("operator") && (
        <div className="space-y-4 border-t border-gray-800 pt-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-semibold text-gray-200">
              <ClipboardList size={16} className="text-gray-500" />
              Nhật ký điều khiển
            </div>
            <ExportCsvButton eventTypes={COMMAND_EVENT_TYPES} label="Xuất nhật ký CSV" />
          </div>
          <p className="text-xs text-gray-500">Mọi lệnh ghi xuống PLC thật — thành công, bị từ chối, hoặc lỗi.</p>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <SummaryCard label="Lệnh thành công" value={writeCount} color="text-green-400" icon={ShieldCheck} />
            <SummaryCard label="Bị từ chối (validate)" value={rejectedCount} color="text-yellow-400" icon={ShieldAlert} />
            <SummaryCard label="Lỗi (không kết nối...)" value={failedCount} color="text-red-400" icon={ShieldX} />
            <SummaryCard label="Bị chặn (rate-limit / quyền)" value={blockedCount} color="text-orange-400" icon={ShieldAlert} />
          </div>

          <div className="overflow-hidden rounded-lg border border-gray-700 bg-gray-800 shadow-sm shadow-black/20">
            {commandEvents.length === 0 ? (
              <div className="flex flex-col items-center gap-2 p-10 text-sm text-gray-500">
                <ClipboardList size={28} className="text-gray-700" />
                Chưa có lệnh điều khiển nào được ghi nhận — có dữ liệu sau khi ai đó (vai trò controller trở lên) gửi lệnh ở Giám sát tiến trình.
              </div>
            ) : (
              <div className="divide-y divide-gray-700">
                {commandEvents.map((event) => (
                  <AuditRow key={event.id} event={event} />
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function SummaryCard({ label, value, color = "text-white", icon: Icon }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-gray-700 bg-gray-800 p-4 shadow-sm shadow-black/20 transition-colors hover:border-gray-600">
      {Icon && (
        <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-gray-900 ${color}`}>
          <Icon size={16} />
        </div>
      )}
      <div>
        <div className="text-xs uppercase tracking-wide text-gray-500">{label}</div>
        <div className={`font-mono text-2xl font-bold ${color}`}>{value}</div>
      </div>
    </div>
  );
}

function EventRow({ event, onAck }) {
  const { hasRole } = useAuth();
  const severityColor = {
    INFO: "text-blue-300 bg-blue-950/40",
    WARN: "text-yellow-300 bg-yellow-950/40",
    ERROR: "text-red-300 bg-red-950/40",
  }[event.severity] || "text-gray-300 bg-gray-900";
  const statusColor = event.status === "ACTIVE" ? "text-red-400" : "text-green-400";
  const needsAck = event.status === "ACTIVE" && !event.acked_by;

  return (
    <div className="grid gap-3 px-4 py-3 transition-colors hover:bg-gray-900/40 md:grid-cols-[140px_110px_1fr_100px_150px] md:items-center">
      <div className="text-xs text-gray-500">{formatTime(event.timestamp)}</div>
      <div>
        <span className={`rounded px-2 py-1 text-[10px] font-bold ${severityColor}`}>{event.severity}</span>
      </div>
      <div>
        <div className="text-sm font-semibold text-gray-200">{event.event_type}</div>
        <div className="text-xs text-gray-500">{event.message}</div>
        {event.tag_key && <div className="text-[10px] text-gray-600">Tag: {event.tag_key}</div>}
      </div>
      <div className={`text-xs font-bold ${statusColor}`}>{event.status}</div>
      <div className="text-xs">
        {event.acked_by ? (
          <div className="text-gray-500">
            <div className="text-green-400">Đã ack: {event.acked_by}</div>
            <div className="text-[10px] text-gray-600">{formatTime(event.acked_at)}</div>
          </div>
        ) : needsAck && hasRole("operator") ? (
          <button
            onClick={() => onAck(event.id)}
            className="flex items-center gap-1 rounded border border-gray-700 bg-gray-900 px-2 py-1 text-[10px] font-semibold text-gray-300 transition-colors hover:border-blue-600 hover:text-blue-300"
          >
            <Check size={11} />
            Ack
          </button>
        ) : needsAck ? (
          <span className="text-gray-600">Chưa ack</span>
        ) : null}
      </div>
    </div>
  );
}

const TYPE_STYLE = {
  COMMAND_WRITE: { label: "ĐÃ GHI", color: "text-green-300 bg-green-950/40" },
  COMMAND_REJECTED: { label: "TỪ CHỐI", color: "text-yellow-300 bg-yellow-950/40" },
  COMMAND_FAILED: { label: "LỖI", color: "text-red-300 bg-red-950/40" },
  COMMAND_RATE_LIMITED: { label: "BỊ CHẶN TỐC ĐỘ", color: "text-orange-300 bg-orange-950/40" },
  ACCESS_DENIED: { label: "TỪ CHỐI TRUY CẬP", color: "text-orange-300 bg-orange-950/40" },
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
