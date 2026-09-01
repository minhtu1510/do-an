import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { FileClock, Loader2, ShieldAlert, ShieldCheck } from "lucide-react";
import { fetchIdsHistory, fetchIdsHistoryDetail } from "../services/api";
import PageHeader from "../components/PageHeader";
import { useToast } from "../components/Toast";
import { idsUploadStore, normalizeOpcuaResult } from "./idsUploadPersist";

// Every pcap ever analyzed via Phân tích lưu lượng mạng, read from a real table
// (pcap_analyses) — the upload page itself only ever held the most recent
// result in browser memory, so this is what makes past runs visible again
// after a refresh or to a different analyst.
export default function PcapHistory() {
  const [analyses, setAnalyses] = useState(null);
  const [openingId, setOpeningId] = useState(null);
  const navigate = useNavigate();
  const toast = useToast();

  useEffect(() => {
    fetchIdsHistory(200).then((data) => setAnalyses(data.analyses || [])).catch(() => setAnalyses([]));
  }, []);

  async function handleOpen(id) {
    setOpeningId(id);
    try {
      const detail = await fetchIdsHistoryDetail(id);
      if (detail.available === false) {
        toast("Lần phân tích này lưu trước khi có tính năng xem lại — chỉ còn số liệu tóm tắt ở bảng, không mở lại chi tiết được.", { tone: "error" });
        return;
      }
      // Stored result_json is the raw pre-normalization payload from the
      // backend — same reason a fresh OPC UA analysis needs normalizing in
      // IdsUpload.jsx's handleSubmit (lowercase "benign", no layer_used).
      idsUploadStore.result = detail.protocol === "opcua" ? normalizeOpcuaResult(detail) : { ...detail, protocol: "s7comm" };
      idsUploadStore.protocol = detail.protocol || "s7comm";
      idsUploadStore.file = null;
      idsUploadStore.historian = null;
      navigate("/ids-upload");
    } catch (err) {
      toast(err.message, { tone: "error" });
    } finally {
      setOpeningId(null);
    }
  }

  const total = analyses?.length ?? 0;
  const withAttack = analyses?.filter((a) => a.attack_flows > 0).length ?? 0;

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        icon={FileClock}
        title="Lịch sử phân tích PCAP"
        subtitle="Mọi lần tải pcap lên phân tích bằng AI — cả S7comm lẫn OPC UA — được lưu lại ở đây, không chỉ giữ kết quả lần gần nhất. Bấm vào 1 dòng để mở lại đúng kết quả lúc đó."
      />

      <div className="grid gap-4 sm:grid-cols-2">
        <SummaryCard label="Tổng số lần phân tích" value={total} color="text-blue-400" icon={FileClock} />
        <SummaryCard label="Có cửa sổ bị dự đoán là tấn công" value={withAttack} color={withAttack > 0 ? "text-red-400" : "text-green-400"} icon={withAttack > 0 ? ShieldAlert : ShieldCheck} />
      </div>

      <div className="overflow-hidden rounded-lg border border-gray-700 bg-gray-800 shadow-sm shadow-black/20">
        <div className="border-b border-gray-700 px-4 py-3 text-sm font-semibold text-gray-200">Danh sách lần phân tích</div>
        {analyses === null ? (
          <div className="p-10 text-center text-sm text-gray-500">Đang tải...</div>
        ) : analyses.length === 0 ? (
          <div className="flex flex-col items-center gap-2 p-10 text-sm text-gray-500">
            <FileClock size={28} className="text-gray-700" />
            Chưa có lần phân tích pcap nào — trang này có dữ liệu sau khi ai đó tải file lên ở mục Phân tích lưu lượng mạng.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <div className="min-w-[820px]">
              <div className="grid grid-cols-[150px_90px_1fr_110px_120px_1fr_100px] gap-3 border-b border-gray-700 px-4 py-2 text-xs uppercase text-gray-500">
                <div>Thời điểm</div>
                <div>Giao thức</div>
                <div>File</div>
                <div>Người phân tích</div>
                <div>Cửa sổ tấn công</div>
                <div>Dự đoán chính</div>
                <div>Tỷ lệ</div>
              </div>
              <div className="divide-y divide-gray-700">
                {analyses.map((a) => (
                  <HistoryRow key={a.id} row={a} onOpen={handleOpen} opening={openingId === a.id} />
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
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

function HistoryRow({ row, onOpen, opening }) {
  const topLabel = Object.entries(row.prediction_counts || {})
    .filter(([k]) => k !== "BENIGN" && k !== "benign")
    .sort((a, b) => b[1] - a[1])[0];

  return (
    <button
      type="button"
      onClick={() => onOpen(row.id)}
      disabled={opening}
      className="grid w-full grid-cols-[150px_90px_1fr_110px_120px_1fr_100px] items-center gap-3 px-4 py-3 text-left text-xs transition-colors hover:bg-gray-900/40 disabled:opacity-60"
    >
      <div className="flex items-center gap-1.5 text-gray-500">
        {opening && <Loader2 size={11} className="animate-spin" />}
        {formatTime(row.timestamp)}
      </div>
      <span className="w-fit rounded bg-gray-900 px-2 py-1 text-[10px] font-bold uppercase text-cyan-300">{row.protocol}</span>
      <div className="truncate text-gray-300" title={row.source_file}>{row.source_file}</div>
      <div className="text-gray-400">{row.analyzed_by}</div>
      <div className={row.attack_flows > 0 ? "font-semibold text-red-400" : "text-green-400"}>
        {row.attack_flows}/{row.total_flows}
      </div>
      <div className="truncate text-gray-400">{topLabel ? `${topLabel[0]} x${topLabel[1]}` : "—"}</div>
      <div className="text-gray-400">{(row.attack_ratio * 100).toFixed(1)}%</div>
    </button>
  );
}

function formatTime(value) {
  if (!value) return "N/A";
  return new Date(value).toLocaleString();
}
