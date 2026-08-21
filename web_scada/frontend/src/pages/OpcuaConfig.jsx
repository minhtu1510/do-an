import { useEffect, useState } from "react";
import { Settings2, Loader2, Radio } from "lucide-react";
import { fetchOpcuaConfig, setOpcuaConfig } from "../services/api";
import PageHeader from "../components/PageHeader";
import { useConfirm } from "../components/ConfirmDialog";
import { useToast } from "../components/Toast";

// Trước đây đổi OPCUA_ENDPOINT là phải SSH vào máy, sửa tay file .env, rồi
// khởi động lại backend. Trang này gọi PUT/POST /admin/opcua-config —
// OPCUAGateway.reconfigure_endpoint() áp dụng ngay trên gateway đang chạy
// (không cần khởi động lại), đồng thời ghi lại vào .env để lần khởi động
// lại thật sự sau này vẫn dùng đúng địa chỉ mới.
export default function OpcuaConfig() {
  const confirm = useConfirm();
  const toast = useToast();
  const [current, setCurrent] = useState(null);
  const [endpoint, setEndpoint] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    fetchOpcuaConfig().then((data) => {
      setCurrent(data);
      setEndpoint(data.endpoint || "");
    });
  }, []);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!endpoint || endpoint === current?.endpoint) return;

    const ok = await confirm({
      title: "Đổi địa chỉ OPC UA server?",
      message: `Gateway sẽ ngắt kết nối hiện tại và kết nối sang "${endpoint}" ngay lập tức — mọi tag sẽ tạm hiện MẤT KẾT NỐI trong lúc chuyển.`,
      confirmLabel: "Đổi endpoint",
    });
    if (!ok) return;

    setBusy(true);
    try {
      const result = await setOpcuaConfig(endpoint);
      setCurrent({ endpoint: result.endpoint, connected: false });
      toast("Đã đổi endpoint — theo dõi Trạng thái hệ thống để xem gateway kết nối lại.", { tone: "success" });
    } catch (err) {
      toast(err.message, { tone: "error" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        icon={Settings2}
        title="Cấu hình OPC UA"
        subtitle="Đổi địa chỉ PLC/OPC UA server mà backend đang kết nối tới — áp dụng ngay, không cần khởi động lại backend."
      />

      <div className="max-w-xl rounded-lg border border-gray-700 bg-gray-800 p-6 shadow-sm shadow-black/20">
        {current === null ? (
          <div className="flex items-center gap-2 text-sm text-gray-500"><Loader2 size={14} className="animate-spin" /> Đang tải cấu hình...</div>
        ) : (
          <>
            <div className="mb-4 flex items-center gap-2 text-xs text-gray-500">
              <Radio size={13} className={current.connected ? "text-green-400" : "text-red-400"} />
              Đang kết nối tới: <span className="font-mono text-gray-300">{current.endpoint}</span>
              <span className={current.connected ? "text-green-400" : "text-red-400"}>
                ({current.connected ? "ĐÃ KẾT NỐI" : "MẤT KẾT NỐI"})
              </span>
            </div>

            <form onSubmit={handleSubmit} className="space-y-3">
              <label className="flex flex-col gap-1">
                <span className="text-xs uppercase text-gray-500">Địa chỉ OPC UA server mới</span>
                <input
                  value={endpoint}
                  onChange={(e) => setEndpoint(e.target.value)}
                  placeholder="opc.tcp://192.168.210.211:4840"
                  className="rounded border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-mono text-gray-200 outline-none transition-colors focus:border-blue-600"
                />
              </label>
              <button
                type="submit"
                disabled={busy || !endpoint || endpoint === current.endpoint}
                className="flex items-center gap-1.5 rounded bg-blue-600 px-4 py-1.5 text-sm font-semibold text-white shadow-sm shadow-blue-950 transition-colors hover:bg-blue-500 disabled:opacity-50"
              >
                {busy && <Loader2 size={14} className="animate-spin" />}
                {busy ? "Đang áp dụng..." : "Lưu và áp dụng ngay"}
              </button>
            </form>
          </>
        )}

        <div className="mt-4 text-[10px] leading-relaxed text-gray-600">
          Đổi endpoint ở đây tương đương sửa OPCUA_ENDPOINT trong .env rồi khởi động lại — chỉ khác là áp dụng ngay
          trên phiên đang chạy, không phải chờ khởi động lại. Mọi lần đổi đều được ghi vào Cảnh báo & Sự kiện.
        </div>
      </div>
    </div>
  );
}
