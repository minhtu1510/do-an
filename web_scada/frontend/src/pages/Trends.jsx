import { useEffect, useState } from "react";
import { fetchProcessHistory } from "../services/api";

export default function Trends() {
  const [historyStatus, setHistoryStatus] = useState(null);

  useEffect(() => {
    fetchProcessHistory().then(setHistoryStatus);
  }, []);

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-100">Trends & History</h1>
        <p className="text-sm text-gray-500">Historical trends require PostgreSQL historian storage. No synthetic trend data is displayed.</p>
      </div>

      <div className="bg-gray-800 rounded border border-gray-700 p-6">
        <div className="text-sm font-semibold text-gray-200">Historian status</div>
        <div className="mt-2 text-2xl font-bold text-yellow-400">Not configured</div>
        <div className="mt-2 text-sm text-gray-500">
          {historyStatus?.message || "PostgreSQL historian is not configured."}
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <InfoCard label="Tag history API" value="Reserved" />
        <InfoCard label="Process history API" value="Reserved" />
        <InfoCard label="Snapshot interval" value="Not configured" />
        <InfoCard label="Storage backend" value="PostgreSQL unavailable" />
      </div>
    </div>
  );
}

function InfoCard({ label, value }) {
  return (
    <div className="rounded border border-gray-700 bg-gray-800 p-4">
      <div className="text-xs uppercase text-gray-500">{label}</div>
      <div className="mt-1 font-mono text-sm font-bold text-gray-300">{value}</div>
    </div>
  );
}
