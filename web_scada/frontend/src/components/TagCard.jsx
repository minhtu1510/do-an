export default function TagCard({ label, value, unit, quality, stale, updated }) {
  const bgColor = stale ? "bg-red-900/30 border-red-700" : "bg-gray-800 border-gray-700";
  const textColor = stale ? "text-red-400" : value ? "text-green-400" : "text-gray-400";

  let displayValue;
  if (typeof value === "boolean") {
    displayValue = value ? "TRUE" : "FALSE";
  } else if (value === null || value === undefined) {
    displayValue = "—";
  } else {
    displayValue = String(value);
  }

  return (
    <div className={`rounded border p-3 ${bgColor}`}>
      <div className="text-xs text-gray-500 uppercase">{label}</div>
      <div className={`text-xl font-mono font-bold mt-1 ${textColor}`}>
        {displayValue}
        {unit && <span className="text-sm ml-1 text-gray-500">{unit}</span>}
      </div>
      <div className="flex justify-between mt-1 text-[10px] text-gray-600">
        <span>{quality || "—"}</span>
        {updated && <span>{new Date(updated).toLocaleTimeString()}</span>}
      </div>
    </div>
  );
}
