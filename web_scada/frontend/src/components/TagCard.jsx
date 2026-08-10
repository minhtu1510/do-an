export default function TagCard({ label, sublabel, value, unit, quality, stale, className }) {
  const isStale = stale;
  const bgColor = isStale ? "bg-red-950/20 border-red-900/50" : "bg-gray-800 border-gray-700";
  let displayValue;
  if (isStale) {
    displayValue = "—";
  } else if (typeof value === "boolean") {
    displayValue = value ? "TRUE" : "FALSE";
  } else if (value === null || value === undefined) {
    displayValue = "—";
  } else {
    displayValue = String(value);
  }
  const textColor = isStale ? "text-gray-600" : typeof value === "boolean" ? (value ? "text-green-400" : "text-gray-400") : "text-blue-300";

  return (
    <div className={`rounded border p-3 ${bgColor} ${className || ""}`}>
      <div className="text-xs text-gray-500">{label}</div>
      {sublabel && <div className="text-[10px] text-gray-600">{sublabel}</div>}
      <div className={`text-xl font-mono font-bold mt-1 ${textColor}`}>
        {displayValue}
        {!isStale && unit && <span className="text-sm ml-1 text-gray-500">{unit}</span>}
      </div>
      <div className="flex justify-between mt-1 text-[10px]">
        <span className={isStale ? "text-red-500" : "text-gray-600"}>
          {isStale ? "STALE" : quality || "—"}
        </span>
      </div>
    </div>
  );
}
