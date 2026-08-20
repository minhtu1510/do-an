import { RadialBar, RadialBarChart, PolarAngleAxis } from "recharts";

// Radial gauge for a single 0-100 ratio — Grafana/Splunk-style KPI gauge.
export default function Gauge({ value, color, label, size = 140 }) {
  const pct = Math.max(0, Math.min(100, value));
  const data = [{ value: pct, fill: color }];

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <RadialBarChart
        width={size}
        height={size}
        cx="50%"
        cy="50%"
        innerRadius="72%"
        outerRadius="100%"
        barSize={10}
        data={data}
        startAngle={90}
        endAngle={-270}
      >
        <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
        <RadialBar dataKey="value" cornerRadius={5} background={{ fill: "#2c2c2a" }} />
      </RadialBarChart>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <div className="text-xl font-bold" style={{ color }}>{pct.toFixed(1)}%</div>
        {label && <div className="text-[10px] uppercase text-gray-500">{label}</div>}
      </div>
    </div>
  );
}
