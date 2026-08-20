import { Line, LineChart, ResponsiveContainer } from "recharts";

// Mini trend line under a stat number — no axes/grid/tooltip, just the shape
// of the trend (Grafana/Splunk "stat panel with sparkline" pattern).
export default function Sparkline({ data, dataKey = "value", color = "#3987e5", height = 32 }) {
  if (!data || data.length < 2) return null;
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 2, right: 2, left: 2, bottom: 2 }}>
          <Line type="monotone" dataKey={dataKey} stroke={color} strokeWidth={2} dot={false} isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
