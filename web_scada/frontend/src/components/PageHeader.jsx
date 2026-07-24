export default function PageHeader({ title, subtitle, right }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-gray-800 pb-4">
      <div className="flex gap-3">
        <div className="mt-1 h-6 w-1 rounded-full bg-blue-500" />
        <div>
          <h1 className="text-xl font-bold text-gray-100">{title}</h1>
          {subtitle && <p className="mt-1 text-sm text-gray-500">{subtitle}</p>}
        </div>
      </div>
      {right && <div className="shrink-0">{right}</div>}
    </div>
  );
}
