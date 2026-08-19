export default function PageHeader({ title, subtitle, right, icon: Icon, eyebrow }) {
  return (
    <div className="flex flex-col justify-between gap-4 border-b border-slate-800/80 pb-5 sm:flex-row sm:items-start">
      <div className="flex min-w-0 gap-3.5">
        {Icon && (
          <div className="mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-cyan-400/15 bg-cyan-400/[0.08] text-cyan-300 shadow-[inset_0_1px_0_rgba(255,255,255,.03)]">
            <Icon size={19} strokeWidth={2.1} />
          </div>
        )}
        <div className="min-w-0">
          {eyebrow && <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-500/80">{eyebrow}</div>}
          <h1 className="text-xl font-semibold tracking-tight text-slate-100 sm:text-2xl">{title}</h1>
          {subtitle && <p className="mt-1.5 max-w-3xl text-sm leading-relaxed text-slate-500">{subtitle}</p>}
        </div>
      </div>
      {right && <div className="shrink-0">{right}</div>}
    </div>
  );
}
