const STEPS = [
  ["Add Environment", "#/environments"],
  ["Discover", "#/environments"],
  ["View Profile", "#/environments"],
  ["Generate Rules", "#/environments"],
  ["Activate Rules", "#/rules"],
  ["Receive Events", "#/events"],
  ["Detect", "#/detections"],
  ["Investigate", "#/detections"],
  ["Forward to SIEM", "#/siem"],
] as const;

/** The primary workflow, shown persistently. `reached` = how many steps have happened so far. */
export function Workflow({ reached }: { reached: number }) {
  return (
    <ol className="flex flex-wrap items-center gap-y-2 rounded-lg border border-ink-700 bg-ink-900 px-3 py-2.5 text-xs">
      {STEPS.map(([label, href], i) => {
        const done = i < reached;
        return (
          <li key={label} className="flex items-center">
            <a href={href} className={`flex items-center gap-1.5 rounded px-2 py-1 transition hover:bg-ink-800 ${done ? "text-slate-200" : "text-slate-500"}`}>
              <span className={`flex h-4 w-4 items-center justify-center rounded-full text-[9px] font-bold ${done ? "bg-brand text-ink-950" : "border border-ink-600 text-slate-500"}`}>
                {done ? "✓" : i + 1}
              </span>
              {label}
            </a>
            {i < STEPS.length - 1 && <span className="mx-0.5 text-ink-600">→</span>}
          </li>
        );
      })}
    </ol>
  );
}
