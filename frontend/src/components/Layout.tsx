import type { ReactNode } from "react";
import type { About } from "../types";

const NAV = [
  ["dashboard", "Dashboard", "M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"],
  ["environments", "Environments", "M4 4h16v6H4zM4 14h16v6H4zM7 7h.01M7 17h.01"],
  ["rules", "Rules", "M9 12h6M9 16h6M7 3h7l5 5v13a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"],
  ["events", "Events", "M3 12h4l3-8 4 16 3-8h4"],
  ["detections", "Detections", "M12 2 3 6v6c0 5 3.8 9.3 9 10 5.2-.7 9-5 9-10V6l-9-4zM12 8v4m0 4h.01"],
  ["siem", "SIEM", "M4 7h16M4 12h16M4 17h10M18 15l3 2-3 2"],
  ["about", "About", "M12 22a10 10 0 1 1 0-20 10 10 0 0 1 0 20zm0-6v-4m0-4h.01"],
] as const;

const SAFE_LOGO = /^(https?:\/\/|\/)[^\s"'<>]*$/i;

export function Layout({ route, about, children }: { route: string; about: About | null; children: ReactNode }) {
  const b = about?.branding;
  const name = b?.project_name ?? "SentinelForge";
  return (
    <div className="flex h-full">
      <aside className="flex w-56 shrink-0 flex-col border-r border-ink-700 bg-ink-900">
        <a href="#/dashboard" className="flex items-center gap-2.5 border-b border-ink-700 px-4 py-4">
          {b?.organization_logo && SAFE_LOGO.test(b.organization_logo) ? (
            <img src={b.organization_logo} alt="" className="h-7 w-7 rounded object-contain" />
          ) : (
            <svg viewBox="0 0 32 32" className="h-7 w-7 shrink-0">
              <path d="M16 2 4 7v8c0 7.2 5.1 13.4 12 15 6.9-1.6 12-7.8 12-15V7L16 2z" fill="#0b1120" stroke="var(--brand)" strokeWidth="2" />
              <path d="m11 16 3.5 3.5L21 13" fill="none" stroke="var(--brand)" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          )}
          <div className="min-w-0">
            <div className="truncate text-sm font-bold tracking-wide text-slate-100">{name}</div>
            <div className="truncate text-[10px] uppercase tracking-wider text-slate-500">{b?.organization_name || "Detection Engineering"}</div>
          </div>
        </a>
        <nav className="flex-1 space-y-0.5 p-2">
          {NAV.map(([key, label, d]) => (
            <a key={key} href={`#/${key}`}
              className={`flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition ${route === key ? "bg-ink-800 text-slate-100" : "text-slate-400 hover:bg-ink-800/60 hover:text-slate-200"}`}>
              <svg viewBox="0 0 24 24" className="h-4 w-4 shrink-0" fill="none" stroke={route === key ? "var(--brand)" : "currentColor"} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d={d} /></svg>
              {label}
            </a>
          ))}
        </nav>
        <footer className="border-t border-ink-700 px-4 py-3 text-[11px] leading-relaxed text-slate-600">
          {b?.footer_text && <div className="mb-1 text-slate-500">{b.footer_text}</div>}
          {b?.customized ? <>Powered by <a href="#/about" className="hover:text-slate-400">SentinelForge</a></> : <a href="#/about" className="hover:text-slate-400">SentinelForge v{about?.upstream.version}</a>}
        </footer>
      </aside>
      <main className="min-w-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-[1400px] px-6 py-6">{children}</div>
      </main>
    </div>
  );
}
