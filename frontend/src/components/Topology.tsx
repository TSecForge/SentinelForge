import type { EnvironmentSummary, Profile } from "../types";

/** Host-level view: network -> interfaces/CIDRs -> host -> exposed services / technologies / containers. */
export function HostTopology({ profile, containers }: { profile: Profile; containers: { name: string; image: string; ports: string[] }[] }) {
  const services = profile.exposed_services.filter((s) => s.protocol === "tcp").slice(0, 14);
  return (
    <div className="font-mono text-xs">
      <div className="flex flex-col items-center">
        <Node tone="net" title="Network" lines={[...profile.network.cidrs.slice(0, 4), profile.network.gateways.length ? `gw ${profile.network.gateways.join(", ")}` : ""]} />
        <Edge />
        <Node tone="host" title={profile.hostname} lines={[profile.os, profile.network.ip_addresses.filter((ip) => !ip.startsWith("fe80")).slice(0, 3).join(", ")]} />
        <Edge />
        <div className="grid w-full grid-cols-1 gap-3 md:grid-cols-3">
          <Group title="Listening services (port → service ← process)">
            {services.map((s) => (
              <div key={`${s.protocol}${s.port}`} className="flex justify-between gap-2">
                <span className="text-sky-300">{s.protocol}/{s.port}</span>
                <span className="truncate text-slate-400">{s.service}{s.process ? ` ← ${s.process}` : ""}</span>
              </div>
            ))}
            {!services.length && <span className="text-slate-600">none exposed</span>}
          </Group>
          <Group title="Technologies">
            <div className="flex flex-wrap gap-1">
              {profile.technologies.map((t) => <span key={t} className="rounded bg-ink-800 px-1.5 py-0.5 text-slate-300">{t}</span>)}
            </div>
          </Group>
          <Group title={`Containers (${containers.length})`}>
            {containers.slice(0, 10).map((c) => (
              <div key={c.name} className="truncate text-slate-400" title={c.image}>
                <span className="text-emerald-300">{c.name}</span> {c.image}{c.ports.length ? ` [${c.ports.join(", ")}]` : ""}
              </div>
            ))}
            {!containers.length && <span className="text-slate-600">no container runtime</span>}
          </Group>
        </div>
      </div>
    </div>
  );
}

/** Estate view: hosts grouped by subnet. */
export function EstateTopology({ envs }: { envs: EnvironmentSummary[] }) {
  const groups = new Map<string, EnvironmentSummary[]>();
  envs.forEach((e) => {
    const cidr = e.cidrs.find((c) => !c.includes(":") && !c.startsWith("172.")) ?? e.cidrs[0] ?? "unknown";
    groups.set(cidr, [...(groups.get(cidr) ?? []), e]);
  });
  return (
    <div className="flex flex-col items-center font-mono text-xs">
      <Node tone="net" title="Network" lines={[`${envs.length} host(s), ${groups.size} subnet(s)`]} />
      <Edge />
      <div className="flex flex-wrap justify-center gap-4">
        {[...groups.entries()].map(([cidr, hosts]) => (
          <div key={cidr} className="rounded-md border border-ink-600 p-2">
            <div className="mb-2 text-center text-sky-300">{cidr}</div>
            <div className="flex flex-wrap gap-2">
              {hosts.map((h) => (
                <a key={h.id} href={`#/environments/${h.id}`} className="rounded border border-ink-600 bg-ink-800 px-2 py-1.5 hover:border-brand">
                  <div className="font-semibold text-slate-100">{h.hostname}</div>
                  <div className="text-slate-500">{h.technologies.filter((t) => !["SMB", "Defender"].includes(t)).slice(0, 4).join(" · ") || h.platform}</div>
                </a>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function Node({ title, lines, tone }: { title: string; lines: string[]; tone: "net" | "host" }) {
  return (
    <div className={`min-w-56 rounded-md border px-3 py-2 text-center ${tone === "host" ? "border-brand bg-ink-800" : "border-ink-600 bg-ink-850"}`}>
      <div className="font-semibold text-slate-100">{title}</div>
      {lines.filter(Boolean).map((l) => <div key={l} className="text-slate-500">{l}</div>)}
    </div>
  );
}

const Edge = () => <div className="h-5 w-px bg-ink-600" />;

function Group({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-ink-700 bg-ink-850 p-2.5">
      <div className="mb-1.5 text-[10px] uppercase tracking-wider text-slate-500">{title}</div>
      <div className="space-y-0.5">{children}</div>
    </div>
  );
}
