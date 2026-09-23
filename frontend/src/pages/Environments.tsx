import { useState } from "react";
import { EstateTopology, HostTopology } from "../components/Topology";
import { Badge, Button, Card, Code, Empty, ErrorNote, fmtTime, KV, PageHeader, SeverityBadge, SimBadge, StatusBadge, Table, Td, Th } from "../components/ui";
import { go, useApi } from "../hooks";
import { api } from "../services/api";

export function Environments() {
  const { data: envs, error, reload } = useApi(api.environments);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [showImport, setShowImport] = useState(false);
  const [json, setJson] = useState("");

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true); setErr(null);
    try { await fn(); await reload(); } catch (e) { setErr(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); }
  };

  return (
    <>
      <PageHeader title="Environments" subtitle="Hosts discovered agentlessly. Each discovery creates a versioned environment profile."
        actions={<>
          <Button onClick={() => act(() => api.discover({ mode: "demo", template: "windows-web-server" }))} disabled={busy}>+ Demo web server</Button>
          <Button onClick={() => act(() => api.discover({ mode: "demo", template: "windows-workstation" }))} disabled={busy}>+ Demo workstation</Button>
          <Button onClick={() => act(() => api.discover({ mode: "demo", template: "docker-host" }))} disabled={busy}>+ Demo Docker host</Button>
          <Button onClick={() => act(() => api.discover({ mode: "demo", template: "linux-k8s-node" }))} disabled={busy}>+ Demo K8s node</Button>
          <Button onClick={() => setShowImport((v) => !v)}>Import inventory</Button>
          <Button variant="primary" onClick={() => act(() => api.discover({ mode: "local" }))} disabled={busy}
            title="Runs collectors/windows/discovery.ps1 on the API host. Requires ENABLE_LIVE_DISCOVERY=true.">{busy ? "Working…" : "Discover this host (live)"}</Button>
        </>} />
      <div className="space-y-4">
        <ErrorNote error={err || error} />
        {showImport && (
          <Card title="Import inventory JSON (output of collectors/windows/discovery.ps1 or any schema-1.0 collector)">
            <textarea value={json} onChange={(e) => setJson(e.target.value)} rows={8} placeholder='{"schema_version": "1.0", ...}'
              className="w-full rounded-md border border-ink-600 bg-ink-950 p-2 font-mono text-xs" />
            <div className="mt-2"><Button variant="primary" disabled={busy || !json} onClick={() => act(async () => {
              let inv: unknown;
              try { inv = JSON.parse(json); } catch { throw new Error("Not valid JSON"); }
              await api.discover({ mode: "import", inventory: inv });
              setJson(""); setShowImport(false);
            })}>Import</Button></div>
          </Card>
        )}
        {envs?.length ? (
          <>
            <Card title="Estate topology"><EstateTopology envs={envs} /></Card>
            <Card title={`${envs.length} environment(s)`}>
              <Table head={<tr><Th>Host</Th><Th>OS</Th><Th>Addresses</Th><Th>Technologies</Th><Th>Active rules</Th><Th>Discovered</Th></tr>}>
                {envs.map((e) => (
                  <tr key={e.id} className="cursor-pointer hover:bg-ink-850" onClick={() => go("environments", e.id)}>
                    <Td><div className="font-semibold text-slate-100">{e.hostname}</div><div className="flex gap-1"><Badge>{e.discovery_mode}</Badge><SimBadge simulated={e.simulated} /></div></Td>
                    <Td className="text-slate-400">{e.os}</Td>
                    <Td className="font-mono text-xs text-slate-400">{e.cidrs.filter((c) => !c.includes(":")).join(", ")}</Td>
                    <Td><div className="flex flex-wrap gap-1">{e.technologies.map((t) => <Badge key={t} tone="sky">{t}</Badge>)}</div></Td>
                    <Td className="tabular-nums">{e.active_rules}</Td>
                    <Td className="whitespace-nowrap text-xs text-slate-500">{fmtTime(e.discovered_at)}</Td>
                  </tr>
                ))}
              </Table>
            </Card>
          </>
        ) : <Empty>No environments yet. Add a demo environment or import an inventory.</Empty>}
      </div>
    </>
  );
}

export function EnvironmentDetailPage({ id }: { id: number }) {
  const { data: env, error, reload } = useApi(() => api.environment(id), [id]);
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState<"profile" | "rules" | "inventory">("profile");

  if (error) return <ErrorNote error={error} />;
  if (!env) return <div className="text-slate-500">Loading…</div>;
  const p = env.profile;
  const inv = env.inventory;
  const containers = (inv.containers?.containers ?? []) as { name: string; image: string; ports: string[] }[];

  const generate = async () => { setBusy(true); try { await api.generateRules(env.id); await reload(); setTab("rules"); } finally { setBusy(false); } };
  const toggle = async (aid: number, status: "active" | "disabled") => { await api.setAssignment(env.id, aid, status); reload(); };

  return (
    <>
      <PageHeader title={env.hostname} subtitle={<span className="flex items-center gap-2">{env.os} <SimBadge simulated={env.simulated} /> <Badge>{env.discovery_mode}</Badge> <span>profile v{env.profile_count}</span></span>}
        actions={<>
          <a href="#/environments" className="text-sm text-slate-400 hover:text-slate-200">← Environments</a>
          <Button variant="primary" onClick={generate} disabled={busy || !p}>{busy ? "Generating…" : env.rules.length ? "Regenerate Rules" : "Generate Rules"}</Button>
        </>} />
      <div className="mb-4 flex gap-1 border-b border-ink-700">
        {(["profile", "rules", "inventory"] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)} className={`-mb-px border-b-2 px-3 py-2 text-sm capitalize ${tab === t ? "border-brand text-slate-100" : "border-transparent text-slate-500 hover:text-slate-300"}`}>
            {t === "rules" ? `Detection rules (${env.rules.filter((r) => r.status === "active").length} active)` : t}
          </button>
        ))}
      </div>

      {tab === "profile" && p && (
        <div className="space-y-4">
          <Card title="Topology"><HostTopology profile={p} containers={containers} /></Card>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Environment profile">
              <KV rows={[
                ["Platform", p.platform],
                ["Environment type", <div className="flex flex-wrap gap-1">{p.environment_type.map((t) => <Badge key={t}>{t}</Badge>)}</div>],
                ["Technologies", <div className="flex flex-wrap gap-1">{p.technologies.map((t) => <Badge key={t} tone="sky">{t}</Badge>)}</div>],
                ["Relevant rule categories", <div className="flex flex-wrap gap-1">{p.rule_categories.map((t) => <Badge key={t}>{t}</Badge>)}</div>],
                ["Docker", inv.containers?.docker ? `yes (${containers.length} containers, service ${inv.containers.docker_service_status || "?"})` : "no"],
                ["Kubernetes", inv.containers?.kubernetes ? `yes (${(inv.containers.kubernetes_indicators ?? []).join(", ")})` : (inv.containers?.kubernetes_indicators?.length ? `indicators only: ${inv.containers.kubernetes_indicators.join(", ")}` : "no")],
                ["Risk context", <div className="flex flex-wrap gap-1">{Object.entries(p.risk_context).map(([k, v]) => (
                  <Badge key={k} tone={v === true || (Array.isArray(v) && v.length) ? "amber" : "slate"}>{k.replace(/_/g, " ")}: {Array.isArray(v) ? (v.join(", ") || "none") : String(v)}</Badge>))}</div>],
              ]} />
            </Card>
            <Card title="Network">
              <KV rows={[
                ["IP addresses", <span className="font-mono text-xs">{p.network.ip_addresses.join(", ")}</span>],
                ["CIDRs", <span className="font-mono text-xs">{p.network.cidrs.join(", ")}</span>],
                ["Gateways", <span className="font-mono text-xs">{p.network.gateways.join(", ")}</span>],
                ["DNS servers", <span className="font-mono text-xs">{p.network.dns_servers.join(", ")}</span>],
                ["Routes", p.network.route_count],
                ["Internal ranges (rule parameter)", <span className="font-mono text-xs">{(p.parameters.internal_cidrs ?? []).join(", ")}</span>],
              ]} />
            </Card>
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Exposed services (service-to-port)">
              <Table head={<tr><Th>Proto/Port</Th><Th>Service</Th><Th>Process</Th><Th>Bind</Th></tr>}>
                {p.exposed_services.map((s) => (
                  <tr key={`${s.protocol}${s.port}`}><Td className="font-mono text-sky-300">{s.protocol}/{s.port}</Td><Td>{s.service}</Td><Td className="text-slate-400">{s.process}</Td><Td className="font-mono text-xs text-slate-500">{s.bind}</Td></tr>
                ))}
              </Table>
            </Card>
            <Card title="Evidence (why each technology was detected)">
              <ul className="space-y-1.5 text-sm">{Object.entries(p.evidence).map(([t, ev]) => (
                <li key={t}><Badge tone="sky">{t}</Badge> <span className="text-slate-400">{ev.join("; ")}</span></li>
              ))}</ul>
            </Card>
          </div>
        </div>
      )}

      {tab === "rules" && (
        env.rules.length ? (
          <Card title="Rule selection for this environment" actions={<span className="text-xs text-slate-500">Rules are activated only when the environment needs them</span>}>
            <Table head={<tr><Th>Rule</Th><Th>Severity</Th><Th>Status</Th><Th>Why</Th><Th>Triggers</Th><Th /></tr>}>
              {env.rules.map((r) => (
                <tr key={r.assignment_id} className={r.status === "not_applicable" ? "opacity-60" : ""}>
                  <Td><a href={`#/rules/${r.rule_id}`} className="font-mono text-xs text-brand">{r.rule_id}</a> <span className="text-xs text-slate-500">v{r.version}</span><div className="text-slate-200">{r.name}</div></Td>
                  <Td><SeverityBadge severity={r.severity} /></Td>
                  <Td><StatusBadge status={r.status} /></Td>
                  <Td className="max-w-md text-xs text-slate-400">{r.reason}</Td>
                  <Td className="tabular-nums">{r.trigger_count}</Td>
                  <Td>{r.status === "active" ? <Button variant="ghost" onClick={() => toggle(r.assignment_id, "disabled")}>Disable</Button>
                    : r.status === "disabled" ? <Button variant="ghost" onClick={() => toggle(r.assignment_id, "active")}>Enable</Button> : null}</Td>
                </tr>
              ))}
            </Table>
          </Card>
        ) : <Empty>No rules generated yet. Click “Generate Rules”.</Empty>
      )}

      {tab === "inventory" && <Card title="Raw inventory (schema 1.0)"><Code className="max-h-[70vh]">{JSON.stringify(inv, null, 2)}</Code></Card>}
    </>
  );
}
