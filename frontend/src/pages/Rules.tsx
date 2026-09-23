import { useMemo, useState } from "react";
import { Badge, Button, Card, Code, Empty, ErrorNote, KV, PageHeader, SeverityBadge, StatusBadge, Table, Td, Th } from "../components/ui";
import { go, useApi } from "../hooks";
import { api } from "../services/api";

export function Rules() {
  const { data: rules, error, reload } = useApi(api.rules);
  const [q, setQ] = useState("");
  const [platform, setPlatform] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [yaml, setYaml] = useState("");
  const [validation, setValidation] = useState<{ valid: boolean; errors: string[] } | null>(null);

  const rows = useMemo(() => (rules ?? []).filter((r) =>
    (!platform || r.platform === platform) &&
    (!q || `${r.rule_id} ${r.name} ${r.mitre_technique} ${r.author}`.toLowerCase().includes(q.toLowerCase()))), [rules, q, platform]);

  const reloadPacks = async () => {
    const r = await api.reloadRules();
    setMsg(`Rule packs reloaded: ${r.new} new, ${r.unchanged} unchanged, ${Object.keys(r.errors).length} file(s) with errors.`);
    reload();
  };

  return (
    <>
      <PageHeader title="Detection rules" subtitle="Rule templates from RULE_PATHS (built-in + organization/custom packs). Environment-specific versions are generated per host."
        actions={<Button onClick={reloadPacks}>Reload rule packs</Button>} />
      <div className="space-y-4">
        <ErrorNote error={error} />
        {msg && <div className="text-sm text-slate-400">{msg}</div>}
        <div className="flex flex-wrap gap-2">
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search id, name, technique, author…"
            className="w-72 rounded-md border border-ink-600 bg-ink-900 px-3 py-1.5 text-sm" />
          <select value={platform} onChange={(e) => setPlatform(e.target.value)} className="rounded-md border border-ink-600 bg-ink-900 px-2 py-1.5 text-sm">
            <option value="">All platforms</option>
            {[...new Set((rules ?? []).map((r) => r.platform))].map((p) => <option key={p}>{p}</option>)}
          </select>
        </div>
        <Card title={`${rows.length} rule(s)`}>
          {rows.length ? (
            <Table head={<tr><Th>ID</Th><Th>Name</Th><Th>Platform</Th><Th>Severity</Th><Th>Status</Th><Th>Version</Th><Th>MITRE</Th><Th>Applicability</Th><Th>Active in</Th><Th>Source</Th></tr>}>
              {rows.map((r) => (
                <tr key={r.rule_id} className="cursor-pointer hover:bg-ink-850" onClick={() => go("rules", r.rule_id)}>
                  <Td className="font-mono text-xs text-brand">{r.rule_id}</Td>
                  <Td className="text-slate-200">{r.name}</Td>
                  <Td><Badge>{r.platform}</Badge></Td>
                  <Td><SeverityBadge severity={r.severity} /></Td>
                  <Td><Badge tone={r.status === "stable" ? "green" : "amber"}>{r.status}</Badge></Td>
                  <Td className="text-slate-400">{r.version}</Td>
                  <Td className="font-mono text-xs text-slate-400">{r.mitre_technique}</Td>
                  <Td className="text-xs text-slate-500">{[...r.applies_when.technologies, ...r.applies_when.environment_types].join(", ") || (["docker", "kubernetes"].includes(r.platform) ? r.platform : "any " + r.platform)}</Td>
                  <Td className="tabular-nums">{r.active_environments} host(s){r.triggers ? <span className="text-orange-400"> · {r.triggers} hits</span> : ""}</Td>
                  <Td><Badge tone={r.source === "builtin" ? "slate" : "violet"}>{r.source}</Badge></Td>
                </tr>
              ))}
            </Table>
          ) : <Empty>No rules match.</Empty>}
        </Card>
        <Card title="Validate a rule (nothing is stored)">
          <textarea value={yaml} onChange={(e) => setYaml(e.target.value)} rows={8} placeholder="Paste rule YAML…"
            className="w-full rounded-md border border-ink-600 bg-ink-950 p-2 font-mono text-xs" />
          <div className="mt-2 flex items-center gap-3">
            <Button onClick={async () => setValidation(await api.validateRule(yaml))} disabled={!yaml}>Validate</Button>
            {validation && (validation.valid ? <Badge tone="green">valid</Badge> : <span className="text-sm text-rose-300">{validation.errors.join(" · ")}</span>)}
          </div>
        </Card>
      </div>
    </>
  );
}

export function RuleDetailPage({ id }: { id: string }) {
  const { data: r, error } = useApi(() => api.rule(id), [id]);
  if (error) return <ErrorNote error={error} />;
  if (!r) return <div className="text-slate-500">Loading…</div>;
  const d = r.definition;
  return (
    <>
      <PageHeader title={`${r.rule_id} · ${d.name}`} subtitle={d.description}
        actions={<a href="#/rules" className="text-sm text-slate-400 hover:text-slate-200">← Rules</a>} />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Metadata">
          <KV rows={[
            ["Severity", <SeverityBadge severity={d.severity} />],
            ["Version", r.version], ["Author", d.author], ["Source", d.source], ["Platform", d.platform], ["Event type", d.event_type],
            ["Fidelity", `${d.fidelity} (drives the documented confidence score)`],
            ["MITRE", d.mitre ? `${d.mitre.technique} (${d.mitre.tactic})` : null],
            ["Applies when", JSON.stringify(d.applies_when)],
            ["Tags", (d.tags ?? []).join(", ")],
            ["False positives", (d.false_positives ?? []).join("; ")],
            ["File", <span className="font-mono text-xs">{r.file_path}</span>],
            ["Versions", r.versions.map((v) => `${v.version} (${v.status})`).join(", ")],
          ]} />
        </Card>
        <Card title="YAML (template)"><Code className="max-h-[480px]">{r.yaml}</Code></Card>
      </div>
      <div className="mt-4">
        <Card title="Environment applicability">
          {r.assignments.length ? (
            <Table head={<tr><Th>Host</Th><Th>Version</Th><Th>Status</Th><Th>Reason</Th><Th>Triggers</Th></tr>}>
              {r.assignments.map((a) => (
                <tr key={a.assignment_id}>
                  <Td className="font-medium">{a.hostname}</Td><Td>{a.version}</Td><Td><StatusBadge status={a.status} /></Td>
                  <Td className="text-xs text-slate-400">{a.reason}</Td><Td className="tabular-nums">{a.trigger_count}</Td>
                </tr>
              ))}
            </Table>
          ) : <Empty>Not evaluated against any environment yet.</Empty>}
          {r.assignments.find((a) => a.generated && a.status === "active") && (
            <details className="mt-3">
              <summary className="cursor-pointer text-sm text-slate-400">Generated (environment-specific) rule as executed</summary>
              <Code className="mt-2 max-h-96">{JSON.stringify(r.assignments.find((a) => a.generated && a.status === "active")!.generated, null, 2)}</Code>
            </details>
          )}
        </Card>
      </div>
    </>
  );
}
