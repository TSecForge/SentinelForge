import { useState } from "react";
import { Badge, Card, Code, Empty, ErrorNote, fmtNum, fmtTime, KV, PageHeader, SeverityBadge, SimBadge, StatusBadge, Table, Td, Th } from "../components/ui";
import { go, useApi } from "../hooks";
import { api } from "../services/api";

export function Detections() {
  const [f, setF] = useState<{ severity?: string; host?: string; q?: string }>({});
  const { data, error } = useApi(() => api.detections({ ...f, limit: 200 }), [JSON.stringify(f)], 15000);
  return (
    <>
      <PageHeader title="Detections" subtitle="Normalized sentinelforge.detection.v1 events produced by the deterministic rule engine." />
      <div className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <input placeholder="Search rule, host, description…" value={f.q ?? ""} onChange={(e) => setF({ ...f, q: e.target.value || undefined })}
            className="w-72 rounded-md border border-ink-600 bg-ink-900 px-3 py-1.5 text-sm" />
          <select value={f.severity ?? ""} onChange={(e) => setF({ ...f, severity: e.target.value || undefined })} className="rounded-md border border-ink-600 bg-ink-900 px-2 py-1.5 text-sm">
            <option value="">Any severity</option>{["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}
          </select>
        </div>
        <ErrorNote error={error} />
        <Card title={`${fmtNum(data?.total)} detection(s)`}>
          {data?.items.length ? (
            <Table head={<tr><Th>Time</Th><Th>Severity</Th><Th>Rule</Th><Th>Host</Th><Th>MITRE</Th><Th>Observables</Th><Th>Delivery</Th></tr>}>
              {data.items.map((d) => (
                <tr key={d.detection_id} className="cursor-pointer hover:bg-ink-850" onClick={() => go("detections", d.detection_id)}>
                  <Td className="whitespace-nowrap text-xs text-slate-500">{fmtTime(d.timestamp)}</Td>
                  <Td><SeverityBadge severity={d.severity} /></Td>
                  <Td><div className="font-medium text-slate-200">{d.rule_name}</div><div className="max-w-lg truncate text-xs text-slate-500">{d.description}</div></Td>
                  <Td className="whitespace-nowrap">{d.host} <SimBadge simulated={d.simulated} /></Td>
                  <Td className="font-mono text-xs text-slate-400">{d.mitre_technique}</Td>
                  <Td className="text-xs text-slate-400">{d.observables.filter((o) => !["command_line", "hostname"].includes(o.type)).slice(0, 3).map((o) => `${o.type}:${o.value}`).join("  ")}</Td>
                  <Td><StatusBadge status={d.delivery_status} /></Td>
                </tr>
              ))}
            </Table>
          ) : <Empty>No detections.</Empty>}
        </Card>
      </div>
    </>
  );
}

export function DetectionDetailPage({ id }: { id: string }) {
  const { data: d, error } = useApi(() => api.detection(id), [id]);
  const [raw, setRaw] = useState(false);
  if (error) return <ErrorNote error={error} />;
  if (!d) return <div className="text-slate-500">Loading…</div>;
  const p = d.payload;
  return (
    <>
      <PageHeader title={d.rule_name} subtitle={<span className="flex items-center gap-2"><SeverityBadge severity={d.severity} /> {p.summary} <SimBadge simulated={d.simulated} /></span>}
        actions={<a href="#/detections" className="text-sm text-slate-400 hover:text-slate-200">← Detections</a>} />
      {d.simulated && (
        <div className="mb-4 rounded-md border border-violet-800/60 bg-violet-950/20 px-3 py-2 text-sm text-violet-300">
          This detection was produced from simulated demo telemetry. No real activity occurred.
        </div>
      )}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Detection">
          <KV rows={[
            ["Detection ID", <span className="font-mono text-xs">{d.detection_id}</span>],
            ["Timestamp", fmtTime(d.timestamp)],
            ["Host", d.host],
            ["Rule", <a href={`#/rules/${d.rule_id}`} className="text-brand">{d.rule_id} v{d.rule_version}</a>],
            ["Rule source / author", `${p.rule.source} / ${p.rule.author}`],
            ["Severity", <SeverityBadge severity={d.severity} />],
            ["Confidence", <span>{d.confidence} <span className="text-xs text-slate-500">({p.confidence_basis})</span></span>],
            ["MITRE ATT&CK", p.mitre ? `${p.mitre.technique} · ${p.mitre.tactic}` : null],
            ["Event type", d.event_type],
            ["Description", p.description],
            ["Why this rule is active here", <span className="text-xs text-slate-400">{p.context.rule_selected_because}</span>],
            ["Possible false positives", (p.context.false_positives ?? []).join("; ")],
          ]} />
        </Card>
        <Card title="Observables" actions={<span className="text-[11px] text-slate-500">extracted values, not verdicts</span>}>
          <Table head={<tr><Th>Type</Th><Th>Value</Th><Th>Seen in</Th></tr>}>
            {p.observables.map((o: { type: string; value: string; context: string }) => (
              <tr key={o.type + o.value}><Td><Badge tone="sky">{o.type}</Badge></Td><Td className="break-all font-mono text-xs">{o.value}</Td><Td className="text-xs text-slate-500">{o.context}</Td></tr>
            ))}
          </Table>
        </Card>
        <Card title="Evidence (fields the rule evaluated)">
          <Code>{JSON.stringify(p.evidence, null, 2)}</Code>
        </Card>
        <Card title="Environment context">
          <KV rows={[
            ["Environment", p.context.environment_id ? <a className="text-brand" href={`#/environments/${p.context.environment_id}`}>#{p.context.environment_id}</a> : "not profiled (baseline rules)"],
            ["Environment type", (p.context.environment_type ?? []).join(", ")],
            ["Technologies", (p.context.technologies ?? []).join(", ")],
            ["Host IPs", <span className="font-mono text-xs">{(p.context.host_ips ?? []).join(", ")}</span>],
            ["SIEM delivery", <span className="flex items-center gap-2"><StatusBadge status={d.delivery_status} />{d.delivery_attempts.map((a, i) => <span key={i} className="text-xs text-slate-500">{a.adapter} {a.status_code ?? a.error}</span>)}</span>],
          ]} />
        </Card>
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card title="Source event (normalized)"><Code className="max-h-96">{JSON.stringify(d.source_event?.data ?? p.event, null, 2)}</Code></Card>
        <Card title="Forwarded document" actions={<button onClick={() => setRaw(!raw)} className="text-xs text-brand">{raw ? "hide" : "show"}</button>}>
          {raw ? <Code className="max-h-96">{JSON.stringify(p, null, 2)}</Code> : <div className="text-sm text-slate-500">The exact sentinelforge.detection.v1 JSON sent to the SIEM.</div>}
        </Card>
      </div>
    </>
  );
}
