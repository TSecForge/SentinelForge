import { useEffect, useState } from "react";
import { api } from "../services/api";
import type { Assignment, Detection, EnvironmentDetail, IngestResult, Scenario, SiemStatus } from "../types";
import { Badge, Button, Card, ErrorNote, SeverityBadge, SimBadge, StatusBadge } from "./ui";

/** Guided demo: DISCOVER -> PROFILE -> GENERATE RULES -> SIMULATE -> DETECT -> FORWARD. All data is simulated. */
export function DemoPanel({ onChange, onClose }: { onChange: () => void; onClose: () => void }) {
  const [templates, setTemplates] = useState<string[]>(["windows-web-server"]);
  const [template, setTemplate] = useState("windows-web-server");
  const [env, setEnv] = useState<EnvironmentDetail | null>(null);
  const [rules, setRules] = useState<{ counts: Record<string, number>; rules: Assignment[] } | null>(null);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [scenario, setScenario] = useState("office_powershell");
  const [result, setResult] = useState<IngestResult | null>(null);
  const [dets, setDets] = useState<Detection[]>([]);
  const [siem, setSiem] = useState<SiemStatus | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { api.templates().then((t) => setTemplates(t.templates)).catch(() => {}); }, []);

  const run = async (label: string, fn: () => Promise<void>) => {
    setBusy(label);
    setError(null);
    try { await fn(); onChange(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); } finally { setBusy(null); }
  };

  const createEnv = () => run("env", async () => {
    const e = await api.demoEnvironment(template);
    setEnv(e); setRules(null); setResult(null); setDets([]);
    const sc = await api.scenarios(e.id);
    setScenarios(sc);
    const firstRelevant = sc.find((s) => s.relevant && s.name === "office_powershell") ?? sc.find((s) => s.relevant);
    if (firstRelevant) setScenario(firstRelevant.name);
  });

  const generate = () => run("rules", async () => { setRules(await api.generateRules(env!.id)); });

  const simulate = (names: string[], benign: number) => run("sim", async () => {
    const r = await api.simulate(env!.id, names, benign);
    setResult(r.result);
    const ids = new Set(r.result.detection_ids);
    const list = await api.detections({ limit: 200, host: env!.hostname });
    setDets(list.items.filter((d) => ids.has(d.detection_id)));
    setSiem(await api.siemStatus());
  });

  const active = rules?.rules.filter((r) => r.status === "active") ?? [];
  const inactive = rules?.rules.filter((r) => r.status !== "active") ?? [];
  const p = env?.profile;

  return (
    <Card title={<span className="flex items-center gap-2">Demo Mode <Badge tone="violet">all data simulated</Badge></span>}
      actions={<Button variant="ghost" onClick={onClose}>Close</Button>} className="border-violet-800/60">
      <ErrorNote error={error} />
      <div className="grid gap-4 lg:grid-cols-2">
        <Step n={1} title="Discover environment" done={!!env}>
          <div className="flex flex-wrap items-center gap-2">
            <select value={template} onChange={(e) => setTemplate(e.target.value)}
              className="rounded-md border border-ink-600 bg-ink-800 px-2 py-1.5 text-sm">
              {templates.map((t) => <option key={t}>{t}</option>)}
            </select>
            <Button variant="primary" onClick={createEnv} disabled={!!busy}>{busy === "env" ? "Discovering…" : "Create Demo Environment"}</Button>
          </div>
          {env && (
            <div className="mt-3 rounded-md border border-emerald-800/60 bg-emerald-950/20 p-3 text-sm">
              <div className="flex items-center gap-2 font-semibold text-emerald-300">Environment discovered <SimBadge simulated={env.simulated} /></div>
              <div className="mt-1 text-slate-300">{env.hostname} · {env.os}</div>
              <div className="text-slate-500">{env.ip_addresses.filter((i) => !i.startsWith("fe80")).join(", ")}</div>
            </div>
          )}
        </Step>

        <Step n={2} title="Environment profile" done={!!p}>
          {p ? (
            <div className="space-y-2 text-sm">
              <Row label="Type">{p.environment_type.map((t) => <Badge key={t}>{t}</Badge>)}</Row>
              <Row label="Technologies">{p.technologies.map((t) => <Badge key={t} tone="sky">{t}</Badge>)}</Row>
              <Row label="Exposed">{p.exposed_services.filter((s) => s.protocol === "tcp").slice(0, 8).map((s) => <Badge key={s.port}>{s.port}/{s.service}</Badge>)}</Row>
              <Row label="Risk">{Object.entries(p.risk_context).filter(([, v]) => v === true).map(([k]) => <Badge key={k} tone="amber">{k.replace(/_/g, " ")}</Badge>)}</Row>
            </div>
          ) : <Pending />}
        </Step>

        <Step n={3} title="Generate detection rules" done={!!rules}>
          <Button variant="primary" onClick={generate} disabled={!env || !!busy}>{busy === "rules" ? "Generating…" : "Generate Rules"}</Button>
          {rules && (
            <div className="mt-3 space-y-2 text-sm">
              <div className="flex gap-2">
                <Badge tone="green">{rules.counts.active} active</Badge>
                <Badge>{rules.counts.not_applicable} not applicable</Badge>
                {rules.counts.rejected > 0 && <Badge tone="red">{rules.counts.rejected} rejected</Badge>}
              </div>
              <div className="flex max-h-28 flex-wrap gap-1 overflow-y-auto">
                {active.map((r) => <span key={r.rule_id} title={r.reason} className="rounded bg-ink-800 px-1.5 py-0.5 font-mono text-[11px] text-slate-300">{r.rule_id}</span>)}
              </div>
              {inactive.length > 0 && (
                <details className="text-xs text-slate-500">
                  <summary className="cursor-pointer">Why some rules were not activated</summary>
                  <ul className="mt-1 space-y-0.5">{inactive.map((r) => <li key={r.rule_id}><span className="font-mono text-slate-400">{r.rule_id}</span> <StatusBadge status={r.status} /> {r.reason}</li>)}</ul>
                </details>
              )}
            </div>
          )}
        </Step>

        <Step n={4} title="Simulate telemetry & detect" done={!!result}>
          <div className="flex flex-wrap items-center gap-2">
            <select value={scenario} onChange={(e) => setScenario(e.target.value)} disabled={!env}
              className="max-w-72 rounded-md border border-ink-600 bg-ink-800 px-2 py-1.5 text-sm">
              {scenarios.map((s) => <option key={s.name} value={s.name}>{s.relevant ? "" : "(inactive here) "}{s.title}</option>)}
            </select>
            <Button variant="primary" onClick={() => simulate([scenario], 0)} disabled={!rules || !!busy}>
              {busy === "sim" ? "Evaluating…" : "Simulate Security Event"}
            </Button>
            <Button onClick={() => simulate(["all"], 1000)} disabled={!rules || !!busy} title="1,000 benign events + every relevant attack scenario">
              Simulate full workload
            </Button>
          </div>
          {result && (
            <div className="mt-3 space-y-2 text-sm">
              <div className="text-slate-400">
                Evaluated <b className="text-slate-200">{result.accepted}</b> events · matched <b className="text-slate-200">{result.matched}</b> ·
                filtered <b className="text-slate-200">{result.accepted - result.matched}</b> · detections <b className="text-slate-200">{result.detections}</b>
              </div>
              <ul className="max-h-48 space-y-1 overflow-y-auto">
                {dets.map((d) => (
                  <li key={d.detection_id}>
                    <a href={`#/detections/${d.detection_id}`} className="flex items-center gap-2 rounded border border-ink-700 bg-ink-850 px-2 py-1.5 hover:border-brand">
                      <SeverityBadge severity={d.severity} />
                      <span className="font-medium text-slate-200">{d.rule_name}</span>
                      <span className="ml-auto font-mono text-[11px] text-slate-500">{d.mitre_technique}</span>
                    </a>
                  </li>
                ))}
                {result.detections === 0 && <li className="text-slate-500">No rule matched: the event was filtered (not forwarded).</li>}
              </ul>
              {siem && (
                <div className="text-xs text-slate-500">
                  SIEM: <span className="text-slate-300">{siem.mode}</span>{" "}
                  {siem.mode === "disabled" ? "- detections stored locally" : `- ${siem.delivered} delivered, ${siem.failed} failed`}
                </div>
              )}
            </div>
          )}
        </Step>
      </div>
    </Card>
  );
}

function Step({ n, title, done, children }: { n: number; title: string; done: boolean; children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-ink-700 bg-ink-850 p-3">
      <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-slate-200">
        <span className={`flex h-5 w-5 items-center justify-center rounded-full text-[10px] ${done ? "bg-brand text-ink-950" : "border border-ink-600 text-slate-500"}`}>{done ? "✓" : n}</span>
        {title}
      </div>
      {children}
    </div>
  );
}

const Row = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <div className="flex flex-wrap items-center gap-1"><span className="w-24 shrink-0 text-xs text-slate-500">{label}</span>{children}</div>
);
const Pending = () => <div className="text-sm text-slate-600">Waiting for discovery…</div>;
