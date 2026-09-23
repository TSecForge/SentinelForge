import { useState } from "react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { DemoPanel } from "../components/DemoPanel";
import { Button, Card, Empty, ErrorNote, fmtNum, fmtTime, PageHeader, SEVERITY_COLOR, SeverityBadge, SimBadge, Stat, Table, Td, Th } from "../components/ui";
import { Workflow } from "../components/Workflow";
import { useApi } from "../hooks";
import { api } from "../services/api";
import type { About } from "../types";

const tooltip = { contentStyle: { background: "#0b1120", border: "1px solid #1e293b", borderRadius: 6, fontSize: 12 }, labelStyle: { color: "#94a3b8" } };

export function Dashboard({ about }: { about: About | null }) {
  const { data: s, error, reload } = useApi(api.dashboard, [], 15000);
  const [demo, setDemo] = useState(false);
  const m = s?.metrics;

  const reached = !s ? 0 : m!.siem_delivered > 0 ? 9 : s.detections > 0 ? 8 : m!.events_received > 0 ? 6 : s.active_rules > 0 ? 5 : s.hosts > 0 ? 3 : 0;

  const reset = async () => {
    if (!confirm("Delete all environments, events, detections and counters? Rule packs are kept.")) return;
    await api.demoReset();
    reload();
  };

  return (
    <>
      <PageHeader title={about?.branding.dashboard_title ?? "Detection Operations"}
        subtitle={about?.branding.project_description}
        actions={<>
          <Button variant="primary" onClick={() => setDemo(true)}>▶ Demo Mode</Button>
          <Button onClick={reload}>Refresh</Button>
          <Button variant="danger" onClick={reset} title="Clear all data">Reset data</Button>
        </>} />
      <div className="space-y-4">
        <Workflow reached={reached} />
        {demo && <DemoPanel onChange={reload} onClose={() => setDemo(false)} />}
        <ErrorNote error={error} />

        <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
          <Stat label="Hosts" value={fmtNum(s?.hosts)} hint={s?.simulated_hosts ? `${s.simulated_hosts} simulated` : undefined} />
          <Stat label="Active rules" value={fmtNum(s?.active_rules)} hint={`${s?.distinct_active_rules ?? 0} distinct`} />
          <Stat label="Events received" value={fmtNum(m?.events_received)} />
          <Stat label="Events filtered" value={fmtNum(m?.events_filtered)} hint="no rule matched" />
          <Stat label="Detections" value={fmtNum(s?.detections)} />
          <Stat label="High / critical" value={fmtNum(s?.high_severity)} accent="text-orange-400" />
          <Stat label="Events forwarded" value={fmtNum(m?.events_forwarded)} hint={m ? `${m.detections_created} detection docs · ${m.siem_delivered} to SIEM` : undefined} />
          <Stat label="Reduction" value={`${m?.reduction_percentage ?? 0}%`} accent="text-brand" hint="this workload" />
        </div>
        {m && m.events_received > 0 && (
          <p className="text-xs text-slate-500">{m.statement} Measured on the events processed by this instance; not a general guarantee.</p>
        )}

        <div className="grid gap-4 xl:grid-cols-3">
          <Card title="Event volume (5-min buckets, event time)" className="xl:col-span-2">
            {s?.event_volume.length ? (
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={s.event_volume.map((v) => ({ ...v, label: new Date(v.t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) }))}>
                  <CartesianGrid stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="label" stroke="#475569" fontSize={11} tickLine={false} />
                  <YAxis stroke="#475569" fontSize={11} tickLine={false} width={40} />
                  <Tooltip {...tooltip} />
                  <Area type="monotone" dataKey="events" name="received" stroke="#64748b" fill="#64748b33" />
                  <Area type="monotone" dataKey="matched" name="matched" stroke="#f97316" fill="#f9731655" />
                </AreaChart>
              </ResponsiveContainer>
            ) : <Empty>No events yet. Start Demo Mode to generate simulated telemetry.</Empty>}
          </Card>
          <Card title="Severity distribution">
            {s?.detections ? (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={s.severity_distribution}>
                  <CartesianGrid stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="severity" stroke="#475569" fontSize={11} tickLine={false} />
                  <YAxis stroke="#475569" fontSize={11} tickLine={false} width={30} allowDecimals={false} />
                  <Tooltip {...tooltip} cursor={{ fill: "#1e293b55" }} />
                  <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                    {s.severity_distribution.map((d) => <Cell key={d.severity} fill={SEVERITY_COLOR[d.severity]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : <Empty>No detections yet.</Empty>}
          </Card>
        </div>

        <div className="grid gap-4 xl:grid-cols-3">
          <Card title="Recent detections" className="xl:col-span-2" actions={<a href="#/detections" className="text-xs text-brand">View all →</a>}>
            {s?.recent_detections.length ? (
              <Table head={<tr><Th>Time</Th><Th>Severity</Th><Th>Rule</Th><Th>Host</Th><Th>MITRE</Th></tr>}>
                {s.recent_detections.map((d) => (
                  <tr key={d.detection_id} className="cursor-pointer hover:bg-ink-850" onClick={() => (window.location.hash = `/detections/${d.detection_id}`)}>
                    <Td className="whitespace-nowrap text-xs text-slate-500">{fmtTime(d.timestamp)}</Td>
                    <Td><SeverityBadge severity={d.severity} /></Td>
                    <Td><div className="font-medium text-slate-200">{d.rule_name}</div><div className="truncate text-xs text-slate-500">{d.description}</div></Td>
                    <Td className="whitespace-nowrap">{d.host} <SimBadge simulated={d.simulated} /></Td>
                    <Td className="font-mono text-xs text-slate-400">{d.mitre_technique}</Td>
                  </tr>
                ))}
              </Table>
            ) : <Empty>No detections yet.</Empty>}
          </Card>
          <div className="space-y-4">
            <Card title="Top rules">
              {s?.top_rules.length ? (
                <ul className="space-y-1.5 text-sm">{s.top_rules.map((r) => (
                  <li key={r.rule_id} className="flex justify-between gap-2"><a href={`#/rules/${r.rule_id}`} className="truncate text-slate-300 hover:text-brand">{r.name}</a><span className="tabular-nums text-slate-500">{r.count}</span></li>
                ))}</ul>
              ) : <Empty>-</Empty>}
            </Card>
            <Card title="MITRE ATT&CK techniques observed">
              {s?.mitre.length ? (
                <ul className="space-y-1 text-sm">{s.mitre.map((t) => (
                  <li key={t.technique} className="flex justify-between gap-2"><span><span className="font-mono text-slate-300">{t.technique}</span> <span className="text-xs text-slate-500">{t.tactic}</span></span><span className="tabular-nums text-slate-500">{t.count}</span></li>
                ))}</ul>
              ) : <Empty>-</Empty>}
            </Card>
          </div>
        </div>
      </div>
    </>
  );
}
