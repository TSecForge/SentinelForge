import { useState } from "react";
import { Badge, Button, Card, Code, Empty, ErrorNote, fmtNum, fmtTime, PageHeader, SeverityBadge, SimBadge, Table, Td, Th } from "../components/ui";
import { useApi } from "../hooks";
import { api } from "../services/api";

type Filters = { host?: string; source?: string; event_type?: string; severity?: string; matched?: string; since?: string; until?: string; offset: number };

export function Events() {
  const [f, setF] = useState<Filters>({ offset: 0 });
  const facets = useApi(api.eventFacets);
  const { data, error } = useApi(() => api.events({
    ...f, matched: f.matched === "" || f.matched === undefined ? undefined : f.matched === "true",
    since: f.since ? new Date(f.since).toISOString() : undefined, until: f.until ? new Date(f.until).toISOString() : undefined, limit: 100,
  }), [JSON.stringify(f)]);
  const [open, setOpen] = useState<number | null>(null);
  const detail = useApi(() => (open ? api.event(open) : Promise.resolve(null)), [open]);

  const set = (k: keyof Filters) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value || undefined, offset: 0 });
  const sel = (k: keyof Filters, label: string, opts: string[]) => (
    <select value={(f[k] as string) ?? ""} onChange={set(k)} className="rounded-md border border-ink-600 bg-ink-900 px-2 py-1.5 text-sm">
      <option value="">{label}</option>{opts.map((o) => <option key={o}>{o}</option>)}
    </select>
  );

  return (
    <>
      <PageHeader title="Normalized events" subtitle="Every source is normalized into one event model before rules run. Unmatched events are counted as filtered." />
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          {sel("host", "All hosts", facets.data?.host ?? [])}
          {sel("source", "All sources", facets.data?.source ?? [])}
          {sel("event_type", "All event types", facets.data?.event_type ?? [])}
          {sel("severity", "Any severity", ["critical", "high", "medium", "low", "informational"])}
          <select value={f.matched ?? ""} onChange={set("matched")} className="rounded-md border border-ink-600 bg-ink-900 px-2 py-1.5 text-sm">
            <option value="">Matched + filtered</option><option value="true">Matched only</option><option value="false">Filtered only</option>
          </select>
          <label className="text-xs text-slate-500">from <input type="datetime-local" value={f.since ?? ""} onChange={set("since")} className="rounded-md border border-ink-600 bg-ink-900 px-2 py-1 text-sm" /></label>
          <label className="text-xs text-slate-500">to <input type="datetime-local" value={f.until ?? ""} onChange={set("until")} className="rounded-md border border-ink-600 bg-ink-900 px-2 py-1 text-sm" /></label>
          <Button variant="ghost" onClick={() => setF({ offset: 0 })}>Clear</Button>
        </div>
        <ErrorNote error={error} />
        <div className="grid gap-4 xl:grid-cols-[1fr_420px]">
          <Card title={`${fmtNum(data?.total)} event(s)`} actions={
            <div className="flex gap-1">
              <Button variant="ghost" disabled={f.offset === 0} onClick={() => setF({ ...f, offset: Math.max(0, f.offset - 100) })}>‹ Prev</Button>
              <Button variant="ghost" disabled={!data || f.offset + 100 >= data.total} onClick={() => setF({ ...f, offset: f.offset + 100 })}>Next ›</Button>
            </div>}>
            {data?.items.length ? (
              <Table head={<tr><Th>Time</Th><Th>Host</Th><Th>Source</Th><Th>Type</Th><Th>Result</Th><Th>Summary</Th></tr>}>
                {data.items.map((e) => (
                  <tr key={e.id} onClick={() => setOpen(e.id)} className={`cursor-pointer hover:bg-ink-850 ${open === e.id ? "bg-ink-850" : ""}`}>
                    <Td className="whitespace-nowrap text-xs text-slate-500">{fmtTime(e.timestamp)}</Td>
                    <Td className="whitespace-nowrap">{e.host} <SimBadge simulated={e.simulated} /></Td>
                    <Td><Badge>{e.source}</Badge></Td>
                    <Td className="font-mono text-xs text-slate-300">{e.event_type}</Td>
                    <Td>{e.matched ? <SeverityBadge severity={e.max_severity} /> : <span className="text-xs text-slate-600">filtered</span>}</Td>
                    <Td className="max-w-md truncate font-mono text-xs text-slate-500">{e.summary}</Td>
                  </tr>
                ))}
              </Table>
            ) : <Empty>No events.</Empty>}
          </Card>
          <Card title="Event detail">
            {detail.data ? <Code className="max-h-[70vh]">{JSON.stringify(detail.data.data, null, 2)}</Code> : <Empty>Select an event.</Empty>}
          </Card>
        </div>
      </div>
    </>
  );
}
