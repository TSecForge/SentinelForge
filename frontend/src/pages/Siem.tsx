import { useState } from "react";
import { Badge, Button, Card, Code, Empty, ErrorNote, fmtNum, fmtTime, KV, PageHeader, Stat, Table, Td, Th } from "../components/ui";
import { useApi } from "../hooks";
import { api } from "../services/api";

export function Siem() {
  const { data: s, error, reload } = useApi(api.siemStatus, [], 10000);
  const sink = useApi(api.siemReceived, [], 10000);
  const [test, setTest] = useState<string | null>(null);

  const runTest = async () => {
    const r = await api.siemTest();
    setTest(r.ok ? `OK (${r.mode}, HTTP ${r.status_code})` : `Failed: ${r.message ?? r.error ?? `HTTP ${r.status_code}`}`);
    reload();
  };

  return (
    <>
      <PageHeader title="SIEM integration" subtitle="Configured with environment variables (SIEM_MODE, WEBHOOK_URL, SPLUNK_HEC_*, ELASTIC_*). Secrets are never shown."
        actions={<Button variant="primary" onClick={runTest}>Send test event</Button>} />
      <div className="space-y-4">
        <ErrorNote error={error} />
        {test && <div className="text-sm text-slate-300">{test}</div>}
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          <Stat label="Mode" value={s?.mode ?? "-"} />
          <Stat label="Connection" value={s ? (s.mode === "disabled" ? "local only" : s.configured ? "configured" : "incomplete") : "-"}
            accent={s?.configured ? "text-emerald-400" : "text-amber-400"} />
          <Stat label="Delivered" value={fmtNum(s?.delivered)} />
          <Stat label="Failed deliveries" value={fmtNum(s?.failed)} accent={s?.failed ? "text-rose-400" : undefined} />
          <Stat label="Stored locally" value={fmtNum(s?.pending_local)} hint="not sent to a SIEM" />
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          <Card title="Integration">
            <KV rows={[
              ["Active adapter", s?.mode],
              ["Target", s?.target ? <span className="font-mono text-xs">{s.target}</span> : "-"],
              ["Available adapters", <div className="flex flex-wrap gap-1">{s?.available_adapters.map((a) => <Badge key={a}>{a}</Badge>)}</div>],
              ["Last successful delivery", fmtTime(s?.last_success)],
              ["Last error", s?.last_error ? `${fmtTime(s.last_error.at)} - ${s.last_error.status_code ?? ""} ${s.last_error.error ?? ""}` : "-"],
            ]} />
            <p className="mt-3 text-xs text-slate-500">
              Tip: set <code className="text-slate-400">SIEM_MODE=webhook</code> and <code className="text-slate-400">WEBHOOK_URL=http://127.0.0.1:8000/api/v1/siem/events</code> to
              deliver to SentinelForge's built-in test receiver (shown below) without an external SIEM.
            </p>
          </Card>
          <Card title="Recent delivery attempts">
            {s?.recent_attempts.length ? (
              <Table head={<tr><Th>Time</Th><Th>Adapter</Th><Th>Result</Th><Th>Latency</Th></tr>}>
                {s.recent_attempts.map((a) => (
                  <tr key={a.id}>
                    <Td className="text-xs text-slate-500">{fmtTime(a.at)}</Td><Td>{a.adapter}</Td>
                    <Td>{a.success ? <Badge tone="green">{a.status_code}</Badge> : <Badge tone="red" title={a.error ?? ""}>{a.status_code ?? "error"}</Badge>}</Td>
                    <Td className="tabular-nums text-xs">{a.latency_ms} ms</Td>
                  </tr>
                ))}
              </Table>
            ) : <Empty>No delivery attempts yet.</Empty>}
          </Card>
        </div>
        <Card title={`Built-in webhook receiver (${sink.data?.count ?? 0} received)`}>
          {sink.data?.items.length ? <Code className="max-h-96">{JSON.stringify(sink.data.items.slice(0, 5), null, 2)}</Code>
            : <Empty>Nothing received at /api/v1/siem/events yet.</Empty>}
        </Card>
      </div>
    </>
  );
}
