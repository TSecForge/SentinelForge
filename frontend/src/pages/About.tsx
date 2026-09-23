import { Badge, Card, KV, PageHeader } from "../components/ui";
import type { About as AboutT } from "../types";

export function About({ about }: { about: AboutT | null }) {
  const u = about?.upstream;
  const b = about?.branding;
  return (
    <>
      <PageHeader title="About" />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={b?.customized ? b.project_name : "SentinelForge"}>
          {b?.customized && (
            <p className="mb-3 text-sm text-slate-400">
              {b.project_name}{b.organization_name ? ` (${b.organization_name})` : ""} is customized from SentinelForge.
            </p>
          )}
          <div className="space-y-2 text-sm text-slate-300">
            <div className="text-lg font-semibold text-slate-100">{u?.name}</div>
            <div className="text-slate-400">{u?.full_name}</div>
            <p>Originally created by <span className="font-semibold text-slate-100">{u?.original_creator}</span>.</p>
            <p className="text-slate-400">Open-source and extensible. Licensed under the {u?.license === "Apache-2.0" ? "Apache License 2.0" : u?.license}; see LICENSE and NOTICE in the repository.</p>
          </div>
          <div className="mt-4">
            <KV rows={[
              ["Version", u?.version],
              ["License", u?.license],
              ["Loaded plugins", about?.plugins.length ? about.plugins.join(", ") : "none"],
              ["SIEM adapters", <div className="flex flex-wrap gap-1">{about?.siem_adapters.map((a) => <Badge key={a}>{a}</Badge>)}</div>],
              ["Event parsers", <div className="flex flex-wrap gap-1">{about?.event_parsers.map((a) => <Badge key={a}>{a}</Badge>)}</div>],
            ]} />
          </div>
        </Card>
        <Card title="What this is (and is not)">
          <ul className="list-disc space-y-1.5 pl-5 text-sm text-slate-400">
            <li>An MVP demonstrating environment-aware rule activation: discover → profile → select/generate rules → detect → enrich → forward.</li>
            <li>Discovery is agentless (built-in PowerShell/WinRM). Continuous telemetry still needs a native mechanism such as Windows Event Forwarding.</li>
            <li>Detection is deterministic: validated YAML rules, no model decides what fires. Confidence is the rule's documented fidelity rating.</li>
            <li>Event reduction figures describe only the workload this instance processed.</li>
            <li>Not a complete detection capability, not enterprise-hardened, and not free of false positives.</li>
          </ul>
        </Card>
      </div>
    </>
  );
}
