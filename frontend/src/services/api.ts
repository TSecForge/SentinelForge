import type {
  About, Assignment, DashboardSummary, Detection, DetectionDetail, EnvironmentDetail, EnvironmentSummary,
  EventRow, IngestResult, Metrics, RuleDetail, RuleRow, Scenario, SiemStatus,
} from "../types";

const BASE = (import.meta.env.VITE_API_URL ?? "") + "/api/v1";
// Optional: only needed when the backend sets API_KEY. Anything in VITE_* ships to the browser.
const KEY = import.meta.env.VITE_API_KEY as string | undefined;

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (KEY) headers["X-API-Key"] = KEY;
  const res = await fetch(BASE + path, { ...init, headers: { ...headers, ...(init?.headers ?? {}) } });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const body = await res.json();
      msg = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch { /* not json */ }
    throw new ApiError(res.status, msg);
  }
  return res.json() as Promise<T>;
}

const post = <T>(path: string, body?: unknown) => req<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });

function qs(params: Record<string, string | number | boolean | undefined | null>) {
  const p = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => v !== undefined && v !== null && v !== "" && p.set(k, String(v)));
  const s = p.toString();
  return s ? `?${s}` : "";
}

export const api = {
  about: () => req<About>("/about"),
  health: () => req<{ status: string; version: string }>("/health"),
  dashboard: () => req<DashboardSummary>("/dashboard/summary"),
  metrics: () => req<Metrics>("/metrics"),

  environments: () => req<EnvironmentSummary[]>("/environments"),
  environment: (id: number) => req<EnvironmentDetail>(`/environments/${id}`),
  discover: (body: { mode: string; template?: string; target?: string; inventory?: unknown }) => post<EnvironmentDetail>("/discovery/run", body),
  templates: () => req<{ templates: string[] }>("/discovery/templates"),
  generateRules: (envId: number) => post<{ counts: Record<string, number>; rules: Assignment[] }>(`/profiles/${envId}/generate-rules`),
  setAssignment: (envId: number, assignmentId: number, status: "active" | "disabled") =>
    req<{ status: string }>(`/environments/${envId}/rules/${assignmentId}`, { method: "PATCH", body: JSON.stringify({ status }) }),

  rules: () => req<RuleRow[]>("/rules"),
  rule: (id: string) => req<RuleDetail>(`/rules/${encodeURIComponent(id)}`),
  reloadRules: () => post<{ new: number; unchanged: number; total: number; errors: Record<string, string[]> }>("/rules/reload"),
  validateRule: (yaml: string) => post<{ valid: boolean; errors: string[]; rule_id: string | null; profile_references: string[] }>("/rules/validate", { yaml }),

  events: (f: Record<string, string | number | boolean | undefined>) => req<{ total: number; items: EventRow[] }>(`/events${qs(f)}`),
  eventFacets: () => req<Record<string, string[]>>("/events/facets"),
  event: (id: number) => req<EventRow & { data: Record<string, any> }>(`/events/${id}`),

  detections: (f: Record<string, string | number | undefined>) => req<{ total: number; items: Detection[] }>(`/detections${qs(f)}`),
  detection: (id: string) => req<DetectionDetail>(`/detections/${encodeURIComponent(id)}`),

  siemStatus: () => req<SiemStatus>("/siem/status"),
  siemTest: () => post<{ ok: boolean; mode: string; message?: string; status_code?: number; error?: string; target?: string }>("/siem/test"),
  siemReceived: () => req<{ count: number; items: { received_at: string; document: any }[] }>("/siem/events"),

  scenarios: (envId?: number) => req<Scenario[]>(`/demo/scenarios${qs({ environment_id: envId })}`),
  demoEnvironment: (template = "windows-web-server") => post<EnvironmentDetail>("/demo/environment", { template }),
  simulate: (environment_id: number, scenarios: string[], benign_count = 0) =>
    post<{ scenarios: string[]; benign_events: number; result: IngestResult }>("/demo/simulate", { environment_id, scenarios, benign_count }),
  demoReset: () => post<{ reset: boolean }>("/demo/reset"),
};
