export type Severity = "critical" | "high" | "medium" | "low" | "informational";

export interface Branding {
  project_name: string;
  project_description: string;
  organization_name: string;
  organization_logo: string;
  primary_brand_color: string;
  dashboard_title: string;
  footer_text: string;
  customized: boolean;
}

export interface About {
  branding: Branding;
  upstream: { name: string; full_name: string; original_creator: string; license: string; version: string };
  plugins: string[];
  siem_adapters: string[];
  event_parsers: string[];
}

export interface Observable {
  type: string;
  value: string;
  context?: string;
}

export interface Detection {
  id: number;
  detection_id: string;
  timestamp: string;
  host: string;
  environment_id: number | null;
  rule_id: string;
  rule_name: string;
  rule_version: string;
  severity: Severity;
  confidence: number;
  event_type: string;
  description: string;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  simulated: boolean;
  delivery_status: string;
  observables: Observable[];
}

export interface DetectionDetail extends Detection {
  payload: Record<string, any>;
  source_event: EventRow & { data: Record<string, any> } | null;
  delivery_attempts: { adapter: string; success: boolean; status_code: number | null; error: string | null; latency_ms: number; at: string }[];
}

export interface EventRow {
  id: number;
  event_id: string;
  timestamp: string;
  source: string;
  host: string;
  event_type: string;
  simulated: boolean;
  matched: boolean;
  max_severity: Severity | null;
  summary: string;
}

export interface Metrics {
  events_received: number;
  events_rejected: number;
  events_duplicate: number;
  events_evaluated: number;
  events_matched: number;
  events_filtered: number;
  detections_created: number;
  events_forwarded: number;
  siem_delivered: number;
  siem_failed: number;
  reduction_percentage: number;
  statement: string;
}

export interface DashboardSummary {
  hosts: number;
  simulated_hosts: number;
  active_rules: number;
  distinct_active_rules: number;
  detections: number;
  high_severity: number;
  severity_distribution: { severity: Severity; count: number }[];
  metrics: Metrics;
  recent_detections: Detection[];
  event_volume: { t: string; events: number; matched: number }[];
  top_rules: { rule_id: string; name: string; count: number }[];
  mitre: { technique: string; tactic: string; count: number }[];
}

export interface ExposedService { port: number; protocol: string; service: string; process: string; bind: string }

export interface Profile {
  hostname: string;
  platform: string;
  os: string;
  environment_type: string[];
  technologies: string[];
  exposed_services: ExposedService[];
  risk_context: Record<string, boolean | string[]>;
  network: { ip_addresses: string[]; cidrs: string[]; gateways: string[]; dns_servers: string[]; route_count: number };
  rule_categories: string[];
  parameters: Record<string, (string | number)[]>;
  evidence: Record<string, string[]>;
}

export interface Assignment {
  assignment_id: number;
  rule_id: string;
  version: string;
  name: string;
  severity: Severity;
  platform: string;
  event_type: string;
  mitre_technique: string | null;
  source: string;
  status: string;
  reason: string;
  trigger_count: number;
  last_triggered_at: string | null;
  generated: Record<string, any> | null;
}

export interface EnvironmentSummary {
  id: number;
  hostname: string;
  platform: string;
  os: string;
  discovery_mode: string;
  simulated: boolean;
  discovered_at: string;
  technologies: string[];
  environment_type: string[];
  ip_addresses: string[];
  cidrs: string[];
  active_rules: number;
}

export interface EnvironmentDetail extends EnvironmentSummary {
  inventory: Record<string, any>;
  profile: Profile | null;
  profile_id: number | null;
  profile_count: number;
  rules: Assignment[];
}

export interface RuleRow {
  rule_id: string;
  version: string;
  name: string;
  platform: string;
  event_type: string;
  severity: Severity;
  source: string;
  author: string;
  category: string;
  status: string;
  mitre_technique: string | null;
  mitre_tactic: string | null;
  applies_when: { platforms: string[]; technologies: string[]; environment_types: string[] };
  active_environments: number;
  triggers: number;
  environments: { environment_id: number; hostname: string; status: string; reason: string; trigger_count: number }[];
}

export interface RuleDetail {
  rule_id: string;
  version: string;
  definition: Record<string, any>;
  yaml: string;
  file_path: string;
  versions: { version: string; status: string; loaded_at: string; content_hash: string }[];
  assignments: { assignment_id: number; hostname: string; version: string; status: string; reason: string; trigger_count: number; generated: any }[];
}

export interface Scenario { name: string; title: string; description: string; platform: string; expected_rules: string[]; relevant: boolean }

export interface IngestResult {
  received: number; accepted: number; duplicates: number; rejected: number; matched: number; detections: number;
  errors: string[]; detection_ids: string[];
}

export interface SiemStatus {
  mode: string;
  available_adapters: string[];
  configured: boolean;
  target: string | null;
  delivered: number;
  failed: number;
  pending_local: number;
  last_success: string | null;
  last_error: { at: string; status_code: number | null; error: string | null } | null;
  recent_attempts: { id: number; adapter: string; success: boolean; status_code: number | null; latency_ms: number; at: string; error: string | null }[];
  local_sink_received: number;
}
