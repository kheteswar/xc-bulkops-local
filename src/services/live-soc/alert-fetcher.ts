// =============================================================================
// Live SOC Monitoring Room — Alert Fetcher
// Fetches active alerts from the F5 XC alerts API and classifies them by type.
// =============================================================================

import { apiClient } from '../api';
import type { AlertEntry } from './types';

// ---------------------------------------------------------------------------
// Alert type classification keywords
// ---------------------------------------------------------------------------

const TSA_KEYWORDS = [
  'traffic_anomaly', 'tsa_', 'traffic_', 'anomaly',
  'ddos', 'volume_spike', 'rate_anomaly',
];

const CONFIG_KEYWORDS = [
  'config_', 'certificate_', 'cert_expir', 'tls_',
  'dns_config', 'route_', 'origin_pool', 'load_balancer',
  'deployment_', 'publish_',
];

const SECURITY_KEYWORDS = [
  'waf_', 'bot_', 'attack_', 'vulnerability_', 'cve_',
  'malicious_', 'brute_force', 'credential_stuffing',
  'api_security', 'threat_', 'injection', 'xss',
];

const INFRA_KEYWORDS = [
  'infra_', 'network_', 'site_', 'node_', 'health_',
  'connectivity_', 'latency_', 'timeout_', 'upstream_',
  'origin_health', 'pool_health', 'dns_health',
];

// ---------------------------------------------------------------------------
// classifyAlertType
// ---------------------------------------------------------------------------

/**
 * Classify an alert into one of four categories based on its name, type,
 * and labels. Falls back to 'infrastructure' if no pattern matches.
 */
export function classifyAlertType(alert: {
  name?: string;
  type?: string;
  labels?: Record<string, string>;
}): 'tsa' | 'config' | 'security' | 'infrastructure' {
  const haystack = [
    alert.name ?? '',
    alert.type ?? '',
    ...(alert.labels ? Object.values(alert.labels) : []),
  ]
    .join(' ')
    .toLowerCase();

  if (TSA_KEYWORDS.some((kw) => haystack.includes(kw))) {
    return 'tsa';
  }
  if (SECURITY_KEYWORDS.some((kw) => haystack.includes(kw))) {
    return 'security';
  }
  if (CONFIG_KEYWORDS.some((kw) => haystack.includes(kw))) {
    return 'config';
  }
  if (INFRA_KEYWORDS.some((kw) => haystack.includes(kw))) {
    return 'infrastructure';
  }

  // Default: infrastructure (covers generic operational alerts)
  return 'infrastructure';
}

// ---------------------------------------------------------------------------
// mapRawAlert — converts API response item → AlertEntry
// ---------------------------------------------------------------------------

function mapRawAlert(raw: Record<string, unknown>): AlertEntry {
  const metadata = (raw.metadata ?? raw) as Record<string, unknown>;
  const spec = (raw.spec ?? raw) as Record<string, unknown>;
  const status = (raw.status ?? raw) as Record<string, unknown>;

  const id =
    (metadata.uid as string) ??
    (metadata.name as string) ??
    `alert-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  const name = (metadata.name as string) ?? (spec.alert_name as string) ?? 'Unknown Alert';

  const severityRaw = (
    (spec.severity as string) ??
    (status.severity as string) ??
    'minor'
  ).toLowerCase();

  const severity: AlertEntry['severity'] =
    severityRaw === 'critical'
      ? 'critical'
      : severityRaw === 'major' || severityRaw === 'high' || severityRaw === 'warning'
        ? 'major'
        : 'minor';

  const alertType = classifyAlertType({
    name,
    type: (spec.alert_type as string) ?? (spec.type as string) ?? '',
    labels: (metadata.labels as Record<string, string>) ?? undefined,
  });

  const description =
    (spec.description as string) ??
    (spec.summary as string) ??
    (status.message as string) ??
    '';

  const createdAt =
    (metadata.creation_timestamp as string) ??
    (status.created_at as string) ??
    new Date().toISOString();

  const updatedAt =
    (metadata.modification_timestamp as string) ??
    (status.updated_at as string) ??
    createdAt;

  const state =
    (status.state as string) ??
    (spec.state as string) ??
    'active';

  return {
    id,
    name,
    severity,
    type: alertType,
    description,
    createdAt,
    updatedAt,
    state,
    labels: (metadata.labels as Record<string, string>) ?? undefined,
  };
}

// ---------------------------------------------------------------------------
// fetchActiveAlerts
// ---------------------------------------------------------------------------

/**
 * Fetch active alerts for a namespace from the data API.
 *
 * GET /api/data/namespaces/{ns}/alerts
 *
 * Returns an empty array if the endpoint fails (e.g. alerts not configured,
 * permissions missing, or API unavailable).
 */
export async function fetchActiveAlerts(namespace: string): Promise<AlertEntry[]> {
  try {
    const response = await apiClient.get<{
      items?: unknown[];
      alerts?: unknown[];
    }>(`/api/data/namespaces/${namespace}/alerts`);

    const items = response.items ?? response.alerts ?? [];

    return items.map((item) => mapRawAlert(item as Record<string, unknown>));
  } catch (err) {
    console.warn(
      `[SOC] Failed to fetch alerts for namespace "${namespace}":`,
      err instanceof Error ? err.message : err,
    );
    return [];
  }
}
