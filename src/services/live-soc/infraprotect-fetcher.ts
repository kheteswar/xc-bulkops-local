// =============================================================================
// Live SOC Monitoring Room — InfraProtect Fetcher
// Retrieves L3/L4 DDoS protection data: alerts, active mitigations, and
// top talkers. Returns empty summary if InfraProtect is not enabled.
// =============================================================================

import { apiClient } from '../api';
import type { InfraProtectSummary } from './types';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function safeNum(val: unknown, fallback = 0): number {
  const n = Number(val);
  return isNaN(n) ? fallback : n;
}

function safeStr(val: unknown, fallback = ''): string {
  return typeof val === 'string' ? val : fallback;
}

// ---------------------------------------------------------------------------
// Empty result — returned when InfraProtect is not enabled or API fails
// ---------------------------------------------------------------------------

function emptyInfraProtect(): InfraProtectSummary {
  return {
    alerts: [],
    activeMitigations: [],
    topTalkers: [],
  };
}

// ---------------------------------------------------------------------------
// Sub-fetchers
// ---------------------------------------------------------------------------

async function fetchAlerts(
  namespace: string,
): Promise<InfraProtectSummary['alerts']> {
  try {
    const res = await apiClient.get<{
      items?: Array<Record<string, unknown>>;
      alerts?: Array<Record<string, unknown>>;
    }>(`/api/data/namespaces/${namespace}/infraprotect/alerts`);

    const items = res.items ?? res.alerts ?? [];

    return items.map((item) => {
      const metadata = (item.metadata ?? {}) as Record<string, unknown>;
      const spec = (item.spec ?? item) as Record<string, unknown>;
      const status = (item.status ?? item) as Record<string, unknown>;

      return {
        id: safeStr(metadata.uid ?? metadata.name ?? item.id, `ip-alert-${Date.now()}`),
        severity: safeStr(spec.severity ?? status.severity ?? item.severity, 'medium'),
        targetNetwork: safeStr(
          spec.target_network ?? spec.target ?? item.target_network,
          'unknown',
        ),
        createdAt: safeStr(
          metadata.creation_timestamp ?? status.created_at ?? item.created_at,
          new Date().toISOString(),
        ),
        status: safeStr(status.state ?? spec.state ?? item.state, 'active'),
      };
    });
  } catch {
    return [];
  }
}

async function fetchMitigations(
  namespace: string,
): Promise<InfraProtectSummary['activeMitigations']> {
  try {
    const res = await apiClient.get<{
      items?: Array<Record<string, unknown>>;
      mitigations?: Array<Record<string, unknown>>;
    }>(`/api/data/namespaces/${namespace}/infraprotect/mitigations`);

    const items = res.items ?? res.mitigations ?? [];

    return items.map((item) => {
      const metadata = (item.metadata ?? {}) as Record<string, unknown>;
      const spec = (item.spec ?? item) as Record<string, unknown>;

      return {
        id: safeStr(metadata.uid ?? metadata.name ?? item.id, `ip-mit-${Date.now()}`),
        targetNetwork: safeStr(
          spec.target_network ?? spec.target ?? item.target_network,
          'unknown',
        ),
        mitigatedIps: safeNum(spec.mitigated_ips ?? spec.blocked_count ?? item.mitigated_ips),
        startedAt: safeStr(
          metadata.creation_timestamp ?? spec.started_at ?? item.started_at,
          new Date().toISOString(),
        ),
      };
    });
  } catch {
    return [];
  }
}

async function fetchTopTalkers(
  namespace: string,
): Promise<InfraProtectSummary['topTalkers']> {
  try {
    const res = await apiClient.post<{
      items?: Array<Record<string, unknown>>;
      top_talkers?: Array<Record<string, unknown>>;
      buckets?: Array<Record<string, unknown>>;
    }>(`/api/data/namespaces/${namespace}/graph/l3l4/top_talkers`, {
      namespace,
    });

    const items = res.items ?? res.top_talkers ?? res.buckets ?? [];

    return items
      .map((item) => ({
        ip: safeStr(item.key ?? item.ip ?? item.src_ip, 'unknown'),
        bps: safeNum(item.bps ?? item.bytes_per_second),
        pps: safeNum(item.pps ?? item.packets_per_second),
      }))
      .sort((a, b) => b.bps - a.bps)
      .slice(0, 20);
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// fetchInfraProtectSummary — main public function
// ---------------------------------------------------------------------------

/**
 * Fetch a summary of InfraProtect (L3/L4 DDoS) status for a namespace.
 *
 * Uses three endpoints in parallel:
 *  - infraprotect/alerts
 *  - infraprotect/mitigations
 *  - graph/l3l4/top_talkers
 *
 * Returns an empty InfraProtectSummary if InfraProtect is not enabled or
 * all calls fail.
 */
export async function fetchInfraProtectSummary(
  namespace: string,
): Promise<InfraProtectSummary> {
  try {
    const [alerts, activeMitigations, topTalkers] = await Promise.all([
      fetchAlerts(namespace),
      fetchMitigations(namespace),
      fetchTopTalkers(namespace),
    ]);

    return { alerts, activeMitigations, topTalkers };
  } catch (err) {
    console.warn(
      `[SOC] InfraProtect fetch failed for "${namespace}":`,
      err instanceof Error ? err.message : err,
    );
    return emptyInfraProtect();
  }
}
