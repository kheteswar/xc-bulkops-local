// =============================================================================
// Live SOC Monitoring Room — DNS Monitor
// Fetches DNS load balancer health status, pool member health, and zone
// query metrics. Returns null if no DNS LBs are configured.
// =============================================================================

import { apiClient } from '../api';
import type { DNSHealthStatus } from './types';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function safeStr(val: unknown, fallback = ''): string {
  return typeof val === 'string' ? val : fallback;
}

function safeNum(val: unknown, fallback = 0): number {
  const n = Number(val);
  return isNaN(n) ? fallback : n;
}

// ---------------------------------------------------------------------------
// Sub-fetchers
// ---------------------------------------------------------------------------

interface DnsLbHealthResponse {
  status?: string;
  health?: string;
  state?: string;
  pools?: Array<Record<string, unknown>>;
  dns_lb_pools?: Array<Record<string, unknown>>;
}

async function fetchDnsLbHealth(
  namespace: string,
  name: string,
): Promise<DnsLbHealthResponse | null> {
  try {
    return await apiClient.get<DnsLbHealthResponse>(
      `/api/config/namespaces/${namespace}/dns_load_balancers/${name}/health_status`,
    );
  } catch {
    return null;
  }
}

interface PoolHealthResponse {
  members?: Array<Record<string, unknown>>;
  items?: Array<Record<string, unknown>>;
  status?: string;
}

async function fetchPoolHealth(
  namespace: string,
  dnsLbName: string,
  poolName: string,
): Promise<PoolHealthResponse | null> {
  try {
    return await apiClient.get<PoolHealthResponse>(
      `/api/config/namespaces/${namespace}/dns_load_balancers/${dnsLbName}/dns_lb_pools/${poolName}/health_status`,
    );
  } catch {
    return null;
  }
}

interface ZoneMetricsResponse {
  total_queries?: number;
  query_count?: number;
  error_count?: number;
  errors?: number;
  items?: Array<Record<string, unknown>>;
}

async function fetchZoneMetrics(
  namespace: string,
): Promise<ZoneMetricsResponse | null> {
  try {
    return await apiClient.get<ZoneMetricsResponse>(
      `/api/data/namespaces/${namespace}/dns_zones/metrics`,
    );
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Health status mapping
// ---------------------------------------------------------------------------

function mapLbStatus(
  raw: DnsLbHealthResponse | null,
): 'healthy' | 'degraded' | 'down' {
  if (!raw) return 'down';

  const healthStr = safeStr(
    raw.health ?? raw.status ?? raw.state,
    '',
  ).toLowerCase();

  if (healthStr.includes('health') || healthStr === 'up' || healthStr === 'ok') {
    return 'healthy';
  }
  if (healthStr.includes('degrad') || healthStr.includes('partial')) {
    return 'degraded';
  }
  if (healthStr.includes('down') || healthStr.includes('error') || healthStr.includes('fail')) {
    return 'down';
  }

  // Default: if we got a response, consider it at least degraded
  return 'degraded';
}

function mapMemberStatus(
  raw: Record<string, unknown>,
): DNSHealthStatus['loadBalancers'][number]['pools'][number]['members'][number] {
  const address = safeStr(
    raw.address ?? raw.ip ?? raw.endpoint ?? raw.name,
    'unknown',
  );

  const statusStr = safeStr(
    raw.health ?? raw.status ?? raw.state,
    'unknown',
  ).toLowerCase();

  const status: 'healthy' | 'unhealthy' =
    statusStr.includes('health') || statusStr === 'up' || statusStr === 'ok'
      ? 'healthy'
      : 'unhealthy';

  const lastChangeTime = safeStr(
    raw.last_change_time ?? raw.last_status_change ?? raw.updated_at,
    new Date().toISOString(),
  );

  return { address, status, lastChangeTime };
}

// ---------------------------------------------------------------------------
// fetchDNSHealth — main public function
// ---------------------------------------------------------------------------

/**
 * Fetch DNS health status for the given DNS load balancers in a namespace.
 *
 * For each DNS LB:
 *  1. Fetches top-level health status
 *  2. Discovers pools from the health response
 *  3. Fetches per-pool member health
 *
 * Also fetches zone-level query metrics for error rate computation.
 *
 * Returns `null` if no DNS LB names are provided or all fetches fail.
 */
export async function fetchDNSHealth(
  namespace: string,
  dnsLbNames: string[],
): Promise<DNSHealthStatus | null> {
  // No DNS LBs configured — nothing to monitor
  if (!dnsLbNames || dnsLbNames.length === 0) {
    return null;
  }

  try {
    // Phase 1: Fetch LB health + zone metrics concurrently
    const [lbHealthResults, zoneMetrics] = await Promise.all([
      Promise.all(
        dnsLbNames.map(async (name) => ({
          name,
          health: await fetchDnsLbHealth(namespace, name),
        })),
      ),
      fetchZoneMetrics(namespace),
    ]);

    // Phase 2: For each LB, fetch pool details
    const loadBalancers = await Promise.all(
      lbHealthResults.map(async ({ name, health }) => {
        const status = mapLbStatus(health);

        // Extract pool names from the LB health response
        const rawPools = health?.pools ?? health?.dns_lb_pools ?? [];
        const poolNames = rawPools.map((p) =>
          safeStr(p.name ?? p.pool_name, ''),
        ).filter(Boolean);

        // Fetch per-pool health
        const pools = await Promise.all(
          poolNames.map(async (poolName) => {
            const poolHealth = await fetchPoolHealth(namespace, name, poolName);
            const members = (poolHealth?.members ?? poolHealth?.items ?? []).map(
              (m) => mapMemberStatus(m as Record<string, unknown>),
            );

            return { name: poolName, members };
          }),
        );

        return { name, status, pools };
      }),
    );

    // If all LBs failed to return health data, return null
    const hasAnyData = loadBalancers.some(
      (lb) => lb.status !== 'down' || lb.pools.length > 0,
    );
    if (!hasAnyData && !zoneMetrics) {
      return null;
    }

    // Build query metrics
    let queryMetrics: DNSHealthStatus['queryMetrics'] = null;
    if (zoneMetrics) {
      const totalQueries = safeNum(
        zoneMetrics.total_queries ?? zoneMetrics.query_count,
      );
      const errorCount = safeNum(
        zoneMetrics.error_count ?? zoneMetrics.errors,
      );

      queryMetrics = {
        totalQueries,
        errorCount,
        errorRate: totalQueries > 0
          ? Math.round((errorCount / totalQueries) * 10000) / 100
          : 0,
      };
    }

    return { loadBalancers, queryMetrics };
  } catch (err) {
    console.warn(
      `[SOC] DNS health fetch failed for "${namespace}":`,
      err instanceof Error ? err.message : err,
    );
    return null;
  }
}
