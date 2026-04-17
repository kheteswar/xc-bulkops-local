// =============================================================================
// Live SOC Monitoring Room — Synthetic Monitor Fetcher
// Retrieves synthetic monitoring health: monitor status, TLS cert summaries,
// and global availability. Returns empty summary if not enabled.
// =============================================================================

import { apiClient } from '../api';
import type { SyntheticHealthSummary } from './types';

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
// Empty result — returned when synthetic monitoring is not enabled
// ---------------------------------------------------------------------------

function emptySyntheticHealth(): SyntheticHealthSummary {
  return {
    monitors: [],
    tlsCerts: [],
    globalAvailabilityPct: 0,
  };
}

// ---------------------------------------------------------------------------
// Sub-fetchers
// ---------------------------------------------------------------------------

async function fetchMonitorHealth(
  namespace: string,
): Promise<Array<Record<string, unknown>>> {
  try {
    const res = await apiClient.get<{
      items?: Array<Record<string, unknown>>;
      monitors?: Array<Record<string, unknown>>;
    }>(`/api/data/namespaces/${namespace}/synthetic_monitor/health`);

    return res.items ?? res.monitors ?? [];
  } catch {
    return [];
  }
}

async function fetchHttpMonitorsHealth(
  namespace: string,
): Promise<Array<Record<string, unknown>>> {
  try {
    const res = await apiClient.get<{
      items?: Array<Record<string, unknown>>;
      monitors?: Array<Record<string, unknown>>;
    }>(`/api/data/namespaces/${namespace}/synthetic_monitor/http-monitors-health`);

    return res.items ?? res.monitors ?? [];
  } catch {
    return [];
  }
}

interface TlsReportSummaryResponse {
  items?: Array<Record<string, unknown>>;
  certs?: Array<Record<string, unknown>>;
  certificates?: Array<Record<string, unknown>>;
}

async function fetchTlsReportSummary(
  namespace: string,
): Promise<TlsReportSummaryResponse | null> {
  try {
    return await apiClient.get<TlsReportSummaryResponse>(
      `/api/data/namespaces/${namespace}/synthetic_monitor/tls-report-summary`,
    );
  } catch {
    return null;
  }
}

interface GlobalSummaryResponse {
  availability_pct?: number;
  global_availability?: number;
  overall_health?: string;
}

async function fetchGlobalSummary(
  namespace: string,
): Promise<GlobalSummaryResponse | null> {
  try {
    return await apiClient.get<GlobalSummaryResponse>(
      `/api/data/namespaces/${namespace}/synthetic_monitor/global-summary`,
    );
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Monitor status mapping
// ---------------------------------------------------------------------------

function mapMonitorStatus(
  raw: Record<string, unknown>,
): SyntheticHealthSummary['monitors'][number] {
  const metadata = (raw.metadata ?? {}) as Record<string, unknown>;
  const spec = (raw.spec ?? raw) as Record<string, unknown>;
  const status = (raw.status ?? raw) as Record<string, unknown>;

  const name = safeStr(
    metadata.name ?? spec.name ?? raw.name,
    'unknown-monitor',
  );

  // Determine monitor type
  const typeRaw = safeStr(spec.type ?? spec.monitor_type ?? raw.type, 'http').toLowerCase();
  const type: 'http' | 'dns' = typeRaw.includes('dns') ? 'dns' : 'http';

  // Determine health status
  const healthRaw = safeStr(
    status.health ?? status.status ?? status.state ?? raw.health,
    'unknown',
  ).toLowerCase();

  let monitorStatus: 'healthy' | 'unhealthy' | 'unknown' = 'unknown';
  if (healthRaw.includes('health') || healthRaw === 'up' || healthRaw === 'pass' || healthRaw === 'ok') {
    monitorStatus = 'healthy';
  } else if (healthRaw.includes('unhealthy') || healthRaw === 'down' || healthRaw === 'fail' || healthRaw === 'error') {
    monitorStatus = 'unhealthy';
  }

  const lastCheckTime = safeStr(
    status.last_check_time ?? status.last_checked ?? raw.last_check_time,
    new Date().toISOString(),
  );

  const availabilityPct = safeNum(
    status.availability_pct ?? status.availability ?? raw.availability_pct,
    monitorStatus === 'healthy' ? 100 : 0,
  );

  return { name, type, status: monitorStatus, lastCheckTime, availabilityPct };
}

// ---------------------------------------------------------------------------
// TLS cert mapping
// ---------------------------------------------------------------------------

function mapTlsCerts(
  tlsResponse: TlsReportSummaryResponse | null,
): SyntheticHealthSummary['tlsCerts'] {
  if (!tlsResponse) return [];

  const items = tlsResponse.items ?? tlsResponse.certs ?? tlsResponse.certificates ?? [];

  return items.map((item) => {
    const domain = safeStr(item.domain ?? item.host ?? item.common_name, 'unknown');
    const expiresAt = safeStr(
      item.expires_at ?? item.not_after ?? item.expiry,
      '',
    );

    let daysUntilExpiry = 0;
    if (expiresAt) {
      const expiryMs = new Date(expiresAt).getTime();
      const nowMs = Date.now();
      daysUntilExpiry = Math.max(0, Math.ceil((expiryMs - nowMs) / (1000 * 60 * 60 * 24)));
    }

    let certStatus: 'ok' | 'warning' | 'critical' = 'ok';
    if (daysUntilExpiry <= 7) {
      certStatus = 'critical';
    } else if (daysUntilExpiry <= 30) {
      certStatus = 'warning';
    }

    return { domain, expiresAt, daysUntilExpiry, status: certStatus };
  });
}

// ---------------------------------------------------------------------------
// fetchSyntheticHealth — main public function
// ---------------------------------------------------------------------------

/**
 * Fetch synthetic monitoring health for a namespace.
 *
 * Uses four endpoints in parallel:
 *  - synthetic_monitor/health
 *  - synthetic_monitor/http-monitors-health
 *  - synthetic_monitor/tls-report-summary
 *  - synthetic_monitor/global-summary
 *
 * Returns an empty SyntheticHealthSummary if synthetic monitoring is not
 * enabled or all calls fail.
 */
export async function fetchSyntheticHealth(
  namespace: string,
): Promise<SyntheticHealthSummary> {
  try {
    const [healthItems, httpMonitorItems, tlsResponse, globalSummary] = await Promise.all([
      fetchMonitorHealth(namespace),
      fetchHttpMonitorsHealth(namespace),
      fetchTlsReportSummary(namespace),
      fetchGlobalSummary(namespace),
    ]);

    // Merge monitor lists — health endpoint may cover all, http-monitors may add extras
    const seenNames = new Set<string>();
    const monitors: SyntheticHealthSummary['monitors'] = [];

    for (const raw of [...healthItems, ...httpMonitorItems]) {
      const mapped = mapMonitorStatus(raw);
      if (!seenNames.has(mapped.name)) {
        seenNames.add(mapped.name);
        monitors.push(mapped);
      }
    }

    // If no monitors found at all, synthetic monitoring is likely not configured
    if (monitors.length === 0 && !tlsResponse && !globalSummary) {
      return emptySyntheticHealth();
    }

    // TLS certificates
    const tlsCerts = mapTlsCerts(tlsResponse);

    // Global availability
    const globalAvailabilityPct = globalSummary
      ? safeNum(
          globalSummary.availability_pct ?? globalSummary.global_availability,
          monitors.length > 0
            ? monitors.reduce((sum, m) => sum + m.availabilityPct, 0) / monitors.length
            : 0,
        )
      : monitors.length > 0
        ? monitors.reduce((sum, m) => sum + m.availabilityPct, 0) / monitors.length
        : 0;

    return {
      monitors,
      tlsCerts,
      globalAvailabilityPct: Math.round(globalAvailabilityPct * 100) / 100,
    };
  } catch (err) {
    console.warn(
      `[SOC] Synthetic health fetch failed for "${namespace}":`,
      err instanceof Error ? err.message : err,
    );
    return emptySyntheticHealth();
  }
}
