// =============================================================================
// Live SOC Monitoring Room — Config Change Tracker
// Fetches recent audit log entries and correlates config changes with anomalies.
// =============================================================================

import { apiClient } from '../api';
import type { AuditEntry } from './types';

// ---------------------------------------------------------------------------
// mapRawAuditEntry — normalises API response item → AuditEntry
// ---------------------------------------------------------------------------

function mapRawAuditEntry(raw: Record<string, unknown>): AuditEntry {
  const metadata = (raw.metadata ?? {}) as Record<string, unknown>;
  const spec = (raw.spec ?? raw) as Record<string, unknown>;

  const timestamp =
    (metadata.creation_timestamp as string) ??
    (spec.timestamp as string) ??
    (raw.timestamp as string) ??
    new Date().toISOString();

  const user =
    (spec.user as string) ??
    (spec.user_name as string) ??
    (spec.principal as string) ??
    (raw.user as string) ??
    'unknown';

  const objectType =
    (spec.object_type as string) ??
    (spec.resource_type as string) ??
    (raw.object_type as string) ??
    '';

  const objectName =
    (spec.object_name as string) ??
    (spec.resource_name as string) ??
    (raw.object_name as string) ??
    '';

  const operation =
    (spec.operation as string) ??
    (spec.action as string) ??
    (raw.operation as string) ??
    '';

  const namespace =
    (spec.namespace as string) ??
    (metadata.namespace as string) ??
    (raw.namespace as string) ??
    '';

  return {
    timestamp,
    user,
    objectType,
    objectName,
    operation,
    namespace,
  };
}

// ---------------------------------------------------------------------------
// fetchRecentChanges
// ---------------------------------------------------------------------------

/**
 * Fetch recent config/audit-log entries for a namespace since a given ISO time.
 *
 * POST /api/data/namespaces/{ns}/audit_logs
 *
 * The body contains a time-range filter so we only retrieve changes that
 * occurred within the SOC monitoring window.
 */
export async function fetchRecentChanges(
  namespace: string,
  since: string,
): Promise<AuditEntry[]> {
  try {
    const body = {
      namespace,
      query: {
        start_time: since,
        end_time: new Date().toISOString(),
        sort: 'DESCENDING',
      },
      aggs: {},
      scroll: false,
    };

    const response = await apiClient.post<{
      events?: unknown[];
      items?: unknown[];
      logs?: unknown[];
    }>(`/api/data/namespaces/${namespace}/audit_logs`, body);

    const items = response.events ?? response.items ?? response.logs ?? [];

    return items.map((item) => mapRawAuditEntry(item as Record<string, unknown>));
  } catch (err) {
    console.warn(
      `[SOC] Failed to fetch audit logs for namespace "${namespace}":`,
      err instanceof Error ? err.message : err,
    );
    return [];
  }
}

// ---------------------------------------------------------------------------
// correlateWithAnomaly
// ---------------------------------------------------------------------------

/**
 * Given a list of audit entries and an anomaly detection timestamp, return
 * only those config changes that occurred within `windowMinutes` **before**
 * the anomaly. This helps operators identify config changes that may have
 * caused or contributed to the detected anomaly.
 *
 * @param changes      - Audit entries from fetchRecentChanges
 * @param anomalyTime  - ISO timestamp of the anomaly detection
 * @param windowMinutes - How far back (in minutes) to look (default 15)
 * @returns Filtered & sorted audit entries within the correlation window
 */
export function correlateWithAnomaly(
  changes: AuditEntry[],
  anomalyTime: string,
  windowMinutes = 15,
): AuditEntry[] {
  const anomalyMs = new Date(anomalyTime).getTime();
  if (isNaN(anomalyMs)) {
    return [];
  }

  const windowMs = windowMinutes * 60 * 1000;
  const windowStart = anomalyMs - windowMs;

  const correlated = changes.filter((entry) => {
    const entryMs = new Date(entry.timestamp).getTime();
    if (isNaN(entryMs)) return false;
    return entryMs >= windowStart && entryMs <= anomalyMs;
  });

  // Sort most recent first (closest to anomaly)
  correlated.sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
  );

  return correlated;
}

// ---------------------------------------------------------------------------
// Helper: summariseChanges
// ---------------------------------------------------------------------------

/**
 * Produce a concise summary string from a list of audit entries,
 * useful for investigation evidence and event feed messages.
 */
export function summariseChanges(entries: AuditEntry[]): string {
  if (entries.length === 0) return 'No config changes detected';

  const grouped = new Map<string, number>();
  for (const entry of entries) {
    const key = `${entry.operation} ${entry.objectType}`;
    grouped.set(key, (grouped.get(key) ?? 0) + 1);
  }

  const parts: string[] = [];
  grouped.forEach((count, key) => {
    parts.push(`${count}x ${key}`);
  });

  return `${entries.length} change(s): ${parts.join(', ')}`;
}
