import type { ClassifiedLogEntry, PathAnalysis, RateStats, TimeGranularity } from './types';
import { extractUserId } from './traffic-analyzer';

/** Extract a valid timestamp string from a log entry, trying multiple field names. */
function extractTs(log: Record<string, unknown>): string {
  for (const key of ['@timestamp', 'time', 'timestamp', 'date', 'event_time']) {
    const val = log[key];
    if (val) {
      if (typeof val === 'string') return val;
      if (typeof val === 'number') return new Date(val).toISOString();
    }
  }
  return '';
}

/**
 * Normalizes paths by collapsing UUIDs, numeric IDs, and MongoDB ObjectIds.
 */
export function normalizePath(path: string | undefined): string {
  if (!path) return '/';
  return path
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '/:uuid')
    .replace(/\/\d+/g, '/:id')
    .replace(/\/[0-9a-f]{24}/gi, '/:objectId');
}

/**
 * Detects sensitive endpoints that may warrant tighter rate limits.
 */
export function isSensitiveEndpoint(path: string | undefined): { sensitive: boolean; reason?: string } {
  if (!path) return { sensitive: false };
  const patterns = [
    { regex: /\/(login|signin|auth)/i, reason: 'Authentication endpoint' },
    { regex: /\/(register|signup)/i, reason: 'Registration endpoint' },
    { regex: /\/(admin|dashboard)/i, reason: 'Admin endpoint' },
    { regex: /\/(password|reset|forgot)/i, reason: 'Password management' },
    { regex: /\/(search|query)/i, reason: 'Search endpoint (resource-intensive)' },
    { regex: /\/(upload|import)/i, reason: 'Upload endpoint (resource-intensive)' },
    { regex: /\/(export|download|report)/i, reason: 'Export endpoint (resource-intensive)' },
    { regex: /\/(pay|checkout|transaction)/i, reason: 'Payment endpoint' },
    { regex: /\/api\/v\d/i, reason: 'Versioned API endpoint' },
  ];
  for (const p of patterns) {
    if (p.regex.test(path)) return { sensitive: true, reason: p.reason };
  }
  return { sensitive: false };
}

function getWindowKey(timestamp: string, granularity: TimeGranularity): string {
  const d = new Date(timestamp);
  if (isNaN(d.getTime())) return `invalid-${Math.random().toString(36).slice(2, 8)}`;
  switch (granularity) {
    case 'second':
      return `${d.getUTCFullYear()}-${d.getUTCMonth()}-${d.getUTCDate()}-${d.getUTCHours()}-${d.getUTCMinutes()}-${d.getUTCSeconds()}`;
    case 'minute':
      return `${d.getUTCFullYear()}-${d.getUTCMonth()}-${d.getUTCDate()}-${d.getUTCHours()}-${d.getUTCMinutes()}`;
    case 'hour':
      return `${d.getUTCFullYear()}-${d.getUTCMonth()}-${d.getUTCDate()}-${d.getUTCHours()}`;
  }
}

function computePercentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const index = Math.floor((p / 100) * sorted.length);
  return sorted[Math.min(index, sorted.length - 1)];
}

function computeRateStats(values: number[]): RateStats {
  if (values.length === 0) {
    return { p50: 0, p75: 0, p90: 0, p95: 0, p99: 0, max: 0, mean: 0, stdDev: 0, sampleCount: 0 };
  }
  const sorted = [...values].sort((a, b) => a - b);
  const sum = sorted.reduce((a, b) => a + b, 0);
  const mean = sum / sorted.length;
  const variance = sorted.reduce((acc, v) => acc + (v - mean) ** 2, 0) / sorted.length;

  return {
    p50: computePercentile(sorted, 50),
    p75: computePercentile(sorted, 75),
    p90: computePercentile(sorted, 90),
    p95: computePercentile(sorted, 95),
    p99: computePercentile(sorted, 99),
    max: sorted[sorted.length - 1],
    mean: Math.round(mean * 100) / 100,
    stdDev: Math.round(Math.sqrt(variance) * 100) / 100,
    sampleCount: sorted.length,
  };
}

/**
 * Analyzes traffic patterns per path.
 * Groups logs by normalized path, computes per-path per-user rate stats,
 * and detects sensitive endpoints.
 */
export function analyzePaths(
  logs: ClassifiedLogEntry[]
): PathAnalysis[] {
  const originLogs = logs.filter(l => l.responseOrigin === 'origin');

  // Group by normalized path
  const pathGroups = new Map<string, { rawPaths: Set<string>; logs: ClassifiedLogEntry[] }>();

  for (const log of originLogs) {
    const normalized = normalizePath(log.req_path || '/');
    if (!pathGroups.has(normalized)) {
      pathGroups.set(normalized, { rawPaths: new Set(), logs: [] });
    }
    const group = pathGroups.get(normalized)!;
    group.rawPaths.add(log.req_path);
    group.logs.push(log);
  }

  const analyses: PathAnalysis[] = [];

  for (const [normalizedPath, group] of pathGroups.entries()) {
    // Unique users
    const uniqueUsers = new Set(group.logs.map(l => extractUserId(l as unknown as Record<string, unknown>)));

    // Methods
    const methods: Record<string, number> = {};
    for (const log of group.logs) {
      methods[log.method] = (methods[log.method] || 0) + 1;
    }

    // Rate stats per granularity (per-user peak rates for this path)
    const rateStats = {
      second: computePathRateStats(group.logs, 'second'),
      minute: computePathRateStats(group.logs, 'minute'),
      hour: computePathRateStats(group.logs, 'hour'),
    };

    const sensitivity = isSensitiveEndpoint(normalizedPath);

    analyses.push({
      normalizedPath,
      rawPaths: [...group.rawPaths].slice(0, 10),
      totalRequests: group.logs.length,
      uniqueUsers: uniqueUsers.size,
      methods,
      rateStats,
      isSensitive: sensitivity.sensitive,
      sensitiveReason: sensitivity.reason,
    });
  }

  return analyses.sort((a, b) => b.totalRequests - a.totalRequests);
}

function computePathRateStats(logs: ClassifiedLogEntry[], granularity: TimeGranularity): RateStats {
  // Group by user, then by time window
  const userWindows = new Map<string, Map<string, number>>();
  for (const log of logs) {
    const userId = extractUserId(log as unknown as Record<string, unknown>);
    const windowKey = getWindowKey(extractTs(log as unknown as Record<string, unknown>) || log['@timestamp'] || log.time, granularity);
    const weight = log.estimatedWeight || 1;
    if (!userWindows.has(userId)) {
      userWindows.set(userId, new Map());
    }
    const windows = userWindows.get(userId)!;
    windows.set(windowKey, (windows.get(windowKey) || 0) + weight);
  }

  // Per-user peak rates
  const peakRates: number[] = [];
  for (const windows of userWindows.values()) {
    let peak = 0;
    for (const count of windows.values()) {
      if (count > peak) peak = count;
    }
    if (peak > 0) peakRates.push(Math.ceil(peak));
  }

  return computeRateStats(peakRates);
}
