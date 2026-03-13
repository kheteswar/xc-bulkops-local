import type { ClassifiedLogEntry, RateStats, TimeGranularity, TrafficSegment, UserProfile, UserReputationType, UserMetadata, PreGroupedCache } from './types';

/**
 * Extract a valid Date from a log entry, trying multiple timestamp field names.
 * Falls back to scanning all string values for ISO 8601 patterns.
 * Returns null if no valid timestamp is found.
 */
function extractLogDate(log: Record<string, unknown>): Date | null {
  // Try known timestamp field names
  for (const key of ['@timestamp', 'time', 'timestamp', 'date', 'event_time', 'connected_time', 'terminated_time']) {
    const val = log[key];
    if (val) {
      const d = typeof val === 'number' ? new Date(val) : new Date(String(val));
      if (!isNaN(d.getTime())) return d;
    }
  }
  // Fallback: scan ALL string values for ISO 8601 patterns
  for (const val of Object.values(log)) {
    if (typeof val === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(val)) {
      const d = new Date(val);
      if (!isNaN(d.getTime())) return d;
    }
  }
  return null;
}

/**
 * Extract user identifier from a log entry, trying multiple field names.
 */
export function extractUserId(log: Record<string, unknown>): string {
  for (const key of ['user', 'user_identifier', 'client_id', 'userId']) {
    const val = log[key];
    if (val && typeof val === 'string' && val !== 'unknown' && val !== '' && val !== '-') return val;
  }
  for (const key of ['src_ip', 'source_ip', 'client_ip', 'srcIp', 'source_address']) {
    const val = log[key];
    if (val && typeof val === 'string' && val !== '' && val !== '-') return val;
  }
  return 'unknown';
}

function getWindowKey(timestamp: string, granularity: TimeGranularity): string {
  const d = new Date(timestamp);
  // Guard against invalid dates — use fallback to avoid collapsing all logs into one bucket
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

function filterBySegment(logs: ClassifiedLogEntry[], segment: TrafficSegment): ClassifiedLogEntry[] {
  switch (segment) {
    case 'clean_only':
      return logs.filter(l => l.responseOrigin === 'origin' && l.userReputation === 'clean');
    case 'all_legitimate':
      return logs.filter(
        l => l.responseOrigin === 'origin' &&
          (l.userReputation === 'clean' || l.userReputation === 'benign_bot' || l.userReputation === 'flagged')
      );
    case 'total':
      return logs;
  }
}

function computePercentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const index = Math.floor((p / 100) * sorted.length);
  return sorted[Math.min(index, sorted.length - 1)];
}

function computeStats(values: number[]): RateStats {
  if (values.length === 0) {
    return { p50: 0, p75: 0, p90: 0, p95: 0, p99: 0, max: 0, mean: 0, stdDev: 0, sampleCount: 0 };
  }

  const sorted = [...values].sort((a, b) => a - b);
  const sum = sorted.reduce((a, b) => a + b, 0);
  const mean = sum / sorted.length;
  const variance = sorted.reduce((acc, v) => acc + (v - mean) ** 2, 0) / sorted.length;
  const stdDev = Math.sqrt(variance);

  return {
    p50: computePercentile(sorted, 50),
    p75: computePercentile(sorted, 75),
    p90: computePercentile(sorted, 90),
    p95: computePercentile(sorted, 95),
    p99: computePercentile(sorted, 99),
    max: sorted[sorted.length - 1],
    mean: Math.round(mean * 100) / 100,
    stdDev: Math.round(stdDev * 100) / 100,
    sampleCount: sorted.length,
  };
}

/**
 * Analyzes traffic rates for a given segment and granularity.
 * For each user, buckets requests into time windows, finds per-user peak rate,
 * then computes distribution statistics across all users.
 */
export function analyzeTraffic(
  logs: ClassifiedLogEntry[],
  segment: TrafficSegment,
  granularity: TimeGranularity
): RateStats {
  const filtered = filterBySegment(logs, segment);

  // Group by user
  const userWindows = new Map<string, Map<string, number>>();

  for (const log of filtered) {
    const userId = extractUserId(log as unknown as Record<string, unknown>);
    const ts = extractLogDate(log as unknown as Record<string, unknown>)?.toISOString() || log['@timestamp'] || log.time || '';
    const windowKey = getWindowKey(ts, granularity);
    const weight = log.estimatedWeight || 1;

    if (!userWindows.has(userId)) {
      userWindows.set(userId, new Map());
    }
    const windows = userWindows.get(userId)!;
    windows.set(windowKey, (windows.get(windowKey) || 0) + weight);
  }

  // For each user, find peak rate
  const peakRates: number[] = [];
  for (const windows of userWindows.values()) {
    let peak = 0;
    for (const count of windows.values()) {
      if (count > peak) peak = count;
    }
    if (peak > 0) {
      peakRates.push(Math.ceil(peak));
    }
  }

  return computeStats(peakRates);
}

/**
 * Pre-groups logs by user and time bucket for fast impact simulation.
 * Returns a map: userId → Map<windowKey, requestCount>
 */
export function preGroupLogs(
  logs: ClassifiedLogEntry[],
  segment: TrafficSegment,
  granularity: TimeGranularity
): Map<string, Map<string, number>> {
  const filtered = filterBySegment(logs, segment);
  const userWindows = new Map<string, Map<string, number>>();

  for (const log of filtered) {
    const userId = extractUserId(log as unknown as Record<string, unknown>);
    const ts = extractLogDate(log as unknown as Record<string, unknown>)?.toISOString() || log['@timestamp'] || log.time || '';
    const windowKey = getWindowKey(ts, granularity);
    const weight = log.estimatedWeight || 1;

    if (!userWindows.has(userId)) {
      userWindows.set(userId, new Map());
    }
    const windows = userWindows.get(userId)!;
    windows.set(windowKey, (windows.get(windowKey) || 0) + weight);
  }

  return userWindows;
}

/**
 * Build compact per-user metadata (reputation + path counts).
 * This replaces the need to keep the full classified logs array in memory.
 */
export function buildUserMetadata(logs: ClassifiedLogEntry[]): Map<string, UserMetadata> {
  const meta = new Map<string, UserMetadata>();
  for (const log of logs) {
    const userId = extractUserId(log as unknown as Record<string, unknown>);
    let entry = meta.get(userId);
    if (!entry) {
      entry = { reputation: log.userReputation, pathCounts: new Map() };
      meta.set(userId, entry);
    }
    entry.pathCounts.set(log.req_path, (entry.pathCounts.get(log.req_path) || 0) + 1);
  }
  return meta;
}

/**
 * Pre-compute all 9 segment × granularity grouped maps in a single pass.
 * This avoids re-iterating all logs when the user changes segment/granularity.
 */
export function buildAllPreGrouped(logs: ClassifiedLogEntry[]): PreGroupedCache {
  const segments: TrafficSegment[] = ['clean_only', 'all_legitimate', 'total'];
  const granularities: TimeGranularity[] = ['second', 'minute', 'hour'];

  const cache = {} as PreGroupedCache;
  for (const seg of segments) {
    cache[seg] = {} as Record<TimeGranularity, Map<string, Map<string, number>>>;
    for (const gran of granularities) {
      cache[seg][gran] = new Map();
    }
  }

  for (const log of logs) {
    const userId = extractUserId(log as unknown as Record<string, unknown>);
    const weight = log.estimatedWeight || 1;
    const isOrigin = log.responseOrigin === 'origin';
    const rep = log.userReputation;

    // Determine which segments this log belongs to
    const inClean = isOrigin && rep === 'clean';
    const inLegit = isOrigin && (rep === 'clean' || rep === 'benign_bot' || rep === 'flagged');
    // 'total' always includes everything

    const ts = extractLogDate(log as unknown as Record<string, unknown>)?.toISOString() || log['@timestamp'] || log.time || '';

    for (const gran of granularities) {
      const windowKey = getWindowKey(ts, gran);

      if (inClean) {
        const m = cache.clean_only[gran];
        if (!m.has(userId)) m.set(userId, new Map());
        const w = m.get(userId)!;
        w.set(windowKey, (w.get(windowKey) || 0) + weight);
      }
      if (inLegit) {
        const m = cache.all_legitimate[gran];
        if (!m.has(userId)) m.set(userId, new Map());
        const w = m.get(userId)!;
        w.set(windowKey, (w.get(windowKey) || 0) + weight);
      }
      {
        const m = cache.total[gran];
        if (!m.has(userId)) m.set(userId, new Map());
        const w = m.get(userId)!;
        w.set(windowKey, (w.get(windowKey) || 0) + weight);
      }
    }
  }

  return cache;
}

/**
 * Build full user profiles from classified logs and reputation data.
 */
export function buildUserProfiles(
  logs: ClassifiedLogEntry[],
  reputationMap: Map<string, { reputation: UserReputationType }>
): UserProfile[] {
  const userDataMap = new Map<string, {
    logs: ClassifiedLogEntry[];
    srcIp: string;
    reputation: UserReputationType;
  }>();

  for (const log of logs) {
    const userId = extractUserId(log as unknown as Record<string, unknown>);
    if (!userDataMap.has(userId)) {
      userDataMap.set(userId, {
        logs: [],
        srcIp: log.src_ip,
        reputation: log.userReputation,
      });
    }
    userDataMap.get(userId)!.logs.push(log);
  }

  const profiles: UserProfile[] = [];

  for (const [userId, data] of userDataMap.entries()) {
    const originLogs = data.logs.filter(l => l.responseOrigin === 'origin');
    const estimatedTotal = data.logs.reduce((sum, l) => sum + l.estimatedWeight, 0);

    // Path analysis
    const pathCounts = new Map<string, number>();
    const methodCounts = new Map<string, number>();
    const hourCounts = new Map<string, number>();

    for (const log of data.logs) {
      pathCounts.set(log.req_path, (pathCounts.get(log.req_path) || 0) + 1);
      methodCounts.set(log.method, (methodCounts.get(log.method) || 0) + 1);
      const d = extractLogDate(log as unknown as Record<string, unknown>) || new Date(log['@timestamp'] || log.time);
      if (!isNaN(d.getTime())) {
        const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
        const hourKey = `${dayNames[d.getUTCDay()]} ${d.getUTCHours().toString().padStart(2, '0')}:00`;
        hourCounts.set(hourKey, (hourCounts.get(hourKey) || 0) + 1);
      }
    }

    const topPaths = [...pathCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([path, count]) => ({ path, count }));

    const topMethods = [...methodCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([method, count]) => ({ method, count }));

    let peakHour = '';
    let peakHourCount = 0;
    for (const [hour, count] of hourCounts.entries()) {
      if (count > peakHourCount) {
        peakHour = hour;
        peakHourCount = count;
      }
    }

    // Reputation details from map
    const repEntry = reputationMap.get(userId);
    const repDetails = repEntry ? (repEntry as { reputation: UserReputationType; details?: { wafBlockCount?: number; wafReportCount?: number; botClassification?: string; botName?: string; attackTypes?: string[] } }).details : undefined;

    // Compute per-granularity rate stats for this single user
    const rateStats = {
      second: computeUserRateStats(data.logs, 'second'),
      minute: computeUserRateStats(data.logs, 'minute'),
      hour: computeUserRateStats(data.logs, 'hour'),
    };

    profiles.push({
      identifier: userId,
      srcIp: data.srcIp,
      reputation: data.reputation,
      totalRequests: data.logs.length,
      estimatedTotalRequests: Math.round(estimatedTotal),
      totalOriginRequests: originLogs.length,
      rateStats,
      wafBlockCount: repDetails?.wafBlockCount || 0,
      wafReportCount: repDetails?.wafReportCount || 0,
      botClassification: repDetails?.botClassification || data.logs[0]?.bot_class || '',
      botName: repDetails?.botName || '',
      attackTypes: repDetails?.attackTypes || [],
      topPaths,
      topMethods,
      peakHour,
      country: data.logs[0]?.country || '',
      userAgent: data.logs[0]?.user_agent || '',
    });
  }

  return profiles.sort((a, b) => b.totalRequests - a.totalRequests);
}

function computeUserRateStats(logs: ClassifiedLogEntry[], granularity: TimeGranularity): RateStats {
  const windows = new Map<string, number>();
  for (const log of logs) {
    const ts = extractLogDate(log as unknown as Record<string, unknown>)?.toISOString() || log['@timestamp'] || log.time || '';
    const key = getWindowKey(ts, granularity);
    const weight = log.estimatedWeight || 1;
    windows.set(key, (windows.get(key) || 0) + weight);
  }
  const rates = [...windows.values()].map(v => Math.ceil(v));
  return computeStats(rates);
}

/**
 * Build time series data for charts.
 */
export function buildTimeSeries(
  logs: ClassifiedLogEntry[],
  segment: TrafficSegment
): Array<{ timestamp: string; requestsPerMinute: number; requestsPerSecond: number }> {
  const filtered = filterBySegment(logs, segment);
  if (filtered.length === 0) return [];

  // Bucket by minute
  const minuteBuckets = new Map<string, number>();
  for (const log of filtered) {
    const d = extractLogDate(log as unknown as Record<string, unknown>) || new Date(log['@timestamp'] || log.time);
    if (isNaN(d.getTime())) continue; // skip entries with invalid timestamps
    // Round to 5-minute buckets for cleaner charts
    const mins = Math.floor(d.getUTCMinutes() / 5) * 5;
    const key = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}T${String(d.getUTCHours()).padStart(2, '0')}:${String(mins).padStart(2, '0')}:00Z`;
    const weight = log.estimatedWeight || 1;
    minuteBuckets.set(key, (minuteBuckets.get(key) || 0) + weight);
  }

  return [...minuteBuckets.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([timestamp, count]) => ({
      timestamp,
      requestsPerMinute: Math.round(count / 5), // average per minute within the 5-min bucket
      requestsPerSecond: Math.round((count / 300) * 100) / 100, // per second
    }));
}

/**
 * Build heatmap data (day of week × hour of day).
 */
export function buildHeatmap(
  logs: ClassifiedLogEntry[],
  segment: TrafficSegment
): Array<{ dayOfWeek: number; hourOfDay: number; avgRequestsPerMinute: number }> {
  const filtered = filterBySegment(logs, segment);
  const buckets = new Map<string, { total: number; minutes: Set<string> }>();

  for (const log of filtered) {
    const d = extractLogDate(log as unknown as Record<string, unknown>) || new Date(log['@timestamp'] || log.time);
    if (isNaN(d.getTime())) continue; // skip invalid timestamps
    const dow = (d.getUTCDay() + 6) % 7; // 0=Mon, 6=Sun
    const hour = d.getUTCHours();
    const key = `${dow}-${hour}`;
    const minuteKey = `${d.getUTCFullYear()}-${d.getUTCMonth()}-${d.getUTCDate()}-${hour}-${d.getUTCMinutes()}`;

    if (!buckets.has(key)) {
      buckets.set(key, { total: 0, minutes: new Set() });
    }
    const bucket = buckets.get(key)!;
    bucket.total += log.estimatedWeight || 1;
    bucket.minutes.add(minuteKey);
  }

  const result: Array<{ dayOfWeek: number; hourOfDay: number; avgRequestsPerMinute: number }> = [];
  for (let dow = 0; dow < 7; dow++) {
    for (let hour = 0; hour < 24; hour++) {
      const key = `${dow}-${hour}`;
      const bucket = buckets.get(key);
      const avg = bucket ? Math.round(bucket.total / Math.max(bucket.minutes.size, 1)) : 0;
      result.push({ dayOfWeek: dow, hourOfDay: hour, avgRequestsPerMinute: avg });
    }
  }

  return result;
}
