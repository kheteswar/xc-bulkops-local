// =============================================================================
// Live SOC Monitoring Room — Raw Log Processor
// =============================================================================
// Processes Track 3 raw log pages to extract:
//   - Latency stats (P50/P95/P99, origin TTFB, 5-field waterfall, per-origin)
//   - Event feed entries (errors + security events → terminal feed)
//   - JA4 TLS fingerprint clustering (attack tool identification)
//   - Sample rate (average across raw logs)
// =============================================================================

import type {
  AccessLogEntry,
  SecurityEventEntry,
  LatencyStats,
  LatencyWaterfall,
  EventFeedEntry,
  JA4Cluster,
} from './types';
import { createEmptyLatencyStats } from './types';

// =============================================================================
// Constants
// =============================================================================

/** Maximum events to keep in the event feed. */
const MAX_EVENT_FEED = 200;

/** Timing field names on AccessLogEntry for the 5-field waterfall. */
const TIMING_FIELDS = [
  'time_to_first_upstream_tx_byte',
  'time_to_first_upstream_rx_byte',
  'time_to_last_upstream_rx_byte',
  'time_to_first_downstream_tx_byte',
  'time_to_last_downstream_tx_byte',
] as const;

// =============================================================================
// Main Processor
// =============================================================================

/**
 * Processes raw access logs and security events from Track 3 into
 * latency statistics, event feed entries, JA4 clusters, and sample rate.
 */
export function processRawLogs(
  accessLogs: AccessLogEntry[],
  securityEvents: SecurityEventEntry[]
): {
  latencyStats: LatencyStats;
  eventFeed: EventFeedEntry[];
  ja4Clusters: JA4Cluster[];
  sampleRate: number;
} {
  // Compute latency stats from access logs
  const latencyStats = computeLatencyStats(accessLogs);

  // Build event feed from both sources
  const eventFeed = buildEventFeed(accessLogs, securityEvents);

  // Cluster by JA4 fingerprint
  const ja4Clusters = clusterByJA4(accessLogs);

  // Compute average sample rate
  const sampleRate = computeAverageSampleRate(accessLogs);

  return { latencyStats, eventFeed, ja4Clusters, sampleRate };
}

// =============================================================================
// Latency Statistics
// =============================================================================

/**
 * Computes comprehensive latency statistics from raw access logs:
 * - Overall P50/P95/P99 from total_duration_seconds
 * - Origin TTFB P50/P95 from time_to_first_upstream_rx_byte
 * - 5-field waterfall with P50/P95 per field
 * - Per-origin breakdown by dst_ip
 */
function computeLatencyStats(accessLogs: AccessLogEntry[]): LatencyStats {
  if (accessLogs.length === 0) {
    return createEmptyLatencyStats();
  }

  // Filter to logs with valid timing data
  const withTiming = accessLogs.filter(
    (log) => log.total_duration_seconds > 0
  );

  if (withTiming.length === 0) {
    return createEmptyLatencyStats();
  }

  // Overall latency from total_duration_seconds (in seconds, convert to ms)
  const durations = withTiming
    .map((log) => log.total_duration_seconds * 1000)
    .sort((a, b) => a - b);

  const p50 = computePercentile(durations, 50);
  const p95 = computePercentile(durations, 95);
  const p99 = computePercentile(durations, 99);

  // Origin TTFB from time_to_first_upstream_rx_byte
  const ttfbValues = withTiming
    .map((log) => safeTimingMs(log.time_to_first_upstream_rx_byte))
    .filter((v) => v > 0)
    .sort((a, b) => a - b);

  const originTTFB_p50 = ttfbValues.length > 0 ? computePercentile(ttfbValues, 50) : 0;
  const originTTFB_p95 = ttfbValues.length > 0 ? computePercentile(ttfbValues, 95) : 0;

  // 5-field waterfall
  const waterfall = computeWaterfall(withTiming);

  // Per-origin breakdown
  const perOrigin = computePerOriginStats(withTiming);

  return {
    p50,
    p95,
    p99,
    originTTFB_p50,
    originTTFB_p95,
    waterfall,
    perOrigin,
  };
}

/**
 * Computes the 5-field latency waterfall with P50/P95 per field.
 *
 * Fields (from spec Section 6.2):
 *   time_to_first_upstream_tx_byte   → XC starts sending to origin
 *   time_to_first_upstream_rx_byte   → TTFB from origin
 *   time_to_last_upstream_rx_byte    → Complete response from origin
 *   time_to_first_downstream_tx_byte → XC starts sending to client
 *   time_to_last_downstream_tx_byte  → Complete delivery to client
 */
function computeWaterfall(logs: AccessLogEntry[]): LatencyWaterfall {
  const fieldValues: Record<string, number[]> = {};
  for (const field of TIMING_FIELDS) {
    fieldValues[field] = [];
  }

  for (const log of logs) {
    for (const field of TIMING_FIELDS) {
      const val = safeTimingMs(log[field]);
      if (val >= 0) {
        fieldValues[field].push(val);
      }
    }
  }

  // Sort each field array and compute percentiles
  for (const field of TIMING_FIELDS) {
    fieldValues[field].sort((a, b) => a - b);
  }

  const getStats = (field: string) => {
    const vals = fieldValues[field];
    if (vals.length === 0) return { p50: 0, p95: 0 };
    return {
      p50: computePercentile(vals, 50),
      p95: computePercentile(vals, 95),
    };
  };

  return {
    toFirstUpstreamTx: getStats('time_to_first_upstream_tx_byte'),
    toFirstUpstreamRx: getStats('time_to_first_upstream_rx_byte'),
    toLastUpstreamRx: getStats('time_to_last_upstream_rx_byte'),
    toFirstDownstreamTx: getStats('time_to_first_downstream_tx_byte'),
    toLastDownstreamTx: getStats('time_to_last_downstream_tx_byte'),
  };
}

/**
 * Computes per-origin latency statistics grouped by dst_ip.
 */
function computePerOriginStats(
  logs: AccessLogEntry[]
): LatencyStats['perOrigin'] {
  // Group logs by dst_ip
  const groups = new Map<string, AccessLogEntry[]>();
  for (const log of logs) {
    const ip = log.dst_ip;
    if (!ip) continue;
    const group = groups.get(ip);
    if (group) {
      group.push(log);
    } else {
      groups.set(ip, [log]);
    }
  }

  const perOrigin: LatencyStats['perOrigin'] = [];

  for (const [dstIp, originLogs] of groups) {
    const durations = originLogs
      .map((log) => log.total_duration_seconds * 1000)
      .filter((v) => v > 0)
      .sort((a, b) => a - b);

    const ttfbValues = originLogs
      .map((log) => safeTimingMs(log.time_to_first_upstream_rx_byte))
      .filter((v) => v > 0)
      .sort((a, b) => a - b);

    perOrigin.push({
      dstIp,
      p50: durations.length > 0 ? computePercentile(durations, 50) : 0,
      p95: durations.length > 0 ? computePercentile(durations, 95) : 0,
      originTTFB_p95: ttfbValues.length > 0 ? computePercentile(ttfbValues, 95) : 0,
      count: originLogs.length,
    });
  }

  // Sort by count descending
  perOrigin.sort((a, b) => b.count - a.count);
  return perOrigin;
}

// =============================================================================
// Percentile Computation
// =============================================================================

/**
 * Computes the p-th percentile from a sorted array of numbers.
 * Uses linear interpolation between closest ranks.
 *
 * @param sorted - Pre-sorted array of numbers (ascending)
 * @param p - Percentile to compute (0-100)
 * @returns The percentile value
 */
export function computePercentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  if (sorted.length === 1) return sorted[0];

  const index = (p / 100) * (sorted.length - 1);
  const lower = Math.floor(index);
  const upper = Math.ceil(index);

  if (lower === upper) return sorted[lower];

  // Linear interpolation
  const fraction = index - lower;
  return sorted[lower] + fraction * (sorted[upper] - sorted[lower]);
}

// =============================================================================
// Event Feed
// =============================================================================

/**
 * Builds event feed entries from raw access logs (errors) and security events.
 * - Access logs with rsp_code >= 400 become error EventFeedEntries
 * - Security events become security EventFeedEntries
 * - Sorted by timestamp descending, limited to MAX_EVENT_FEED entries
 */
function buildEventFeed(
  accessLogs: AccessLogEntry[],
  securityEvents: SecurityEventEntry[]
): EventFeedEntry[] {
  const entries: EventFeedEntry[] = [];

  // Error entries from access logs
  for (const log of accessLogs) {
    const rspCode = parseInt(log.rsp_code, 10);
    if (rspCode < 400) continue;

    const is5xxErr = rspCode >= 500;

    entries.push({
      id: log.req_id || generateId(),
      timestamp: safeTimestamp(log['@timestamp'] || log.time || (log as Record<string,unknown>).timestamp),
      type: 'error',
      severity: is5xxErr ? 'error' : 'warning',
      message: formatErrorMessage(log),
      details: {
        rspCode: log.rsp_code,
        rspCodeDetails: log.rsp_code_details,
        srcIp: log.src_ip,
        reqPath: log.req_path,
        dstIp: log.dst_ip,
        method: log.method,
        domain: log.domain || log.authority,
      },
    });
  }

  // Security entries from security events
  for (const evt of securityEvents) {
    entries.push({
      id: evt.req_id || generateId(),
      timestamp: safeTimestamp(evt['@timestamp'] || evt.time || (evt as Record<string,unknown>).timestamp),
      type: 'security',
      severity: mapSecEventSeverity(evt),
      message: formatSecurityMessage(evt),
      details: {
        secEventName: evt.sec_event_name,
        action: evt.action,
        srcIp: evt.src_ip,
        reqPath: evt.req_path,
        country: evt.country,
        wafMode: evt.waf_mode,
        violationRating: evt.violation_rating,
      },
    });
  }

  // Sort by timestamp descending (most recent first)
  entries.sort((a, b) => {
    const tA = new Date(a.timestamp).getTime();
    const tB = new Date(b.timestamp).getTime();
    return tB - tA;
  });

  // Limit to MAX_EVENT_FEED
  return entries.slice(0, MAX_EVENT_FEED);
}

/**
 * Formats an error access log into a human-readable message for the event feed.
 */
function formatErrorMessage(log: AccessLogEntry): string {
  const parts: string[] = [];
  parts.push(`${log.rsp_code}`);

  if (log.rsp_code_details) {
    parts.push(log.rsp_code_details);
  }

  parts.push(`${log.method} ${log.req_path}`);

  if (log.src_ip) {
    parts.push(`from ${log.src_ip}`);
  }

  if (log.dst_ip) {
    parts.push(`→ ${log.dst_ip}`);
  }

  return parts.join(' | ');
}

/**
 * Formats a security event into a human-readable message for the event feed.
 */
function formatSecurityMessage(evt: SecurityEventEntry): string {
  const parts: string[] = [];

  if (evt.action) {
    parts.push(`[${evt.action.toUpperCase()}]`);
  }

  if (evt.sec_event_name) {
    parts.push(evt.sec_event_name);
  }

  parts.push(`${evt.method || ''} ${evt.req_path || ''}`.trim());

  if (evt.src_ip) {
    parts.push(`from ${evt.src_ip}`);
  }

  if (evt.country) {
    parts.push(`(${evt.country})`);
  }

  return parts.join(' ');
}

/**
 * Safely extract a timestamp, falling back to current time if invalid.
 */
function safeTimestamp(val: unknown): string {
  if (!val) return new Date().toISOString();
  const s = String(val);
  const d = new Date(s);
  if (isNaN(d.getTime())) return new Date().toISOString();
  return d.toISOString();
}

/**
 * Maps a security event to a feed severity level.
 */
function mapSecEventSeverity(evt: SecurityEventEntry): EventFeedEntry['severity'] {
  const action = (evt.action || '').toLowerCase();
  if (action === 'block' || action === 'blocked') return 'critical';
  if (action === 'reject' || action === 'denied') return 'critical';
  if (action === 'flag' || action === 'flagged') return 'warning';
  if (action === 'alert') return 'warning';

  const rating = (evt.violation_rating || '').toLowerCase();
  if (rating === 'critical' || rating === '5') return 'critical';
  if (rating === 'high' || rating === '4') return 'error';
  if (rating === 'medium' || rating === '3') return 'warning';

  return 'info';
}

// =============================================================================
// JA4 Clustering
// =============================================================================

/**
 * Groups access logs by JA4 TLS fingerprint to identify attack tools.
 * Falls back to tls_fingerprint if ja4_tls_fingerprint is not available.
 *
 * For each cluster: count of requests, unique IPs, and top user agent.
 */
function clusterByJA4(accessLogs: AccessLogEntry[]): JA4Cluster[] {
  const clusters = new Map<
    string,
    { count: number; ips: Set<string>; uaCounts: Map<string, number> }
  >();

  for (const log of accessLogs) {
    const fingerprint = log.ja4_tls_fingerprint || log.tls_fingerprint;
    if (!fingerprint) continue;

    let cluster = clusters.get(fingerprint);
    if (!cluster) {
      cluster = { count: 0, ips: new Set(), uaCounts: new Map() };
      clusters.set(fingerprint, cluster);
    }

    cluster.count++;

    if (log.src_ip) {
      cluster.ips.add(log.src_ip);
    }

    if (log.user_agent) {
      const uaCount = cluster.uaCounts.get(log.user_agent) || 0;
      cluster.uaCounts.set(log.user_agent, uaCount + 1);
    }
  }

  // Convert to JA4Cluster array
  const result: JA4Cluster[] = [];
  for (const [fingerprint, data] of clusters) {
    // Find top user agent
    let topUa = '';
    let topUaCount = 0;
    for (const [ua, count] of data.uaCounts) {
      if (count > topUaCount) {
        topUa = ua;
        topUaCount = count;
      }
    }

    result.push({
      fingerprint,
      count: data.count,
      ips: Array.from(data.ips),
      topUa,
    });
  }

  // Sort by count descending
  result.sort((a, b) => b.count - a.count);
  return result;
}

// =============================================================================
// Sample Rate
// =============================================================================

/**
 * Computes the average sample_rate across all raw access logs.
 * When avg > 1, F5 XC is sampling (traffic is higher than log entries suggest).
 */
function computeAverageSampleRate(accessLogs: AccessLogEntry[]): number {
  if (accessLogs.length === 0) return 1;

  let totalSampleRate = 0;
  let count = 0;

  for (const log of accessLogs) {
    const sr = Number(log.sample_rate);
    if (sr > 0 && isFinite(sr)) {
      totalSampleRate += sr;
      count++;
    }
  }

  if (count === 0) return 1;
  return totalSampleRate / count;
}

// =============================================================================
// Helpers
// =============================================================================

/**
 * Safely converts a timing field value to milliseconds.
 * F5 XC timing fields may be in seconds (fractional) or already in ms.
 * Values > 1000 are assumed to be already in ms.
 */
function safeTimingMs(value: unknown): number {
  const num = Number(value);
  if (!isFinite(num) || num < 0) return 0;

  // F5 XC timing fields are in seconds (as fractional numbers)
  // Convert to milliseconds. Values that look like they're already in ms (>100s)
  // are left as-is, but typically XC returns sub-second values.
  if (num < 100) {
    return num * 1000;
  }
  return num;
}

/**
 * Generates a unique ID for events without a req_id.
 */
function generateId(): string {
  return Date.now().toString(36) + Math.random().toString(36).substring(2, 8);
}
