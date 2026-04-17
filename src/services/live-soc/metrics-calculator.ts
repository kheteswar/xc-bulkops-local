// =============================================================================
// Live SOC Monitoring Room — Metrics Calculator
// =============================================================================
// Transforms aggregation API responses into DashboardMetrics.
// Handles parsing of F5 XC aggregation response format, error diagnosis
// enrichment via K000146828 KB, response code distribution, origin health,
// security breakdown, and all delta tracking for cycle-over-cycle badges.
// =============================================================================

import type {
  AggBucket,
  AggregationResults,
  HeartbeatResult,
  DashboardMetrics,
  AlertEntry,
  AuditEntry,
  ErrorDiagnosisEntry,
} from './types';
import { createEmptyMetrics } from './types';

// =============================================================================
// Aggregation Response Parser
// =============================================================================

/**
 * Robust parser that handles F5 XC aggregation response format.
 * Looks for `aggs.{key}.buckets` array where each bucket has
 * `key` and `count` (or `doc_count`).
 *
 * Handles multiple response shapes:
 * - { aggs: { fieldName: { buckets: [...] } } }
 * - { aggregations: { fieldName: { buckets: [...] } } }
 * - { buckets: [...] } (direct)
 * - Array passed directly
 */
export function parseAggregationResponse(response: unknown): AggBucket[] {
  if (!response) return [];

  // If already an array, try to parse directly
  if (Array.isArray(response)) {
    return parseBucketArray(response);
  }

  if (typeof response !== 'object') return [];

  const resp = response as Record<string, unknown>;

  // Direct buckets array at top level
  if (Array.isArray(resp.buckets)) {
    return parseBucketArray(resp.buckets);
  }

  // Look in 'aggs' container (F5 XC uses 'aggs' key)
  const aggsContainer = (resp.aggs ?? resp.aggregations ?? resp.data) as Record<string, unknown> | undefined;
  if (aggsContainer && typeof aggsContainer === 'object' && !Array.isArray(aggsContainer)) {
    // Find the first key that has a buckets array
    for (const key of Object.keys(aggsContainer)) {
      const aggField = aggsContainer[key];
      if (aggField && typeof aggField === 'object' && !Array.isArray(aggField)) {
        const af = aggField as Record<string, unknown>;
        if (Array.isArray(af.buckets)) {
          return parseBucketArray(af.buckets);
        }
        // F5 XC may also return field_agg.field_agg.buckets (nested)
        for (const subKey of Object.keys(af)) {
          const sub = af[subKey];
          if (sub && typeof sub === 'object' && !Array.isArray(sub)) {
            const s = sub as Record<string, unknown>;
            if (Array.isArray(s.buckets)) return parseBucketArray(s.buckets);
          }
        }
      }
      // aggField itself might be a buckets array
      if (Array.isArray(aggField)) {
        return parseBucketArray(aggField);
      }
    }
  }

  // Fallback: search all top-level keys for anything with a buckets array
  for (const key of Object.keys(resp)) {
    const field = resp[key];
    if (field && typeof field === 'object' && !Array.isArray(field)) {
      const f = field as Record<string, unknown>;
      if (Array.isArray(f.buckets)) {
        return parseBucketArray(f.buckets);
      }
      // One more level deep
      for (const subKey of Object.keys(f)) {
        const sub = f[subKey];
        if (sub && typeof sub === 'object' && !Array.isArray(sub)) {
          const s = sub as Record<string, unknown>;
          if (Array.isArray(s.buckets)) return parseBucketArray(s.buckets);
        }
      }
    }
  }

  return [];
}

/**
 * Parses a raw bucket array into typed AggBucket objects.
 * Handles both `count` and `doc_count` fields for compatibility.
 */
function parseBucketArray(buckets: unknown[]): AggBucket[] {
  const result: AggBucket[] = [];

  for (const bucket of buckets) {
    if (!bucket || typeof bucket !== 'object') continue;

    const b = bucket as Record<string, unknown>;
    const key = String(b.key ?? b.name ?? b.label ?? '');
    const count = Number(b.count ?? b.doc_count ?? b.value ?? 0);

    if (!key && count === 0) continue;

    const aggBucket: AggBucket = { key, count };

    // Check for nested sub-buckets
    if (Array.isArray(b.sub_buckets) || Array.isArray(b.subBuckets) || Array.isArray(b.buckets)) {
      const subRaw = (b.sub_buckets ?? b.subBuckets ?? b.buckets) as unknown[];
      aggBucket.subBuckets = parseBucketArray(subRaw);
    }

    result.push(aggBucket);
  }

  // Sort by count descending
  result.sort((a, b) => b.count - a.count);
  return result;
}

// =============================================================================
// Response Code Helpers
// =============================================================================

/** Returns the class (2xx, 3xx, 4xx, 5xx) for a numeric or string response code. */
function rspCodeClass(code: string): string {
  const num = parseInt(code, 10);
  if (num >= 200 && num < 300) return '2xx';
  if (num >= 300 && num < 400) return '3xx';
  if (num >= 400 && num < 500) return '4xx';
  if (num >= 500 && num < 600) return '5xx';
  return 'other';
}

/** Checks if a response code string represents a 4xx error. */
function is4xx(code: string): boolean {
  const num = parseInt(code, 10);
  return num >= 400 && num < 500;
}

/** Checks if a response code string represents a 5xx error. */
function is5xx(code: string): boolean {
  const num = parseInt(code, 10);
  return num >= 500 && num < 600;
}

// =============================================================================
// Main Metrics Calculator
// =============================================================================

/**
 * Transforms aggregation results, heartbeat, and context data into
 * a complete DashboardMetrics object.
 *
 * @param aggregation - Parsed aggregation results from Track 2
 * @param heartbeat - Track 1 heartbeat (total_hits, secEventHits)
 * @param prevMetrics - Previous cycle metrics for delta calculations
 * @param alerts - Active alerts from the alerts API
 * @param auditEntries - Recent audit log entries
 * @param windowSeconds - Data window in seconds (e.g. 300 for 5min)
 * @param diagnosisKB - Error diagnosis KB entries for enrichment
 */
export function calculateMetrics(
  aggregation: AggregationResults,
  heartbeat: HeartbeatResult,
  prevMetrics: DashboardMetrics,
  alerts: AlertEntry[],
  auditEntries: AuditEntry[],
  windowSeconds: number,
  diagnosisKB: ErrorDiagnosisEntry[]
): DashboardMetrics {
  const metrics = createEmptyMetrics();

  // -------------------------------------------------------------------------
  // Traffic: RPS and totals from heartbeat (Track 1 — accurate, not sampled)
  // -------------------------------------------------------------------------
  metrics.rps = windowSeconds > 0 ? heartbeat.totalHits / windowSeconds : 0;
  metrics.prevRps = prevMetrics.rps;
  metrics.totalRequests = heartbeat.totalHits;
  metrics.totalSecEvents = heartbeat.secEventHits;
  metrics.prevTotalSecEvents = prevMetrics.totalSecEvents;

  // -------------------------------------------------------------------------
  // Response Code Distribution (from Agg-A1: byRspCode)
  // -------------------------------------------------------------------------
  const rspCodeDist = calculateResponseCodeDistribution(aggregation.byRspCode);
  metrics.responseCodeDist = rspCodeDist.distribution;

  // Error rates from the distribution (aggregation counts are exact)
  const total4xx = rspCodeDist.total4xx;
  const total5xx = rspCodeDist.total5xx;
  const totalFromAgg = rspCodeDist.totalCount;

  if (totalFromAgg > 0) {
    metrics.errorRate = (total4xx + total5xx) / totalFromAgg;
    metrics.error4xxRate = total4xx / totalFromAgg;
    metrics.error5xxRate = total5xx / totalFromAgg;
  }
  metrics.prevErrorRate = prevMetrics.errorRate;

  // -------------------------------------------------------------------------
  // Error Diagnosis (from Agg-A2: byRspCodeDetails + KB enrichment)
  // -------------------------------------------------------------------------
  metrics.errorDiagnosis = calculateErrorDiagnosis(
    aggregation.byRspCodeDetails,
    prevMetrics.errorDiagnosis,
    diagnosisKB
  );

  // -------------------------------------------------------------------------
  // Origin Health (from Agg-A4: byDstIp)
  // -------------------------------------------------------------------------
  metrics.originHealth = calculateOriginHealth(aggregation.byDstIp);

  // -------------------------------------------------------------------------
  // Security Breakdown (from Agg-S1: secByEventName)
  // -------------------------------------------------------------------------
  metrics.securityBreakdown = calculateSecurityBreakdown(aggregation.secByEventName);

  // -------------------------------------------------------------------------
  // Top Signatures (from Agg-S2: secBySignatureId)
  // -------------------------------------------------------------------------
  metrics.topSignatures = aggregation.secBySignatureId.slice(0, 20).map((b) => ({
    id: b.key,
    count: b.count,
  }));

  // -------------------------------------------------------------------------
  // Top Attacking IPs (from Agg-S3: secBySrcIp)
  // -------------------------------------------------------------------------
  metrics.topAttackingIps = aggregation.secBySrcIp.slice(0, 20).map((b) => ({
    ip: b.key,
    count: b.count,
    // Country and ASN would require sub-aggregation; populated from sub-buckets if available
    country: b.subBuckets?.find((sb) => sb.key !== b.key)?.key,
    asn: undefined,
  }));

  // -------------------------------------------------------------------------
  // Top Violations (from Agg-S5: secByViolation)
  // -------------------------------------------------------------------------
  metrics.topViolations = aggregation.secByViolation.slice(0, 20).map((b) => ({
    name: b.key,
    count: b.count,
  }));

  // -------------------------------------------------------------------------
  // Geo Distribution (from Agg-A3: byCountry)
  // -------------------------------------------------------------------------
  metrics.geoDistribution = calculateGeoDistribution(
    aggregation.byCountry,
    prevMetrics.geoDistribution
  );

  // -------------------------------------------------------------------------
  // Hot Paths (from Agg-A5: byReqPath)
  // -------------------------------------------------------------------------
  metrics.hotPaths = calculateHotPaths(aggregation.byReqPath);

  // -------------------------------------------------------------------------
  // Top Talkers — non-security (from Agg-A7: bySrcIp)
  // -------------------------------------------------------------------------
  metrics.topTalkers = aggregation.bySrcIp.slice(0, 30).map((b) => ({
    ip: b.key,
    count: b.count,
  }));

  // -------------------------------------------------------------------------
  // WAF Action Distribution (from Agg-A8: byWafAction)
  // -------------------------------------------------------------------------
  metrics.wafActions = aggregation.byWafAction.map((b) => ({
    action: b.key,
    count: b.count,
  }));

  // -------------------------------------------------------------------------
  // Domain Breakdown (from Agg-A6: byDomain)
  // -------------------------------------------------------------------------
  metrics.domainBreakdown = calculateDomainBreakdown(aggregation.byDomain);

  // -------------------------------------------------------------------------
  // Alerts & Config Changes
  // -------------------------------------------------------------------------
  metrics.activeAlertCount = alerts.filter((a) => a.state === 'active' || a.state === 'ACTIVE').length;
  metrics.recentConfigChanges = auditEntries.length;

  // -------------------------------------------------------------------------
  // CDN and Bot (set by caller from feature-specific fetchers)
  // -------------------------------------------------------------------------
  metrics.cacheHitRatio = prevMetrics.cacheHitRatio;
  metrics.botRatio = prevMetrics.botRatio;

  return metrics;
}

// =============================================================================
// Response Code Distribution
// =============================================================================

interface RspCodeDistResult {
  distribution: Array<{ code: string; count: number; pct: number }>;
  totalCount: number;
  total2xx: number;
  total3xx: number;
  total4xx: number;
  total5xx: number;
}

function calculateResponseCodeDistribution(byRspCode: AggBucket[]): RspCodeDistResult {
  const totalCount = byRspCode.reduce((sum, b) => sum + b.count, 0);
  let total2xx = 0;
  let total3xx = 0;
  let total4xx = 0;
  let total5xx = 0;

  const distribution = byRspCode.map((b) => {
    const cls = rspCodeClass(b.key);
    if (cls === '2xx') total2xx += b.count;
    else if (cls === '3xx') total3xx += b.count;
    else if (cls === '4xx') total4xx += b.count;
    else if (cls === '5xx') total5xx += b.count;

    return {
      code: b.key,
      count: b.count,
      pct: totalCount > 0 ? (b.count / totalCount) * 100 : 0,
    };
  });

  return { distribution, totalCount, total2xx, total3xx, total4xx, total5xx };
}

// =============================================================================
// Error Diagnosis
// =============================================================================

function calculateErrorDiagnosis(
  byRspCodeDetails: AggBucket[],
  prevDiagnosis: DashboardMetrics['errorDiagnosis'],
  diagnosisKB: ErrorDiagnosisEntry[]
): DashboardMetrics['errorDiagnosis'] {
  // Build a lookup from previous cycle for delta tracking
  const prevCounts = new Map<string, number>();
  for (const entry of prevDiagnosis) {
    prevCounts.set(entry.rspCodeDetails, entry.count);
  }

  return byRspCodeDetails.map((bucket) => {
    const rspCodeDetails = bucket.key;
    const count = bucket.count;
    const prevCount = prevCounts.get(rspCodeDetails) ?? 0;

    // Try to match against the KB
    const kbMatch = matchDiagnosisKB(rspCodeDetails, diagnosisKB);

    if (kbMatch) {
      return {
        rspCodeDetails,
        rspCode: kbMatch.rspCode,
        count,
        prevCount,
        isOriginError: kbMatch.isOriginError,
        rootCause: kbMatch.rootCause,
        severity: kbMatch.severity,
        category: kbMatch.category,
        remediation: kbMatch.remediation,
      };
    }

    // No KB match — infer basic info from the details string
    const inferredRspCode = inferRspCodeFromDetails(rspCodeDetails);
    return {
      rspCodeDetails,
      rspCode: inferredRspCode,
      count,
      prevCount,
      isOriginError: rspCodeDetails.includes('via_upstream'),
      rootCause: rspCodeDetails,
      severity: is5xx(inferredRspCode) ? 'HIGH' : is4xx(inferredRspCode) ? 'MEDIUM' : 'INFO',
      category: rspCodeDetails.includes('upstream') ? 'origin' : 'config',
      remediation: `Investigate ${rspCodeDetails} errors`,
    };
  });
}

/**
 * Matches a rsp_code_details string against the diagnosis KB.
 * Uses regex matching against each KB entry's pattern.
 */
function matchDiagnosisKB(
  rspCodeDetails: string,
  kb: ErrorDiagnosisEntry[]
): ErrorDiagnosisEntry | null {
  if (!rspCodeDetails) return null;

  for (const entry of kb) {
    try {
      const regex = new RegExp(entry.pattern, 'i');
      if (regex.test(rspCodeDetails)) {
        return entry;
      }
    } catch {
      // Fallback to substring match if pattern is not valid regex
      if (rspCodeDetails.toLowerCase().includes(entry.pattern.toLowerCase())) {
        return entry;
      }
    }
  }

  return null;
}

/**
 * Attempts to infer the HTTP response code from a rsp_code_details string.
 * Many details strings start with or contain the status code.
 */
function inferRspCodeFromDetails(details: string): string {
  // Common patterns: "503 upstream_reset...", "via_upstream" (503), "route_not_found" (404)
  const codeMatch = details.match(/^(\d{3})/);
  if (codeMatch) return codeMatch[1];

  // Known detail patterns to code mappings
  const patternMap: Record<string, string> = {
    'route_not_found': '404',
    'csrf_origin_mismatch': '403',
    'ext_authz_denied': '403',
    'request_overall_timeout': '408',
    'request_payload_too_large': '413',
    'misdirected_request': '421',
    'upstream_reset': '503',
    'no_healthy_upstream': '503',
    'cluster_not_found': '503',
    'via_upstream': '503',
    'remote_reset': '503',
    'response_payload_too_large': '503',
    'stream_idle_timeout': '504',
    'upstream_response_timeout': '504',
  };

  const detailLower = details.toLowerCase();
  for (const [pattern, code] of Object.entries(patternMap)) {
    if (detailLower.includes(pattern.toLowerCase())) {
      return code;
    }
  }

  return 'unknown';
}

// =============================================================================
// Origin Health
// =============================================================================

/**
 * Calculates per-origin health from Agg-A4 (byDstIp).
 * Each bucket represents a destination IP with its request count.
 * Sub-buckets (if available) may contain error code breakdowns.
 */
function calculateOriginHealth(
  byDstIp: AggBucket[]
): DashboardMetrics['originHealth'] {
  return byDstIp.map((bucket) => {
    const dstIp = bucket.key;
    const totalCount = bucket.count;

    // If sub-buckets exist, sum 4xx and 5xx counts
    let errorCount = 0;
    if (bucket.subBuckets && bucket.subBuckets.length > 0) {
      for (const sub of bucket.subBuckets) {
        if (is4xx(sub.key) || is5xx(sub.key)) {
          errorCount += sub.count;
        }
      }
    }

    const errorRate = totalCount > 0 ? errorCount / totalCount : 0;

    return {
      dstIp,
      totalCount,
      errorCount,
      errorRate,
      // P95 latency is populated from Track 3 raw logs, not aggregation
      p95Latency: 0,
    };
  });
}

// =============================================================================
// Security Breakdown
// =============================================================================

/**
 * Calculates security event breakdown with percentages from Agg-S1 (secByEventName).
 */
function calculateSecurityBreakdown(
  secByEventName: AggBucket[]
): DashboardMetrics['securityBreakdown'] {
  const totalSecEvents = secByEventName.reduce((sum, b) => sum + b.count, 0);

  return secByEventName.map((bucket) => ({
    eventName: bucket.key,
    count: bucket.count,
    pct: totalSecEvents > 0 ? (bucket.count / totalSecEvents) * 100 : 0,
  }));
}

// =============================================================================
// Geo Distribution
// =============================================================================

/**
 * Calculates geo distribution with anomaly flag for new countries.
 * Compares current distribution to previous cycle to detect new sources.
 */
function calculateGeoDistribution(
  byCountry: AggBucket[],
  prevGeo: DashboardMetrics['geoDistribution']
): DashboardMetrics['geoDistribution'] {
  const totalCount = byCountry.reduce((sum, b) => sum + b.count, 0);

  // Build a set of previously known countries
  const prevCountries = new Set(prevGeo.map((g) => g.country));

  return byCountry.map((bucket) => ({
    country: bucket.key,
    count: bucket.count,
    pct: totalCount > 0 ? (bucket.count / totalCount) * 100 : 0,
    isNew: prevCountries.size > 0 && !prevCountries.has(bucket.key),
  }));
}

// =============================================================================
// Hot Paths
// =============================================================================

/**
 * Calculates hot path statistics from Agg-A5 (byReqPath).
 * Sub-buckets may contain response code breakdowns per path.
 */
function calculateHotPaths(
  byReqPath: AggBucket[]
): DashboardMetrics['hotPaths'] {
  return byReqPath.slice(0, 30).map((bucket) => {
    const path = bucket.key;
    const count = bucket.count;

    // Sum error codes from sub-buckets if available
    let errorCount = 0;
    if (bucket.subBuckets && bucket.subBuckets.length > 0) {
      for (const sub of bucket.subBuckets) {
        if (is4xx(sub.key) || is5xx(sub.key)) {
          errorCount += sub.count;
        }
      }
    }

    const errorRate = count > 0 ? errorCount / count : 0;

    return { path, count, errorCount, errorRate };
  });
}

// =============================================================================
// Domain Breakdown
// =============================================================================

/**
 * Calculates per-domain breakdown from Agg-A6 (byDomain).
 * Sub-buckets may contain error code counts per domain.
 */
function calculateDomainBreakdown(
  byDomain: AggBucket[]
): DashboardMetrics['domainBreakdown'] {
  return byDomain.map((bucket) => {
    const domain = bucket.key;
    const count = bucket.count;

    let errorCount = 0;
    if (bucket.subBuckets && bucket.subBuckets.length > 0) {
      for (const sub of bucket.subBuckets) {
        if (is4xx(sub.key) || is5xx(sub.key)) {
          errorCount += sub.count;
        }
      }
    }

    return { domain, count, errorCount };
  });
}

// =============================================================================
// Enrichment Helpers
// =============================================================================

/**
 * Enriches origin health metrics with P95 latency data from raw logs.
 * Called after Track 3 processing provides per-origin latency stats.
 */
export function enrichOriginHealthWithLatency(
  metrics: DashboardMetrics,
  perOriginLatency: Array<{ dstIp: string; p95: number }>
): DashboardMetrics {
  const latencyMap = new Map(perOriginLatency.map((o) => [o.dstIp, o.p95]));

  const enrichedHealth = metrics.originHealth.map((origin) => ({
    ...origin,
    p95Latency: latencyMap.get(origin.dstIp) ?? origin.p95Latency,
  }));

  return {
    ...metrics,
    originHealth: enrichedHealth,
  };
}

/**
 * Enriches metrics with CDN cache hit ratio from feature-specific data.
 */
export function enrichWithCacheHitRatio(
  metrics: DashboardMetrics,
  cacheHitRatio: number
): DashboardMetrics {
  return { ...metrics, cacheHitRatio };
}

/**
 * Enriches metrics with bot traffic ratio from Bot Defense data.
 */
export function enrichWithBotRatio(
  metrics: DashboardMetrics,
  botRatio: number
): DashboardMetrics {
  return { ...metrics, botRatio };
}

// =============================================================================
// Aggregation Result Assembly
// =============================================================================

/**
 * Assembles individual aggregation API responses into the unified
 * AggregationResults structure. Each key maps to a specific aggregation query.
 *
 * @param responses - Map of aggregation query ID to raw API response
 */
export function assembleAggregationResults(
  responses: Map<string, unknown>
): AggregationResults {
  return {
    byRspCode: parseAggregationResponse(responses.get('A1')),
    byRspCodeDetails: parseAggregationResponse(responses.get('A2')),
    byCountry: parseAggregationResponse(responses.get('A3')),
    byDstIp: parseAggregationResponse(responses.get('A4')),
    byReqPath: parseAggregationResponse(responses.get('A5')),
    byDomain: parseAggregationResponse(responses.get('A6')),
    bySrcIp: parseAggregationResponse(responses.get('A7')),
    byWafAction: parseAggregationResponse(responses.get('A8')),
    secByEventName: parseAggregationResponse(responses.get('S1')),
    secBySignatureId: parseAggregationResponse(responses.get('S2')),
    secBySrcIp: parseAggregationResponse(responses.get('S3')),
    secByCountry: parseAggregationResponse(responses.get('S4')),
    secByViolation: parseAggregationResponse(responses.get('S5')),
  };
}

// =============================================================================
// Summary Helpers
// =============================================================================

/**
 * Computes a compact summary string from metrics for lobby card display.
 */
export function summarizeMetrics(metrics: DashboardMetrics): string {
  const parts: string[] = [];

  // RPS
  if (metrics.rps >= 1000) {
    parts.push(`~${(metrics.rps / 1000).toFixed(1)}K rps`);
  } else {
    parts.push(`~${Math.round(metrics.rps)} rps`);
  }

  // Error rate
  parts.push(`${(metrics.errorRate * 100).toFixed(1)}% err`);

  // Security events
  if (metrics.totalSecEvents > 0) {
    parts.push(`${metrics.totalSecEvents} sec`);
  }

  // Alerts
  if (metrics.activeAlertCount > 0) {
    parts.push(`${metrics.activeAlertCount} alerts`);
  }

  return parts.join(' | ');
}

/**
 * Extracts the total count from aggregation buckets.
 */
export function totalFromBuckets(buckets: AggBucket[]): number {
  return buckets.reduce((sum, b) => sum + b.count, 0);
}

/**
 * Finds a specific bucket by key (case-insensitive).
 */
export function findBucket(buckets: AggBucket[], key: string): AggBucket | undefined {
  const keyLower = key.toLowerCase();
  return buckets.find((b) => b.key.toLowerCase() === keyLower);
}

/**
 * Sums counts for buckets whose keys match a predicate.
 */
export function sumBuckets(buckets: AggBucket[], predicate: (key: string) => boolean): number {
  return buckets
    .filter((b) => predicate(b.key))
    .reduce((sum, b) => sum + b.count, 0);
}

/**
 * Computes the percentage delta between two values.
 * Returns a formatted string like "+12.3%" or "-5.1%".
 */
export function percentDelta(current: number, previous: number): string {
  if (previous === 0) {
    if (current === 0) return '0%';
    return '+100%';
  }
  const delta = ((current - previous) / previous) * 100;
  const sign = delta >= 0 ? '+' : '';
  return `${sign}${delta.toFixed(1)}%`;
}
