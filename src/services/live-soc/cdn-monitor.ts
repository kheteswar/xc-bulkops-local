// =============================================================================
// Live SOC Monitoring Room — CDN Monitor
// Analyses CDN cache performance: hit/miss ratio, miss reasons, TS cookie
// issues, and origin pull rate.
// =============================================================================

import { apiClient } from '../api';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CDNCacheAnalysis {
  /** Cache hit ratio as a percentage (0-100). */
  hitRatio: number;
  /** Breakdown of cache miss reasons with counts. */
  missReasons: Array<{ reason: string; count: number }>;
  /**
   * True if the TS cookie (XC session cookie) is likely causing excessive
   * cache misses — a common misconfiguration.
   */
  tsCookieIssue: boolean;
  /** Percentage of requests that resulted in an origin pull. */
  originPullRate: number;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function safeNum(val: unknown, fallback = 0): number {
  const n = Number(val);
  return isNaN(n) ? fallback : n;
}

// ---------------------------------------------------------------------------
// Strategy 1: graph/lb_cache_content endpoint (CDN-specific)
// ---------------------------------------------------------------------------

interface CacheContentResponse {
  data?: Array<Record<string, unknown>>;
  items?: Array<Record<string, unknown>>;
  total_hits?: number;
  total_misses?: number;
  hit_ratio?: number;
  cache_hit_ratio?: number;
  buckets?: Array<Record<string, unknown>>;
}

async function fetchCacheGraph(
  namespace: string,
  lbName: string,
  startTime: string,
  endTime: string,
): Promise<CacheContentResponse | null> {
  try {
    return await apiClient.post<CacheContentResponse>(
      `/api/data/namespaces/${namespace}/graph/lb_cache_content`,
      {
        namespace,
        virtual_host: lbName,
        start_time: startTime,
        end_time: endTime,
      },
    );
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Strategy 2: access-log aggregation for cache_status field
// ---------------------------------------------------------------------------

interface AggResponse {
  aggs?: Record<string, { buckets?: Array<{ key: string; doc_count: number }> }>;
  aggregations?: Record<string, { buckets?: Array<{ key: string; doc_count: number }> }>;
  total_hits?: number;
  hits?: number;
}

async function fetchCacheAggregation(
  namespace: string,
  lbName: string,
  startTime: string,
  endTime: string,
): Promise<AggResponse | null> {
  try {
    const body = {
      namespace,
      query: {
        start_time: startTime,
        end_time: endTime,
        virtual_hosts: [lbName],
      },
      aggs: {
        cache_status_agg: {
          field: 'cache_status',
          topk: 20,
        },
        miss_reason_agg: {
          field: 'cache_miss_reason',
          topk: 20,
        },
        cookie_miss_agg: {
          field: 'req_headers.cookie',
          topk: 10,
        },
      },
      scroll: false,
    };

    return await apiClient.post<AggResponse>(
      `/api/data/namespaces/${namespace}/access_logs`,
      body,
    );
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// TS cookie detection
// ---------------------------------------------------------------------------

/** Known XC session cookie names that bypass CDN cache. */
const TS_COOKIE_PATTERNS = [
  'ts_', 'ts=', '_ts_', '__ts',
  'ves-', '_ves_',
  'botdefense', 'bd_',
];

function detectTsCookieIssue(
  missReasons: Array<{ reason: string; count: number }>,
  totalRequests: number,
): boolean {
  // If "cookie" or "set-cookie" is a dominant miss reason, likely TS cookie
  const cookieMisses = missReasons.filter((r) => {
    const lower = r.reason.toLowerCase();
    return (
      lower.includes('cookie') ||
      lower.includes('set-cookie') ||
      lower.includes('vary_cookie') ||
      TS_COOKIE_PATTERNS.some((p) => lower.includes(p))
    );
  });

  const cookieMissCount = cookieMisses.reduce((sum, r) => sum + r.count, 0);

  // Flag if cookie-related misses account for >20% of total misses
  const totalMisses = missReasons.reduce((sum, r) => sum + r.count, 0);
  if (totalMisses > 0 && cookieMissCount / totalMisses > 0.2) {
    return true;
  }

  // Also flag if cookie misses are >5% of all requests
  if (totalRequests > 0 && cookieMissCount / totalRequests > 0.05) {
    return true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// analyzeCDNCache — main public function
// ---------------------------------------------------------------------------

/**
 * Analyse CDN cache performance for a load balancer.
 *
 * Attempts two strategies:
 *  1. The dedicated `graph/lb_cache_content` CDN endpoint
 *  2. Access-log aggregation on the `cache_status` field
 *
 * Returns a complete CDNCacheAnalysis or `null` if neither strategy yields
 * usable data (e.g. CDN is not configured for this LB).
 */
export async function analyzeCDNCache(
  namespace: string,
  lbName: string,
  startTime: string,
  endTime: string,
): Promise<CDNCacheAnalysis | null> {
  // Try both strategies concurrently
  const [graphResult, aggResult] = await Promise.all([
    fetchCacheGraph(namespace, lbName, startTime, endTime),
    fetchCacheAggregation(namespace, lbName, startTime, endTime),
  ]);

  // ---------------------------------------------------------------------------
  // Strategy 1: Use graph endpoint data if available
  // ---------------------------------------------------------------------------
  if (graphResult) {
    const directHitRatio =
      safeNum(graphResult.hit_ratio ?? graphResult.cache_hit_ratio, -1);

    if (directHitRatio >= 0) {
      const totalHits = safeNum(graphResult.total_hits);
      const totalMisses = safeNum(graphResult.total_misses);
      const totalReqs = totalHits + totalMisses || 1;

      // Parse miss reasons from buckets if available
      const missReasons = (graphResult.buckets ?? [])
        .filter((b) => {
          const key = String(b.key ?? '').toLowerCase();
          return key.includes('miss') || key.includes('expired') || key.includes('bypass');
        })
        .map((b) => ({
          reason: String(b.key ?? 'unknown'),
          count: safeNum(b.doc_count ?? b.count),
        }));

      return {
        hitRatio: Math.round(directHitRatio * 100) / 100,
        missReasons,
        tsCookieIssue: detectTsCookieIssue(missReasons, totalReqs),
        originPullRate:
          totalReqs > 0
            ? Math.round((totalMisses / totalReqs) * 10000) / 100
            : 0,
      };
    }
  }

  // ---------------------------------------------------------------------------
  // Strategy 2: Derive from access-log aggregation
  // ---------------------------------------------------------------------------
  if (aggResult) {
    const aggs = aggResult.aggs ?? aggResult.aggregations ?? {};

    // Cache status buckets
    const cacheStatusBuckets =
      aggs.cache_status_agg?.buckets ??
      aggs['cache_status']?.buckets ??
      [];

    const totalRequests = safeNum(aggResult.total_hits ?? aggResult.hits, 0);

    if (cacheStatusBuckets.length > 0) {
      let hits = 0;
      let misses = 0;

      for (const bucket of cacheStatusBuckets) {
        const key = String(bucket.key).toLowerCase();
        const count = safeNum(bucket.doc_count);

        if (key.includes('hit') && !key.includes('miss')) {
          hits += count;
        } else if (
          key.includes('miss') ||
          key.includes('expired') ||
          key.includes('bypass') ||
          key.includes('dynamic') ||
          key.includes('stale')
        ) {
          misses += count;
        }
      }

      const total = hits + misses || 1;
      const hitRatio = (hits / total) * 100;

      // Miss reason buckets
      const missReasonBuckets =
        aggs.miss_reason_agg?.buckets ??
        aggs['cache_miss_reason']?.buckets ??
        [];

      const missReasons = missReasonBuckets.map((b) => ({
        reason: String(b.key),
        count: safeNum(b.doc_count),
      }));

      return {
        hitRatio: Math.round(hitRatio * 100) / 100,
        missReasons,
        tsCookieIssue: detectTsCookieIssue(missReasons, totalRequests || total),
        originPullRate:
          total > 0
            ? Math.round((misses / total) * 10000) / 100
            : 0,
      };
    }
  }

  // Neither strategy produced results — CDN likely not configured
  return null;
}
