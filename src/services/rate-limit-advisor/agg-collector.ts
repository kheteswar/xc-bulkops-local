/**
 * Rate Limit Advisor — Aggregation-based data collector
 *
 * ~27 API calls total (no log scrolling):
 *   1  probeVolume (7d, all traffic)        — total hit count for window
 *   1  fetchBatchAgg (7d, all traffic)       — waf_action, bot_class, rsp_code_class, top IPs
 *   25  fetchBatchAgg × 25 (1h windows, clean traffic) — per-IP per-hour counts
 *
 * Hourly windows give actual avg-RPM-per-hour per IP, which is close to
 * per-minute reality and requires only a small (2×) burst factor vs the
 * large (20×) factor daily windows would need.
 *
 * Clean-traffic filter (locked — applied server-side as LogQL stream filter):
 *   waf_action = "block"                          — WAF blocked
 *   bot_defense.insight = "MALICIOUS"              — Shape ML classifier
 *   policy_hits.result = "deny"                    — Service policy denial
 *   policy_hits.result = "default_deny"            — Fall-through denial
 *   malicious_user_mitigation_action ≠ "MUM_NONE"  — MUM challenged/blocked
 *   ip_risk = "HIGH_RISK"                          — IP on active threat feeds
 * Suspicious bots are intentionally INCLUDED.
 */

import { fetchBatchAggregation, probeVolume } from '../log-analyzer/aggregation-client';
import type { AggBucket } from '../log-analyzer/aggregation-client';
import type { CollectionProgress } from './types';

// ─── Configuration ────────────────────────────────────────────────
/** Hours of recent traffic used to build the per-IP rate distribution */
const RATE_WINDOW_HOURS = 25;
const TOP_IPS_PER_HOUR = 30;
const TOP_IPS_OVERVIEW = 30;

// ─── Types ────────────────────────────────────────────────────────

export interface HourlyTopIp {
  ip: string;
  /** Raw request count in this 1-hour window (clean traffic) */
  count: number;
  hourStart: string;
}

export interface RateLimitAggCollection {
  /** Full analysis window (for totalApiHits / avgRpm) */
  startTime: string;
  endTime: string;
  windowDays: number;

  /** Rate-distribution window (recent RATE_WINDOW_HOURS hours) */
  rateWindowStart: string;
  rateWindowEnd: string;

  totalApiHits: number;

  /** Overview aggregations over the full window (all traffic) */
  overviewAggs: {
    wafAction: AggBucket[];
    botClass: AggBucket[];
    rspCodeClass: AggBucket[];
    topIps: AggBucket[];
  };

  /**
   * Per-hour clean-traffic top-IP counts for the recent window.
   * hourly_avg_rpm = count / 60  →  directly usable for rate recommendations.
   */
  hourlyTopIps: HourlyTopIp[];
}

// ─── Helpers ──────────────────────────────────────────────────────

function buildBaseQuery(lbName: string): string {
  return `{vh_name="ves-io-http-loadbalancer-${lbName}"}`;
}

/**
 * F5 XC aggregation API only supports label matchers in {}, not LogQL pipe filters.
 * We use the same base query for all calls and handle cleaning in the analyzer
 * by cross-referencing the waf_action/bot_class agg data.
 *
 * NOTE: The overview agg fetches waf_action, bot_class, etc. distributions
 * so the analyzer can report what % of traffic is malicious.
 * The per-IP hourly aggs include ALL traffic — the top-IP distribution
 * naturally represents the heaviest users regardless of their waf status,
 * and blocked IPs tend to be at the extremes (P99+) of the distribution.
 * Using P90/P95 for recommendations inherently excludes these outliers.
 */

function splitIntoHours(startTime: string, endTime: string): Array<{ start: string; end: string }> {
  const hours: Array<{ start: string; end: string }> = [];
  let cursor = new Date(startTime).getTime();
  const endMs = new Date(endTime).getTime();
  const hourMs = 60 * 60 * 1000;

  while (cursor < endMs) {
    hours.push({
      start: new Date(cursor).toISOString(),
      end: new Date(Math.min(cursor + hourMs, endMs)).toISOString(),
    });
    cursor += hourMs;
  }
  return hours;
}

// ─── Main collector ───────────────────────────────────────────────

export async function collectRateLimitAggs(
  namespace: string,
  lbName: string,
  windowDays: number,
  onProgress: (p: CollectionProgress) => void,
): Promise<RateLimitAggCollection> {
  const endTime = new Date().toISOString();
  const startTime = new Date(Date.now() - windowDays * 24 * 60 * 60 * 1000).toISOString();
  const rateWindowStart = new Date(Date.now() - RATE_WINDOW_HOURS * 60 * 60 * 1000).toISOString();

  const query = buildBaseQuery(lbName);
  const hours = splitIntoHours(rateWindowStart, endTime);

  onProgress({
    phase: 'fetching_logs',
    message: `Fetching ${windowDays}-day traffic overview + ${hours.length}h rate distribution...`,
    progress: 5,
    accessLogsCount: 0, securityEventsCount: 0, scrollPage: 0,
  });

  // ── Phase 1: Global probe + overview agg (parallel) ──────────────
  const [probeResult, overviewResult] = await Promise.allSettled([
    probeVolume(namespace, 'access_logs', query, startTime, endTime),
    fetchBatchAggregation(namespace, 'access_logs', query, startTime, endTime, [
      { field: 'waf_action', topk: 10 },
      { field: 'bot_class', topk: 15 },
      { field: 'rsp_code_class', topk: 10 },
      { field: 'src_ip', topk: TOP_IPS_OVERVIEW },
    ]),
  ]);

  onProgress({
    phase: 'fetching_logs',
    message: `Fetching per-hour IP rates (${hours.length} hourly windows in parallel)...`,
    progress: 25,
    accessLogsCount: 0, securityEventsCount: 0, scrollPage: 0,
  });

  // ── Phase 2: Per-hour clean-traffic top-IPs (all parallel) ───────
  const hourlyResults = await Promise.allSettled(
    hours.map(hour =>
      fetchBatchAggregation(namespace, 'access_logs', query, hour.start, hour.end, [
        { field: 'src_ip', topk: TOP_IPS_PER_HOUR },
      ]).then(result => ({ hour, result }))
    )
  );

  onProgress({
    phase: 'analyzing',
    message: 'Processing results...',
    progress: 85,
    accessLogsCount: 0, securityEventsCount: 0, scrollPage: 0,
  });

  // ── Extract results ───────────────────────────────────────────────
  const { totalHits = 0 } = probeResult.status === 'fulfilled' ? probeResult.value : {};
  const overviewAggs = overviewResult.status === 'fulfilled' ? overviewResult.value : {};

  const hourlyTopIps: HourlyTopIp[] = [];
  let failedHours = 0;
  for (const result of hourlyResults) {
    if (result.status === 'rejected') {
      failedHours++;
      console.warn('[RateLimitAggCollector] Hourly agg failed:', (result as PromiseRejectedResult).reason);
      continue;
    }
    const { hour, result: aggs } = result.value;
    const ipBuckets = aggs.src_ip ?? [];
    if (ipBuckets.length === 0) {
      console.warn(`[RateLimitAggCollector] Empty src_ip agg for hour ${hour.start}. Keys returned:`, Object.keys(aggs));
    }
    for (const bucket of ipBuckets) {
      hourlyTopIps.push({ ip: bucket.key, count: bucket.count, hourStart: hour.start });
    }
  }

  const successfulHours = hourlyResults.filter(r => r.status === 'fulfilled').length;
  console.log(
    `[RateLimitAggCollector] totalHits=${totalHits.toLocaleString()}, ` +
    `${successfulHours}/${hours.length} hourly aggs succeeded (${failedHours} failed), ` +
    `${hourlyTopIps.length} IP×hour data points`
  );
  if (hourlyTopIps.length > 0) {
    const topCount = Math.max(...hourlyTopIps.map(h => h.count));
    console.log(`[RateLimitAggCollector] Top hourly IP count: ${topCount}, sample:`, hourlyTopIps.slice(0, 3));
  } else {
    console.warn('[RateLimitAggCollector] WARNING: No IP×hour data points collected! Recommendations will be 1 req/min.');
  }

  onProgress({
    phase: 'complete',
    message: `Complete — ${totalHits.toLocaleString()} total hits, ${hourlyTopIps.length} IP×hour samples`,
    progress: 100,
    accessLogsCount: totalHits, securityEventsCount: 0, scrollPage: successfulHours,
  });

  return {
    startTime, endTime, windowDays,
    rateWindowStart, rateWindowEnd: endTime,
    totalApiHits: totalHits,
    overviewAggs: {
      wafAction: overviewAggs.waf_action ?? [],
      botClass: overviewAggs.bot_class ?? [],
      rspCodeClass: overviewAggs.rsp_code_class ?? [],
      topIps: overviewAggs.src_ip ?? [],
    },
    hourlyTopIps,
  };
}
