/**
 * Rate Limit Advisor — Aggregation-based analysis engine
 *
 * Uses hourly per-IP request counts to derive meaningful per-minute rates:
 *
 *   hourly_avg_rpm = ip_hour_count / 60
 *
 * This is the IP's actual average request rate during that specific hour —
 * already in req/min units without any conversion factor.
 *
 * A small WITHIN_HOUR_BURST_FACTOR of 2× accounts for the fact that
 * a user's busiest minute in an hour is roughly 2× their hourly average
 * (standard web traffic behavior). This is a conservative, well-established
 * property — not a user-facing tuning knob.
 *
 * Exclusions (applied server-side in agg-collector via query filter):
 *   - waf_action="block"  → WAF-blocked requests
 *   - bot_class="bad_bot" → Known malicious bots
 *   Suspicious bots are INCLUDED (may be legitimate automated clients).
 */

import type { RateLimitAggCollection } from './agg-collector';

// ─── Constants ────────────────────────────────────────────────────

const MINUTES_PER_HOUR = 60;

// ─── Types ────────────────────────────────────────────────────────

export interface IpHourlyStats {
  /** Number of (IP, hour) pairs in the distribution */
  sampleCount: number;
  /** All values are raw request counts per IP per hour */
  p50: number;
  p75: number;
  p90: number;
  p95: number;
  p99: number;
  max: number;
  mean: number;
}

export interface RateLimitRecommendation {
  label: string;
  percentile: number;
  /** P-th percentile of raw hourly request counts per IP */
  hourlyCountAtPercentile: number;
  /** Final per-minute rate limit (rounded clean) */
  rateLimit: number;
  burstMultiplier: number;
  effectiveLimit: number;
  reasoning: string;
}

export interface AggAnalysisResults {
  lbName: string;
  namespace: string;
  startTime: string;
  endTime: string;
  generatedAt: string;
  windowDays: number;

  // ── Volume ────────────────────────────────────────────────────
  totalApiHits: number;
  avgRpm: number;
  peakHourRpm: number;

  // ── Traffic mix ───────────────────────────────────────────────
  trafficMix: {
    totalSampled: number;
    blockedCount: number;
    blockedPct: number;
    maliciousBotCount: number;
    maliciousBotPct: number;
    botClasses: Array<{ cls: string; count: number; pct: number }>;
    wafActions: Array<{ action: string; count: number; pct: number }>;
    responseBreakdown: Array<{ code: string; count: number; pct: number }>;
  };

  // ── Per-IP rate distribution (clean traffic, hourly windows) ──
  ipStats: IpHourlyStats;
  topIps: Array<{
    ip: string;
    totalCount: number;
    hoursObserved: number;
    peakHourCount: number;
    avgHourCount: number;
  }>;

  // ── Recommendations (per minute) ──────────────────────────────
  recommendations: {
    conservative: RateLimitRecommendation;
    balanced: RateLimitRecommendation;
    aggressive: RateLimitRecommendation;
  };

  /** Internal: per-IP hourly count data for the impact simulator */
  _ipHourlyData: Array<{ ip: string; hourlyCounts: number[] }>;
}

// ─── Helpers ──────────────────────────────────────────────────────

function calcPercentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(Math.floor((p / 100) * sorted.length), sorted.length - 1);
  return sorted[idx];
}

function roundToClean(n: number): number {
  if (n <= 0) return 1;
  if (n < 5) return Math.ceil(n);
  if (n < 20) return Math.ceil(n / 5) * 5;
  if (n < 100) return Math.ceil(n / 10) * 10;
  if (n < 1000) return Math.ceil(n / 50) * 50;
  return Math.ceil(n / 100) * 100;
}

function buildRecommendation(
  label: string,
  percentile: number,
  hourlyCount: number,
  safetyMargin: number,
  burstMultiplier: number,
): RateLimitRecommendation {
  // Use hourly count directly as the per-minute ceiling:
  // if an IP made N requests in an hour, worst case all N came in one minute.
  const rateLimit = Math.max(roundToClean(hourlyCount * safetyMargin), 1);
  const effectiveLimit = rateLimit * burstMultiplier;

  return {
    label,
    percentile,
    hourlyCountAtPercentile: Math.round(hourlyCount),
    rateLimit,
    burstMultiplier,
    effectiveLimit,
    reasoning:
      `P${percentile} of clean-traffic IPs made up to ${Math.round(hourlyCount)} requests in their busiest hour. ` +
      `Rate limit set at ${rateLimit} req/min (${Math.round((safetyMargin - 1) * 100)}% safety margin). ` +
      `Burst ${burstMultiplier}× absorbs short spikes up to ${effectiveLimit} req/min.`,
  };
}

// ─── Main analyzer ────────────────────────────────────────────────

export function analyzeRateLimitAggs(
  collection: RateLimitAggCollection,
  lbName: string,
  namespace: string,
): AggAnalysisResults {
  const { totalApiHits, overviewAggs, hourlyTopIps, windowDays } = collection;
  const windowMinutes = windowDays * 24 * 60;

  // ── Global RPM ───────────────────────────────────────────────────
  const avgRpm = windowMinutes > 0 ? Math.round(totalApiHits / windowMinutes) : 0;

  // Peak hour: max single-hour total across all IP×hour data
  const hourTotals = new Map<string, number>();
  for (const { hourStart, count } of hourlyTopIps) {
    hourTotals.set(hourStart, (hourTotals.get(hourStart) ?? 0) + count);
  }
  const peakHourCount = hourTotals.size > 0 ? Math.max(...hourTotals.values()) : 0;
  const peakHourRpm = Math.round(peakHourCount / MINUTES_PER_HOUR);

  // ── Traffic mix ──────────────────────────────────────────────────
  const wafBuckets = overviewAggs.wafAction;
  const wafTotal = wafBuckets.reduce((s, b) => s + b.count, 0);
  const blockedCount = wafBuckets.find(b => b.key === 'block')?.count ?? 0;
  const blockedPct = wafTotal > 0 ? Math.round((blockedCount / wafTotal) * 1000) / 10 : 0;

  const botBuckets = overviewAggs.botClass;
  const botTotal = botBuckets.reduce((s, b) => s + b.count, 0);
  const maliciousBotCount = botBuckets
    .filter(b => b.key === 'bad_bot' || b.key === 'malicious')
    .reduce((s, b) => s + b.count, 0);
  const maliciousBotPct = botTotal > 0 ? Math.round((maliciousBotCount / botTotal) * 1000) / 10 : 0;

  // ── Per-IP hourly count distribution ──────────────────────────────
  // Use raw hourly counts — NOT divided by 60.
  // Rationale: if an IP made 15 requests in an hour, worst case all 15
  // came in one minute. Using the raw count as the per-minute ceiling
  // is the safest assumption with hourly-resolution data.
  const hourlyCounts: number[] = [];
  const ipHourlyMap = new Map<string, number[]>();

  for (const { ip, count } of hourlyTopIps) {
    if (count > 0) {
      hourlyCounts.push(count);
      const existing = ipHourlyMap.get(ip);
      if (existing) existing.push(count);
      else ipHourlyMap.set(ip, [count]);
    }
  }
  hourlyCounts.sort((a, b) => a - b);

  const ipStats: IpHourlyStats = {
    sampleCount: hourlyCounts.length,
    p50: calcPercentile(hourlyCounts, 50),
    p75: calcPercentile(hourlyCounts, 75),
    p90: calcPercentile(hourlyCounts, 90),
    p95: calcPercentile(hourlyCounts, 95),
    p99: calcPercentile(hourlyCounts, 99),
    max: hourlyCounts.length > 0 ? hourlyCounts[hourlyCounts.length - 1] : 0,
    mean: hourlyCounts.length > 0
      ? hourlyCounts.reduce((s, v) => s + v, 0) / hourlyCounts.length : 0,
  };

  // ── Top IPs summary ──────────────────────────────────────────────
  const topIps = [...ipHourlyMap.entries()]
    .map(([ip, counts]) => ({
      ip,
      totalCount: counts.reduce((s, v) => s + v, 0),
      hoursObserved: counts.length,
      peakHourCount: Math.max(...counts),
      avgHourCount: Math.round(counts.reduce((s, v) => s + v, 0) / counts.length),
    }))
    .sort((a, b) => b.peakHourCount - a.peakHourCount)
    .slice(0, 20);

  // ── Recommendations ──────────────────────────────────────────────
  // Conservative: P99 × 2 burst × 1.5 safety  — covers the heaviest legitimate users
  // Balanced:     P95 × 2 burst × 1.5 safety  — doesn't block 95% of users
  // Aggressive:   P90 × 2 burst × 1.2 safety  — tighter, more abuser-catching
  const recommendations = {
    conservative: buildRecommendation('Conservative (P99)', 99, ipStats.p99, 1.5, 2),
    balanced:     buildRecommendation('Balanced (P95)',     95, ipStats.p95, 1.5, 2),
    aggressive:   buildRecommendation('Aggressive (P90)',   90, ipStats.p90, 1.2, 2),
  };

  return {
    lbName,
    namespace,
    startTime: collection.startTime,
    endTime: collection.endTime,
    generatedAt: new Date().toISOString(),
    windowDays,
    totalApiHits,
    avgRpm,
    peakHourRpm,
    trafficMix: {
      totalSampled: wafTotal,
      blockedCount,
      blockedPct,
      maliciousBotCount,
      maliciousBotPct,
      botClasses: botBuckets.map(b => ({
        cls: b.key, count: b.count,
        pct: botTotal > 0 ? Math.round((b.count / botTotal) * 1000) / 10 : 0,
      })),
      wafActions: wafBuckets.map(b => ({
        action: b.key, count: b.count,
        pct: wafTotal > 0 ? Math.round((b.count / wafTotal) * 1000) / 10 : 0,
      })),
      responseBreakdown: overviewAggs.rspCodeClass.map(b => ({
        code: b.key, count: b.count,
        pct: wafTotal > 0 ? Math.round((b.count / wafTotal) * 1000) / 10 : 0,
      })),
    },
    ipStats,
    topIps,
    recommendations,

    // Pre-build the per-IP hourly data so the simulator can run instantly on slider changes
    _ipHourlyData: [...ipHourlyMap.entries()].map(([ip, counts]) => ({ ip, hourlyCounts: counts })),
  };
}

// ─── Impact Simulator ─────────────────────────────────────────────

export interface AggImpactResult {
  rateLimit: number;
  burstMultiplier: number;
  effectiveLimit: number;

  totalIps: number;
  ipsAffected: number;
  ipsAffectedPct: number;

  totalIpHours: number;
  ipHoursAffected: number;

  estimatedBlockedRequests: number;
  estimatedTotalRequests: number;
  blockedPct: number;

  affectedIps: Array<{
    ip: string;
    hoursAffected: number;
    peakHourCount: number;
    avgHourCount: number;
    estimatedBlocked: number;
  }>;
}

/**
 * Simulates the impact of a proposed rate limit against the hourly aggregation data.
 * Runs instantly — designed to be called on every slider change.
 */
export function simulateAggImpact(
  results: AggAnalysisResults,
  rateLimit: number,
  burstMultiplier: number,
): AggImpactResult {
  const effectiveLimit = rateLimit * burstMultiplier;
  const ipData = results._ipHourlyData;

  let ipsAffected = 0;
  let ipHoursAffected = 0;
  let totalIpHours = 0;
  let estimatedBlocked = 0;
  let estimatedTotal = 0;
  const affected: AggImpactResult['affectedIps'] = [];

  for (const { ip, hourlyCounts } of ipData) {
    let ipBlocked = 0;
    let ipHoursHit = 0;
    let peak = 0;
    let sum = 0;

    for (const hourCount of hourlyCounts) {
      totalIpHours++;
      estimatedTotal += hourCount;
      if (hourCount > peak) peak = hourCount;
      sum += hourCount;

      // If hourly count exceeds the effective limit, the user would have been
      // rate-limited during at least some minutes of that hour.
      // Excess requests ≈ hourCount - effectiveLimit (conservative estimate,
      // since if they spread evenly they'd lose less, but if bursty they'd lose more).
      if (hourCount > effectiveLimit) {
        ipHoursHit++;
        ipHoursAffected++;
        const excess = hourCount - effectiveLimit;
        ipBlocked += excess;
        estimatedBlocked += excess;
      }
    }

    if (ipHoursHit > 0) {
      ipsAffected++;
      affected.push({
        ip,
        hoursAffected: ipHoursHit,
        peakHourCount: peak,
        avgHourCount: Math.round(sum / hourlyCounts.length),
        estimatedBlocked: Math.round(ipBlocked),
      });
    }
  }

  affected.sort((a, b) => b.estimatedBlocked - a.estimatedBlocked);

  return {
    rateLimit,
    burstMultiplier,
    effectiveLimit,
    totalIps: ipData.length,
    ipsAffected,
    ipsAffectedPct: ipData.length > 0 ? Math.round((ipsAffected / ipData.length) * 1000) / 10 : 0,
    totalIpHours,
    ipHoursAffected,
    estimatedBlockedRequests: Math.round(estimatedBlocked),
    estimatedTotalRequests: Math.round(estimatedTotal),
    blockedPct: estimatedTotal > 0 ? Math.round((estimatedBlocked / estimatedTotal) * 1000) / 10 : 0,
    affectedIps: affected.slice(0, 15),
  };
}
