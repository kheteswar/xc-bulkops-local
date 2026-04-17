/**
 * Rate Limit Advisor — Funnel-based statistical analyzer
 *
 * Stage 6 — Statistical analysis:
 *   - Prune low-activity candidates
 *   - Compute per-user peak and median RPM
 *   - 3×IQR outlier trim on peaks
 *   - Three ceilings: typical (P95 medians), peak (P99 trimmed peaks), absolute (P99.9)
 *   - Guards: seasonality, trend, bimodal, sample-size, short-window
 *   - Final N = ceil(peak_ceiling × safety_factor), B = ceil(absolute/peak)
 *
 * Stage 7 — Per-domain vs LB-wide decision
 */

import type { FunnelCollection } from './funnel-collector';

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

const MIN_ACTIVE_MINUTES = 5;
const MIN_REQUESTS_PER_USER = 10;
const IQR_MULTIPLIER = 3.0;
const XC_NUMBER_MAX = 8192;
const BURST_MIN = 1;
const BURST_MAX = 5;
const BURST_NOOP_THRESHOLD = 1.2;

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

export type ConfidenceLevel = 'high' | 'medium' | 'low';

export interface Recommendation {
  scope: string; // 'lb' or domain name
  numberOfRequests: number; // N
  burstMultiplier: number;  // B
  effectiveLimit: number;   // N × B
  confidence: ConfidenceLevel;
  rationale: string;
  stats: {
    typicalCeiling: number;  // P95 of per-user medians
    peakCeiling: number;     // P99 of trimmed peaks
    absoluteCeiling: number; // P99.9 of trimmed peaks
    candidatesAnalyzed: number;
    outliersTrimmed: number;
  };
}

export interface FunnelResult {
  lbName: string;
  namespace: string;
  domains: string[];
  windowStart: string;
  windowEnd: string;
  windowDays: number;
  apiCallsUsed: number;
  runtimeSeconds: number;

  // Traffic
  totalRequests: number;       // clean + filtered
  cleanRequests: number;
  filterBreakdown: FunnelCollection['filterBreakdown'];

  // Funnel
  peakHoursAnalyzed: number;
  candidatesIdentified: number;
  candidatesAfterPruning: number;

  // Per-user data (for impact simulator)
  userPeaks: Array<{ userId: string; peakRpm: number; medianRpm: number; activeMinutes: number }>;
  trimmedPeaks: number[];  // sorted, after IQR trim

  // Recommendations
  lbRecommendation: Recommendation;
  domainRecommendations: Recommendation[];

  // Warnings & guards
  warnings: string[];

  // Daily shape for display
  dailyShape: Array<{ dayStart: string; count: number }>;
}

export interface ImpactResult {
  rateLimit: number;
  burstMultiplier: number;
  effectiveLimit: number;
  totalUsers: number;
  usersAffected: number;
  usersAffectedPct: number;
  affectedUsers: Array<{
    userId: string;
    peakRpm: number;
    medianRpm: number;
    activeMinutes: number;
  }>;
}

// ═══════════════════════════════════════════════════════════════════
// MATH HELPERS
// ═══════════════════════════════════════════════════════════════════

function pct(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const k = Math.max(0, Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[k];
}

function median(arr: number[]): number {
  if (arr.length === 0) return 0;
  const s = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 === 0 ? (s[mid - 1] + s[mid]) / 2 : s[mid];
}

// ═══════════════════════════════════════════════════════════════════
// MAIN ANALYZER
// ═══════════════════════════════════════════════════════════════════

export function analyzeFunnel(
  collection: FunnelCollection,
  safetyFactor: number = 1.3,
): FunnelResult {
  const warnings: string[] = [];

  if (collection.windowDays < 7) {
    warnings.push(
      `Window is ${collection.windowDays} day(s). Cannot capture weekly seasonality. Confidence capped at 'medium'.`
    );
  }

  // ────────────────────────────────────────────────────────────────
  // STAGE 6 — Statistical analysis
  // ────────────────────────────────────────────────────────────────

  // 6a — Prune low-activity candidates
  const pruned: Record<string, number[]> = {};
  for (const [userId, counts] of Object.entries(collection.userMinuteCounts)) {
    const totalReqs = counts.reduce((s, v) => s + v, 0);
    if (counts.length >= MIN_ACTIVE_MINUTES && totalReqs >= MIN_REQUESTS_PER_USER) {
      pruned[userId] = counts;
    }
  }
  const candidatesAfterPruning = Object.keys(pruned).length;

  if (collection.totalRequests < 10000) {
    warnings.push(
      `Only ${collection.totalRequests.toLocaleString()} clean requests in window (need ≥10,000). Recommendation may be unreliable.`
    );
  }

  if (candidatesAfterPruning < 10) {
    warnings.push(
      `Only ${candidatesAfterPruning} candidates passed activity filter. Low sample — recommendation is approximate.`
    );
  }

  // 6b — Per-user statistics
  const userPeaks: FunnelResult['userPeaks'] = [];
  const allPeaks: number[] = [];
  const allMedians: number[] = [];

  for (const [userId, counts] of Object.entries(pruned)) {
    const peak = Math.max(...counts);
    const med = median(counts);
    allPeaks.push(peak);
    allMedians.push(med);
    userPeaks.push({ userId, peakRpm: peak, medianRpm: med, activeMinutes: counts.length });
  }

  allPeaks.sort((a, b) => a - b);
  allMedians.sort((a, b) => a - b);

  // 6c — 3×IQR outlier trim on peaks
  const q1 = pct(allPeaks, 25);
  const q3 = pct(allPeaks, 75);
  const iqr = q3 - q1;
  const upperFence = q3 + IQR_MULTIPLIER * iqr;
  const trimmedPeaks = allPeaks.filter(p => p <= upperFence);
  const outliersTrimmed = allPeaks.length - trimmedPeaks.length;

  if (outliersTrimmed > 0) {
    console.log(`[FunnelAnalyzer] IQR trim: Q1=${q1}, Q3=${q3}, IQR=${iqr}, fence=${upperFence}, trimmed ${outliersTrimmed} outliers`);
  }

  // 6d — Three ceilings
  const typicalCeiling = pct(allMedians, 95);
  const peakCeiling = Math.max(pct(trimmedPeaks, 99), 1);
  const absoluteCeiling = pct(trimmedPeaks, 99.9);

  // 6e — Guards
  seasonalityGuard(collection.dailyShape, warnings);
  safetyFactor = trendGuard(collection.dailyShape, safetyFactor, warnings);

  // Bimodal detection
  const p95Peaks = pct(allPeaks, 95) || 1;
  const p99Peaks = pct(allPeaks, 99);
  if (p99Peaks / p95Peaks > 5) {
    warnings.push(
      `Bimodal distribution detected (P99/P95 = ${(p99Peaks / p95Peaks).toFixed(1)}). ` +
      `Consider separate rate limiter policy for heavy backend integrations.`
    );
  }

  // 6f — Final N and B
  const n = Math.min(XC_NUMBER_MAX, Math.max(1, Math.ceil(peakCeiling * safetyFactor)));

  const burstRatio = peakCeiling > 0 ? absoluteCeiling / peakCeiling : 1;
  const b = burstRatio < BURST_NOOP_THRESHOLD
    ? BURST_MIN
    : Math.min(BURST_MAX, Math.max(BURST_MIN, Math.ceil(burstRatio)));

  // 6g — Confidence
  let confidence: ConfidenceLevel;
  if (collection.totalRequests >= 100000 && candidatesAfterPruning >= 100 && collection.windowDays >= 7) {
    confidence = 'high';
  } else if (collection.totalRequests >= 10000 && candidatesAfterPruning >= 10) {
    confidence = 'medium';
  } else {
    confidence = 'low';
  }
  if (collection.windowDays < 7 && confidence === 'high') confidence = 'medium';

  const rationale = [
    `Analysed ${candidatesAfterPruning} candidate users from ${collection.totalRequests.toLocaleString()} requests (${collection.windowDays}-day window)` +
    (outliersTrimmed > 0 ? `. ${outliersTrimmed} extreme outlier${outliersTrimmed > 1 ? 's' : ''} removed.` : '.'),

    `95% of users typically send ≤${typicalCeiling} req/min. ` +
    `99% never exceed ${peakCeiling} req/min in their busiest minute. ` +
    `Rare power-user peak: ${absoluteCeiling} req/min.`,

    `Rate Limit (N) = ${peakCeiling} × ${safetyFactor} safety = ${n} req/min — 99% of legitimate users will never hit this.`,

    b > 1
      ? `Burst (B) = ${b}×. The token bucket holds up to ${n * b} tokens (${n} × ${b}), allowing brief spikes to ${n * b} req/min. ` +
        `A sustained attacker above ${n} req/min will still be blocked within minutes as the bucket drains faster than it refills.`
      : `Burst (B) = 1× — peaks and sustained rates are similar, no burst headroom needed.`,
  ].join('\n\n');

  const lbRecommendation: Recommendation = {
    scope: 'lb',
    numberOfRequests: n,
    burstMultiplier: b,
    effectiveLimit: n * b,
    confidence,
    rationale,
    stats: {
      typicalCeiling,
      peakCeiling,
      absoluteCeiling,
      candidatesAnalyzed: candidatesAfterPruning,
      outliersTrimmed,
    },
  };

  // ────────────────────────────────────────────────────────────────
  // STAGE 7 — Per-domain vs LB-wide (stub — future enhancement)
  // ────────────────────────────────────────────────────────────────
  const domainRecommendations: Recommendation[] = [];
  // Per-domain analysis would go here for LBs with divergent domain traffic shapes.

  return {
    lbName: collection.lbName,
    namespace: collection.namespace,
    domains: collection.domains,
    windowStart: collection.startTime,
    windowEnd: collection.endTime,
    windowDays: collection.windowDays,
    apiCallsUsed: collection.apiCallsUsed,
    runtimeSeconds: Math.round(collection.runtimeMs / 100) / 10,
    totalRequests: collection.totalRequests,
    cleanRequests: collection.totalRequests - collection.filterBreakdown.total,
    filterBreakdown: collection.filterBreakdown,
    peakHoursAnalyzed: collection.peakDays.length,
    candidatesIdentified: collection.candidateUsers.length,
    candidatesAfterPruning,
    userPeaks,
    trimmedPeaks,
    lbRecommendation,
    domainRecommendations,
    warnings,
    dailyShape: collection.dailyShape,
  };
}

// ═══════════════════════════════════════════════════════════════════
// GUARDS
// ═══════════════════════════════════════════════════════════════════

function seasonalityGuard(daily: Array<{ dayStart: string; count: number }>, warnings: string[]) {
  const weekday: number[] = [];
  const weekend: number[] = [];
  for (const { dayStart, count } of daily) {
    try {
      const d = new Date(dayStart);
      const dow = d.getUTCDay();
      (dow >= 1 && dow <= 5 ? weekday : weekend).push(count);
    } catch { /* ignore */ }
  }
  if (!weekday.length || !weekend.length) return;
  const wdAvg = weekday.reduce((s, v) => s + v, 0) / weekday.length;
  const weAvg = weekend.reduce((s, v) => s + v, 0) / weekend.length;
  const ratio = wdAvg / Math.max(weAvg, 1);
  if (ratio > 3 || ratio < 0.33) {
    warnings.push(
      `Strong weekday/weekend difference (ratio ${ratio.toFixed(1)}×). Ensure window covers full business weeks.`
    );
  }
}

function trendGuard(daily: Array<{ dayStart: string; count: number }>, safetyFactor: number, warnings: string[]): number {
  if (daily.length < 3) return safetyFactor;
  const sorted = [...daily].sort((a, b) => a.dayStart.localeCompare(b.dayStart));
  const ys = sorted.map(d => d.count);
  const n = ys.length;
  const xs = Array.from({ length: n }, (_, i) => i);
  const mx = xs.reduce((s, v) => s + v, 0) / n;
  const my = ys.reduce((s, v) => s + v, 0) / n;
  const denom = xs.reduce((s, x) => s + (x - mx) ** 2, 0) || 1;
  const slope = xs.reduce((s, x, i) => s + (x - mx) * (ys[i] - my), 0) / denom;
  const growth = (slope * (n - 1)) / (ys[0] || 1);

  if (growth > 0.2) {
    warnings.push(`Traffic growing ~${Math.round(growth * 100)}% over window. Safety factor bumped +0.1.`);
    return safetyFactor + 0.1;
  }
  if (growth < -0.2) {
    warnings.push(`Traffic declining ~${Math.round(Math.abs(growth) * 100)}% over window. Recommendation may be conservative.`);
  }
  return safetyFactor;
}

// ═══════════════════════════════════════════════════════════════════
// IMPACT SIMULATOR
// ═══════════════════════════════════════════════════════════════════

/**
 * Simulates impact of a proposed rate limit against per-user peak data.
 * Runs instantly — designed for slider interaction.
 */
export function simulateFunnelImpact(
  result: FunnelResult,
  rateLimit: number,
  burstMultiplier: number,
): ImpactResult {
  const effectiveLimit = rateLimit * burstMultiplier;
  const affected: ImpactResult['affectedUsers'] = [];

  for (const user of result.userPeaks) {
    if (user.peakRpm > effectiveLimit) {
      affected.push(user);
    }
  }

  affected.sort((a, b) => b.peakRpm - a.peakRpm);

  return {
    rateLimit,
    burstMultiplier,
    effectiveLimit,
    totalUsers: result.userPeaks.length,
    usersAffected: affected.length,
    usersAffectedPct: result.userPeaks.length > 0
      ? Math.round((affected.length / result.userPeaks.length) * 1000) / 10
      : 0,
    affectedUsers: affected,
  };
}
