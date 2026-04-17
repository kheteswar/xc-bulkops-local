/**
 * Rate Limit Advisor — Deep Mode Analyzer
 *
 * Works on full raw log data (per-user per-minute counts from every log entry).
 * Produces the same statistical analysis as funnel-analyzer (IQR trim, three
 * ceilings, guards, N+B) but with exact data instead of estimates.
 *
 * Includes a full impact simulator that replays ALL users against a proposed
 * rate limit — not just the top-N candidates.
 */

import type { RawLogCollection } from './rawlog-collector';

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

const IQR_MULTIPLIER = 3.0;
const XC_NUMBER_MAX = 8192;
const BURST_MAX = 5;
const BURST_NOOP_THRESHOLD = 1.2;
const SAFETY_FACTOR = 1.3;

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

export type ConfidenceLevel = 'high' | 'medium' | 'low';

export interface RawRecommendation {
  numberOfRequests: number;
  burstMultiplier: number;
  effectiveLimit: number;
  confidence: ConfidenceLevel;
  rationale: string;
  stats: {
    typicalCeiling: number;
    peakCeiling: number;
    absoluteCeiling: number;
    candidatesAnalyzed: number;
    outliersTrimmed: number;
  };
}

export interface RawAnalysisResult {
  lbName: string;
  namespace: string;
  startTime: string;
  endTime: string;
  windowHours: number;

  totalLogsScrolled: number;
  cleanLogs: number;
  totalUsers: number;
  usersAfterPruning: number;

  filterBreakdown: RawLogCollection['filterBreakdown'];

  recommendation: RawRecommendation;

  /** Per-user data for display and simulator */
  userPeaks: Array<{
    userId: string;
    peakRpm: number;
    medianRpm: number;
    activeMinutes: number;
    totalRequests: number;
  }>;

  warnings: string[];

  apiCallsUsed: number;
  runtimeSeconds: number;
}

export interface RawImpactResult {
  rateLimit: number;
  burstMultiplier: number;
  effectiveLimit: number;
  totalUsers: number;
  usersAffected: number;
  usersAffectedPct: number;
  totalRequestsAnalyzed: number;
  requestsBlocked: number;
  requestsBlockedPct: number;
  affectedUsers: Array<{
    userId: string;
    peakRpm: number;
    medianRpm: number;
    minutesBlocked: number;
    requestsBlocked: number;
  }>;
}

// ═══════════════════════════════════════════════════════════════════
// MATH
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
// ANALYZER
// ═══════════════════════════════════════════════════════════════════

export function analyzeRawLogs(collection: RawLogCollection): RawAnalysisResult {
  const warnings: string[] = [];

  if (collection.windowHours < 24) {
    warnings.push(`Window is ${collection.windowHours}h — shorter windows give a snapshot, not a full day's pattern. Use 24h+ for production decisions.`);
  }

  // Deep mode: include ALL clean users — no activity pruning.
  // Every user with at least 1 clean request is included in the analysis.
  const pruned = collection.userMinuteCounts;
  const usersAfterPruning = Object.keys(pruned).length;

  if (usersAfterPruning === 0) {
    warnings.push(`No users found in ${collection.cleanLogs.toLocaleString()} clean logs. Check if all traffic is being filtered out.`);
  }

  // Per-user peaks and medians
  const userPeaks: RawAnalysisResult['userPeaks'] = [];
  const allPeaks: number[] = [];
  const allMedians: number[] = [];

  for (const [userId, counts] of Object.entries(pruned)) {
    const peak = Math.max(...counts);
    const med = median(counts);
    const total = counts.reduce((s, v) => s + v, 0);
    allPeaks.push(peak);
    allMedians.push(med);
    userPeaks.push({ userId, peakRpm: peak, medianRpm: med, activeMinutes: counts.length, totalRequests: total });
  }

  allPeaks.sort((a, b) => a - b);
  allMedians.sort((a, b) => a - b);

  // 3×IQR trim on peaks
  const q1 = pct(allPeaks, 25);
  const q3 = pct(allPeaks, 75);
  const iqr = q3 - q1;
  const upperFence = q3 + IQR_MULTIPLIER * iqr;
  const trimmedPeaks = allPeaks.filter(p => p <= upperFence);
  const outliersTrimmed = allPeaks.length - trimmedPeaks.length;

  // Three ceilings
  const typicalCeiling = pct(allMedians, 95);
  const peakCeiling = Math.max(pct(trimmedPeaks, 99), 1);
  const absoluteCeiling = pct(trimmedPeaks, 99.9);

  // Bimodal detection
  const p95Peaks = pct(allPeaks, 95) || 1;
  const p99Peaks = pct(allPeaks, 99);
  if (p99Peaks / p95Peaks > 5) {
    warnings.push(`Bimodal distribution (P99/P95 = ${(p99Peaks / p95Peaks).toFixed(1)}). Consider separate policy for heavy integrations.`);
  }

  // N and B
  let sf = SAFETY_FACTOR;
  // Trend guard — simple: compare first half vs second half of user counts
  const userCountValues = Object.values(pruned).map(c => c.reduce((s, v) => s + v, 0));
  if (userCountValues.length > 10) {
    const mid = Math.floor(userCountValues.length / 2);
    const firstHalf = userCountValues.slice(0, mid).reduce((s, v) => s + v, 0);
    const secondHalf = userCountValues.slice(mid).reduce((s, v) => s + v, 0);
    if (secondHalf > firstHalf * 1.2) {
      warnings.push('Traffic appears to be growing. Safety factor bumped +0.1.');
      sf += 0.1;
    }
  }

  const n = Math.min(XC_NUMBER_MAX, Math.max(1, Math.ceil(peakCeiling * sf)));
  const burstRatio = peakCeiling > 0 ? absoluteCeiling / peakCeiling : 1;
  const b = burstRatio < BURST_NOOP_THRESHOLD ? 1 : Math.min(BURST_MAX, Math.max(1, Math.ceil(burstRatio)));

  // Confidence
  let confidence: ConfidenceLevel;
  if (collection.cleanLogs >= 100000 && usersAfterPruning >= 100 && collection.windowHours >= 168) {
    confidence = 'high';
  } else if (collection.cleanLogs >= 10000 && usersAfterPruning >= 20) {
    confidence = 'medium';
  } else {
    confidence = 'low';
  }
  if (collection.windowHours < 168 && confidence === 'high') confidence = 'medium';

  const rationale = [
    `Analysed ${collection.cleanLogs.toLocaleString()} clean requests from ${usersAfterPruning} unique users` +
    (outliersTrimmed > 0 ? ` (${outliersTrimmed} extreme outlier${outliersTrimmed > 1 ? 's' : ''} removed)` : '') + '.',

    `For each user, we measured their per-minute request counts across the full window. ` +
    `95% of users typically send ≤${typicalCeiling} req/min (their median). ` +
    `99% of users never exceed ${peakCeiling} req/min in their busiest minute. ` +
    `The rare power-user peak reaches ${absoluteCeiling} req/min (P99.9).`,

    `Rate Limit (N) = ${peakCeiling} × ${sf} safety margin = ${n} req/min. ` +
    `This means F5 XC allows each user up to ${n} requests per minute as a sustained rate. ` +
    `99% of your legitimate users will never hit this limit.`,

    `Burst Multiplier (B) = ${b}×. ` +
    (b > 1
      ? `F5 XC uses a token bucket: tokens refill at ${n}/min (the rate limit), but the bucket can hold up to ${n * b} tokens (${n} × ${b}). ` +
        `This lets a legitimate user briefly spike to ${n * b} req/min without being blocked — ` +
        `for example, a page load that fires ${n * b} API calls at once. ` +
        `However, a sustained attacker at ${Math.round(n * 1.5)} req/min will drain the bucket and get blocked within minutes. ` +
        `Without burst (B=1), that same page-load spike would be falsely blocked. ` +
        `With a higher base rate instead (${n * b}/min × 1 burst), the attacker at ${Math.round(n * 1.5)} req/min would never be caught.`
      : `Burst is 1× because the peak and absolute ceilings are close — users don't have significant short-term spikes beyond their sustained rate.`),
  ].join('\n\n');

  // Sort user peaks by peakRpm desc
  userPeaks.sort((a, b) => b.peakRpm - a.peakRpm);

  return {
    lbName: collection.lbName,
    namespace: collection.namespace,
    startTime: collection.startTime,
    endTime: collection.endTime,
    windowHours: collection.windowHours,
    totalLogsScrolled: collection.totalLogsScrolled,
    cleanLogs: collection.cleanLogs,
    totalUsers: collection.allUsers.length,
    usersAfterPruning,
    filterBreakdown: collection.filterBreakdown,
    recommendation: {
      numberOfRequests: n,
      burstMultiplier: b,
      effectiveLimit: n * b,
      confidence,
      rationale,
      stats: { typicalCeiling, peakCeiling, absoluteCeiling, candidatesAnalyzed: usersAfterPruning, outliersTrimmed },
    },
    userPeaks,
    warnings,
    apiCallsUsed: collection.apiCallsUsed,
    runtimeSeconds: Math.round(collection.runtimeMs / 100) / 10,
  };
}

// ═══════════════════════════════════════════════════════════════════
// IMPACT SIMULATOR — replays ALL users
// ═══════════════════════════════════════════════════════════════════

/**
 * Simulates impact of a proposed rate limit against the full per-user
 * per-minute data. Shows every affected user with exact blocked minutes
 * and request counts.
 */
export function simulateRawImpact(
  _result: RawAnalysisResult,
  userMinuteCounts: Record<string, number[]>,
  rateLimit: number,
  burstMultiplier: number,
): RawImpactResult {
  const effectiveLimit = rateLimit * burstMultiplier;
  const affected: RawImpactResult['affectedUsers'] = [];
  let totalRequests = 0;
  let totalBlocked = 0;

  for (const [userId, counts] of Object.entries(userMinuteCounts)) {
    let userBlocked = 0;
    let minutesBlocked = 0;

    for (const count of counts) {
      totalRequests += count;
      if (count > effectiveLimit) {
        const excess = count - effectiveLimit;
        userBlocked += excess;
        totalBlocked += excess;
        minutesBlocked++;
      }
    }

    if (userBlocked > 0) {
      const peak = Math.max(...counts);
      const med = median(counts);
      affected.push({ userId, peakRpm: peak, medianRpm: med, minutesBlocked, requestsBlocked: userBlocked });
    }
  }

  affected.sort((a, b) => b.requestsBlocked - a.requestsBlocked);

  const totalUsers = Object.keys(userMinuteCounts).length;

  return {
    rateLimit,
    burstMultiplier,
    effectiveLimit,
    totalUsers,
    usersAffected: affected.length,
    usersAffectedPct: totalUsers > 0 ? Math.round((affected.length / totalUsers) * 1000) / 10 : 0,
    totalRequestsAnalyzed: totalRequests,
    requestsBlocked: totalBlocked,
    requestsBlockedPct: totalRequests > 0 ? Math.round((totalBlocked / totalRequests) * 1000) / 10 : 0,
    affectedUsers: affected,
  };
}
