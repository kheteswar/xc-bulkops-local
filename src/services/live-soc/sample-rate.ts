// =============================================================================
// Live SOC Monitoring Room — Sample Rate Compensation
// =============================================================================
// F5 XC performs rate-adaptive sampling on access logs. sample_rate can be
// 1 (no sampling) to 100+ (heavy sampling).
//
// Rules:
// - Track 2 aggregation counts are exact (server counts all logs) — no compensation.
// - Track 1 total_hits are exact — no compensation.
// - Track 3 raw logs are sampled — compensation needed for volume counts only.
// - Percentiles (latency) are statistically valid from sampled data.
// =============================================================================

import type { AccessLogEntry } from './types';

/**
 * Extracts the average sample_rate from a batch of raw access log entries.
 * Returns 1 if no entries or no sample_rate fields present (meaning no sampling).
 */
export function extractAvgSampleRate(logs: AccessLogEntry[]): number {
  if (!logs || logs.length === 0) return 1;

  let sum = 0;
  let count = 0;

  for (const log of logs) {
    // sample_rate may be on the entry directly or nested in the log object
    const rate =
      (log as Record<string, unknown>)['sample_rate'] ??
      (log as Record<string, unknown>)['sampleRate'];

    if (rate !== undefined && rate !== null) {
      const numRate = typeof rate === 'number' ? rate : Number(rate);
      if (!isNaN(numRate) && numRate > 0) {
        sum += numRate;
        count++;
      }
    }
  }

  if (count === 0) return 1;
  return Math.max(1, sum / count);
}

/**
 * Detects a sample rate surge: returns true if current average sample_rate
 * exceeds the baseline by more than 5x. A surge indicates F5 XC is seeing
 * a massive traffic spike (anomaly detector #15).
 *
 * @param current  - Current cycle's average sample rate
 * @param baseline - Baseline average sample rate
 * @returns true if current > baseline * 5
 */
export function isSampleRateSurge(current: number, baseline: number): boolean {
  // Avoid false positives when baseline is 1 (no sampling history)
  if (baseline <= 0) return false;
  if (current <= 1 && baseline <= 1) return false;

  return current > baseline * 5;
}

/**
 * Estimates the actual (unsampled) count from a sampled count.
 * For raw log volume estimates: estimated_count = sampledCount * avgSampleRate.
 *
 * Note: This should only be used for Track 3 raw log volume estimates.
 * Track 1 and Track 2 counts are already exact.
 *
 * @param sampledCount   - Number of entries in the sampled batch
 * @param avgSampleRate  - Average sample_rate from the batch
 * @returns Estimated actual count
 */
export function estimateActualCount(
  sampledCount: number,
  avgSampleRate: number
): number {
  if (sampledCount <= 0) return 0;
  const rate = Math.max(1, avgSampleRate);
  return Math.round(sampledCount * rate);
}
