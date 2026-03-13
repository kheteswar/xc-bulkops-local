import type { ClassifiedLogEntry, BurstEvent, TimeGranularity } from './types';
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

function getWindowDuration(granularity: TimeGranularity): number {
  switch (granularity) {
    case 'second': return 1;
    case 'minute': return 60;
    case 'hour': return 3600;
  }
}

/**
 * Analyzes burst patterns: finds all time windows where any user exceeded the base rate limit,
 * and recommends a burst multiplier based on P90 of spike ratios.
 */
export function analyzeBursts(
  logs: ClassifiedLogEntry[],
  baseRateLimit: number,
  granularity: TimeGranularity
): { events: BurstEvent[]; recommendedMultiplier: number; ratioP90: number } {
  if (baseRateLimit <= 0 || logs.length === 0) {
    return { events: [], recommendedMultiplier: 1, ratioP90: 1 };
  }

  // Group by user → time window → count
  const userWindows = new Map<string, Map<string, { count: number; timestamp: string }>>();

  for (const log of logs) {
    if (log.responseOrigin !== 'origin') continue;

    const userId = extractUserId(log as unknown as Record<string, unknown>);
    const ts = extractTs(log as unknown as Record<string, unknown>) || log['@timestamp'] || log.time || '';
    const windowKey = getWindowKey(ts, granularity);
    const weight = log.estimatedWeight || 1;

    if (!userWindows.has(userId)) {
      userWindows.set(userId, new Map());
    }
    const windows = userWindows.get(userId)!;
    if (!windows.has(windowKey)) {
      windows.set(windowKey, { count: 0, timestamp: ts });
    }
    const w = windows.get(windowKey)!;
    w.count += weight;
  }

  // Find all spike events (windows where rate > baseRateLimit)
  const burstEvents: BurstEvent[] = [];
  const ratios: number[] = [];
  const duration = getWindowDuration(granularity);

  for (const [userId, windows] of userWindows.entries()) {
    for (const [, data] of windows.entries()) {
      const rate = Math.ceil(data.count);
      if (rate > baseRateLimit) {
        const ratio = rate / baseRateLimit;
        ratios.push(ratio);
        burstEvents.push({
          timestamp: data.timestamp,
          userIdentifier: userId,
          rateObserved: rate,
          baseRate: baseRateLimit,
          ratio: Math.round(ratio * 100) / 100,
          durationSeconds: duration,
        });
      }
    }
  }

  // P90 of ratios
  let ratioP90 = 1;
  let recommendedMultiplier = 1;

  if (ratios.length > 0) {
    ratios.sort((a, b) => a - b);
    const idx = Math.floor(0.9 * ratios.length);
    ratioP90 = Math.round(ratios[Math.min(idx, ratios.length - 1)] * 100) / 100;
    recommendedMultiplier = Math.min(Math.ceil(ratioP90), 10); // Cap at 10
  }

  // Sort burst events by rate descending
  burstEvents.sort((a, b) => b.rateObserved - a.rateObserved);

  return { events: burstEvents.slice(0, 100), recommendedMultiplier, ratioP90 };
}
