import { normalizePath } from '../rate-limit-advisor/path-analyzer';
import type { AccessLogEntry } from '../rate-limit-advisor/types';
import type { PathStats } from './types';

// ═══════════════════════════════════════════════════════════════
// USER COUNTER — exact Set up to threshold, then approximate
// ═══════════════════════════════════════════════════════════════

export class UserCounter {
  private exact: Set<string> | null = new Set();
  private approximate = 0;
  private readonly THRESHOLD = 10000;

  add(userId: string): void {
    if (this.exact) {
      this.exact.add(userId);
      if (this.exact.size > this.THRESHOLD) {
        this.approximate = this.exact.size;
        this.exact = null;
      }
    } else {
      this.approximate++;
    }
  }

  has(userId: string): boolean {
    return this.exact ? this.exact.has(userId) : false;
  }

  get count(): number {
    return this.exact ? this.exact.size : this.approximate;
  }
}

function createPathStats(): PathStats {
  return {
    totalRequests: 0,
    totalUsers: 0,
    flaggedRequests: 0,
    flaggedUsers: 0,
    userAgents: new Map(),
    countries: new Map(),
    rspCodes: new Map(),
    methods: new Map(),
    timestampSamples: [],
  };
}

function incMap(map: Map<string, number>, key: string): void {
  map.set(key, (map.get(key) || 0) + 1);
}

/**
 * Process a batch of access logs into streaming aggregation stats.
 * Called for each batch of ~500 logs during scroll pagination.
 * Does NOT store full log entries — only aggregates.
 */
export function aggregateBatch(
  batch: AccessLogEntry[],
  pathStats: Map<string, PathStats>,
  userCounters: Map<string, UserCounter>,
  flaggedUserCounters: Map<string, UserCounter>,
  reqIdSet: Set<string>,
  sampleEveryN: number = 100
): void {
  for (const log of batch) {
    const rawPath = (log as Record<string, unknown>).req_path as string | undefined;
    const path = normalizePath(rawPath);

    if (!pathStats.has(path)) {
      pathStats.set(path, createPathStats());
      userCounters.set(path, new UserCounter());
      flaggedUserCounters.set(path, new UserCounter());
    }

    const stats = pathStats.get(path)!;
    const counter = userCounters.get(path)!;
    const flaggedCounter = flaggedUserCounters.get(path)!;

    const weight = 1 / ((log.sample_rate as number) || 1);
    stats.totalRequests += weight;

    const userId = (log as Record<string, unknown>).user as string
      || (log as Record<string, unknown>).src_ip as string
      || 'unknown';
    counter.add(userId);

    const reqId = (log as Record<string, unknown>).req_id as string;
    if (reqId && reqIdSet.has(reqId)) {
      stats.flaggedRequests += weight;
      flaggedCounter.add(userId);
    }

    const ua = ((log as Record<string, unknown>).user_agent as string) || 'unknown';
    incMap(stats.userAgents, ua);

    const country = ((log as Record<string, unknown>).country as string) || 'unknown';
    incMap(stats.countries, country);

    const rspCode = ((log as Record<string, unknown>).rsp_code as string) || '0';
    incMap(stats.rspCodes, rspCode);

    const method = ((log as Record<string, unknown>).method as string) || 'GET';
    incMap(stats.methods, method);

    // Temporal sampling — keep every Nth timestamp
    if (stats.totalRequests % sampleEveryN < weight && stats.timestampSamples.length < 5000) {
      const ts = ((log as Record<string, unknown>)['@timestamp'] as string)
        || ((log as Record<string, unknown>).time as string)
        || '';
      if (ts) stats.timestampSamples.push(ts);
    }
  }
}

/**
 * Finalize aggregation: convert UserCounter counts into PathStats fields.
 */
export function finalizeAggregation(
  pathStats: Map<string, PathStats>,
  userCounters: Map<string, UserCounter>,
  flaggedUserCounters: Map<string, UserCounter>
): void {
  for (const [path, stats] of pathStats) {
    const counter = userCounters.get(path);
    if (counter) stats.totalUsers = counter.count;
    const flaggedCounter = flaggedUserCounters.get(path);
    if (flaggedCounter) stats.flaggedUsers = flaggedCounter.count;
  }
}
