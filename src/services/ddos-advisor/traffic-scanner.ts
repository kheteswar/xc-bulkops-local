/**
 * DDoS Advisor — Lightweight Traffic Scanner
 *
 * Instead of downloading ALL logs for the analysis period (slow, rate-limited),
 * this module uses a 3-phase approach:
 *
 *   Phase 1: PROBE — Make lightweight requests (limit=1) per hour to get total_hits.
 *            This maps traffic volume across the full duration with minimal API calls.
 *
 *   Phase 2: PEAK DETECTION — Identify the top N busiest hours from the probe data.
 *
 *   Phase 3: TARGETED FETCH — Download actual logs only from peak hours for
 *            per-second RPS analysis and traffic profiling.
 *
 * For 7 days: ~168 lightweight probes + ~3 hours of full log download
 * vs. the old approach: ~168 hours of full log download
 */

import { apiClient } from '../api';
import { AdaptiveConcurrencyController } from '../fp-analyzer/adaptive-concurrency';
import type { AdaptiveConcurrencyConfig } from '../fp-analyzer/adaptive-concurrency';
import { normalizeLogEntries } from '../rate-limit-advisor/log-collector';
import type {
  AccessLogEntry,
  AccessLogResponse,
  SecurityEventEntry,
  SecurityEventResponse,
} from '../rate-limit-advisor/types';

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

/** Probe resolution — 1 hour per probe */
const PROBE_CHUNK_HOURS = 1;
/** How many peak hours to download in detail */
const PEAK_HOURS_TO_FETCH = 3;
/** Records per scroll page when fetching peak logs */
const PAGE_SIZE = 500;
/** Max retries per API call */
const MAX_RETRIES = 4;
/** Base delay for exponential backoff (ms) */
const RETRY_BASE_MS = 2000;

/** Adaptive concurrency for lightweight probes — start conservative, ramp up slowly */
const PROBE_CONCURRENCY: Partial<AdaptiveConcurrencyConfig> = {
  initialConcurrency: 2,
  minConcurrency: 1,
  maxConcurrency: 5,
  rampUpAfterSuccesses: 8,
  rampDownFactor: 0.5,
  yellowDelayMs: 1500,
  redDelayMs: 5000,
  redCooldownMs: 15000,
};

/** Adaptive concurrency for peak log fetching */
const FETCH_CONCURRENCY: Partial<AdaptiveConcurrencyConfig> = {
  initialConcurrency: 2,
  minConcurrency: 1,
  maxConcurrency: 4,
  rampUpAfterSuccesses: 6,
  rampDownFactor: 0.5,
  yellowDelayMs: 1000,
  redDelayMs: 4000,
  redCooldownMs: 12000,
};

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

export interface HourlyVolume {
  start: string;
  end: string;
  totalHits: number;
  avgRps: number;
  label: string;
}

export interface ScanProgress {
  phase: 'scanning' | 'peak_detection' | 'fetching_peaks' | 'fetching_security' | 'analyzing' | 'complete' | 'error';
  message: string;
  progress: number; // 0-100
}

export interface ScanResult {
  hourlyVolumes: HourlyVolume[];
  peakHours: HourlyVolume[];
  peakLogs: AccessLogEntry[];
  totalRequestsEstimate: number;
  securityEventCount: number;
  securityEventSample: SecurityEventEntry[];
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

interface TimeChunk {
  start: string;
  end: string;
  label: string;
}

function isRateLimitError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  const lower = msg.toLowerCase();
  return msg.includes('429') || lower.includes('too many')
    || lower.includes('exceeds maximum rate') || lower.includes('rate limit');
}

function isTransientError(err: unknown): boolean {
  if (isRateLimitError(err)) return true;
  const msg = err instanceof Error ? err.message : String(err);
  return msg.includes('502') || msg.includes('503') || msg.includes('504');
}

async function withRetry<T>(
  fn: () => Promise<T>,
  label: string,
  controller: AdaptiveConcurrencyController
): Promise<T> {
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const paceDelay = controller.getRequestDelay();
    if (paceDelay > 0) await new Promise(r => setTimeout(r, paceDelay));

    try {
      const result = await fn();
      controller.recordSuccess();
      return result;
    } catch (err) {
      if (isRateLimitError(err)) {
        controller.recordRateLimit();
      } else {
        controller.recordError();
      }
      const msg = err instanceof Error ? err.message : String(err);
      if (!isTransientError(err) || attempt === MAX_RETRIES) throw err;
      const delay = RETRY_BASE_MS * Math.pow(2, attempt) + Math.random() * 1000;
      console.log(`[Scanner] ${label}: ${msg} — retry ${attempt + 1}/${MAX_RETRIES} in ${Math.round(delay)}ms`);
      await new Promise(r => setTimeout(r, delay));
    }
  }
  throw new Error('Unreachable');
}

function splitIntoChunks(startTime: string, endTime: string, chunkHours: number): TimeChunk[] {
  const chunks: TimeChunk[] = [];
  const start = new Date(startTime).getTime();
  const end = new Date(endTime).getTime();
  const chunkMs = chunkHours * 60 * 60 * 1000;

  let cursor = start;
  while (cursor < end) {
    const chunkEnd = Math.min(cursor + chunkMs, end);
    const d = new Date(cursor);
    const label = `${(d.getUTCMonth() + 1).toString().padStart(2, '0')}/${d.getUTCDate().toString().padStart(2, '0')} ${d.getUTCHours().toString().padStart(2, '0')}:00`;
    chunks.push({
      start: new Date(cursor).toISOString(),
      end: new Date(chunkEnd).toISOString(),
      label,
    });
    cursor = chunkEnd;
  }

  return chunks;
}

function parseTotalHits(rawHits: unknown): number {
  if (typeof rawHits === 'number' && isFinite(rawHits)) return Math.floor(rawHits);
  if (typeof rawHits === 'string') {
    const parsed = parseInt(rawHits, 10);
    return isFinite(parsed) ? parsed : 0;
  }
  if (rawHits && typeof rawHits === 'object' && 'value' in (rawHits as Record<string, unknown>)) {
    return parseInt(String((rawHits as Record<string, unknown>).value), 10) || 0;
  }
  return 0;
}

/** Adaptive pool — runs tasks with dynamic concurrency */
async function adaptivePool<T>(
  tasks: Array<() => Promise<T>>,
  controller: AdaptiveConcurrencyController,
): Promise<T[]> {
  if (tasks.length === 0) return [];

  const results: (T | undefined)[] = new Array(tasks.length);
  const taskQueue: number[] = [...Array(tasks.length).keys()];
  const chunkAttempts = new Map<number, number>();
  let completedCount = 0;
  let activeWorkerCount = 0;

  return new Promise<T[]>((resolve, reject) => {
    let settled = false;

    function finish(err?: Error) {
      if (settled) return;
      settled = true;
      controller.onStateChange = undefined;
      if (err) reject(err);
      else resolve(results as T[]);
    }

    function spawnWorkers() {
      if (settled) return;
      const maxNew = controller.concurrency - activeWorkerCount;
      let spawned = 0;
      while (spawned < maxNew && taskQueue.length > 0) {
        const idx = taskQueue.shift()!;
        activeWorkerCount++;
        spawned++;
        runTask(idx);
      }
    }

    function runTask(idx: number) {
      tasks[idx]()
        .then(result => {
          if (settled) return;
          results[idx] = result;
          completedCount++;
          activeWorkerCount--;
          if (completedCount === tasks.length) finish();
          else spawnWorkers();
        })
        .catch(err => {
          if (settled) return;
          activeWorkerCount--;
          const attempts = (chunkAttempts.get(idx) || 0) + 1;
          chunkAttempts.set(idx, attempts);
          if (attempts <= 2) {
            taskQueue.push(idx);
            spawnWorkers();
          } else {
            finish(err instanceof Error ? err : new Error(String(err)));
          }
        });
    }

    controller.onStateChange = () => spawnWorkers();
    spawnWorkers();
  });
}

// ═══════════════════════════════════════════════════════════════════
// PHASE 1: LIGHTWEIGHT VOLUME SCAN
// ═══════════════════════════════════════════════════════════════════

async function scanHourlyVolumes(
  namespace: string,
  query: string,
  startTime: string,
  endTime: string,
  onProbe: (completed: number, total: number) => void
): Promise<HourlyVolume[]> {
  const chunks = splitIntoChunks(startTime, endTime, PROBE_CHUNK_HOURS);
  const controller = new AdaptiveConcurrencyController(PROBE_CONCURRENCY);
  let completed = 0;

  const tasks = chunks.map((chunk, idx) => async (): Promise<HourlyVolume> => {
    // Stagger probe requests to avoid burst-hitting the rate limit
    // Even with adaptive concurrency, the data API needs spacing between requests
    const staggerDelay = Math.min(idx * 200, 2000);
    if (staggerDelay > 0) await new Promise(r => setTimeout(r, staggerDelay));

    const response = await withRetry(
      () => apiClient.post<AccessLogResponse>(
        `/api/data/namespaces/${namespace}/access_logs`,
        { query, namespace, start_time: chunk.start, end_time: chunk.end, scroll: false, limit: 1 }
      ),
      `probe ${chunk.label}`,
      controller
    );

    let totalHits = parseTotalHits(response.total_hits);
    // Fallback: if total_hits is 0 but logs array has entries, count them
    if (totalHits <= 0 && response.logs?.length) totalHits = response.logs.length;

    const chunkDurationSec = (new Date(chunk.end).getTime() - new Date(chunk.start).getTime()) / 1000;
    const avgRps = chunkDurationSec > 0 ? totalHits / chunkDurationSec : 0;

    completed++;
    onProbe(completed, chunks.length);

    return {
      start: chunk.start,
      end: chunk.end,
      totalHits,
      avgRps: Math.round(avgRps * 100) / 100,
      label: chunk.label,
    };
  });

  const results = await adaptivePool(tasks, controller);
  const stats = controller.getStats();
  console.log(`[Scanner] Volume scan: ${stats.totalRequests} requests, ${stats.rateLimitHits} rate-limited (${stats.rateLimitPct})`);

  return results;
}

// ═══════════════════════════════════════════════════════════════════
// PHASE 2: PEAK DETECTION
// ═══════════════════════════════════════════════════════════════════

function identifyPeakHours(volumes: HourlyVolume[], count: number): HourlyVolume[] {
  // Sort by traffic volume descending, take top N
  const sorted = [...volumes]
    .filter(v => v.totalHits > 0)
    .sort((a, b) => b.totalHits - a.totalHits);

  // Take top N, but also merge adjacent hours to capture sustained peaks
  const selected = sorted.slice(0, count);

  // Sort selected by time for better fetching
  selected.sort((a, b) => new Date(a.start).getTime() - new Date(b.start).getTime());

  return selected;
}

// ═══════════════════════════════════════════════════════════════════
// PHASE 3: TARGETED LOG FETCH (PEAK HOURS ONLY)
// ═══════════════════════════════════════════════════════════════════

async function fetchPeakLogs(
  namespace: string,
  query: string,
  peakHours: HourlyVolume[],
  onProgress: (logs: number) => void
): Promise<AccessLogEntry[]> {
  const controller = new AdaptiveConcurrencyController(FETCH_CONCURRENCY);
  let totalLogs = 0;

  const tasks = peakHours.map((hour) => async (): Promise<AccessLogEntry[]> => {
    const logs: AccessLogEntry[] = [];

    const initial = await withRetry(
      () => apiClient.post<AccessLogResponse>(
        `/api/data/namespaces/${namespace}/access_logs`,
        { query, namespace, start_time: hour.start, end_time: hour.end, scroll: true, limit: PAGE_SIZE }
      ),
      `peak-fetch ${hour.label}`,
      controller
    );

    if (initial.logs) {
      logs.push(...initial.logs);
      totalLogs += initial.logs.length;
      onProgress(totalLogs);
    }

    // Scroll remaining pages
    let scrollId = initial.scroll_id;
    while (scrollId) {
      const page = await withRetry(
        () => apiClient.post<AccessLogResponse>(
          `/api/data/namespaces/${namespace}/access_logs/scroll`,
          { scroll_id: scrollId!, namespace }
        ),
        `peak-scroll ${hour.label}`,
        controller
      );
      if (!page.logs || page.logs.length === 0) break;
      logs.push(...page.logs);
      scrollId = page.scroll_id;
      totalLogs += page.logs.length;
      onProgress(totalLogs);
    }

    return logs;
  });

  const results = await adaptivePool(tasks, controller);
  const stats = controller.getStats();
  console.log(`[Scanner] Peak fetch: ${stats.totalRequests} requests, ${stats.rateLimitHits} rate-limited`);

  // Normalize and flatten
  const rawLogs = results.flat();
  return normalizeLogEntries<AccessLogEntry>(rawLogs, 'peak-access-logs');
}

// ═══════════════════════════════════════════════════════════════════
// PHASE 4: SECURITY EVENTS QUICK PROBE
// ═══════════════════════════════════════════════════════════════════

async function probeSecurityEvents(
  namespace: string,
  query: string,
  startTime: string,
  endTime: string
): Promise<{ count: number; sample: SecurityEventEntry[] }> {
  const controller = new AdaptiveConcurrencyController({
    initialConcurrency: 1,
    minConcurrency: 1,
    maxConcurrency: 2,
  });

  try {
    const response = await withRetry(
      () => apiClient.post<SecurityEventResponse>(
        `/api/data/namespaces/${namespace}/app_security/events`,
        { query, namespace, start_time: startTime, end_time: endTime, scroll: false, limit: 50 }
      ),
      'security-probe',
      controller
    );

    const count = parseTotalHits(response.total_hits);
    const sample = response.events
      ? normalizeLogEntries<SecurityEventEntry>(response.events, 'security-sample')
      : [];

    return { count: Math.max(count, sample.length), sample };
  } catch (err) {
    console.warn('[Scanner] Security events probe failed:', err);
    return { count: 0, sample: [] };
  }
}

// ═══════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════

/**
 * Scans traffic for the DDoS Advisor using a lightweight probe-first strategy.
 *
 * 1. Probes each hour to get request volume (total_hits only)
 * 2. Identifies the top N busiest hours
 * 3. Downloads actual logs only from peak hours
 * 4. Quick-probes security events for a sample
 *
 * This is orders of magnitude faster than downloading all logs.
 */
export async function scanTraffic(
  namespace: string,
  lbName: string,
  startTime: string,
  endTime: string,
  onProgress: (p: ScanProgress) => void
): Promise<ScanResult> {
  const query = `{vh_name="ves-io-http-loadbalancer-${lbName}"}`;

  // Phase 1: Volume scan
  onProgress({ phase: 'scanning', message: 'Scanning hourly traffic volumes...', progress: 5 });

  const hourlyVolumes = await scanHourlyVolumes(namespace, query, startTime, endTime, (done, total) => {
    const pct = Math.round((done / total) * 50);
    onProgress({
      phase: 'scanning',
      message: `Scanning traffic: ${done}/${total} hours probed`,
      progress: 5 + pct,
    });
  });

  const totalRequestsEstimate = hourlyVolumes.reduce((sum, v) => sum + v.totalHits, 0);
  console.log(`[Scanner] Volume scan complete: ${totalRequestsEstimate.toLocaleString()} total requests across ${hourlyVolumes.length} hours`);

  // Phase 2: Peak detection
  onProgress({ phase: 'peak_detection', message: 'Identifying peak traffic hours...', progress: 58 });

  // Scale peak hours to fetch based on analysis duration
  const totalHours = hourlyVolumes.length;
  const peakCount = totalHours <= 24 ? 2 : totalHours <= 168 ? PEAK_HOURS_TO_FETCH : Math.min(5, Math.ceil(totalHours / 50));
  const peakHours = identifyPeakHours(hourlyVolumes, peakCount);

  const peakTotal = peakHours.reduce((sum, h) => sum + h.totalHits, 0);
  console.log(
    `[Scanner] Peak hours: ${peakHours.map(h => `${h.label} (${h.totalHits} hits)`).join(', ')} — ` +
    `${peakTotal.toLocaleString()} logs to download (${((peakTotal / Math.max(totalRequestsEstimate, 1)) * 100).toFixed(1)}% of total)`
  );

  // Phase 3: Fetch peak logs
  onProgress({
    phase: 'fetching_peaks',
    message: `Downloading ${peakCount} peak hours (~${peakTotal.toLocaleString()} logs)...`,
    progress: 60,
  });

  const expectedVhName = `ves-io-http-loadbalancer-${lbName}`;
  let peakLogs: AccessLogEntry[] = [];
  if (peakTotal > 0) {
    const rawLogs = await fetchPeakLogs(namespace, query, peakHours, (count) => {
      const pct = peakTotal > 0 ? Math.round((count / peakTotal) * 25) : 0;
      onProgress({
        phase: 'fetching_peaks',
        message: `Peak logs: ${count.toLocaleString()} / ~${peakTotal.toLocaleString()} fetched`,
        progress: 60 + pct,
      });
    });

    // Client-side filter for this LB
    peakLogs = rawLogs.filter(l => {
      const vhName = (l as Record<string, unknown>).vh_name as string | undefined;
      return !vhName || vhName === expectedVhName;
    });
  }

  // Phase 4: Security events probe
  onProgress({ phase: 'fetching_security', message: 'Probing security events...', progress: 88 });
  const securityResult = await probeSecurityEvents(namespace, query, startTime, endTime);
  // Filter security sample for this LB
  const filteredSample = securityResult.sample.filter(e => {
    const vhName = (e as Record<string, unknown>).vh_name as string | undefined;
    return !vhName || vhName === expectedVhName;
  });

  console.log(
    `[Scanner] Complete: ${totalRequestsEstimate.toLocaleString()} total requests, ` +
    `${peakLogs.length.toLocaleString()} peak logs, ${securityResult.count} security events`
  );

  onProgress({ phase: 'complete', message: 'Scan complete', progress: 95 });

  return {
    hourlyVolumes,
    peakHours,
    peakLogs,
    totalRequestsEstimate,
    securityEventCount: securityResult.count,
    securityEventSample: filteredSample,
  };
}
