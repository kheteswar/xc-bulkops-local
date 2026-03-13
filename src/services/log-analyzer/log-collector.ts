import { apiClient } from '../api';
import { AdaptiveConcurrencyController } from '../fp-analyzer/adaptive-concurrency';
import type { AdaptiveConcurrencyConfig } from '../fp-analyzer/adaptive-concurrency';
import { normalizeLogEntries } from '../rate-limit-advisor/log-collector';
import type { AccessLogEntry, AccessLogResponse } from '../rate-limit-advisor/types';
import type { QueryFilter, LogCollectionProgress } from './types';

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

const CHUNK_HOURS = 4;
const PAGE_SIZE = 500;
const MAX_RETRIES = 4;
const RETRY_BASE_MS = 2000;
const MAX_CHUNK_RETRIES = 2;

const ADAPTIVE_CONFIG: Partial<AdaptiveConcurrencyConfig> = {
  initialConcurrency: 3,
  minConcurrency: 1,
  maxConcurrency: 10,
  rampUpAfterSuccesses: 5,
  rampDownFactor: 0.5,
  yellowDelayMs: 300,
  redDelayMs: 3000,
  redCooldownMs: 8000,
};

// ═══════════════════════════════════════════════════════════════════
// QUERY BUILDER
// ═══════════════════════════════════════════════════════════════════

export function buildQuery(filters: QueryFilter[]): string {
  if (filters.length === 0) return '{}';
  const parts = filters.map(f => `${f.field}="${f.value}"`);
  return `{${parts.join(',')}}`;
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS (adapted from rate-limit-advisor/log-collector.ts)
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

async function withAdaptiveRetry<T>(
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

      if (!isTransientError(err) || attempt === MAX_RETRIES) throw err;

      const delay = RETRY_BASE_MS * Math.pow(2, attempt) + Math.random() * 1000;
      console.log(
        `[LogAnalyzer] ${label}: retry ${attempt + 1}/${MAX_RETRIES} in ${Math.round(delay)}ms ` +
        `[${controller.getState()} x${controller.concurrency}]`
      );
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
    chunks.push({ start: new Date(cursor).toISOString(), end: new Date(chunkEnd).toISOString(), label });
    cursor = chunkEnd;
  }

  return chunks;
}

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
          if (attempts <= MAX_CHUNK_RETRIES) {
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
// CHUNK FETCHER
// ═══════════════════════════════════════════════════════════════════

async function fetchChunk(
  namespace: string,
  query: string,
  chunk: TimeChunk,
  controller: AdaptiveConcurrencyController,
  onBatch: (batchSize: number) => void,
  onTotalKnown: (totalHits: number) => void
): Promise<AccessLogEntry[]> {
  const logs: AccessLogEntry[] = [];

  const initial = await withAdaptiveRetry(
    () => apiClient.post<AccessLogResponse>(
      `/api/data/namespaces/${namespace}/access_logs`,
      { query, namespace, start_time: chunk.start, end_time: chunk.end, scroll: true, limit: PAGE_SIZE }
    ),
    `chunk ${chunk.label}`,
    controller
  );

  const rawHits = initial.total_hits;
  let totalHits = 0;
  if (typeof rawHits === 'number' && isFinite(rawHits)) {
    totalHits = Math.floor(rawHits);
  } else if (typeof rawHits === 'string') {
    totalHits = parseInt(rawHits, 10);
    if (!isFinite(totalHits)) totalHits = 0;
  } else if (rawHits && typeof rawHits === 'object' && 'value' in (rawHits as Record<string, unknown>)) {
    totalHits = parseInt(String((rawHits as Record<string, unknown>).value), 10) || 0;
  }
  if (totalHits <= 0) totalHits = initial.logs?.length || 0;

  onTotalKnown(totalHits);

  if (initial.logs) {
    logs.push(...initial.logs);
    onBatch(initial.logs.length);
  }

  let scrollId = initial.scroll_id;
  while (scrollId) {
    const page = await withAdaptiveRetry(
      () => apiClient.post<AccessLogResponse>(
        `/api/data/namespaces/${namespace}/access_logs/scroll`,
        { scroll_id: scrollId!, namespace }
      ),
      `scroll ${chunk.label}`,
      controller
    );
    if (!page.logs || page.logs.length === 0) break;
    logs.push(...page.logs);
    scrollId = page.scroll_id;
    onBatch(page.logs.length);
  }

  return logs;
}

// ═══════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════

/**
 * Probe logs — fetch a small sample to discover available field values.
 */
export async function probeLogs(
  namespace: string,
  query: string,
  startTime: string,
  endTime: string,
  limit: number = 50,
): Promise<{ logs: AccessLogEntry[]; totalHits: number }> {
  const raw = await apiClient.post<AccessLogResponse>(
    `/api/data/namespaces/${namespace}/access_logs`,
    { query, namespace, start_time: startTime, end_time: endTime, scroll: false, limit }
  );

  const rawHits = raw.total_hits;
  let totalHits = 0;
  if (typeof rawHits === 'number' && isFinite(rawHits)) totalHits = Math.floor(rawHits);
  else if (typeof rawHits === 'string') totalHits = parseInt(rawHits, 10) || 0;
  else if (rawHits && typeof rawHits === 'object' && 'value' in (rawHits as Record<string, unknown>)) {
    totalHits = parseInt(String((rawHits as Record<string, unknown>).value), 10) || 0;
  }

  const logs = raw.logs ? normalizeLogEntries<AccessLogEntry>(raw.logs, 'probe') : [];
  return { logs, totalHits };
}

/**
 * Collect all access logs matching the query with adaptive concurrency.
 */
export async function collectLogs(
  namespace: string,
  query: string,
  startTime: string,
  endTime: string,
  onProgress: (p: LogCollectionProgress) => void,
): Promise<AccessLogEntry[]> {
  const chunks = splitIntoChunks(startTime, endTime, CHUNK_HOURS);
  const controller = new AdaptiveConcurrencyController(ADAPTIVE_CONFIG);

  let collected = 0;
  let grandTotal = 0;

  onProgress({
    phase: 'fetching',
    message: `Fetching access logs — ${chunks.length} streams...`,
    progress: 3,
    logsCollected: 0,
    estimatedTotal: 0,
  });

  const updateProgress = () => {
    const pct = grandTotal > 0 ? Math.round((collected / grandTotal) * 100) : 0;
    const barProgress = grandTotal > 0 ? Math.min(3 + Math.round((collected / grandTotal) * 90), 93) : 3;
    const stats = controller.getStats();
    const rateLimitLabel = stats.rateLimitHits > 0 ? ` | ${stats.rateLimitHits} rate-limited` : '';
    onProgress({
      phase: 'fetching',
      message: `Fetching — ${collected.toLocaleString()}${grandTotal > 0 ? ` / ${grandTotal.toLocaleString()}` : ''} (${pct}%) x${stats.concurrency}${rateLimitLabel}`,
      progress: barProgress,
      logsCollected: collected,
      estimatedTotal: grandTotal,
    });
  };

  const tasks = chunks.map((chunk) => () =>
    fetchChunk(
      namespace, query, chunk, controller,
      (batchSize) => { collected += batchSize; updateProgress(); },
      (totalHits) => { grandTotal += totalHits; updateProgress(); }
    )
  );

  const chunkResults = await adaptivePool(tasks, controller);
  const rawLogs = chunkResults.flat();
  const normalized = normalizeLogEntries<AccessLogEntry>(rawLogs, 'log-analyzer');

  const stats = controller.getStats();
  onProgress({
    phase: 'complete',
    message: `Complete: ${normalized.length.toLocaleString()} logs (${stats.totalRequests} API calls, ${stats.rateLimitHits} rate-limited)`,
    progress: 100,
    logsCollected: normalized.length,
    estimatedTotal: normalized.length,
  });

  return normalized;
}
