import { apiClient } from '../api';
import { AdaptiveConcurrencyController } from '../fp-analyzer/adaptive-concurrency';
import type { AdaptiveConcurrencyConfig } from '../fp-analyzer/adaptive-concurrency';
import type {
  AccessLogEntry,
  AccessLogResponse,
  SecurityEventEntry,
  SecurityEventResponse,
  CollectionProgress,
} from './types';

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

/** Hours per chunk — smaller = more parallel streams = faster */
const CHUNK_HOURS = 4;
/** Use larger chunks for security events to reduce total request count */
const SEC_CHUNK_HOURS = 12;
/** Records per scroll page — API max is 500 */
const PAGE_SIZE = 500;
/** Max retries on 429 / transient errors per API call */
const MAX_RETRIES = 4;
/** Base delay for exponential backoff (ms) */
const RETRY_BASE_MS = 2000;
/** Max times to re-queue a completely failed chunk before giving up */
const MAX_CHUNK_RETRIES = 2;

/** Adaptive concurrency for access logs — starts moderate, ramps up quickly */
const ACCESS_LOG_ADAPTIVE: Partial<AdaptiveConcurrencyConfig> = {
  initialConcurrency: 3,
  minConcurrency: 1,
  maxConcurrency: 10,
  rampUpAfterSuccesses: 5,
  rampDownFactor: 0.5,
  yellowDelayMs: 300,
  redDelayMs: 3000,
  redCooldownMs: 8000,
};

/** Adaptive concurrency for security events — starts conservative (stricter rate limits) */
const SECURITY_EVENT_ADAPTIVE: Partial<AdaptiveConcurrencyConfig> = {
  initialConcurrency: 1,
  minConcurrency: 1,
  maxConcurrency: 4,
  rampUpAfterSuccesses: 8,
  rampDownFactor: 0.5,
  yellowDelayMs: 1000,
  redDelayMs: 5000,
  redCooldownMs: 15000,
};

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

interface TimeChunk {
  start: string;
  end: string;
  label: string;
}

/** Detect if an error is a rate limit (429) */
function isRateLimitError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  const lower = msg.toLowerCase();
  return msg.includes('429') || lower.includes('too many')
    || lower.includes('exceeds maximum rate') || lower.includes('rate limit');
}

/** Detect if an error is transient (retryable) */
function isTransientError(err: unknown): boolean {
  if (isRateLimitError(err)) return true;
  const msg = err instanceof Error ? err.message : String(err);
  return msg.includes('502') || msg.includes('503') || msg.includes('504');
}

/**
 * Retry wrapper with adaptive concurrency signaling.
 * On success → signals controller to potentially ramp up.
 * On 429 → signals controller to reduce concurrency for ALL workers.
 * Respects controller's pacing delay before each attempt.
 */
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

      const msg = err instanceof Error ? err.message : String(err);
      if (!isTransientError(err) || attempt === MAX_RETRIES) throw err;

      const delay = RETRY_BASE_MS * Math.pow(2, attempt) + Math.random() * 1000;
      console.log(
        `[LogCollector] ${label}: ${msg} — retry ${attempt + 1}/${MAX_RETRIES} in ${Math.round(delay)}ms ` +
        `[${controller.getState()} ×${controller.concurrency}]`
      );
      await new Promise(r => setTimeout(r, delay));
    }
  }
  throw new Error('Unreachable');
}

/** Split a time range into N-hour chunks */
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

/**
 * Adaptive concurrency pool — dynamically adjusts worker count based on
 * rate limit feedback from the shared controller. Failed chunks are
 * re-queued (up to MAX_CHUNK_RETRIES) to prevent data loss.
 *
 * When a 429 is detected (inside withAdaptiveRetry), the controller
 * reduces concurrency and this pool reacts by not spawning new workers
 * until existing ones finish. When successes accumulate, concurrency
 * ramps back up and the onStateChange callback spawns new workers.
 */
async function adaptivePool<T>(
  tasks: Array<() => Promise<T>>,
  controller: AdaptiveConcurrencyController,
  onAdaptiveUpdate?: (concurrency: number, state: string) => void
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

          if (completedCount === tasks.length) {
            finish();
          } else {
            spawnWorkers();
          }
        })
        .catch(err => {
          if (settled) return;
          activeWorkerCount--;

          const attempts = (chunkAttempts.get(idx) || 0) + 1;
          chunkAttempts.set(idx, attempts);

          if (attempts <= MAX_CHUNK_RETRIES) {
            console.warn(
              `[AdaptivePool] Chunk ${idx} failed (attempt ${attempts}/${MAX_CHUNK_RETRIES + 1}), re-queuing`
            );
            taskQueue.push(idx);
            spawnWorkers();
          } else {
            console.error(`[AdaptivePool] Chunk ${idx} permanently failed after ${attempts} attempts`);
            finish(err instanceof Error ? err : new Error(String(err)));
          }
        });
    }

    // React to concurrency changes — spawn new workers when capacity increases
    controller.onStateChange = (state, concurrency) => {
      onAdaptiveUpdate?.(concurrency, state);
      spawnWorkers();
    };

    spawnWorkers();
  });
}

/** F5 XC data-layer fields — present on actual log data, NOT on wrapper metadata */
const F5_DATA_FIELDS = ['rsp_code', 'rsp_code_details', 'src_ip', 'vh_name', 'req_path', 'waf_action', 'sample_rate'];

/** Check if an object contains at least 2 F5-specific data fields */
function hasF5DataFields(obj: Record<string, unknown>): boolean {
  let matchCount = 0;
  for (const field of F5_DATA_FIELDS) {
    if (obj[field] !== undefined && obj[field] !== null) matchCount++;
  }
  return matchCount >= 2;
}

/**
 * Normalize raw API response entries into our expected shape.
 *
 * The F5 XC API may return entries in various formats:
 *   - Flat objects with all fields at top level
 *   - Wrapped in _source (Elasticsearch)
 *   - With top-level metadata (id, time, stream) and data nested under attributes/data/log
 *
 * We detect the correct structure by checking for F5-SPECIFIC DATA FIELDS
 * (not just a timestamp) to avoid short-circuiting on wrapper metadata.
 */
export function normalizeLogEntries<T>(rawEntries: unknown[], logType: string): T[] {
  if (rawEntries.length === 0) return [];

  // ═══════════════════════════════════════════════════════════════
  // CRITICAL: F5 XC API returns log entries as JSON STRINGS, not objects.
  // Each entry in the logs/events array is a serialized JSON string
  // that must be parsed before field access will work.
  // ═══════════════════════════════════════════════════════════════
  let entries = rawEntries;
  if (typeof entries[0] === 'string') {
    console.log(`[LogCollector] ${logType}: Entries are JSON strings — parsing ${entries.length} entries...`);
    entries = entries.map((e, i) => {
      try {
        return JSON.parse(e as string);
      } catch (err) {
        if (i < 3) console.warn(`[LogCollector] ${logType}: Failed to parse entry ${i}:`, (e as string).slice(0, 200));
        return {};
      }
    });
    console.log(`[LogCollector] ${logType}: Parsed ${entries.length} JSON string entries into objects`);
  }

  const sample = entries[0] as Record<string, unknown>;

  // ═══════════════════════════════════════════════════════════════
  // DIAGNOSTIC: Raw API response structure analysis
  // ═══════════════════════════════════════════════════════════════
  console.group(`[DIAG-Normalize] ${logType}: ${entries.length} entries (were strings: ${typeof rawEntries[0] === 'string'})`);
  console.log('Top-level keys:', Object.keys(sample).sort().join(', '));

  // Check each F5 data field at top level
  console.group('F5 data field check at top level:');
  let topLevelHits = 0;
  for (const field of F5_DATA_FIELDS) {
    const val = sample[field];
    const present = val !== undefined && val !== null;
    if (present) topLevelHits++;
    console.log(`  ${field}: ${present ? `FOUND — value=${JSON.stringify(val)} type=${typeof val}` : 'MISSING'}`);
  }
  console.log(`  => ${topLevelHits}/${F5_DATA_FIELDS.length} found (need ≥2 for match)`);
  console.groupEnd();

  // Dump all field types
  console.group('All fields with types:');
  for (const [k, v] of Object.entries(sample)) {
    const type = v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v;
    const preview = type === 'object' || type === 'array'
      ? `${JSON.stringify(v).slice(0, 150)}${JSON.stringify(v).length > 150 ? '...' : ''}`
      : String(v).slice(0, 150);
    console.log(`  ${k} [${type}]: ${preview}`);
  }
  console.groupEnd();

  console.log('First entry (full JSON, 5000 chars):', JSON.stringify(sample).slice(0, 5000));
  console.groupEnd();

  // Check 1: F5 data fields directly on the object (flat structure)
  if (hasF5DataFields(sample)) {
    console.log(`[DIAG-Normalize] ${logType}: ✓ F5 data fields found at top level — using flat structure`);
    return entries as T[];
  }

  // Check 2: Try known wrapper keys (including _source for Elasticsearch)
  console.group(`[DIAG-Normalize] ${logType}: Checking known wrapper keys...`);
  const WRAPPER_KEYS = ['_source', 'attributes', 'data', 'log', 'fields', 'record', 'event', 'message'];
  for (const key of WRAPPER_KEYS) {
    if (sample[key] && typeof sample[key] === 'object' && !Array.isArray(sample[key])) {
      const inner = sample[key] as Record<string, unknown>;
      const innerKeys = Object.keys(inner);
      const innerF5Hits = F5_DATA_FIELDS.filter(f => inner[f] !== undefined && inner[f] !== null);
      console.log(`  '${key}': ${innerKeys.length} keys, F5 fields found: [${innerF5Hits.join(', ')}]`);
      if (hasF5DataFields(inner)) {
        console.log(`  => ✓ MATCH! Unwrapping from '${key}'`);
        console.log(`  Inner sample keys:`, innerKeys.sort().join(', '));
        console.log(`  Inner rsp_code:`, JSON.stringify(inner['rsp_code']));
        console.groupEnd();
        return entries.map(e => {
          const wrapper = e as Record<string, unknown>;
          const data = wrapper[key] as Record<string, unknown>;
          return { ...data, _wrapper_id: wrapper['id'], _wrapper_time: wrapper['time'] } as T;
        });
      }
    } else {
      console.log(`  '${key}': ${sample[key] === undefined ? 'undefined' : 'not an object'}`);
    }
  }
  console.groupEnd();

  // Check 3: Deep scan — check ALL object-type values in the sample
  console.group(`[DIAG-Normalize] ${logType}: Deep scan of all nested objects...`);
  for (const [key, val] of Object.entries(sample)) {
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      const inner = val as Record<string, unknown>;
      const innerF5Hits = F5_DATA_FIELDS.filter(f => inner[f] !== undefined && inner[f] !== null);
      console.log(`  '${key}': ${Object.keys(inner).length} keys, F5 fields: [${innerF5Hits.join(', ')}]`);
      if (hasF5DataFields(inner)) {
        console.log(`  => ✓ MATCH! Unwrapping from '${key}'`);
        console.groupEnd();
        return entries.map(e => {
          const wrapper = e as Record<string, unknown>;
          const data = wrapper[key] as Record<string, unknown>;
          return { ...data, _wrapper_id: wrapper['id'], _wrapper_time: wrapper['time'] } as T;
        });
      }
    }
  }
  console.groupEnd();

  // Fallback: log everything for debugging and return as-is
  console.error(`[DIAG-Normalize] ${logType}: ✗ COULD NOT FIND F5 DATA FIELDS in any structure!`);
  console.error(`[DIAG-Normalize] ${logType}: This means the API response structure is unexpected.`);
  console.error(`[DIAG-Normalize] ${logType}: Full first entry JSON:`, JSON.stringify(sample));

  return entries as T[];
}

/** Scroll all pages for one access log chunk (adaptive concurrency) */
async function fetchChunkAccessLogs(
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
    `access-logs ${chunk.label}`,
    controller
  );

  // Parse total_hits carefully — API may return string, number, or object
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

  console.log(`[LogCollector] Chunk ${chunk.label}: total_hits raw=${JSON.stringify(rawHits)}, parsed=${totalHits}`);

  // Diagnostic: dump raw API response shape for the first chunk that has data
  if (initial.logs && initial.logs.length > 0) {
    const rawResponse = initial as unknown as Record<string, unknown>;
    console.group(`[DIAG-API] Raw access_logs API response for chunk ${chunk.label}`);
    console.log('Response top-level keys:', Object.keys(rawResponse).join(', '));
    console.log('logs array length:', initial.logs.length);
    console.log('First log entry keys:', Object.keys(initial.logs[0] as Record<string, unknown>).sort().join(', '));
    console.log('First log entry (5000 chars):', JSON.stringify(initial.logs[0]).slice(0, 5000));
    console.groupEnd();
  }

  onTotalKnown(totalHits);

  if (initial.logs) {
    logs.push(...initial.logs);
    onBatch(initial.logs.length);
  }

  // Scroll remaining pages — errors propagate so the chunk can be re-queued
  let scrollId = initial.scroll_id;
  while (scrollId) {
    const page = await withAdaptiveRetry(
      () => apiClient.post<AccessLogResponse>(
        `/api/data/namespaces/${namespace}/access_logs/scroll`,
        { scroll_id: scrollId!, namespace }
      ),
      `access-scroll ${chunk.label}`,
      controller
    );
    if (!page.logs || page.logs.length === 0) break;
    logs.push(...page.logs);
    scrollId = page.scroll_id;
    onBatch(page.logs.length);
  }

  return logs;
}

/** Scroll all pages for one security events chunk (adaptive concurrency) */
async function fetchChunkSecurityEvents(
  namespace: string,
  query: string,
  chunk: TimeChunk,
  controller: AdaptiveConcurrencyController,
  onBatch: (batchSize: number) => void,
  onTotalKnown: (totalHits: number) => void
): Promise<SecurityEventEntry[]> {
  const events: SecurityEventEntry[] = [];

  const initial = await withAdaptiveRetry(
    () => apiClient.post<SecurityEventResponse>(
      `/api/data/namespaces/${namespace}/app_security/events`,
      { query, namespace, start_time: chunk.start, end_time: chunk.end, scroll: true, limit: PAGE_SIZE }
    ),
    `security ${chunk.label}`,
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
  if (totalHits <= 0) totalHits = initial.events?.length || 0;

  console.log(`[LogCollector] Security chunk ${chunk.label}: total_hits raw=${JSON.stringify(rawHits)}, parsed=${totalHits}`);

  onTotalKnown(totalHits);

  if (initial.events) {
    events.push(...initial.events);
    onBatch(initial.events.length);
  }

  // Scroll remaining pages — errors propagate so the chunk can be re-queued
  let scrollId = initial.scroll_id;
  while (scrollId) {
    const page = await withAdaptiveRetry(
      () => apiClient.post<SecurityEventResponse>(
        `/api/data/namespaces/${namespace}/app_security/events/scroll`,
        { scroll_id: scrollId!, namespace }
      ),
      `security-scroll ${chunk.label}`,
      controller
    );
    if (!page.events || page.events.length === 0) break;
    events.push(...page.events);
    scrollId = page.scroll_id;
    onBatch(page.events.length);
  }

  return events;
}

// ═══════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════

/**
 * Collects access logs using adaptive concurrency.
 * Starts with 3 concurrent streams, ramps up to 10 on success,
 * backs down on 429s. Failed chunks are re-queued to prevent data loss.
 */
export async function collectAccessLogs(
  namespace: string,
  lbName: string,
  startTime: string,
  endTime: string,
  onProgress: (p: CollectionProgress) => void
): Promise<AccessLogEntry[]> {
  const query = `{vh_name="ves-io-http-loadbalancer-${lbName}"}`;
  const chunks = splitIntoChunks(startTime, endTime, CHUNK_HOURS);
  const controller = new AdaptiveConcurrencyController(ACCESS_LOG_ADAPTIVE);

  let collected = 0;
  let grandTotal = 0;
  let completedChunks = 0;

  onProgress({
    phase: 'fetching_logs',
    message: `Fetching access logs — ${chunks.length} streams (${CHUNK_HOURS}h windows, adaptive ×${controller.concurrency}, ${PAGE_SIZE}/page)...`,
    progress: 3,
    accessLogsCount: 0,
    securityEventsCount: 0,
    scrollPage: 0,
  });

  const updateProgress = () => {
    const pct = grandTotal > 0 ? Math.round((collected / grandTotal) * 100) : 0;
    const barProgress = grandTotal > 0
      ? Math.min(3 + Math.round((collected / grandTotal) * 40), 43)
      : 3;
    const stats = controller.getStats();
    const stateLabel = stats.state === 'green' ? '' : ` [${stats.state} ×${stats.concurrency}]`;
    const rateLimitLabel = stats.rateLimitHits > 0 ? ` | ${stats.rateLimitHits} rate-limited` : '';
    onProgress({
      phase: 'fetching_logs',
      message: `Access logs — ${collected.toLocaleString()}${grandTotal > 0 ? ` / ${grandTotal.toLocaleString()}` : ''} fetched (${pct}%) ×${stats.concurrency}${stateLabel}${rateLimitLabel}`,
      progress: barProgress,
      accessLogsCount: collected,
      securityEventsCount: 0,
      scrollPage: completedChunks,
      estimatedTotal: grandTotal,
    });
  };

  const tasks = chunks.map((chunk) => () =>
    fetchChunkAccessLogs(
      namespace, query, chunk, controller,
      (batchSize) => {
        collected += batchSize;
        updateProgress();
      },
      (totalHits) => {
        grandTotal += totalHits;
        updateProgress();
      }
    ).then((logs) => {
      completedChunks++;
      updateProgress();
      return logs;
    })
  );

  const chunkResults = await adaptivePool(tasks, controller, (concurrency, state) => {
    console.log(`[LogCollector] Adaptive: ${state} ×${concurrency} (${controller.getStats().rateLimitHits} rate-limited)`);
  });
  const rawLogs = chunkResults.flat();

  const stats = controller.getStats();
  console.log(
    `[LogCollector] Access logs adaptive stats: ${stats.totalRequests} requests, ` +
    `${stats.rateLimitHits} rate-limited (${stats.rateLimitPct}), ${stats.requestsPerSecond} req/s`
  );

  // Normalize: detect and unwrap if API returns nested structures
  const normalized = normalizeLogEntries<AccessLogEntry>(rawLogs, 'access-logs');

  // Client-side filter: ensure only logs for the selected LB
  const expectedVhName = `ves-io-http-loadbalancer-${lbName}`;
  const allLogs = normalized.filter(l => {
    const vhName = (l as Record<string, unknown>).vh_name as string | undefined;
    return !vhName || vhName === expectedVhName;
  });

  if (allLogs.length !== normalized.length) {
    console.warn(
      `[LogCollector] Access logs: filtered ${normalized.length} → ${allLogs.length} ` +
      `(removed ${normalized.length - allLogs.length} logs from other LBs)`
    );
  }

  console.log(`[LogCollector] Access logs done: fetched=${allLogs.length}, API total_hits sum=${grandTotal}`);

  onProgress({
    phase: 'fetching_logs',
    message: `Access logs complete: ${allLogs.length.toLocaleString()} records (${stats.totalRequests} API calls, ${stats.rateLimitHits} rate-limited)`,
    progress: 45,
    accessLogsCount: allLogs.length,
    securityEventsCount: 0,
    scrollPage: chunks.length,
    estimatedTotal: allLogs.length,
  });

  return allLogs;
}

/**
 * Collects security events using adaptive concurrency.
 * Starts with 1 concurrent stream (strict rate limits), ramps to 4.
 * Controller pacing replaces fixed throttle delays.
 */
export async function collectSecurityEvents(
  namespace: string,
  lbName: string,
  startTime: string,
  endTime: string,
  onProgress: (p: CollectionProgress) => void,
  accessLogsCount: number
): Promise<SecurityEventEntry[]> {
  const query = `{vh_name="ves-io-http-loadbalancer-${lbName}"}`;

  console.log(`[LogCollector] Security events query: ${query}`);

  const chunks = splitIntoChunks(startTime, endTime, SEC_CHUNK_HOURS);
  const controller = new AdaptiveConcurrencyController(SECURITY_EVENT_ADAPTIVE);

  let collected = 0;
  let grandTotal = 0;
  let completedChunks = 0;

  onProgress({
    phase: 'fetching_security',
    message: `Fetching security events — ${chunks.length} streams (adaptive ×${controller.concurrency})...`,
    progress: 48,
    accessLogsCount,
    securityEventsCount: 0,
    scrollPage: 0,
  });

  const updateProgress = () => {
    const pct = grandTotal > 0 ? Math.round((collected / grandTotal) * 100) : 0;
    const barProgress = grandTotal > 0
      ? Math.min(48 + Math.round((collected / grandTotal) * 20), 68)
      : 48;
    const stats = controller.getStats();
    const stateLabel = stats.state === 'green' ? '' : ` [${stats.state} ×${stats.concurrency}]`;
    const rateLimitLabel = stats.rateLimitHits > 0 ? ` | ${stats.rateLimitHits} rate-limited` : '';
    onProgress({
      phase: 'fetching_security',
      message: `Security events — ${collected.toLocaleString()}${grandTotal > 0 ? ` / ${grandTotal.toLocaleString()}` : ''} fetched (${pct}%) ×${stats.concurrency}${stateLabel}${rateLimitLabel}`,
      progress: barProgress,
      accessLogsCount,
      securityEventsCount: collected,
      scrollPage: completedChunks,
      estimatedTotal: grandTotal,
    });
  };

  const tasks = chunks.map((chunk) => () =>
    fetchChunkSecurityEvents(
      namespace, query, chunk, controller,
      (batchSize) => {
        collected += batchSize;
        updateProgress();
      },
      (totalHits) => {
        grandTotal += totalHits;
        updateProgress();
      }
    ).then((events) => {
      completedChunks++;
      updateProgress();
      return events;
    })
  );

  const chunkResults = await adaptivePool(tasks, controller, (concurrency, state) => {
    console.log(`[LogCollector] Security adaptive: ${state} ×${concurrency} (${controller.getStats().rateLimitHits} rate-limited)`);
  });
  const normalized = normalizeLogEntries<SecurityEventEntry>(chunkResults.flat(), 'security-events');

  const stats = controller.getStats();
  console.log(
    `[LogCollector] Security events adaptive stats: ${stats.totalRequests} requests, ` +
    `${stats.rateLimitHits} rate-limited (${stats.rateLimitPct}), ${stats.requestsPerSecond} req/s`
  );

  // ═══════════════════════════════════════════════════════════════
  // CLIENT-SIDE FILTER: The security events API may return events
  // from ALL load balancers in the namespace despite the vh_name
  // query filter. Post-filter to ensure only events for this LB.
  // ═══════════════════════════════════════════════════════════════
  const expectedVhName = `ves-io-http-loadbalancer-${lbName}`;
  const allEvents = normalized.filter(e => {
    const vhName = (e as Record<string, unknown>).vh_name as string | undefined;
    return !vhName || vhName === expectedVhName;
  });

  if (allEvents.length !== normalized.length) {
    console.warn(
      `[LogCollector] Security events: filtered ${normalized.length} → ${allEvents.length} ` +
      `(removed ${normalized.length - allEvents.length} events from other LBs)`
    );
  }

  console.log(`[LogCollector] Security events done: fetched=${allEvents.length}, API total_hits sum=${grandTotal}`);

  onProgress({
    phase: 'fetching_security',
    message: `Security events complete: ${allEvents.length.toLocaleString()} (${stats.totalRequests} API calls, ${stats.rateLimitHits} rate-limited)`,
    progress: 68,
    accessLogsCount,
    securityEventsCount: allEvents.length,
    scrollPage: chunks.length,
    estimatedTotal: allEvents.length,
  });

  return allEvents;
}
