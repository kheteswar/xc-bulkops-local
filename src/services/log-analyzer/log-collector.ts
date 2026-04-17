import { apiClient } from '../api';
import { AdaptiveConcurrencyController } from '../fp-analyzer/adaptive-concurrency';
import type { AdaptiveConcurrencyConfig } from '../fp-analyzer/adaptive-concurrency';
import { normalizeLogEntries } from '../rate-limit-advisor/log-collector';
import type { AccessLogEntry, AccessLogResponse, SecurityEventEntry, SecurityEventResponse } from '../rate-limit-advisor/types';
import type { QueryFilter, LogCollectionProgress, AggregatedLogData } from './types';
import {
  probeVolume, fetchBatchAggregation, scanHourlyVolume,
} from './aggregation-client';

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

const SEC_CHUNK_HOURS = 12;
const SEC_ADAPTIVE_CONFIG: Partial<AdaptiveConcurrencyConfig> = {
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

// ═══════════════════════════════════════════════════════════════════
// SECURITY EVENT CHUNK FETCHER
// ═══════════════════════════════════════════════════════════════════

async function fetchSecurityChunk(
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
  onTotalKnown(totalHits);

  if (initial.events) {
    events.push(...initial.events);
    onBatch(initial.events.length);
  }

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
// COLLECT SECURITY EVENTS
// ═══════════════════════════════════════════════════════════════════

/**
 * Collect security events matching the query with adaptive concurrency.
 * Uses conservative concurrency (max 4) due to stricter rate limits.
 */
export async function collectSecurityEvents(
  namespace: string,
  query: string,
  startTime: string,
  endTime: string,
  onProgress: (p: LogCollectionProgress) => void,
): Promise<SecurityEventEntry[]> {
  const chunks = splitIntoChunks(startTime, endTime, SEC_CHUNK_HOURS);
  const controller = new AdaptiveConcurrencyController(SEC_ADAPTIVE_CONFIG);

  let collected = 0;
  let grandTotal = 0;

  onProgress({
    phase: 'fetching',
    message: `Fetching security events — ${chunks.length} streams...`,
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
      message: `Security events — ${collected.toLocaleString()}${grandTotal > 0 ? ` / ${grandTotal.toLocaleString()}` : ''} (${pct}%) x${stats.concurrency}${rateLimitLabel}`,
      progress: barProgress,
      logsCollected: collected,
      estimatedTotal: grandTotal,
    });
  };

  const tasks = chunks.map((chunk) => () =>
    fetchSecurityChunk(
      namespace, query, chunk, controller,
      (batchSize) => { collected += batchSize; updateProgress(); },
      (totalHits) => { grandTotal += totalHits; updateProgress(); }
    )
  );

  const chunkResults = await adaptivePool(tasks, controller);
  const rawEvents = chunkResults.flat();
  const normalized = normalizeLogEntries<SecurityEventEntry>(rawEvents, 'security-events');

  const stats = controller.getStats();
  onProgress({
    phase: 'complete',
    message: `Complete: ${normalized.length.toLocaleString()} security events (${stats.totalRequests} API calls, ${stats.rateLimitHits} rate-limited)`,
    progress: 100,
    logsCollected: normalized.length,
    estimatedTotal: normalized.length,
  });

  return normalized;
}

// ═══════════════════════════════════════════════════════════════════
// AGGREGATION-BASED COLLECTION (fast path — replaces full scroll)
// ═══════════════════════════════════════════════════════════════════

/** Access log fields to aggregate (server-side top-N counts) */
const ACCESS_AGG_FIELDS = [
  { field: 'rsp_code',         topk: 30 },
  { field: 'rsp_code_class',   topk: 10 },
  { field: 'rsp_code_details', topk: 30 },
  { field: 'country',          topk: 50 },
  { field: 'req_path',         topk: 50 },
  { field: 'src_ip',           topk: 50 },
  { field: 'domain',           topk: 30 },
  { field: 'waf_action',       topk: 10 },
  { field: 'method',           topk: 10 },
  { field: 'user_agent',       topk: 30 },
  { field: 'bot_class',        topk: 20 },
  { field: 'dst_ip',           topk: 30 },
  { field: 'as_org',           topk: 30 },
  { field: 'tls_version',      topk: 10 },
  { field: 'protocol',         topk: 10 },
];

/** Security event fields to aggregate */
const SECURITY_AGG_FIELDS = [
  { field: 'sec_event_name',   topk: 20 },
  { field: 'signatures.id',    topk: 30 },
  { field: 'violations.name',  topk: 30 },
  { field: 'src_ip',           topk: 30 },
  { field: 'country',          topk: 30 },
  { field: 'waf_action',       topk: 10 },
  { field: 'attack_types',     topk: 20 },
];

/**
 * Collect log analytics using aggregation API instead of raw log scrolling.
 *
 * Flow:
 *  1. Probe (1 call each): total_hits + sample_rate for access + security
 *  2. Batch aggregations (2 calls): all access fields + all security fields in parallel
 *  3. Raw sample (1 call): 500 records for table view + latency estimation
 *  4. Hourly time series (N calls, concurrency-limited): volume per time bucket
 *
 * Result: ~30+ parallel API calls → complete analytics in 3-5 seconds
 * vs old approach: 50-200+ sequential scrolling calls → 30-120 seconds
 */
export async function collectWithAggregations(
  namespace: string,
  query: string,
  startTime: string,
  endTime: string,
  onProgress: (p: LogCollectionProgress) => void,
): Promise<AggregatedLogData> {
  onProgress({ phase: 'fetching', message: 'Probing traffic volume...', progress: 5, logsCollected: 0, estimatedTotal: 0 });

  const rangeHours = (new Date(endTime).getTime() - new Date(startTime).getTime()) / 3600000;
  const bucketHours = rangeHours <= 1 ? 1 : rangeHours <= 24 ? 1 : rangeHours <= 168 ? 6 : 24;

  // Phase 1: parallel — probe + both batch aggregations + raw sample
  onProgress({ phase: 'fetching', message: 'Running server-side aggregations...', progress: 15, logsCollected: 0, estimatedTotal: 0 });

  const [
    accessProbe,
    secProbe,
    accessAggs,
    securityAggs,
    rawSampleResp,
    rawSecSampleResp,
  ] = await Promise.all([
    probeVolume(namespace, 'access_logs', query, startTime, endTime),
    probeVolume(namespace, 'app_security/events', query, startTime, endTime),
    fetchBatchAggregation(namespace, 'access_logs', query, startTime, endTime, ACCESS_AGG_FIELDS),
    fetchBatchAggregation(namespace, 'app_security/events', query, startTime, endTime, SECURITY_AGG_FIELDS),
    // Small raw sample for table view + latency percentiles
    apiClient.post<AccessLogResponse>(
      `/api/data/namespaces/${namespace}/access_logs`,
      { query, namespace, start_time: startTime, end_time: endTime, scroll: false, limit: 500, sort: 'DESCENDING' }
    ).catch(() => ({ logs: [] } as AccessLogResponse)),
    // Small security event sample for event feed
    apiClient.post<SecurityEventResponse>(
      `/api/data/namespaces/${namespace}/app_security/events`,
      { query, namespace, start_time: startTime, end_time: endTime, scroll: false, limit: 200, sort: 'DESCENDING' }
    ).catch(() => ({ events: [] } as SecurityEventResponse)),
  ]);

  onProgress({ phase: 'fetching', message: 'Building time series...', progress: 70, logsCollected: accessProbe.totalHits, estimatedTotal: accessProbe.totalHits });

  // Phase 2: hourly time series (lightweight probes)
  const hourlyBuckets = await scanHourlyVolume(
    namespace, 'access_logs', query, startTime, endTime, bucketHours,
    (done, total) => {
      const pct = 70 + Math.round((done / total) * 25);
      onProgress({ phase: 'fetching', message: `Time series: ${done}/${total} buckets`, progress: pct, logsCollected: accessProbe.totalHits, estimatedTotal: accessProbe.totalHits });
    },
  );

  const sampleLogs = normalizeLogEntries<AccessLogEntry>(rawSampleResp.logs ?? [], 'agg-sample');
  const sampleSecurityEvents = normalizeLogEntries<SecurityEventEntry>(rawSecSampleResp.events ?? [], 'agg-sec-sample');

  const timeSeries = hourlyBuckets.map(b => ({
    timestamp: b.start,
    count: b.totalHits,
    label: b.label,
  }));

  const estimatedRequests = accessProbe.sampleRate > 0 && accessProbe.sampleRate < 1
    ? Math.round(accessProbe.totalHits / accessProbe.sampleRate)
    : accessProbe.totalHits;

  onProgress({
    phase: 'complete',
    message: `Complete: ~${estimatedRequests.toLocaleString()} requests · ${accessProbe.totalHits.toLocaleString()} sampled · ${sampleLogs.length} in table`,
    progress: 100,
    logsCollected: accessProbe.totalHits,
    estimatedTotal: accessProbe.totalHits,
  });

  return {
    totalHits: accessProbe.totalHits,
    sampleRate: accessProbe.sampleRate,
    estimatedRequests,
    accessAggs,
    securityAggs,
    sampleLogs,
    sampleSecurityEvents,
    timeSeries,
    totalSecurityEvents: secProbe.totalHits,
  };
}

// ═══════════════════════════════════════════════════════════════════
// MERGE SECURITY EVENTS INTO ACCESS LOGS
// ═══════════════════════════════════════════════════════════════════

/** All security event fields to merge/flatten onto matching access log entries */
const SEC_MERGE_FIELDS = [
  'sec_event_type', 'sec_event_name', 'action', 'recommended_action',
  'enforcement_mode', 'violation_rating', 'req_risk', 'req_risk_reasons',
  'app_firewall_name', 'waf_mode', 'attack_types', 'sec_event_data',
  'route_uuid', 'vhost_id', 'stream',
] as const;

/**
 * Flatten nested objects from a security event into dot-notation fields.
 * E.g., bot_info: { name: "X", classification: "Y" } → bot_info.name: "X", bot_info.classification: "Y"
 */
function flattenSecurityEvent(evt: Record<string, unknown>): Record<string, unknown> {
  const fields: Record<string, unknown> = {};

  // Copy top-level merge fields
  for (const key of SEC_MERGE_FIELDS) {
    const val = evt[key];
    if (val !== undefined && val !== null && val !== '') {
      // req_risk_reasons is an array — join as string for field analysis
      if (key === 'req_risk_reasons' && Array.isArray(val)) {
        fields[key] = (val as string[]).join('; ');
      } else {
        fields[key] = val;
      }
    }
  }

  // Flatten bot_info object
  const botInfo = evt.bot_info as Record<string, unknown> | undefined;
  if (botInfo && typeof botInfo === 'object') {
    for (const subKey of ['name', 'classification', 'type', 'anomaly']) {
      if (botInfo[subKey]) fields[`bot_info.${subKey}`] = botInfo[subKey];
    }
  }

  // Flatten signatures array — take first signature's fields + count
  const signatures = evt.signatures as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(signatures) && signatures.length > 0) {
    const first = signatures[0];
    for (const subKey of ['id', 'name', 'attack_type', 'accuracy', 'risk']) {
      if (first[subKey]) fields[`signatures.${subKey}`] = first[subKey];
    }
    if (signatures.length > 1) {
      fields['signatures.count'] = signatures.length;
      // Concatenate all signature names for analysis
      fields['signatures.all_names'] = signatures.map(s => s.name || s.id).filter(Boolean).join(', ');
    }
  }

  // Flatten violations array — take first violation + count
  const violations = evt.violations as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(violations) && violations.length > 0) {
    const first = violations[0];
    for (const subKey of ['name', 'context']) {
      if (first[subKey]) fields[`violations.${subKey}`] = first[subKey];
    }
    if (violations.length > 1) {
      fields['violations.count'] = violations.length;
    }
  }

  // Flatten threat_campaigns array
  const campaigns = evt.threat_campaigns as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(campaigns) && campaigns.length > 0) {
    fields['threat_campaigns.name'] = campaigns[0].name;
    fields['threat_campaigns.id'] = campaigns[0].id;
  }

  // Flatten policy_hits (from security events — different structure than access logs)
  const policyHits = evt.policy_hits as Record<string, unknown> | undefined;
  if (policyHits && typeof policyHits === 'object' && !Array.isArray(policyHits)) {
    if (policyHits.policy) fields['policy_hits.policy'] = policyHits.policy;
    if (policyHits.rule) fields['policy_hits.rule'] = policyHits.rule;
    if (policyHits.action) fields['policy_hits.action'] = policyHits.action;
  }

  return fields;
}

/**
 * Merge security events into access logs.
 *
 * Strategy:
 * 1. Match by req_id where possible (same request → enrich access log with sec event fields)
 * 2. Unmatched security events are APPENDED as standalone entries (not dropped)
 *    so they always appear in field analysis.
 *
 * All nested objects (bot_info, signatures, violations, threat_campaigns) are
 * flattened to dot-notation for field analysis compatibility.
 */
export function mergeSecurityIntoAccessLogs(
  accessLogs: AccessLogEntry[],
  securityEvents: SecurityEventEntry[],
): AccessLogEntry[] {
  if (securityEvents.length === 0) return accessLogs;

  // Build lookup by req_id for security events
  // Store BOTH the raw event (all fields) and the flattened merge fields
  const secByReqId = new Map<string, { raw: Record<string, unknown>; flattened: Record<string, unknown> }>();
  const unmatchedSecEvents: Record<string, unknown>[] = [];

  for (const evt of securityEvents) {
    const raw = evt as Record<string, unknown>;
    const reqId = raw.req_id as string;
    const flattened = flattenSecurityEvent(raw);

    if (reqId) {
      secByReqId.set(reqId, { raw, flattened });
    } else {
      // No req_id: spread ALL raw fields + flattened nested fields
      unmatchedSecEvents.push({ ...raw, ...flattened });
    }
  }

  // Phase 1: Merge matched events onto access logs
  let mergedCount = 0;
  const matchedReqIds = new Set<string>();
  const result = accessLogs.map(log => {
    const reqId = (log as Record<string, unknown>).req_id as string;
    if (!reqId) return log;
    const secEntry = secByReqId.get(reqId);
    if (!secEntry) return log;
    mergedCount++;
    matchedReqIds.add(reqId);
    // Spread flattened fields onto the access log (access log fields take precedence for common fields)
    return { ...log, ...secEntry.flattened, has_sec_event: true } as AccessLogEntry;
  });

  // Phase 2: Append unmatched security events as standalone entries
  // These are security events with req_id that didn't match any access log
  for (const [reqId, entry] of secByReqId) {
    if (matchedReqIds.has(reqId)) continue;
    // Include ALL raw fields + flattened nested fields
    unmatchedSecEvents.push({ ...entry.raw, ...entry.flattened });
  }

  // Convert unmatched security events to AccessLogEntry-compatible objects
  for (const secEvt of unmatchedSecEvents) {
    const raw = secEvt as Record<string, unknown>;
    result.push({
      ...raw,
      has_sec_event: true,
      // Ensure key fields exist for table display
      rsp_code: (raw.rsp_code as string) || '',
      rsp_code_class: (raw.rsp_code_class as string) || '',
      method: (raw.method as string) || '',
      req_path: (raw.req_path as string) || (raw.original_path as string) || '',
      src_ip: (raw.src_ip as string) || '',
      domain: (raw.domain as string) || (raw.authority as string) || '',
      country: (raw.country as string) || '',
      user_agent: (raw.user_agent as string) || '',
      '@timestamp': (raw['@timestamp'] as string) || (raw.time as string) || new Date().toISOString(),
    } as AccessLogEntry);
  }

  const unmatchedCount = unmatchedSecEvents.length;
  console.log(
    `[LogAnalyzer] Merge: ${mergedCount} matched by req_id, ${unmatchedCount} unmatched sec events appended as standalone rows ` +
    `(${accessLogs.length} access + ${securityEvents.length} security → ${result.length} total)`
  );

  return result;
}
