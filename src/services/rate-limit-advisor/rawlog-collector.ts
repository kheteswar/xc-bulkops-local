/**
 * Rate Limit Advisor — Deep Mode (Full Raw Log Collector)
 *
 * Key constraint: F5 XC's access_logs scroll API has a 10,000 document
 * depth limit (Elasticsearch). To fetch ALL logs, we:
 *   1. Probe the total for the window
 *   2. Dynamically calculate chunk duration so each chunk has <5,000 records
 *   3. Scroll each chunk independently with adaptive concurrency + retry
 *
 * Uses the proven scroll pattern: POST access_logs with scroll=true,
 * follow scroll_id via POST access_logs/scroll until empty.
 */

import { apiClient } from '../api';
import { AdaptiveConcurrencyController } from '../fp-analyzer/adaptive-concurrency';
import type { AccessLogResponse } from './types';
import { probeVolume } from '../log-analyzer/aggregation-client';

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

/** Max records per API request */
const PAGE_SIZE = 500;
/** Target records per chunk — must be UNDER 500 so each chunk fits in one request (no scroll needed) */
const TARGET_PER_CHUNK = 400;
/** Max retries per API call */
const MAX_RETRIES = 4;
const RETRY_BASE_MS = 2000;
/** Minimum chunk duration in seconds (don't go smaller than 30s) */
const MIN_CHUNK_SECONDS = 30;

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

export interface RawLogProgress {
  phase: 'probing' | 'scrolling' | 'processing' | 'complete' | 'error';
  message: string;
  progress: number;
  logsCollected: number;
  totalEstimate: number;
  apiCalls: number;
}

export interface RawLogCollection {
  lbName: string;
  namespace: string;
  startTime: string;
  endTime: string;
  windowHours: number;
  totalExpected: number;
  totalLogsScrolled: number;
  cleanLogs: number;
  userMinuteCounts: Record<string, number[]>;
  allUsers: string[];
  filterBreakdown: {
    waf_block: number;
    bot_malicious: number;
    policy_deny: number;
    mum_action: number;
    ip_high_risk: number;
    total: number;
  };
  apiCallsUsed: number;
  runtimeMs: number;
}

// ═══════════════════════════════════════════════════════════════════
// RETRY + ADAPTIVE CONCURRENCY
// ═══════════════════════════════════════════════════════════════════

function isRateLimitError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  const l = msg.toLowerCase();
  return msg.includes('429') || l.includes('too many') || l.includes('rate limit');
}

function isTransientError(err: unknown): boolean {
  if (isRateLimitError(err)) return true;
  const msg = err instanceof Error ? err.message : String(err);
  return msg.includes('502') || msg.includes('503') || msg.includes('504');
}

async function withRetry<T>(
  fn: () => Promise<T>,
  label: string,
  controller: AdaptiveConcurrencyController,
): Promise<T> {
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const pace = Math.max(controller.getRequestDelay(), 100);
    await new Promise(r => setTimeout(r, pace));
    try {
      const result = await fn();
      controller.recordSuccess();
      return result;
    } catch (err) {
      if (isRateLimitError(err)) controller.recordRateLimit();
      else controller.recordError();
      if (!isTransientError(err) || attempt === MAX_RETRIES) throw err;
      const delay = RETRY_BASE_MS * Math.pow(2, attempt) + Math.random() * 1000;
      console.log(`[RawLog] ${label}: retry ${attempt + 1}/${MAX_RETRIES} in ${Math.round(delay)}ms`);
      await new Promise(r => setTimeout(r, delay));
    }
  }
  throw new Error('Unreachable');
}

// ═══════════════════════════════════════════════════════════════════
// CLEANING FILTER
// ═══════════════════════════════════════════════════════════════════

function lower(val: unknown): string {
  if (typeof val === 'string') return val.toLowerCase();
  if (val == null) return '';
  return String(val).toLowerCase();
}

function isExcluded(entry: Record<string, unknown>): { excluded: boolean; reason: string } {
  if (lower(entry.waf_action) === 'block')
    return { excluded: true, reason: 'waf_block' };
  const botInsight = lower(entry.bot_defense_insight) || lower(entry['bot_defense.insight']);
  if (botInsight === 'malicious')
    return { excluded: true, reason: 'bot_malicious' };
  const botClass = lower(entry.bot_class);
  if (botClass === 'bad_bot' || botClass === 'malicious')
    return { excluded: true, reason: 'bot_malicious' };

  const ph = entry.policy_hits;
  if (ph && typeof ph === 'object') {
    const inner = (ph as Record<string, unknown>).policy_hits;
    if (Array.isArray(inner) && inner.length > 0) {
      const hit = inner[0] as Record<string, unknown>;
      const result = lower(hit.result);
      if (result === 'deny' || result === 'default_deny')
        return { excluded: true, reason: 'policy_deny' };
      const mum = lower(hit.malicious_user_mitigate_action);
      if (mum && mum !== 'mum_none')
        return { excluded: true, reason: 'mum_action' };
      const risk = lower(hit.ip_risk);
      if (risk === 'high_risk')
        return { excluded: true, reason: 'ip_high_risk' };
    }
  }
  return { excluded: false, reason: '' };
}

// ═══════════════════════════════════════════════════════════════════
// NORMALIZE LOG ENTRY (F5 XC may return JSON strings or objects)
// ═══════════════════════════════════════════════════════════════════

function normalizeEntry(raw: unknown): Record<string, unknown> | null {
  if (typeof raw === 'string') {
    try { return JSON.parse(raw); } catch { return null; }
  }
  if (raw && typeof raw === 'object') return raw as Record<string, unknown>;
  return null;
}

// ═══════════════════════════════════════════════════════════════════
// FETCH ONE CHUNK (single request, no scroll — chunks are sized to fit)
// ═══════════════════════════════════════════════════════════════════

async function fetchChunk(
  namespace: string,
  query: string,
  startTime: string,
  endTime: string,
  label: string,
  controller: AdaptiveConcurrencyController,
): Promise<unknown[]> {
  const resp = await withRetry(
    () => apiClient.post<AccessLogResponse>(
      `/api/data/namespaces/${namespace}/access_logs`,
      { query, namespace, start_time: startTime, end_time: endTime, scroll: false, limit: PAGE_SIZE },
    ),
    `fetch-${label}`, controller,
  );
  return resp.logs ?? [];
}

// ═══════════════════════════════════════════════════════════════════
// MAIN COLLECTOR
// ═══════════════════════════════════════════════════════════════════

export async function collectRawLogs(
  namespace: string,
  lbName: string,
  windowHours: number,
  onProgress: (p: RawLogProgress) => void,
): Promise<RawLogCollection> {
  const startMs = Date.now();
  let apiCalls = 0;

  const now = new Date();
  const endTime = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours())).toISOString();
  const startTime = new Date(new Date(endTime).getTime() - windowHours * 3600000).toISOString();
  const query = `{vh_name="ves-io-http-loadbalancer-${lbName}"}`;

  const controller = new AdaptiveConcurrencyController({
    initialConcurrency: 2, minConcurrency: 1, maxConcurrency: 6,
    rampUpAfterSuccesses: 5, rampDownFactor: 0.5,
    yellowDelayMs: 300, redDelayMs: 3000, redCooldownMs: 10000,
  });

  console.log(`[RawLog] Window: ${startTime} → ${endTime} (${windowHours}h)`);

  // ── Step 1: Probe total ─────────────────────────────────────────
  onProgress({ phase: 'probing', message: 'Probing total log count...', progress: 2, logsCollected: 0, totalEstimate: 0, apiCalls: 0 });

  let totalExpected: number;
  try {
    const probeResult = await probeVolume(namespace, 'access_logs', query, startTime, endTime);
    totalExpected = probeResult.totalHits;
    apiCalls++;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('index_closed') || msg.includes('400')) {
      throw new Error(`F5 XC logs for this time range are unavailable (index closed). Try a shorter or more recent window.`);
    }
    throw new Error(`Failed to probe logs for "${lbName}": ${msg}`);
  }

  console.log(`[RawLog] Probe: ${totalExpected.toLocaleString()} total records`);
  if (totalExpected === 0) throw new Error(`No access logs for "${lbName}" in the last ${windowHours}h. Try a different time window.`);

  // ── Step 2: Calculate dynamic chunk size ────────────────────────
  // F5 XC scroll has a ~10,000 record depth limit (Elasticsearch).
  // We size chunks so each has at most TARGET_PER_CHUNK records.
  const windowSeconds = windowHours * 3600;
  const rps = totalExpected / windowSeconds; // average records per second
  let chunkSeconds = Math.floor(TARGET_PER_CHUNK / Math.max(rps, 0.01));
  chunkSeconds = Math.max(chunkSeconds, MIN_CHUNK_SECONDS); // floor at 30s
  chunkSeconds = Math.min(chunkSeconds, windowSeconds); // cap at full window

  // Build chunks
  interface Chunk { start: string; end: string; label: string }
  const chunks: Chunk[] = [];
  const startMs2 = new Date(startTime).getTime();
  const endMs2 = new Date(endTime).getTime();
  for (let t = startMs2; t < endMs2; t += chunkSeconds * 1000) {
    const s = new Date(t);
    const e = new Date(Math.min(t + chunkSeconds * 1000, endMs2));
    chunks.push({
      start: s.toISOString(),
      end: e.toISOString(),
      label: `${s.getUTCHours()}:${String(s.getUTCMinutes()).padStart(2, '0')}`,
    });
  }

  const estPerChunk = Math.round(totalExpected / chunks.length);
  console.log(`[RawLog] Chunk plan: ${chunks.length} chunks × ~${chunkSeconds}s each (~${estPerChunk} records/chunk, ${rps.toFixed(1)} rps)`);

  onProgress({
    phase: 'scrolling',
    message: `Scrolling ${totalExpected.toLocaleString()} logs in ${chunks.length} chunks (${chunkSeconds}s each, ~${estPerChunk}/chunk)...`,
    progress: 5, logsCollected: 0, totalEstimate: totalExpected, apiCalls,
  });

  // ── Step 3: Fetch all chunks with adaptive concurrency ──────────
  const allRawLogs: unknown[] = [];
  let totalCollected = 0;
  let chunksDone = 0;
  let chunksActive = 0;
  const chunkQueue = [...chunks];

  await new Promise<void>((resolve) => {
    function dispatch() {
      while (chunksActive < controller.concurrency && chunkQueue.length > 0) {
        const chunk = chunkQueue.shift()!;
        chunksActive++;
        fetchChunk(namespace, query, chunk.start, chunk.end, chunk.label, controller)
          .then(logs => {
            allRawLogs.push(...logs);
            totalCollected += logs.length;
            apiCalls++;
            chunksDone++;

            // Progress update every few chunks
            if (chunksDone % 5 === 0 || chunksDone === chunks.length) {
              const stats = controller.getStats();
              onProgress({
                phase: 'scrolling',
                message: `${totalCollected.toLocaleString()} / ${totalExpected.toLocaleString()} logs — chunk ${chunksDone}/${chunks.length} ×${stats.concurrency}${stats.rateLimitHits > 0 ? ` (${stats.rateLimitHits} retried)` : ''}`,
                progress: 5 + Math.round((chunksDone / chunks.length) * 65),
                logsCollected: totalCollected, totalEstimate: totalExpected, apiCalls,
              });
            }
          })
          .catch(err => {
            chunksDone++;
            apiCalls++;
            const msg = err instanceof Error ? err.message : String(err);
            if (msg.includes('index_closed')) {
              console.warn(`[RawLog] Chunk ${chunk.label}: index closed, skipping`);
            } else {
              console.error(`[RawLog] Chunk ${chunk.label} failed:`, msg);
            }
          })
          .finally(() => {
            chunksActive--;
            if (chunksDone === chunks.length) resolve();
            else dispatch();
          });
      }
    }
    if (chunks.length === 0) resolve();
    else dispatch();
  });

  const fetchPct = totalExpected > 0 ? Math.round((allRawLogs.length / totalExpected) * 100) : 100;
  console.log(`[RawLog] Scroll complete: ${allRawLogs.length.toLocaleString()} / ${totalExpected.toLocaleString()} (${fetchPct}%) in ${chunksDone} chunks`);

  if (fetchPct < 80) {
    console.warn(`[RawLog] Only fetched ${fetchPct}% of expected. Some chunks may have exceeded the 10K scroll limit.`);
  }

  // ── Step 4: Process — normalize, filter, group ──────────────────
  onProgress({ phase: 'processing', message: `Processing ${allRawLogs.length.toLocaleString()} entries...`, progress: 72, logsCollected: allRawLogs.length, totalEstimate: totalExpected, apiCalls });

  const filterCounts = { waf_block: 0, bot_malicious: 0, policy_deny: 0, mum_action: 0, ip_high_risk: 0, total: 0 };
  const userMinuteMap = new Map<string, Map<string, number>>();
  const allUsersSet = new Set<string>();
  let cleanCount = 0;

  for (const raw of allRawLogs) {
    const entry = normalizeEntry(raw);
    if (!entry) continue;

    const userId = (entry.user as string) || (entry.src_ip as string) || '';
    const ts = (entry['@timestamp'] as string) || (entry.time as string) || '';
    if (!userId || !ts) continue;

    allUsersSet.add(userId);

    const { excluded, reason } = isExcluded(entry);
    if (excluded) {
      (filterCounts as unknown as Record<string, number>)[reason] = ((filterCounts as unknown as Record<string, number>)[reason] ?? 0) + 1;
      filterCounts.total++;
      continue;
    }

    cleanCount++;
    const minuteKey = ts.slice(0, 16);
    let minuteMap = userMinuteMap.get(userId);
    if (!minuteMap) { minuteMap = new Map(); userMinuteMap.set(userId, minuteMap); }
    minuteMap.set(minuteKey, (minuteMap.get(minuteKey) ?? 0) + 1);
  }

  const userMinuteCounts: Record<string, number[]> = {};
  for (const [userId, minuteMap] of userMinuteMap) {
    userMinuteCounts[userId] = [...minuteMap.values()];
  }

  const runtimeMs = Date.now() - startMs;
  console.log(
    `[RawLog] DONE: ${allRawLogs.length.toLocaleString()} fetched (${fetchPct}%), ` +
    `${filterCounts.total} filtered, ${cleanCount} clean, ${userMinuteMap.size} users, ` +
    `${apiCalls} API calls, ${(runtimeMs / 1000).toFixed(1)}s`
  );
  console.log(`[RawLog] Filters: waf=${filterCounts.waf_block} bot=${filterCounts.bot_malicious} policy=${filterCounts.policy_deny} mum=${filterCounts.mum_action} ip_risk=${filterCounts.ip_high_risk}`);

  onProgress({
    phase: 'complete',
    message: `${cleanCount.toLocaleString()} clean from ${allRawLogs.length.toLocaleString()} logs (${fetchPct}% of expected), ${userMinuteMap.size} users`,
    progress: 100, logsCollected: allRawLogs.length, totalEstimate: totalExpected, apiCalls,
  });

  return {
    lbName, namespace, startTime, endTime, windowHours, totalExpected,
    totalLogsScrolled: allRawLogs.length, cleanLogs: cleanCount,
    userMinuteCounts, allUsers: [...allUsersSet],
    filterBreakdown: filterCounts, apiCallsUsed: apiCalls, runtimeMs,
  };
}
