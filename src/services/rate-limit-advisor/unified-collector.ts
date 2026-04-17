/**
 * Rate Limit Advisor — Unified Collector
 *
 * Orchestrates two phases with a shared adaptive concurrency controller:
 *
 * Phase A — Weekly Baseline (always 7 days, ~14 API calls)
 *   Provides: daily traffic shape, trend detection, seasonality, filter breakdown,
 *   top users by volume. NO per-user raw log fetches (Phase B handles that).
 *
 * Phase B — Deep Scan (user-selected: 1h/4h/12h/24h, variable calls)
 *   Fetches ALL raw logs using dynamic chunking (≤400 records/chunk, no scroll needed).
 *   Applies cleaning filter, builds per-user per-minute counts.
 *
 * API constraints (confirmed by testing):
 *   - 500 records max per request
 *   - scroll_id NOT reliably returned — avoided entirely
 *   - Only label matchers in queries ({field="value"}), no pipe filters
 *   - `user` field = rate limiting identifier (e.g., "IP-136.226.234.89")
 *   - policy_hits.policy_hits[0] contains ip_risk, malicious_user_mitigate_action, result
 *   - 429 rate limits handled by adaptive concurrency + exponential backoff
 */

import { apiClient } from '../api';
import { AdaptiveConcurrencyController } from '../fp-analyzer/adaptive-concurrency';
import type { AccessLogResponse } from './types';
import { fetchBatchAggregation, probeVolume } from '../log-analyzer/aggregation-client';
import type { AggBucket } from '../log-analyzer/aggregation-client';

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

const PAGE_SIZE = 500;
const TARGET_PER_CHUNK = 400;
const MIN_CHUNK_SECONDS = 30;
const MAX_RETRIES = 4;
const RETRY_BASE_MS = 2000;
const TOP_USERS_AGG = 20;

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

export interface UnifiedProgress {
  phase: 'baseline' | 'deep' | 'processing' | 'complete' | 'error';
  stage: string;
  message: string;
  progress: number; // 0–100
  apiCalls: number;
}

export interface DailyBucket {
  dayStart: string;
  count: number;
}

export interface FilterBreakdown {
  waf_block: number;
  bot_malicious: number;
  policy_deny: number;
  mum_action: number;
  ip_high_risk: number;
  total: number;
}

export interface UnifiedCollection {
  lbName: string;
  namespace: string;
  domains: string[];

  // Phase A — 7-day baseline
  baselineStart: string;
  baselineEnd: string;
  totalRequests7d: number;
  dailyShape: DailyBucket[];
  filterBreakdown: FilterBreakdown;
  topUsers7d: AggBucket[]; // top users across 7 days by volume

  // Phase B — deep scan
  deepStart: string;
  deepEnd: string;
  deepWindowHours: number;
  deepTotalExpected: number;
  deepTotalFetched: number;
  deepCleanLogs: number;
  deepFilterBreakdown: FilterBreakdown;

  /** Per-user per-minute counts from Phase B (clean traffic only) */
  userMinuteCounts: Record<string, number[]>;
  /** All unique user IDs from Phase B */
  allUsers: string[];

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
      console.log(`[Unified] ${label}: retry ${attempt + 1}/${MAX_RETRIES} in ${Math.round(delay)}ms`);
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

function normalizeEntry(raw: unknown): Record<string, unknown> | null {
  if (typeof raw === 'string') { try { return JSON.parse(raw); } catch { return null; } }
  if (raw && typeof raw === 'object') return raw as Record<string, unknown>;
  return null;
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

function buildQuery(lbName: string): string {
  return `{vh_name="ves-io-http-loadbalancer-${lbName}"}`;
}

async function probeCount(ns: string, query: string, start: string, end: string): Promise<number> {
  const r = await probeVolume(ns, 'access_logs', query, start, end);
  return r.totalHits;
}

// ═══════════════════════════════════════════════════════════════════
// MAIN PIPELINE
// ═══════════════════════════════════════════════════════════════════

export async function collectUnified(
  namespace: string,
  lbName: string,
  deepWindowHours: number,
  onProgress: (p: UnifiedProgress) => void,
): Promise<UnifiedCollection> {
  const startMs = Date.now();
  let apiCalls = 0;
  const query = buildQuery(lbName);

  // Time windows
  const now = new Date();
  const endDate = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours()));
  const baselineStart = new Date(endDate.getTime() - 7 * 24 * 3600000).toISOString();
  const baselineEnd = endDate.toISOString();
  const deepStart = new Date(endDate.getTime() - deepWindowHours * 3600000).toISOString();
  const deepEnd = baselineEnd;

  const controller = new AdaptiveConcurrencyController({
    initialConcurrency: 3, minConcurrency: 1, maxConcurrency: 6,
    rampUpAfterSuccesses: 5, rampDownFactor: 0.5,
    yellowDelayMs: 300, redDelayMs: 3000, redCooldownMs: 10000,
  });

  const report = (phase: UnifiedProgress['phase'], stage: string, msg: string, pct: number) =>
    onProgress({ phase, stage, message: msg, progress: pct, apiCalls });

  // ════════════════════════════════════════════════════════════════
  // PHASE A — Weekly Baseline (14 calls, ~5-10s)
  // ════════════════════════════════════════════════════════════════

  // A1: LB config
  report('baseline', 'LB Config', 'Loading LB configuration...', 1);
  let domains: string[] = [];
  try {
    const lb = await withRetry(() => apiClient.getLoadBalancer(namespace, lbName), 'lb-config', controller);
    apiCalls++;
    const spec = (lb as Record<string, unknown>).spec as Record<string, unknown> | undefined;
    domains = (spec?.domains as string[]) ?? [];
  } catch (err) {
    throw new Error(`Cannot load LB "${lbName}": ${err instanceof Error ? err.message : err}`);
  }

  // A2: 7-day total probe
  report('baseline', 'Volume', 'Probing 7-day traffic volume...', 3);
  let totalRequests7d = 0;
  try {
    totalRequests7d = await withRetry(() => probeCount(namespace, query, baselineStart, baselineEnd), '7d-probe', controller);
    apiCalls++;
  } catch { /* non-critical */ }

  // A3: Filter breakdown aggregation (7-day)
  report('baseline', 'Filters', 'Fetching filter breakdown...', 5);
  const filterBreakdown: FilterBreakdown = { waf_block: 0, bot_malicious: 0, policy_deny: 0, mum_action: 0, ip_high_risk: 0, total: 0 };
  try {
    const agg = await withRetry(
      () => fetchBatchAggregation(namespace, 'access_logs', query, baselineStart, baselineEnd, [
        { field: 'waf_action', topk: 10 }, { field: 'bot_class', topk: 10 }, { field: 'ip_risk', topk: 5 },
      ]),
      'filter-agg', controller,
    );
    apiCalls++;
    filterBreakdown.waf_block = agg.waf_action?.filter(b => b.key.toLowerCase() === 'block').reduce((s, b) => s + b.count, 0) ?? 0;
    filterBreakdown.bot_malicious = agg.bot_class?.filter(b => { const k = b.key.toLowerCase(); return k === 'bad_bot' || k === 'malicious'; }).reduce((s, b) => s + b.count, 0) ?? 0;
    filterBreakdown.ip_high_risk = agg.ip_risk?.filter(b => b.key.toLowerCase() === 'high_risk').reduce((s, b) => s + b.count, 0) ?? 0;
    filterBreakdown.total = filterBreakdown.waf_block + filterBreakdown.bot_malicious + filterBreakdown.ip_high_risk;
  } catch { /* non-critical */ }

  // A4: Daily probes (7 calls)
  report('baseline', 'Daily Shape', 'Probing daily traffic shape...', 7);
  const dayMs = 24 * 3600000;
  const dailyShape: DailyBucket[] = [];
  for (let t = new Date(baselineStart).getTime(); t < endDate.getTime(); t += dayMs) {
    const dStart = new Date(t).toISOString();
    const dEnd = new Date(Math.min(t + dayMs, endDate.getTime())).toISOString();
    try {
      const count = await withRetry(() => probeCount(namespace, query, dStart, dEnd), `day-probe`, controller);
      apiCalls++;
      dailyShape.push({ dayStart: dStart, count });
    } catch {
      dailyShape.push({ dayStart: dStart, count: 0 });
      apiCalls++;
    }
  }

  // A5: Top users aggregation (whole 7-day window)
  report('baseline', 'Top Users', 'Identifying top users (7-day)...', 15);
  let topUsers7d: AggBucket[] = [];
  try {
    const result = await withRetry(
      () => fetchBatchAggregation(namespace, 'access_logs', query, baselineStart, baselineEnd, [
        { field: 'user', topk: TOP_USERS_AGG },
      ]),
      'top-users-7d', controller,
    );
    apiCalls++;
    topUsers7d = result.user ?? [];
  } catch { /* non-critical */ }

  console.log(`[Unified] Phase A done: ${totalRequests7d.toLocaleString()} 7d requests, ${dailyShape.length} days, ${topUsers7d.length} top users, ${filterBreakdown.total} filtered`);

  // ════════════════════════════════════════════════════════════════
  // PHASE B — Deep Scan (variable calls)
  // ════════════════════════════════════════════════════════════════

  // B1: Probe deep window
  report('deep', 'Probe', `Probing ${deepWindowHours}h window...`, 20);
  let deepTotalExpected = 0;
  try {
    deepTotalExpected = await withRetry(() => probeCount(namespace, query, deepStart, deepEnd), 'deep-probe', controller);
    apiCalls++;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('index_closed')) throw new Error(`Logs for this time range are unavailable (index closed). Try a more recent window.`);
    throw new Error(`Deep probe failed: ${msg}`);
  }
  if (deepTotalExpected === 0) throw new Error(`No logs for "${lbName}" in the last ${deepWindowHours}h.`);

  // B2: Calculate chunks
  const windowSeconds = deepWindowHours * 3600;
  const rps = deepTotalExpected / windowSeconds;
  let chunkSeconds = Math.floor(TARGET_PER_CHUNK / Math.max(rps, 0.01));
  chunkSeconds = Math.max(chunkSeconds, MIN_CHUNK_SECONDS);
  chunkSeconds = Math.min(chunkSeconds, windowSeconds);

  const chunks: Array<{ start: string; end: string }> = [];
  for (let t = new Date(deepStart).getTime(); t < new Date(deepEnd).getTime(); t += chunkSeconds * 1000) {
    chunks.push({
      start: new Date(t).toISOString(),
      end: new Date(Math.min(t + chunkSeconds * 1000, new Date(deepEnd).getTime())).toISOString(),
    });
  }

  console.log(`[Unified] Phase B: ${deepTotalExpected.toLocaleString()} expected in ${chunks.length} chunks (~${chunkSeconds}s each, ~${Math.round(rps)} rps)`);
  report('deep', 'Scrolling', `Fetching ${deepTotalExpected.toLocaleString()} logs in ${chunks.length} chunks...`, 22);

  // B3: Fetch all chunks with adaptive concurrency
  const allRawLogs: unknown[] = [];
  let chunksDone = 0;
  let chunksActive = 0;
  const chunkQueue = [...chunks];

  await new Promise<void>((resolve) => {
    function dispatch() {
      while (chunksActive < controller.concurrency && chunkQueue.length > 0) {
        const chunk = chunkQueue.shift()!;
        chunksActive++;

        withRetry(
          () => apiClient.post<AccessLogResponse>(
            `/api/data/namespaces/${namespace}/access_logs`,
            { query, namespace, start_time: chunk.start, end_time: chunk.end, scroll: false, limit: PAGE_SIZE },
          ),
          'chunk', controller,
        )
          .then(resp => { if (resp.logs) allRawLogs.push(...resp.logs); })
          .catch(err => {
            const msg = err instanceof Error ? err.message : String(err);
            if (!msg.includes('index_closed')) console.error(`[Unified] Chunk failed:`, msg);
          })
          .finally(() => {
            chunksActive--;
            chunksDone++;
            apiCalls++;
            if (chunksDone % 10 === 0 || chunksDone === chunks.length) {
              const stats = controller.getStats();
              report('deep', 'Scrolling',
                `${allRawLogs.length.toLocaleString()} / ${deepTotalExpected.toLocaleString()} logs — chunk ${chunksDone}/${chunks.length} ×${stats.concurrency}${stats.rateLimitHits > 0 ? ` (${stats.rateLimitHits} retried)` : ''}`,
                22 + Math.round((chunksDone / chunks.length) * 55));
            }
            if (chunksDone === chunks.length) resolve();
            else dispatch();
          });
      }
    }
    if (chunks.length === 0) resolve();
    else dispatch();
  });

  const fetchPct = deepTotalExpected > 0 ? Math.round((allRawLogs.length / deepTotalExpected) * 100) : 100;
  console.log(`[Unified] Phase B scroll: ${allRawLogs.length.toLocaleString()} / ${deepTotalExpected.toLocaleString()} (${fetchPct}%)`);

  // B4: Process — normalize, filter, group
  report('processing', 'Processing', `Processing ${allRawLogs.length.toLocaleString()} entries...`, 80);

  const deepFilter: FilterBreakdown = { waf_block: 0, bot_malicious: 0, policy_deny: 0, mum_action: 0, ip_high_risk: 0, total: 0 };
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
      (deepFilter as unknown as Record<string, number>)[reason] = ((deepFilter as unknown as Record<string, number>)[reason] ?? 0) + 1;
      deepFilter.total++;
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
    `[Unified] DONE: Phase A (${totalRequests7d.toLocaleString()} 7d) + Phase B (${allRawLogs.length.toLocaleString()} fetched, ${cleanCount} clean, ${userMinuteMap.size} users). ` +
    `${apiCalls} calls, ${(runtimeMs / 1000).toFixed(1)}s`
  );

  report('complete', 'Done',
    `${cleanCount.toLocaleString()} clean logs, ${userMinuteMap.size} users — ${apiCalls} API calls in ${(runtimeMs / 1000).toFixed(1)}s`,
    100);

  return {
    lbName, namespace, domains,
    baselineStart, baselineEnd,
    totalRequests7d, dailyShape, filterBreakdown, topUsers7d,
    deepStart, deepEnd, deepWindowHours,
    deepTotalExpected, deepTotalFetched: allRawLogs.length, deepCleanLogs: cleanCount,
    deepFilterBreakdown: deepFilter,
    userMinuteCounts, allUsers: [...allUsersSet],
    apiCallsUsed: apiCalls, runtimeMs,
  };
}
