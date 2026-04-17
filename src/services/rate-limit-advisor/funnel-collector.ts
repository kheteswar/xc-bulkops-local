/**
 * Rate Limit Advisor — Funnel-based data collector
 *
 * Strict API budget: ~15–17 calls for 7-day window, ~7 for 24-hour.
 *
 *   Stage 0 — GET LB config → domains                             (1 call)
 *   Stage 1 — Total probe + daily probes → traffic shape           (1 + N calls, N = windowDays)
 *   Stage 2 — Select peak days (local)                             (0 calls)
 *   Stage 3 — Top-20 src_ip agg per peak day + whole window        (3–4 calls)
 *   Stage 4 — Raw log sample (500 entries) per peak day            (2–3 calls)
 *             Parse timestamps + src_ip client-side → per-user per-minute counts
 *   Stage 5 — Filter breakdown agg                                 (1 call)
 *
 * All calls use adaptive concurrency (max 2) + retry with backoff.
 * 200ms minimum pacing between requests.
 */

import { apiClient } from '../api';
import { AdaptiveConcurrencyController } from '../fp-analyzer/adaptive-concurrency';
import { fetchBatchAggregation, probeVolume } from '../log-analyzer/aggregation-client';

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

const TOP_USERS_PER_AGG = 20;
const MAX_CANDIDATES = 50;
const RAW_SAMPLE_SIZE = 500;
const MAX_RETRIES = 4;
const RETRY_BASE_MS = 2000;
const MIN_PACE_MS = 250;

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

export interface FunnelProgress {
  stage: number;
  stageName: string;
  message: string;
  progress: number;
  apiCalls: number;
}

export interface FilterBreakdown {
  waf_block: number;
  bot_malicious: number;
  policy_deny: number;
  policy_default_deny: number;
  malicious_user: number;
  ip_high_risk: number;
  total: number;
}

export interface FunnelCollection {
  lbName: string;
  namespace: string;
  domains: string[];
  startTime: string;
  endTime: string;
  windowDays: number;
  dailyShape: Array<{ dayStart: string; count: number }>;
  totalRequests: number;
  peakDays: string[];
  candidateUsers: string[];
  userMinuteCounts: Record<string, number[]>;
  filterBreakdown: FilterBreakdown;
  apiCallsUsed: number;
  runtimeMs: number;
}

// ═══════════════════════════════════════════════════════════════════
// RETRY + PACING
// ═══════════════════════════════════════════════════════════════════

function isRateLimitError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  const lower = msg.toLowerCase();
  return msg.includes('429') || lower.includes('too many') || lower.includes('rate limit');
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
    const pace = Math.max(controller.getRequestDelay(), MIN_PACE_MS);
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
      console.log(`[Funnel] ${label}: retry ${attempt + 1}/${MAX_RETRIES} in ${Math.round(delay)}ms [${controller.getState()} ×${controller.concurrency}]`);
      await new Promise(r => setTimeout(r, delay));
    }
  }
  throw new Error('Unreachable');
}

/** Run tasks with adaptive concurrency from the shared controller. */
async function adaptivePool<T>(
  tasks: Array<() => Promise<T>>,
  controller: AdaptiveConcurrencyController,
  onDone?: () => void,
): Promise<Array<{ ok: true; value: T } | { ok: false; error: string }>> {
  const results: Array<{ ok: true; value: T } | { ok: false; error: string }> = new Array(tasks.length);
  const queue = [...tasks.keys()];
  let done = 0;

  await new Promise<void>((resolve) => {
    let active = 0;
    function dispatch() {
      while (active < controller.concurrency && queue.length > 0) {
        const i = queue.shift()!;
        active++;
        tasks[i]()
          .then(v => { results[i] = { ok: true, value: v }; })
          .catch(e => { results[i] = { ok: false, error: e instanceof Error ? e.message : String(e) }; })
          .finally(() => { active--; done++; onDone?.(); if (done === tasks.length) resolve(); else dispatch(); });
      }
    }
    if (tasks.length === 0) resolve(); else dispatch();
  });
  return results;
}

function buildQuery(lbName: string): string {
  return `{vh_name="ves-io-http-loadbalancer-${lbName}"}`;
}

// ═══════════════════════════════════════════════════════════════════
// RAW LOG PARSING
// ═══════════════════════════════════════════════════════════════════

/**
 * Cleaning filter — matches the spec exactly.
 * A request is excluded if ANY of these is true:
 *
 *   waf_action = "block"
 *   bot_defense.insight = "MALICIOUS"  (field name in logs: bot_defense_insight or bot_defense.insight)
 *   policy_hits.result = "deny"        (may be nested in policy_hits array)
 *   policy_hits.result = "default_deny"
 *   malicious_user_mitigation_action ≠ "MUM_NONE" and not empty
 *   ip_risk = "HIGH_RISK"
 */

interface ParsedLogEntry {
  /** The `user` field from the log — what F5 XC uses for rate limiting (e.g., "IP-136.226.234.89") */
  userId: string;
  minuteKey: string; // "YYYY-MM-DDTHH:MM"
  excluded: boolean;
  excludeReason: string;
}

/**
 * Extract policy_hits fields that are NESTED inside policy_hits.policy_hits[0].
 * Based on actual F5 XC log structure:
 *   policy_hits: { policy_hits: [{ result, ip_risk, malicious_user_mitigate_action, ... }] }
 */
function extractPolicyHitFields(entry: Record<string, unknown>): {
  result: string; ipRisk: string; mumAction: string;
} {
  const ph = entry.policy_hits;
  if (ph && typeof ph === 'object') {
    const inner = (ph as Record<string, unknown>).policy_hits;
    if (Array.isArray(inner)) {
      for (const hit of inner) {
        if (hit && typeof hit === 'object') {
          const h = hit as Record<string, unknown>;
          return {
            result: lower(h.result),
            ipRisk: lower(h.ip_risk),
            mumAction: lower(h.malicious_user_mitigate_action),
          };
        }
      }
    }
  }
  return { result: '', ipRisk: '', mumAction: '' };
}

function isExcluded(entry: Record<string, unknown>): { excluded: boolean; reason: string } {
  // 1. WAF action = block (top-level field)
  const wafAction = lower(entry.waf_action);
  if (wafAction === 'block') return { excluded: true, reason: `waf_action=${str(entry.waf_action)}` };

  // 2. Bot defense insight = MALICIOUS (top-level)
  const botInsight = lower(entry.bot_defense_insight) || lower(entry['bot_defense.insight']);
  if (botInsight === 'malicious') return { excluded: true, reason: `bot_defense=MALICIOUS` };

  // 3. Bot class = bad_bot or malicious (top-level)
  const botClass = lower(entry.bot_class);
  if (botClass === 'bad_bot' || botClass === 'malicious') return { excluded: true, reason: `bot_class=${str(entry.bot_class)}` };

  // 4–6. Fields nested inside policy_hits.policy_hits[0]
  const ph = extractPolicyHitFields(entry);

  // 4. Policy result = deny or default_deny
  if (ph.result === 'deny' || ph.result === 'default_deny') return { excluded: true, reason: `policy=${ph.result}` };

  // 5. Malicious user mitigation action ≠ MUM_NONE
  if (ph.mumAction && ph.mumAction !== 'mum_none') return { excluded: true, reason: `mum=${ph.mumAction}` };

  // 6. IP risk = HIGH_RISK
  if (ph.ipRisk === 'high_risk') return { excluded: true, reason: `ip_risk=HIGH_RISK` };

  return { excluded: false, reason: '' };
}

function str(val: unknown): string {
  if (typeof val === 'string') return val;
  if (val === null || val === undefined) return '';
  return String(val);
}

function lower(val: unknown): string {
  return str(val).toLowerCase();
}

/** Extract policy_hits result from various log entry formats */


function parseRawLogs(rawLogs: unknown[]): ParsedLogEntry[] {
  const entries: ParsedLogEntry[] = [];
  for (const raw of rawLogs) {
    let entry: Record<string, unknown>;
    if (typeof raw === 'string') {
      try { entry = JSON.parse(raw); } catch { continue; }
    } else if (raw && typeof raw === 'object') {
      entry = raw as Record<string, unknown>;
    } else continue;

    // Use the `user` field — this is what F5 XC uses for rate limiting.
    // Format: "IP-136.226.234.89" (from User Identification Policy).
    // Fallback to src_ip if user field is missing.
    const userId = str(entry.user) || str(entry.src_ip);
    const ts = str(entry['@timestamp']) || str(entry.time);
    if (!userId || !ts) continue;

    const d = new Date(ts);
    if (isNaN(d.getTime())) continue;
    const minuteKey = ts.slice(0, 16);

    const { excluded, reason } = isExcluded(entry);
    entries.push({ userId, minuteKey, excluded, excludeReason: reason });
  }
  return entries;
}

/**
 * Group parsed entries into per-user per-minute counts.
 * Returns: { "1.2.3.4": [5, 12, 3, 8], "5.6.7.8": [2, 1] }
 * Each array element = requests in one active minute.
 */
function buildUserMinuteCounts(entries: ParsedLogEntry[]): Record<string, number[]> {
  // Group: user → minute → count
  const userMinuteMap = new Map<string, Map<string, number>>();

  for (const { userId, minuteKey, excluded } of entries) {
    if (excluded) continue;
    let minuteMap = userMinuteMap.get(userId);
    if (!minuteMap) { minuteMap = new Map(); userMinuteMap.set(userId, minuteMap); }
    minuteMap.set(minuteKey, (minuteMap.get(minuteKey) ?? 0) + 1);
  }

  // Flatten to arrays of per-minute counts
  const result: Record<string, number[]> = {};
  for (const [userId, minuteMap] of userMinuteMap) {
    result[userId] = [...minuteMap.values()];
  }
  return result;
}

// ═══════════════════════════════════════════════════════════════════
// MAIN PIPELINE
// ═══════════════════════════════════════════════════════════════════

interface AccessLogResponse {
  logs?: unknown[];
  total_hits?: number | string | { value: number };
}

export async function collectFunnel(
  namespace: string,
  lbName: string,
  windowDays: number,
  onProgress: (p: FunnelProgress) => void,
): Promise<FunnelCollection> {
  const startMs = Date.now();
  let apiCalls = 0;
  // Align to UTC midnight boundaries to match XC console's time bucketing
  const now = new Date();
  const endDate = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), now.getUTCHours()));
  const startDate = new Date(endDate.getTime() - windowDays * 24 * 60 * 60 * 1000);
  const endTime = endDate.toISOString();
  const startTime = startDate.toISOString();
  const query = buildQuery(lbName);

  const controller = new AdaptiveConcurrencyController({
    initialConcurrency: 3,
    minConcurrency: 1,
    maxConcurrency: 6,
    rampUpAfterSuccesses: 5,
    rampDownFactor: 0.5,
    yellowDelayMs: 300,
    redDelayMs: 3000,
    redCooldownMs: 10000,
  });

  const report = (stage: number, name: string, msg: string, pct: number) =>
    onProgress({ stage, stageName: name, message: msg, progress: pct, apiCalls });

  // ════════════════════════════════════════════════════════════════
  // STAGE 0 — Discover LB domains (1 call)
  // ════════════════════════════════════════════════════════════════
  report(0, 'Discover', 'Loading LB configuration...', 2);
  let domains: string[] = [];
  try {
    const lb = await withRetry(() => apiClient.getLoadBalancer(namespace, lbName), 'lb-config', controller);
    apiCalls++;
    const spec = (lb as Record<string, unknown>).spec as Record<string, unknown> | undefined;
    domains = (spec?.domains as string[]) ?? [];
    console.log(`[Funnel] Stage 0: "${lbName}" → ${domains.length} domains`);
  } catch (err) {
    throw new Error(`Cannot load LB "${lbName}": ${err instanceof Error ? err.message : err}`);
  }

  // ════════════════════════════════════════════════════════════════
  // STAGE 1 — Total probe + daily traffic shape (1 + N calls)
  // ════════════════════════════════════════════════════════════════
  report(1, 'Traffic Shape', 'Probing total traffic volume...', 5);

  // 1a: Full window probe — this IS the total shown on screen
  let totalRequests: number;
  try {
    const result = await withRetry(
      () => probeVolume(namespace, 'access_logs', query, startTime, endTime),
      'total-probe', controller,
    );
    totalRequests = result.totalHits;
    apiCalls++;
    console.log(`[Funnel] Stage 1: Full window total_hits = ${totalRequests.toLocaleString()}`);
    console.log(`[Funnel] Stage 1: Window: ${startTime} → ${endTime}`);
  } catch (err) {
    throw new Error(`API probe failed for "${lbName}": ${err instanceof Error ? err.message : err}`);
  }

  if (totalRequests === 0) {
    throw new Error(`No access logs for "${lbName}" in the last ${windowDays} day(s). Query: ${query}`);
  }

  // 1b: Full window filter breakdown — direct API call for accurate counts
  //     This queries the FULL dataset via aggregation, not a sample.
  report(1, 'Traffic Shape', `${totalRequests.toLocaleString()} total. Fetching filter breakdown...`, 6);

  const filterBreakdown: FilterBreakdown = {
    waf_block: 0, bot_malicious: 0, policy_deny: 0,
    policy_default_deny: 0, malicious_user: 0, ip_high_risk: 0, total: 0,
  };

  try {
    // Direct API call — NOT through fetchBatchAggregation which swallows errors
    const aggBody = {
      namespace, query, start_time: startTime, end_time: endTime,
      aggs: {
        waf_action_agg: { field: 'waf_action', topk: 10 },
        bot_class_agg: { field: 'bot_class', topk: 10 },
        ip_risk_agg: { field: 'ip_risk', topk: 5 },
      },
    };
    const aggResp = await withRetry(
      () => apiClient.post<Record<string, unknown>>(
        `/api/data/namespaces/${namespace}/access_logs/aggregation`,
        aggBody,
      ),
      'filter-agg', controller,
    );
    apiCalls++;

    const aggs = aggResp.aggs as Record<string, { buckets?: Array<{ key: string; count?: number; doc_count?: number }> }> | undefined;
    console.log('[Funnel] Stage 1 raw agg response keys:', aggs ? Object.keys(aggs) : 'no aggs');

    const getBuckets = (key: string) => aggs?.[key]?.buckets ?? [];
    const countKey = (buckets: Array<{ key: string; count?: number; doc_count?: number }>, match: string) =>
      buckets.filter(b => b.key.toLowerCase() === match).reduce((s, b) => s + (b.count ?? b.doc_count ?? 0), 0);

    const wafBuckets = getBuckets('waf_action_agg');
    const botBuckets = getBuckets('bot_class_agg');
    const riskBuckets = getBuckets('ip_risk_agg');

    console.log('[Funnel] Stage 1 waf_action buckets:', wafBuckets.map(b => `${b.key}:${b.count ?? b.doc_count}`).join(', '));
    console.log('[Funnel] Stage 1 bot_class buckets:', botBuckets.map(b => `${b.key}:${b.count ?? b.doc_count}`).join(', '));
    console.log('[Funnel] Stage 1 ip_risk buckets:', riskBuckets.map(b => `${b.key}:${b.count ?? b.doc_count}`).join(', '));

    filterBreakdown.waf_block = countKey(wafBuckets, 'block');
    filterBreakdown.bot_malicious = botBuckets
      .filter(b => { const k = b.key.toLowerCase(); return k === 'bad_bot' || k === 'malicious'; })
      .reduce((s, b) => s + (b.count ?? b.doc_count ?? 0), 0);
    filterBreakdown.ip_high_risk = countKey(riskBuckets, 'high_risk');
    filterBreakdown.total = filterBreakdown.waf_block + filterBreakdown.bot_malicious +
      filterBreakdown.policy_deny + filterBreakdown.policy_default_deny +
      filterBreakdown.malicious_user + filterBreakdown.ip_high_risk;
  } catch (err) {
    console.error('[Funnel] Stage 1 filter agg FAILED:', err instanceof Error ? err.message : err);
  }

  // 1c: Daily probes for peak day selection
  report(1, 'Traffic Shape', `Probing ${windowDays} daily buckets for peak detection...`, 8);

  const dayMs = 24 * 60 * 60 * 1000;
  const days: Array<{ start: string; end: string }> = [];
  for (let t = new Date(startTime).getTime(); t < new Date(endTime).getTime(); t += dayMs) {
    days.push({
      start: new Date(t).toISOString(),
      end: new Date(Math.min(t + dayMs, new Date(endTime).getTime())).toISOString(),
    });
  }

  const dailyShape: Array<{ dayStart: string; count: number }> = [];
  for (let i = 0; i < days.length; i++) {
    const day = days[i];
    try {
      const result = await withRetry(
        () => probeVolume(namespace, 'access_logs', query, day.start, day.end),
        `day-${i}`, controller,
      );
      apiCalls++;
      dailyShape.push({ dayStart: day.start, count: result.totalHits });
      report(1, 'Traffic Shape', `Day ${i + 1}/${days.length}: ${result.totalHits.toLocaleString()} requests`, 8 + Math.round(((i + 1) / days.length) * 20));
    } catch (err) {
      console.warn(`[Funnel] Day ${i} probe failed:`, err instanceof Error ? err.message : err);
      dailyShape.push({ dayStart: day.start, count: 0 });
      apiCalls++;
    }
  }

  const dailySum = dailyShape.reduce((s, d) => s + d.count, 0);
  console.log(`[Funnel] Stage 1: ${dailyShape.length} daily buckets, daily sum = ${dailySum.toLocaleString()}, full probe = ${totalRequests.toLocaleString()}`);
  for (const d of dailyShape) {
    console.log(`  ${d.dayStart.slice(0, 10)}: ${d.count.toLocaleString()}`);
  }

  // ════════════════════════════════════════════════════════════════
  // STAGE 2 — Select peak days (local)
  // ════════════════════════════════════════════════════════════════
  report(2, 'Select Peaks', 'Identifying busiest days...', 30);
  const sortedDays = [...dailyShape].filter(d => d.count > 0).sort((a, b) => b.count - a.count);
  const nPeakDays = windowDays >= 7 ? 3 : Math.min(2, sortedDays.length);
  const peakDays = sortedDays.slice(0, nPeakDays).map(d => d.dayStart);
  console.log(`[Funnel] Stage 2: ${peakDays.length} peak days, top = ${sortedDays[0]?.count.toLocaleString()}`);

  // ════════════════════════════════════════════════════════════════
  // STAGE 3 — Top-N users per peak day + whole window (3–4 calls)
  // ════════════════════════════════════════════════════════════════
  report(3, 'Top Users', `Identifying heavy users from ${peakDays.length} peak days...`, 35);
  const candidateSet = new Set<string>();

  // Helper: fetch src_ip agg with full diagnostic logging
  // Note: fetchBatchAggregation swallows errors internally, so we also
  // try a direct single-field call if batch returns empty.
  async function fetchTopIps(label: string, start: string, end: string): Promise<string[]> {
    await new Promise(r => setTimeout(r, MIN_PACE_MS));

    // Try batch first
    const batchResult = await fetchBatchAggregation(namespace, 'access_logs', query, start, end, [
      { field: 'user', topk: TOP_USERS_PER_AGG },
    ]);
    apiCalls++;
    const batchIps = batchResult.user ?? [];

    if (batchIps.length > 0) {
      console.log(`[Funnel] Stage 3 (${label}): batch agg → ${batchIps.length} IPs, top: ${batchIps[0]?.key} (${batchIps[0]?.count})`);
      return batchIps.map(b => b.key);
    }

    // Batch returned empty — try direct single-field call
    console.warn(`[Funnel] Stage 3 (${label}): batch agg returned 0 user buckets. Trying direct call...`);

    try {
      const { fetchFieldAggregation } = await import('../log-analyzer/aggregation-client');
      const directResult = await fetchFieldAggregation(namespace, 'access_logs', query, start, end, 'user', TOP_USERS_PER_AGG);
      apiCalls++;

      if (directResult.length > 0) {
        console.log(`[Funnel] Stage 3 (${label}): direct agg → ${directResult.length} IPs, top: ${directResult[0]?.key} (${directResult[0]?.count})`);
        return directResult.map(b => b.key);
      }

      // Both failed — log the raw API response for debugging
      console.error(`[Funnel] Stage 3 (${label}): Both batch and direct agg returned empty.`);
      console.error(`  Query: ${query}`);
      console.error(`  Time: ${start} → ${end}`);

      // Last resort: try fetching raw logs and extracting IPs
      console.log(`[Funnel] Stage 3 (${label}): Falling back to raw log sample for IPs...`);
      const rawResp = await apiClient.post<AccessLogResponse>(
        `/api/data/namespaces/${namespace}/access_logs`,
        { query, namespace, start_time: start, end_time: end, scroll: false, limit: RAW_SAMPLE_SIZE },
      );
      apiCalls++;
      const rawLogs = rawResp.logs ?? [];
      const ipCounts = new Map<string, number>();
      for (const raw of rawLogs) {
        let entry: Record<string, unknown>;
        if (typeof raw === 'string') { try { entry = JSON.parse(raw); } catch { continue; } }
        else if (raw && typeof raw === 'object') { entry = raw as Record<string, unknown>; }
        else continue;
        const ip = (entry.user as string) || (entry.src_ip as string) || '';
        if (ip) ipCounts.set(ip, (ipCounts.get(ip) ?? 0) + 1);
      }
      const topIps = [...ipCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, TOP_USERS_PER_AGG).map(([ip]) => ip);
      console.log(`[Funnel] Stage 3 (${label}): raw log fallback → ${rawLogs.length} logs, ${topIps.length} unique IPs`);
      return topIps;

    } catch (err) {
      console.error(`[Funnel] Stage 3 (${label}): All methods failed:`, err instanceof Error ? err.message : err);
      return [];
    }
  }

  // All peak days + whole window in parallel via adaptive pool
  const stage3Tasks = [
    ...peakDays.map((dayStart, i) => () => {
      const dayEnd = new Date(new Date(dayStart).getTime() + dayMs).toISOString();
      return fetchTopIps(`peak-${i + 1}`, dayStart, dayEnd);
    }),
    () => fetchTopIps('whole-window', startTime, endTime),
  ];

  let s3Done = 0;
  const stage3Results = await adaptivePool(stage3Tasks, controller, () => {
    s3Done++;
    report(3, 'Top Users', `${s3Done}/${stage3Tasks.length} agg calls done (${candidateSet.size} candidates)`, 35 + Math.round((s3Done / stage3Tasks.length) * 10));
  });

  for (const r of stage3Results) {
    if (r.ok) for (const ip of r.value) candidateSet.add(ip);
  }

  if (candidateSet.size === 0) {
    throw new Error(
      'No candidate users found. The user aggregation returned empty for all time windows. ' +
      'Check the browser console for API diagnostics.'
    );
  }
  const candidateUsers = [...candidateSet].slice(0, MAX_CANDIDATES);
  console.log(`[Funnel] Stage 3: ${candidateUsers.length} unique candidates`);

  // ════════════════════════════════════════════════════════════════
  // STAGE 4 — Per-candidate raw log fetch across the full window
  //
  // For each candidate user from Stage 3, fetch THEIR logs specifically
  // using a filtered query: {vh_name="...", src_ip="<candidate>"}
  //
  // This gives us accurate per-user per-minute data for exactly the
  // users the funnel identified as heavy — not random 500-entry samples.
  //
  // Calls: 1 per candidate user (up to MAX_CANDIDATES = 30–50)
  // Each returns up to 500 entries for that user across the full window.
  // ════════════════════════════════════════════════════════════════
  report(4, 'Profile Users', `Fetching logs for ${candidateUsers.length} candidate users (×${controller.concurrency} concurrent)...`, 50);
  const allParsedEntries: ParsedLogEntry[] = [];
  let usersDone = 0;

  const userTasks = candidateUsers.map((user, i) => () =>
    withRetry(
      () => apiClient.post<AccessLogResponse>(
        `/api/data/namespaces/${namespace}/access_logs`,
        {
          query: `{vh_name="ves-io-http-loadbalancer-${lbName}", user="${user}"}`,
          namespace, start_time: startTime, end_time: endTime, scroll: false, limit: RAW_SAMPLE_SIZE,
        },
      ),
      `user-${i}`, controller,
    ).then(resp => {
      const rawLogs = resp.logs ?? [];
      const parsed = parseRawLogs(rawLogs);
      return { user, parsed, rawCount: rawLogs.length };
    })
  );

  const userResults = await adaptivePool(userTasks, controller, () => {
    usersDone++;
    apiCalls++;
    if (usersDone % 5 === 0 || usersDone === candidateUsers.length) {
      const stats = controller.getStats();
      report(4, 'Profile Users',
        `${usersDone}/${candidateUsers.length} users fetched ×${stats.concurrency} [${stats.state}]${stats.rateLimitHits > 0 ? ` ${stats.rateLimitHits} rate-limited` : ''}`,
        50 + Math.round((usersDone / candidateUsers.length) * 30));
    }
  });

  for (const r of userResults) {
    if (!r.ok) continue;
    allParsedEntries.push(...r.value.parsed);
    if (r.value.rawCount > 0) {
      console.log(`[Funnel] Stage 4: ${r.value.user} → ${r.value.rawCount} logs, ${r.value.parsed.filter(e => !e.excluded).length} clean`);
    }
  }

  // Log filter diagnostics
  const excludedEntries = allParsedEntries.filter(e => e.excluded);
  const cleanEntries = allParsedEntries.filter(e => !e.excluded);
  const reasonCounts = new Map<string, number>();
  for (const e of excludedEntries) {
    reasonCounts.set(e.excludeReason, (reasonCounts.get(e.excludeReason) ?? 0) + 1);
  }
  console.log(
    `[Funnel] Stage 4: ${allParsedEntries.length} total entries from ${candidateUsers.length} users → ` +
    `${excludedEntries.length} excluded (${[...reasonCounts.entries()].map(([r, c]) => `${r}: ${c}`).join(', ')}) → ` +
    `${cleanEntries.length} clean`
  );

  // Build per-user per-minute counts from clean entries only
  const userMinuteCounts = buildUserMinuteCounts(allParsedEntries);
  const usersWithData = Object.keys(userMinuteCounts).length;
  const totalActiveMinutes = Object.values(userMinuteCounts).reduce((s, a) => s + a.length, 0);
  console.log(`[Funnel] Stage 4: ${usersWithData} users with per-minute data, ${totalActiveMinutes} active minutes`);

  // Stage 5 filter breakdown already collected in Stage 1 (full dataset aggregation)
  // Log per-user filter stats from raw logs for diagnostic comparison
  console.log(
    `[Funnel] Stage 4 per-user filter stats (from raw logs): ` +
    `${excludedEntries.length} excluded out of ${allParsedEntries.length} entries ` +
    `(${[...reasonCounts.entries()].map(([r, c]) => `${r}: ${c}`).join(', ')})`
  );

  // ════════════════════════════════════════════════════════════════
  // DONE
  // ════════════════════════════════════════════════════════════════
  const runtimeMs = Date.now() - startMs;
  const stats = controller.getStats();
  report(5, 'Complete',
    `${apiCalls} API calls in ${(runtimeMs / 1000).toFixed(1)}s` +
    (stats.rateLimitHits > 0 ? ` (${stats.rateLimitHits} retried after rate limit)` : ''),
    100);

  console.log(`[Funnel] DONE: ${apiCalls} calls, ${(runtimeMs / 1000).toFixed(1)}s, ${usersWithData} users profiled`);

  return {
    lbName, namespace, domains, startTime, endTime, windowDays,
    dailyShape, totalRequests,
    peakDays,
    candidateUsers,
    userMinuteCounts,
    filterBreakdown,
    apiCallsUsed: apiCalls,
    runtimeMs,
  };
}
