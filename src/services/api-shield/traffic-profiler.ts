/**
 * API Shield Advisor — Traffic Profiler
 *
 * Uses F5 XC server-side aggregation instead of raw log scrolling:
 *
 *   1. BATCH AGG  — one request returns top-k buckets for country, rsp_code_class,
 *                   req_path, user_agent, bot_class — covers all field analysis.
 *   2. PROBE      — limit=1 request to get totalHits for avgRps computation.
 *   3. TINY SAMPLE — limit=100 raw logs (no scroll) for avgLatencyMs + peakRps timing.
 *
 * 3 API calls instead of up to N scroll pages. No rate-limit thrashing.
 */

import { apiClient } from '../api';
import { fetchBatchAggregation, probeVolume } from '../log-analyzer/aggregation-client';
import type { AggBucket } from '../log-analyzer/aggregation-client';
import type { TrafficProfileInsight } from './types';

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

/** Raw log records fetched for latency/RPS timing (no scroll — single page) */
const TIMING_SAMPLE_SIZE = 100;

/** Bot UA patterns for classification */
const BOT_UA_PATTERNS = [
  /bot\b/i, /crawler/i, /spider/i, /googlebot/i, /bingbot/i,
  /slurp/i, /curl\//i, /wget/i, /python-requests/i, /go-http-client/i,
  /scrapy/i, /httpclient/i, /libwww/i, /java\//i, /okhttp/i,
];

function isLikelyBot(userAgent: string, botClass: string): boolean {
  if (botClass && botClass !== '' && botClass !== 'good_bot' && botClass !== 'clean') return true;
  return BOT_UA_PATTERNS.some(p => p.test(userAgent));
}

// ═══════════════════════════════════════════════════════════════════
// TYPES (internal)
// ═══════════════════════════════════════════════════════════════════

interface AccessLogResponse {
  logs?: unknown[];
  total_hits?: number | string | { value: number };
}

interface TimingSample {
  timestamp: string;
  durationMs: number;
  sampleRate: number;
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

function parseTimingSample(rawEntries: unknown[]): TimingSample[] {
  let entries = rawEntries;
  if (entries.length > 0 && typeof entries[0] === 'string') {
    entries = entries.map(e => { try { return JSON.parse(e as string); } catch { return {}; } });
  }
  return entries
    .filter(e => e && typeof e === 'object')
    .map(raw => {
      const entry = raw as Record<string, unknown>;
      return {
        timestamp: (entry['@timestamp'] as string) || (entry.time as string) || '',
        durationMs: typeof entry.total_duration_seconds === 'number'
          ? entry.total_duration_seconds * 1000 : 0,
        sampleRate: typeof entry.sample_rate === 'number' && entry.sample_rate > 0
          ? entry.sample_rate : 1,
      };
    });
}

// ═══════════════════════════════════════════════════════════════════
// ANALYSIS
// ═══════════════════════════════════════════════════════════════════

function buildProfile(
  aggBuckets: Record<string, AggBucket[]>,
  timingSamples: TimingSample[],
  totalHits: number,
  sampleRate: number,
  startTime: string,
  endTime: string,
): TrafficProfileInsight {
  const estimatedTotalRequests = sampleRate < 1
    ? Math.round(totalHits / sampleRate) : totalHits;

  const durationSec = Math.max((new Date(endTime).getTime() - new Date(startTime).getTime()) / 1000, 1);
  const avgRps = Math.round((estimatedTotalRequests / durationSec) * 100) / 100;

  // ─── Peak RPS from timing sample ───
  const secondBuckets = new Map<string, number>();
  for (const entry of timingSamples) {
    if (!entry.timestamp) continue;
    const d = new Date(entry.timestamp);
    if (isNaN(d.getTime())) continue;
    const weight = entry.sampleRate < 1 ? 1 / entry.sampleRate : 1;
    const secKey = `${d.getUTCFullYear()}-${d.getUTCMonth()}-${d.getUTCDate()}-${d.getUTCHours()}-${d.getUTCMinutes()}-${d.getUTCSeconds()}`;
    secondBuckets.set(secKey, (secondBuckets.get(secKey) || 0) + weight);
  }
  const rpsValues = [...secondBuckets.values()];
  const peakRps = rpsValues.length > 0 ? Math.ceil(Math.max(...rpsValues)) : 0;

  // ─── Avg latency from timing sample ───
  const latencies = timingSamples.filter(e => e.durationMs > 0).map(e => e.durationMs);
  const avgLatencyMs = latencies.length > 0
    ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length * 100) / 100
    : 0;

  // ─── Top paths from agg ───
  const pathBuckets = aggBuckets.req_path ?? [];
  const topPaths = pathBuckets.slice(0, 20).map(b => {
    const segments = b.key.split('/').filter(Boolean);
    const normalizedPath = '/' + segments.slice(0, 2).join('/');
    return { path: normalizedPath, count: b.count, errorRate: 0 };
  });

  // ─── Top countries from agg ───
  const topCountries = (aggBuckets.country ?? []).slice(0, 15)
    .map(b => ({ country: b.key, count: b.count }));

  // ─── Response code breakdown from rsp_code_class agg ───
  const responseCodeBreakdown: Record<string, number> = {};
  let errorCount = 0;
  let totalCoded = 0;
  for (const b of (aggBuckets.rsp_code_class ?? [])) {
    responseCodeBreakdown[b.key] = b.count;
    totalCoded += b.count;
    if (b.key.startsWith('4') || b.key.startsWith('5')) errorCount += b.count;
  }
  const errorRate = totalCoded > 0
    ? Math.round((errorCount / totalCoded) * 10000) / 100 : 0;

  // ─── Bot traffic from bot_class agg + user_agent agg ───
  let botCount = 0;
  let nonBotCount = 0;
  for (const b of (aggBuckets.bot_class ?? [])) {
    if (isLikelyBot('', b.key)) botCount += b.count;
    else nonBotCount += b.count;
  }
  // Fallback: classify from top user agents if bot_class agg is empty
  if (botCount === 0 && nonBotCount === 0 && (aggBuckets.user_agent ?? []).length > 0) {
    for (const b of (aggBuckets.user_agent ?? [])) {
      if (isLikelyBot(b.key, '')) botCount += b.count;
      else nonBotCount += b.count;
    }
  }
  const totalBotSample = botCount + nonBotCount;
  const botTrafficPercent = totalBotSample > 0
    ? Math.round((botCount / totalBotSample) * 10000) / 100 : 0;

  return {
    totalRequests: estimatedTotalRequests,
    avgRps,
    peakRps,
    topPaths,
    topCountries,
    responseCodeBreakdown,
    errorRate,
    avgLatencyMs,
    botTrafficPercent,
    timeRangeStart: startTime,
    timeRangeEnd: endTime,
    sampleSize: timingSamples.length,
  };
}

// ═══════════════════════════════════════════════════════════════════
// PUBLIC: PROFILE TRAFFIC
// ═══════════════════════════════════════════════════════════════════

/**
 * Profiles traffic for the given LBs over the last 24 hours.
 *
 * Uses server-side aggregation (3 API calls) instead of log scrolling.
 */
export async function profileTraffic(
  namespace: string,
  lbNames: string[],
  onProgress: (msg: string, pct: number) => void
): Promise<TrafficProfileInsight> {
  const endTime = new Date().toISOString();
  const startTime = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  const vhQueries = lbNames.map(name => `vh_name="ves-io-http-loadbalancer-${name}"`);
  const query = vhQueries.length === 1
    ? `{${vhQueries[0]}}`
    : `{${vhQueries.join(' OR ')}}`;

  onProgress('Fetching traffic aggregations...', 10);

  try {
    // Run aggregation, probe, and timing sample in parallel
    const [aggResult, probeResult, sampleResult] = await Promise.allSettled([
      fetchBatchAggregation(namespace, 'access_logs', query, startTime, endTime, [
        { field: 'country', topk: 20 },
        { field: 'rsp_code_class', topk: 10 },
        { field: 'req_path', topk: 25 },
        { field: 'user_agent', topk: 30 },
        { field: 'bot_class', topk: 10 },
        { field: 'waf_action', topk: 10 },
      ]),
      probeVolume(namespace, 'access_logs', query, startTime, endTime),
      apiClient.post<AccessLogResponse>(
        `/api/data/namespaces/${namespace}/access_logs`,
        { query, namespace, start_time: startTime, end_time: endTime, scroll: false, limit: TIMING_SAMPLE_SIZE }
      ),
    ]);

    onProgress('Processing results...', 80);

    const aggBuckets = aggResult.status === 'fulfilled' ? aggResult.value : {};
    const { totalHits, sampleRate } = probeResult.status === 'fulfilled'
      ? probeResult.value : { totalHits: 0, sampleRate: 1 };
    const rawLogs = sampleResult.status === 'fulfilled'
      ? (sampleResult.value.logs ?? []) : [];
    const timingSamples = parseTimingSample(rawLogs);

    if (aggResult.status === 'rejected') {
      console.warn('[TrafficProfiler] Aggregation failed:', aggResult.reason);
    }

    console.log(
      `[TrafficProfiler] Complete: ${totalHits.toLocaleString()} total hits, ` +
      `${Object.keys(aggBuckets).length} agg fields, ${timingSamples.length} timing samples`
    );

    const profile = buildProfile(aggBuckets, timingSamples, totalHits, sampleRate, startTime, endTime);
    onProgress('Traffic profiling complete', 100);
    return profile;
  } catch (err) {
    console.error('[TrafficProfiler] Failed to profile traffic:', err);
    return {
      totalRequests: 0, avgRps: 0, peakRps: 0,
      topPaths: [], topCountries: [],
      responseCodeBreakdown: {}, errorRate: 0,
      avgLatencyMs: 0, botTrafficPercent: 0,
      timeRangeStart: startTime, timeRangeEnd: endTime,
      sampleSize: 0,
    };
  }
}
