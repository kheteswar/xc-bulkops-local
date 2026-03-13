import type { AccessLogEntry } from '../rate-limit-advisor/types';
import type { AggregateRateStats, TrafficStats, TrafficProfile } from './types';
import { classifyResponse, getResponseCategory } from '../rate-limit-advisor';
import { buildUserReputationMap } from '../rate-limit-advisor';
import type { ScanResult } from './traffic-scanner';

// ═══════════════════════════════════════════════════════════════════
// TRAFFIC PROFILE CLASSIFICATION
// ═══════════════════════════════════════════════════════════════════

/** Path patterns that indicate API traffic */
const API_PATH_PATTERNS = [
  /^\/api\//i,
  /^\/v[0-9]+\//i,         // /v1/, /v2/, etc.
  /^\/graphql/i,
  /^\/rest\//i,
  /^\/rpc\//i,
  /^\/ws\//i,               // WebSocket API
  /^\/webhook/i,
  /^\/\.well-known\//i,
  /^\/oauth/i,
  /^\/token/i,
  /^\/auth\//i,
  /\/api$/i,
];

/** User agent patterns for classification */
const BROWSER_UA_PATTERNS = [
  /mozilla.*?(chrome|firefox|safari|edge|opera|msie|trident)/i,
  /applewebkit/i,
];
const MOBILE_UA_PATTERNS = [
  /android.*?mobile/i,
  /iphone|ipad|ipod/i,
  /mobile.*?safari/i,
];
const BOT_UA_PATTERNS = [
  /bot\b/i, /crawler/i, /spider/i, /googlebot/i, /bingbot/i,
  /slurp/i, /duckduckbot/i, /yandexbot/i, /baiduspider/i,
  /facebot/i, /ia_archiver/i, /semrush/i, /ahrefs/i,
];
const API_CLIENT_UA_PATTERNS = [
  /^curl\//i, /^python-requests/i, /^python-urllib/i, /^okhttp/i,
  /^axios/i, /^node-fetch/i, /^go-http-client/i, /^java\//i,
  /^ruby/i, /^php/i, /^wget/i, /^postman/i, /^insomnia/i,
  /^httpie/i, /^grpc/i, /^apache-httpclient/i, /^libcurl/i,
];

function classifyUserAgent(ua: string): 'browser' | 'mobile' | 'bot' | 'api' | 'unknown' {
  if (!ua || ua.length === 0) return 'unknown';
  if (MOBILE_UA_PATTERNS.some(p => p.test(ua))) return 'mobile';
  if (BOT_UA_PATTERNS.some(p => p.test(ua))) return 'bot';
  if (API_CLIENT_UA_PATTERNS.some(p => p.test(ua))) return 'api';
  if (BROWSER_UA_PATTERNS.some(p => p.test(ua))) return 'browser';
  return 'unknown';
}

function isApiPath(path: string): boolean {
  return API_PATH_PATTERNS.some(p => p.test(path));
}

function classifyTrafficProfile(accessLogs: AccessLogEntry[]): TrafficProfile {
  const uaBreakdown = { browser: 0, mobile: 0, bot: 0, api: 0, unknown: 0 };
  const pathCounts = new Map<string, { count: number; isApi: boolean }>();
  let apiPathRequests = 0;
  let apiEndpointRequests = 0;

  for (const log of accessLogs) {
    const uaType = classifyUserAgent(log.user_agent || '');
    uaBreakdown[uaType]++;

    const path = log.req_path || '/';
    const segments = path.split('/').filter(Boolean);
    const normalizedPath = '/' + segments.slice(0, 2).join('/');
    const pathIsApi = isApiPath(path) || !!log.api_endpoint;

    if (pathIsApi) apiPathRequests++;
    if (log.api_endpoint) apiEndpointRequests++;

    const existing = pathCounts.get(normalizedPath);
    if (existing) {
      existing.count++;
      if (pathIsApi) existing.isApi = true;
    } else {
      pathCounts.set(normalizedPath, { count: 1, isApi: pathIsApi });
    }
  }

  const total = accessLogs.length || 1;
  const programmaticRequests = uaBreakdown.api + uaBreakdown.bot;
  const browserRequests = uaBreakdown.browser + uaBreakdown.mobile;

  const pathApiPct = (apiPathRequests / total) * 100;
  const uaApiPct = (programmaticRequests / total) * 100;
  const apiPct = Math.round(pathApiPct * 0.6 + uaApiPct * 0.4);
  const webPct = 100 - apiPct;

  let type: TrafficProfile['type'];
  if (apiPct >= 70) type = 'api';
  else if (apiPct <= 30) type = 'web';
  else type = 'mixed';

  if (apiEndpointRequests > total * 0.5) type = 'api';

  const topPaths = [...pathCounts.entries()]
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 15)
    .map(([path, { count, isApi }]) => ({ path, count, isApi }));

  return {
    type,
    apiTrafficPct: apiPct,
    webTrafficPct: webPct,
    hasBrowserTraffic: browserRequests > 0,
    hasProgrammaticTraffic: programmaticRequests > 0,
    topPaths,
    uaBreakdown,
  };
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

function extractTimestamp(log: Record<string, unknown>): Date | null {
  for (const key of ['@timestamp', 'time', 'timestamp', 'date', 'event_time']) {
    const val = log[key];
    if (val) {
      const d = typeof val === 'number' ? new Date(val) : new Date(String(val));
      if (!isNaN(d.getTime())) return d;
    }
  }
  return null;
}

function computePercentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const index = Math.floor((p / 100) * sorted.length);
  return sorted[Math.min(index, sorted.length - 1)];
}

function computeStats(values: number[]): AggregateRateStats {
  if (values.length === 0) {
    return { p50: 0, p75: 0, p90: 0, p95: 0, p99: 0, max: 0, mean: 0, stdDev: 0, sampleCount: 0 };
  }
  const sorted = [...values].sort((a, b) => a - b);
  const sum = sorted.reduce((a, b) => a + b, 0);
  const mean = sum / sorted.length;
  const variance = sorted.reduce((acc, v) => acc + (v - mean) ** 2, 0) / sorted.length;
  const stdDev = Math.sqrt(variance);
  return {
    p50: computePercentile(sorted, 50),
    p75: computePercentile(sorted, 75),
    p90: computePercentile(sorted, 90),
    p95: computePercentile(sorted, 95),
    p99: computePercentile(sorted, 99),
    max: sorted[sorted.length - 1],
    mean: Math.round(mean * 100) / 100,
    stdDev: Math.round(stdDev * 100) / 100,
    sampleCount: sorted.length,
  };
}

// ═══════════════════════════════════════════════════════════════════
// MAIN ANALYSIS — from scan results (probe + peak logs)
// ═══════════════════════════════════════════════════════════════════

/**
 * Analyzes traffic from a lightweight scan result.
 *
 * Uses hourly volumes for overall traffic pattern and time series,
 * and peak hour logs for per-second RPS distribution, traffic profiling,
 * response analysis, and source analysis.
 */
export function analyzeFromScan(scanResult: ScanResult): TrafficStats {
  const { hourlyVolumes, peakLogs, securityEventSample, totalRequestsEstimate, securityEventCount } = scanResult;

  // ─── Per-second RPS from peak logs (most accurate for DDoS thresholds) ───
  const secondBuckets = new Map<string, number>();
  const minuteBuckets = new Map<string, number>();
  // Group second buckets by hour key for per-hour peak RPS
  const hourlySecondBuckets = new Map<string, Map<string, number>>();
  const durations: number[] = [];
  const countryCounts = new Map<string, number>();
  const asnCounts = new Map<string, number>();

  const responseBreakdown = { origin2xx: 0, origin3xx: 0, origin4xx: 0, origin5xx: 0, f5Blocked: 0 };
  let sampleRateSum = 0;
  let sampleRateCount = 0;

  for (const log of peakLogs) {
    // Response classification
    const origin = classifyResponse(log);
    const category = getResponseCategory(log, origin);
    switch (category) {
      case 'origin_2xx': responseBreakdown.origin2xx++; break;
      case 'origin_3xx': responseBreakdown.origin3xx++; break;
      case 'origin_4xx': responseBreakdown.origin4xx++; break;
      case 'origin_5xx': responseBreakdown.origin5xx++; break;
      case 'f5_blocked': responseBreakdown.f5Blocked++; break;
    }

    const sr = typeof log.sample_rate === 'number' && log.sample_rate > 0 ? log.sample_rate : 1;
    sampleRateSum += sr;
    sampleRateCount++;

    const d = extractTimestamp(log as unknown as Record<string, unknown>);
    if (!d) continue;

    const weight = typeof log.sample_rate === 'number' && log.sample_rate > 0 ? 1 / log.sample_rate : 1;

    // Per-second bucket
    const secKey = `${d.getUTCFullYear()}-${d.getUTCMonth()}-${d.getUTCDate()}-${d.getUTCHours()}-${d.getUTCMinutes()}-${d.getUTCSeconds()}`;
    secondBuckets.set(secKey, (secondBuckets.get(secKey) || 0) + weight);

    // Group per-second buckets by hour (using the hourly volume start timestamp)
    const hourKey = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}T${String(d.getUTCHours()).padStart(2, '0')}`;
    if (!hourlySecondBuckets.has(hourKey)) {
      hourlySecondBuckets.set(hourKey, new Map());
    }
    hourlySecondBuckets.get(hourKey)!.set(secKey, (hourlySecondBuckets.get(hourKey)!.get(secKey) || 0) + weight);

    // Per-minute bucket
    const minKey = `${d.getUTCFullYear()}-${d.getUTCMonth()}-${d.getUTCDate()}-${d.getUTCHours()}-${d.getUTCMinutes()}`;
    minuteBuckets.set(minKey, (minuteBuckets.get(minKey) || 0) + weight);

    // Duration
    if (typeof log.total_duration_seconds === 'number' && log.total_duration_seconds > 0) {
      durations.push(log.total_duration_seconds * 1000);
    }

    // Source
    if (log.country && typeof log.country === 'string') {
      countryCounts.set(log.country, (countryCounts.get(log.country) || 0) + 1);
    }
    const asnVal = log.asn || log.as_number;
    if (asnVal && typeof asnVal === 'string') {
      asnCounts.set(asnVal, (asnCounts.get(asnVal) || 0) + 1);
    }
  }

  const avgSampleRate = sampleRateCount > 0 ? sampleRateSum / sampleRateCount : 1;

  // Per-second RPS distribution (from peak logs)
  const rpsValues = [...secondBuckets.values()].map(v => Math.ceil(v));
  const rpmValues = [...minuteBuckets.values()].map(v => Math.ceil(v));
  const aggregateRps = computeStats(rpsValues);
  const aggregateRpm = computeStats(rpmValues);

  // ─── Time series from hourly volumes with peak RPS per hour ───
  let peakRps = aggregateRps.max;
  let peakRpsTimestamp = '';
  let peakRpm = aggregateRpm.max;
  let peakRpmTimestamp = '';

  const timeSeries = hourlyVolumes.map(vol => {
    // Try to find actual per-second peak for this hour from downloaded logs
    const volDate = new Date(vol.start);
    const hourKey = `${volDate.getUTCFullYear()}-${String(volDate.getUTCMonth() + 1).padStart(2, '0')}-${String(volDate.getUTCDate()).padStart(2, '0')}T${String(volDate.getUTCHours()).padStart(2, '0')}`;
    const hourBuckets = hourlySecondBuckets.get(hourKey);

    let hourPeakRps: number;
    if (hourBuckets && hourBuckets.size > 0) {
      // We have per-second data for this hour — compute actual peak
      hourPeakRps = Math.ceil(Math.max(...hourBuckets.values()));
    } else {
      // No per-second data — use avgRps as best estimate
      hourPeakRps = Math.round(vol.avgRps);
    }

    return {
      timestamp: vol.start,
      peakRps: hourPeakRps,
      avgRps: Math.round(vol.avgRps * 100) / 100,
    };
  });

  // Find peak hour for timestamp
  const peakHour = [...hourlyVolumes].sort((a, b) => b.totalHits - a.totalHits)[0];
  if (peakHour) {
    peakRpsTimestamp = peakHour.start;
    peakRpmTimestamp = peakHour.start;
  }

  // Duration stats
  const durationsSorted = [...durations].sort((a, b) => a - b);
  const avgDurationMs = durations.length > 0 ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length) : 0;
  const p95DurationMs = computePercentile(durationsSorted, 95);
  const p99DurationMs = computePercentile(durationsSorted, 99);

  // Top sources
  const topCountries = [...countryCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([country, count]) => ({ country, count }));
  const topAsns = [...asnCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([asn, count]) => ({ asn, count }));

  // Security events analysis (from sample)
  let ddosEventCount = 0;
  let wafEventCount = 0;
  let botEventCount = 0;
  for (const evt of securityEventSample) {
    const type = (evt.sec_event_type || '').toLowerCase();
    if (type.includes('ddos') || type.includes('dos')) ddosEventCount++;
    else if (type.includes('waf')) wafEventCount++;
    else if (type.includes('bot')) botEventCount++;
  }

  // User reputation (from sample)
  const repMap = buildUserReputationMap(securityEventSample);
  const userReputationSummary = { clean: 0, benignBot: 0, flagged: 0, malicious: 0 };
  const seenUsers = new Set<string>();
  for (const log of peakLogs) {
    const uid = log.user || log.src_ip || 'unknown';
    if (seenUsers.has(uid)) continue;
    seenUsers.add(uid);
    const rep = repMap.get(uid);
    if (!rep) userReputationSummary.clean++;
    else {
      switch (rep.reputation) {
        case 'clean': userReputationSummary.clean++; break;
        case 'benign_bot': userReputationSummary.benignBot++; break;
        case 'flagged': userReputationSummary.flagged++; break;
        case 'malicious': userReputationSummary.malicious++; break;
      }
    }
  }

  // Traffic profile (from peak logs)
  const trafficProfile = classifyTrafficProfile(peakLogs);
  console.log(`[TrafficAnalyzer] Traffic profile: ${trafficProfile.type} (API: ${trafficProfile.apiTrafficPct}%, Web: ${trafficProfile.webTrafficPct}%)`);

  return {
    totalRequests: totalRequestsEstimate,
    estimatedActualRequests: totalRequestsEstimate,
    avgSampleRate,
    aggregateRps,
    aggregateRpm,
    timeSeries,
    peakRpsTimestamp,
    peakRps,
    peakRpmTimestamp,
    peakRpm,
    totalSecurityEvents: securityEventCount,
    ddosEventCount,
    wafEventCount,
    botEventCount,
    topCountries,
    topAsns,
    avgDurationMs,
    p95DurationMs,
    p99DurationMs,
    responseBreakdown,
    userReputationSummary,
    trafficProfile,
  };
}
