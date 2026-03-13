import type { AccessLogEntry } from '../rate-limit-advisor/types';
import type {
  NumericFieldStats, StringFieldStats, TimeSeriesPoint, LogSummary, ClientFilter,
  ErrorAnalysis, PerformanceAnalysis, SecurityInsights, TopTalker, StatusTimeSeriesPoint,
} from './types';
import { FIELD_DEFINITIONS } from './field-definitions';

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = (p / 100) * (sorted.length - 1);
  const lower = Math.floor(idx);
  const upper = Math.ceil(idx);
  if (lower === upper) return sorted[lower];
  return sorted[lower] + (sorted[upper] - sorted[lower]) * (idx - lower);
}

function extractNumeric(log: AccessLogEntry, key: string, parseAsNumber: boolean): number | null {
  const raw = (log as Record<string, unknown>)[key];
  if (raw === undefined || raw === null || raw === '') return null;
  if (typeof raw === 'number') return isFinite(raw) ? raw : null;
  if (parseAsNumber || typeof raw === 'string') {
    const n = parseFloat(String(raw));
    return isFinite(n) ? n : null;
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════
// NUMERIC FIELD STATS
// ═══════════════════════════════════════════════════════════════════

export function computeNumericStats(
  logs: AccessLogEntry[],
  fieldKey: string,
): NumericFieldStats {
  const def = FIELD_DEFINITIONS.find(f => f.key === fieldKey);
  const parseAsNum = def?.parseAsNumber ?? false;
  const label = def?.label ?? fieldKey;

  const values: number[] = [];
  for (const log of logs) {
    const v = extractNumeric(log, fieldKey, parseAsNum);
    if (v !== null) values.push(v);
  }

  if (values.length === 0) {
    return {
      field: fieldKey, label, count: 0, sum: 0, min: 0, max: 0,
      mean: 0, median: 0, stdDev: 0, p50: 0, p75: 0, p90: 0, p95: 0, p99: 0,
      histogram: [],
    };
  }

  values.sort((a, b) => a - b);

  const sum = values.reduce((a, b) => a + b, 0);
  const mean = sum / values.length;
  const variance = values.reduce((acc, v) => acc + (v - mean) ** 2, 0) / values.length;
  const stdDev = Math.sqrt(variance);

  const min = values[0];
  const max = values[values.length - 1];

  // Build histogram (10-20 buckets)
  const bucketCount = Math.min(20, Math.max(5, Math.ceil(Math.sqrt(values.length))));
  const range = max - min;
  const histogram: Array<{ bucket: string; count: number }> = [];

  if (range === 0) {
    histogram.push({ bucket: formatValue(min), count: values.length });
  } else {
    const bucketSize = range / bucketCount;
    const buckets = new Array(bucketCount).fill(0);
    for (const v of values) {
      const idx = Math.min(Math.floor((v - min) / bucketSize), bucketCount - 1);
      buckets[idx]++;
    }
    for (let i = 0; i < bucketCount; i++) {
      const lo = min + i * bucketSize;
      const hi = lo + bucketSize;
      histogram.push({ bucket: `${formatValue(lo)}-${formatValue(hi)}`, count: buckets[i] });
    }
  }

  return {
    field: fieldKey,
    label,
    count: values.length,
    sum,
    min,
    max,
    mean,
    median: percentile(values, 50),
    stdDev,
    p50: percentile(values, 50),
    p75: percentile(values, 75),
    p90: percentile(values, 90),
    p95: percentile(values, 95),
    p99: percentile(values, 99),
    histogram,
  };
}

function formatValue(v: number): string {
  if (Number.isInteger(v)) return v.toLocaleString();
  if (Math.abs(v) < 0.001) return v.toExponential(2);
  return v.toFixed(3);
}

// ═══════════════════════════════════════════════════════════════════
// STRING FIELD STATS
// ═══════════════════════════════════════════════════════════════════

export function computeStringStats(
  logs: AccessLogEntry[],
  fieldKey: string,
  topN: number = 0,
): StringFieldStats {
  const def = FIELD_DEFINITIONS.find(f => f.key === fieldKey);
  const label = def?.label ?? fieldKey;

  const counts = new Map<string, number>();
  let total = 0;

  for (const log of logs) {
    const raw = (log as Record<string, unknown>)[fieldKey];
    const val = raw === undefined || raw === null ? '(empty)' : String(raw);
    counts.set(val, (counts.get(val) || 0) + 1);
    total++;
  }

  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  const topValues = (topN > 0 ? sorted.slice(0, topN) : sorted).map(([value, count]) => ({
    value,
    count,
    percentage: total > 0 ? (count / total) * 100 : 0,
  }));

  return {
    field: fieldKey,
    label,
    totalCount: total,
    uniqueCount: counts.size,
    topValues,
  };
}

// ═══════════════════════════════════════════════════════════════════
// BOOLEAN FIELD STATS (returned as StringFieldStats)
// ═══════════════════════════════════════════════════════════════════

export function computeBooleanStats(
  logs: AccessLogEntry[],
  fieldKey: string,
): StringFieldStats {
  const def = FIELD_DEFINITIONS.find(f => f.key === fieldKey);
  const label = def?.label ?? fieldKey;

  let trueCount = 0;
  let falseCount = 0;

  for (const log of logs) {
    const raw = (log as Record<string, unknown>)[fieldKey];
    if (raw === true || raw === 'true') trueCount++;
    else falseCount++;
  }

  const total = trueCount + falseCount;
  return {
    field: fieldKey,
    label,
    totalCount: total,
    uniqueCount: 2,
    topValues: [
      { value: 'true', count: trueCount, percentage: total > 0 ? (trueCount / total) * 100 : 0 },
      { value: 'false', count: falseCount, percentage: total > 0 ? (falseCount / total) * 100 : 0 },
    ],
  };
}

// ═══════════════════════════════════════════════════════════════════
// TIME SERIES
// ═══════════════════════════════════════════════════════════════════

export function buildTimeSeries(
  logs: AccessLogEntry[],
  rangeHours: number,
): TimeSeriesPoint[] {
  if (logs.length === 0) return [];

  // Auto-select bucket size
  let bucketMinutes: number;
  if (rangeHours <= 1) bucketMinutes = 1;
  else if (rangeHours <= 6) bucketMinutes = 5;
  else if (rangeHours <= 24) bucketMinutes = 15;
  else if (rangeHours <= 168) bucketMinutes = 60;
  else bucketMinutes = 120;

  const bucketMs = bucketMinutes * 60 * 1000;
  const buckets = new Map<number, number>();

  for (const log of logs) {
    const ts = log['@timestamp'] || log.time;
    if (!ts) continue;
    const t = new Date(ts).getTime();
    if (!isFinite(t)) continue;
    const bucket = Math.floor(t / bucketMs) * bucketMs;
    buckets.set(bucket, (buckets.get(bucket) || 0) + 1);
  }

  const sorted = [...buckets.entries()].sort((a, b) => a[0] - b[0]);

  // Fill gaps with zeros
  if (sorted.length > 1) {
    const filled: Array<[number, number]> = [];
    for (let i = 0; i < sorted.length; i++) {
      filled.push(sorted[i]);
      if (i < sorted.length - 1) {
        let next = sorted[i][0] + bucketMs;
        while (next < sorted[i + 1][0]) {
          filled.push([next, 0]);
          next += bucketMs;
        }
      }
    }
    return filled.map(([ts, count]) => {
      const d = new Date(ts);
      const label = bucketMinutes >= 60
        ? `${(d.getMonth() + 1).toString().padStart(2, '0')}/${d.getDate().toString().padStart(2, '0')} ${d.getHours().toString().padStart(2, '0')}:00`
        : `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
      return { timestamp: d.toISOString(), count, label };
    });
  }

  return sorted.map(([ts, count]) => {
    const d = new Date(ts);
    return { timestamp: d.toISOString(), count, label: d.toISOString() };
  });
}

// ═══════════════════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════════════════

export function computeSummary(logs: AccessLogEntry[]): LogSummary {
  if (logs.length === 0) {
    return { totalLogs: 0, uniqueIPs: 0, uniquePaths: 0, uniqueDomains: 0, avgDurationMs: 0, errorRate: 0 };
  }

  const ips = new Set<string>();
  const paths = new Set<string>();
  const domains = new Set<string>();
  let totalDuration = 0;
  let durationCount = 0;
  let errorCount = 0;

  for (const log of logs) {
    if (log.src_ip) ips.add(log.src_ip);
    if (log.req_path) paths.add(log.req_path);
    if (log.domain) domains.add(log.domain);

    const dur = typeof log.total_duration_seconds === 'number' ? log.total_duration_seconds : parseFloat(String(log.total_duration_seconds));
    if (isFinite(dur)) { totalDuration += dur; durationCount++; }

    const code = log.rsp_code ? parseInt(log.rsp_code, 10) : 0;
    if (code >= 400) errorCount++;
  }

  return {
    totalLogs: logs.length,
    uniqueIPs: ips.size,
    uniquePaths: paths.size,
    uniqueDomains: domains.size,
    avgDurationMs: durationCount > 0 ? (totalDuration / durationCount) * 1000 : 0,
    errorRate: (errorCount / logs.length) * 100,
  };
}

// ═══════════════════════════════════════════════════════════════════
// CLIENT-SIDE FILTERING
// ═══════════════════════════════════════════════════════════════════

export function applyClientFilters(
  logs: AccessLogEntry[],
  filters: ClientFilter[],
): AccessLogEntry[] {
  if (filters.length === 0) return logs;

  return logs.filter(log => {
    return filters.every(f => {
      const raw = (log as Record<string, unknown>)[f.field];
      const val = raw === undefined || raw === null ? '' : String(raw);

      switch (f.operator) {
        case 'equals':
          return val === f.value;
        case 'not_equals':
          return val !== f.value;
        case 'contains':
          return val.toLowerCase().includes(f.value.toLowerCase());
        case 'regex':
          try { return new RegExp(f.value, 'i').test(val); }
          catch { return false; }
        default:
          return true;
      }
    });
  });
}

// ═══════════════════════════════════════════════════════════════════
// ERROR ANALYSIS
// ═══════════════════════════════════════════════════════════════════

export function computeErrorAnalysis(logs: AccessLogEntry[]): ErrorAnalysis {
  const total = logs.length;
  const errors = logs.filter(l => {
    const code = parseInt(l.rsp_code, 10);
    return code >= 400 || code === 0;
  });

  const byCode = countAndSort(errors, 'rsp_code');
  const byCodeClass = countAndSort(errors, 'rsp_code_class');
  const byDetail = countAndSort(errors, 'rsp_code_details');

  // Response flags — parse JSON string
  const flagCounts = new Map<string, number>();
  for (const log of errors) {
    const raw = (log as Record<string, unknown>).response_flags;
    if (!raw || raw === '{}') { flagCounts.set('(none)', (flagCounts.get('(none)') || 0) + 1); continue; }
    try {
      const flags = typeof raw === 'string' ? JSON.parse(raw) : raw;
      const keys = Object.keys(flags as Record<string, unknown>);
      const label = keys.length > 0 ? keys.join(', ') : '(none)';
      flagCounts.set(label, (flagCounts.get(label) || 0) + 1);
    } catch { flagCounts.set(String(raw).slice(0, 60), (flagCounts.get(String(raw)) || 0) + 1); }
  }

  // Error rate by path
  const pathTotal = new Map<string, number>();
  const pathErrors = new Map<string, number>();
  for (const l of logs) {
    const p = l.req_path || '(empty)';
    pathTotal.set(p, (pathTotal.get(p) || 0) + 1);
  }
  for (const l of errors) {
    const p = l.req_path || '(empty)';
    pathErrors.set(p, (pathErrors.get(p) || 0) + 1);
  }
  const byPath = [...pathErrors.entries()]
    .map(([path, count]) => ({ path, count, errorRate: (count / (pathTotal.get(path) || 1)) * 100 }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 30);

  // Error by source IP
  const ipTotal = new Map<string, number>();
  const ipErrors = new Map<string, { count: number; country: string }>();
  for (const l of logs) { ipTotal.set(l.src_ip || '', (ipTotal.get(l.src_ip || '') || 0) + 1); }
  for (const l of errors) {
    const ip = l.src_ip || '';
    const prev = ipErrors.get(ip) || { count: 0, country: l.country || '' };
    prev.count++;
    ipErrors.set(ip, prev);
  }
  const bySource = [...ipErrors.entries()]
    .map(([ip, { count, country }]) => ({ ip, count, errorRate: (count / (ipTotal.get(ip) || 1)) * 100, country }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  return {
    totalErrors: errors.length,
    errorRate: total > 0 ? (errors.length / total) * 100 : 0,
    byCode: byCode.map(v => ({ code: v.value, count: v.count, pct: (v.count / errors.length) * 100 })),
    byCodeClass: byCodeClass.map(v => ({ cls: v.value, count: v.count, pct: (v.count / errors.length) * 100 })),
    byPath,
    bySource,
    byDetail: byDetail.map(v => ({ detail: v.value, count: v.count, pct: (v.count / errors.length) * 100 })),
    byResponseFlag: [...flagCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([flag, count]) => ({ flag, count, pct: (count / errors.length) * 100 })),
  };
}

function countAndSort(logs: AccessLogEntry[], field: string): Array<{ value: string; count: number }> {
  const counts = new Map<string, number>();
  for (const l of logs) {
    const v = (l as Record<string, unknown>)[field];
    const s = v === undefined || v === null ? '(empty)' : String(v);
    counts.set(s, (counts.get(s) || 0) + 1);
  }
  return [...counts.entries()].map(([value, count]) => ({ value, count })).sort((a, b) => b.count - a.count);
}

// ═══════════════════════════════════════════════════════════════════
// PERFORMANCE ANALYSIS
// ═══════════════════════════════════════════════════════════════════

export function computePerformanceAnalysis(logs: AccessLogEntry[]): PerformanceAnalysis {
  const durations: number[] = [];
  for (const l of logs) {
    const d = parseDuration(l);
    if (d !== null) durations.push(d);
  }
  durations.sort((a, b) => a - b);

  const overall = durations.length > 0 ? {
    p50: percentile(durations, 50),
    p90: percentile(durations, 90),
    p95: percentile(durations, 95),
    p99: percentile(durations, 99),
    max: durations[durations.length - 1],
    mean: durations.reduce((a, b) => a + b, 0) / durations.length,
  } : { p50: 0, p90: 0, p95: 0, p99: 0, max: 0, mean: 0 };

  // Slowest requests
  const withDur = logs
    .map(l => ({ log: l, dur: parseDuration(l) ?? 0 }))
    .sort((a, b) => b.dur - a.dur)
    .slice(0, 25);
  const slowRequests = withDur.map(({ log: l, dur }) => ({
    timestamp: l['@timestamp'] || l.time || '',
    method: l.method || '',
    path: l.req_path || '',
    code: l.rsp_code || '',
    durationS: dur,
    srcIp: l.src_ip || '',
    country: l.country || '',
    detail: l.rsp_code_details || '',
  }));

  // Latency by path
  const pathDurations = new Map<string, number[]>();
  for (const l of logs) {
    const d = parseDuration(l);
    if (d === null) continue;
    const p = l.req_path || '(empty)';
    if (!pathDurations.has(p)) pathDurations.set(p, []);
    pathDurations.get(p)!.push(d);
  }
  const byPath = [...pathDurations.entries()]
    .map(([path, durs]) => {
      durs.sort((a, b) => a - b);
      return {
        path,
        count: durs.length,
        avgMs: (durs.reduce((a, b) => a + b, 0) / durs.length) * 1000,
        p95Ms: percentile(durs, 95) * 1000,
        maxMs: durs[durs.length - 1] * 1000,
      };
    })
    .sort((a, b) => b.p95Ms - a.p95Ms)
    .slice(0, 20);

  // Latency by country
  const countryDurations = new Map<string, number[]>();
  for (const l of logs) {
    const d = parseDuration(l);
    if (d === null) continue;
    const c = l.country || '(unknown)';
    if (!countryDurations.has(c)) countryDurations.set(c, []);
    countryDurations.get(c)!.push(d);
  }
  const byCountry = [...countryDurations.entries()]
    .map(([country, durs]) => {
      durs.sort((a, b) => a - b);
      return {
        country,
        count: durs.length,
        avgMs: (durs.reduce((a, b) => a + b, 0) / durs.length) * 1000,
        p95Ms: percentile(durs, 95) * 1000,
      };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  // Latency by site
  const siteDurations = new Map<string, number[]>();
  for (const l of logs) {
    const d = parseDuration(l);
    if (d === null) continue;
    const s = l.src_site || l.site || '(unknown)';
    if (!siteDurations.has(s)) siteDurations.set(s, []);
    siteDurations.get(s)!.push(d);
  }
  const bySite = [...siteDurations.entries()]
    .map(([site, durs]) => {
      durs.sort((a, b) => a - b);
      return {
        site,
        count: durs.length,
        avgMs: (durs.reduce((a, b) => a + b, 0) / durs.length) * 1000,
        p95Ms: percentile(durs, 95) * 1000,
      };
    })
    .sort((a, b) => b.count - a.count);

  return { overall, slowRequests, byPath, byCountry, bySite };
}

function parseDuration(l: AccessLogEntry): number | null {
  const raw = (l as Record<string, unknown>).total_duration_seconds
    ?? (l as Record<string, unknown>).duration_with_data_tx_delay;
  if (raw === undefined || raw === null || raw === '') return null;
  const v = typeof raw === 'number' ? raw : parseFloat(String(raw));
  return isFinite(v) ? v : null;
}

// ═══════════════════════════════════════════════════════════════════
// SECURITY INSIGHTS
// ═══════════════════════════════════════════════════════════════════

export function computeSecurityInsights(logs: AccessLogEntry[]): SecurityInsights {
  const total = logs.length;

  // WAF actions
  const wafCounts = new Map<string, number>();
  for (const l of logs) {
    const a = (l as Record<string, unknown>).waf_action;
    const v = !a ? '(none)' : String(a);
    wafCounts.set(v, (wafCounts.get(v) || 0) + 1);
  }
  const wafActions = [...wafCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([action, count]) => ({ action, count, pct: (count / total) * 100 }));

  // Bot classes
  const botCounts = new Map<string, number>();
  for (const l of logs) {
    const b = (l as Record<string, unknown>).bot_class;
    const v = !b ? '(none)' : String(b);
    botCounts.set(v, (botCounts.get(v) || 0) + 1);
  }
  const botClasses = [...botCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([cls, count]) => ({ cls, count, pct: (count / total) * 100 }));

  // Top blocked IPs (waf_action = block or rsp_code_details contains blocked/denied)
  const blockedIPs = new Map<string, { count: number; country: string; wafAction: string }>();
  for (const l of logs) {
    const waf = String((l as Record<string, unknown>).waf_action || '');
    const detail = String(l.rsp_code_details || '').toLowerCase();
    if (waf === 'block' || detail.includes('blocked') || detail.includes('denied') || detail.includes('ext_authz')) {
      const ip = l.src_ip || '';
      const prev = blockedIPs.get(ip) || { count: 0, country: l.country || '', wafAction: waf || detail };
      prev.count++;
      blockedIPs.set(ip, prev);
    }
  }
  const topBlockedIPs = [...blockedIPs.entries()]
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 20)
    .map(([ip, d]) => ({ ip, count: d.count, country: d.country, wafAction: d.wafAction }));

  // Policy hit results
  const policyCounts = new Map<string, number>();
  for (const l of logs) {
    const ph = (l as Record<string, unknown>).policy_hits as { policy_hits?: Array<{ result?: string }> } | undefined;
    if (ph?.policy_hits) {
      for (const hit of ph.policy_hits) {
        const r = hit.result || '(unknown)';
        policyCounts.set(r, (policyCounts.get(r) || 0) + 1);
      }
    }
  }
  const policyHitResults = [...policyCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([result, count]) => ({ result, count, pct: (count / Math.max(1, [...policyCounts.values()].reduce((a, b) => a + b, 0))) * 100 }));

  // Suspicious paths (paths with high block rate)
  const pathTotal = new Map<string, number>();
  const pathBlocked = new Map<string, number>();
  for (const l of logs) {
    const p = l.req_path || '(empty)';
    pathTotal.set(p, (pathTotal.get(p) || 0) + 1);
    const waf = String((l as Record<string, unknown>).waf_action || '');
    const detail = String(l.rsp_code_details || '').toLowerCase();
    if (waf === 'block' || detail.includes('blocked') || detail.includes('denied')) {
      pathBlocked.set(p, (pathBlocked.get(p) || 0) + 1);
    }
  }
  const suspiciousPaths = [...pathBlocked.entries()]
    .map(([path, count]) => ({ path, count, blockedPct: (count / (pathTotal.get(path) || 1)) * 100 }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  return { wafActions, botClasses, topBlockedIPs, policyHitResults, suspiciousPaths };
}

// ═══════════════════════════════════════════════════════════════════
// TOP TALKERS
// ═══════════════════════════════════════════════════════════════════

export function computeTopTalkers(logs: AccessLogEntry[], topN: number = 25): TopTalker[] {
  const ipData = new Map<string, {
    requests: number; errors: number; bandwidth: number;
    country: string; asOrg: string; paths: Map<string, number>;
    botClass: string; wafBlocked: number;
  }>();

  for (const l of logs) {
    const ip = l.src_ip || '(unknown)';
    if (!ipData.has(ip)) {
      ipData.set(ip, {
        requests: 0, errors: 0, bandwidth: 0,
        country: l.country || '', asOrg: (l as Record<string, unknown>).as_org as string || '',
        paths: new Map(), botClass: (l as Record<string, unknown>).bot_class as string || '',
        wafBlocked: 0,
      });
    }
    const d = ipData.get(ip)!;
    d.requests++;
    const code = parseInt(l.rsp_code, 10);
    if (code >= 400 || code === 0) d.errors++;
    d.bandwidth += parseInt(l.rsp_size || '0', 10) || 0;
    const p = l.req_path || '/';
    d.paths.set(p, (d.paths.get(p) || 0) + 1);
    const waf = String((l as Record<string, unknown>).waf_action || '');
    if (waf === 'block') d.wafBlocked++;
  }

  return [...ipData.entries()]
    .map(([ip, d]) => {
      const topPath = [...d.paths.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || '/';
      return {
        ip, requests: d.requests, errors: d.errors,
        errorRate: (d.errors / d.requests) * 100,
        bandwidth: d.bandwidth, country: d.country, asOrg: d.asOrg,
        topPath, botClass: d.botClass, wafBlocked: d.wafBlocked,
      };
    })
    .sort((a, b) => b.requests - a.requests)
    .slice(0, topN);
}

// ═══════════════════════════════════════════════════════════════════
// STATUS TIME SERIES (stacked by response class)
// ═══════════════════════════════════════════════════════════════════

export function buildStatusTimeSeries(logs: AccessLogEntry[], rangeHours: number): StatusTimeSeriesPoint[] {
  if (logs.length === 0) return [];

  let bucketMinutes: number;
  if (rangeHours <= 1) bucketMinutes = 1;
  else if (rangeHours <= 6) bucketMinutes = 5;
  else if (rangeHours <= 24) bucketMinutes = 15;
  else if (rangeHours <= 168) bucketMinutes = 60;
  else bucketMinutes = 120;

  const bucketMs = bucketMinutes * 60 * 1000;
  const buckets = new Map<number, { '2xx': number; '3xx': number; '4xx': number; '5xx': number; other: number }>();

  for (const log of logs) {
    const ts = log['@timestamp'] || log.time;
    if (!ts) continue;
    const t = new Date(ts).getTime();
    if (!isFinite(t)) continue;
    const bucket = Math.floor(t / bucketMs) * bucketMs;
    if (!buckets.has(bucket)) buckets.set(bucket, { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0, other: 0 });
    const b = buckets.get(bucket)!;
    const cls = log.rsp_code_class || '';
    if (cls === '2xx') b['2xx']++;
    else if (cls === '3xx') b['3xx']++;
    else if (cls === '4xx') b['4xx']++;
    else if (cls === '5xx') b['5xx']++;
    else b.other++;
  }

  const sorted = [...buckets.entries()].sort((a, b) => a[0] - b[0]);

  // Fill gaps
  const filled: Array<[number, typeof sorted[0][1]]> = [];
  for (let i = 0; i < sorted.length; i++) {
    filled.push(sorted[i]);
    if (i < sorted.length - 1) {
      let next = sorted[i][0] + bucketMs;
      while (next < sorted[i + 1][0]) {
        filled.push([next, { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0, other: 0 }]);
        next += bucketMs;
      }
    }
  }

  return filled.map(([ts, data]) => {
    const d = new Date(ts);
    const label = bucketMinutes >= 60
      ? `${(d.getMonth() + 1).toString().padStart(2, '0')}/${d.getDate().toString().padStart(2, '0')} ${d.getHours().toString().padStart(2, '0')}:00`
      : `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
    return { timestamp: d.toISOString(), label, ...data };
  });
}
