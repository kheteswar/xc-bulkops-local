/**
 * FP Analyzer — Structured Operation Logger with PII Anonymization
 *
 * Captures detailed logs of the entire analysis pipeline for troubleshooting.
 * All PII (IPs, users, user agents, domains, paths with query params) is
 * anonymized before being stored.
 */

// ═══════════════════════════════════════════════════════════════
// PII ANONYMIZATION
// ═══════════════════════════════════════════════════════════════

/** One-way hash for consistent anonymization (same input → same output within a session) */
function simpleHash(input: string): string {
  let h = 0;
  for (let i = 0; i < input.length; i++) {
    h = ((h << 5) - h + input.charCodeAt(i)) | 0;
  }
  return Math.abs(h).toString(36).slice(0, 8);
}

const anonCache = new Map<string, string>();

function anonymize(value: string, prefix: string): string {
  if (!value) return '';
  const key = `${prefix}:${value}`;
  if (anonCache.has(key)) return anonCache.get(key)!;
  const anon = `${prefix}_${simpleHash(value)}`;
  anonCache.set(key, anon);
  return anon;
}

/** Mask an IP address: 192.168.1.100 → ip_a3f2b1c0 */
export function anonIP(ip: string): string {
  return anonymize(ip, 'ip');
}

/** Mask a user identifier: user@domain.com → user_b7e3d2a1 */
export function anonUser(user: string): string {
  return anonymize(user, 'user');
}

/** Redact user agent to browser family only: "Mozilla/5.0 ... Chrome/120" → "Chrome-family" */
export function anonUA(ua: string): string {
  if (!ua) return '';
  if (/chrome/i.test(ua) && !/edge|opr/i.test(ua)) return 'Chrome-family';
  if (/firefox/i.test(ua)) return 'Firefox-family';
  if (/safari/i.test(ua) && !/chrome/i.test(ua)) return 'Safari-family';
  if (/edge|edg/i.test(ua)) return 'Edge-family';
  if (/opr|opera/i.test(ua)) return 'Opera-family';
  if (/bingbot/i.test(ua)) return 'Bingbot';
  if (/googlebot/i.test(ua)) return 'Googlebot';
  if (/bot|spider|crawler/i.test(ua)) return 'Bot/Crawler';
  if (/python|curl|wget|go-http|java|node/i.test(ua)) return 'Scripting-tool';
  return 'Other-UA';
}

/** Anonymize domain: www.example.com → domain_c4e1f2a3 */
export function anonDomain(domain: string): string {
  return anonymize(domain, 'domain');
}

/** Sanitize path: keep structure, strip query params */
export function sanitizePath(path: string): string {
  if (!path) return '';
  // Remove query string
  const qIdx = path.indexOf('?');
  return qIdx >= 0 ? path.slice(0, qIdx) : path;
}

// ═══════════════════════════════════════════════════════════════
// LOG ENTRY TYPES
// ═══════════════════════════════════════════════════════════════

export type LogLevel = 'info' | 'warn' | 'error' | 'debug';

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  phase: string;
  message: string;
  data?: Record<string, unknown>;
}

// ═══════════════════════════════════════════════════════════════
// ANALYSIS LOGGER CLASS
// ═══════════════════════════════════════════════════════════════

export class AnalysisLogger {
  private entries: LogEntry[] = [];
  private startTime: number = Date.now();

  constructor() {
    this.reset();
  }

  reset(): void {
    this.entries = [];
    this.startTime = Date.now();
    anonCache.clear();
  }

  private elapsed(): string {
    return `+${((Date.now() - this.startTime) / 1000).toFixed(1)}s`;
  }

  private add(level: LogLevel, phase: string, message: string, data?: Record<string, unknown>): void {
    this.entries.push({
      timestamp: `${new Date().toISOString()} (${this.elapsed()})`,
      level,
      phase,
      message,
      data,
    });
  }

  info(phase: string, message: string, data?: Record<string, unknown>): void {
    this.add('info', phase, message, data);
  }

  warn(phase: string, message: string, data?: Record<string, unknown>): void {
    this.add('warn', phase, message, data);
  }

  error(phase: string, message: string, data?: Record<string, unknown>): void {
    this.add('error', phase, message, data);
  }

  debug(phase: string, message: string, data?: Record<string, unknown>): void {
    this.add('debug', phase, message, data);
  }

  // ───── PIPELINE LOGGING HELPERS ─────

  logAnalysisStart(config: {
    namespace: string;
    lbName: string;
    domains: string[];
    scopes: string[];
    hoursBack: number;
    startTime: string;
    endTime: string;
  }): void {
    this.info('config', 'Analysis started', {
      namespace: config.namespace,
      lbName: config.lbName,
      domains: config.domains.map(d => anonDomain(d)),
      scopes: config.scopes,
      hoursBack: config.hoursBack,
      timeRange: `${config.startTime} → ${config.endTime}`,
    });
  }

  logSecurityEventsFetched(totalRaw: number, totalFiltered: number, removedFromOtherLBs: number): void {
    this.info('fetch-security', 'Security events fetched', {
      totalRaw,
      totalFiltered,
      removedFromOtherLBs,
    });
    if (removedFromOtherLBs > 0) {
      this.warn('fetch-security', `Removed ${removedFromOtherLBs} events from other LBs (client-side filter)`);
    }
  }

  logIndexingResults(stats: {
    totalEvents: number;
    wafEvents: number;
    threatMeshEvents: number;
    policyEvents: number;
    uniqueSignatures: number;
    uniqueViolations: number;
    uniqueThreatMeshIPs: number;
  }): void {
    this.info('indexing', 'Security event indexes built', stats);
  }

  logAccessLogsFetched(total: number, pathsAggregated: number): void {
    this.info('fetch-access', 'Access logs fetched and aggregated', {
      totalAccessLogs: total,
      pathsAggregated,
    });
  }

  logSignatureAnalysis(sigId: string, sigName: string, contextKey: string, signals: {
    composite: number;
    verdict: string;
    userBreadth: number;
    requestBreadth: number;
    pathBreadth: number;
    contextAnalysis: number;
    clientProfile: number;
    temporalPattern: number;
    signatureAccuracy: number;
    override?: string;
    flaggedUsers: number;
    totalUsers: number;
    flaggedRequests: number;
    totalRequests: number;
    pathCount: number;
  }): void {
    this.debug('sig-analysis', `Sig ${sigId} (${sigName}) @ ${sanitizePath(contextKey)}`, {
      composite: signals.composite,
      verdict: signals.verdict,
      signals: {
        userBreadth: signals.userBreadth,
        requestBreadth: signals.requestBreadth,
        pathBreadth: signals.pathBreadth,
        contextAnalysis: signals.contextAnalysis,
        clientProfile: signals.clientProfile,
        temporalPattern: signals.temporalPattern,
        signatureAccuracy: signals.signatureAccuracy,
      },
      override: signals.override || null,
      ratios: {
        userRatio: signals.totalUsers > 0 ? `${signals.flaggedUsers}/${signals.totalUsers} (${((signals.flaggedUsers / signals.totalUsers) * 100).toFixed(1)}%)` : 'no-data',
        requestRatio: signals.totalRequests > 0 ? `${signals.flaggedRequests}/${signals.totalRequests} (${((signals.flaggedRequests / signals.totalRequests) * 100).toFixed(1)}%)` : 'no-data',
      },
      pathCount: signals.pathCount,
    });
  }

  logViolationAnalysis(violName: string, path: string, composite: number, verdict: string): void {
    this.debug('viol-analysis', `Violation ${violName} @ ${sanitizePath(path)}`, {
      composite,
      verdict,
    });
  }

  logThreatMeshAnalysis(ip: string, score: number, verdict: string, reasons: string[]): void {
    this.debug('tm-analysis', `Threat Mesh ${anonIP(ip)}`, {
      fpScore: score,
      verdict,
      reasons,
    });
  }

  logServicePolicyAnalysis(rule: string, score: number, verdict: string, blockedCount: number): void {
    this.debug('sp-analysis', `Service Policy ${rule}`, {
      fpScore: score,
      verdict,
      blockedIPCount: blockedCount,
    });
  }

  logExclusionGenerated(type: string, name: string, path: string): void {
    this.info('exclusion', `Exclusion generated: ${type}`, {
      ruleName: name,
      path: sanitizePath(path),
    });
  }

  logSummary(summary: {
    totalAnalyzed: number;
    highlyLikelyFP: number;
    likelyFP: number;
    ambiguous: number;
    likelyTP: number;
    confirmedTP: number;
    exclusionsGenerated: number;
    totalSecurityEvents: number;
    totalAccessLogs: number;
    pathsAggregated: number;
    durationMs: number;
  }): void {
    this.info('summary', 'Analysis complete', {
      ...summary,
      duration: `${(summary.durationMs / 1000).toFixed(1)}s`,
    });
  }

  logError(phase: string, err: unknown): void {
    const message = err instanceof Error ? err.message : String(err);
    const stack = err instanceof Error ? err.stack?.split('\n').slice(0, 3).join('\n') : undefined;
    this.error(phase, message, stack ? { stack } : undefined);
  }

  // ───── EXPORT ─────

  getEntries(): LogEntry[] {
    return [...this.entries];
  }

  /** Export logs as a formatted text file (no PII) */
  exportAsText(): string {
    const lines: string[] = [
      '═══════════════════════════════════════════════════════════',
      '  FP Analyzer — Operation Log',
      `  Generated: ${new Date().toISOString()}`,
      `  Total entries: ${this.entries.length}`,
      '  NOTE: All PII (IPs, users, user agents, domains) is anonymized.',
      '═══════════════════════════════════════════════════════════',
      '',
    ];

    for (const entry of this.entries) {
      const prefix = `[${entry.timestamp}] [${entry.level.toUpperCase().padEnd(5)}] [${entry.phase}]`;
      lines.push(`${prefix} ${entry.message}`);
      if (entry.data) {
        const json = JSON.stringify(entry.data, null, 2);
        for (const line of json.split('\n')) {
          lines.push(`    ${line}`);
        }
      }
    }

    lines.push('');
    lines.push(`═══ END OF LOG (${this.entries.length} entries) ═══`);
    return lines.join('\n');
  }

  /** Export logs as JSON */
  exportAsJSON(): string {
    return JSON.stringify({
      generatedAt: new Date().toISOString(),
      totalEntries: this.entries.length,
      note: 'All PII (IPs, users, user agents, domains) is anonymized.',
      entries: this.entries,
    }, null, 2);
  }
}

// Singleton logger instance shared across the analysis pipeline
export const analysisLogger = new AnalysisLogger();
