/**
 * FP Analyzer — Analysis Job Orchestrator
 *
 * Manages the full server-side pipeline:
 *   fetch security events → index → fetch access logs → aggregate → analyze → generate exclusions
 *
 * Each job runs independently with its own AdaptiveConcurrencyController.
 */

import { NodeApiCaller } from './node-api-caller';
import { AdaptiveConcurrencyController } from '../src/services/fp-analyzer/adaptive-concurrency';
import { runAdaptivePool } from '../src/services/fp-analyzer/adaptive-worker-pool';
import { buildSecurityEventIndexes } from '../src/services/fp-analyzer/security-event-indexer';
import { aggregateBatch, finalizeAggregation, UserCounter } from '../src/services/fp-analyzer/streaming-aggregator';
import { analyzeSignatures } from '../src/services/fp-analyzer/signature-analyzer';
import { analyzeViolations } from '../src/services/fp-analyzer/violation-analyzer';
import { analyzeThreatMesh } from '../src/services/fp-analyzer/threat-mesh-analyzer';
import { analyzeServicePolicies } from '../src/services/fp-analyzer/service-policy-analyzer';
import { generateExclusionsForSignatures, generateViolationExclusion, buildWafExclusionPolicy } from '../src/services/fp-analyzer/exclusion-generator';
import { AnalysisLogger } from '../src/services/fp-analyzer/analysis-logger';
import type {
  AnalysisScope,
  SecurityEventEntry,
  SecurityEventIndexes,
  PathStats,
  FPAnalysisResults,
  WafExclusionRule,
} from '../src/services/fp-analyzer/types';
import type { AccessLogEntry } from '../src/services/rate-limit-advisor/types';
import type { RateLimitState } from '../src/services/fp-analyzer/adaptive-concurrency';

// ═══════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════

const CHUNK_HOURS = 2;
const PAGE_SIZE = 500;
const JOB_EXPIRY_MS = 30 * 60 * 1000; // 30 minutes

// ═══════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════

export interface JobConfig {
  tenant: string;
  token: string;
  namespace: string;
  lbName: string;
  domains: string[];
  scopes: AnalysisScope[];
  hoursBack: number;
}

export type JobPhase =
  | 'queued'
  | 'fetching_security'
  | 'indexing'
  | 'fetching_access'
  | 'analyzing'
  | 'complete'
  | 'error'
  | 'cancelled';

export interface JobProgress {
  phase: JobPhase;
  message: string;
  progress: number; // 0-100
  securityEventsCount: number;
  accessLogsStreamed: number;
  pathsAggregated: number;
  adaptiveState: RateLimitState;
  adaptiveConcurrency: number;
  error?: string;
}

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════

interface TimeChunk {
  start: string;
  end: string;
  label: string;
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
    chunks.push({
      start: new Date(cursor).toISOString(),
      end: new Date(chunkEnd).toISOString(),
      label,
    });
    cursor = chunkEnd;
  }

  return chunks;
}

/** F5 XC data fields for normalization detection */
const F5_DATA_FIELDS = ['rsp_code', 'rsp_code_details', 'src_ip', 'vh_name', 'req_path', 'waf_action', 'sample_rate'];

function hasF5DataFields(obj: Record<string, unknown>): boolean {
  let matchCount = 0;
  for (const field of F5_DATA_FIELDS) {
    if (obj[field] !== undefined && obj[field] !== null) matchCount++;
  }
  return matchCount >= 2;
}

/** Normalize raw API entries — handles JSON strings and nested wrappers */
function normalizeEntries<T>(rawEntries: unknown[], logType: string): T[] {
  if (rawEntries.length === 0) return [];

  // F5 XC API may return entries as JSON strings
  let entries = rawEntries;
  if (typeof entries[0] === 'string') {
    console.log(`[FPJob] ${logType}: Parsing ${entries.length} JSON string entries...`);
    entries = entries.map((e) => {
      try { return JSON.parse(e as string); } catch { return {}; }
    });
  }

  const sample = entries[0] as Record<string, unknown>;

  // Check 1: F5 data fields at top level
  if (hasF5DataFields(sample)) return entries as T[];

  // Check 2: Known wrapper keys
  const WRAPPER_KEYS = ['_source', 'attributes', 'data', 'log', 'fields', 'record', 'event', 'message'];
  for (const key of WRAPPER_KEYS) {
    if (sample[key] && typeof sample[key] === 'object' && !Array.isArray(sample[key])) {
      if (hasF5DataFields(sample[key] as Record<string, unknown>)) {
        console.log(`[FPJob] ${logType}: Unwrapping from '${key}'`);
        return entries.map(e => (e as Record<string, unknown>)[key] as T);
      }
    }
  }

  // Check 3: Deep scan all object values
  for (const [key, val] of Object.entries(sample)) {
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      if (hasF5DataFields(val as Record<string, unknown>)) {
        console.log(`[FPJob] ${logType}: Unwrapping from '${key}'`);
        return entries.map(e => (e as Record<string, unknown>)[key] as T);
      }
    }
  }

  return entries as T[];
}

/** Parse total_hits from F5 API (can be number, string, or object) */
function parseTotalHits(raw: unknown): number {
  if (typeof raw === 'number' && isFinite(raw)) return Math.floor(raw);
  if (typeof raw === 'string') {
    const n = parseInt(raw, 10);
    return isFinite(n) ? n : 0;
  }
  if (raw && typeof raw === 'object' && 'value' in (raw as Record<string, unknown>)) {
    return parseInt(String((raw as Record<string, unknown>).value), 10) || 0;
  }
  return 0;
}

// ═══════════════════════════════════════════════════════════════
// ANALYSIS JOB CLASS
// ═══════════════════════════════════════════════════════════════

export class AnalysisJob {
  readonly id: string;
  private config: JobConfig;
  private api: NodeApiCaller;
  private logger: AnalysisLogger;
  private cancelled = false;
  private createdAt = Date.now();

  // Progress tracking
  private phase: JobPhase = 'queued';
  private message = 'Queued';
  private progressPct = 0;
  private securityEventsCount = 0;
  private accessLogsStreamed = 0;
  private pathsAggregated = 0;

  // Adaptive controllers (one per phase)
  private secController: AdaptiveConcurrencyController;
  private accessController: AdaptiveConcurrencyController;

  // Results
  private results: FPAnalysisResults | null = null;

  constructor(id: string, config: JobConfig) {
    this.id = id;
    this.config = config;
    this.api = new NodeApiCaller({ tenant: config.tenant, token: config.token });
    this.logger = new AnalysisLogger();

    // Security events: start conservative
    this.secController = new AdaptiveConcurrencyController({
      initialConcurrency: 3,
      minConcurrency: 1,
      maxConcurrency: 8,
      rampUpAfterSuccesses: 10,
    });

    // Access logs: can ramp higher
    this.accessController = new AdaptiveConcurrencyController({
      initialConcurrency: 3,
      minConcurrency: 1,
      maxConcurrency: 12,
      rampUpAfterSuccesses: 10,
    });
  }

  isExpired(): boolean {
    return Date.now() - this.createdAt > JOB_EXPIRY_MS;
  }

  cancel(): void {
    this.cancelled = true;
    this.phase = 'cancelled';
    this.message = 'Cancelled by user';
    console.log(`[FPJob ${this.id}] Cancelled`);
  }

  getProgress(): JobProgress {
    // Use the active controller for the current phase
    const ctrl = this.phase === 'fetching_access' ? this.accessController : this.secController;
    return {
      phase: this.phase,
      message: this.message,
      progress: this.progressPct,
      securityEventsCount: this.securityEventsCount,
      accessLogsStreamed: this.accessLogsStreamed,
      pathsAggregated: this.pathsAggregated,
      adaptiveState: ctrl.getState(),
      adaptiveConcurrency: ctrl.concurrency,
      error: this.phase === 'error' ? this.message : undefined,
    };
  }

  getResults(): FPAnalysisResults | null {
    return this.results;
  }

  getLogText(): string {
    return this.logger.exportAsText();
  }

  getLogJSON(): string {
    return this.logger.exportAsJSON();
  }

  // ═══════════════════════════════════════════════════════════════
  // MAIN PIPELINE
  // ═══════════════════════════════════════════════════════════════

  async run(): Promise<void> {
    const startMs = Date.now();
    const now = new Date();
    const endTime = now.toISOString();
    const startTime = new Date(now.getTime() - this.config.hoursBack * 60 * 60 * 1000).toISOString();

    this.logger.reset();
    this.logger.logAnalysisStart({
      namespace: this.config.namespace,
      lbName: this.config.lbName,
      domains: this.config.domains,
      scopes: this.config.scopes,
      hoursBack: this.config.hoursBack,
      startTime,
      endTime,
    });

    console.log(`[FPJob ${this.id}] Starting: ns=${this.config.namespace} lb=${this.config.lbName} hours=${this.config.hoursBack}`);

    try {
      // ── Phase 1: Fetch Security Events ──
      const securityEvents = await this.fetchSecurityEvents(startTime, endTime);
      if (this.cancelled) return;

      // ── Phase 2: Index Security Events ──
      this.setProgress('indexing', 'Building security event indexes...', 35);
      const indexes = buildSecurityEventIndexes(securityEvents);
      this.logger.logIndexingResults(indexes.stats);
      console.log(`[FPJob ${this.id}] Indexed: ${indexes.stats.uniqueSignatures} sigs, ${indexes.stats.uniqueViolations} viols, ${indexes.stats.uniqueThreatMeshIPs} TM IPs`);

      // ── Phase 3: Fetch & Aggregate Access Logs ──
      const { pathStats, totalStreamed } = await this.fetchAndAggregateAccessLogs(
        startTime, endTime, indexes.reqIdSet,
      );
      if (this.cancelled) return;
      this.logger.logAccessLogsFetched(totalStreamed, pathStats.size);

      // ── Phase 4: Detect WAF Config ──
      let wafPolicyName: string | undefined;
      try {
        const lbConfig = await this.api.getLBConfig(this.config.namespace, this.config.lbName);
        const spec = lbConfig.spec as Record<string, unknown> | undefined;
        if (spec?.app_firewall) {
          const af = spec.app_firewall as Record<string, unknown>;
          wafPolicyName = (af.name as string) || undefined;
        }
      } catch (err) {
        this.logger.logError('lb-config', err);
        console.warn(`[FPJob ${this.id}] Could not fetch LB config: ${err}`);
      }

      // ── Phase 5: Run Analysis ──
      this.setProgress('analyzing', 'Running FP analysis...', 75);
      const analysisResults = this.runAnalysis(indexes, pathStats, wafPolicyName, startTime, endTime);
      if (this.cancelled) return;

      // ── Done ──
      const durationMs = Date.now() - startMs;
      this.logger.logSummary({
        ...analysisResults.summary,
        exclusionsGenerated: analysisResults.suggestedExclusions.length,
        totalSecurityEvents: analysisResults.totalSecurityEvents,
        totalAccessLogs: analysisResults.totalAccessLogs,
        pathsAggregated: pathStats.size,
        durationMs,
      });

      this.results = analysisResults;
      this.setProgress('complete', `Analysis complete in ${(durationMs / 1000).toFixed(1)}s`, 100);
      console.log(`[FPJob ${this.id}] Complete: ${durationMs}ms, ${analysisResults.summary.totalAnalyzed} units analyzed`);

    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.logError('pipeline', err);
      this.phase = 'error';
      this.message = msg;
      this.progressPct = 0;
      console.error(`[FPJob ${this.id}] Error: ${msg}`);
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // PHASE 1: FETCH SECURITY EVENTS
  // ═══════════════════════════════════════════════════════════════

  private async fetchSecurityEvents(startTime: string, endTime: string): Promise<SecurityEventEntry[]> {
    this.setProgress('fetching_security', 'Fetching security events...', 5);
    const query = `{vh_name="ves-io-http-loadbalancer-${this.config.lbName}"}`;
    const chunks = splitIntoChunks(startTime, endTime, CHUNK_HOURS);
    console.log(`[FPJob ${this.id}] Security events: ${chunks.length} chunks (${CHUNK_HOURS}h each)`);

    const allEvents: SecurityEventEntry[] = [];

    // Build tasks: each task fetches one chunk (initial + scroll loop)
    const tasks = chunks.map((chunk, idx) => ({
      id: idx,
      execute: async (): Promise<SecurityEventEntry[]> => {
        const chunkEvents: unknown[] = [];

        const initial = await this.api.fetchSecurityEventsPage(
          this.config.namespace, query, chunk.start, chunk.end, PAGE_SIZE,
        );

        if (initial.events) chunkEvents.push(...initial.events);

        let scrollId = initial.scroll_id;
        while (scrollId) {
          try {
            const page = await this.api.scrollSecurityEvents(this.config.namespace, scrollId);
            if (!page.events || page.events.length === 0) break;
            chunkEvents.push(...page.events);
            scrollId = page.scroll_id;
          } catch {
            break; // Scroll expired or error — keep what we have
          }
        }

        return normalizeEntries<SecurityEventEntry>(chunkEvents, `sec-chunk-${chunk.label}`);
      },
    }));

    await runAdaptivePool(
      tasks,
      this.secController,
      (r) => {
        if (r.result) {
          allEvents.push(...r.result);
          this.securityEventsCount = allEvents.length;
          const pct = Math.min(5 + Math.round((r.id / chunks.length) * 25), 30);
          this.setProgress('fetching_security', `Security events: ${allEvents.length.toLocaleString()} fetched`, pct);
        }
        if (r.error) {
          this.logger.logError('fetch-security', r.error);
        }
      },
      undefined,
      () => this.cancelled,
    );

    // Client-side filter: ensure only events for this LB
    const expectedVh = `ves-io-http-loadbalancer-${this.config.lbName}`;
    const filtered = allEvents.filter(e => {
      const vh = (e as Record<string, unknown>).vh_name as string | undefined;
      return !vh || vh === expectedVh;
    });

    const removed = allEvents.length - filtered.length;
    this.logger.logSecurityEventsFetched(allEvents.length, filtered.length, removed);
    this.securityEventsCount = filtered.length;
    console.log(`[FPJob ${this.id}] Security events: ${filtered.length} (filtered from ${allEvents.length})`);

    return filtered;
  }

  // ═══════════════════════════════════════════════════════════════
  // PHASE 3: FETCH & AGGREGATE ACCESS LOGS (per-chunk aggregation)
  // ═══════════════════════════════════════════════════════════════

  private async fetchAndAggregateAccessLogs(
    startTime: string,
    endTime: string,
    reqIdSet: Set<string>,
  ): Promise<{ pathStats: Map<string, PathStats>; totalStreamed: number }> {
    this.setProgress('fetching_access', 'Fetching access logs...', 40);
    const query = `{vh_name="ves-io-http-loadbalancer-${this.config.lbName}"}`;
    const chunks = splitIntoChunks(startTime, endTime, CHUNK_HOURS);
    console.log(`[FPJob ${this.id}] Access logs: ${chunks.length} chunks (${CHUNK_HOURS}h each)`);

    // Shared aggregation state
    const pathStats = new Map<string, PathStats>();
    const userCounters = new Map<string, UserCounter>();
    const flaggedUserCounters = new Map<string, UserCounter>();
    let totalStreamed = 0;

    const tasks = chunks.map((chunk, idx) => ({
      id: idx,
      execute: async (): Promise<number> => {
        // Fetch all pages for this chunk
        const chunkLogs: unknown[] = [];

        const initial = await this.api.fetchAccessLogsPage(
          this.config.namespace, query, chunk.start, chunk.end, PAGE_SIZE,
        );

        if (initial.logs) chunkLogs.push(...initial.logs);

        let scrollId = initial.scroll_id;
        while (scrollId) {
          try {
            const page = await this.api.scrollAccessLogs(this.config.namespace, scrollId);
            if (!page.logs || page.logs.length === 0) break;
            chunkLogs.push(...page.logs);
            scrollId = page.scroll_id;
          } catch {
            break;
          }
        }

        // Normalize and filter
        const normalized = normalizeEntries<AccessLogEntry>(chunkLogs, `access-chunk-${chunk.label}`);
        const expectedVh = `ves-io-http-loadbalancer-${this.config.lbName}`;
        const filtered = normalized.filter(l => {
          const vh = (l as Record<string, unknown>).vh_name as string | undefined;
          return !vh || vh === expectedVh;
        });

        // Aggregate this chunk immediately — memory stays flat
        if (filtered.length > 0) {
          aggregateBatch(filtered, pathStats, userCounters, flaggedUserCounters, reqIdSet);
        }

        return filtered.length;
      },
    }));

    await runAdaptivePool(
      tasks,
      this.accessController,
      (r) => {
        if (r.result !== undefined) {
          totalStreamed += r.result;
          this.accessLogsStreamed = totalStreamed;
          this.pathsAggregated = pathStats.size;
          const pct = Math.min(40 + Math.round((r.id / chunks.length) * 30), 70);
          this.setProgress('fetching_access', `Access logs: ${totalStreamed.toLocaleString()} streamed, ${pathStats.size} paths`, pct);
        }
        if (r.error) {
          this.logger.logError('fetch-access', r.error);
        }
      },
      undefined,
      () => this.cancelled,
    );

    // Finalize: convert UserCounter counts into PathStats
    finalizeAggregation(pathStats, userCounters, flaggedUserCounters);

    this.pathsAggregated = pathStats.size;
    console.log(`[FPJob ${this.id}] Access logs: ${totalStreamed} streamed, ${pathStats.size} paths aggregated`);

    return { pathStats, totalStreamed };
  }

  // ═══════════════════════════════════════════════════════════════
  // PHASE 5: RUN ANALYSIS
  // ═══════════════════════════════════════════════════════════════

  private runAnalysis(
    indexes: SecurityEventIndexes,
    pathStats: Map<string, PathStats>,
    wafPolicyName: string | undefined,
    startTime: string,
    endTime: string,
  ): FPAnalysisResults {
    const scopes = this.config.scopes;
    const exclusions: WafExclusionRule[] = [];
    const domain = this.config.domains[0] || '';

    // Signature analysis
    let signatureUnits;
    if (scopes.includes('waf_signatures')) {
      signatureUnits = analyzeSignatures(indexes, pathStats);
      const sigExclusions = generateExclusionsForSignatures(signatureUnits, domain);
      exclusions.push(...sigExclusions);
      for (const excl of sigExclusions) {
        this.logger.logExclusionGenerated('signature', excl.metadata.name, excl.path_regex);
      }
    }

    // Violation analysis
    let violationUnits;
    if (scopes.includes('waf_violations')) {
      violationUnits = analyzeViolations(indexes, pathStats);
      for (const unit of violationUnits) {
        if (unit.signals.verdict === 'highly_likely_fp' || unit.signals.verdict === 'likely_fp') {
          const topMethod = Object.keys(unit.methods)[0] || 'GET';
          const excl = generateViolationExclusion(
            unit.violationName, 'request', '', domain, unit.path, [topMethod],
          );
          exclusions.push(excl);
          this.logger.logExclusionGenerated('violation', excl.metadata.name, excl.path_regex);
        }
      }
    }

    // Threat mesh analysis
    let threatMeshUnits;
    if (scopes.includes('threat_mesh')) {
      threatMeshUnits = analyzeThreatMesh(indexes, pathStats);
    }

    // Service policy analysis
    let servicePolicyUnits;
    if (scopes.includes('service_policy')) {
      servicePolicyUnits = analyzeServicePolicies(indexes, pathStats);
    }

    // Compute summary
    const allVerdicts = [
      ...(signatureUnits || []).map(u => u.signals.verdict),
      ...(violationUnits || []).map(u => u.signals.verdict),
      ...(threatMeshUnits || []).map(u => u.verdict),
      ...(servicePolicyUnits || []).map(u => u.verdict),
    ];

    const summary = {
      totalAnalyzed: allVerdicts.length,
      highlyLikelyFP: allVerdicts.filter(v => v === 'highly_likely_fp').length,
      likelyFP: allVerdicts.filter(v => v === 'likely_fp').length,
      ambiguous: allVerdicts.filter(v => v === 'ambiguous').length,
      likelyTP: allVerdicts.filter(v => v === 'likely_tp').length,
      confirmedTP: allVerdicts.filter(v => v === 'confirmed_tp').length,
    };

    // Build WAF Exclusion Policy object
    const suggestedPolicy = exclusions.length > 0
      ? buildWafExclusionPolicy(this.config.lbName, this.config.namespace, exclusions)
      : undefined;

    return {
      lbName: this.config.lbName,
      namespace: this.config.namespace,
      domains: this.config.domains,
      analysisScopes: scopes,
      wafPolicyName,
      suggestedPolicy,
      analysisStart: startTime,
      analysisEnd: endTime,
      generatedAt: new Date().toISOString(),
      totalSecurityEvents: this.securityEventsCount,
      totalAccessLogs: this.accessLogsStreamed,
      totalAccessLogsStreamed: this.accessLogsStreamed,
      avgSampleRate: 0,
      signatureUnits,
      violationUnits,
      threatMeshUnits,
      servicePolicyUnits,
      summary,
      suggestedExclusions: exclusions,
      existingExclusions: [],
    };
  }

  // ═══════════════════════════════════════════════════════════════
  // HELPERS
  // ═══════════════════════════════════════════════════════════════

  private setProgress(phase: JobPhase, message: string, progress: number): void {
    this.phase = phase;
    this.message = message;
    this.progressPct = progress;
  }
}
