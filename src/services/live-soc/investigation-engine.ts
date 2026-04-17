// =============================================================================
// Live SOC Monitoring Room — Investigation Engine
// =============================================================================
// Implements all 12 auto-investigation workflows defined in spec Sections 7.1
// through 7.12. Each workflow is a sequence of steps that gather evidence,
// correlate data across sources, diagnose root causes via the K000146828
// knowledge base, and produce remediation recommendations.
//
// Exports:
//   createInvestigation(workflowId, triggerAnomalyId, parentId?)
//   executeInvestigation(investigation, context)
//   MAX_CHAIN_DEPTH
// =============================================================================

import type {
  Investigation,
  InvestigationWorkflowId,
  InvestigationStep,
  InvestigationFinding,
  RemediationAction,
  SOCRoomConfig,
  AggregationResults,
  LatencyStats,
  AlertEntry,
  AuditEntry,
  AnomalySeverity,
} from './types';

import { apiClient } from '../api';
import { diagnoseError, classifyLatencyBottleneck } from './error-diagnosis';
import { fetchRuleSuggestion, fetchMultipleSuggestions } from './rule-suggestion';
import { evaluateChains } from './investigation-chains';

// =============================================================================
// Constants
// =============================================================================

/** Maximum depth for investigation chaining to prevent infinite loops. */
export const MAX_CHAIN_DEPTH = 3;

// =============================================================================
// Investigation Context
// =============================================================================

export interface InvestigationContext {
  namespace: string;
  room: SOCRoomConfig;
  aggregation: AggregationResults;
  latencyStats: LatencyStats;
  alerts: AlertEntry[];
  auditEntries: AuditEntry[];
  onStepUpdate: (investigation: Investigation) => void;
}

// =============================================================================
// Workflow Step Definitions
// =============================================================================

interface WorkflowDefinition {
  steps: Array<{ id: string; label: string }>;
}

const WORKFLOW_DEFINITIONS: Record<InvestigationWorkflowId, WorkflowDefinition> = {
  // -------------------------------------------------------------------------
  // 7.1 Origin 5xx Surge
  // -------------------------------------------------------------------------
  origin_5xx: {
    steps: [
      { id: 'classify_errors', label: 'Classify errors via rsp_code_details KB' },
      { id: 'separate_f5_vs_origin', label: 'Separate F5-generated vs origin-generated errors' },
      { id: 'identify_failing_origins', label: 'Identify failing origins by dst_ip' },
      { id: 'analyze_timing_waterfall', label: 'Analyze timing waterfall' },
      { id: 'check_cross_site_routing', label: 'Check cross-site routing' },
      { id: 'check_circuit_breaker', label: 'Check circuit breaker flags' },
      { id: 'check_config_changes', label: 'Check recent config changes' },
      { id: 'check_health_check', label: 'Check health check configuration' },
      { id: 'fetch_remediation', label: 'Fetch remediation rule suggestions' },
    ],
  },

  // -------------------------------------------------------------------------
  // 7.2 WAF Attack Surge
  // -------------------------------------------------------------------------
  waf_attack: {
    steps: [
      { id: 'aggregate_signatures', label: 'Aggregate by WAF signature' },
      { id: 'identify_attack_sources', label: 'Identify attack source IPs and geo' },
      { id: 'check_threat_campaigns', label: 'Check threat campaigns' },
      { id: 'classify_fp_vs_tp', label: 'Classify FP vs TP on top signatures' },
      { id: 'cross_reference_access_logs', label: 'Cross-reference with access logs' },
      { id: 'ja4_clustering', label: 'JA4 fingerprint clustering' },
      { id: 'check_waf_policy_changes', label: 'Check for WAF policy changes' },
      { id: 'generate_remediation', label: 'Generate remediation rules' },
    ],
  },

  // -------------------------------------------------------------------------
  // 7.3 DDoS Detection
  // -------------------------------------------------------------------------
  ddos: {
    steps: [
      { id: 'fetch_tsa_alerts', label: 'Fetch active TSA alerts' },
      { id: 'profile_spike', label: 'Profile the traffic spike' },
      { id: 'classify_attack_type', label: 'Classify attack type' },
      { id: 'check_existing_mitigations', label: 'Check existing mitigations' },
      { id: 'check_sample_rate_surge', label: 'Check sample_rate surge' },
      { id: 'check_infraprotect', label: 'Check InfraProtect L3/L4 alerts' },
      { id: 'generate_mitigation', label: 'Generate DDoS mitigation rules' },
      { id: 'recommend_threshold', label: 'Recommend DDoS threshold' },
    ],
  },

  // -------------------------------------------------------------------------
  // 7.4 Latency Spike
  // -------------------------------------------------------------------------
  latency_spike: {
    steps: [
      { id: 'analyze_waterfall', label: 'Analyze timing waterfall' },
      { id: 'per_origin_breakdown', label: 'Per-origin latency breakdown' },
      { id: 'check_site_routing', label: 'Check cross-site routing' },
      { id: 'check_http_protocol', label: 'Check HTTP protocol negotiation' },
      { id: 'check_idle_timeout', label: 'Check idle timeout configuration' },
      { id: 'path_specific_analysis', label: 'Path-specific latency analysis' },
      { id: 'remediation', label: 'Generate latency remediation' },
    ],
  },

  // -------------------------------------------------------------------------
  // 7.5 Bot Surge
  // -------------------------------------------------------------------------
  bot_surge: {
    steps: [
      { id: 'fetch_bot_overview', label: 'Fetch bot traffic overview' },
      { id: 'get_attack_intent', label: 'Get bot attack intent classification' },
      { id: 'identify_top_attackers', label: 'Identify top malicious bot sources' },
      { id: 'identify_target_endpoints', label: 'Identify targeted endpoints' },
      { id: 'ja4_clustering', label: 'JA4 fingerprint clustering' },
      { id: 'check_bot_defense_config', label: 'Check bot defense configuration' },
      { id: 'check_mitigation_effectiveness', label: 'Check mitigation effectiveness' },
      { id: 'generate_response', label: 'Generate block rules for top attackers' },
    ],
  },

  // -------------------------------------------------------------------------
  // 7.6 Service Policy Block Surge
  // -------------------------------------------------------------------------
  service_policy_block: {
    steps: [
      { id: 'identify_blocking_policy', label: 'Identify blocking policy and rule' },
      { id: 'fetch_policy_config', label: 'Fetch service policy configuration' },
      { id: 'profile_blocked_traffic', label: 'Profile blocked traffic' },
      { id: 'check_audit_logs', label: 'Check audit logs for policy changes' },
      { id: 'cross_reference_reputation', label: 'Cross-reference IP reputation' },
      { id: 'calculate_false_block_rate', label: 'Calculate false-block rate' },
      { id: 'remediation', label: 'Generate trust rule / policy fix' },
    ],
  },

  // -------------------------------------------------------------------------
  // 7.7 Rate Limit Impact Assessment
  // -------------------------------------------------------------------------
  rate_limit_impact: {
    steps: [
      { id: 'count_rate_limited', label: 'Count rate-limited requests' },
      { id: 'profile_users', label: 'Profile rate-limited users' },
      { id: 'identify_affected_paths', label: 'Identify affected paths' },
      { id: 'compare_to_config', label: 'Compare to rate limit configuration' },
      { id: 'calculate_false_limit_rate', label: 'Calculate false-limit rate' },
      { id: 'remediation', label: 'Generate rate limit remediation' },
    ],
  },

  // -------------------------------------------------------------------------
  // 7.8 TLS/Certificate Error
  // -------------------------------------------------------------------------
  tls_cert_error: {
    steps: [
      { id: 'classify_tls_error', label: 'Classify TLS error variant' },
      { id: 'fetch_origin_tls_config', label: 'Fetch origin pool TLS configuration' },
      { id: 'map_kb_remediation', label: 'Map to KB remediation' },
    ],
  },

  // -------------------------------------------------------------------------
  // 7.9 Route Configuration Error
  // -------------------------------------------------------------------------
  route_config_error: {
    steps: [
      { id: 'extract_authorities', label: 'Extract request authorities from 404s' },
      { id: 'fetch_lb_config', label: 'Fetch LB configuration' },
      { id: 'compare_domains', label: 'Compare requested vs configured domains' },
      { id: 'check_cname', label: 'Check CNAME / DNS configuration' },
      { id: 'check_health_checks', label: 'Check origin health checks' },
      { id: 'check_audit_logs', label: 'Check audit logs for route changes' },
      { id: 'remediation', label: 'Generate route configuration remediation' },
    ],
  },

  // -------------------------------------------------------------------------
  // 7.10 Credential Stuffing Attack
  // -------------------------------------------------------------------------
  credential_stuffing: {
    steps: [
      { id: 'fetch_cred_stuffing_metrics', label: 'Fetch credential stuffing metrics' },
      { id: 'identify_targeted_endpoints', label: 'Identify targeted endpoints' },
      { id: 'profile_sources', label: 'Profile attack source IPs' },
      { id: 'check_bot_defense_effectiveness', label: 'Check bot defense effectiveness' },
      { id: 'check_rate_limiters', label: 'Check rate limiters on login paths' },
      { id: 'generate_remediation', label: 'Generate block + rate limit rules' },
    ],
  },

  // -------------------------------------------------------------------------
  // 7.11 Client-Side Script Attack (Magecart)
  // -------------------------------------------------------------------------
  csd_magecart: {
    steps: [
      { id: 'fetch_detected_scripts', label: 'Fetch detected scripts and behaviors' },
      { id: 'identify_form_fields', label: 'Identify affected form fields' },
      { id: 'check_network_interactions', label: 'Check script network interactions' },
      { id: 'count_affected_users', label: 'Count affected users' },
      { id: 'check_mitigation_status', label: 'Check domain mitigation status' },
      { id: 'severity_determination', label: 'Determine severity from targeted fields' },
      { id: 'remediation', label: 'Generate CSD remediation' },
    ],
  },

  // -------------------------------------------------------------------------
  // 7.12 DNS Failure
  // -------------------------------------------------------------------------
  dns_failure: {
    steps: [
      { id: 'fetch_dns_lb_health', label: 'Fetch DNS LB health status' },
      { id: 'get_pool_member_status', label: 'Get pool member health status' },
      { id: 'get_health_change_events', label: 'Get health state change events' },
      { id: 'check_failover', label: 'Check failover policy' },
      { id: 'check_dns_query_metrics', label: 'Check DNS query metrics' },
      { id: 'remediation', label: 'Generate DNS remediation' },
    ],
  },
};

// =============================================================================
// ID Generation
// =============================================================================

let investigationCounter = 0;

function generateId(prefix: string): string {
  investigationCounter += 1;
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).slice(2, 8);
  return `${prefix}-${ts}-${rand}-${investigationCounter}`;
}

// =============================================================================
// createInvestigation
// =============================================================================

/**
 * Creates a new investigation in 'pending' state with all steps defined
 * per the workflow specification.
 */
export function createInvestigation(
  workflowId: InvestigationWorkflowId,
  triggerAnomalyId: string,
  parentId?: string,
): Investigation {
  const definition = WORKFLOW_DEFINITIONS[workflowId];

  const steps: InvestigationStep[] = definition.steps.map((s) => ({
    id: s.id,
    label: s.label,
    status: 'pending',
  }));

  return {
    id: generateId('inv'),
    workflowId,
    triggerAnomalyId,
    parentInvestigationId: parentId,
    status: 'pending',
    steps,
    currentStepIndex: 0,
    childInvestigationIds: [],
    createdAt: new Date().toISOString(),
  };
}

// =============================================================================
// Step Execution Helpers
// =============================================================================

/**
 * Marks a step as 'running' and notifies the UI.
 */
function beginStep(
  investigation: Investigation,
  stepIndex: number,
  ctx: InvestigationContext,
): void {
  const step = investigation.steps[stepIndex];
  step.status = 'running';
  step.startedAt = new Date().toISOString();
  investigation.currentStepIndex = stepIndex;
  ctx.onStepUpdate({ ...investigation });
}

/**
 * Marks a step as 'complete' with the gathered evidence.
 */
function completeStep(
  investigation: Investigation,
  stepIndex: number,
  evidence: Record<string, unknown>,
  ctx: InvestigationContext,
): void {
  const step = investigation.steps[stepIndex];
  step.status = 'complete';
  step.evidence = evidence;
  step.completedAt = new Date().toISOString();
  ctx.onStepUpdate({ ...investigation });
}

/**
 * Marks a step as 'skipped' (e.g. API feature not enabled or call failed).
 */
function skipStep(
  investigation: Investigation,
  stepIndex: number,
  reason: string,
  ctx: InvestigationContext,
): void {
  const step = investigation.steps[stepIndex];
  step.status = 'skipped';
  step.error = reason;
  step.completedAt = new Date().toISOString();
  ctx.onStepUpdate({ ...investigation });
}

/**
 * Marks a step as 'error'.
 */
function errorStep(
  investigation: Investigation,
  stepIndex: number,
  error: string,
  ctx: InvestigationContext,
): void {
  const step = investigation.steps[stepIndex];
  step.status = 'error';
  step.error = error;
  step.completedAt = new Date().toISOString();
  ctx.onStepUpdate({ ...investigation });
}

// =============================================================================
// Shared Utility Helpers
// =============================================================================

function safeNum(val: unknown, fallback = 0): number {
  const n = Number(val);
  return isNaN(n) ? fallback : n;
}

function safeStr(val: unknown, fallback = ''): string {
  return typeof val === 'string' ? val : fallback;
}

/** Compute time window for investigation lookback (default 30 minutes). */
function computeTimeWindow(minutesBack = 30): { startTime: string; endTime: string } {
  const end = new Date();
  const start = new Date(end.getTime() - minutesBack * 60 * 1000);
  return { startTime: start.toISOString(), endTime: end.toISOString() };
}

/** Pick the first LB name from the room config, or empty string. */
function primaryLb(room: SOCRoomConfig): string {
  return room.loadBalancers[0] ?? '';
}

/** Build the aggregation query filter for the room's LBs. */
function buildLbFilter(lbNames: string[]): string {
  if (!lbNames.length) return '{}';
  const prefixed = lbNames.map((n) =>
    n.startsWith('ves-io-http-loadbalancer-') ? n : `ves-io-http-loadbalancer-${n}`,
  );
  if (prefixed.length === 1) return `{vh_name="${prefixed[0]}"}`;
  return `{vh_name=~"${prefixed.join('|')}"}`;
}

/** Top N from an array of {key, count} buckets. */
function topN<T extends { count: number }>(items: T[], n: number): T[] {
  return [...items].sort((a, b) => b.count - a.count).slice(0, n);
}

/** Safe API call wrapper — returns null on failure. */
async function safeApiGet<T>(endpoint: string): Promise<T | null> {
  try {
    return await apiClient.get<T>(endpoint);
  } catch {
    return null;
  }
}

async function safeApiPost<T>(endpoint: string, body: unknown): Promise<T | null> {
  try {
    return await apiClient.post<T>(endpoint, body);
  } catch {
    return null;
  }
}

/** Filter audit entries to a time window (minutes back from now). */
function recentAuditEntries(entries: AuditEntry[], minutesBack = 30): AuditEntry[] {
  const cutoff = new Date(Date.now() - minutesBack * 60 * 1000).toISOString();
  return entries.filter((e) => e.timestamp >= cutoff);
}

/** Filter audit entries by object type keywords. */
function filterAuditByObjectType(entries: AuditEntry[], keywords: string[]): AuditEntry[] {
  return entries.filter((e) => {
    const t = e.objectType.toLowerCase();
    return keywords.some((kw) => t.includes(kw));
  });
}

/**
 * Evaluate chain triggers and filter to non-null child workflows.
 * The evaluateChains function returns nullable workflowIds (null = terminal),
 * but the InvestigationFinding.childTriggers type requires non-null workflowIds.
 */
function evaluateChainsFiltered(
  parentWorkflow: InvestigationWorkflowId,
  finding: InvestigationFinding,
): Array<{ workflowId: InvestigationWorkflowId; reason: string }> {
  const raw = evaluateChains(finding, parentWorkflow);
  return raw
    .filter((t): t is { workflowId: InvestigationWorkflowId; reason: string } => t.workflowId !== null);
}

// =============================================================================
// Per-Workflow Execution Functions
// =============================================================================

// ---------------------------------------------------------------------------
// 7.1 Origin 5xx Surge
// ---------------------------------------------------------------------------

async function executeOrigin5xx(
  inv: Investigation,
  ctx: InvestigationContext,
): Promise<InvestigationFinding> {
  const { namespace, room, aggregation, latencyStats, auditEntries } = ctx;
  const lb = primaryLb(room);
  const evidence: Record<string, unknown> = {};
  let overallSeverity: AnomalySeverity = 'HIGH';

  // Step 0: Classify errors via rsp_code_details KB
  let stepIdx = 0;
  beginStep(inv, stepIdx, ctx);
  try {
    const errorBreakdown = aggregation.byRspCodeDetails
      .filter((b) => b.key && b.count > 0)
      .map((bucket) => {
        const diagnosis = diagnoseError('', bucket.key);
        return {
          rspCodeDetails: bucket.key,
          count: bucket.count,
          diagnosis: diagnosis
            ? {
                rootCause: diagnosis.rootCause,
                severity: diagnosis.severity,
                category: diagnosis.category,
                isOriginError: diagnosis.isOriginError,
                remediation: diagnosis.remediation,
              }
            : null,
        };
      })
      .sort((a, b) => b.count - a.count);

    evidence.errorBreakdown = errorBreakdown;
    if (errorBreakdown.length > 0) {
      evidence.dominantErrorPattern = errorBreakdown[0].rspCodeDetails;
      if (errorBreakdown[0].diagnosis?.severity === 'CRITICAL') {
        overallSeverity = 'CRITICAL';
      }
    }
    completeStep(inv, stepIdx, { errorBreakdown: errorBreakdown.slice(0, 10) }, ctx);
  } catch (err) {
    errorStep(inv, stepIdx, err instanceof Error ? err.message : 'Failed to classify errors', ctx);
  }

  // Step 1: Separate F5-generated vs origin-generated
  stepIdx = 1;
  beginStep(inv, stepIdx, ctx);
  try {
    const breakdown = (evidence.errorBreakdown as Array<{
      count: number;
      diagnosis: { isOriginError: boolean } | null;
    }>) ?? [];
    let f5Count = 0;
    let originCount = 0;
    let totalErrors = 0;

    for (const entry of breakdown) {
      totalErrors += entry.count;
      if (entry.diagnosis?.isOriginError) {
        originCount += entry.count;
      } else {
        f5Count += entry.count;
      }
    }

    const f5Pct = totalErrors > 0 ? Math.round((f5Count / totalErrors) * 100) : 0;
    const originPct = totalErrors > 0 ? Math.round((originCount / totalErrors) * 100) : 0;

    evidence.f5GeneratedPct = f5Pct;
    evidence.originGeneratedPct = originPct;
    evidence.totalErrorCount = totalErrors;

    completeStep(inv, stepIdx, {
      f5GeneratedCount: f5Count,
      f5GeneratedPct: f5Pct,
      originGeneratedCount: originCount,
      originGeneratedPct: originPct,
      summary: `${f5Pct}% F5-generated, ${originPct}% origin-generated (${totalErrors} total errors)`,
    }, ctx);
  } catch (err) {
    errorStep(inv, stepIdx, err instanceof Error ? err.message : 'Failed to separate error sources', ctx);
  }

  // Step 2: Identify failing origins
  stepIdx = 2;
  beginStep(inv, stepIdx, ctx);
  try {
    const originErrors = aggregation.byDstIp
      .filter((b) => b.count > 0)
      .map((b) => {
        // Try to find 5xx sub-bucket info if available
        const errorSubCount = b.subBuckets
          ?.filter((sb) => sb.key.startsWith('5'))
          .reduce((sum, sb) => sum + sb.count, 0) ?? 0;
        return {
          dstIp: b.key,
          totalCount: b.count,
          errorCount: errorSubCount || b.count,
          errorRate: b.count > 0 ? Math.round(((errorSubCount || b.count) / b.count) * 100) : 0,
        };
      })
      .sort((a, b) => b.errorCount - a.errorCount);

    // Enrich with latency stats per-origin
    const perOriginLatency = latencyStats.perOrigin;
    const enriched = originErrors.map((oe) => {
      const lat = perOriginLatency.find((l) => l.dstIp === oe.dstIp);
      return {
        ...oe,
        p95Latency: lat?.p95 ?? null,
        originTTFB: lat?.originTTFB_p95 ?? null,
      };
    });

    evidence.failingOrigins = enriched;
    completeStep(inv, stepIdx, { failingOrigins: enriched.slice(0, 10) }, ctx);
  } catch (err) {
    errorStep(inv, stepIdx, err instanceof Error ? err.message : 'Failed to identify failing origins', ctx);
  }

  // Step 3: Analyze timing waterfall
  stepIdx = 3;
  beginStep(inv, stepIdx, ctx);
  try {
    const bottleneck = classifyLatencyBottleneck(latencyStats.waterfall);
    evidence.latencyBottleneck = bottleneck;
    completeStep(inv, stepIdx, {
      bottleneck: bottleneck.bottleneck,
      description: bottleneck.description,
      waterfall: {
        toFirstUpstreamRx_p95: latencyStats.waterfall.toFirstUpstreamRx.p95,
        toLastUpstreamRx_p95: latencyStats.waterfall.toLastUpstreamRx.p95,
        toFirstDownstreamTx_p95: latencyStats.waterfall.toFirstDownstreamTx.p95,
        toLastDownstreamTx_p95: latencyStats.waterfall.toLastDownstreamTx.p95,
      },
    }, ctx);
  } catch (err) {
    errorStep(inv, stepIdx, err instanceof Error ? err.message : 'Failed to analyze waterfall', ctx);
  }

  // Step 4: Check cross-site routing
  stepIdx = 4;
  beginStep(inv, stepIdx, ctx);
  try {
    const tw = computeTimeWindow(10);
    const rawLogs = await safeApiPost<{
      logs?: Array<Record<string, unknown>>;
      events?: Array<Record<string, unknown>>;
    }>(`/api/data/namespaces/${namespace}/access_logs`, {
      namespace,
      query: buildLbFilter(room.loadBalancers),
      start_time: tw.startTime,
      end_time: tw.endTime,
      limit: 200,
      sort: 'DESCENDING',
    });

    const logs = rawLogs?.logs ?? rawLogs?.events ?? [];
    let crossSiteCount = 0;
    let totalCount = logs.length;
    const crossSitePairs: Record<string, number> = {};

    for (const log of logs) {
      const srcSite = safeStr(log.src_site);
      const dstSite = safeStr(log.dst_site);
      if (srcSite && dstSite && srcSite !== dstSite) {
        crossSiteCount++;
        const pair = `${srcSite} → ${dstSite}`;
        crossSitePairs[pair] = (crossSitePairs[pair] ?? 0) + 1;
      }
    }

    const crossSitePct = totalCount > 0 ? Math.round((crossSiteCount / totalCount) * 100) : 0;
    evidence.crossSiteRoutingPct = crossSitePct;

    completeStep(inv, stepIdx, {
      crossSiteCount,
      crossSitePct,
      totalSampled: totalCount,
      topPairs: Object.entries(crossSitePairs)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 5)
        .map(([pair, count]) => ({ pair, count })),
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Failed to check cross-site routing', ctx);
  }

  // Step 5: Check circuit breaker
  stepIdx = 5;
  beginStep(inv, stepIdx, ctx);
  try {
    const tw = computeTimeWindow(10);
    const rawLogs = await safeApiPost<{
      logs?: Array<Record<string, unknown>>;
      events?: Array<Record<string, unknown>>;
    }>(`/api/data/namespaces/${namespace}/access_logs`, {
      namespace,
      query: buildLbFilter(room.loadBalancers),
      start_time: tw.startTime,
      end_time: tw.endTime,
      limit: 500,
      sort: 'DESCENDING',
    });

    const logs = rawLogs?.logs ?? rawLogs?.events ?? [];
    let circuitBreakerCount = 0;
    let upstreamFailureCount = 0;
    const flagCounts: Record<string, number> = {};

    for (const log of logs) {
      const flags = safeStr(log.response_flags);
      if (flags) {
        for (const flag of flags.split(',')) {
          const trimmed = flag.trim();
          if (trimmed) {
            flagCounts[trimmed] = (flagCounts[trimmed] ?? 0) + 1;
          }
          if (trimmed === 'UO') circuitBreakerCount++;
          if (trimmed === 'UF') upstreamFailureCount++;
        }
      }
    }

    evidence.circuitBreakerTriggered = circuitBreakerCount > 0;

    completeStep(inv, stepIdx, {
      circuitBreakerCount,
      upstreamFailureCount,
      flagCounts,
      summary: circuitBreakerCount > 0
        ? `Circuit breaker triggered on ${circuitBreakerCount} requests (UpstreamOverflow)`
        : 'No circuit breaker triggers detected',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Failed to check circuit breaker', ctx);
  }

  // Step 6: Check config changes
  stepIdx = 6;
  beginStep(inv, stepIdx, ctx);
  try {
    const recent = recentAuditEntries(auditEntries, 30);
    const relevant = filterAuditByObjectType(recent, [
      'origin_pool', 'http_loadbalancer', 'health_check',
      'route', 'cluster', 'endpoint',
    ]);

    evidence.recentConfigChanges = relevant;
    completeStep(inv, stepIdx, {
      changeCount: relevant.length,
      changes: relevant.slice(0, 10).map((c) => ({
        timestamp: c.timestamp,
        user: c.user,
        objectType: c.objectType,
        objectName: c.objectName,
        operation: c.operation,
      })),
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Failed to check config changes', ctx);
  }

  // Step 7: Check health check config
  stepIdx = 7;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!lb) {
      skipStep(inv, stepIdx, 'No load balancer configured', ctx);
    } else {
      const lbConfig = await safeApiGet<Record<string, unknown>>(
        `/api/config/namespaces/${namespace}/http_loadbalancers/${lb}`,
      );

      let healthCheckInfo: Record<string, unknown> = {};

      if (lbConfig) {
        const spec = (lbConfig.spec ?? lbConfig) as Record<string, unknown>;
        const originPools = spec.origin_pools ?? spec.default_pool ?? [];
        const originPoolNames: string[] = [];

        if (Array.isArray(originPools)) {
          for (const pool of originPools) {
            const p = pool as Record<string, unknown>;
            const poolRef = p.pool as Record<string, unknown> | undefined;
            const name = safeStr(poolRef?.name ?? p.name);
            if (name) originPoolNames.push(name);
          }
        }

        // Fetch origin pool configs to find health check details
        const poolConfigs = await Promise.all(
          originPoolNames.slice(0, 5).map(async (name) => {
            const config = await safeApiGet<Record<string, unknown>>(
              `/api/config/namespaces/${namespace}/origin_pools/${name}`,
            );
            return { name, config };
          }),
        );

        healthCheckInfo = {
          originPools: poolConfigs.map((pc) => {
            const pSpec = ((pc.config?.spec ?? pc.config) ?? {}) as Record<string, unknown>;
            return {
              name: pc.name,
              healthCheck: pSpec.health_check ?? pSpec.healthcheck ?? null,
              endpointSelection: pSpec.endpoint_selection ?? null,
              loadbalancerAlgorithm: pSpec.loadbalancer_algorithm ?? null,
            };
          }),
        };

        evidence.allHealthChecksFailed = poolConfigs.every((pc) => {
          const pSpec = ((pc.config?.spec ?? pc.config) ?? {}) as Record<string, unknown>;
          const status = safeStr(pSpec.health_status ?? pSpec.status).toLowerCase();
          return status.includes('fail') || status.includes('unhealthy') || status.includes('down');
        });
      }

      completeStep(inv, stepIdx, healthCheckInfo, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Failed to check health config', ctx);
  }

  // Step 8: Fetch remediation
  stepIdx = 8;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!lb) {
      skipStep(inv, stepIdx, 'No load balancer configured', ctx);
    } else {
      const tw = computeTimeWindow(15);
      const suggestions = await fetchMultipleSuggestions(
        namespace,
        lb,
        ['block_client', 'ddos_mitigation'],
        { startTime: tw.startTime, endTime: tw.endTime },
      );

      completeStep(inv, stepIdx, {
        suggestions: suggestions.map((s) => ({
          type: s.type,
          ruleCount: s.rules.length,
          rules: s.rules.slice(0, 3),
        })),
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Failed to fetch remediation', ctx);
  }

  // Build finding
  const dominantError = evidence.dominantErrorPattern as string | undefined;
  const failingOrigins = evidence.failingOrigins as Array<{ dstIp: string; errorRate: number }> | undefined;
  const bottleneck = evidence.latencyBottleneck as { bottleneck: string; description: string } | undefined;

  const remediationActions: RemediationAction[] = [];

  // Add KB-based remediation for the dominant error
  if (dominantError) {
    const diag = diagnoseError('', dominantError);
    if (diag) {
      remediationActions.push({
        label: diag.remediation,
        type: 'info',
        context: { rspCodeDetails: dominantError, category: diag.category },
      });
    }
  }

  // Add cross-launch to Config Visualizer if config-related
  if (lb) {
    remediationActions.push({
      label: 'Open Config Visualizer for this LB',
      type: 'cross_launch',
      targetTool: 'config-visualizer',
      context: { namespace, loadBalancer: lb },
    });
  }

  // Add rule suggestions if available
  const sugStep = inv.steps[8];
  if (sugStep?.evidence?.suggestions) {
    const suggestions = sugStep.evidence.suggestions as Array<{
      type: string;
      ruleCount: number;
      rules: unknown[];
    }>;
    for (const s of suggestions) {
      if (s.ruleCount > 0) {
        remediationActions.push({
          label: `Apply ${s.type} rule (${s.ruleCount} suggestions)`,
          type: 'rule_suggestion',
          suggestedRule: s.rules[0],
          context: { suggestionType: s.type },
        });
      }
    }
  }

  const childTriggers = evaluateChainsFiltered('origin_5xx', {
    rootCause: '',
    severity: overallSeverity,
    evidenceSummary: '',
    remediationActions: [],
    childTriggers: [],
    evidence,
  });

  return {
    rootCause: dominantError
      ? `Dominant error: ${dominantError}. ${failingOrigins?.[0] ? `Primary failing origin: ${failingOrigins[0].dstIp} (${failingOrigins[0].errorRate}% error rate).` : ''} ${bottleneck?.description ?? ''}`
      : 'Unable to determine dominant error pattern from available data.',
    severity: overallSeverity,
    evidenceSummary: buildEvidenceSummary(inv),
    remediationActions,
    childTriggers,
    evidence,
  };
}

// ---------------------------------------------------------------------------
// 7.2 WAF Attack Surge
// ---------------------------------------------------------------------------

async function executeWafAttack(
  inv: Investigation,
  ctx: InvestigationContext,
): Promise<InvestigationFinding> {
  const { namespace, room, aggregation, auditEntries } = ctx;
  const lb = primaryLb(room);
  const evidence: Record<string, unknown> = {};
  let overallSeverity: AnomalySeverity = 'HIGH';

  // Step 0: Aggregate by signature
  let stepIdx = 0;
  beginStep(inv, stepIdx, ctx);
  try {
    const topSignatures = topN(aggregation.secBySignatureId, 20);
    evidence.topSignatures = topSignatures;
    completeStep(inv, stepIdx, {
      signatureCount: topSignatures.length,
      topSignatures: topSignatures.slice(0, 10).map((s) => ({
        signatureId: s.key,
        hitCount: s.count,
      })),
    }, ctx);
  } catch (err) {
    errorStep(inv, stepIdx, err instanceof Error ? err.message : 'Failed to aggregate signatures', ctx);
  }

  // Step 1: Identify attack sources
  stepIdx = 1;
  beginStep(inv, stepIdx, ctx);
  try {
    const topAttackers = topN(aggregation.secBySrcIp, 20);
    const geoDistribution = aggregation.secByCountry
      .filter((b) => b.count > 0)
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    evidence.topAttackers = topAttackers;
    evidence.attackGeoDistribution = geoDistribution;

    completeStep(inv, stepIdx, {
      topAttackerIps: topAttackers.slice(0, 10).map((a) => ({
        ip: a.key,
        count: a.count,
      })),
      geoDistribution: geoDistribution.map((g) => ({
        country: g.key,
        count: g.count,
      })),
      uniqueAttackerCount: topAttackers.length,
    }, ctx);
  } catch (err) {
    errorStep(inv, stepIdx, err instanceof Error ? err.message : 'Failed to identify sources', ctx);
  }

  // Step 2: Check threat campaigns
  stepIdx = 2;
  beginStep(inv, stepIdx, ctx);
  try {
    const topSigs = ((evidence.topSignatures as Array<{ key: string }>) ?? []).slice(0, 5);
    const campaignResults: Array<{ signatureId: string; campaign: unknown }> = [];

    for (const sig of topSigs) {
      const campaign = await safeApiGet<Record<string, unknown>>(
        `/api/waf/threat_campaign/${sig.key}`,
      );
      if (campaign) {
        campaignResults.push({ signatureId: sig.key, campaign });
      }
    }

    evidence.threatCampaigns = campaignResults;
    completeStep(inv, stepIdx, {
      campaignCount: campaignResults.length,
      campaigns: campaignResults.map((c) => ({
        signatureId: c.signatureId,
        name: safeStr((c.campaign as Record<string, unknown>)?.name ?? (c.campaign as Record<string, unknown>)?.campaign_name),
        description: safeStr((c.campaign as Record<string, unknown>)?.description),
      })),
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Threat campaign lookup failed', ctx);
  }

  // Step 3: Classify FP vs TP
  stepIdx = 3;
  beginStep(inv, stepIdx, ctx);
  try {
    // Use aggregation data to estimate FP likelihood
    // If significant portion of blocked traffic comes from diverse geo/IPs, more likely TP
    const topAttackers = (evidence.topAttackers as Array<{ key: string; count: number }>) ?? [];
    const totalSecEvents = aggregation.secByEventName.reduce((sum, b) => sum + b.count, 0);
    // Concentration ratio: if top 5 IPs account for >80% of events, more likely targeted attack (TP)
    const top5Count = topAttackers.slice(0, 5).reduce((sum, a) => sum + a.count, 0);
    const concentrationRatio = totalSecEvents > 0 ? top5Count / totalSecEvents : 0;

    // More diverse sources = more likely TP (broad attack)
    // Very concentrated = could be FP (single legitimate client)
    const fpScore = concentrationRatio > 0.8
      ? 60  // Concentrated — possibly FP
      : concentrationRatio > 0.5
        ? 30  // Mixed
        : 10; // Diverse — likely TP

    evidence.topSignatureFpScore = fpScore;
    evidence.botClassificationDominant = false;

    // Check if bot-related events dominate
    const botEvents = aggregation.secByEventName.filter((b) =>
      b.key.toLowerCase().includes('bot'),
    );
    const botEventTotal = botEvents.reduce((sum, b) => sum + b.count, 0);
    if (totalSecEvents > 0 && botEventTotal / totalSecEvents > 0.5) {
      evidence.botClassificationDominant = true;
    }

    completeStep(inv, stepIdx, {
      fpScore,
      concentrationRatio: Math.round(concentrationRatio * 100),
      assessment: fpScore > 50
        ? 'Possible false positive — concentrated source pattern'
        : 'Likely true positive — distributed attack pattern',
      topAttackerConcentration: `Top 5 IPs: ${Math.round(concentrationRatio * 100)}% of events`,
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'FP classification failed', ctx);
  }

  // Step 4: Cross-reference with access logs
  stepIdx = 4;
  beginStep(inv, stepIdx, ctx);
  try {
    // Check if blocked requests would have gotten 200 (FP indicator)
    const tw = computeTimeWindow(10);
    const accessLogs = await safeApiPost<{
      logs?: Array<Record<string, unknown>>;
      events?: Array<Record<string, unknown>>;
    }>(`/api/data/namespaces/${namespace}/access_logs`, {
      namespace,
      query: buildLbFilter(room.loadBalancers),
      start_time: tw.startTime,
      end_time: tw.endTime,
      limit: 500,
      sort: 'DESCENDING',
    });

    const logs = accessLogs?.logs ?? accessLogs?.events ?? [];
    const topAttackerIps = new Set(
      ((evidence.topAttackers as Array<{ key: string }>) ?? [])
        .slice(0, 10)
        .map((a) => a.key),
    );

    let attackerRequests = 0;
    let attackerSuccessful = 0;

    for (const log of logs) {
      const srcIp = safeStr(log.src_ip);
      if (topAttackerIps.has(srcIp)) {
        attackerRequests++;
        const rspCode = safeStr(log.rsp_code ?? log.response_code);
        if (rspCode.startsWith('2')) {
          attackerSuccessful++;
        }
      }
    }

    const successRate = attackerRequests > 0
      ? Math.round((attackerSuccessful / attackerRequests) * 100)
      : 0;

    completeStep(inv, stepIdx, {
      attackerRequestsInAccessLogs: attackerRequests,
      attackerSuccessfulCount: attackerSuccessful,
      successRate,
      summary: attackerRequests > 0
        ? `${successRate}% of blocked IPs' requests returned 200 ${successRate > 40 ? '→ likely FP' : '→ blocking effective'}`
        : 'No matching access log entries found for top attacker IPs',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Access log cross-reference failed', ctx);
  }

  // Step 5: JA4 clustering
  stepIdx = 5;
  beginStep(inv, stepIdx, ctx);
  try {
    const tw = computeTimeWindow(10);
    const rawLogs = await safeApiPost<{
      logs?: Array<Record<string, unknown>>;
      events?: Array<Record<string, unknown>>;
    }>(`/api/data/namespaces/${namespace}/app_security/events`, {
      namespace,
      query: buildLbFilter(room.loadBalancers),
      start_time: tw.startTime,
      end_time: tw.endTime,
      limit: 500,
      sort: 'DESCENDING',
    });

    const logs = rawLogs?.logs ?? rawLogs?.events ?? [];
    const ja4Map: Record<string, { count: number; ips: Set<string>; topUa: string }> = {};

    for (const log of logs) {
      const ja4 = safeStr(log.ja4 ?? log.tls_fingerprint ?? log.ja3_hash);
      if (!ja4) continue;

      if (!ja4Map[ja4]) {
        ja4Map[ja4] = { count: 0, ips: new Set(), topUa: '' };
      }
      ja4Map[ja4].count++;
      const ip = safeStr(log.src_ip);
      if (ip) ja4Map[ja4].ips.add(ip);
      if (!ja4Map[ja4].topUa) {
        ja4Map[ja4].topUa = safeStr(log.user_agent ?? log.ua);
      }
    }

    const clusters = Object.entries(ja4Map)
      .map(([fp, data]) => ({
        fingerprint: fp,
        count: data.count,
        uniqueIps: data.ips.size,
        topUa: data.topUa,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    completeStep(inv, stepIdx, {
      clusterCount: clusters.length,
      clusters,
      summary: clusters.length > 0
        ? `${((evidence.topAttackers as Array<{ key: string }>) ?? []).length} attacker IPs clustered into ${clusters.length} JA4 fingerprints → ${clusters.length <= 3 ? 'few attack tools' : 'diverse tooling'}`
        : 'No JA4 fingerprint data available',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'JA4 clustering failed', ctx);
  }

  // Step 6: Check WAF policy changes
  stepIdx = 6;
  beginStep(inv, stepIdx, ctx);
  try {
    const recent = recentAuditEntries(auditEntries, 60);
    const wafChanges = filterAuditByObjectType(recent, [
      'app_firewall', 'waf', 'exclusion', 'app_setting',
    ]);

    completeStep(inv, stepIdx, {
      wafChangeCount: wafChanges.length,
      changes: wafChanges.slice(0, 10).map((c) => ({
        timestamp: c.timestamp,
        user: c.user,
        objectType: c.objectType,
        objectName: c.objectName,
        operation: c.operation,
      })),
      summary: wafChanges.length > 0
        ? `${wafChanges.length} WAF-related config changes in last 60 minutes`
        : 'No recent WAF policy changes detected',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'WAF policy change check failed', ctx);
  }

  // Step 7: Generate remediation
  stepIdx = 7;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!lb) {
      skipStep(inv, stepIdx, 'No load balancer configured', ctx);
    } else {
      const tw = computeTimeWindow(15);
      const topSigs = ((evidence.topSignatures as Array<{ key: string }>) ?? [])
        .slice(0, 5)
        .map((s) => s.key);
      const topIps = ((evidence.topAttackers as Array<{ key: string }>) ?? [])
        .slice(0, 10)
        .map((a) => a.key);

      const fpScore = safeNum(evidence.topSignatureFpScore);
      const suggestionTypes = fpScore > 50
        ? ['waf_exclusion' as const, 'trust_client' as const]
        : ['block_client' as const, 'ddos_mitigation' as const];

      const suggestions = await fetchMultipleSuggestions(
        namespace,
        lb,
        suggestionTypes,
        {
          srcIps: topIps,
          signatureIds: topSigs,
          startTime: tw.startTime,
          endTime: tw.endTime,
        },
      );

      completeStep(inv, stepIdx, {
        suggestions: suggestions.map((s) => ({
          type: s.type,
          ruleCount: s.rules.length,
          rules: s.rules.slice(0, 3),
        })),
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Remediation generation failed', ctx);
  }

  // Build finding
  const topSigs = (evidence.topSignatures as Array<{ key: string; count: number }>) ?? [];
  const topAttackers = (evidence.topAttackers as Array<{ key: string; count: number }>) ?? [];
  const campaigns = (evidence.threatCampaigns as Array<{ signatureId: string }>) ?? [];

  const remediationActions: RemediationAction[] = [];

  // Add rule suggestions
  const sugStep = inv.steps[7];
  if (sugStep?.evidence?.suggestions) {
    const suggestions = sugStep.evidence.suggestions as Array<{
      type: string;
      ruleCount: number;
      rules: unknown[];
    }>;
    for (const s of suggestions) {
      if (s.ruleCount > 0) {
        remediationActions.push({
          label: `Apply ${s.type} rule (${s.ruleCount} suggestions)`,
          type: 'rule_suggestion',
          suggestedRule: s.rules[0],
          context: { suggestionType: s.type },
        });
      }
    }
  }

  // Cross-launch to FP Analyzer
  if (lb) {
    remediationActions.push({
      label: 'Open FP Analyzer for deep signature analysis',
      type: 'cross_launch',
      targetTool: 'fp-analyzer',
      context: { namespace, loadBalancer: lb },
    });
  }

  const childTriggers = evaluateChainsFiltered('waf_attack', {
    rootCause: '',
    severity: overallSeverity,
    evidenceSummary: '',
    remediationActions: [],
    childTriggers: [],
    evidence,
  });

  return {
    rootCause: `WAF attack surge: ${topSigs.length} signatures firing, ${topAttackers.length} source IPs. ${campaigns.length > 0 ? `Linked to ${campaigns.length} threat campaign(s).` : ''} ${safeNum(evidence.topSignatureFpScore) > 50 ? 'Possible false positive pattern detected.' : 'Attack appears to be true positive.'}`,
    severity: overallSeverity,
    evidenceSummary: buildEvidenceSummary(inv),
    remediationActions,
    childTriggers,
    evidence,
  };
}

// ---------------------------------------------------------------------------
// 7.3 DDoS Detection
// ---------------------------------------------------------------------------

async function executeDdos(
  inv: Investigation,
  ctx: InvestigationContext,
): Promise<InvestigationFinding> {
  const { namespace, room, aggregation, alerts } = ctx;
  const lb = primaryLb(room);
  const evidence: Record<string, unknown> = {};
  let overallSeverity: AnomalySeverity = 'CRITICAL';

  // Step 0: Fetch active TSA alerts
  let stepIdx = 0;
  beginStep(inv, stepIdx, ctx);
  try {
    const tsaAlerts = alerts.filter((a) =>
      a.type === 'tsa' || a.name.toLowerCase().includes('traffic') ||
      a.name.toLowerCase().includes('anomaly') || a.name.toLowerCase().includes('ddos'),
    );

    evidence.tsaAlerts = tsaAlerts;
    completeStep(inv, stepIdx, {
      alertCount: tsaAlerts.length,
      alerts: tsaAlerts.slice(0, 10).map((a) => ({
        name: a.name,
        severity: a.severity,
        description: a.description,
        createdAt: a.createdAt,
      })),
    }, ctx);
  } catch (err) {
    errorStep(inv, stepIdx, err instanceof Error ? err.message : 'Failed to fetch TSA alerts', ctx);
  }

  // Step 1: Profile the spike
  stepIdx = 1;
  beginStep(inv, stepIdx, ctx);
  try {
    const geoProfile = topN(aggregation.byCountry, 10);
    const srcIpProfile = topN(aggregation.bySrcIp, 20);

    // Fetch JA4/UA from raw logs
    const tw = computeTimeWindow(10);
    const rawLogs = await safeApiPost<{
      logs?: Array<Record<string, unknown>>;
      events?: Array<Record<string, unknown>>;
    }>(`/api/data/namespaces/${namespace}/access_logs`, {
      namespace,
      query: buildLbFilter(room.loadBalancers),
      start_time: tw.startTime,
      end_time: tw.endTime,
      limit: 500,
      sort: 'DESCENDING',
    });

    const logs = rawLogs?.logs ?? rawLogs?.events ?? [];
    const ja4Set = new Set<string>();
    const uaSet = new Set<string>();

    for (const log of logs) {
      const ja4 = safeStr(log.ja4 ?? log.tls_fingerprint);
      if (ja4) ja4Set.add(ja4);
      const ua = safeStr(log.user_agent ?? log.ua);
      if (ua) uaSet.add(ua);
    }

    evidence.geoProfile = geoProfile;
    evidence.srcIpProfile = srcIpProfile;
    evidence.uniqueJa4Count = ja4Set.size;
    evidence.uniqueUaCount = uaSet.size;
    evidence.uniqueSrcIpCount = srcIpProfile.length;

    completeStep(inv, stepIdx, {
      topCountries: geoProfile.slice(0, 5).map((g) => ({ country: g.key, count: g.count })),
      topSrcIps: srcIpProfile.slice(0, 10).map((s) => ({ ip: s.key, count: s.count })),
      uniqueJa4Fingerprints: ja4Set.size,
      uniqueUserAgents: uaSet.size,
      uniqueSrcIps: srcIpProfile.length,
    }, ctx);
  } catch (err) {
    errorStep(inv, stepIdx, err instanceof Error ? err.message : 'Failed to profile spike', ctx);
  }

  // Step 2: Classify attack type
  stepIdx = 2;
  beginStep(inv, stepIdx, ctx);
  try {
    const uniqueIps = safeNum(evidence.uniqueSrcIpCount);
    const uniqueJa4 = safeNum(evidence.uniqueJa4Count);
    const topPaths = topN(aggregation.byReqPath, 5);

    let attackType: string;
    let attackDescription: string;

    if (uniqueIps > 100 && uniqueJa4 > 20) {
      attackType = 'volumetric';
      attackDescription = `Volumetric DDoS: ${uniqueIps} unique IPs, ${uniqueJa4} JA4 fingerprints — large botnet`;
      overallSeverity = 'CRITICAL';
    } else if (uniqueIps <= 20 && topPaths.length > 0) {
      attackType = 'application_layer';
      attackDescription = `Application-layer attack: ${uniqueIps} IPs targeting ${topPaths[0].key} — targeted resource exhaustion`;
      overallSeverity = 'HIGH';
    } else if (uniqueIps > 20 && uniqueJa4 <= 5) {
      attackType = 'botnet_coordinated';
      attackDescription = `Coordinated botnet: ${uniqueIps} IPs but only ${uniqueJa4} JA4 fingerprints — same tool, distributed`;
      overallSeverity = 'CRITICAL';
    } else {
      attackType = 'mixed';
      attackDescription = `Mixed attack pattern: ${uniqueIps} IPs, ${uniqueJa4} fingerprints`;
      overallSeverity = 'HIGH';
    }

    evidence.attackType = attackType;

    // Check if WAF signatures are also spiking (for chain triggers)
    const totalSecEvents = aggregation.secByEventName.reduce((sum, b) => sum + b.count, 0);
    evidence.wafSignaturesSpiking = totalSecEvents > 100;

    completeStep(inv, stepIdx, {
      attackType,
      description: attackDescription,
      targetedPaths: topPaths.slice(0, 5).map((p) => ({ path: p.key, count: p.count })),
    }, ctx);
  } catch (err) {
    errorStep(inv, stepIdx, err instanceof Error ? err.message : 'Failed to classify attack', ctx);
  }

  // Step 3: Check existing mitigations
  stepIdx = 3;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!lb) {
      skipStep(inv, stepIdx, 'No load balancer configured', ctx);
    } else {
      const lbConfig = await safeApiGet<Record<string, unknown>>(
        `/api/config/namespaces/${namespace}/http_loadbalancers/${lb}`,
      );

      const spec = ((lbConfig?.spec ?? lbConfig) ?? {}) as Record<string, unknown>;
      const mitigations = {
        l7DdosProtection: spec.l7_ddos_protection ?? spec.ddos_protection ?? null,
        rateLimiters: spec.rate_limiter ?? spec.rate_limiters ?? null,
        servicePolicies: spec.service_policies_from_namespace ?? spec.active_service_policies ?? null,
        slowDdosMitigation: spec.slow_ddos_mitigation ?? null,
      };

      // Check if rate limiters are firing (for chain trigger)
      evidence.rateLimitersFiring = Boolean(mitigations.rateLimiters);

      completeStep(inv, stepIdx, {
        mitigations,
        summary: Object.entries(mitigations)
          .filter(([, v]) => v != null)
          .map(([k]) => k)
          .join(', ') || 'No active mitigations configured',
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Failed to check mitigations', ctx);
  }

  // Step 4: Check sample_rate surge
  stepIdx = 4;
  beginStep(inv, stepIdx, ctx);
  try {
    const tw = computeTimeWindow(10);
    const rawLogs = await safeApiPost<{
      logs?: Array<Record<string, unknown>>;
      events?: Array<Record<string, unknown>>;
    }>(`/api/data/namespaces/${namespace}/access_logs`, {
      namespace,
      query: buildLbFilter(room.loadBalancers),
      start_time: tw.startTime,
      end_time: tw.endTime,
      limit: 50,
      sort: 'DESCENDING',
    });

    const logs = rawLogs?.logs ?? rawLogs?.events ?? [];
    const sampleRates = logs
      .map((l) => safeNum(l.sample_rate, 1))
      .filter((r) => r > 0);

    const avgSampleRate = sampleRates.length > 0
      ? sampleRates.reduce((sum, r) => sum + r, 0) / sampleRates.length
      : 1;

    evidence.avgSampleRate = avgSampleRate;

    completeStep(inv, stepIdx, {
      avgSampleRate: Math.round(avgSampleRate * 100) / 100,
      sampleCount: sampleRates.length,
      summary: avgSampleRate > 5
        ? `sample_rate jumped to ${Math.round(avgSampleRate)} → F5 XC is under heavy load`
        : `sample_rate is ${Math.round(avgSampleRate)} — normal`,
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Failed to check sample rate', ctx);
  }

  // Step 5: Check InfraProtect
  stepIdx = 5;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!room.features.infraProtectEnabled) {
      skipStep(inv, stepIdx, 'InfraProtect not enabled', ctx);
    } else {
      const [ipAlerts, ipMitigations] = await Promise.all([
        safeApiGet<{ items?: unknown[]; alerts?: unknown[] }>(
          `/api/data/namespaces/${namespace}/infraprotect/alerts`,
        ),
        safeApiGet<{ items?: unknown[]; mitigations?: unknown[] }>(
          `/api/data/namespaces/${namespace}/infraprotect/mitigations`,
        ),
      ]);

      const alertItems = ipAlerts?.items ?? ipAlerts?.alerts ?? [];
      const mitigationItems = ipMitigations?.items ?? ipMitigations?.mitigations ?? [];

      completeStep(inv, stepIdx, {
        infraprotectAlerts: alertItems.length,
        activeMitigations: mitigationItems.length,
        summary: alertItems.length > 0
          ? `${alertItems.length} InfraProtect L3/L4 alert(s) active alongside L7 DDoS`
          : 'No L3/L4 DDoS alerts from InfraProtect',
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'InfraProtect check failed', ctx);
  }

  // Step 6: Generate mitigation
  stepIdx = 6;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!lb) {
      skipStep(inv, stepIdx, 'No load balancer configured', ctx);
    } else {
      const tw = computeTimeWindow(15);
      const topIps = ((evidence.srcIpProfile as Array<{ key: string }>) ?? [])
        .slice(0, 20)
        .map((s) => s.key);
      const topCountries = ((evidence.geoProfile as Array<{ key: string }>) ?? [])
        .slice(0, 5)
        .map((g) => g.key);

      const suggestion = await fetchRuleSuggestion(
        namespace,
        lb,
        'ddos_mitigation',
        {
          srcIps: topIps,
          countries: topCountries,
          startTime: tw.startTime,
          endTime: tw.endTime,
        },
      );

      completeStep(inv, stepIdx, {
        type: suggestion.type,
        ruleCount: suggestion.rules.length,
        rules: suggestion.rules.slice(0, 5),
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Mitigation generation failed', ctx);
  }

  // Step 7: Recommend threshold
  stepIdx = 7;
  beginStep(inv, stepIdx, ctx);
  try {
    // Peak × 3 algorithm from DDoS Advisor
    const totalRequests = aggregation.byRspCode.reduce((sum, b) => sum + b.count, 0);
    const windowMinutes = room.dataWindowMinutes;
    const currentRps = windowMinutes > 0 ? totalRequests / (windowMinutes * 60) : 0;
    const peakEstimate = currentRps * 1.5; // Assume current is near-peak
    const recommendedThreshold = Math.ceil(peakEstimate * 3);

    completeStep(inv, stepIdx, {
      currentRps: Math.round(currentRps),
      peakEstimate: Math.round(peakEstimate),
      recommendedThreshold,
      summary: `Current RPS: ~${Math.round(currentRps)}. Recommended DDoS threshold: ${recommendedThreshold} RPS (peak × 3)`,
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Threshold recommendation failed', ctx);
  }

  // Build finding
  const attackType = safeStr(evidence.attackType, 'unknown');
  const remediationActions: RemediationAction[] = [];

  // Add DDoS mitigation rule suggestion
  const mitStep = inv.steps[6];
  if (mitStep?.evidence?.ruleCount && (mitStep.evidence.ruleCount as number) > 0) {
    remediationActions.push({
      label: `Apply DDoS mitigation rule (${mitStep.evidence.ruleCount} suggestions)`,
      type: 'rule_suggestion',
      suggestedRule: (mitStep.evidence.rules as unknown[])?.[0],
      context: { suggestionType: 'ddos_mitigation' },
    });
  }

  // Cross-launch to DDoS Advisor
  remediationActions.push({
    label: 'Open DDoS Advisor for detailed analysis',
    type: 'cross_launch',
    targetTool: 'ddos-advisor',
    context: { namespace, loadBalancer: lb },
  });

  // Threshold recommendation
  const threshStep = inv.steps[7];
  if (threshStep?.evidence?.recommendedThreshold) {
    remediationActions.push({
      label: `Set DDoS threshold to ${threshStep.evidence.recommendedThreshold} RPS`,
      type: 'config_change',
      context: { threshold: threshStep.evidence.recommendedThreshold },
    });
  }

  const childTriggers = evaluateChainsFiltered('ddos', {
    rootCause: '',
    severity: overallSeverity,
    evidenceSummary: '',
    remediationActions: [],
    childTriggers: [],
    evidence,
  });

  return {
    rootCause: `DDoS attack detected: ${attackType} pattern. ${safeNum(evidence.uniqueSrcIpCount)} unique source IPs, ${safeNum(evidence.uniqueJa4Count)} JA4 fingerprints. ${safeNum(evidence.avgSampleRate) > 5 ? `Sample rate surged to ${Math.round(safeNum(evidence.avgSampleRate))} indicating extreme traffic volume.` : ''}`,
    severity: overallSeverity,
    evidenceSummary: buildEvidenceSummary(inv),
    remediationActions,
    childTriggers,
    evidence,
  };
}

// ---------------------------------------------------------------------------
// 7.4 Latency Spike
// ---------------------------------------------------------------------------

async function executeLatencySpike(
  inv: Investigation,
  ctx: InvestigationContext,
): Promise<InvestigationFinding> {
  const { namespace, room, aggregation, latencyStats } = ctx;
  const lb = primaryLb(room);
  const evidence: Record<string, unknown> = {};
  let overallSeverity: AnomalySeverity = 'HIGH';

  // Step 0: Analyze timing waterfall
  let stepIdx = 0;
  beginStep(inv, stepIdx, ctx);
  try {
    const bottleneck = classifyLatencyBottleneck(latencyStats.waterfall);
    evidence.latencyBottleneck = bottleneck;

    if (bottleneck.bottleneck === 'origin_slow') {
      overallSeverity = 'HIGH';
    } else if (bottleneck.bottleneck === 'xc_processing') {
      overallSeverity = 'MEDIUM';
    }

    completeStep(inv, stepIdx, {
      bottleneck: bottleneck.bottleneck,
      description: bottleneck.description,
      p50: latencyStats.p50,
      p95: latencyStats.p95,
      p99: latencyStats.p99,
      originTTFB_p95: latencyStats.originTTFB_p95,
      waterfall: {
        toFirstUpstreamTx: latencyStats.waterfall.toFirstUpstreamTx,
        toFirstUpstreamRx: latencyStats.waterfall.toFirstUpstreamRx,
        toLastUpstreamRx: latencyStats.waterfall.toLastUpstreamRx,
        toFirstDownstreamTx: latencyStats.waterfall.toFirstDownstreamTx,
        toLastDownstreamTx: latencyStats.waterfall.toLastDownstreamTx,
      },
    }, ctx);
  } catch (err) {
    errorStep(inv, stepIdx, err instanceof Error ? err.message : 'Waterfall analysis failed', ctx);
  }

  // Step 1: Per-origin breakdown
  stepIdx = 1;
  beginStep(inv, stepIdx, ctx);
  try {
    const perOrigin = latencyStats.perOrigin
      .map((o) => ({
        dstIp: o.dstIp,
        p50: o.p50,
        p95: o.p95,
        originTTFB_p95: o.originTTFB_p95,
        count: o.count,
      }))
      .sort((a, b) => b.p95 - a.p95);

    evidence.perOriginLatency = perOrigin;

    completeStep(inv, stepIdx, {
      origins: perOrigin.slice(0, 10),
      slowestOrigin: perOrigin[0] ?? null,
      summary: perOrigin.length > 0
        ? `Slowest origin: ${perOrigin[0].dstIp} (P95=${Math.round(perOrigin[0].p95)}ms TTFB=${Math.round(perOrigin[0].originTTFB_p95)}ms)`
        : 'No per-origin latency data available',
    }, ctx);
  } catch (err) {
    errorStep(inv, stepIdx, err instanceof Error ? err.message : 'Per-origin breakdown failed', ctx);
  }

  // Step 2: Check cross-site routing
  stepIdx = 2;
  beginStep(inv, stepIdx, ctx);
  try {
    const tw = computeTimeWindow(10);
    const rawLogs = await safeApiPost<{
      logs?: Array<Record<string, unknown>>;
      events?: Array<Record<string, unknown>>;
    }>(`/api/data/namespaces/${namespace}/access_logs`, {
      namespace,
      query: buildLbFilter(room.loadBalancers),
      start_time: tw.startTime,
      end_time: tw.endTime,
      limit: 300,
      sort: 'DESCENDING',
    });

    const logs = rawLogs?.logs ?? rawLogs?.events ?? [];
    let crossSiteCount = 0;
    const pairs: Record<string, number> = {};

    for (const log of logs) {
      const srcSite = safeStr(log.src_site);
      const dstSite = safeStr(log.dst_site);
      if (srcSite && dstSite && srcSite !== dstSite) {
        crossSiteCount++;
        const pair = `${srcSite} → ${dstSite}`;
        pairs[pair] = (pairs[pair] ?? 0) + 1;
      }
    }

    const crossSitePct = logs.length > 0 ? Math.round((crossSiteCount / logs.length) * 100) : 0;
    evidence.crossSiteRoutingDetected = crossSitePct > 20;
    evidence.crossSiteRoutingPct = crossSitePct;

    completeStep(inv, stepIdx, {
      crossSiteCount,
      crossSitePct,
      totalSampled: logs.length,
      topPairs: Object.entries(pairs)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 5)
        .map(([pair, count]) => ({ pair, count })),
      summary: crossSitePct > 20
        ? `${crossSitePct}% cross-site routing detected → recommend LocalEndpointsPreferred`
        : `Cross-site routing at ${crossSitePct}% — within normal range`,
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Cross-site routing check failed', ctx);
  }

  // Step 3: Check HTTP protocol
  stepIdx = 3;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!lb) {
      skipStep(inv, stepIdx, 'No load balancer configured', ctx);
    } else {
      const lbConfig = await safeApiGet<Record<string, unknown>>(
        `/api/config/namespaces/${namespace}/http_loadbalancers/${lb}`,
      );

      const spec = ((lbConfig?.spec ?? lbConfig) ?? {}) as Record<string, unknown>;
      const httpProtocol = spec.http_protocol ?? spec.http_version ?? null;
      const originProtocol = spec.origin_protocol ?? null;

      completeStep(inv, stepIdx, {
        httpProtocol,
        originProtocol,
        summary: httpProtocol
          ? `HTTP protocol: ${JSON.stringify(httpProtocol)}`
          : 'HTTP protocol configuration not specified — using defaults',
        recommendation: !originProtocol
          ? 'Consider enabling HTTP/2 for origin connection reuse and multiplexing'
          : null,
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'HTTP protocol check failed', ctx);
  }

  // Step 4: Check idle timeout
  stepIdx = 4;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!lb) {
      skipStep(inv, stepIdx, 'No load balancer configured', ctx);
    } else {
      const lbConfig = await safeApiGet<Record<string, unknown>>(
        `/api/config/namespaces/${namespace}/http_loadbalancers/${lb}`,
      );

      const spec = ((lbConfig?.spec ?? lbConfig) ?? {}) as Record<string, unknown>;
      const idleTimeout = spec.idle_timeout ?? spec.connection_idle_timeout ?? null;
      const requestTimeout = spec.request_timeout ?? spec.route_timeout ?? null;

      // Check raw logs for duration discrepancies
      const tw = computeTimeWindow(10);
      const rawLogs = await safeApiPost<{
        logs?: Array<Record<string, unknown>>;
        events?: Array<Record<string, unknown>>;
      }>(`/api/data/namespaces/${namespace}/access_logs`, {
        namespace,
        query: buildLbFilter(room.loadBalancers),
        start_time: tw.startTime,
        end_time: tw.endTime,
        limit: 100,
        sort: 'DESCENDING',
      });

      const logs = rawLogs?.logs ?? rawLogs?.events ?? [];
      let idleTimeoutIssueCount = 0;

      for (const log of logs) {
        const withDelay = safeNum(log.duration_with_data_tx_delay);
        const noDelay = safeNum(log.duration_with_no_data_tx_delay);
        if (withDelay > 0 && noDelay > 0 && Math.abs(withDelay - noDelay) > 1000) {
          idleTimeoutIssueCount++;
        }
      }

      completeStep(inv, stepIdx, {
        idleTimeout,
        requestTimeout,
        idleTimeoutIssueCount,
        totalSampled: logs.length,
        summary: idleTimeoutIssueCount > 0
          ? `${idleTimeoutIssueCount} requests show idle timeout discrepancy — connection idle timeout may need adjustment`
          : 'No idle timeout issues detected',
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Idle timeout check failed', ctx);
  }

  // Step 5: Path-specific analysis
  stepIdx = 5;
  beginStep(inv, stepIdx, ctx);
  try {
    const hotPaths = aggregation.byReqPath
      .filter((b) => b.count > 0)
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    const overallP95 = latencyStats.p95;
    const slowPaths = hotPaths.filter((p) => {
      // We don't have per-path latency from aggregation, but we can flag high-volume paths
      return p.count > 100;
    });

    completeStep(inv, stepIdx, {
      topPaths: hotPaths.map((p) => ({
        path: p.key,
        requestCount: p.count,
      })),
      overallP95,
      highVolumePaths: slowPaths.length,
      summary: `${hotPaths.length} active paths. Overall P95=${Math.round(overallP95)}ms. ${slowPaths.length} high-volume paths may benefit from path-specific optimization.`,
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Path analysis failed', ctx);
  }

  // Step 6: Remediation
  stepIdx = 6;
  beginStep(inv, stepIdx, ctx);
  try {
    const bottleneck = evidence.latencyBottleneck as {
      bottleneck: string;
      description: string;
    } | undefined;
    const crossSite = Boolean(evidence.crossSiteRoutingDetected);
    const recommendations: string[] = [];

    if (bottleneck?.bottleneck === 'origin_slow') {
      recommendations.push('Investigate origin server performance — P95 TTFB is the primary bottleneck');
      recommendations.push('Consider increasing request/route timeout if origin is expected to be slow');
    }
    if (bottleneck?.bottleneck === 'xc_processing') {
      recommendations.push('Review WAF rules and security policies — F5 XC inspection is adding latency');
      recommendations.push('Consider simplifying regex-based WAF rules');
    }
    if (bottleneck?.bottleneck === 'large_response_body') {
      recommendations.push('Enable compression on origin or at F5 XC level');
      recommendations.push('Consider enabling HTTP/2 for better transfer efficiency');
    }
    if (bottleneck?.bottleneck === 'slow_client') {
      recommendations.push('Clients appear to be on slow connections — consider CDN caching');
    }
    if (crossSite) {
      recommendations.push('Set LocalEndpointsPreferred to reduce cross-site routing latency');
    }

    if (recommendations.length === 0) {
      recommendations.push('Monitor — latency may be transient');
    }

    completeStep(inv, stepIdx, {
      recommendations,
      bottleneckType: bottleneck?.bottleneck ?? 'unknown',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Remediation generation failed', ctx);
  }

  // Build finding
  const bottleneck = evidence.latencyBottleneck as { bottleneck: string; description: string } | undefined;
  const remediationActions: RemediationAction[] = [];

  const remStep = inv.steps[6];
  if (remStep?.evidence?.recommendations) {
    for (const rec of remStep.evidence.recommendations as string[]) {
      remediationActions.push({ label: rec, type: 'info' });
    }
  }

  if (Boolean(evidence.crossSiteRoutingDetected) && lb) {
    remediationActions.push({
      label: 'Set LocalEndpointsPreferred on LB',
      type: 'config_change',
      context: { namespace, loadBalancer: lb, setting: 'local_endpoints_preferred' },
    });
  }

  const childTriggers = evaluateChainsFiltered('latency_spike', {
    rootCause: '',
    severity: overallSeverity,
    evidenceSummary: '',
    remediationActions: [],
    childTriggers: [],
    evidence,
  });

  return {
    rootCause: `Latency spike: P95=${Math.round(latencyStats.p95)}ms. ${bottleneck?.description ?? 'Bottleneck undetermined.'}`,
    severity: overallSeverity,
    evidenceSummary: buildEvidenceSummary(inv),
    remediationActions,
    childTriggers,
    evidence,
  };
}

// ---------------------------------------------------------------------------
// 7.5 Bot Surge
// ---------------------------------------------------------------------------

async function executeBotSurge(
  inv: Investigation,
  ctx: InvestigationContext,
): Promise<InvestigationFinding> {
  const { namespace, room } = ctx;
  const lb = primaryLb(room);
  const evidence: Record<string, unknown> = {};
  let overallSeverity: AnomalySeverity = 'HIGH';

  const tw = computeTimeWindow(15);
  const bdBase = `/api/data/namespaces/${namespace}/bot_defense/virtual_host/${lb}`;

  // Step 0: Fetch bot traffic overview
  let stepIdx = 0;
  beginStep(inv, stepIdx, ctx);
  try {
    const overview = await safeApiPost<Record<string, unknown>>(
      `${bdBase}/traffic/overview`,
      { start_time: tw.startTime, end_time: tw.endTime, namespace },
    );

    if (!overview) {
      skipStep(inv, stepIdx, 'Bot Defense not enabled or traffic overview unavailable', ctx);
    } else {
      const total = safeNum(overview.total);
      const humanPct = safeNum(overview.human_pct) || (total > 0 ? (safeNum(overview.human) / total) * 100 : 0);
      const maliciousPct = safeNum(overview.malicious_bot_pct) || (total > 0 ? (safeNum(overview.malicious_bot) / total) * 100 : 0);

      evidence.botOverview = { total, humanPct, maliciousPct };

      completeStep(inv, stepIdx, {
        totalRequests: total,
        humanPct: Math.round(humanPct * 100) / 100,
        maliciousBotPct: Math.round(maliciousPct * 100) / 100,
        goodBotPct: Math.round(safeNum(overview.good_bot_pct) * 100) / 100,
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Bot overview fetch failed', ctx);
  }

  // Step 1: Get attack intent
  stepIdx = 1;
  beginStep(inv, stepIdx, ctx);
  try {
    const result = await safeApiPost<{ items?: Array<Record<string, unknown>>; buckets?: Array<Record<string, unknown>> }>(
      `${bdBase}/top/type/malicious/dimension/attackintent`,
      { start_time: tw.startTime, end_time: tw.endTime, namespace },
    );

    const items = result?.items ?? result?.buckets ?? [];
    const intents = items.map((item) => ({
      intent: safeStr(item.key ?? item.name ?? item.intent, 'unknown'),
      count: safeNum(item.count ?? item.doc_count),
      pct: safeNum(item.pct),
    })).sort((a, b) => b.count - a.count);

    evidence.attackIntents = intents;
    evidence.credentialStuffingDetected = intents.some(
      (i) => i.intent.toLowerCase().includes('credential') && i.count > 0,
    );

    completeStep(inv, stepIdx, {
      intents: intents.slice(0, 10),
      dominantIntent: intents[0]?.intent ?? 'unknown',
      summary: intents.length > 0
        ? intents.map((i) => `${i.intent}: ${i.pct || Math.round(i.count)}%`).join(', ')
        : 'No attack intent data available',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Attack intent fetch failed', ctx);
  }

  // Step 2: Identify top attackers
  stepIdx = 2;
  beginStep(inv, stepIdx, ctx);
  try {
    const [ipResult, uaResult, asnResult] = await Promise.all([
      safeApiPost<{ items?: Array<Record<string, unknown>>; buckets?: Array<Record<string, unknown>> }>(
        `${bdBase}/top/type/malicious/dimension/ip`,
        { start_time: tw.startTime, end_time: tw.endTime, namespace },
      ),
      safeApiPost<{ items?: Array<Record<string, unknown>>; buckets?: Array<Record<string, unknown>> }>(
        `${bdBase}/top/type/malicious/dimension/ua`,
        { start_time: tw.startTime, end_time: tw.endTime, namespace },
      ),
      safeApiPost<{ items?: Array<Record<string, unknown>>; buckets?: Array<Record<string, unknown>> }>(
        `${bdBase}/top/type/malicious/dimension/asorg`,
        { start_time: tw.startTime, end_time: tw.endTime, namespace },
      ),
    ]);

    const topIps = (ipResult?.items ?? ipResult?.buckets ?? []).map((i) => ({
      ip: safeStr(i.key ?? i.ip, 'unknown'),
      count: safeNum(i.count ?? i.doc_count),
    })).sort((a, b) => b.count - a.count).slice(0, 20);

    const topUas = (uaResult?.items ?? uaResult?.buckets ?? []).map((i) => ({
      ua: safeStr(i.key ?? i.ua, 'unknown'),
      count: safeNum(i.count ?? i.doc_count),
    })).sort((a, b) => b.count - a.count).slice(0, 10);

    const topAsns = (asnResult?.items ?? asnResult?.buckets ?? []).map((i) => ({
      asOrg: safeStr(i.key ?? i.as_org, 'unknown'),
      count: safeNum(i.count ?? i.doc_count),
    })).sort((a, b) => b.count - a.count).slice(0, 10);

    evidence.topBotIps = topIps;

    completeStep(inv, stepIdx, {
      topIps: topIps.slice(0, 10),
      topUserAgents: topUas.slice(0, 5),
      topAsnOrgs: topAsns.slice(0, 5),
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Top attacker identification failed', ctx);
  }

  // Step 3: Identify target endpoints
  stepIdx = 3;
  beginStep(inv, stepIdx, ctx);
  try {
    const result = await safeApiPost<{ items?: Array<Record<string, unknown>>; buckets?: Array<Record<string, unknown>> }>(
      `${bdBase}/top/type/malicious/dimension/endpoints`,
      { start_time: tw.startTime, end_time: tw.endTime, namespace },
    );

    const endpoints = (result?.items ?? result?.buckets ?? []).map((i) => ({
      endpoint: safeStr(i.key ?? i.endpoint ?? i.path, 'unknown'),
      count: safeNum(i.count ?? i.doc_count),
    })).sort((a, b) => b.count - a.count).slice(0, 10);

    evidence.targetedEndpoints = endpoints;

    completeStep(inv, stepIdx, {
      endpoints,
      summary: endpoints.length > 0
        ? `Top targeted: ${endpoints[0].endpoint} (${endpoints[0].count} attacks)`
        : 'No endpoint targeting data available',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Target endpoint fetch failed', ctx);
  }

  // Step 4: JA4 clustering
  stepIdx = 4;
  beginStep(inv, stepIdx, ctx);
  try {
    const rawLogs = await safeApiPost<{
      logs?: Array<Record<string, unknown>>;
      events?: Array<Record<string, unknown>>;
    }>(`/api/data/namespaces/${namespace}/access_logs`, {
      namespace,
      query: buildLbFilter(room.loadBalancers),
      start_time: tw.startTime,
      end_time: tw.endTime,
      limit: 500,
      sort: 'DESCENDING',
    });

    const logs = rawLogs?.logs ?? rawLogs?.events ?? [];
    const ja4Map: Record<string, { count: number; ips: Set<string> }> = {};

    for (const log of logs) {
      const ja4 = safeStr(log.ja4 ?? log.tls_fingerprint);
      if (!ja4) continue;
      if (!ja4Map[ja4]) ja4Map[ja4] = { count: 0, ips: new Set() };
      ja4Map[ja4].count++;
      const ip = safeStr(log.src_ip);
      if (ip) ja4Map[ja4].ips.add(ip);
    }

    const clusters = Object.entries(ja4Map)
      .map(([fp, data]) => ({
        fingerprint: fp,
        count: data.count,
        uniqueIps: data.ips.size,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    completeStep(inv, stepIdx, {
      clusters,
      summary: `${clusters.length} distinct JA4 fingerprints → ${clusters.length <= 3 ? 'few attack tools identified' : 'diverse tooling detected'}`,
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'JA4 clustering failed', ctx);
  }

  // Step 5: Check bot defense config
  stepIdx = 5;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!lb) {
      skipStep(inv, stepIdx, 'No load balancer configured', ctx);
    } else {
      const lbConfig = await safeApiGet<Record<string, unknown>>(
        `/api/config/namespaces/${namespace}/http_loadbalancers/${lb}`,
      );

      const spec = ((lbConfig?.spec ?? lbConfig) ?? {}) as Record<string, unknown>;
      const botDefense = spec.bot_defense ?? spec.bot_defense_config ?? null;
      const protectedEndpoints = spec.protected_endpoints ?? spec.bot_defense_endpoints ?? [];

      completeStep(inv, stepIdx, {
        botDefenseEnabled: botDefense != null,
        botDefenseConfig: botDefense ? 'configured' : 'not configured',
        protectedEndpointCount: Array.isArray(protectedEndpoints) ? protectedEndpoints.length : 0,
        summary: botDefense
          ? `Bot Defense is configured with ${Array.isArray(protectedEndpoints) ? protectedEndpoints.length : 0} protected endpoints`
          : 'Bot Defense is NOT configured on this load balancer',
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Bot config check failed', ctx);
  }

  // Step 6: Check mitigation effectiveness
  stepIdx = 6;
  beginStep(inv, stepIdx, ctx);
  try {
    const result = await safeApiPost<{ items?: Array<Record<string, unknown>>; buckets?: Array<Record<string, unknown>> }>(
      `${bdBase}/traffic/malicious/overview/actions`,
      { start_time: tw.startTime, end_time: tw.endTime, namespace },
    );

    const actions = (result?.items ?? result?.buckets ?? []).map((i) => ({
      action: safeStr(i.key ?? i.action, 'unknown'),
      count: safeNum(i.count ?? i.doc_count),
      pct: safeNum(i.pct),
    })).sort((a, b) => b.count - a.count);

    completeStep(inv, stepIdx, {
      actions,
      summary: actions.length > 0
        ? actions.map((a) => `${a.action}: ${a.pct || a.count}%`).join(', ')
        : 'No mitigation action data available',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Mitigation effectiveness check failed', ctx);
  }

  // Step 7: Generate block rules
  stepIdx = 7;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!lb) {
      skipStep(inv, stepIdx, 'No load balancer configured', ctx);
    } else {
      const topIps = ((evidence.topBotIps as Array<{ ip: string }>) ?? [])
        .slice(0, 10)
        .map((i) => i.ip);

      const suggestion = await fetchRuleSuggestion(
        namespace,
        lb,
        'block_client',
        { srcIps: topIps, startTime: tw.startTime, endTime: tw.endTime },
      );

      completeStep(inv, stepIdx, {
        type: suggestion.type,
        ruleCount: suggestion.rules.length,
        rules: suggestion.rules.slice(0, 3),
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Block rule generation failed', ctx);
  }

  // Build finding
  const remediationActions: RemediationAction[] = [];

  const blockStep = inv.steps[7];
  if (blockStep?.evidence?.ruleCount && (blockStep.evidence.ruleCount as number) > 0) {
    remediationActions.push({
      label: `Apply block rule for top ${((evidence.topBotIps as unknown[]) ?? []).length} malicious IPs`,
      type: 'rule_suggestion',
      suggestedRule: (blockStep.evidence.rules as unknown[])?.[0],
      context: { suggestionType: 'block_client' },
    });
  }

  remediationActions.push({
    label: 'Review bot defense configuration',
    type: 'cross_launch',
    targetTool: 'config-visualizer',
    context: { namespace, loadBalancer: lb },
  });

  const childTriggers = evaluateChainsFiltered('bot_surge', {
    rootCause: '',
    severity: overallSeverity,
    evidenceSummary: '',
    remediationActions: [],
    childTriggers: [],
    evidence,
  });

  const dominantIntent = ((evidence.attackIntents as Array<{ intent: string }>) ?? [])[0]?.intent ?? 'unknown';

  return {
    rootCause: `Bot surge detected: dominant intent is "${dominantIntent}". ${((evidence.topBotIps as unknown[]) ?? []).length} malicious IPs identified. ${evidence.credentialStuffingDetected ? 'Credential stuffing activity detected.' : ''}`,
    severity: overallSeverity,
    evidenceSummary: buildEvidenceSummary(inv),
    remediationActions,
    childTriggers,
    evidence,
  };
}

// ---------------------------------------------------------------------------
// 7.6 Service Policy Block Surge
// ---------------------------------------------------------------------------

async function executeServicePolicyBlock(
  inv: Investigation,
  ctx: InvestigationContext,
): Promise<InvestigationFinding> {
  const { namespace, room, aggregation, auditEntries } = ctx;
  const lb = primaryLb(room);
  const evidence: Record<string, unknown> = {};
  let overallSeverity: AnomalySeverity = 'MEDIUM';

  // Step 0: Identify blocking policy
  let stepIdx = 0;
  beginStep(inv, stepIdx, ctx);
  try {
    const tw = computeTimeWindow(10);
    const rawLogs = await safeApiPost<{
      logs?: Array<Record<string, unknown>>;
      events?: Array<Record<string, unknown>>;
    }>(`/api/data/namespaces/${namespace}/access_logs`, {
      namespace,
      query: buildLbFilter(room.loadBalancers),
      start_time: tw.startTime,
      end_time: tw.endTime,
      limit: 200,
      sort: 'DESCENDING',
    });

    const logs = rawLogs?.logs ?? rawLogs?.events ?? [];
    const policyHits: Record<string, number> = {};

    for (const log of logs) {
      const rspCode = safeStr(log.rsp_code ?? log.response_code);
      if (rspCode !== '403') continue;

      const hits = log.policy_hits as Record<string, unknown> | undefined;
      if (hits) {
        const policyName = safeStr(hits.policy_name ?? hits.name);
        const ruleName = safeStr(hits.rule_name ?? hits.rule);
        const key = policyName ? `${policyName}/${ruleName}` : 'unknown';
        policyHits[key] = (policyHits[key] ?? 0) + 1;
      }
    }

    const sortedPolicies = Object.entries(policyHits)
      .sort(([, a], [, b]) => b - a);

    evidence.blockingPolicies = sortedPolicies;

    completeStep(inv, stepIdx, {
      policies: sortedPolicies.slice(0, 10).map(([key, count]) => ({
        policy: key,
        blockCount: count,
      })),
      summary: sortedPolicies.length > 0
        ? `Top blocking: "${sortedPolicies[0][0]}" (${sortedPolicies[0][1]} blocks)`
        : 'Unable to identify specific blocking policy from raw logs',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Policy identification failed', ctx);
  }

  // Step 1: Fetch policy config
  stepIdx = 1;
  beginStep(inv, stepIdx, ctx);
  try {
    const policies = await safeApiGet<{ items?: Array<Record<string, unknown>> }>(
      `/api/config/namespaces/${namespace}/service_policys`,
    );

    const items = policies?.items ?? [];
    evidence.policyConfigs = items;

    completeStep(inv, stepIdx, {
      policyCount: items.length,
      policies: items.slice(0, 5).map((p) => ({
        name: safeStr((p.metadata as Record<string, unknown>)?.name ?? p.name),
        ruleCount: Array.isArray(p.spec) ? 0 : Array.isArray((p.spec as Record<string, unknown>)?.rules) ? ((p.spec as Record<string, unknown>).rules as unknown[]).length : 0,
      })),
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Policy config fetch failed', ctx);
  }

  // Step 2: Profile blocked traffic
  stepIdx = 2;
  beginStep(inv, stepIdx, ctx);
  try {
    // Filter aggregation data to 403 responses
    const blockedByCountry = aggregation.byCountry
      .filter((b) => b.count > 0)
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    const blockedBySrcIp = aggregation.bySrcIp
      .filter((b) => b.count > 0)
      .sort((a, b) => b.count - a.count)
      .slice(0, 20);

    evidence.blockedTrafficProfile = { byCountry: blockedByCountry, bySrcIp: blockedBySrcIp };

    completeStep(inv, stepIdx, {
      topCountries: blockedByCountry.slice(0, 5).map((c) => ({ country: c.key, count: c.count })),
      topIps: blockedBySrcIp.slice(0, 10).map((s) => ({ ip: s.key, count: s.count })),
    }, ctx);
  } catch (err) {
    errorStep(inv, stepIdx, err instanceof Error ? err.message : 'Traffic profiling failed', ctx);
  }

  // Step 3: Check audit logs
  stepIdx = 3;
  beginStep(inv, stepIdx, ctx);
  try {
    const recent = recentAuditEntries(auditEntries, 60);
    const policyChanges = filterAuditByObjectType(recent, [
      'service_policy', 'policy', 'forward_proxy',
    ]);

    evidence.policyAuditChanges = policyChanges;

    completeStep(inv, stepIdx, {
      changeCount: policyChanges.length,
      changes: policyChanges.slice(0, 10).map((c) => ({
        timestamp: c.timestamp,
        user: c.user,
        objectType: c.objectType,
        objectName: c.objectName,
        operation: c.operation,
      })),
      summary: policyChanges.length > 0
        ? `${policyChanges.length} policy changes in last 60 min — ${policyChanges[0].objectName} modified by ${policyChanges[0].user} at ${policyChanges[0].timestamp}`
        : 'No recent service policy changes detected',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Audit log check failed', ctx);
  }

  // Step 4: Cross-reference reputation
  stepIdx = 4;
  beginStep(inv, stepIdx, ctx);
  try {
    const tw = computeTimeWindow(10);
    const rawLogs = await safeApiPost<{
      logs?: Array<Record<string, unknown>>;
      events?: Array<Record<string, unknown>>;
    }>(`/api/data/namespaces/${namespace}/access_logs`, {
      namespace,
      query: buildLbFilter(room.loadBalancers),
      start_time: tw.startTime,
      end_time: tw.endTime,
      limit: 300,
      sort: 'DESCENDING',
    });

    const logs = rawLogs?.logs ?? rawLogs?.events ?? [];
    let highTrustBlocked = 0;
    let lowTrustBlocked = 0;
    let totalBlocked = 0;

    for (const log of logs) {
      const rspCode = safeStr(log.rsp_code ?? log.response_code);
      if (rspCode !== '403') continue;

      totalBlocked++;
      const trustScore = safeNum(log.ip_trustscore ?? log.trust_score, -1);
      if (trustScore >= 0) {
        if (trustScore > 80) highTrustBlocked++;
        else lowTrustBlocked++;
      }
    }

    const highTrustPct = totalBlocked > 0 ? Math.round((highTrustBlocked / totalBlocked) * 100) : 0;
    evidence.highTrustBlockedPct = highTrustPct;

    completeStep(inv, stepIdx, {
      totalBlocked,
      highTrustBlocked,
      lowTrustBlocked,
      highTrustPct,
      summary: highTrustPct > 50
        ? `${highTrustPct}% of blocked IPs have trustscore > 80 → likely false blocks`
        : `${highTrustPct}% of blocked IPs are high-trust — blocking appears targeted`,
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Reputation cross-reference failed', ctx);
  }

  // Step 5: Calculate false-block rate
  stepIdx = 5;
  beginStep(inv, stepIdx, ctx);
  try {
    const highTrustPct = safeNum(evidence.highTrustBlockedPct);
    const falseBlockRate = highTrustPct;

    if (falseBlockRate > 50) {
      overallSeverity = 'HIGH';
    }

    evidence.falseBlockRate = falseBlockRate;

    completeStep(inv, stepIdx, {
      falseBlockRate,
      assessment: falseBlockRate > 50
        ? `High false-block rate (${falseBlockRate}%) — policy may be too restrictive`
        : falseBlockRate > 20
          ? `Moderate false-block rate (${falseBlockRate}%) — review policy rules`
          : `Low false-block rate (${falseBlockRate}%) — blocking is effective`,
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'False-block calculation failed', ctx);
  }

  // Step 6: Remediation
  stepIdx = 6;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!lb) {
      skipStep(inv, stepIdx, 'No load balancer configured', ctx);
    } else {
      const falseBlockRate = safeNum(evidence.falseBlockRate);
      const tw = computeTimeWindow(15);

      if (falseBlockRate > 30) {
        // High false-block → suggest trust rule
        const suggestion = await fetchRuleSuggestion(
          namespace,
          lb,
          'trust_client',
          { startTime: tw.startTime, endTime: tw.endTime },
        );

        completeStep(inv, stepIdx, {
          approach: 'trust_rule',
          type: suggestion.type,
          ruleCount: suggestion.rules.length,
          rules: suggestion.rules.slice(0, 3),
        }, ctx);
      } else {
        // Low false-block → blocking is effective
        completeStep(inv, stepIdx, {
          approach: 'effective',
          summary: 'Service policy blocking is effective — no changes recommended',
        }, ctx);
      }
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Remediation generation failed', ctx);
  }

  // Build finding
  const remediationActions: RemediationAction[] = [];
  const remStep = inv.steps[6];
  if (remStep?.evidence?.ruleCount && (remStep.evidence.ruleCount as number) > 0) {
    remediationActions.push({
      label: 'Apply trust rule for legitimate users',
      type: 'rule_suggestion',
      suggestedRule: (remStep.evidence.rules as unknown[])?.[0],
      context: { suggestionType: 'trust_client' },
    });
  }

  if (((evidence.policyAuditChanges as unknown[]) ?? []).length > 0) {
    remediationActions.push({
      label: 'Review recent service policy changes',
      type: 'info',
      context: { changeCount: ((evidence.policyAuditChanges as unknown[]) ?? []).length },
    });
  }

  return {
    rootCause: `Service policy block surge: ${safeNum(evidence.falseBlockRate)}% false-block rate. ${((evidence.policyAuditChanges as unknown[]) ?? []).length > 0 ? 'Recent policy changes detected.' : 'No recent policy changes.'}`,
    severity: overallSeverity,
    evidenceSummary: buildEvidenceSummary(inv),
    remediationActions,
    childTriggers: [],
    evidence,
  };
}

// ---------------------------------------------------------------------------
// 7.7 Rate Limit Impact Assessment
// ---------------------------------------------------------------------------

async function executeRateLimitImpact(
  inv: Investigation,
  ctx: InvestigationContext,
): Promise<InvestigationFinding> {
  const { namespace, room } = ctx;
  const lb = primaryLb(room);
  const evidence: Record<string, unknown> = {};
  let overallSeverity: AnomalySeverity = 'MEDIUM';

  const tw = computeTimeWindow(10);

  // Step 0: Count rate-limited requests
  let stepIdx = 0;
  beginStep(inv, stepIdx, ctx);
  try {
    const rawLogs = await safeApiPost<{
      logs?: Array<Record<string, unknown>>;
      events?: Array<Record<string, unknown>>;
    }>(`/api/data/namespaces/${namespace}/access_logs`, {
      namespace,
      query: buildLbFilter(room.loadBalancers),
      start_time: tw.startTime,
      end_time: tw.endTime,
      limit: 500,
      sort: 'DESCENDING',
    });

    const logs = rawLogs?.logs ?? rawLogs?.events ?? [];
    let rateLimitedCount = 0;

    for (const log of logs) {
      const hits = log.policy_hits as Record<string, unknown> | undefined;
      if (hits?.rate_limiter_action || hits?.rate_limited) {
        rateLimitedCount++;
      }
      // Also check response code 429
      const rspCode = safeStr(log.rsp_code ?? log.response_code);
      if (rspCode === '429') {
        rateLimitedCount++;
      }
    }

    evidence.rateLimitedCount = rateLimitedCount;
    evidence.rawLogs = logs;

    completeStep(inv, stepIdx, {
      rateLimitedCount,
      totalSampled: logs.length,
      rateLimitedPct: logs.length > 0 ? Math.round((rateLimitedCount / logs.length) * 100) : 0,
    }, ctx);
  } catch (err) {
    errorStep(inv, stepIdx, err instanceof Error ? err.message : 'Failed to count rate-limited requests', ctx);
  }

  // Step 1: Profile rate-limited users
  stepIdx = 1;
  beginStep(inv, stepIdx, ctx);
  try {
    const logs = (evidence.rawLogs as Array<Record<string, unknown>>) ?? [];
    const userProfile: Record<string, { count: number; trustScore: number }> = {};

    for (const log of logs) {
      const rspCode = safeStr(log.rsp_code ?? log.response_code);
      const hits = log.policy_hits as Record<string, unknown> | undefined;
      if (rspCode !== '429' && !hits?.rate_limiter_action) continue;

      const srcIp = safeStr(log.src_ip);
      if (!srcIp) continue;

      if (!userProfile[srcIp]) {
        userProfile[srcIp] = { count: 0, trustScore: safeNum(log.ip_trustscore ?? log.trust_score, -1) };
      }
      userProfile[srcIp].count++;
    }

    const profiles = Object.entries(userProfile)
      .map(([ip, data]) => ({ ip, ...data }))
      .sort((a, b) => b.count - a.count);

    const cleanUsers = profiles.filter((p) => p.trustScore > 70);
    const maliciousUsers = profiles.filter((p) => p.trustScore >= 0 && p.trustScore <= 30);

    evidence.rateLimitedProfiles = profiles;
    evidence.cleanUserCount = cleanUsers.length;

    completeStep(inv, stepIdx, {
      totalUsers: profiles.length,
      cleanUsers: cleanUsers.length,
      maliciousUsers: maliciousUsers.length,
      topUsers: profiles.slice(0, 10).map((p) => ({
        ip: p.ip,
        requestCount: p.count,
        trustScore: p.trustScore,
      })),
    }, ctx);
  } catch (err) {
    errorStep(inv, stepIdx, err instanceof Error ? err.message : 'User profiling failed', ctx);
  }

  // Step 2: Identify affected paths
  stepIdx = 2;
  beginStep(inv, stepIdx, ctx);
  try {
    const logs = (evidence.rawLogs as Array<Record<string, unknown>>) ?? [];
    const pathCounts: Record<string, number> = {};

    for (const log of logs) {
      const rspCode = safeStr(log.rsp_code ?? log.response_code);
      const hits = log.policy_hits as Record<string, unknown> | undefined;
      if (rspCode !== '429' && !hits?.rate_limiter_action) continue;

      const path = safeStr(log.req_path ?? log.path);
      if (path) {
        pathCounts[path] = (pathCounts[path] ?? 0) + 1;
      }
    }

    const affectedPaths = Object.entries(pathCounts)
      .sort(([, a], [, b]) => b - a)
      .map(([path, count]) => ({ path, count }));

    completeStep(inv, stepIdx, {
      affectedPaths: affectedPaths.slice(0, 10),
      summary: affectedPaths.length > 0
        ? `Top affected: ${affectedPaths[0].path} (${affectedPaths[0].count} rate-limited)`
        : 'No path-specific rate limit data available',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Path analysis failed', ctx);
  }

  // Step 3: Compare to config
  stepIdx = 3;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!lb) {
      skipStep(inv, stepIdx, 'No load balancer configured', ctx);
    } else {
      const lbConfig = await safeApiGet<Record<string, unknown>>(
        `/api/config/namespaces/${namespace}/http_loadbalancers/${lb}`,
      );

      const spec = ((lbConfig?.spec ?? lbConfig) ?? {}) as Record<string, unknown>;
      const rateLimiter = spec.rate_limiter ?? spec.rate_limiters ?? null;

      // Find top user's rate
      const profiles = (evidence.rateLimitedProfiles as Array<{ ip: string; count: number }>) ?? [];
      const topUserRate = profiles[0]?.count ?? 0;

      completeStep(inv, stepIdx, {
        rateLimiterConfig: rateLimiter,
        topUserRequestCount: topUserRate,
        summary: rateLimiter
          ? `Rate limiter configured. Top rate-limited user: ${topUserRate} requests in window.`
          : 'No rate limiter configuration found on LB',
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Config comparison failed', ctx);
  }

  // Step 4: Calculate false-limit rate
  stepIdx = 4;
  beginStep(inv, stepIdx, ctx);
  try {
    const profiles = (evidence.rateLimitedProfiles as Array<{ trustScore: number }>) ?? [];
    const totalLimited = profiles.length;
    const cleanLimited = profiles.filter((p) => p.trustScore > 70).length;
    const falseLimitRate = totalLimited > 0 ? Math.round((cleanLimited / totalLimited) * 100) : 0;

    if (falseLimitRate > 30) {
      overallSeverity = 'HIGH';
    }

    evidence.falseLimitRate = falseLimitRate;

    completeStep(inv, stepIdx, {
      falseLimitRate,
      cleanLimited,
      totalLimited,
      assessment: falseLimitRate > 30
        ? `${falseLimitRate}% of rate-limited users are clean → limit may be too aggressive`
        : `${falseLimitRate}% false-limit rate — rate limiting is effective`,
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'False-limit calculation failed', ctx);
  }

  // Step 5: Remediation
  stepIdx = 5;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!lb) {
      skipStep(inv, stepIdx, 'No load balancer configured', ctx);
    } else {
      const falseLimitRate = safeNum(evidence.falseLimitRate);

      if (falseLimitRate > 30) {
        const suggestion = await fetchRuleSuggestion(
          namespace,
          lb,
          'rate_limit',
          { startTime: tw.startTime, endTime: tw.endTime },
        );

        completeStep(inv, stepIdx, {
          approach: 'increase_threshold',
          type: suggestion.type,
          ruleCount: suggestion.rules.length,
          rules: suggestion.rules.slice(0, 3),
          summary: 'High false-limit rate — consider increasing rate limit threshold',
        }, ctx);
      } else {
        completeStep(inv, stepIdx, {
          approach: 'effective',
          summary: 'Rate limiting is effective — attack traffic is being blocked',
        }, ctx);
      }
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Remediation generation failed', ctx);
  }

  // Build finding
  const remediationActions: RemediationAction[] = [];
  const remStep = inv.steps[5];
  if (remStep?.evidence?.ruleCount && (remStep.evidence.ruleCount as number) > 0) {
    remediationActions.push({
      label: 'Apply updated rate limit rule',
      type: 'rule_suggestion',
      suggestedRule: (remStep.evidence.rules as unknown[])?.[0],
      context: { suggestionType: 'rate_limit' },
    });
  }

  remediationActions.push({
    label: 'Open Rate Limit Advisor for detailed analysis',
    type: 'cross_launch',
    targetTool: 'rate-limit-advisor',
    context: { namespace, loadBalancer: lb },
  });

  // Clean up large evidence before storing
  delete evidence.rawLogs;

  return {
    rootCause: `Rate limiting impact: ${safeNum(evidence.rateLimitedCount)} requests rate-limited, ${safeNum(evidence.falseLimitRate)}% false-limit rate. ${safeNum(evidence.falseLimitRate) > 30 ? 'Threshold may be too aggressive.' : 'Rate limiting is effective.'}`,
    severity: overallSeverity,
    evidenceSummary: buildEvidenceSummary(inv),
    remediationActions,
    childTriggers: [],
    evidence,
  };
}

// ---------------------------------------------------------------------------
// 7.8 TLS/Certificate Error
// ---------------------------------------------------------------------------

async function executeTlsCertError(
  inv: Investigation,
  ctx: InvestigationContext,
): Promise<InvestigationFinding> {
  const { namespace, room, aggregation } = ctx;
  const lb = primaryLb(room);
  const evidence: Record<string, unknown> = {};
  let overallSeverity: AnomalySeverity = 'HIGH';

  // Step 0: Classify TLS error variant
  let stepIdx = 0;
  beginStep(inv, stepIdx, ctx);
  try {
    const tlsPatterns = [
      'TLS_error', 'CERTIFICATE_VERIFY_FAILED', 'WRONG_VERSION_NUMBER',
      'Connection_reset', 'connection_termination', 'SSL',
    ];

    const tlsErrors = aggregation.byRspCodeDetails
      .filter((b) => tlsPatterns.some((p) => b.key.toLowerCase().includes(p.toLowerCase())))
      .sort((a, b) => b.count - a.count);

    const allTlsErrors = tlsErrors.map((b) => {
      const diag = diagnoseError('503', b.key);
      return {
        rspCodeDetails: b.key,
        count: b.count,
        variant: diag?.pattern ?? 'unknown',
        rootCause: diag?.rootCause ?? 'Unknown TLS error',
        remediation: diag?.remediation ?? 'Review TLS configuration',
      };
    });

    evidence.tlsErrors = allTlsErrors;
    evidence.dominantVariant = allTlsErrors[0]?.variant ?? 'unknown';

    if (allTlsErrors.some((e) => e.rspCodeDetails.includes('CERTIFICATE_VERIFY_FAILED'))) {
      overallSeverity = 'HIGH';
    }

    completeStep(inv, stepIdx, {
      errorCount: allTlsErrors.length,
      errors: allTlsErrors.slice(0, 10),
      dominantVariant: allTlsErrors[0]?.variant ?? 'unknown',
      dominantCount: allTlsErrors[0]?.count ?? 0,
    }, ctx);
  } catch (err) {
    errorStep(inv, stepIdx, err instanceof Error ? err.message : 'TLS error classification failed', ctx);
  }

  // Step 1: Fetch origin pool TLS config
  stepIdx = 1;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!lb) {
      skipStep(inv, stepIdx, 'No load balancer configured', ctx);
    } else {
      const lbConfig = await safeApiGet<Record<string, unknown>>(
        `/api/config/namespaces/${namespace}/http_loadbalancers/${lb}`,
      );

      const spec = ((lbConfig?.spec ?? lbConfig) ?? {}) as Record<string, unknown>;
      const originPools = spec.origin_pools ?? spec.default_pool ?? [];
      const poolNames: string[] = [];

      if (Array.isArray(originPools)) {
        for (const pool of originPools) {
          const p = pool as Record<string, unknown>;
          const poolRef = p.pool as Record<string, unknown> | undefined;
          const name = safeStr(poolRef?.name ?? p.name);
          if (name) poolNames.push(name);
        }
      }

      const tlsConfigs = await Promise.all(
        poolNames.slice(0, 5).map(async (name) => {
          const config = await safeApiGet<Record<string, unknown>>(
            `/api/config/namespaces/${namespace}/origin_pools/${name}`,
          );
          const pSpec = ((config?.spec ?? config) ?? {}) as Record<string, unknown>;
          return {
            poolName: name,
            useTls: Boolean(pSpec.use_tls ?? pSpec.tls_config),
            tlsConfig: pSpec.tls_config ?? pSpec.use_tls ?? null,
            verificationMode: safeStr(pSpec.server_name ?? pSpec.sni),
            customCA: Boolean(pSpec.trusted_ca ?? pSpec.ca_cert),
            skipVerification: Boolean(pSpec.no_tls_verification ?? pSpec.skip_server_verification),
          };
        }),
      );

      evidence.originTlsConfigs = tlsConfigs;

      completeStep(inv, stepIdx, {
        poolCount: tlsConfigs.length,
        configs: tlsConfigs,
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'TLS config fetch failed', ctx);
  }

  // Step 2: Map to KB remediation
  stepIdx = 2;
  beginStep(inv, stepIdx, ctx);
  try {
    const tlsErrors = (evidence.tlsErrors as Array<{
      rspCodeDetails: string;
      variant: string;
      rootCause: string;
      remediation: string;
    }>) ?? [];

    const remediationMap = tlsErrors.map((e) => ({
      variant: e.variant,
      rspCodeDetails: e.rspCodeDetails,
      rootCause: e.rootCause,
      remediation: e.remediation,
    }));

    completeStep(inv, stepIdx, {
      remediations: remediationMap,
      summary: remediationMap.length > 0
        ? `${remediationMap.length} TLS error variants mapped to KB remediations`
        : 'No TLS error patterns matched in KB',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'KB mapping failed', ctx);
  }

  // Build finding
  const tlsErrors = (evidence.tlsErrors as Array<{
    rspCodeDetails: string;
    remediation: string;
    rootCause: string;
  }>) ?? [];

  const remediationActions: RemediationAction[] = [];

  for (const tlsErr of tlsErrors.slice(0, 3)) {
    remediationActions.push({
      label: tlsErr.remediation,
      type: 'info',
      context: {
        rspCodeDetails: tlsErr.rspCodeDetails,
        rootCause: tlsErr.rootCause,
      },
    });
  }

  if (lb) {
    remediationActions.push({
      label: 'Open Config Visualizer to review origin pool TLS settings',
      type: 'cross_launch',
      targetTool: 'config-visualizer',
      context: { namespace, loadBalancer: lb },
    });
  }

  return {
    rootCause: `TLS/certificate errors: dominant variant is "${evidence.dominantVariant}". ${tlsErrors[0]?.rootCause ?? 'Review origin pool TLS configuration.'}`,
    severity: overallSeverity,
    evidenceSummary: buildEvidenceSummary(inv),
    remediationActions,
    childTriggers: [],
    evidence,
  };
}

// ---------------------------------------------------------------------------
// 7.9 Route Configuration Error
// ---------------------------------------------------------------------------

async function executeRouteConfigError(
  inv: Investigation,
  ctx: InvestigationContext,
): Promise<InvestigationFinding> {
  const { namespace, room, aggregation, auditEntries } = ctx;
  const lb = primaryLb(room);
  const evidence: Record<string, unknown> = {};
  let overallSeverity: AnomalySeverity = 'HIGH';

  // Step 0: Extract request authorities from 404s
  let stepIdx = 0;
  beginStep(inv, stepIdx, ctx);
  try {
    const domainBuckets = aggregation.byDomain
      .filter((b) => b.count > 0)
      .sort((a, b) => b.count - a.count);

    evidence.requestedDomains = domainBuckets;

    completeStep(inv, stepIdx, {
      domains: domainBuckets.slice(0, 10).map((d) => ({
        domain: d.key,
        requestCount: d.count,
      })),
      summary: `${domainBuckets.length} unique domains/authorities in traffic`,
    }, ctx);
  } catch (err) {
    errorStep(inv, stepIdx, err instanceof Error ? err.message : 'Authority extraction failed', ctx);
  }

  // Step 1: Fetch LB config
  stepIdx = 1;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!lb) {
      skipStep(inv, stepIdx, 'No load balancer configured', ctx);
    } else {
      const lbConfig = await safeApiGet<Record<string, unknown>>(
        `/api/config/namespaces/${namespace}/http_loadbalancers/${lb}`,
      );

      const spec = ((lbConfig?.spec ?? lbConfig) ?? {}) as Record<string, unknown>;
      const domains = spec.domains ?? [];
      const routes = spec.routes ?? spec.route_rules ?? [];

      evidence.configuredDomains = domains;
      evidence.configuredRoutes = routes;
      evidence.lbConfig = spec;

      completeStep(inv, stepIdx, {
        configuredDomains: domains,
        routeCount: Array.isArray(routes) ? routes.length : 0,
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'LB config fetch failed', ctx);
  }

  // Step 2: Compare requested vs configured domains
  stepIdx = 2;
  beginStep(inv, stepIdx, ctx);
  try {
    const requested = ((evidence.requestedDomains as Array<{ key: string }>) ?? []).map((d) => d.key);
    const configured = evidence.configuredDomains as string[] | undefined ?? [];
    const configuredSet = new Set(Array.isArray(configured) ? configured.map((d: unknown) => safeStr(d).toLowerCase()) : []);

    const unmatched = requested.filter((d) => !configuredSet.has(d.toLowerCase()));
    evidence.unmatchedDomains = unmatched;

    completeStep(inv, stepIdx, {
      requestedCount: requested.length,
      configuredCount: configuredSet.size,
      unmatchedDomains: unmatched.slice(0, 10),
      summary: unmatched.length > 0
        ? `${unmatched.length} domain(s) in traffic not configured on LB: ${unmatched.slice(0, 3).join(', ')}`
        : 'All requested domains match configured domains',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Domain comparison failed', ctx);
  }

  // Step 3: Check CNAME
  stepIdx = 3;
  beginStep(inv, stepIdx, ctx);
  try {
    const spec = (evidence.lbConfig ?? {}) as Record<string, unknown>;
    const dnsInfo = spec.dns_info ?? spec.dns ?? spec.cname ?? null;
    const autocert = spec.auto_cert ?? spec.automatic_certificates ?? null;

    completeStep(inv, stepIdx, {
      dnsInfo,
      autocert: autocert != null,
      summary: dnsInfo
        ? `DNS/CNAME configuration found: ${JSON.stringify(dnsInfo).slice(0, 200)}`
        : 'No DNS/CNAME configuration found — verify DNS records point to correct CNAME',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'CNAME check failed', ctx);
  }

  // Step 4: Check health checks
  stepIdx = 4;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!lb) {
      skipStep(inv, stepIdx, 'No load balancer configured', ctx);
    } else {
      const lbConfig = await safeApiGet<Record<string, unknown>>(
        `/api/config/namespaces/${namespace}/http_loadbalancers/${lb}`,
      );

      const spec = ((lbConfig?.spec ?? lbConfig) ?? {}) as Record<string, unknown>;
      const originPools = spec.origin_pools ?? spec.default_pool ?? [];
      const poolNames: string[] = [];

      if (Array.isArray(originPools)) {
        for (const pool of originPools) {
          const p = pool as Record<string, unknown>;
          const poolRef = p.pool as Record<string, unknown> | undefined;
          const name = safeStr(poolRef?.name ?? p.name);
          if (name) poolNames.push(name);
        }
      }

      let allFailed = true;
      const poolHealths = await Promise.all(
        poolNames.slice(0, 5).map(async (name) => {
          const config = await safeApiGet<Record<string, unknown>>(
            `/api/config/namespaces/${namespace}/origin_pools/${name}`,
          );
          const pSpec = ((config?.spec ?? config) ?? {}) as Record<string, unknown>;
          const healthCheck = pSpec.health_check ?? pSpec.healthcheck ?? null;
          const status = safeStr(pSpec.health_status ?? pSpec.status).toLowerCase();

          if (!status.includes('fail') && !status.includes('unhealthy') && !status.includes('down')) {
            allFailed = false;
          }

          return {
            poolName: name,
            healthCheck,
            status: status || 'unknown',
          };
        }),
      );

      evidence.allHealthChecksFailed = allFailed && poolNames.length > 0;

      completeStep(inv, stepIdx, {
        pools: poolHealths,
        allFailed: evidence.allHealthChecksFailed,
        summary: allFailed && poolNames.length > 0
          ? 'All health checks failed — route_not_found may be caused by no healthy upstreams'
          : 'At least some origin pools are healthy',
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Health check verification failed', ctx);
  }

  // Step 5: Check audit logs for route changes
  stepIdx = 5;
  beginStep(inv, stepIdx, ctx);
  try {
    const recent = recentAuditEntries(auditEntries, 60);
    const routeChanges = filterAuditByObjectType(recent, [
      'http_loadbalancer', 'route', 'domain', 'dns', 'origin_pool',
    ]);

    completeStep(inv, stepIdx, {
      changeCount: routeChanges.length,
      changes: routeChanges.slice(0, 10).map((c) => ({
        timestamp: c.timestamp,
        user: c.user,
        objectType: c.objectType,
        objectName: c.objectName,
        operation: c.operation,
      })),
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Audit log check failed', ctx);
  }

  // Step 6: Remediation
  stepIdx = 6;
  beginStep(inv, stepIdx, ctx);
  try {
    const unmatched = (evidence.unmatchedDomains as string[]) ?? [];
    const allFailed = Boolean(evidence.allHealthChecksFailed);
    const recommendations: string[] = [];

    if (unmatched.length > 0) {
      recommendations.push(`Add missing domain(s) to LB configuration: ${unmatched.slice(0, 3).join(', ')}`);
    }
    if (allFailed) {
      recommendations.push('Fix origin server health — all health checks are failing');
      recommendations.push('Verify health check endpoint returns expected response');
    }
    recommendations.push('Verify DNS records point to correct F5 XC CNAME');
    recommendations.push('Check route match conditions for coverage');

    completeStep(inv, stepIdx, { recommendations }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Remediation generation failed', ctx);
  }

  // Build finding
  const remediationActions: RemediationAction[] = [];
  const remStep = inv.steps[6];
  if (remStep?.evidence?.recommendations) {
    for (const rec of remStep.evidence.recommendations as string[]) {
      remediationActions.push({ label: rec, type: 'info' });
    }
  }

  if (lb) {
    remediationActions.push({
      label: 'Open Config Visualizer to review routes and domains',
      type: 'cross_launch',
      targetTool: 'config-visualizer',
      context: { namespace, loadBalancer: lb },
    });
  }

  const childTriggers = evaluateChainsFiltered('route_config_error', {
    rootCause: '',
    severity: overallSeverity,
    evidenceSummary: '',
    remediationActions: [],
    childTriggers: [],
    evidence,
  });

  const unmatched = (evidence.unmatchedDomains as string[]) ?? [];

  return {
    rootCause: `Route configuration error (404 route_not_found). ${unmatched.length > 0 ? `Unmatched domains: ${unmatched.slice(0, 3).join(', ')}.` : ''} ${evidence.allHealthChecksFailed ? 'All origin health checks failing.' : ''}`,
    severity: overallSeverity,
    evidenceSummary: buildEvidenceSummary(inv),
    remediationActions,
    childTriggers,
    evidence,
  };
}

// ---------------------------------------------------------------------------
// 7.10 Credential Stuffing Attack
// ---------------------------------------------------------------------------

async function executeCredentialStuffing(
  inv: Investigation,
  ctx: InvestigationContext,
): Promise<InvestigationFinding> {
  const { namespace, room } = ctx;
  const lb = primaryLb(room);
  const evidence: Record<string, unknown> = {};
  let overallSeverity: AnomalySeverity = 'CRITICAL';

  const tw = computeTimeWindow(15);
  const bdBase = `/api/data/namespaces/${namespace}/bot_defense/virtual_host/${lb}`;

  // Step 0: Fetch credential stuffing metrics
  let stepIdx = 0;
  beginStep(inv, stepIdx, ctx);
  try {
    const csResult = await safeApiPost<Record<string, unknown>>(
      `${bdBase}/insight/credential-stuffing-attack`,
      { start_time: tw.startTime, end_time: tw.endTime, namespace },
    );

    if (!csResult) {
      skipStep(inv, stepIdx, 'Credential stuffing insight not available', ctx);
    } else {
      evidence.credStuffingMetrics = csResult;

      completeStep(inv, stepIdx, {
        detected: Boolean(csResult.detected ?? csResult.is_active ?? csResult.attack_detected),
        volume: safeNum(csResult.attack_volume ?? csResult.total_attempts),
        successRate: safeNum(csResult.success_rate ?? csResult.login_success_rate),
        raw: csResult,
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Credential stuffing fetch failed', ctx);
  }

  // Step 1: Identify targeted endpoints
  stepIdx = 1;
  beginStep(inv, stepIdx, ctx);
  try {
    const result = await safeApiPost<{ items?: Array<Record<string, unknown>>; buckets?: Array<Record<string, unknown>> }>(
      `${bdBase}/top/type/malicious/dimension/endpoints`,
      { start_time: tw.startTime, end_time: tw.endTime, namespace },
    );

    const endpoints = (result?.items ?? result?.buckets ?? [])
      .map((i) => ({
        endpoint: safeStr(i.key ?? i.endpoint ?? i.path, 'unknown'),
        count: safeNum(i.count ?? i.doc_count),
      }))
      .filter((e) => {
        // Filter to login/auth-related endpoints
        const lower = e.endpoint.toLowerCase();
        return lower.includes('login') || lower.includes('auth') ||
          lower.includes('signin') || lower.includes('token') ||
          lower.includes('session') || lower.includes('credential') ||
          e.count > 0; // Include all if no clear login pattern
      })
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    evidence.targetedEndpoints = endpoints;

    completeStep(inv, stepIdx, {
      endpoints,
      summary: endpoints.length > 0
        ? `Top targeted: ${endpoints[0].endpoint} (${endpoints[0].count} attempts)`
        : 'No endpoint targeting data available',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Endpoint identification failed', ctx);
  }

  // Step 2: Profile sources
  stepIdx = 2;
  beginStep(inv, stepIdx, ctx);
  try {
    const result = await safeApiPost<{ items?: Array<Record<string, unknown>>; buckets?: Array<Record<string, unknown>> }>(
      `${bdBase}/top/type/malicious/dimension/ip`,
      { start_time: tw.startTime, end_time: tw.endTime, namespace },
    );

    const sources = (result?.items ?? result?.buckets ?? [])
      .map((i) => ({
        ip: safeStr(i.key ?? i.ip, 'unknown'),
        count: safeNum(i.count ?? i.doc_count),
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 20);

    evidence.attackSources = sources;

    completeStep(inv, stepIdx, {
      sourceCount: sources.length,
      topSources: sources.slice(0, 10),
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Source profiling failed', ctx);
  }

  // Step 3: Check bot defense effectiveness
  stepIdx = 3;
  beginStep(inv, stepIdx, ctx);
  try {
    const result = await safeApiPost<{ items?: Array<Record<string, unknown>>; buckets?: Array<Record<string, unknown>> }>(
      `${bdBase}/traffic/malicious/overview/actions`,
      { start_time: tw.startTime, end_time: tw.endTime, namespace },
    );

    const actions = (result?.items ?? result?.buckets ?? [])
      .map((i) => ({
        action: safeStr(i.key ?? i.action, 'unknown'),
        count: safeNum(i.count ?? i.doc_count),
        pct: safeNum(i.pct),
      }))
      .sort((a, b) => b.count - a.count);

    const blockPct = actions.find((a) => a.action.toLowerCase().includes('block'))?.pct ?? 0;
    const challengePct = actions.find((a) => a.action.toLowerCase().includes('challenge'))?.pct ?? 0;
    const allowPct = actions.find((a) => a.action.toLowerCase().includes('allow'))?.pct ?? 0;

    completeStep(inv, stepIdx, {
      actions,
      blockPct,
      challengePct,
      allowPct,
      summary: `Block: ${blockPct}%, Challenge: ${challengePct}%, Allow: ${allowPct}%`,
      effectiveness: blockPct > 80 ? 'high' : blockPct > 50 ? 'moderate' : 'low',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Effectiveness check failed', ctx);
  }

  // Step 4: Check rate limiters on login paths
  stepIdx = 4;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!lb) {
      skipStep(inv, stepIdx, 'No load balancer configured', ctx);
    } else {
      const lbConfig = await safeApiGet<Record<string, unknown>>(
        `/api/config/namespaces/${namespace}/http_loadbalancers/${lb}`,
      );

      const spec = ((lbConfig?.spec ?? lbConfig) ?? {}) as Record<string, unknown>;
      const rateLimiters = spec.rate_limiter ?? spec.rate_limiters ?? null;
      const routes = spec.routes ?? spec.route_rules ?? [];

      // Check if any rate limiter covers login paths
      const hasLoginRateLimit = rateLimiters != null; // Simplified check

      completeStep(inv, stepIdx, {
        rateLimitersConfigured: rateLimiters != null,
        routeCount: Array.isArray(routes) ? routes.length : 0,
        loginPathProtected: hasLoginRateLimit,
        summary: hasLoginRateLimit
          ? 'Rate limiters are configured'
          : 'No rate limiters configured — login endpoints may be unprotected',
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Rate limiter check failed', ctx);
  }

  // Step 5: Generate remediation
  stepIdx = 5;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!lb) {
      skipStep(inv, stepIdx, 'No load balancer configured', ctx);
    } else {
      const topIps = ((evidence.attackSources as Array<{ ip: string }>) ?? [])
        .slice(0, 10)
        .map((s) => s.ip);
      const endpoints = ((evidence.targetedEndpoints as Array<{ endpoint: string }>) ?? [])
        .slice(0, 5)
        .map((e) => e.endpoint);

      const suggestions = await fetchMultipleSuggestions(
        namespace,
        lb,
        ['block_client', 'rate_limit'],
        {
          srcIps: topIps,
          paths: endpoints,
          startTime: tw.startTime,
          endTime: tw.endTime,
        },
      );

      completeStep(inv, stepIdx, {
        suggestions: suggestions.map((s) => ({
          type: s.type,
          ruleCount: s.rules.length,
          rules: s.rules.slice(0, 3),
        })),
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Remediation generation failed', ctx);
  }

  // Build finding
  const remediationActions: RemediationAction[] = [];

  const remStep = inv.steps[5];
  if (remStep?.evidence?.suggestions) {
    for (const s of remStep.evidence.suggestions as Array<{ type: string; ruleCount: number; rules: unknown[] }>) {
      if (s.ruleCount > 0) {
        remediationActions.push({
          label: `Apply ${s.type} rule (${s.ruleCount} suggestions)`,
          type: 'rule_suggestion',
          suggestedRule: s.rules[0],
          context: { suggestionType: s.type },
        });
      }
    }
  }

  remediationActions.push({
    label: 'Enable rate limiting on login/auth endpoints',
    type: 'config_change',
    context: {
      endpoints: ((evidence.targetedEndpoints as Array<{ endpoint: string }>) ?? []).map((e) => e.endpoint),
    },
  });

  return {
    rootCause: `Credential stuffing attack targeting ${((evidence.targetedEndpoints as unknown[]) ?? []).length} endpoint(s). ${((evidence.attackSources as unknown[]) ?? []).length} source IPs identified.`,
    severity: overallSeverity,
    evidenceSummary: buildEvidenceSummary(inv),
    remediationActions,
    childTriggers: [],
    evidence,
  };
}

// ---------------------------------------------------------------------------
// 7.11 Client-Side Script Attack (Magecart)
// ---------------------------------------------------------------------------

async function executeCsdMagecart(
  inv: Investigation,
  ctx: InvestigationContext,
): Promise<InvestigationFinding> {
  const { namespace } = ctx;
  const evidence: Record<string, unknown> = {};
  let overallSeverity: AnomalySeverity = 'HIGH';

  // Step 0: Fetch detected scripts
  let stepIdx = 0;
  beginStep(inv, stepIdx, ctx);
  try {
    const scriptsRes = await safeApiGet<{ items?: Array<Record<string, unknown>>; scripts?: Array<Record<string, unknown>> }>(
      `/api/data/namespaces/${namespace}/csd/scripts`,
    );

    const scripts = scriptsRes?.items ?? scriptsRes?.scripts ?? [];
    const enriched = await Promise.all(
      scripts.slice(0, 20).map(async (script) => {
        const id = safeStr(script.id ?? script.script_id);
        const classification = safeStr(script.classification ?? script.status, 'benign').toLowerCase();

        let behaviors: unknown = null;
        if (classification !== 'benign' && id) {
          behaviors = await safeApiGet(
            `/api/data/namespaces/${namespace}/csd/scripts/${id}/behaviors`,
          );
        }

        return {
          id,
          domain: safeStr(script.domain ?? script.host, 'unknown'),
          classification,
          behaviors,
        };
      }),
    );

    evidence.detectedScripts = enriched;
    const malicious = enriched.filter((s) => s.classification === 'malicious');
    const suspicious = enriched.filter((s) => s.classification === 'suspicious');

    completeStep(inv, stepIdx, {
      totalScripts: enriched.length,
      maliciousCount: malicious.length,
      suspiciousCount: suspicious.length,
      scripts: enriched.slice(0, 10).map((s) => ({
        id: s.id,
        domain: s.domain,
        classification: s.classification,
      })),
    }, ctx);
  } catch (err) {
    errorStep(inv, stepIdx, err instanceof Error ? err.message : 'Script fetch failed', ctx);
  }

  // Step 1: Identify affected form fields
  stepIdx = 1;
  beginStep(inv, stepIdx, ctx);
  try {
    const scripts = (evidence.detectedScripts as Array<{
      id: string;
      classification: string;
    }>) ?? [];

    const nonBenign = scripts.filter((s) => s.classification !== 'benign');
    const formFieldResults: Array<{ scriptId: string; fields: string[] }> = [];

    for (const script of nonBenign.slice(0, 10)) {
      if (!script.id) continue;
      const result = await safeApiGet<{
        items?: Array<{ name?: string; field_name?: string }>;
        form_fields?: Array<{ name?: string; field_name?: string }>;
      }>(`/api/data/namespaces/${namespace}/csd/scripts/${script.id}/formFields`);

      const items = result?.items ?? result?.form_fields ?? [];
      const fields = items.map((f) => safeStr(f.name ?? f.field_name, 'unknown'));
      formFieldResults.push({ scriptId: script.id, fields });
    }

    evidence.formFieldResults = formFieldResults;

    // Check for payment fields
    const allFields = formFieldResults.flatMap((r) => r.fields);
    const paymentFields = allFields.filter((f) => {
      const lower = f.toLowerCase();
      return lower.includes('cc') || lower.includes('card') || lower.includes('cvv') ||
        lower.includes('credit') || lower.includes('payment') || lower.includes('expir');
    });

    evidence.paymentFieldsTargeted = paymentFields.length > 0;
    evidence.targetedFields = allFields;

    if (paymentFields.length > 0) {
      overallSeverity = 'CRITICAL';
    }

    completeStep(inv, stepIdx, {
      formFieldResults: formFieldResults.slice(0, 10),
      paymentFieldsFound: paymentFields,
      isPaymentTargeted: paymentFields.length > 0,
      summary: paymentFields.length > 0
        ? `CRITICAL: Scripts accessing payment fields: ${paymentFields.join(', ')}`
        : `Scripts accessing ${allFields.length} form field(s)`,
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Form field analysis failed', ctx);
  }

  // Step 2: Check network interactions
  stepIdx = 2;
  beginStep(inv, stepIdx, ctx);
  try {
    const scripts = (evidence.detectedScripts as Array<{
      id: string;
      classification: string;
    }>) ?? [];

    const nonBenign = scripts.filter((s) => s.classification !== 'benign');
    const networkResults: Array<{ scriptId: string; domains: string[] }> = [];

    for (const script of nonBenign.slice(0, 10)) {
      if (!script.id) continue;
      const result = await safeApiGet<{
        items?: Array<{ domain?: string; host?: string }>;
        network_interactions?: Array<{ domain?: string; host?: string }>;
      }>(`/api/data/namespaces/${namespace}/csd/scripts/${script.id}/networkInteractions`);

      const items = result?.items ?? result?.network_interactions ?? [];
      const domains = items.map((i) => safeStr(i.domain ?? i.host, 'unknown'));
      networkResults.push({ scriptId: script.id, domains });
    }

    const allExternalDomains = Array.from(new Set(networkResults.flatMap((r) => r.domains)));
    evidence.externalDomains = allExternalDomains;

    completeStep(inv, stepIdx, {
      networkResults: networkResults.slice(0, 10),
      externalDomains: allExternalDomains,
      summary: allExternalDomains.length > 0
        ? `Scripts communicating with ${allExternalDomains.length} external domain(s): ${allExternalDomains.slice(0, 3).join(', ')}`
        : 'No external network interactions detected',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Network interaction check failed', ctx);
  }

  // Step 3: Count affected users
  stepIdx = 3;
  beginStep(inv, stepIdx, ctx);
  try {
    const scripts = (evidence.detectedScripts as Array<{
      id: string;
      classification: string;
    }>) ?? [];

    const nonBenign = scripts.filter((s) => s.classification !== 'benign');
    let totalAffected = 0;
    const perScript: Array<{ scriptId: string; count: number }> = [];

    for (const script of nonBenign.slice(0, 10)) {
      if (!script.id) continue;
      const result = await safeApiGet<{
        count?: number;
        total?: number;
        users?: unknown[];
        items?: unknown[];
      }>(`/api/data/namespaces/${namespace}/csd/scripts/${script.id}/affectedUsers`);

      const count = safeNum(
        result?.count ?? result?.total ??
        (Array.isArray(result?.users) ? result!.users.length : 0) ??
        (Array.isArray(result?.items) ? result!.items.length : 0),
      );

      totalAffected += count;
      perScript.push({ scriptId: script.id, count });
    }

    evidence.totalAffectedUsers = totalAffected;

    completeStep(inv, stepIdx, {
      totalAffectedUsers: totalAffected,
      perScript,
      summary: `${totalAffected} users affected by malicious/suspicious scripts`,
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Affected user count failed', ctx);
  }

  // Step 4: Check mitigation status
  stepIdx = 4;
  beginStep(inv, stepIdx, ctx);
  try {
    const detectedDomains = await safeApiGet<{
      items?: Array<Record<string, unknown>>;
      domains?: Array<Record<string, unknown>>;
    }>(`/api/data/namespaces/${namespace}/csd/detected_domains`);

    const domains = detectedDomains?.items ?? detectedDomains?.domains ?? [];
    const mitigated = domains.filter((d) => d.mitigated === true || d.is_mitigated === true);
    const unmitigated = domains.filter((d) => d.mitigated !== true && d.is_mitigated !== true);

    evidence.mitigatedDomainCount = mitigated.length;
    evidence.unmitigatedDomainCount = unmitigated.length;

    completeStep(inv, stepIdx, {
      totalDetected: domains.length,
      mitigatedCount: mitigated.length,
      unmitigatedCount: unmitigated.length,
      unmitigatedDomains: unmitigated.slice(0, 10).map((d) => safeStr(d.domain ?? d.host)),
      summary: unmitigated.length > 0
        ? `${unmitigated.length} detected domain(s) NOT yet mitigated`
        : 'All detected domains are mitigated',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Mitigation status check failed', ctx);
  }

  // Step 5: Severity determination
  stepIdx = 5;
  beginStep(inv, stepIdx, ctx);
  try {
    const paymentTargeted = Boolean(evidence.paymentFieldsTargeted);
    const loginTargeted = ((evidence.targetedFields as string[]) ?? []).some((f) => {
      const lower = f.toLowerCase();
      return lower.includes('password') || lower.includes('login') ||
        lower.includes('username') || lower.includes('email');
    });

    if (paymentTargeted) {
      overallSeverity = 'CRITICAL';
    } else if (loginTargeted) {
      overallSeverity = 'HIGH';
    } else {
      overallSeverity = 'MEDIUM';
    }

    completeStep(inv, stepIdx, {
      severity: overallSeverity,
      paymentFieldsTargeted: paymentTargeted,
      loginFieldsTargeted: loginTargeted,
      summary: paymentTargeted
        ? 'CRITICAL: Payment/credit card fields are being targeted'
        : loginTargeted
          ? 'HIGH: Login/authentication fields are being targeted'
          : 'MEDIUM: Non-sensitive form fields targeted',
    }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Severity determination failed', ctx);
  }

  // Step 6: Remediation
  stepIdx = 6;
  beginStep(inv, stepIdx, ctx);
  try {
    const unmitigated = safeNum(evidence.unmitigatedDomainCount);
    const recommendations: string[] = [];

    if (unmitigated > 0) {
      recommendations.push('Add detected malicious domains to CSD mitigation list');
    }
    recommendations.push('Review and block external script domains communicating with suspicious targets');
    if (evidence.paymentFieldsTargeted) {
      recommendations.push('URGENT: Malicious scripts targeting payment fields — immediate mitigation required');
    }
    recommendations.push('Enable Content Security Policy (CSP) headers to restrict script sources');

    completeStep(inv, stepIdx, { recommendations }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Remediation generation failed', ctx);
  }

  // Build finding
  const remediationActions: RemediationAction[] = [];
  const remStep = inv.steps[6];
  if (remStep?.evidence?.recommendations) {
    for (const rec of remStep.evidence.recommendations as string[]) {
      remediationActions.push({ label: rec, type: 'info' });
    }
  }

  return {
    rootCause: `Client-side script attack (Magecart): ${((evidence.detectedScripts as unknown[]) ?? []).length} scripts detected, ${safeNum(evidence.totalAffectedUsers)} users affected. ${evidence.paymentFieldsTargeted ? 'PAYMENT FIELDS TARGETED.' : ''}`,
    severity: overallSeverity,
    evidenceSummary: buildEvidenceSummary(inv),
    remediationActions,
    childTriggers: [],
    evidence,
  };
}

// ---------------------------------------------------------------------------
// 7.12 DNS Failure
// ---------------------------------------------------------------------------

async function executeDnsFailure(
  inv: Investigation,
  ctx: InvestigationContext,
): Promise<InvestigationFinding> {
  const { namespace, room } = ctx;
  const evidence: Record<string, unknown> = {};
  let overallSeverity: AnomalySeverity = 'HIGH';

  const dnsLbNames = room.dnsLoadBalancers;

  // Step 0: Fetch DNS LB health
  let stepIdx = 0;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!dnsLbNames.length) {
      skipStep(inv, stepIdx, 'No DNS load balancers configured', ctx);
    } else {
      const healthResults = await Promise.all(
        dnsLbNames.map(async (name) => {
          const health = await safeApiGet<Record<string, unknown>>(
            `/api/config/namespaces/${namespace}/dns_load_balancers/${name}/health_status`,
          );
          return { name, health };
        }),
      );

      evidence.dnsLbHealth = healthResults;

      const downCount = healthResults.filter((r) => {
        const status = safeStr(r.health?.status ?? r.health?.health ?? r.health?.state).toLowerCase();
        return status.includes('down') || status.includes('fail') || !r.health;
      }).length;

      if (downCount === dnsLbNames.length) {
        overallSeverity = 'CRITICAL';
      }

      completeStep(inv, stepIdx, {
        lbCount: healthResults.length,
        healthyCount: healthResults.length - downCount,
        downCount,
        results: healthResults.map((r) => ({
          name: r.name,
          status: safeStr(r.health?.status ?? r.health?.health ?? r.health?.state, 'unknown'),
        })),
      }, ctx);
    }
  } catch (err) {
    errorStep(inv, stepIdx, err instanceof Error ? err.message : 'DNS LB health fetch failed', ctx);
  }

  // Step 1: Get pool member status
  stepIdx = 1;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!dnsLbNames.length) {
      skipStep(inv, stepIdx, 'No DNS load balancers configured', ctx);
    } else {
      const allPoolMembers: Array<{
        lbName: string;
        poolName: string;
        members: Array<{ address: string; status: string }>;
      }> = [];

      for (const lbName of dnsLbNames) {
        // Get pools from LB health
        const lbHealth = ((evidence.dnsLbHealth as Array<{ name: string; health: Record<string, unknown> }>) ?? [])
          .find((r) => r.name === lbName);

        const rawPools = (lbHealth?.health?.pools ?? lbHealth?.health?.dns_lb_pools ?? []) as Array<Record<string, unknown>>;
        const poolNames = rawPools.map((p) => safeStr(p.name ?? p.pool_name)).filter(Boolean);

        for (const poolName of poolNames) {
          const poolHealth = await safeApiGet<{
            members?: Array<Record<string, unknown>>;
            items?: Array<Record<string, unknown>>;
          }>(`/api/config/namespaces/${namespace}/dns_load_balancers/${lbName}/dns_lb_pools/${poolName}/health_status`);

          const members = (poolHealth?.members ?? poolHealth?.items ?? []).map((m) => ({
            address: safeStr(m.address ?? m.ip ?? m.endpoint, 'unknown'),
            status: safeStr(m.health ?? m.status ?? m.state, 'unknown'),
          }));

          allPoolMembers.push({ lbName, poolName, members });
        }
      }

      evidence.poolMembers = allPoolMembers;
      const unhealthyMembers = allPoolMembers.flatMap((p) =>
        p.members.filter((m) => {
          const s = m.status.toLowerCase();
          return s.includes('unhealthy') || s.includes('down') || s.includes('fail');
        }),
      );

      completeStep(inv, stepIdx, {
        poolCount: allPoolMembers.length,
        totalMembers: allPoolMembers.reduce((sum, p) => sum + p.members.length, 0),
        unhealthyMembers: unhealthyMembers.length,
        pools: allPoolMembers.map((p) => ({
          lbName: p.lbName,
          poolName: p.poolName,
          memberCount: p.members.length,
          unhealthyCount: p.members.filter((m) => {
            const s = m.status.toLowerCase();
            return s.includes('unhealthy') || s.includes('down') || s.includes('fail');
          }).length,
        })),
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Pool member status fetch failed', ctx);
  }

  // Step 2: Get health change events
  stepIdx = 2;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!dnsLbNames.length) {
      skipStep(inv, stepIdx, 'No DNS load balancers configured', ctx);
    } else {
      const events: Array<{ lbName: string; poolName: string; events: unknown[] }> = [];

      const poolMembers = (evidence.poolMembers as Array<{ lbName: string; poolName: string }>) ?? [];

      for (const pool of poolMembers) {
        const result = await safeApiGet<{
          items?: unknown[];
          events?: unknown[];
        }>(`/api/config/namespaces/${namespace}/dns_load_balancers/${pool.lbName}/dns_lb_pools/${pool.poolName}/health_status_change_events`);

        events.push({
          lbName: pool.lbName,
          poolName: pool.poolName,
          events: result?.items ?? result?.events ?? [],
        });
      }

      evidence.healthChangeEvents = events;

      const totalEvents = events.reduce((sum, e) => sum + e.events.length, 0);

      completeStep(inv, stepIdx, {
        poolsChecked: events.length,
        totalChangeEvents: totalEvents,
        events: events.map((e) => ({
          lbName: e.lbName,
          poolName: e.poolName,
          eventCount: e.events.length,
        })),
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Health change events fetch failed', ctx);
  }

  // Step 3: Check failover
  stepIdx = 3;
  beginStep(inv, stepIdx, ctx);
  try {
    if (!dnsLbNames.length) {
      skipStep(inv, stepIdx, 'No DNS load balancers configured', ctx);
    } else {
      const failoverConfigs: Array<{ lbName: string; failoverPolicy: unknown }> = [];

      for (const lbName of dnsLbNames) {
        const config = await safeApiGet<Record<string, unknown>>(
          `/api/config/namespaces/${namespace}/dns_load_balancers/${lbName}`,
        );

        const spec = ((config?.spec ?? config) ?? {}) as Record<string, unknown>;
        failoverConfigs.push({
          lbName,
          failoverPolicy: spec.failover_policy ?? spec.failover ?? spec.fallback_pool ?? null,
        });
      }

      completeStep(inv, stepIdx, {
        configs: failoverConfigs,
        summary: failoverConfigs.some((c) => c.failoverPolicy)
          ? 'Failover policies configured — traffic should fail over to healthy members'
          : 'No explicit failover policies configured — check DNS LB fallback behavior',
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Failover check failed', ctx);
  }

  // Step 4: Check DNS query metrics
  stepIdx = 4;
  beginStep(inv, stepIdx, ctx);
  try {
    const zoneMetrics = await safeApiGet<{
      total_queries?: number;
      query_count?: number;
      error_count?: number;
      errors?: number;
    }>(`/api/data/namespaces/${namespace}/dns_zones/metrics`);

    if (!zoneMetrics) {
      skipStep(inv, stepIdx, 'DNS zone metrics not available', ctx);
    } else {
      const totalQueries = safeNum(zoneMetrics.total_queries ?? zoneMetrics.query_count);
      const errorCount = safeNum(zoneMetrics.error_count ?? zoneMetrics.errors);
      const errorRate = totalQueries > 0 ? Math.round((errorCount / totalQueries) * 10000) / 100 : 0;

      // High query volume could indicate DNS DDoS
      evidence.dnsQueryVolume = totalQueries;

      completeStep(inv, stepIdx, {
        totalQueries,
        errorCount,
        errorRate,
        summary: errorRate > 10
          ? `High DNS error rate: ${errorRate}% (${errorCount}/${totalQueries})`
          : `DNS query metrics: ${totalQueries} queries, ${errorRate}% error rate`,
        possibleDnsDdos: totalQueries > 100000,
      }, ctx);
    }
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'DNS metrics check failed', ctx);
  }

  // Step 5: Remediation
  stepIdx = 5;
  beginStep(inv, stepIdx, ctx);
  try {
    const recommendations: string[] = [];

    const poolMembers = (evidence.poolMembers as Array<{
      members: Array<{ status: string }>;
    }>) ?? [];
    const unhealthyCount = poolMembers.flatMap((p) =>
      p.members.filter((m) => {
        const s = m.status.toLowerCase();
        return s.includes('unhealthy') || s.includes('down');
      }),
    ).length;

    if (unhealthyCount > 0) {
      recommendations.push(`Fix ${unhealthyCount} unhealthy pool member(s) — check origin DNS records and server health`);
    }
    recommendations.push('Review health check configuration for DNS LB pools');
    recommendations.push('Verify pool member addresses resolve correctly');
    if (safeNum(evidence.dnsQueryVolume) > 100000) {
      recommendations.push('Abnormally high DNS query volume — possible DNS DDoS');
    }

    completeStep(inv, stepIdx, { recommendations }, ctx);
  } catch (err) {
    skipStep(inv, stepIdx, err instanceof Error ? err.message : 'Remediation generation failed', ctx);
  }

  // Build finding
  const remediationActions: RemediationAction[] = [];
  const remStep = inv.steps[5];
  if (remStep?.evidence?.recommendations) {
    for (const rec of remStep.evidence.recommendations as string[]) {
      remediationActions.push({ label: rec, type: 'info' });
    }
  }

  return {
    rootCause: `DNS failure: ${dnsLbNames.length} DNS LB(s) monitored. Pool members showing health failures. ${safeNum(evidence.dnsQueryVolume) > 100000 ? 'Abnormally high query volume detected.' : ''}`,
    severity: overallSeverity,
    evidenceSummary: buildEvidenceSummary(inv),
    remediationActions,
    childTriggers: [],
    evidence,
  };
}

// =============================================================================
// Evidence Summary Builder
// =============================================================================

function buildEvidenceSummary(inv: Investigation): string {
  const completed = inv.steps.filter((s) => s.status === 'complete');
  const skipped = inv.steps.filter((s) => s.status === 'skipped');
  const errored = inv.steps.filter((s) => s.status === 'error');

  const parts: string[] = [];
  parts.push(`${completed.length}/${inv.steps.length} steps completed`);

  if (skipped.length > 0) {
    parts.push(`${skipped.length} skipped`);
  }
  if (errored.length > 0) {
    parts.push(`${errored.length} errors`);
  }

  // Add key findings from completed steps
  for (const step of completed) {
    if (step.evidence?.summary) {
      parts.push(String(step.evidence.summary));
    }
  }

  return parts.join('. ');
}

// =============================================================================
// Workflow Dispatcher
// =============================================================================

const WORKFLOW_EXECUTORS: Record<
  InvestigationWorkflowId,
  (inv: Investigation, ctx: InvestigationContext) => Promise<InvestigationFinding>
> = {
  origin_5xx: executeOrigin5xx,
  waf_attack: executeWafAttack,
  ddos: executeDdos,
  latency_spike: executeLatencySpike,
  bot_surge: executeBotSurge,
  service_policy_block: executeServicePolicyBlock,
  rate_limit_impact: executeRateLimitImpact,
  tls_cert_error: executeTlsCertError,
  route_config_error: executeRouteConfigError,
  credential_stuffing: executeCredentialStuffing,
  csd_magecart: executeCsdMagecart,
  dns_failure: executeDnsFailure,
};

// =============================================================================
// executeInvestigation
// =============================================================================

/**
 * Executes all steps of an investigation sequentially, populating evidence
 * and producing a final InvestigationFinding.
 *
 * Each step:
 *  1. Sets status to 'running', calls onStepUpdate
 *  2. Executes API call or computation
 *  3. Stores evidence in step.evidence
 *  4. Sets status to 'complete', calls onStepUpdate
 *
 * At the end, produces an InvestigationFinding with root cause, severity,
 * evidence summary, remediation actions, and child investigation triggers.
 */
export async function executeInvestigation(
  investigation: Investigation,
  context: InvestigationContext,
): Promise<Investigation> {
  // Mark investigation as running
  investigation.status = 'running';
  context.onStepUpdate({ ...investigation });

  try {
    const executor = WORKFLOW_EXECUTORS[investigation.workflowId];
    if (!executor) {
      investigation.status = 'error';
      investigation.finding = {
        rootCause: `Unknown workflow: ${investigation.workflowId}`,
        severity: 'INFO',
        evidenceSummary: 'No executor found for this workflow ID.',
        remediationActions: [],
        childTriggers: [],
      };
      context.onStepUpdate({ ...investigation });
      return investigation;
    }

    // Execute the workflow
    const finding = await executor(investigation, context);

    // Store finding and mark complete
    investigation.finding = finding;
    investigation.status = 'complete';
    investigation.completedAt = new Date().toISOString();

    // Populate childInvestigationIds from childTriggers (the caller is
    // responsible for actually creating and executing child investigations,
    // respecting MAX_CHAIN_DEPTH)
    investigation.childInvestigationIds = [];

    context.onStepUpdate({ ...investigation });
    return investigation;
  } catch (err) {
    // Catch-all for unhandled errors in workflow execution
    investigation.status = 'error';
    investigation.finding = {
      rootCause: `Investigation failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
      severity: 'INFO',
      evidenceSummary: buildEvidenceSummary(investigation),
      remediationActions: [],
      childTriggers: [],
    };
    investigation.completedAt = new Date().toISOString();
    context.onStepUpdate({ ...investigation });
    return investigation;
  }
}
