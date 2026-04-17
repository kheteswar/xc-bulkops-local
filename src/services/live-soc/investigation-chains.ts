// =============================================================================
// Live SOC Monitoring Room — Investigation Chains
// =============================================================================
// Defines chain triggers that link parent investigation findings to child
// investigation workflows. When a parent investigation completes, its finding
// is evaluated against these triggers to determine if follow-up investigations
// should be spawned.
//
// From spec Section 8.1:
//   Origin 5xx → TLS (if TLS errors), terminal (if via_upstream),
//                capacity (if circuit breaker), config (if recent change)
//   DDoS       → WAF Attack (if WAF spiking), Rate Limit Impact (if rate limiters firing)
//   WAF Attack → Bot Surge (if bot dominant), terminal FP (if FP score > 70)
//   Latency    → terminal recommendation (if cross-site routing)
//   Route Conf → Origin Health (if health checks all failed)
//   Bot Surge  → Credential Stuffing (if detected)
// =============================================================================

import type {
  ChainTrigger,
  InvestigationFinding,
  InvestigationWorkflowId,
} from './types';

// =============================================================================
// Chain Trigger Definitions
// =============================================================================

export const CHAIN_TRIGGERS: ChainTrigger[] = [
  // ---------------------------------------------------------------------------
  // Origin 5xx chains
  // ---------------------------------------------------------------------------
  {
    parentWorkflow: 'origin_5xx',
    condition: (finding: InvestigationFinding): boolean => {
      // TLS errors are dominant in the evidence
      const evidence = finding.evidence ?? {};
      const errorBreakdown = evidence.errorBreakdown as Array<{ details: string; count: number }> | undefined;
      if (!errorBreakdown) {
        // Fallback: check dominantErrorPattern string
        const dominantError = String(evidence.dominantErrorPattern ?? '').toLowerCase();
        return (
          dominantError.includes('tls_error') ||
          dominantError.includes('certificate_verify_failed') ||
          dominantError.includes('wrong_version_number') ||
          dominantError.includes('connection_reset')
        );
      }

      const totalErrors = errorBreakdown.reduce((sum, e) => sum + e.count, 0);
      if (totalErrors === 0) return false;

      const tlsErrors = errorBreakdown
        .filter((e) => /tls|ssl|certificate|wrong_version/i.test(e.details))
        .reduce((sum, e) => sum + e.count, 0);

      return tlsErrors / totalErrors > 0.3;
    },
    childWorkflow: 'tls_cert_error',
    reason: 'TLS/certificate errors are dominant (>30% of 5xx errors)',
  },
  {
    parentWorkflow: 'origin_5xx',
    condition: (finding: InvestigationFinding): boolean => {
      // via_upstream is dominant — origin itself is returning 503
      const evidence = finding.evidence ?? {};
      const errorBreakdown = evidence.errorBreakdown as Array<{ details: string; count: number }> | undefined;
      if (!errorBreakdown) {
        const dominantError = String(evidence.dominantErrorPattern ?? '').toLowerCase();
        return dominantError.includes('via_upstream');
      }

      const totalErrors = errorBreakdown.reduce((sum, e) => sum + e.count, 0);
      if (totalErrors === 0) return false;

      const viaUpstream = errorBreakdown
        .filter((e) => /via_upstream/i.test(e.details))
        .reduce((sum, e) => sum + e.count, 0);

      return viaUpstream / totalErrors > 0.5;
    },
    childWorkflow: null, // Terminal — no further investigation
    reason: 'Origin itself is returning 503 (via_upstream dominant) — investigate origin server directly',
  },
  {
    parentWorkflow: 'origin_5xx',
    condition: (finding: InvestigationFinding): boolean => {
      // Circuit breaker (UO/UF response flags)
      const evidence = finding.evidence ?? {};
      return Boolean(evidence.circuitBreakerTriggered);
    },
    childWorkflow: null, // Terminal — capacity assessment recommendation
    reason: 'Circuit breaker triggered (UpstreamOverflow) — increase connection limits or add origins',
  },
  {
    parentWorkflow: 'origin_5xx',
    condition: (finding: InvestigationFinding): boolean => {
      // Recent config change detected
      const evidence = finding.evidence ?? {};
      return Boolean(evidence.recentConfigChange);
    },
    childWorkflow: 'route_config_error',
    reason: 'Recent configuration change detected — investigating for config-related root cause',
  },

  // ---------------------------------------------------------------------------
  // DDoS chains
  // ---------------------------------------------------------------------------
  {
    parentWorkflow: 'ddos',
    condition: (finding: InvestigationFinding): boolean => {
      // WAF signatures also spiking
      const evidence = finding.evidence ?? {};
      return Boolean(evidence.wafSpiking || evidence.wafSignaturesSpiking);
    },
    childWorkflow: 'waf_attack',
    reason: 'WAF signatures spiking alongside traffic surge — investigating attack patterns',
  },
  {
    parentWorkflow: 'ddos',
    condition: (finding: InvestigationFinding): boolean => {
      // Rate limiters firing
      const evidence = finding.evidence ?? {};
      return Boolean(evidence.rateLimitersFiring);
    },
    childWorkflow: 'rate_limit_impact',
    reason: 'Rate limiters are actively triggering — assessing rate limit impact on legitimate traffic',
  },

  // ---------------------------------------------------------------------------
  // WAF Attack chains
  // ---------------------------------------------------------------------------
  {
    parentWorkflow: 'waf_attack',
    condition: (finding: InvestigationFinding): boolean => {
      // Bot classifications are dominant in attack traffic
      const evidence = finding.evidence ?? {};
      return Boolean(evidence.botDominant || evidence.botClassificationDominant);
    },
    childWorkflow: 'bot_surge',
    reason: 'Bot-classified traffic is dominant in WAF attack sources — investigating bot surge',
  },
  {
    parentWorkflow: 'waf_attack',
    condition: (finding: InvestigationFinding): boolean => {
      // High FP score for top signatures
      const evidence = finding.evidence ?? {};
      const fpScore = Number(evidence.topFpScore ?? evidence.topSignatureFpScore ?? 0);
      return fpScore > 70;
    },
    childWorkflow: null, // Terminal — FP assessment recommendation
    reason: 'Top WAF signatures have FP score > 70% — likely false positives, recommend WAF exclusion rules',
  },

  // ---------------------------------------------------------------------------
  // Latency Spike chains
  // ---------------------------------------------------------------------------
  {
    parentWorkflow: 'latency_spike',
    condition: (finding: InvestigationFinding): boolean => {
      // Cross-site routing detected
      const evidence = finding.evidence ?? {};
      const crossSitePct = Number(evidence.crossSiteRoutingPct ?? 0);
      return Boolean(evidence.crossSiteRoutingDetected) || crossSitePct > 10;
    },
    childWorkflow: null, // Terminal — recommend LocalEndpointsPreferred
    reason: 'Cross-site routing is causing latency — recommend enabling LocalEndpointsPreferred',
  },

  // ---------------------------------------------------------------------------
  // Route Config Error chains
  // ---------------------------------------------------------------------------
  {
    parentWorkflow: 'route_config_error',
    condition: (finding: InvestigationFinding): boolean => {
      // All health checks failed
      const evidence = finding.evidence ?? {};
      return Boolean(evidence.allHealthChecksFailed);
    },
    childWorkflow: 'origin_5xx',
    reason: 'All origin health checks have failed — investigating origin health',
  },

  // ---------------------------------------------------------------------------
  // Bot Surge chains
  // ---------------------------------------------------------------------------
  {
    parentWorkflow: 'bot_surge',
    condition: (finding: InvestigationFinding): boolean => {
      // Credential stuffing detected
      const evidence = finding.evidence ?? {};
      return Boolean(evidence.credentialStuffingDetected);
    },
    childWorkflow: 'credential_stuffing',
    reason: 'Credential stuffing attack detected within bot surge — investigating login abuse',
  },
];

// =============================================================================
// Chain Evaluation
// =============================================================================

/**
 * Evaluates all chain triggers for a given investigation finding.
 * Returns an array of child workflows that should be spawned.
 *
 * The evaluator:
 * 1. Filters triggers to those matching the parent workflow ID
 * 2. Tests each trigger's condition against the finding
 * 3. Returns matching child workflow IDs with reasons
 *
 * Note: `childWorkflow: null` means the trigger is terminal —
 * it produces a recommendation but doesn't spawn a child investigation.
 * Terminal triggers are still returned so the UI can display the reason.
 *
 * @param finding - The completed investigation's finding
 * @param parentWorkflow - The workflow ID of the completed investigation
 * @returns Array of child workflows to spawn (including null for terminal triggers)
 */
export function evaluateChains(
  finding: InvestigationFinding,
  parentWorkflow: InvestigationWorkflowId
): Array<{ workflowId: InvestigationWorkflowId | null; reason: string }> {
  const results: Array<{ workflowId: InvestigationWorkflowId | null; reason: string }> = [];

  for (const trigger of CHAIN_TRIGGERS) {
    if (trigger.parentWorkflow !== parentWorkflow) continue;

    try {
      if (trigger.condition(finding)) {
        results.push({
          workflowId: trigger.childWorkflow,
          reason: trigger.reason,
        });
      }
    } catch {
      // Condition evaluation failed — skip this trigger silently.
      // This prevents one bad trigger from blocking all chain evaluation.
    }
  }

  return results;
}

// =============================================================================
// Chain Depth Management
// =============================================================================

/** Maximum depth for investigation chains to prevent runaway chains. */
export const MAX_CHAIN_DEPTH = 3;

/**
 * Computes the depth of an investigation chain by following
 * parentInvestigationId links.
 *
 * @param investigationId - The investigation to check depth for
 * @param investigationMap - Map of investigation ID to its parentInvestigationId
 * @returns Depth (0 = root, 1 = first child, etc.)
 */
export function getChainDepth(
  investigationId: string,
  investigationMap: Map<string, string | undefined>
): number {
  let depth = 0;
  let currentId: string | undefined = investigationId;

  while (currentId) {
    const parentId = investigationMap.get(currentId);
    if (!parentId) break;
    depth++;
    currentId = parentId;

    // Safety: prevent infinite loops
    if (depth > MAX_CHAIN_DEPTH + 5) break;
  }

  return depth;
}

/**
 * Determines if a chain can spawn a child investigation.
 *
 * @param parentInvestigationId - The parent investigation ID
 * @param investigationMap - Map of investigation ID to its parentInvestigationId
 * @returns true if a child can be spawned (depth < MAX_CHAIN_DEPTH)
 */
export function canSpawnChild(
  parentInvestigationId: string,
  investigationMap: Map<string, string | undefined>
): boolean {
  const depth = getChainDepth(parentInvestigationId, investigationMap);
  return depth < MAX_CHAIN_DEPTH;
}

// =============================================================================
// Workflow Name Mapping
// =============================================================================

/** Human-readable names for investigation workflows. */
export const WORKFLOW_NAMES: Record<InvestigationWorkflowId, string> = {
  origin_5xx: 'Origin 5xx Investigation',
  waf_attack: 'WAF Attack Investigation',
  ddos: 'DDoS Detection',
  latency_spike: 'Latency Spike Investigation',
  bot_surge: 'Bot Surge Investigation',
  service_policy_block: 'Service Policy Block Surge',
  rate_limit_impact: 'Rate Limit Impact Assessment',
  tls_cert_error: 'TLS/Certificate Error',
  route_config_error: 'Route Configuration Error',
  credential_stuffing: 'Credential Stuffing Investigation',
  csd_magecart: 'Client-Side Script Attack (Magecart)',
  dns_failure: 'DNS Failure Investigation',
};

/** Maps anomaly detector IDs to the investigation workflow they should trigger. */
export const DETECTOR_TO_WORKFLOW: Partial<Record<number, InvestigationWorkflowId>> = {
  1: 'ddos',               // RPS Spike → DDoS (if sec events too)
  2: 'origin_5xx',         // RPS Drop → Origin investigation
  3: 'origin_5xx',         // 5xx Error Spike → Origin 5xx
  4: 'route_config_error', // 4xx Error Spike → Route Config (if 404)
  5: 'waf_attack',         // WAF Surge → WAF Attack
  7: 'latency_spike',      // Latency Spike → Latency
  8: 'origin_5xx',         // Origin Down → Origin 5xx
  10: 'bot_surge',         // Bot Surge (AL) → Bot
  11: 'rate_limit_impact', // Rate Limit Fire → Rate Limit Impact
  16: 'bot_surge',         // Bot Traffic Surge (BD) → Bot
  17: 'credential_stuffing', // Credential Stuffing → Credential Stuffing
  18: 'dns_failure',       // Synthetic Monitor Fail → DNS Failure (as proxy)
  19: 'dns_failure',       // DNS Health Degradation → DNS Failure
  20: 'csd_magecart',      // Client-Side Script Alert → Magecart
};
