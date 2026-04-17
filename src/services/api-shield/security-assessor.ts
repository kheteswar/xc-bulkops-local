/**
 * API Shield Advisor — Security Assessor
 *
 * Orchestrates the full API security assessment and generates prioritized
 * recommendations. Coordinates config scanning, API discovery fetching,
 * traffic profiling, and security events collection, then maps results
 * to security controls, calculates scores, and produces actionable
 * recommendations.
 */

import { apiClient } from '../api';
import { scanLBConfigs, assessControlStatus } from './config-scanner';
import { fetchAPIDiscoveryData } from './api-discovery-fetcher';
import { profileTraffic } from './traffic-profiler';
import type {
  AssessmentConfig,
  AssessmentResult,
  SecurityControl,
  ControlPhase,
  ControlPriority,
  ControlStatusValue,
  LBSecurityConfig,
  APIDiscoveryInsight,
  TrafficProfileInsight,
  SecuritySummaryInsight,
  Recommendation,
  PhaseProgress,
  OWASPCoverage,
  DomainScore,
} from './types';

// ═══════════════════════════════════════════════════════════════════
// CONTROL DEFINITIONS
// ═══════════════════════════════════════════════════════════════════

/**
 * Master list of security controls evaluated by the API Shield Advisor.
 * Organized by deployment phase (foundation → visibility → enforcement → advanced).
 */
interface ControlDefinition {
  id: string;
  name: string;
  description: string;
  phase: ControlPhase;
  priority: ControlPriority;
  owaspMapping: string[];
}

const CONTROL_DEFINITIONS: ControlDefinition[] = [
  // ─── Foundation Phase ───
  {
    id: 'waf',
    name: 'Web Application Firewall',
    description: 'Protects against OWASP Top 10 web attacks including injection, XSS, and SSRF',
    phase: 'foundation',
    priority: 'critical',
    owaspMapping: ['API1', 'API3', 'API8'],
  },
  {
    id: 'ddos-protection',
    name: 'L7 DDoS Protection',
    description: 'Automatic detection and mitigation of application-layer DDoS attacks',
    phase: 'foundation',
    priority: 'critical',
    owaspMapping: ['API4'],
  },
  {
    id: 'ip-reputation',
    name: 'IP Reputation',
    description: 'Blocks traffic from known malicious IPs using threat intelligence feeds',
    phase: 'foundation',
    priority: 'high',
    owaspMapping: ['API4', 'API8'],
  },
  {
    id: 'cors',
    name: 'CORS Policy',
    description: 'Controls cross-origin resource sharing to prevent unauthorized API access from browsers',
    phase: 'foundation',
    priority: 'medium',
    owaspMapping: ['API7'],
  },

  // ─── Visibility Phase ───
  {
    id: 'api-discovery',
    name: 'API Discovery',
    description: 'Automatically discovers and catalogs API endpoints from live traffic',
    phase: 'visibility',
    priority: 'high',
    owaspMapping: ['API9'],
  },
  {
    id: 'api-definition',
    name: 'API Definition',
    description: 'OpenAPI/Swagger spec uploaded for schema-based protection',
    phase: 'visibility',
    priority: 'high',
    owaspMapping: ['API9', 'API6'],
  },
  {
    id: 'user-identification',
    name: 'User Identification',
    description: 'Identifies and tracks API consumers by IP, header, or cookie for per-user analytics',
    phase: 'visibility',
    priority: 'medium',
    owaspMapping: ['API1', 'API2'],
  },
  {
    id: 'sensitive-data',
    name: 'Sensitive Data Discovery',
    description: 'Detects PII and sensitive data in API responses to prevent data leakage',
    phase: 'visibility',
    priority: 'high',
    owaspMapping: ['API3', 'API6'],
  },

  // ─── Enforcement Phase ───
  {
    id: 'schema-validation',
    name: 'API Schema Validation',
    description: 'Validates API requests and responses against OpenAPI spec for type/format enforcement',
    phase: 'enforcement',
    priority: 'critical',
    owaspMapping: ['API3', 'API6', 'API8'],
  },
  {
    id: 'rate-limiting',
    name: 'Rate Limiting',
    description: 'Enforces request rate limits per user/IP to prevent abuse and resource exhaustion',
    phase: 'enforcement',
    priority: 'critical',
    owaspMapping: ['API4'],
  },
  {
    id: 'bot-defense',
    name: 'Bot Defense',
    description: 'Detects and mitigates automated bot traffic using JavaScript challenges and ML',
    phase: 'enforcement',
    priority: 'high',
    owaspMapping: ['API4', 'API2'],
  },
  {
    id: 'service-policy',
    name: 'Service Policies',
    description: 'Custom request/response rules for access control, header manipulation, and routing',
    phase: 'enforcement',
    priority: 'medium',
    owaspMapping: ['API1', 'API5'],
  },
  {
    id: 'data-guard',
    name: 'Data Guard',
    description: 'Masks or blocks sensitive data patterns (SSN, credit cards) in API responses',
    phase: 'enforcement',
    priority: 'high',
    owaspMapping: ['API3', 'API6'],
  },

  // ─── Advanced Phase ───
  {
    id: 'malicious-user',
    name: 'Malicious User Detection',
    description: 'ML-based behavioral analysis that progressively challenges suspicious users',
    phase: 'advanced',
    priority: 'high',
    owaspMapping: ['API2', 'API4'],
  },
  {
    id: 'mtls',
    name: 'Mutual TLS (mTLS)',
    description: 'Client certificate authentication for zero-trust API access',
    phase: 'advanced',
    priority: 'medium',
    owaspMapping: ['API1', 'API2'],
  },
  {
    id: 'slow-ddos',
    name: 'Slow DDoS Mitigation',
    description: 'Protection against Slowloris and Slow POST attacks with custom timeouts',
    phase: 'advanced',
    priority: 'medium',
    owaspMapping: ['API4'],
  },
  {
    id: 'api-protection',
    name: 'Full API Protection',
    description: 'Combined API definition + schema validation for complete request/response enforcement',
    phase: 'advanced',
    priority: 'high',
    owaspMapping: ['API3', 'API6', 'API8', 'API9'],
  },
];

// ═══════════════════════════════════════════════════════════════════
// OWASP API SECURITY TOP 10 (2023)
// ═══════════════════════════════════════════════════════════════════

const OWASP_API_TOP_10 = [
  { id: 'API1', name: 'Broken Object Level Authorization', description: 'APIs exposing endpoints that handle object IDs without proper authorization checks' },
  { id: 'API2', name: 'Broken Authentication', description: 'Weak or missing authentication mechanisms allowing unauthorized access' },
  { id: 'API3', name: 'Broken Object Property Level Authorization', description: 'Excessive data exposure or mass assignment vulnerabilities' },
  { id: 'API4', name: 'Unrestricted Resource Consumption', description: 'Missing or inadequate rate limiting leading to DoS or resource exhaustion' },
  { id: 'API5', name: 'Broken Function Level Authorization', description: 'Complex access control policies with unclear admin/user separation' },
  { id: 'API6', name: 'Unrestricted Access to Sensitive Business Flows', description: 'APIs vulnerable to abuse through automated access to business flows' },
  { id: 'API7', name: 'Server-Side Request Forgery', description: 'APIs fetching remote resources without proper URL validation' },
  { id: 'API8', name: 'Security Misconfiguration', description: 'Missing security hardening, permissive CORS, verbose errors, missing patches' },
  { id: 'API9', name: 'Improper Inventory Management', description: 'Exposed undocumented/shadow APIs, outdated versions, missing deprecation' },
  { id: 'API10', name: 'Unsafe Consumption of APIs', description: 'Insufficient validation of data from third-party API integrations' },
];

// ═══════════════════════════════════════════════════════════════════
// SECURITY EVENTS FETCHER
// ═══════════════════════════════════════════════════════════════════

interface SecurityEventResponse {
  events?: unknown[];
  total_hits?: number | string | { value: number };
}

function parseTotalHits(rawHits: unknown): number {
  if (typeof rawHits === 'number' && isFinite(rawHits)) return Math.floor(rawHits);
  if (typeof rawHits === 'string') {
    const parsed = parseInt(rawHits, 10);
    return isFinite(parsed) ? parsed : 0;
  }
  if (rawHits && typeof rawHits === 'object' && 'value' in (rawHits as Record<string, unknown>)) {
    return parseInt(String((rawHits as Record<string, unknown>).value), 10) || 0;
  }
  return 0;
}

/**
 * Fetches a summary of security events for the given LBs.
 * Returns categorized event counts and top attack patterns.
 */
async function fetchSecurityEventsSummary(
  namespace: string,
  lbNames: string[],
  onProgress: (msg: string, pct: number) => void
): Promise<SecuritySummaryInsight> {
  const vhQueries = lbNames.map(name => `vh_name="ves-io-http-loadbalancer-${name}"`);
  const query = vhQueries.length === 1
    ? `{${vhQueries[0]}}`
    : `{${vhQueries.join(' OR ')}}`;

  const endTime = new Date().toISOString();
  const startTime = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  const result: SecuritySummaryInsight = {
    totalSecurityEvents: 0,
    wafEvents: 0,
    botEvents: 0,
    ddosEvents: 0,
    rateLimitEvents: 0,
    apiViolationEvents: 0,
    topAttackTypes: [],
    topSourceIPs: [],
    topTargetPaths: [],
  };

  try {
    onProgress('Fetching security events summary...', 10);

    const response = await apiClient.post<SecurityEventResponse>(
      `/api/data/namespaces/${namespace}/app_security/events`,
      {
        query,
        namespace,
        start_time: startTime,
        end_time: endTime,
        scroll: false,
        limit: 200,
      }
    );

    const totalHits = parseTotalHits(response.total_hits);
    result.totalSecurityEvents = Math.max(totalHits, (response.events || []).length);

    if (!response.events || response.events.length === 0) {
      return result;
    }

    // Parse events — F5 XC may return them as JSON strings
    let events = response.events;
    if (events.length > 0 && typeof events[0] === 'string') {
      events = events.map(e => {
        try { return JSON.parse(e as string); }
        catch { return {}; }
      });
    }

    // Categorize events
    const attackTypeCounts = new Map<string, number>();
    const srcIpCounts = new Map<string, number>();
    const targetPathCounts = new Map<string, number>();

    for (const raw of events) {
      if (!raw || typeof raw !== 'object') continue;
      const evt = raw as Record<string, unknown>;

      const evtType = ((evt.sec_event_type as string) || '').toLowerCase();
      const evtName = (evt.sec_event_name as string) || '';

      // Categorize
      if (evtType.includes('waf') || evtType.includes('app_firewall')) {
        result.wafEvents++;
      } else if (evtType.includes('bot')) {
        result.botEvents++;
      } else if (evtType.includes('ddos') || evtType.includes('dos')) {
        result.ddosEvents++;
      } else if (evtType.includes('rate_limit') || evtType.includes('rate_limiter')) {
        result.rateLimitEvents++;
      } else if (evtType.includes('api') || evtType.includes('schema')) {
        result.apiViolationEvents++;
      }

      // Track attack types
      const attackType = evtName || evtType || 'unknown';
      attackTypeCounts.set(attackType, (attackTypeCounts.get(attackType) || 0) + 1);

      // Track source IPs
      const srcIp = (evt.src_ip as string) || '';
      if (srcIp) srcIpCounts.set(srcIp, (srcIpCounts.get(srcIp) || 0) + 1);

      // Track target paths
      const path = (evt.req_path as string) || '';
      if (path) targetPathCounts.set(path, (targetPathCounts.get(path) || 0) + 1);
    }

    result.topAttackTypes = [...attackTypeCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([type, count]) => ({ type, count }));

    result.topSourceIPs = [...srcIpCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ip, count]) => ({ ip, count }));

    result.topTargetPaths = [...targetPathCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([path, count]) => ({ path, count }));

    console.log(
      `[SecurityAssessor] Security events: ${result.totalSecurityEvents} total, ` +
      `${result.wafEvents} WAF, ${result.botEvents} bot, ${result.ddosEvents} DDoS, ` +
      `${result.rateLimitEvents} rate limit, ${result.apiViolationEvents} API violations`
    );
  } catch (err) {
    console.warn('[SecurityAssessor] Failed to fetch security events:', err);
  }

  return result;
}

// ═══════════════════════════════════════════════════════════════════
// MAP CONTROLS FROM CONFIG SCAN
// ═══════════════════════════════════════════════════════════════════

/**
 * Maps control definitions to their actual status based on scanned LB configs.
 */
function mapControls(configs: LBSecurityConfig[]): SecurityControl[] {
  return CONTROL_DEFINITIONS.map(def => {
    const status = assessControlStatus(configs, def.id);
    return {
      id: def.id,
      name: def.name,
      description: def.description,
      phase: def.phase,
      priority: def.priority,
      status: status.status,
      details: status.details,
      owaspMapping: def.owaspMapping,
    };
  });
}

// ═══════════════════════════════════════════════════════════════════
// SCORING
// ═══════════════════════════════════════════════════════════════════

/** Weights for each phase in overall score */
const PHASE_WEIGHTS: Record<ControlPhase, number> = {
  foundation: 0.35,
  visibility: 0.25,
  enforcement: 0.30,
  advanced: 0.10,
};

/** Weight multiplier by control priority */
const PRIORITY_WEIGHTS: Record<ControlPriority, number> = {
  critical: 3,
  high: 2,
  medium: 1,
  low: 0.5,
};

/** Score contribution for each status */
const STATUS_SCORES: Record<ControlStatusValue, number> = {
  enabled: 1.0,
  partial: 0.5,
  disabled: 0,
  unknown: 0,
};

/**
 * Calculates per-domain security scores.
 */
function calculateDomainScores(
  configs: LBSecurityConfig[],
  controls: SecurityControl[]
): DomainScore[] {
  const scores: DomainScore[] = [];

  for (const config of configs) {
    const phases: Record<ControlPhase, { score: number; maxScore: number }> = {
      foundation: { score: 0, maxScore: 0 },
      visibility: { score: 0, maxScore: 0 },
      enforcement: { score: 0, maxScore: 0 },
      advanced: { score: 0, maxScore: 0 },
    };

    let enabledCount = 0;

    for (const control of controls) {
      // Determine per-LB status for this control
      const singleStatus = assessControlStatus([config], control.id);
      const weight = PRIORITY_WEIGHTS[control.priority];
      const statusScore = STATUS_SCORES[singleStatus.status] * weight;
      const maxScore = weight;

      phases[control.phase].score += statusScore;
      phases[control.phase].maxScore += maxScore;

      if (singleStatus.status === 'enabled') enabledCount++;
    }

    const phaseScores: Record<string, number> = {};
    for (const [phase, vals] of Object.entries(phases)) {
      phaseScores[phase] = vals.maxScore > 0
        ? Math.round((vals.score / vals.maxScore) * 100)
        : 0;
    }

    // Weighted overall score
    let overallScore = 0;
    for (const [phase, weight] of Object.entries(PHASE_WEIGHTS)) {
      overallScore += (phaseScores[phase] || 0) * weight;
    }

    const domains = config.domains.length > 0
      ? config.domains
      : [config.name];

    for (const domain of domains) {
      scores.push({
        domain,
        lbName: config.name,
        overallScore: Math.round(overallScore),
        foundationScore: phaseScores.foundation,
        visibilityScore: phaseScores.visibility,
        enforcementScore: phaseScores.enforcement,
        advancedScore: phaseScores.advanced,
        enabledControls: enabledCount,
        totalControls: controls.length,
      });
    }
  }

  return scores;
}

/**
 * Calculates OWASP API Security Top 10 coverage.
 */
function calculateOWASPCoverage(controls: SecurityControl[]): OWASPCoverage[] {
  return OWASP_API_TOP_10.map(owasp => {
    const coveringControls = controls.filter(
      c => c.owaspMapping.includes(owasp.id) && c.status === 'enabled'
    );
    const totalMapping = controls.filter(
      c => c.owaspMapping.includes(owasp.id)
    );

    const coveragePercent = totalMapping.length > 0
      ? Math.round((coveringControls.length / totalMapping.length) * 100)
      : 0;

    return {
      id: owasp.id,
      name: owasp.name,
      riskName: owasp.name,
      description: owasp.description,
      coveredByControls: coveringControls.map(c => c.id),
      coveragePercent,
      score: coveragePercent,
      status: coveragePercent >= 80 ? 'fully_covered' as const : coveragePercent > 0 ? 'partially_covered' as const : 'not_covered' as const,
    };
  });
}

// ═══════════════════════════════════════════════════════════════════
// PUBLIC: CALCULATE PHASE PROGRESS
// ═══════════════════════════════════════════════════════════════════

/**
 * Calculates deployment phase progress from control statuses.
 */
export function calculatePhaseProgress(controls: SecurityControl[]): PhaseProgress[] {
  const phases: ControlPhase[] = ['foundation', 'visibility', 'enforcement', 'advanced'];
  const phaseNames: Record<ControlPhase, string> = {
    foundation: 'Foundation',
    visibility: 'Visibility',
    enforcement: 'Enforcement',
    advanced: 'Advanced',
  };

  return phases.map(phase => {
    const phaseControls = controls.filter(c => c.phase === phase);
    const enabled = phaseControls.filter(c => c.status === 'enabled').length;
    const partial = phaseControls.filter(c => c.status === 'partial').length;
    const disabled = phaseControls.filter(c => c.status === 'disabled' || c.status === 'unknown').length;
    const total = phaseControls.length;

    const completionPercent = total > 0
      ? Math.round(((enabled + partial * 0.5) / total) * 100)
      : 0;

    return {
      phase,
      phaseName: phaseNames[phase],
      name: phaseNames[phase],
      totalControls: total,
      enabledControls: enabled,
      partialControls: partial,
      disabledControls: disabled,
      completionPercent,
      progress: completionPercent,
      status: completionPercent === 100 ? 'complete' as const : completionPercent > 0 ? 'in_progress' as const : 'not_started' as const,
    };
  });
}

// ═══════════════════════════════════════════════════════════════════
// PUBLIC: GENERATE RECOMMENDATIONS
// ═══════════════════════════════════════════════════════════════════

/**
 * Generates prioritized, data-driven recommendations based on control
 * statuses and optional discovery/traffic/security insights.
 */
export function generateRecommendations(
  controls: SecurityControl[],
  discovery: APIDiscoveryInsight | null,
  traffic: TrafficProfileInsight | null,
  security: SecuritySummaryInsight | null
): Recommendation[] {
  const recommendations: Recommendation[] = [];

  // Priority boost factors based on data evidence
  const priorityOrder: Record<ControlPriority, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };

  const phaseOrder: Record<ControlPhase, number> = {
    foundation: 0,
    visibility: 1,
    enforcement: 2,
    advanced: 3,
  };

  for (const control of controls) {
    if (control.status === 'enabled') continue;

    const evidence: string[] = [];
    let boostedPriority = control.priority;
    let effort: 'low' | 'medium' | 'high' = 'medium';
    let impact = '';
    const steps: string[] = [];

    // ─── Data-driven evidence and priority boosting ───

    // WAF recommendations
    if (control.id === 'waf') {
      impact = 'Protects against injection, XSS, SSRF, and other OWASP Top 10 web attacks';
      effort = 'low';
      steps.push(
        'Create an App Firewall policy in blocking mode',
        'Attach the firewall policy to the HTTP load balancer',
        'Monitor security events for false positives and add exclusions as needed'
      );
      if (security && security.wafEvents > 0) {
        evidence.push(`${security.wafEvents} WAF security events detected in the last 24h — attacks are actively targeting this application`);
        boostedPriority = 'critical';
      }
      if (traffic && traffic.errorRate > 10) {
        evidence.push(`High error rate (${traffic.errorRate}%) may indicate active attack attempts that WAF would catch`);
      }
    }

    // API Discovery recommendations
    if (control.id === 'api-discovery') {
      impact = 'Provides visibility into all API endpoints including undocumented shadow APIs';
      effort = 'low';
      steps.push(
        'Enable API Discovery on the HTTP load balancer under API Protection settings',
        'Allow 24-48 hours for traffic-based endpoint discovery',
        'Review discovered endpoints and identify shadow APIs'
      );
      if (discovery && discovery.shadowApiCount > 0) {
        evidence.push(`${discovery.shadowApiCount} shadow APIs detected — these undocumented endpoints may be vulnerable`);
        boostedPriority = 'critical';
      }
    }

    // API Definition recommendations
    if (control.id === 'api-definition') {
      impact = 'Enables schema validation and positive security model for API protection';
      effort = 'medium';
      steps.push(
        'Generate or obtain an OpenAPI/Swagger specification for your API',
        'Upload the spec as an API Definition in the F5 XC console',
        'Attach the API Definition to the HTTP load balancer'
      );
      if (discovery && discovery.totalDiscoveredEndpoints > 0) {
        evidence.push(`${discovery.totalDiscoveredEndpoints} discovered endpoints could be protected with schema validation once a definition is uploaded`);
      }
    }

    // Schema Validation recommendations
    if (control.id === 'schema-validation') {
      impact = 'Validates API requests against OpenAPI spec, blocking malformed and malicious payloads';
      effort = 'medium';
      steps.push(
        'Ensure an API Definition (OpenAPI spec) is attached to the load balancer',
        'Enable API Schema Validation under API Protection settings',
        'Set validation to blocking mode after initial monitoring period'
      );
      if (discovery && discovery.shadowApiCount > 0) {
        evidence.push(`${discovery.shadowApiCount} shadow APIs detected — enabling schema validation would protect these endpoints from injection and abuse`);
        boostedPriority = 'critical';
      }
      if (traffic && traffic.errorRate > 5) {
        evidence.push(`${traffic.errorRate}% error rate suggests malformed requests that schema validation would reject`);
      }
    }

    // Bot Defense recommendations
    if (control.id === 'bot-defense') {
      impact = 'Identifies and mitigates automated traffic from bots, scrapers, and attack tools';
      effort = 'low';
      steps.push(
        'Enable Bot Defense on the HTTP load balancer',
        'Configure protected endpoints (login, API, checkout)',
        'Set bot mitigation actions (block, challenge, or flag)'
      );
      if (security && security.botEvents > 0) {
        evidence.push(`${security.botEvents} bot-related security events detected — automated traffic is targeting this application`);
        boostedPriority = 'critical';
      }
      if (traffic && traffic.botTrafficPercent > 20) {
        evidence.push(`${traffic.botTrafficPercent}% of traffic is from bots — bot defense would give visibility and control over this traffic`);
        if (traffic.botTrafficPercent > 40) boostedPriority = 'critical';
      }
    }

    // DDoS Protection recommendations
    if (control.id === 'ddos-protection') {
      impact = 'Automatically detects and mitigates application-layer DDoS attacks';
      effort = 'low';
      steps.push(
        'Enable L7 DDoS Auto Mitigation on the HTTP load balancer',
        'Set an RPS threshold based on your normal peak traffic',
        'Configure mitigation action (JS Challenge for web, Block for API)'
      );
      if (traffic && traffic.peakRps > 100) {
        evidence.push(`Peak RPS of ${traffic.peakRps} — DDoS protection should be tuned to this traffic level`);
      }
      if (security && security.ddosEvents > 0) {
        evidence.push(`${security.ddosEvents} DDoS events detected — the application is under active attack`);
        boostedPriority = 'critical';
      }
    }

    // Rate Limiting recommendations
    if (control.id === 'rate-limiting') {
      impact = 'Prevents API abuse, brute force attacks, and resource exhaustion';
      effort = 'medium';
      steps.push(
        'Analyze current traffic patterns to determine appropriate rate limits',
        'Create a Rate Limiter object with per-user limits',
        'Attach the rate limiter to the HTTP load balancer',
        'Consider using the Rate Limit Advisor tool for data-driven threshold recommendations'
      );
      if (traffic && traffic.totalRequests > 0 && !traffic.avgRps) {
        evidence.push('No rate limiting configured — any user can send unlimited requests');
      }
      if (traffic && traffic.peakRps > 50) {
        evidence.push(`Peak traffic of ${traffic.peakRps} RPS without rate limiting leaves the API vulnerable to abuse`);
        boostedPriority = 'critical';
      }
      if (security && security.rateLimitEvents > 0) {
        evidence.push(`${security.rateLimitEvents} rate limit events already detected — refine rate limiting configuration`);
      }
    }

    // IP Reputation recommendations
    if (control.id === 'ip-reputation') {
      impact = 'Blocks traffic from known malicious IPs (botnets, scanners, proxies, Tor)';
      effort = 'low';
      steps.push(
        'Enable IP Reputation on the HTTP load balancer',
        'Select all 12 threat categories for comprehensive coverage',
        'No performance impact — checks are done at the edge before reaching origin'
      );
    }

    // CORS recommendations
    if (control.id === 'cors') {
      impact = 'Prevents unauthorized cross-origin API access from malicious websites';
      effort = 'low';
      steps.push(
        'Configure CORS policy on the HTTP load balancer',
        'Set allowed origins to your known domains only',
        'Restrict allowed methods and headers to what your API requires'
      );
    }

    // Data Guard recommendations
    if (control.id === 'data-guard') {
      impact = 'Prevents sensitive data (SSN, credit card numbers) from leaking in API responses';
      effort = 'low';
      steps.push(
        'Enable Data Guard Rules on the HTTP load balancer',
        'Configure data masking patterns for sensitive data types',
        'Test with monitoring mode before enabling blocking'
      );
      if (discovery && discovery.piiTypesFound.length > 0) {
        evidence.push(`PII types detected in API responses: ${discovery.piiTypesFound.join(', ')} — Data Guard would mask or block this exposure`);
        boostedPriority = 'critical';
      }
    }

    // Sensitive Data Discovery recommendations
    if (control.id === 'sensitive-data') {
      impact = 'Automatically detects PII and sensitive data flowing through API endpoints';
      effort = 'low';
      steps.push(
        'Enable Sensitive Data Policy on the HTTP load balancer',
        'Configure detection for relevant data types (SSN, PII, PCI, etc.)',
        'Review discovered sensitive data exposure in the dashboard'
      );
      if (discovery && discovery.piiTypesFound.length > 0) {
        evidence.push(`${discovery.piiTypesFound.length} PII type(s) already detected: ${discovery.piiTypesFound.slice(0, 5).join(', ')} — sensitive data policy would provide ongoing monitoring`);
      }
    }

    // Malicious User Detection recommendations
    if (control.id === 'malicious-user') {
      impact = 'ML-based behavioral detection with progressive mitigation of suspicious users';
      effort = 'low';
      steps.push(
        'Enable Malicious User Detection on the HTTP load balancer',
        'Ensure User Identification policy is configured (required dependency)',
        'Monitor malicious user events and tune sensitivity as needed'
      );
      if (security && (security.wafEvents + security.botEvents) > 10) {
        evidence.push(`${security.wafEvents + security.botEvents} WAF/bot events indicate suspicious user activity — malicious user detection would automatically track and mitigate repeat offenders`);
      }
    }

    // mTLS recommendations
    if (control.id === 'mtls') {
      impact = 'Provides zero-trust client authentication using certificates';
      effort = 'high';
      steps.push(
        'Generate or obtain client certificates for API consumers',
        'Configure client certificate validation on the HTTP load balancer',
        'Distribute certificates to authorized API clients'
      );
    }

    // Slow DDoS recommendations
    if (control.id === 'slow-ddos') {
      impact = 'Protects against Slowloris and Slow POST attacks that exhaust server connections';
      effort = 'low';
      steps.push(
        'Enable Slow DDoS Mitigation on the HTTP load balancer',
        'Set request headers timeout based on your P95 response time',
        'Set request timeout based on your P99 response time with a safety margin'
      );
      if (traffic && traffic.avgLatencyMs > 0) {
        evidence.push(`Average latency is ${traffic.avgLatencyMs}ms — use this as a baseline for slow DDoS timeout configuration`);
      }
    }

    // User Identification recommendations
    if (control.id === 'user-identification') {
      impact = 'Enables per-user tracking for rate limiting, malicious user detection, and analytics';
      effort = 'low';
      steps.push(
        'Create a User Identification Policy',
        'Configure identification method (IP, header, cookie, or TLS fingerprint)',
        'Attach the policy to the HTTP load balancer'
      );
    }

    // Service Policy recommendations
    if (control.id === 'service-policy') {
      impact = 'Custom access control rules for fine-grained request filtering';
      effort = 'medium';
      steps.push(
        'Create Service Policies for access control requirements',
        'Define rules for IP allowlisting, header validation, path restrictions',
        'Attach service policies to the HTTP load balancer'
      );
    }

    // API Protection (combined) recommendations
    if (control.id === 'api-protection') {
      impact = 'Complete positive security model — only valid, documented API calls are allowed';
      effort = 'high';
      steps.push(
        'Upload an OpenAPI/Swagger specification as an API Definition',
        'Enable API Schema Validation in blocking mode',
        'Configure API Groups for endpoint-specific rules',
        'Monitor for false positives and refine the specification'
      );
      if (discovery && discovery.shadowApiCount > 0 && discovery.totalDiscoveredEndpoints > 0) {
        evidence.push(`${discovery.shadowApiCount} of ${discovery.totalDiscoveredEndpoints} endpoints are shadow APIs — full API protection would enforce documentation-first security`);
      }
    }

    // Build description
    const statusLabel = control.status === 'partial'
      ? 'partially enabled (not all LBs)'
      : 'not enabled';

    const description = `${control.name} is ${statusLabel}. ${control.description}.`;

    // Add default evidence if none was generated
    if (evidence.length === 0) {
      evidence.push(`${control.name} is ${statusLabel} across the scanned load balancers`);
    }

    const title = control.status === 'partial'
      ? `Enable ${control.name} on all load balancers`
      : `Enable ${control.name}`;

    recommendations.push({
      id: `rec-${control.id}`,
      controlId: control.id,
      controlName: control.name,
      domain: control.domain || control.phase,
      phase: control.phase,
      priority: boostedPriority,
      title,
      description,
      evidence,
      impact,
      effort,
      steps,
    });
  }

  // Sort by priority (critical first), then by phase (foundation first)
  recommendations.sort((a, b) => {
    const priDiff = priorityOrder[a.priority] - priorityOrder[b.priority];
    if (priDiff !== 0) return priDiff;
    return phaseOrder[a.phase] - phaseOrder[b.phase];
  });

  return recommendations;
}

// ═══════════════════════════════════════════════════════════════════
// OVERALL SCORE
// ═══════════════════════════════════════════════════════════════════

function calculateOverallScore(controls: SecurityControl[]): number {
  let weightedScore = 0;
  let totalWeight = 0;

  for (const control of controls) {
    const phaseWeight = PHASE_WEIGHTS[control.phase];
    const priorityWeight = PRIORITY_WEIGHTS[control.priority];
    const weight = phaseWeight * priorityWeight;
    const score = STATUS_SCORES[control.status];

    weightedScore += score * weight;
    totalWeight += weight;
  }

  return totalWeight > 0 ? Math.round((weightedScore / totalWeight) * 100) : 0;
}

// ═══════════════════════════════════════════════════════════════════
// PUBLIC: RUN ASSESSMENT
// ═══════════════════════════════════════════════════════════════════

/**
 * Orchestrates the full API security assessment.
 *
 * Steps based on assessment depth:
 * 1. Scan LB configs (0-20%) — always
 * 2. Fetch API discovery data (20-40%) — standard/deep
 * 3. Profile traffic (40-60%) — deep only
 * 4. Fetch security events (60-75%) — deep only
 * 5. Map control statuses (75-85%)
 * 6. Calculate domain scores (85-90%)
 * 7. Calculate OWASP coverage (90-95%)
 * 8. Generate recommendations (95-100%)
 */
export async function runAssessment(
  config: AssessmentConfig,
  onProgress: (msg: string, pct: number) => void
): Promise<AssessmentResult> {
  const startTime = Date.now();
  const { namespace, lbNames, depth } = config;

  // ─── Step 1: Scan LB Configs (0-20%) ───
  onProgress('Scanning load balancer configurations...', 2);
  const lbConfigs = await scanLBConfigs(namespace, lbNames, (msg, pct) => {
    onProgress(msg, Math.round(pct * 0.2));
  });

  // ─── Step 2: Fetch API Discovery Data (20-40%) — standard/deep ───
  let discovery: APIDiscoveryInsight | null = null;
  if (depth === 'standard' || depth === 'deep') {
    onProgress('Fetching API discovery data...', 20);
    try {
      discovery = await fetchAPIDiscoveryData(namespace, lbNames, (msg, pct) => {
        onProgress(msg, 20 + Math.round(pct * 0.2));
      }, lbConfigs);
    } catch (err) {
      console.warn('[SecurityAssessor] API discovery failed, continuing without:', err);
    }
  }

  // ─── Step 3: Profile Traffic (40-60%) — deep only ───
  let traffic: TrafficProfileInsight | null = null;
  if (depth === 'deep') {
    onProgress('Profiling traffic patterns...', 40);
    try {
      traffic = await profileTraffic(namespace, lbNames, (msg, pct) => {
        onProgress(msg, 40 + Math.round(pct * 0.2));
      });
    } catch (err) {
      console.warn('[SecurityAssessor] Traffic profiling failed, continuing without:', err);
    }
  }

  // ─── Step 4: Fetch Security Events (60-75%) — deep only ───
  let security: SecuritySummaryInsight | null = null;
  if (depth === 'deep') {
    onProgress('Fetching security events summary...', 60);
    try {
      security = await fetchSecurityEventsSummary(namespace, lbNames, (msg, pct) => {
        onProgress(msg, 60 + Math.round(pct * 0.15));
      });
    } catch (err) {
      console.warn('[SecurityAssessor] Security events fetch failed, continuing without:', err);
    }
  }

  // ─── Step 5: Map Control Statuses (75-85%) ───
  onProgress('Evaluating security controls...', 75);
  const controls = mapControls(lbConfigs);

  // ─── Step 6: Calculate Domain Scores (85-90%) ───
  onProgress('Calculating security scores...', 85);
  const domainScores = calculateDomainScores(lbConfigs, controls);

  // ─── Step 7: Calculate OWASP Coverage (90-95%) ───
  onProgress('Mapping OWASP API Security coverage...', 90);
  const owaspCoverage = calculateOWASPCoverage(controls);

  // ─── Step 8: Generate Recommendations (95-100%) ───
  onProgress('Generating recommendations...', 95);
  const recommendations = generateRecommendations(controls, discovery, traffic, security);

  // Phase progress
  const phaseProgress = calculatePhaseProgress(controls);

  // Overall score
  const overallScore = calculateOverallScore(controls);

  const assessmentDurationMs = Date.now() - startTime;
  onProgress('Assessment complete', 100);

  console.log(
    `[SecurityAssessor] Assessment complete in ${(assessmentDurationMs / 1000).toFixed(1)}s: ` +
    `score=${overallScore}/100, ${recommendations.length} recommendations, ` +
    `${controls.filter(c => c.status === 'enabled').length}/${controls.length} controls enabled`
  );

  return {
    namespace,
    lbNames,
    depth,
    generatedAt: new Date().toISOString(),
    assessmentDurationMs,
    lbConfigs,
    controls,
    discovery,
    traffic,
    security,
    domainScores,
    owaspCoverage,
    phaseProgress,
    recommendations,
    overallScore,
  };
}
