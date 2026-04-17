// ═══════════════════════════════════════════════════════════════════
// API Shield Advisor — Types
// ═══════════════════════════════════════════════════════════════════

// ─── Assessment Configuration ────────────────────────────────────

export type AssessmentDepth = 'quick' | 'standard' | 'deep';

export interface AssessmentConfig {
  namespace: string;
  lbNames: string[];
  depth: AssessmentDepth;
}

// ─── LB Security Configuration (from config scan) ───────────────

export interface LBSecurityConfig {
  name: string;
  namespace: string;

  // WAF
  wafEnabled: boolean;
  wafPolicyName: string | null;

  // API Discovery & Definition
  apiDiscoveryEnabled: boolean;
  apiDefinitionAttached: boolean;
  schemaValidationEnabled: boolean;

  // Bot Defense
  botDefenseEnabled: boolean;

  // DDoS
  ddosProtectionEnabled: boolean;
  slowDdosProtectionEnabled: boolean;

  // Rate Limiting
  rateLimitEnabled: boolean;

  // Service Policies
  servicePolicies: string[];

  // CORS
  corsEnabled: boolean;

  // mTLS
  mtlsEnabled: boolean;

  // Data Protection
  dataGuardEnabled: boolean;
  sensitiveDataDiscoveryEnabled: boolean;

  // Threat Intelligence
  maliciousUserDetectionEnabled: boolean;
  ipReputationEnabled: boolean;
  userIdentificationEnabled: boolean;

  // Metadata
  domains: string[];
  routeCount: number;
  originPoolCount: number;

  // Raw spec for deep inspection
  rawSpec: Record<string, unknown>;
}

// ─── Control Definitions ─────────────────────────────────────────

export type ControlPhase = 'foundation' | 'visibility' | 'enforcement' | 'advanced';
export type ControlPriority = 'critical' | 'high' | 'medium' | 'low';
export type ControlStatusValue = 'enabled' | 'partial' | 'disabled' | 'unknown';

export interface SecurityControl {
  id: string;
  name: string;
  description: string;
  phase: ControlPhase;
  priority: ControlPriority;
  status: ControlStatusValue;
  details: string;
  implementationPath?: string;
  threatScenarios?: string[];
  dataInsight?: string;
  domain?: string;
  /** OWASP API Security Top 10 items this control addresses */
  owaspMapping: string[];
}

export interface ControlStatus {
  controlId: string;
  status: ControlStatusValue;
  enabledCount: number;
  totalCount: number;
  details: string;
}

// ─── API Discovery Insight ───────────────────────────────────────

export interface DiscoveredEndpoint {
  path: string;
  method: string;
  discoveredAt: string;
  isInDefinition: boolean;
  riskScore: number;
  piiTypes: string[];
  requestCount: number;
  authenticated: boolean;
}

export interface APIDiscoveryInsight {
  totalDiscoveredEndpoints: number;
  shadowApiCount: number;
  authenticatedEndpoints: number;
  unauthenticatedEndpoints: number;
  piiTypesFound: string[];
  endpoints: DiscoveredEndpoint[];
  discoveryEnabledLBs: string[];
  specUploadedLBs: string[];
  lbInsights: Array<{
    lbName: string;
    discoveryEnabled: boolean;
    specUploaded: boolean;
    endpointCount: number;
    shadowCount: number;
  }>;
}

// ─── Traffic Profile Insight ─────────────────────────────────────

export interface TrafficProfileInsight {
  totalRequests: number;
  avgRps: number;
  peakRps: number;
  topPaths: Array<{ path: string; count: number; errorRate: number }>;
  topCountries: Array<{ country: string; count: number }>;
  responseCodeBreakdown: Record<string, number>;
  errorRate: number;
  avgLatencyMs: number;
  botTrafficPercent: number;
  timeRangeStart: string;
  timeRangeEnd: string;
  sampleSize: number;
}

// ─── Security Summary Insight ────────────────────────────────────

export interface SecuritySummaryInsight {
  totalSecurityEvents: number;
  wafEvents: number;
  botEvents: number;
  ddosEvents: number;
  rateLimitEvents: number;
  apiViolationEvents: number;
  topAttackTypes: Array<{ type: string; count: number }>;
  topSourceIPs: Array<{ ip: string; count: number }>;
  topTargetPaths: Array<{ path: string; count: number }>;
}

// ─── Recommendations ─────────────────────────────────────────────

export interface Recommendation {
  id: string;
  controlId: string;
  controlName: string;
  domain: string;
  phase: ControlPhase;
  priority: ControlPriority;
  title: string;
  description: string;
  evidence: string[];
  impact: string;
  effort: 'low' | 'medium' | 'high';
  steps: string[];
}

// ─── Phase Progress ──────────────────────────────────────────────

export interface PhaseProgress {
  phase: ControlPhase;
  phaseName: string;
  totalControls: number;
  enabledControls: number;
  partialControls: number;
  disabledControls: number;
  completionPercent: number;
}

// ─── OWASP Coverage ─────────────────────────────────────────────

export interface OWASPCoverage {
  id: string;
  name: string;
  description: string;
  coveredByControls: string[];
  coveragePercent: number;
}

// ─── Domain Score ────────────────────────────────────────────────

export interface DomainScore {
  domain: string;
  lbName: string;
  overallScore: number;
  foundationScore: number;
  visibilityScore: number;
  enforcementScore: number;
  advancedScore: number;
  enabledControls: number;
  totalControls: number;
}

// ─── Assessment Result ───────────────────────────────────────────

export interface AssessmentResult {
  namespace: string;
  lbNames: string[];
  depth: AssessmentDepth;
  generatedAt: string;
  assessmentDurationMs: number;

  // Configuration scan
  lbConfigs: LBSecurityConfig[];

  // Control statuses
  controls: SecurityControl[];

  // Discovery insight (standard/deep)
  discovery: APIDiscoveryInsight | null;

  // Traffic insight (deep only)
  traffic: TrafficProfileInsight | null;

  // Security events (deep only)
  security: SecuritySummaryInsight | null;

  // Scoring
  domainScores: DomainScore[];
  owaspCoverage: OWASPCoverage[];
  phaseProgress: PhaseProgress[];

  // Recommendations
  recommendations: Recommendation[];

  // Overall score (0-100)
  overallScore: number;
}
