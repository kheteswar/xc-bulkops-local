// =============================================================================
// Live SOC Monitoring Room — Type Definitions
// =============================================================================

import type { AccessLogEntry, SecurityEventEntry } from '../rate-limit-advisor/types';

// Re-export for convenience
export type { AccessLogEntry, SecurityEventEntry };

// =============================================================================
// Room Configuration
// =============================================================================

export interface SOCRoomConfig {
  id: string;
  name: string;
  namespace: string;

  // Monitored objects
  loadBalancers: string[];
  cdnDistributions: string[];
  dnsZones: string[];
  dnsLoadBalancers: string[];

  // Feature detection flags
  features: SOCFeatureFlags;

  // Polling settings
  pollingIntervalSec: 120 | 180 | 300;
  dataWindowMinutes: 5 | 10 | 15;
  fetchDepth: 'light' | 'standard' | 'deep';

  // Watch paths with custom thresholds
  watchPaths: WatchPath[];

  // Display
  primaryDomain?: string;
  layout?: 'full' | 'compact';

  // Timestamps
  createdAt: string;
  lastOpenedAt: string;
}

export interface SOCFeatureFlags {
  botDefenseEnabled: boolean;
  clientSideDefenseEnabled: boolean;
  infraProtectEnabled: boolean;
  syntheticMonitorsEnabled: boolean;
  apiSecurityEnabled: boolean;
}

export interface WatchPath {
  path: string;
  label: string;
  errorThreshold?: number;
  latencyThresholdMs?: number;
}

// =============================================================================
// Aggregation
// =============================================================================

export interface AggBucket {
  key: string;
  count: number;
  subBuckets?: AggBucket[];
}

export interface AggregationQuery {
  id: string;
  endpoint: string;
  body: Record<string, unknown>;
}

export interface AggregationResults {
  byRspCode: AggBucket[];
  byRspCodeDetails: AggBucket[];
  byCountry: AggBucket[];
  byDstIp: AggBucket[];
  byReqPath: AggBucket[];
  byDomain: AggBucket[];
  bySrcIp: AggBucket[];
  byWafAction: AggBucket[];
  secByEventName: AggBucket[];
  secBySignatureId: AggBucket[];
  secBySrcIp: AggBucket[];
  secByCountry: AggBucket[];
  secByViolation: AggBucket[];
}

export const EMPTY_AGGREGATION: AggregationResults = {
  byRspCode: [],
  byRspCodeDetails: [],
  byCountry: [],
  byDstIp: [],
  byReqPath: [],
  byDomain: [],
  bySrcIp: [],
  byWafAction: [],
  secByEventName: [],
  secBySignatureId: [],
  secBySrcIp: [],
  secByCountry: [],
  secByViolation: [],
};

// =============================================================================
// Dashboard Metrics (derived from aggregation)
// =============================================================================

export interface DashboardMetrics {
  // Traffic
  rps: number;
  prevRps: number;
  totalRequests: number;
  totalSecEvents: number;
  prevTotalSecEvents: number;

  // Error rates
  errorRate: number;
  error5xxRate: number;
  error4xxRate: number;
  prevErrorRate: number;

  // Response code distribution
  responseCodeDist: Array<{ code: string; count: number; pct: number }>;

  // Error diagnosis
  errorDiagnosis: Array<{
    rspCodeDetails: string;
    rspCode: string;
    count: number;
    prevCount: number;
    isOriginError: boolean;
    rootCause: string;
    severity: string;
    category: string;
    remediation: string;
  }>;

  // Per-origin health
  originHealth: Array<{
    dstIp: string;
    totalCount: number;
    errorCount: number;
    errorRate: number;
    p95Latency: number;
  }>;

  // Security
  securityBreakdown: Array<{ eventName: string; count: number; pct: number }>;
  topSignatures: Array<{ id: string; count: number }>;
  topAttackingIps: Array<{ ip: string; count: number; country?: string; asn?: string }>;
  topViolations: Array<{ name: string; count: number }>;

  // Geo
  geoDistribution: Array<{ country: string; count: number; pct: number; isNew: boolean }>;

  // Top paths
  hotPaths: Array<{ path: string; count: number; errorCount: number; errorRate: number }>;

  // Top source IPs (non-security)
  topTalkers: Array<{ ip: string; count: number }>;

  // WAF action distribution
  wafActions: Array<{ action: string; count: number }>;

  // Domain breakdown
  domainBreakdown: Array<{ domain: string; count: number; errorCount: number }>;

  // CDN (if applicable)
  cacheHitRatio: number | null;

  // Bot (if applicable)
  botRatio: number | null;

  // Alerts
  activeAlertCount: number;

  // Config changes
  recentConfigChanges: number;
}

export function createEmptyMetrics(): DashboardMetrics {
  return {
    rps: 0, prevRps: 0, totalRequests: 0,
    totalSecEvents: 0, prevTotalSecEvents: 0,
    errorRate: 0, error5xxRate: 0, error4xxRate: 0, prevErrorRate: 0,
    responseCodeDist: [], errorDiagnosis: [], originHealth: [],
    securityBreakdown: [], topSignatures: [], topAttackingIps: [], topViolations: [],
    geoDistribution: [], hotPaths: [], topTalkers: [], wafActions: [], domainBreakdown: [],
    cacheHitRatio: null, botRatio: null,
    activeAlertCount: 0, recentConfigChanges: 0,
  };
}

// =============================================================================
// Latency Stats (from Track 3 raw logs)
// =============================================================================

export interface LatencyStats {
  p50: number;
  p95: number;
  p99: number;
  originTTFB_p50: number;
  originTTFB_p95: number;
  waterfall: LatencyWaterfall;
  perOrigin: Array<{
    dstIp: string;
    p50: number;
    p95: number;
    originTTFB_p95: number;
    count: number;
  }>;
}

export interface LatencyWaterfall {
  toFirstUpstreamTx: { p50: number; p95: number };
  toFirstUpstreamRx: { p50: number; p95: number };
  toLastUpstreamRx: { p50: number; p95: number };
  toFirstDownstreamTx: { p50: number; p95: number };
  toLastDownstreamTx: { p50: number; p95: number };
}

export function createEmptyLatencyStats(): LatencyStats {
  const z = { p50: 0, p95: 0 };
  return {
    p50: 0, p95: 0, p99: 0,
    originTTFB_p50: 0, originTTFB_p95: 0,
    waterfall: {
      toFirstUpstreamTx: { ...z }, toFirstUpstreamRx: { ...z },
      toLastUpstreamRx: { ...z }, toFirstDownstreamTx: { ...z },
      toLastDownstreamTx: { ...z },
    },
    perOrigin: [],
  };
}

// =============================================================================
// JA4 Clustering
// =============================================================================

export interface JA4Cluster {
  fingerprint: string;
  count: number;
  ips: string[];
  topUa: string;
}

// =============================================================================
// Event Feed
// =============================================================================

export type EventFeedEntryType = 'access' | 'security' | 'error' | 'bot' | 'dns' | 'config' | 'alert' | 'investigation';

export interface EventFeedEntry {
  id: string;
  timestamp: string;
  type: EventFeedEntryType;
  severity: 'info' | 'warning' | 'error' | 'critical';
  message: string;
  details?: Record<string, unknown>;
}

// =============================================================================
// Alerts
// =============================================================================

export interface AlertEntry {
  id: string;
  name: string;
  severity: 'minor' | 'major' | 'critical';
  type: string;
  description: string;
  createdAt: string;
  updatedAt: string;
  state: string;
  labels?: Record<string, string>;
}

// =============================================================================
// Audit / Config Changes
// =============================================================================

export interface AuditEntry {
  timestamp: string;
  user: string;
  objectType: string;
  objectName: string;
  operation: string;
  namespace: string;
}

// =============================================================================
// Bot Defense
// =============================================================================

export interface BotTrafficOverview {
  humanPct: number;
  goodBotPct: number;
  maliciousBotPct: number;
  totalRequests: number;
  attackIntent: Array<{ intent: string; count: number; pct: number }>;
  topMaliciousIps: Array<{ ip: string; count: number }>;
  topMaliciousUAs: Array<{ ua: string; count: number }>;
  credentialStuffingDetected: boolean;
  mitigationActions: Array<{ action: string; count: number; pct: number }>;
}

// =============================================================================
// Synthetic Monitoring
// =============================================================================

export interface SyntheticHealthSummary {
  monitors: Array<{
    name: string;
    type: 'http' | 'dns';
    status: 'healthy' | 'unhealthy' | 'unknown';
    lastCheckTime: string;
    availabilityPct: number;
  }>;
  tlsCerts: Array<{
    domain: string;
    expiresAt: string;
    daysUntilExpiry: number;
    status: 'ok' | 'warning' | 'critical';
  }>;
  globalAvailabilityPct: number;
}

// =============================================================================
// DNS Health
// =============================================================================

export interface DNSHealthStatus {
  loadBalancers: Array<{
    name: string;
    status: 'healthy' | 'degraded' | 'down';
    pools: Array<{
      name: string;
      members: Array<{
        address: string;
        status: 'healthy' | 'unhealthy';
        lastChangeTime: string;
      }>;
    }>;
  }>;
  queryMetrics: {
    totalQueries: number;
    errorCount: number;
    errorRate: number;
  } | null;
}

// =============================================================================
// CSD (Client-Side Defense)
// =============================================================================

export interface CSDSummary {
  scripts: Array<{
    id: string;
    domain: string;
    classification: 'benign' | 'suspicious' | 'malicious';
    targetedFormFields: string[];
    affectedUserCount: number;
    networkInteractions: string[];
  }>;
  detectedDomains: Array<{
    domain: string;
    classification: string;
    mitigated: boolean;
  }>;
}

// =============================================================================
// InfraProtect (L3/L4 DDoS)
// =============================================================================

export interface InfraProtectSummary {
  alerts: Array<{
    id: string;
    severity: string;
    targetNetwork: string;
    createdAt: string;
    status: string;
  }>;
  activeMitigations: Array<{
    id: string;
    targetNetwork: string;
    mitigatedIps: number;
    startedAt: string;
  }>;
  topTalkers: Array<{
    ip: string;
    bps: number;
    pps: number;
  }>;
}

// =============================================================================
// API Security
// =============================================================================

export interface APISecuritySummary {
  totalEndpoints: number;
  shadowEndpoints: number;
  vulnerabilities: Array<{
    id: string;
    severity: string;
    endpoint: string;
    description: string;
  }>;
  sensitiveData: Array<{
    type: string;
    endpoint: string;
    riskLevel: string;
  }>;
  unauthenticatedEndpoints: number;
}

// =============================================================================
// Anomaly Detection
// =============================================================================

export type ThreatLevel = 'NOMINAL' | 'ELEVATED' | 'HIGH' | 'CRITICAL';
export type AnomalySeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';

export const THREAT_COLORS: Record<ThreatLevel, string> = {
  NOMINAL: '#00ff88',
  ELEVATED: '#ffbe0b',
  HIGH: '#ff6b35',
  CRITICAL: '#ff0040',
};

export type DetectorId =
  | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10
  | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20
  | 21 | 22 | 23;

export interface Anomaly {
  id: string;
  detectorId: DetectorId;
  detectorName: string;
  severity: AnomalySeverity;
  triggerValue: number | string;
  baselineValue: number | string;
  message: string;
  firstDetectedAt: string;
  lastDetectedAt: string;
  resolved: boolean;
  resolvedAt?: string;
  investigationId?: string;
}

// =============================================================================
// Baseline (persisted to localStorage per room)
// =============================================================================

export interface Baseline {
  avgRps: number;
  stdDevRps: number;
  avgSampleRate: number;
  avgErrorRate: number;
  avg5xxRate: number;
  avg4xxRate: number;
  avgSecEvents: number;
  avgWafBlocks: number;
  avgThreatMeshHits: number;
  avgBotRatio: number;
  knownSignatureIds: string[];
  avgLatencyP50: number;
  avgLatencyP95: number;
  avgOriginTTFB: number;
  avgCacheHitRatio: number;
  topCountries: Record<string, number>;
  topJA4: string[];
  perDomain: Record<string, DomainBaseline>;
  perWatchPath: Record<string, PathBaseline>;
  sampleCount: number;
  lastUpdated: string;
}

export interface DomainBaseline {
  avgRps: number;
  avgErrorRate: number;
  avgSecEvents: number;
}

export interface PathBaseline {
  avgRps: number;
  avgErrorRate: number;
  avgLatencyP95: number;
}

export function createEmptyBaseline(): Baseline {
  return {
    avgRps: 0, stdDevRps: 0, avgSampleRate: 1,
    avgErrorRate: 0, avg5xxRate: 0, avg4xxRate: 0,
    avgSecEvents: 0, avgWafBlocks: 0, avgThreatMeshHits: 0, avgBotRatio: 0,
    knownSignatureIds: [],
    avgLatencyP50: 0, avgLatencyP95: 0, avgOriginTTFB: 0,
    avgCacheHitRatio: 0,
    topCountries: {}, topJA4: [],
    perDomain: {}, perWatchPath: {},
    sampleCount: 0, lastUpdated: new Date().toISOString(),
  };
}

// =============================================================================
// Incidents
// =============================================================================

export type IncidentStatus = 'active' | 'investigating' | 'resolved';

export interface Incident {
  id: string;
  title: string;
  severity: AnomalySeverity;
  status: IncidentStatus;
  anomalyIds: string[];
  investigationIds: string[];
  createdAt: string;
  resolvedAt?: string;
  summary: string;
}

// =============================================================================
// Investigation Engine
// =============================================================================

export type InvestigationWorkflowId =
  | 'origin_5xx' | 'waf_attack' | 'ddos' | 'latency_spike'
  | 'bot_surge' | 'service_policy_block' | 'rate_limit_impact'
  | 'tls_cert_error' | 'route_config_error' | 'credential_stuffing'
  | 'csd_magecart' | 'dns_failure';

export type InvestigationStatus = 'pending' | 'running' | 'complete' | 'error';
export type StepStatus = 'pending' | 'running' | 'complete' | 'skipped' | 'error';

export interface InvestigationStep {
  id: string;
  label: string;
  status: StepStatus;
  evidence?: Record<string, unknown>;
  error?: string;
  startedAt?: string;
  completedAt?: string;
}

export interface Investigation {
  id: string;
  workflowId: InvestigationWorkflowId;
  triggerAnomalyId: string;
  parentInvestigationId?: string;
  status: InvestigationStatus;
  steps: InvestigationStep[];
  currentStepIndex: number;
  finding?: InvestigationFinding;
  childInvestigationIds: string[];
  createdAt: string;
  completedAt?: string;
}

export interface InvestigationFinding {
  rootCause: string;
  severity: AnomalySeverity;
  evidenceSummary: string;
  remediationActions: RemediationAction[];
  childTriggers: Array<{
    workflowId: InvestigationWorkflowId;
    reason: string;
  }>;
  evidence?: Record<string, unknown>;
}

export interface RemediationAction {
  label: string;
  type: 'cross_launch' | 'rule_suggestion' | 'config_change' | 'info';
  targetTool?: string;
  context?: Record<string, unknown>;
  suggestedRule?: unknown;
}

// =============================================================================
// Investigation Chains
// =============================================================================

export interface ChainTrigger {
  parentWorkflow: InvestigationWorkflowId;
  condition: (finding: InvestigationFinding) => boolean;
  childWorkflow: InvestigationWorkflowId | null;
  reason: string;
}

// =============================================================================
// History / Ring Buffer
// =============================================================================

export interface TimeSeriesPoint {
  timestamp: string;
  rps: number;
  errorRate: number;
  secEvents: number;
  p95Latency: number;
  threatLevel: ThreatLevel;
}

export interface CycleSnapshot {
  cycleNumber: number;
  timestamp: string;
  metrics: DashboardMetrics;
  latencyStats: LatencyStats;
  aggregation: AggregationResults;
  anomalies: Anomaly[];
  threatLevel: ThreatLevel;
  heartbeat: HeartbeatResult;
}

// =============================================================================
// Heartbeat
// =============================================================================

export interface HeartbeatResult {
  totalHits: number;
  secEventHits: number;
  rps: number;
  timestamp: string;
}

// =============================================================================
// Polling Engine
// =============================================================================

export type PollingStatus = 'idle' | 'running' | 'paused' | 'error';

export interface PollingCycleResult {
  heartbeat: HeartbeatResult;
  aggregation: AggregationResults;
  alerts: AlertEntry[];
  auditEntries: AuditEntry[];
  incidents: Array<Record<string, unknown>>;
  suspiciousUserCount: number;
  rawLogs: {
    latencyStats: LatencyStats;
    eventFeed: EventFeedEntry[];
    ja4Clusters: JA4Cluster[];
    sampleRate: number;
  };
  botOverview: BotTrafficOverview | null;
  syntheticHealth: SyntheticHealthSummary | null;
  dnsHealth: DNSHealthStatus | null;
}

// =============================================================================
// SOC Room State (useReducer)
// =============================================================================

export interface SOCRoomState {
  room: SOCRoomConfig;
  pollingStatus: PollingStatus;
  cycleNumber: number;
  lastCycleTimestamp: string | null;
  nextCycleIn: number;
  isCatchingUp: boolean;

  heartbeat: HeartbeatResult;
  aggregation: AggregationResults;
  alerts: AlertEntry[];
  auditEntries: AuditEntry[];
  suspiciousUserCount: number;

  botOverview: BotTrafficOverview | null;
  syntheticHealth: SyntheticHealthSummary | null;
  dnsHealth: DNSHealthStatus | null;
  csdSummary: CSDSummary | null;
  infraProtect: InfraProtectSummary | null;
  apiSecurity: APISecuritySummary | null;

  latencyStats: LatencyStats;
  eventFeed: EventFeedEntry[];
  ja4Clusters: JA4Cluster[];
  rawLogSampleRate: number;

  metrics: DashboardMetrics;
  baseline: Baseline;
  activeAnomalies: Anomaly[];
  threatLevel: ThreatLevel;

  incidents: Incident[];
  activeInvestigations: Investigation[];
  completedInvestigations: Investigation[];

  timeSeriesHistory: TimeSeriesPoint[];
  snapshotHistory: CycleSnapshot[];

  selectedDomain: string | null;
  historyMode: boolean;
  historyCursor: number | null;

  error: string | null;
}

// =============================================================================
// SOC Room Actions (useReducer dispatch)
// =============================================================================

export type SOCAction =
  | { type: 'CYCLE_START' }
  | { type: 'CYCLE_RESULT'; payload: PollingCycleResult }
  | { type: 'CYCLE_COMPLETE'; payload: { metrics: DashboardMetrics; anomalies: Anomaly[]; threatLevel: ThreatLevel; baseline: Baseline; incidents: Incident[] } }
  | { type: 'INVESTIGATION_UPDATE'; payload: Investigation }
  | { type: 'INVESTIGATION_COMPLETE'; payload: Investigation }
  | { type: 'CSD_RESULT'; payload: CSDSummary }
  | { type: 'INFRAPROTECT_RESULT'; payload: InfraProtectSummary }
  | { type: 'API_SECURITY_RESULT'; payload: APISecuritySummary }
  | { type: 'SET_DOMAIN_FILTER'; payload: string | null }
  | { type: 'SET_HISTORY_MODE'; payload: { enabled: boolean; cursor?: number } }
  | { type: 'APPLY_SNAPSHOT'; payload: CycleSnapshot }
  | { type: 'POLLING_PAUSED' }
  | { type: 'POLLING_RESUMED' }
  | { type: 'POLLING_ERROR'; payload: string }
  | { type: 'COUNTDOWN_TICK' }
  | { type: 'BASELINE_RESET' }
  | { type: 'ADD_EVENT'; payload: EventFeedEntry }
  ;

// =============================================================================
// Error Diagnosis Knowledge Base Types
// =============================================================================

export interface ErrorDiagnosisEntry {
  rspCode: string;
  pattern: string;
  category: 'config' | 'origin' | 'security' | 'network';
  severity: AnomalySeverity;
  isOriginError: boolean;
  rootCause: string;
  autoAction: string;
  remediation: string;
}

// =============================================================================
// Rule Suggestion
// =============================================================================

export type RuleSuggestionType =
  | 'waf_exclusion' | 'block_client' | 'trust_client'
  | 'ddos_mitigation' | 'rate_limit' | 'oas_validation'
  | 'data_exposure' | 'api_endpoint_protection'
  | 'cdn_waf_exclusion' | 'cdn_block_client' | 'cdn_ddos_mitigation';

// =============================================================================
// Operator Questions
// =============================================================================

export type OperatorTab = 'health' | 'security' | 'performance' | 'cdn' | 'api_security' | 'bot_defense' | 'infrastructure' | 'operations';

export interface OperatorQuestion {
  question: string;
  dataSource: string;
  computeAnswer: (state: SOCRoomState) => OperatorAnswer;
}

export interface OperatorAnswer {
  status: 'good' | 'warning' | 'critical' | 'info' | 'unknown';
  summary: string;
  details?: string;
  value?: number | string;
  trend?: 'up' | 'down' | 'stable';
}

// =============================================================================
// Lobby
// =============================================================================

export interface LobbyRoomStatus {
  roomId: string;
  threatLevel: ThreatLevel;
  rps: number;
  errorRate: number;
  incidentCount: number;
  lastPollTimestamp: string | null;
  isPolling: boolean;
}
