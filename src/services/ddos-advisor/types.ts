// DDoS Settings Advisor - Types

export type TimePeriod = '24h' | '7d' | '14d' | '30d' | 'custom';

export const TIME_PERIOD_HOURS: Record<string, number> = {
  '24h': 24,
  '7d': 168,
  '14d': 336,
  '30d': 720,
};

export const TIME_PERIOD_LABELS: Record<TimePeriod, string> = {
  '24h': 'Last 24 Hours',
  '7d': 'Last 7 Days',
  '14d': 'Last 14 Days',
  '30d': 'Last 30 Days',
  'custom': 'Custom Range',
};

export interface DdosAnalysisProgress {
  phase: 'idle' | 'fetching_config' | 'fetching_logs' | 'fetching_security' | 'analyzing' | 'complete' | 'error';
  message: string;
  progress: number;
  accessLogsCount: number;
  securityEventsCount: number;
  error?: string;
}

export interface CurrentDdosConfig {
  // L7 DDoS Protection
  hasL7DdosProtection: boolean;
  rpsThreshold: number | null;        // null = default (10000), number = custom
  isDefaultRpsThreshold: boolean;
  mitigationAction: 'block' | 'js_challenge' | 'captcha_challenge' | 'none' | 'not_configured';
  clientsideAction: 'none' | 'js_challenge' | 'captcha_challenge' | 'not_configured';
  jsChallenge?: { jsScriptDelay?: number; cookieExpiry?: number };
  ddosPolicy: string | null;          // custom service policy name

  // DDoS Mitigation Rules
  mitigationRules: Array<{
    name: string;
    type: 'ip_prefix' | 'client_source';
    detail: string;
  }>;

  // Slow DDoS
  hasSlowDdosMitigation: boolean;
  slowDdosHeadersTimeout: number | null;    // ms
  slowDdosRequestTimeout: number | null;    // ms

  // Related security features
  threatMeshEnabled: boolean;
  ipReputationEnabled: boolean;
  ipThreatCategories: string[];
  maliciousUserDetectionEnabled: boolean;
  botDefenseEnabled: boolean;
}

export interface AggregateRateStats {
  p50: number;
  p75: number;
  p90: number;
  p95: number;
  p99: number;
  max: number;
  mean: number;
  stdDev: number;
  sampleCount: number;
}

export interface TrafficStats {
  totalRequests: number;
  estimatedActualRequests: number;
  avgSampleRate: number;

  // Aggregate RPS (total across ALL users hitting the LB each second)
  aggregateRps: AggregateRateStats;
  // Aggregate RPM
  aggregateRpm: AggregateRateStats;

  // Time series (hourly buckets)
  timeSeries: Array<{
    timestamp: string;
    peakRps: number;
    avgRps: number;
  }>;

  // Peak info
  peakRpsTimestamp: string;
  peakRps: number;
  peakRpmTimestamp: string;
  peakRpm: number;

  // Security events summary
  totalSecurityEvents: number;
  ddosEventCount: number;
  wafEventCount: number;
  botEventCount: number;

  // Source analysis
  topCountries: Array<{ country: string; count: number }>;
  topAsns: Array<{ asn: string; count: number }>;

  // Response time analysis (for slow DDoS recommendations)
  avgDurationMs: number;
  p95DurationMs: number;
  p99DurationMs: number;

  // Response breakdown
  responseBreakdown: {
    origin2xx: number;
    origin3xx: number;
    origin4xx: number;
    origin5xx: number;
    f5Blocked: number;
  };

  // User reputation summary
  userReputationSummary: {
    clean: number;
    benignBot: number;
    flagged: number;
    malicious: number;
  };

  // Traffic profile — classifies traffic type for context-aware recommendations
  trafficProfile: TrafficProfile;
}

export interface TrafficProfile {
  /** Overall classification: web (browser), api (programmatic), or mixed */
  type: 'web' | 'api' | 'mixed';
  /** Percentage of traffic classified as API (0-100) */
  apiTrafficPct: number;
  /** Percentage of traffic classified as web/browser (0-100) */
  webTrafficPct: number;
  /** Whether real browser user agents are present */
  hasBrowserTraffic: boolean;
  /** Whether programmatic/bot user agents are present */
  hasProgrammaticTraffic: boolean;
  /** Top request path patterns with API classification */
  topPaths: Array<{ path: string; count: number; isApi: boolean }>;
  /** User agent type breakdown */
  uaBreakdown: { browser: number; mobile: number; bot: number; api: number; unknown: number };
}

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingCategory =
  | 'rps_threshold'
  | 'mitigation_action'
  | 'clientside_action'
  | 'slow_ddos'
  | 'threat_mesh'
  | 'ip_reputation'
  | 'malicious_user_detection'
  | 'bot_defense'
  | 'ddos_policy'
  | 'mitigation_rules';

export interface DdosFinding {
  category: FindingCategory;
  severity: SeverityLevel;
  title: string;
  currentValue: string;
  recommendedValue: string;
  description: string;
  rationale: string;
}

export interface RpsRecommendation {
  algorithm: string;
  label: string;
  rpsThreshold: number;
  description: string;
  formula: string;
  isRecommended?: boolean;
}

export interface RecommendedDdosConfig {
  l7_ddos_protection: Record<string, unknown>;
  slow_ddos_mitigation?: {
    request_headers_timeout: number;
    request_timeout: number;
  };
  enable_threat_mesh?: Record<string, never>;
  enable_ip_reputation?: {
    ip_threat_categories: string[];
  };
  enable_malicious_user_detection?: Record<string, never>;
}

export interface DdosAnalysisResults {
  lbName: string;
  namespace: string;
  domains: string[];
  analysisStart: string;
  analysisEnd: string;
  generatedAt: string;

  currentConfig: CurrentDdosConfig;
  trafficStats: TrafficStats;
  findings: DdosFinding[];
  rpsRecommendations: RpsRecommendation[];
  recommendedConfig: RecommendedDdosConfig;
}
