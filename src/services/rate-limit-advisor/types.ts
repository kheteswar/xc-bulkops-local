// ═══════════════════════════════════════════════════════════════════
// ACCESS LOG (from /api/data/namespaces/{ns}/access_logs)
// ═══════════════════════════════════════════════════════════════════

export interface AccessLogEntry {
  '@timestamp': string;
  time: string;
  req_id: string;

  // User identification
  user: string;
  src_ip: string;
  tls_fingerprint: string;
  ja4_tls_fingerprint: string;

  // Request details
  method: string;
  req_path: string;
  authority: string;
  domain: string;
  original_authority: string;
  scheme: string;
  protocol: string;
  user_agent: string;
  req_size: string;

  // Response details
  rsp_code: string;
  rsp_code_class: string;
  rsp_code_details: string;
  rsp_size: string;

  // Timing
  time_to_first_upstream_rx_byte: number;
  time_to_last_upstream_rx_byte: number;
  time_to_first_upstream_tx_byte: number;
  time_to_first_downstream_tx_byte: number;
  time_to_last_downstream_tx_byte: number;
  total_duration_seconds: number;
  rtt_upstream_seconds: string;
  duration_with_data_tx_delay: string;
  duration_with_no_data_tx_delay: string;

  // Routing
  dst: string;
  dst_instance: string;
  dst_ip: string;
  dst_port: string;
  dst_site: string;
  src: string;
  src_site: string;
  src_instance: string;
  src_port: string;

  // Security context
  waf_action: string;
  bot_class: string;
  has_sec_event: boolean;

  // Sampling
  sample_rate: number;

  // Policy hits
  policy_hits: {
    policy_hits: Array<{
      result: string;
      ip_trustscore: string;
      ip_trustworthiness: string;
      ip_risk: string;
      rate_limiter_action: string;
      malicious_user_mitigate_action: string;
      policy_set: string;
    }>;
  };

  // Metadata
  vh_name: string;
  vh_type: string;
  namespace: string;
  tenant: string;
  app_type: string;
  cluster_name: string;
  site: string;
  hostname: string;

  // Geo
  country: string;
  region: string;
  city: string;
  asn: string;
  as_number: string;
  as_org: string;

  // TLS
  tls_version: string;
  tls_cipher_suite: string;
  sni: string;
  mtls: boolean;

  // Other
  api_endpoint: string;
  connection_state: string;
  stream: string;
  proxy_type: string;
  messageid: string;
  message_key: string;
  node_id: string;

  [key: string]: unknown;
}

export interface AccessLogQuery {
  query: string;
  namespace: string;
  start_time: string;
  end_time: string;
  scroll?: boolean;
  limit?: number;
}

export interface AccessLogResponse {
  logs: AccessLogEntry[];
  scroll_id?: string;
  total_hits?: number;
}

// ═══════════════════════════════════════════════════════════════════
// SECURITY EVENT (from /api/data/namespaces/{ns}/app_security/events)
// ═══════════════════════════════════════════════════════════════════

export interface SecurityEventEntry {
  '@timestamp': string;
  time: string;
  req_id: string;

  // Event classification
  sec_event_type: string;
  sec_event_name: string;
  action: string;
  recommended_action: string;
  waf_mode: string;
  enforcement_mode: string;

  // Client
  src_ip: string;
  user: string;
  user_agent: string;
  country: string;
  region: string;
  city: string;
  asn: string;
  as_number: string;
  as_org: string;
  src_instance: string;
  src_port: string;
  tls_fingerprint: string;
  ja4_tls_fingerprint: string;

  // Bot info
  'bot_info.name': string;
  'bot_info.classification': string;
  'bot_info.type': string;

  // Request
  method: string;
  req_path: string;
  authority: string;
  domain: string;
  http_version: string;
  x_forwarded_for: string;
  req_size: number;
  req_headers_size: number;

  // Response
  rsp_code: string;
  rsp_code_class: string;
  rsp_size: number;

  // WAF details
  app_firewall_name: string;
  violation_rating: string;
  req_risk: string;

  // Metadata
  vh_name: string;
  namespace: string;
  tenant: string;
  site: string;
  src_site: string;
  cluster_name: string;
  hostname: string;
  messageid: string;
  message_key: string;

  [key: string]: unknown;
}

export interface SecurityEventQuery {
  query: string;
  namespace: string;
  start_time: string;
  end_time: string;
  scroll?: boolean;
  limit?: number;
}

export interface SecurityEventResponse {
  events: SecurityEventEntry[];
  scroll_id?: string;
  total_hits?: number;
}

// ═══════════════════════════════════════════════════════════════════
// ANALYSIS ENGINE TYPES
// ═══════════════════════════════════════════════════════════════════

export type ResponseOrigin = 'origin' | 'f5_blocked';
export type UserReputationType = 'clean' | 'benign_bot' | 'flagged' | 'malicious';
export type TimeGranularity = 'second' | 'minute' | 'hour';
export type TrafficSegment = 'clean_only' | 'all_legitimate' | 'total';
export type AlgorithmType = 'percentile' | 'mean_stddev' | 'peak_buffer' | 'p99_burst';

/** Compact per-user metadata — used for simulation without keeping full logs in memory */
export interface UserMetadata {
  reputation: UserReputationType;
  pathCounts: Map<string, number>;
}

/** All 9 pre-grouped maps (3 segments × 3 granularities) */
export type PreGroupedCache = Record<TrafficSegment, Record<TimeGranularity, Map<string, Map<string, number>>>>;

export interface ClassifiedLogEntry extends AccessLogEntry {
  responseOrigin: ResponseOrigin;
  userReputation: UserReputationType;
  estimatedWeight: number;

  // Security event enrichment (only present if req_id matched a security event)
  hasSecurityEvent: boolean;
  secEventType?: string;
  secEventName?: string;
  secAction?: string;
  secBotClassification?: string;
  secBotName?: string;
  secViolationRating?: string;
  secWafMode?: string;
}

export interface UserProfile {
  identifier: string;
  srcIp: string;
  reputation: UserReputationType;
  totalRequests: number;
  estimatedTotalRequests: number;
  totalOriginRequests: number;

  rateStats: {
    second: RateStats;
    minute: RateStats;
    hour: RateStats;
  };

  // Security context
  wafBlockCount: number;
  wafReportCount: number;
  botClassification: string;
  botName: string;
  attackTypes: string[];

  // Traffic pattern
  topPaths: Array<{ path: string; count: number }>;
  topMethods: Array<{ method: string; count: number }>;
  peakHour: string;
  country: string;
  userAgent: string;
}

export interface RateStats {
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

export interface BurstEvent {
  timestamp: string;
  userIdentifier: string;
  rateObserved: number;
  baseRate: number;
  ratio: number;
  durationSeconds: number;
}

export interface PathAnalysis {
  normalizedPath: string;
  rawPaths: string[];
  totalRequests: number;
  uniqueUsers: number;
  methods: Record<string, number>;
  rateStats: {
    second: RateStats;
    minute: RateStats;
    hour: RateStats;
  };
  isSensitive: boolean;
  sensitiveReason?: string;
}

// ═══════════════════════════════════════════════════════════════════
// RECOMMENDATION & IMPACT SIMULATION
// ═══════════════════════════════════════════════════════════════════

export interface AlgorithmResult {
  type: AlgorithmType;
  label: string;
  description: string;
  rateLimit: number;
  granularity: TimeGranularity;
  burstMultiplier: number;
  formula: string;
  parameters: {
    percentile?: number;
    safetyMargin?: number;
    nSigma?: number;
    bufferPercent?: number;
  };
}

export interface ImpactSimulation {
  rateLimit: number;
  granularity: TimeGranularity;
  burstMultiplier: number;

  usersAffected: number;
  usersAffectedPercent: number;
  totalUsersAnalyzed: number;
  requestsBlocked: number;
  requestsBlockedPercent: number;
  totalRequestsAnalyzed: number;

  affectedUsers: Array<{
    identifier: string;
    timesBlocked: number;
    peakRate: number;
    avgRate: number;
    reputation: UserReputationType;
    topBlockedPaths: string[];
  }>;

  blockTimeline: Array<{
    timestamp: string;
    blockedCount: number;
  }>;

  pathImpact: Array<{
    path: string;
    blockedRequests: number;
    percentOfBlocks: number;
  }>;
}

// ═══════════════════════════════════════════════════════════════════
// DATA COLLECTION PROGRESS
// ═══════════════════════════════════════════════════════════════════

export interface CollectionProgress {
  phase: 'idle' | 'fetching_logs' | 'fetching_security' | 'classifying' | 'analyzing' | 'complete' | 'error';
  message: string;
  progress: number;
  accessLogsCount: number;
  securityEventsCount: number;
  scrollPage: number;
  estimatedTotal?: number;
  error?: string;
}

// ═══════════════════════════════════════════════════════════════════
// ANALYSIS RESULTS
// ═══════════════════════════════════════════════════════════════════

export interface AnalysisResults {
  lbName: string;
  namespace: string;
  analysisStart: string;
  analysisEnd: string;
  generatedAt: string;

  totalAccessLogs: number;
  totalSecurityEvents: number;
  avgSampleRate: number;
  estimatedActualRequests: number;
  /** Sum of total_hits from all access log API chunk responses (total records in F5 XC for the window) */
  totalApiHits: number;
  /** Sum of total_hits from all security event API chunk responses */
  totalSecurityApiHits: number;
  /** Average RPM derived from totalApiHits across the full time window */
  globalAvgRpm: number;
  /** Peak RPM from the single busiest chunk window */
  globalPeakRpm: number;

  responseBreakdown: {
    origin2xx: number;
    origin3xx: number;
    origin4xx: number;
    origin5xx: number;
    f5Blocked: number;
    f5BlockedReasons: Record<string, number>;
    originOther: number;
  };

  users: UserProfile[];
  userReputationSummary: {
    clean: number;
    benignBot: number;
    flagged: number;
    malicious: number;
  };

  currentConfig: {
    hasRateLimit: boolean;
    currentLimit?: number;
    currentUnit?: string;
    currentBurstMultiplier?: number;
    userIdPolicyName?: string;
    trustedClients: string[];
    existingPolicies: string[];
  };

  rateAnalysis: Record<TrafficSegment, {
    second: RateStats;
    minute: RateStats;
    hour: RateStats;
    userCount: number;
    requestCount: number;
  }>;

  burstEvents: BurstEvent[];
  recommendedBurstMultiplier: number;
  burstRatioP90: number;

  paths: PathAnalysis[];

  algorithms: AlgorithmResult[];

  timeSeries: Array<{
    timestamp: string;
    requestsPerMinute: number;
    requestsPerSecond: number;
  }>;

  heatmap: Array<{
    dayOfWeek: number;
    hourOfDay: number;
    avgRequestsPerMinute: number;
  }>;
}

// ═══════════════════════════════════════════════════════════════════
// F5 XC CONFIG OBJECTS (for JSON generation)
// ═══════════════════════════════════════════════════════════════════

export interface GeneratedRateLimitConfig {
  rateLimiter: {
    unit: 'SECOND' | 'MINUTE' | 'HOUR';
    total_number: number;
    burst_multiplier: number;
    period_multiplier: number;
  };

  rateLimiterPolicy?: {
    metadata: { name: string; namespace: string; description: string };
    spec: {
      rules: Array<{
        metadata: { name: string; disable: boolean };
        spec: {
          custom_rate_limiter: { namespace: string; name: string; kind: 'rate_limiter' };
          any_ip: Record<string, never>;
          any_asn: Record<string, never>;
          any_country: Record<string, never>;
          http_method: { methods: string[]; invert_matcher: boolean };
          domain_matcher: { exact_values: string[]; regex_values: string[] };
          path: { prefix_values: string[]; exact_values: string[]; regex_values: string[]; suffix_values: string[]; transformers: string[]; invert_matcher: boolean };
          headers: unknown[];
        };
      }>;
    };
  };

  rateLimiterObjects?: Array<{
    metadata: { name: string; namespace: string; description: string };
    spec: { total_number: number; unit: string; burst_multiplier: number };
  }>;

  rationale: string;
}

export interface LBRateLimitConfig {
  rate_limit?: {
    rate_limiter?: {
      unit: string;
      total_number: number;
      burst_multiplier: number;
      period_multiplier: number;
    };
    no_ip_allowed_list?: Record<string, never>;
    ip_allowed_list?: { prefixes: string[] };
    policies?: {
      policies: Array<{ tenant: string; namespace: string; name: string; kind: string }>;
    };
  };
  user_identification?: {
    tenant: string;
    namespace: string;
    name: string;
    kind: string;
  };
  trusted_clients?: Array<{
    user_identifier: string;
    metadata: { name: string };
    actions: string[];
  }>;
  domains?: string[];
}

// ═══════════════════════════════════════════════════════════════════
// USER SECURITY DETAILS (internal to reputation engine)
// ═══════════════════════════════════════════════════════════════════

export interface UserSecurityDetails {
  wafBlockCount: number;
  wafReportCount: number;
  botClassification: string;
  botName: string;
  svcPolicyBlockCount: number;
  apiViolationCount: number;
  attackTypes: string[];
}
