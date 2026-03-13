# RATE LIMIT ADVISOR — COMPLETE BUILD SPECIFICATION

## For: Claude Code / Developer building this tool in the xc-app-store repo

---

## TABLE OF CONTENTS
1. Project Context & Existing Patterns
2. Design Philosophy
3. Files to Create & Modify
4. TypeScript Interfaces (Complete)
5. API Integration (Endpoints, Request/Response, Real Samples)
6. Service Layer Implementation
7. Algorithm Implementation
8. UI Component Specification
9. Integration with Existing App

---

## 1. PROJECT CONTEXT

### Repository
- **Repo**: `xc-app-store` (local path or cloned from `https://github.com/kheteswar/xc-app-store`)
- **Stack**: React 18 + TypeScript + Vite + TailwindCSS
- **Styling**: Dark theme (`bg-slate-900` base), all Tailwind utility classes
- **Icons**: `lucide-react`
- **Charts**: `recharts` (already a dependency)
- **State**: React Context (`AppContext` for connection, `ToastContext` for notifications)
- **API Client**: Singleton `apiClient` in `src/services/api.ts` — all F5 XC API calls go through a Vite proxy at `/api/proxy`
- **Routing**: `react-router-dom` v6 in `src/App.tsx`

### Existing Patterns to Follow
- Pages are in `src/pages/` as named exports (e.g., `export function WAFScanner()`)
- Services are in `src/services/` with separate directories for complex modules (see `security-auditor/`)
- Types go in `src/types/index.ts`
- Pages use `useApp()` to check `isConnected` and `useNavigate()` to redirect if not
- Pages use `useToast()` for notifications (`toast.success()`, `toast.error()`, etc.)
- Pages use `apiClient` from `src/services/api.ts` for API calls
- UI follows dark theme: `bg-slate-800/50`, `border-slate-700`, `text-slate-100`, `text-slate-400`
- Featured cards use blue gradients: `from-blue-500/10`, `border-blue-500/30`
- Buttons: `bg-blue-600 hover:bg-blue-700 text-white rounded-lg px-4 py-2`

### How the API Proxy Works
All API calls go through the Vite middleware proxy. The frontend POSTs to `/api/proxy` with:
```json
{
  "tenant": "tenant-name",
  "token": "api-token",
  "endpoint": "/api/data/namespaces/ns-name/access_logs",
  "method": "POST",
  "body": { ... }
}
```
The proxy forwards to `https://{tenant}.console.ves.volterra.io{endpoint}` with `Authorization: APIToken {token}`.

The `apiClient.post(path, body)` and `apiClient.get(path)` methods handle this automatically.

---

## 2. DESIGN PHILOSOPHY: TRANSPARENT ANALYSIS WORKBENCH

This tool is NOT a black box that outputs a magic number. It is a guided analysis workbench where:

1. **Every number traces back to real data** — clicking any statistic shows the actual users/requests behind it
2. **The operator makes the final decision** — the tool provides three algorithmic starting points and an interactive slider, but the human picks the number
3. **Assumptions are visible and adjustable** — which response codes count as "legitimate", which users are excluded, all toggleable
4. **The centerpiece is an Interactive Impact Simulator** — a slider where the operator sets any rate limit value and sees real-time impact against 7 days of historical data (which users would have been blocked, when, on which paths)
5. **The output includes an auto-generated rationale** — a paragraph explaining the decision with data backing, suitable for sharing with customers

### UI Flow: Data → Insights → Decision (not Button → Magic Number)
```
Section 1: Data Collection Report (what was pulled, sampling rates, response classification)
Section 2: User Landscape (who are your users, reputation from security events)
Section 3: Traffic Patterns (time-series, heatmap, path distribution)
Section 4: Distribution Analysis (histogram, percentiles, mean/σ — full math shown)
Section 5: Interactive Impact Simulator (THE KEY FEATURE — slider + real-time replay)
Section 6: Decision + Config Generation (chosen value, rationale, JSON configs)
```

---

## 3. FILES TO CREATE & MODIFY

### New Files

```
src/services/rate-limit-advisor/
├── index.ts                    // Re-exports all modules
├── types.ts                    // All TypeScript interfaces for this tool
├── log-collector.ts            // Fetches access logs + security events with scroll pagination
├── response-classifier.ts     // Classifies responses as origin vs F5-generated
├── user-reputation.ts          // Builds user reputation map from security events
├── traffic-analyzer.ts         // Time bucketing, percentile/mean/σ calculation
├── burst-analyzer.ts           // Spike detection, burst multiplier calculation
├── recommendation-engine.ts    // Three algorithms + impact simulation
├── path-analyzer.ts            // Path normalization, grouping, sensitive endpoint detection
└── config-generator.ts         // Generates F5 XC JSON configs from chosen settings

src/pages/
└── RateLimitAdvisor.tsx        // Main page component (~2000-2500 lines)
```

### Files to Modify

**`src/App.tsx`** — Add import and route:
```tsx
import { RateLimitAdvisor } from './pages/RateLimitAdvisor';
// Inside <Routes>:
<Route path="/rate-limit-advisor" element={<RateLimitAdvisor />} />
```

**`src/pages/Home.tsx`** — Add to the `tools` array:
```tsx
{
  name: 'Rate Limit Advisor',
  description: 'Analyze 7 days of traffic to find safe rate limits. Combines access logs with security events for data-driven recommendations.',
  icon: Gauge, // import { Gauge } from 'lucide-react'
  to: '/rate-limit-advisor',
  tags: [
    { label: 'Analyze', type: 'report' as const },
    { label: 'Read-Only', type: 'safe' as const },
  ],
  badge: 'New',
  featured: true,
},
```

**`src/services/api.ts`** — Add these methods to the `F5XCApiClient` class:
```typescript
// Access Logs
async getAccessLogs(namespace: string, body: AccessLogQuery): Promise<AccessLogResponse> {
  return this.post(`/api/data/namespaces/${namespace}/access_logs`, body);
}

async scrollAccessLogs(namespace: string, body: { scroll_id: string; namespace: string }): Promise<AccessLogResponse> {
  return this.post(`/api/data/namespaces/${namespace}/access_logs/scroll`, body);
}

// Security Events
async getSecurityEvents(namespace: string, body: SecurityEventQuery): Promise<SecurityEventResponse> {
  return this.post(`/api/data/namespaces/${namespace}/app_security/events`, body);
}

async scrollSecurityEvents(namespace: string, body: { scroll_id: string; namespace: string }): Promise<SecurityEventResponse> {
  return this.post(`/api/data/namespaces/${namespace}/app_security/events/scroll`, body);
}

// Rate Limiters (Shared Objects)
async getRateLimiters(namespace: string): Promise<{ items: RateLimiterObject[] }> {
  return this.get(`/api/config/namespaces/${namespace}/rate_limiters`);
}

async createRateLimiter(namespace: string, body: unknown): Promise<RateLimiterObject> {
  return this.post(`/api/config/namespaces/${namespace}/rate_limiters`, body);
}

// Rate Limiter Policies
async getRateLimiterPolicies(namespace: string): Promise<{ items: RateLimiterPolicyObject[] }> {
  return this.get(`/api/config/namespaces/${namespace}/rate_limiter_policys`);
}

async createRateLimiterPolicy(namespace: string, body: unknown): Promise<RateLimiterPolicyObject> {
  return this.post(`/api/config/namespaces/${namespace}/rate_limiter_policys`, body);
}

// User Identification Policies
async getUserIdentificationPolicies(namespace: string): Promise<{ items: UserIdentificationPolicyObject[] }> {
  return this.get(`/api/config/namespaces/${namespace}/user_identification_policys`);
}
```

**`src/types/index.ts`** — Add these interfaces (or import from `rate-limit-advisor/types.ts`):
The full interfaces are defined in Section 4 below. Add import/re-export as needed.

---

## 4. TYPESCRIPT INTERFACES (Complete)

Place in `src/services/rate-limit-advisor/types.ts`:

```typescript
// ═══════════════════════════════════════════════════════════════════
// ACCESS LOG (from /api/data/namespaces/{ns}/access_logs)
// ═══════════════════════════════════════════════════════════════════

export interface AccessLogEntry {
  '@timestamp': string;                          // ISO 8601: "2026-03-09T08:32:47.254Z"
  time: string;                                  // Same as @timestamp
  req_id: string;                                // UUID: "4546e7fe-e730-4aa5-a478-2f3b5637be34"
  
  // User identification
  user: string;                                  // "IP-169.254.253.254-JA4TLSFingerprint-t13d091000..."
  src_ip: string;                                // "169.254.253.254"
  tls_fingerprint: string;                       // JA3: "ff31b5f09e4ea006f5a77eee361c9091"
  ja4_tls_fingerprint: string;                   // JA4: "t13d091000_f91f431d341e_78e6aca7449b"
  
  // Request details
  method: string;                                // "GET", "POST", etc.
  req_path: string;                              // "/", "/api/login", etc.
  authority: string;                             // "rb-test02.notf5.com"
  domain: string;                                // "jsxc.f5xc.support"
  original_authority: string;                    // "jsxc.f5xc.support"
  scheme: string;                                // "https"
  protocol: string;                              // "HTTP11", "HTTP2"
  user_agent: string;                            // "Envoy/HC", "Mozilla/5.0..."
  req_size: string;                              // "257" (string, not number)
  
  // Response details
  rsp_code: string;                              // "200", "403", "503", "0" (string!)
  rsp_code_class: string;                        // "2xx", "4xx", "5xx"
  rsp_code_details: string;                      // KEY FIELD: "via_upstream" or "cluster_not_found" etc.
  rsp_size: string;                              // "20521"
  
  // Timing (all numbers, in seconds)
  time_to_first_upstream_rx_byte: number;        // 0 = no upstream response = F5 blocked
  time_to_last_upstream_rx_byte: number;
  time_to_first_upstream_tx_byte: number;
  time_to_first_downstream_tx_byte: number;
  time_to_last_downstream_tx_byte: number;
  total_duration_seconds: number;                // 0.107
  rtt_upstream_seconds: string;                  // "0.003000" (string!)
  duration_with_data_tx_delay: string;           // "0.066770"
  duration_with_no_data_tx_delay: string;        // "0.066415"
  
  // Routing
  dst: string;                                   // "S:rb-test02.notf5.com" or "NOT-APPLICABLE"
  dst_instance: string;                          // "159.60.153.215" or "NOT-APPLICABLE"
  dst_ip: string;                                // "159.60.153.215"
  dst_port: string;                              // "443"
  dst_site: string;                              // "dc12-ash"
  src: string;                                   // "N:public"
  src_site: string;                              // "dc12-ash"
  src_instance: string;                          // "UNKNOWN"
  src_port: string;                              // "43347"
  
  // Security context
  waf_action: string;                            // "allow", "block", "report"
  bot_class: string;                             // "suspicious", "malicious", "benign", ""
  has_sec_event: boolean;                        // true/false — does this req have a matching security event?
  
  // Sampling
  sample_rate: number;                           // 1, 0.999, 0.5, 0.1, etc. USE 1/sample_rate for extrapolation
  
  // Policy hits (inline)
  policy_hits: {
    policy_hits: Array<{
      result: string;                            // "default_allow"
      ip_trustscore: string;                     // "100"
      ip_trustworthiness: string;                // "HIGH"
      ip_risk: string;                           // "LOW_RISK"
      rate_limiter_action: string;               // "pass" or "rate_limited"
      malicious_user_mitigate_action: string;    // "MUM_NONE"
      policy_set: string;
    }>;
  };
  
  // Metadata
  vh_name: string;                               // "ves-io-http-loadbalancer-test" (no namespace suffix!)
  vh_type: string;                               // "HTTP-LOAD-BALANCER"
  namespace: string;                             // "ambarish-rb18"
  tenant: string;                                // "sdc-support-yqpfidyt"
  app_type: string;                              // "ves-io-ambarish-rb18-test"
  cluster_name: string;                          // "dc12-ash-int-ves-io"
  site: string;                                  // "dc12-ash"
  hostname: string;                              // "master-12"
  
  // Geo (often "PRIVATE" for internal traffic)
  country: string;
  region: string;
  city: string;
  asn: string;
  as_number: string;
  as_org: string;
  
  // TLS
  tls_version: string;                           // "TLSv1_3"
  tls_cipher_suite: string;                      // "TLSv1_3/TLS_AES_128_GCM_SHA256"
  sni: string;                                   // "jsxc.f5xc.support"
  mtls: boolean;

  // Other
  api_endpoint: string;                          // "UNKNOWN" or discovered endpoint name
  connection_state: string;                      // "CLOSED"
  stream: string;                                // "svcfw"
  proxy_type: string;                            // "http"
  messageid: string;
  message_key: string;
  node_id: string;
  
  // Flattened policy hits (from CSV export, may not be in API response)
  [key: string]: unknown;
}

export interface AccessLogQuery {
  query: string;                                 // '{vh_name="ves-io-http-loadbalancer-{name}"}'
  namespace: string;
  start_time: string;                            // ISO 8601
  end_time: string;                              // ISO 8601
  scroll?: boolean;                              // true for paginated fetching
  limit?: number;                                // records per page (500 recommended)
}

export interface AccessLogResponse {
  logs: AccessLogEntry[];
  scroll_id?: string;                            // present if scroll=true, use for next page
  total_hits?: number;
}

// ═══════════════════════════════════════════════════════════════════
// SECURITY EVENT (from /api/data/namespaces/{ns}/app_security/events)
// ═══════════════════════════════════════════════════════════════════

export interface SecurityEventEntry {
  '@timestamp': string;
  time: string;
  req_id: string;                                // Cross-reference key with access logs
  
  // Event classification
  sec_event_type: string;                        // "waf_sec_event", "bot_defense_sec_event", "svc_policy_sec_event", "api_sec_event"
  sec_event_name: string;                        // "WAF", "Bot Defense", etc.
  action: string;                                // "allow", "block" — THE ACTUAL action taken
  recommended_action: string;                    // "report", "block" — what WAF recommended
  waf_mode: string;                              // "report", "block"
  enforcement_mode: string;                      // "Blocking", "Monitoring"
  
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
  'bot_info.name': string;                       // "UNKNOWN", "Googlebot", etc.
  'bot_info.classification': string;             // "suspicious", "malicious", "benign"
  'bot_info.type': string;                       // "UNKNOWN", "Search Engine", etc.
  
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
  rsp_code: string;                              // "0" = blocked before response, "200", "403", etc.
  rsp_code_class: string;                        // "2xx", "UNKNOWN", "5xx"
  rsp_size: number;
  
  // WAF details
  app_firewall_name: string;                     // "syr-fw"
  violation_rating: string;                      // "1", "2", etc.
  req_risk: string;                              // "none", "low", "medium", "high"
  
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
  query: string;                                 // '{}' for all, or filter string
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
export type UserReputation = 'clean' | 'benign_bot' | 'flagged' | 'malicious';
export type TimeGranularity = 'second' | 'minute' | 'hour';
export type TrafficSegment = 'clean_only' | 'all_legitimate' | 'total';
export type AlgorithmType = 'percentile' | 'mean_stddev' | 'peak_buffer';

export interface ClassifiedLogEntry extends AccessLogEntry {
  responseOrigin: ResponseOrigin;                // 'origin' or 'f5_blocked'
  userReputation: UserReputation;                // from security event cross-reference
  estimatedWeight: number;                       // 1/sample_rate — for volume extrapolation
}

export interface UserProfile {
  identifier: string;                            // The `user` field value
  srcIp: string;
  reputation: UserReputation;
  totalRequests: number;
  estimatedTotalRequests: number;                // weighted by sample_rate
  totalOriginRequests: number;                   // only origin-responded requests
  
  // Per-granularity rate stats
  rateStats: {
    second: RateStats;
    minute: RateStats;
    hour: RateStats;
  };
  
  // Security context
  wafBlockCount: number;
  wafReportCount: number;
  botClassification: string;                     // from bot_info.classification
  botName: string;                               // from bot_info.name
  attackTypes: string[];
  
  // Traffic pattern
  topPaths: Array<{ path: string; count: number }>;
  topMethods: Array<{ method: string; count: number }>;
  peakHour: string;                              // e.g., "Tuesday 10:00"
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
  sampleCount: number;                           // number of time windows with >0 requests
}

export interface BurstEvent {
  timestamp: string;
  userIdentifier: string;
  rateObserved: number;                          // actual rate during burst
  baseRate: number;                              // the threshold that was exceeded
  ratio: number;                                 // rateObserved / baseRate
  durationSeconds: number;
}

export interface PathAnalysis {
  normalizedPath: string;                        // "/api/users/:id" (params collapsed)
  rawPaths: string[];                            // ["/api/users/123", "/api/users/456"]
  totalRequests: number;
  uniqueUsers: number;
  methods: Record<string, number>;               // { GET: 500, POST: 100 }
  rateStats: {
    second: RateStats;
    minute: RateStats;
    hour: RateStats;
  };
  isSensitive: boolean;                          // auto-detected: login, auth, admin, etc.
  sensitiveReason?: string;                      // "Contains 'login' in path"
}

// ═══════════════════════════════════════════════════════════════════
// RECOMMENDATION & IMPACT SIMULATION
// ═══════════════════════════════════════════════════════════════════

export interface AlgorithmResult {
  type: AlgorithmType;
  label: string;                                 // "Percentile P95 × 1.5"
  description: string;                           // Plain language explanation with actual numbers
  rateLimit: number;                             // The computed number
  granularity: TimeGranularity;
  burstMultiplier: number;
  formula: string;                               // "P95=42, margin=1.5x, result=63"
  parameters: {                                  // The tunable knobs
    percentile?: number;                         // 95 for P95
    safetyMargin?: number;                       // 1.5
    nSigma?: number;                             // 3
    bufferPercent?: number;                       // 0.2 (20%)
  };
}

export interface ImpactSimulation {
  rateLimit: number;
  granularity: TimeGranularity;
  burstMultiplier: number;
  
  // Impact stats
  usersAffected: number;
  usersAffectedPercent: number;
  totalUsersAnalyzed: number;
  requestsBlocked: number;
  requestsBlockedPercent: number;
  totalRequestsAnalyzed: number;
  
  // Detailed breakdown
  affectedUsers: Array<{
    identifier: string;
    timesBlocked: number;
    peakRate: number;
    avgRate: number;
    reputation: UserReputation;
    topBlockedPaths: string[];
  }>;
  
  // When blocks would occur
  blockTimeline: Array<{
    timestamp: string;
    blockedCount: number;
  }>;
  
  // Which paths see blocks
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
  progress: number;                              // 0-100
  accessLogsCount: number;
  securityEventsCount: number;
  scrollPage: number;
  estimatedTotal?: number;
  error?: string;
}

// ═══════════════════════════════════════════════════════════════════
// ANALYSIS RESULTS (complete output of the analysis pipeline)
// ═══════════════════════════════════════════════════════════════════

export interface AnalysisResults {
  // Metadata
  lbName: string;
  namespace: string;
  analysisStart: string;
  analysisEnd: string;
  generatedAt: string;
  
  // Data collection summary
  totalAccessLogs: number;
  totalSecurityEvents: number;
  avgSampleRate: number;
  estimatedActualRequests: number;
  
  // Response classification
  responseBreakdown: {
    origin2xx: number;
    origin3xx: number;
    origin4xx: number;
    origin5xx: number;
    f5Blocked: number;
    f5BlockedReasons: Record<string, number>;    // { "cluster_not_found": 13, "waf_block": 1890 }
  };
  
  // User analysis
  users: UserProfile[];
  userReputationSummary: {
    clean: number;
    benignBot: number;
    flagged: number;
    malicious: number;
  };
  
  // Current LB config (for comparison)
  currentConfig: {
    hasRateLimit: boolean;
    currentLimit?: number;
    currentUnit?: string;
    currentBurstMultiplier?: number;
    userIdPolicyName?: string;
    trustedClients: string[];
    existingPolicies: string[];
  };
  
  // Rate analysis (per traffic segment)
  rateAnalysis: Record<TrafficSegment, {
    second: RateStats;
    minute: RateStats;
    hour: RateStats;
    userCount: number;
    requestCount: number;
  }>;
  
  // Burst analysis
  burstEvents: BurstEvent[];
  recommendedBurstMultiplier: number;
  burstRatioP90: number;
  
  // Path analysis
  paths: PathAnalysis[];
  
  // Algorithm results
  algorithms: AlgorithmResult[];
  
  // Traffic patterns (for charts)
  timeSeries: Array<{
    timestamp: string;                           // ISO 8601, bucketed
    requestsPerMinute: number;
    requestsPerSecond: number;
  }>;
  
  heatmap: Array<{
    dayOfWeek: number;                           // 0=Mon, 6=Sun
    hourOfDay: number;                           // 0-23
    avgRequestsPerMinute: number;
  }>;
}

// ═══════════════════════════════════════════════════════════════════
// F5 XC CONFIG OBJECTS (for JSON generation)
// ═══════════════════════════════════════════════════════════════════

export interface GeneratedRateLimitConfig {
  // Inline rate_limit block for the LB
  rateLimiter: {
    unit: 'SECOND' | 'MINUTE' | 'HOUR';
    total_number: number;
    burst_multiplier: number;
    period_multiplier: number;
  };
  
  // Rate limiter policy (for path-specific rules)
  rateLimiterPolicy?: {
    metadata: { name: string; namespace: string; description: string };
    spec: {
      rules: Array<{
        metadata: { name: string; disable: boolean };
        spec: {
          custom_rate_limiter: { namespace: string; name: string; kind: 'rate_limiter' };
          any_ip: {};
          any_asn: {};
          any_country: {};
          http_method: { methods: string[]; invert_matcher: boolean };
          domain_matcher: { exact_values: string[]; regex_values: string[] };
          path: { prefix_values: string[]; exact_values: string[]; regex_values: string[]; suffix_values: string[]; transformers: string[]; invert_matcher: boolean };
          headers: unknown[];
        };
      }>;
    };
  };
  
  // Shared rate_limiter objects referenced by policies
  rateLimiterObjects?: Array<{
    metadata: { name: string; namespace: string; description: string };
    spec: { total_number: number; unit: string; burst_multiplier: number };
  }>;
  
  // Plain text rationale
  rationale: string;
}

// ═══════════════════════════════════════════════════════════════════
// EXISTING LB CONFIG (relevant fields we read)
// ═══════════════════════════════════════════════════════════════════

export interface LBRateLimitConfig {
  rate_limit?: {
    rate_limiter?: {
      unit: string;
      total_number: number;
      burst_multiplier: number;
      period_multiplier: number;
    };
    no_ip_allowed_list?: {};
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
```

---

## 5. API INTEGRATION

### Access Logs API

**Endpoint**: `POST /api/data/namespaces/{namespace}/access_logs`

**Request Body**:
```json
{
  "query": "{vh_name=\"ves-io-http-loadbalancer-{lb_name}\"}",
  "namespace": "ambarish-rb18",
  "start_time": "2026-03-02T00:00:00.000Z",
  "end_time": "2026-03-09T00:00:00.000Z",
  "scroll": true,
  "limit": 500
}
```

**vh_name format**: `ves-io-http-loadbalancer-{lb_name}` — NO namespace suffix. The LB name comes from the LB list API.

**Scroll pagination**: First response includes `scroll_id`. Continue with:
```
POST /api/data/namespaces/{namespace}/access_logs/scroll
{ "scroll_id": "{scroll_id}", "namespace": "{namespace}" }
```
Repeat until `logs` array is empty.

**Real sample entry** (from the actual system):
```json
{
  "country": "PRIVATE",
  "app_type": "ves-io-ambarish-rb18-test",
  "req_id": "4546e7fe-e730-4aa5-a478-2f3b5637be34",
  "waf_action": "allow",
  "protocol": "HTTP11",
  "original_authority": "jsxc.f5xc.support",
  "method": "GET",
  "rsp_code": "200",
  "rsp_code_class": "2xx",
  "rsp_code_details": "via_upstream",
  "time_to_first_upstream_rx_byte": 0.105104913,
  "dst": "S:rb-test02.notf5.com",
  "dst_instance": "159.60.153.215",
  "src_ip": "169.254.253.254",
  "user": "IP-169.254.253.254-JA4TLSFingerprint-t13d091000_f91f431d341e_78e6aca7449b",
  "user_agent": "Envoy/HC",
  "bot_class": "suspicious",
  "has_sec_event": true,
  "sample_rate": 1,
  "vh_name": "ves-io-http-loadbalancer-test",
  "namespace": "ambarish-rb18",
  "req_path": "/",
  "@timestamp": "2026-03-09T08:32:47.254Z",
  "authority": "rb-test02.notf5.com",
  "domain": "jsxc.f5xc.support",
  "total_duration_seconds": 0.107,
  "policy_hits": {
    "policy_hits": [{
      "result": "default_allow",
      "ip_trustscore": "100",
      "ip_risk": "LOW_RISK",
      "rate_limiter_action": "pass"
    }]
  }
}
```

### Security Events API

**Endpoint**: `POST /api/data/namespaces/{namespace}/app_security/events`

**Request Body**:
```json
{
  "query": "{}",
  "namespace": "ambarish-rb18",
  "start_time": "2026-03-02T00:00:00.000Z",
  "end_time": "2026-03-09T00:00:00.000Z",
  "scroll": true
}
```

**Real security event fields (confirmed)**:
- `sec_event_type`: `"waf_sec_event"`, `"bot_defense_sec_event"`, `"svc_policy_sec_event"`, `"api_sec_event"`
- `action`: `"allow"` or `"block"` — the ACTUAL decision
- `recommended_action`: `"report"` or `"block"` — WAF's recommendation
- `rsp_code`: `"0"` = blocked before response, `"200"` = inspected but allowed
- `bot_info.classification`: `"suspicious"`, `"malicious"`, `"benign"`
- `req_id`: UUID matching access log entry

### LB Config API

**Endpoint**: `GET /api/config/namespaces/{namespace}/http_loadbalancers/{name}`

Used to read current rate limit settings, user identification policy, trusted clients, and domains.

**Key fields in response** (from real config):
```json
{
  "spec": {
    "domains": ["kdot.f5xc.support", "jean-paul-sartre.f5xc.support", "jsxc.f5xc.support"],
    "user_identification": { "name": "test-oo7", "namespace": "ambarish-rb18" },
    "rate_limit": {
      "rate_limiter": { "unit": "MINUTE", "total_number": 200, "burst_multiplier": 1, "period_multiplier": 1 },
      "no_ip_allowed_list": {},
      "policies": { "policies": [{ "name": "rlp-tst-rb18-weekend", "namespace": "ambarish-rb18" }] }
    },
    "trusted_clients": [
      { "user_identifier": "IP-169.254.253.254-JA4TLSFingerprint-t13d091000...", "metadata": { "name": "private-ip-rb-pod" } }
    ],
    "app_firewall": { "name": "syr-fw" },
    "disable_bot_defense": {},
    "enable_api_discovery": {}
  }
}
```

---

## 6. SERVICE LAYER IMPLEMENTATION

### 6.1 `log-collector.ts`

Responsible for paginated fetching of access logs and security events with progress reporting.

```typescript
// Key implementation notes:
// - Use scroll pagination: call initial endpoint, then /scroll with scroll_id until empty
// - Report progress via callback: (progress: CollectionProgress) => void
// - Collect ALL available logs — do NOT stop early
// - Handle API errors gracefully (timeout, rate limiting)
// - Target: ~500 records per page, continue until logs array is empty

export async function collectAccessLogs(
  namespace: string,
  lbName: string,
  startTime: string,
  endTime: string,
  onProgress: (p: CollectionProgress) => void
): Promise<AccessLogEntry[]> {
  // Step 1: Initial query
  const query = `{vh_name="ves-io-http-loadbalancer-${lbName}"}`;
  // Step 2: Scroll until empty
  // Step 3: Return all collected entries
}

export async function collectSecurityEvents(
  namespace: string,
  startTime: string,
  endTime: string,
  onProgress: (p: CollectionProgress) => void
): Promise<SecurityEventEntry[]> {
  // Same scroll pattern but for security events
  // Filter by vh_name if possible, otherwise collect all for namespace
}
```

### 6.2 `response-classifier.ts`

Classifies each access log entry as origin-generated or F5-generated.

```typescript
// THE KEY INSIGHT: rsp_code_details is the definitive field
// "via_upstream" = origin responded (count for rate limit)
// Anything else = F5 XC generated (exclude from baseline)

export function classifyResponse(log: AccessLogEntry): ResponseOrigin {
  if (log.rsp_code_details === 'via_upstream') {
    return 'origin';
  }
  return 'f5_blocked';
}

// Secondary validation (for edge cases)
export function isDefinitelyF5Blocked(log: AccessLogEntry): boolean {
  return log.rsp_code === '0'
    || log.dst === 'NOT-APPLICABLE'
    || log.time_to_first_upstream_rx_byte === 0;
}
```

### 6.3 `user-reputation.ts`

Builds a reputation map from security events.

```typescript
// For each unique user identifier, count security events by type
// Assign reputation:
//   - MALICIOUS: action="block" in ANY security event, OR bot_info.classification="malicious"
//   - FLAGGED: has security events with action="allow" + recommended_action="report"
//   - BENIGN_BOT: bot_info.classification="benign" (Googlebot, Bingbot, etc.)
//   - CLEAN: no security events at all

export function buildUserReputationMap(
  securityEvents: SecurityEventEntry[]
): Map<string, { reputation: UserReputation; details: UserSecurityDetails }> {
  // Index by user identifier
  // Count WAF blocks, bot classifications, service policy actions
  // Return map
}
```

### 6.4 `traffic-analyzer.ts`

Core statistical analysis engine.

```typescript
// For each user, bucket their requests into time windows and compute rates
// Then compute distribution statistics across ALL users

export function analyzeTraffic(
  logs: ClassifiedLogEntry[],
  segment: TrafficSegment,
  granularity: TimeGranularity
): RateStats {
  // Step 1: Filter logs by segment (clean_only / all_legitimate / total)
  //   clean_only: responseOrigin='origin' AND reputation='clean'
  //   all_legitimate: responseOrigin='origin' AND reputation IN ('clean','benign_bot','flagged')
  //   total: all logs
  
  // Step 2: Group by user identifier
  
  // Step 3: For each user, bucket requests into time windows
  //   For 'second': 1-second windows
  //   For 'minute': 60-second windows
  //   For 'hour': 3600-second windows
  
  // Step 4: For each user, find their PEAK rate across all windows
  //   (This is the per-user peak rate)
  //   Apply sample_rate weighting: rate = count_in_window / sample_rate
  
  // Step 5: Collect all per-user peak rates into an array
  
  // Step 6: Compute percentiles (p50, p75, p90, p95, p99, max), mean, stdDev
  //   Use sorted array for percentiles: p95 = array[Math.floor(0.95 * length)]
  //   mean = sum / length
  //   stdDev = sqrt(sum((x - mean)^2) / length)
  
  return { p50, p75, p90, p95, p99, max, mean, stdDev, sampleCount };
}
```

### 6.5 `burst-analyzer.ts`

Detects traffic spikes and recommends burst multiplier.

```typescript
// For a given base rate limit, find all time windows where any user exceeded it
// The burst multiplier = P90 of (spike_rate / base_rate) ratios, rounded up

export function analyzeBursts(
  logs: ClassifiedLogEntry[],
  baseRateLimit: number,
  granularity: TimeGranularity
): { events: BurstEvent[]; recommendedMultiplier: number; ratioP90: number } {
  // Step 1: For each user, find all windows where rate > baseRateLimit
  // Step 2: For each spike, compute ratio = window_rate / baseRateLimit
  // Step 3: Collect all ratios, find P90
  // Step 4: Recommended multiplier = Math.ceil(P90 ratio)
  // Step 5: Cap at reasonable max (e.g., 10)
}
```

### 6.6 `recommendation-engine.ts`

Three algorithms + interactive impact simulation.

```typescript
// Algorithm A: Percentile-based
export function percentileRecommendation(
  stats: RateStats,
  percentile: number = 95,   // tunable: 90, 95, 99
  safetyMargin: number = 1.5  // tunable: 1.0 - 3.0
): AlgorithmResult {
  const pValue = percentile === 90 ? stats.p90 : percentile === 95 ? stats.p95 : stats.p99;
  const result = Math.min(Math.ceil(pValue * safetyMargin), 8192);
  return {
    type: 'percentile',
    label: `Percentile P${percentile} × ${safetyMargin}`,
    description: `${percentile}% of your users stay below ${pValue} req/min. With ${safetyMargin}x safety margin: ${result}.`,
    rateLimit: result,
    formula: `P${percentile}=${pValue}, margin=${safetyMargin}x, result=${result}`,
    parameters: { percentile, safetyMargin },
    // ... other fields
  };
}

// Algorithm B: Mean + N×StdDev
export function meanStdDevRecommendation(
  stats: RateStats,
  nSigma: number = 3          // tunable: 2, 3, 4
): AlgorithmResult {
  const result = Math.min(Math.ceil(stats.mean + nSigma * stats.stdDev), 8192);
  return {
    type: 'mean_stddev',
    label: `Mean + ${nSigma}σ`,
    description: `Average=${stats.mean.toFixed(1)}, spread=${stats.stdDev.toFixed(1)}. ${nSigma} standard deviations above mean: ${result}.`,
    rateLimit: result,
    formula: `μ=${stats.mean.toFixed(1)}, σ=${stats.stdDev.toFixed(1)}, ${nSigma}σ → ${result}`,
    parameters: { nSigma },
  };
}

// Algorithm C: Peak + Buffer
export function peakBufferRecommendation(
  stats: RateStats,
  bufferPercent: number = 0.2  // tunable: 0.1 - 1.0
): AlgorithmResult {
  const result = Math.min(Math.ceil(stats.max * (1 + bufferPercent)), 8192);
  return {
    type: 'peak_buffer',
    label: `Peak + ${(bufferPercent * 100).toFixed(0)}%`,
    description: `Your busiest user peaked at ${stats.max} req/min. With ${(bufferPercent * 100).toFixed(0)}% headroom: ${result}.`,
    rateLimit: result,
    formula: `peak=${stats.max}, buffer=${(bufferPercent * 100).toFixed(0)}%, result=${result}`,
    parameters: { bufferPercent },
  };
}

// IMPACT SIMULATION — replay 7 days of traffic against a proposed limit
export function simulateImpact(
  logs: ClassifiedLogEntry[],
  rateLimit: number,
  granularity: TimeGranularity,
  burstMultiplier: number,
  segment: TrafficSegment
): ImpactSimulation {
  // Step 1: Filter logs by segment
  // Step 2: Group by user, bucket into time windows
  // Step 3: For each window, if user's rate > rateLimit * burstMultiplier → "blocked"
  // Step 4: Count affected users, blocked requests, when blocks occurred, which paths
  // Step 5: Return full ImpactSimulation object
}
```

### 6.7 `path-analyzer.ts`

```typescript
// Normalize paths: collapse UUIDs, numbers, and path parameters
// "/api/users/12345/orders/abc-def" → "/api/users/:id/orders/:id"
export function normalizePath(path: string): string {
  return path
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '/:uuid')
    .replace(/\/\d+/g, '/:id')
    .replace(/\/[0-9a-f]{24}/gi, '/:objectId');
}

// Detect sensitive endpoints
export function isSensitiveEndpoint(path: string): { sensitive: boolean; reason?: string } {
  const patterns = [
    { regex: /\/(login|signin|auth)/i, reason: 'Authentication endpoint' },
    { regex: /\/(register|signup)/i, reason: 'Registration endpoint' },
    { regex: /\/(admin|dashboard)/i, reason: 'Admin endpoint' },
    { regex: /\/(password|reset|forgot)/i, reason: 'Password management' },
    { regex: /\/(search|query)/i, reason: 'Search endpoint (resource-intensive)' },
    { regex: /\/(upload|import)/i, reason: 'Upload endpoint (resource-intensive)' },
    { regex: /\/(export|download|report)/i, reason: 'Export endpoint (resource-intensive)' },
    { regex: /\/(pay|checkout|transaction)/i, reason: 'Payment endpoint' },
    { regex: /\/api\/v\d/i, reason: 'Versioned API endpoint' },
  ];
  for (const p of patterns) {
    if (p.regex.test(path)) return { sensitive: true, reason: p.reason };
  }
  return { sensitive: false };
}
```

### 6.8 `config-generator.ts`

```typescript
// Generate the three JSON config objects based on operator's chosen values

export function generateConfig(
  lbName: string,
  namespace: string,
  rateLimit: number,
  unit: 'SECOND' | 'MINUTE' | 'HOUR',
  burstMultiplier: number,
  pathRules: Array<{ path: string; method: string; domain: string; limit: number; unit: string }>,
  analysis: AnalysisResults
): GeneratedRateLimitConfig {
  const date = new Date().toISOString().split('T')[0];
  
  return {
    rateLimiter: {
      unit,
      total_number: rateLimit,
      burst_multiplier: burstMultiplier,
      period_multiplier: 1,
    },
    rationale: generateRationale(lbName, rateLimit, unit, burstMultiplier, analysis),
    // ... rateLimiterPolicy and rateLimiterObjects if pathRules provided
  };
}

function generateRationale(/* ... */): string {
  // Auto-generate a paragraph like:
  // "Rate limit of 45 requests per minute per user was selected based on
  //  7-day traffic analysis (Mar 2-9, 2026) of LB 'my-app' in namespace 'production'.
  //  45,231 access logs analyzed, 3,071 unique clean users identified.
  //  43 malicious users excluded (1,847 WAF blocks). 323 origin-generated 4xx
  //  responses included as legitimate traffic. The P95 per-user request rate
  //  is 42 req/min. At this limit, 154 users (5%) would have been temporarily
  //  rate-limited during peak hours."
}
```

---

## 7. UI COMPONENT SPECIFICATION

### `RateLimitAdvisor.tsx` — Main Page

The page has 6 sections rendered as a scrollable single page (not tabs — the operator should see the full journey).

#### State Management
```typescript
// Configuration state
const [selectedNamespace, setSelectedNamespace] = useState<string>('');
const [selectedLB, setSelectedLB] = useState<string>('');
const [dateRange, setDateRange] = useState({ start: '7 days ago', end: 'now' });

// Collection state
const [isCollecting, setIsCollecting] = useState(false);
const [progress, setProgress] = useState<CollectionProgress>({ phase: 'idle', ... });

// Analysis results
const [results, setResults] = useState<AnalysisResults | null>(null);

// Interactive controls
const [selectedGranularity, setSelectedGranularity] = useState<TimeGranularity>('minute');
const [selectedSegment, setSelectedSegment] = useState<TrafficSegment>('clean_only');
const [sliderValue, setSliderValue] = useState<number>(0); // the interactive rate limit slider
const [burstMultiplier, setBurstMultiplier] = useState<number>(2);
const [impactResult, setImpactResult] = useState<ImpactSimulation | null>(null);

// Algorithm tuning
const [percentileMargin, setPercentileMargin] = useState(1.5);
const [nSigma, setNSigma] = useState(3);
const [bufferPercent, setBufferPercent] = useState(0.2);
```

#### Section 1: Config Panel + Data Collection
- Namespace dropdown (from `apiClient.getNamespaces()`)
- LB dropdown (from `apiClient.getLoadBalancers(namespace)`)
- Date range picker (default: last 7 days)
- "Analyze" button → triggers collection pipeline
- Progress bar showing phase, record counts, elapsed time

#### Section 2: Data Collection Report
- Total logs pulled, sampling rate breakdown
- Response classification: origin 2xx/3xx/4xx/5xx vs F5-blocked
- Each category expandable with counts and top paths
- Explanation of WHY each category is included/excluded
- "Adjust Filters" toggle for response code inclusion

#### Section 3: User Landscape
- Reputation breakdown: CLEAN / BENIGN_BOT / FLAGGED / MALICIOUS with counts
- Expandable tables for each category (malicious users show WAF block count + attack type)
- Top 20 users table (sortable by total requests, peak rate, avg rate)
- Each user row clickable for detail (traffic timeline, top paths)

#### Section 4: Traffic Patterns
- 7-day RPS time-series chart using Recharts `<AreaChart>` or `<LineChart>`
- Granularity toggle: per-second / per-minute / per-hour
- Day × Hour heatmap (7 rows × 24 cols)
- Path distribution bar chart
- Inline annotations explaining patterns

#### Section 5: Distribution Analysis + Impact Simulator (MAIN SECTION)
- Histogram of per-user rates using Recharts `<BarChart>`
- Percentile table with plain-language explanations
- **Interactive Slider**: `<input type="range">` controlling rate limit value
  - Range: 0 to stats.max * 1.5
  - On change: recalculate `simulateImpact()` and update display
  - Show: users affected, requests blocked, affected user table, block timeline, path impact
- Three algorithm preset buttons that set the slider position
- Each preset shows its formula and math
- Burst multiplier slider below main slider

#### Section 6: Decision + Config
- Chosen value summary
- Auto-generated rationale (editable textarea)
- JSON config blocks with syntax highlighting (use `<pre>` with `bg-slate-950 text-green-400`)
- Copy-to-clipboard buttons
- Current vs Recommended comparison (if LB already has rate limits)

### Recharts Usage
```tsx
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';

// Time series
<ResponsiveContainer width="100%" height={300}>
  <AreaChart data={results.timeSeries}>
    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
    <XAxis dataKey="timestamp" stroke="#94a3b8" />
    <YAxis stroke="#94a3b8" />
    <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #475569' }} />
    <Area type="monotone" dataKey="requestsPerMinute" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.1} />
  </AreaChart>
</ResponsiveContainer>
```

---

## 8. CRITICAL IMPLEMENTATION DETAILS

### The `rsp_code_details` Field Is the 4xx Classifier
- `"via_upstream"` = response came from origin server → COUNT as legitimate traffic
- `"cluster_not_found"`, or any other value = F5 XC generated the response → EXCLUDE from baseline
- This is confirmed from real sample data. Do NOT use a complex multi-signal approach.

### The `sample_rate` Field Enables Precise Volume Estimation
- Each log entry has `sample_rate` (1 = 100% sampled, 0.5 = 50% sampled)
- Estimated weight per entry: `1 / sample_rate`
- Total estimated requests = `sum(1/entry.sample_rate for all entries)`
- Per-user rates should also apply this weighting

### The `user` Field Is the Resolved User Identifier
- Format: `"IP-{ip}-JA4TLSFingerprint-{ja4_fingerprint}"` (when User ID Policy uses IP + TLS)
- Format: `"IP-{ip}"` (when only IP is configured)
- This field is pre-resolved by F5 XC. Use it directly as the grouping key.

### F5 XC Rate Limit Hard Maximum
- `total_number` maximum: **8192** requests per period
- All recommendations must be capped at 8192

### The Impact Simulator Must Be Fast
- Recalculates on every slider move
- Pre-process: group logs by user and time bucket ONCE after collection
- Simulation: iterate pre-grouped data, check against threshold
- Target: <100ms for 50K logs

---

## 9. INTEGRATION CHECKLIST

### Files Modified (exact changes):

**`src/App.tsx`**: Add `import { RateLimitAdvisor } from './pages/RateLimitAdvisor';` and add `<Route path="/rate-limit-advisor" element={<RateLimitAdvisor />} />` inside `<Routes>`.

**`src/pages/Home.tsx`**: Add `import { Gauge } from 'lucide-react';` in the icon imports. Add tool card object to the `tools` array (see Section 3).

**`src/services/api.ts`**: Add the 7 new methods to `F5XCApiClient` class (see Section 3).

**`src/types/index.ts`**: Add `export * from '../services/rate-limit-advisor/types';` OR add relevant interfaces inline.

### New Files Created (10 files):
1. `src/services/rate-limit-advisor/types.ts`
2. `src/services/rate-limit-advisor/index.ts`
3. `src/services/rate-limit-advisor/log-collector.ts`
4. `src/services/rate-limit-advisor/response-classifier.ts`
5. `src/services/rate-limit-advisor/user-reputation.ts`
6. `src/services/rate-limit-advisor/traffic-analyzer.ts`
7. `src/services/rate-limit-advisor/burst-analyzer.ts`
8. `src/services/rate-limit-advisor/recommendation-engine.ts`
9. `src/services/rate-limit-advisor/path-analyzer.ts`
10. `src/services/rate-limit-advisor/config-generator.ts`
11. `src/pages/RateLimitAdvisor.tsx`

### Build Phases (suggested order):

**Phase 1 — Foundation**: types.ts, log-collector.ts, response-classifier.ts, basic RateLimitAdvisor.tsx with config panel + data collection + progress bar.

**Phase 2 — Analysis Engine**: user-reputation.ts, traffic-analyzer.ts, distribution display with percentile table.

**Phase 3 — Interactive Simulator**: recommendation-engine.ts (all 3 algorithms), the slider + simulateImpact(), affected users table.

**Phase 4 — Visualization**: Recharts time-series, heatmap, histogram, path distribution.

**Phase 5 — Config Generation**: config-generator.ts, burst-analyzer.ts, path-analyzer.ts, JSON display, copy buttons, rationale generation, current vs recommended comparison.
