# Rate Limit Advisor — Refined Development Blueprint v2

## XC App Store New Tool

---

## 1. DESIGN PHILOSOPHY: ANALYSIS WORKBENCH, NOT BLACK BOX

This tool is NOT a magic number generator. It is a **transparent analysis workbench** that shows the operator every step of the data journey — from raw logs to statistical distributions to the final recommendation. The operator should be able to:

1. **See the raw data** — how many logs were pulled, what the sampling rate was, what was filtered and why
2. **Understand the math** — every percentile, mean, and standard deviation is shown with the actual numbers behind it
3. **Question the assumptions** — every filter, exclusion, and threshold is visible and adjustable
4. **Trace any recommendation back to real traffic** — "This limit of 45 req/min comes from the P95 of your 3,071 clean users. Here are the actual users near that threshold. User X had 43 req/min on Tuesday at 2pm. User Y peaked at 47 req/min on Friday at 11am."
5. **Make an educated decision they can defend** — the operator picks the final number, not the tool

### What This Means in Practice

**Every number shown has a "Show me why" drill-down:**
- "45 req/min recommended" → click → shows the distribution curve with P95 marked, lists the actual users at and above that threshold, shows what time of day they peaked, shows what paths they hit
- "127 users excluded as malicious" → click → shows each user, their WAF block count, what attacks were detected, what their request rate was (so the operator can verify they really should be excluded)
- "Sampling rate: 1.0" → shown explicitly so operator knows if data is complete or extrapolated
- "323 origin-generated 4xx included in baseline" → click → shows breakdown: 180 were 404s, 95 were 400s, 48 were 401s, with top paths that returned each code

**The UI flow is: Data → Insights → Decision, not: Button → Magic Number**

```
┌─────────────────────────────────────────────────────────┐
│  STEP 1: DATA COLLECTION                                │
│  "Here's what we pulled and what we found"              │
│  - X logs pulled, Y security events                     │
│  - Sampling rate breakdown                              │
│  - Data quality indicators                              │
├─────────────────────────────────────────────────────────┤
│  STEP 2: TRAFFIC UNDERSTANDING                          │
│  "Here's what your traffic looks like"                  │
│  - Who are your users? How many? How active?            │
│  - What patterns emerge? Peak hours? Quiet periods?     │
│  - Which responses came from origin vs F5?              │
│  - Who triggered security events? What kind?            │
├─────────────────────────────────────────────────────────┤
│  STEP 3: STATISTICAL ANALYSIS                           │
│  "Here are the numbers behind the numbers"              │
│  - Full distribution curves (not just percentiles)      │
│  - Three different statistical lenses on the same data  │
│  - Burst pattern timeline with actual spike events      │
│  - Per-path breakdown with hotspot identification       │
├─────────────────────────────────────────────────────────┤
│  STEP 4: IMPACT SIMULATION                              │
│  "Here's what would happen if you set limit X"          │
│  - Interactive slider: move the limit, see who gets     │
│    blocked in real time against 7 days of real data     │
│  - Named users/IPs that would have been affected        │
│  - Which paths and times would see the most blocks      │
├─────────────────────────────────────────────────────────┤
│  STEP 5: YOUR DECISION + CONFIG                         │
│  "You've seen the data. Pick your limit."               │
│  - Three algorithm suggestions as starting points       │
│  - Manual override with instant impact recalculation    │
│  - Generated JSON config for whatever you chose         │
│  - Plain-text summary explaining the rationale          │
└─────────────────────────────────────────────────────────┘
```

---

## 2. DATA SOURCES — DUAL LOG ENRICHMENT

### Source 1: Access Logs (Request Patterns)

```
POST /api/data/namespaces/{ns}/access_logs
Body: { query, namespace, start_time, end_time, scroll: true, limit: 500 }
Scroll: POST /api/data/namespaces/{ns}/access_logs/scroll
```

**Key fields used:**

| Field | Purpose |
|---|---|
| `timestamp` | Time bucketing (per-second, per-minute, per-hour) |
| `user` | User identifier per User ID Policy (default: src_ip based) |
| `src_ip` | Fallback identifier if user field is empty |
| `tls_fingerprint` | For IP + TLS based identification |
| `req_path` | Per-path analysis |
| `method` | Method-specific analysis |
| `authority` | Domain-level analysis for multi-domain LBs |
| `rsp_code` | Traffic classification (2xx, 3xx = legitimate; 4xx/5xx = errors) |
| `user_agent` | Traffic type identification |
| `country` | Geo-based patterns |

**Response code classification — THE CRITICAL 4xx DISTINCTION:**

Not all 4xx responses are equal. A 4xx can originate from two completely different places:

| Origin of 4xx | Examples | Meaning | Count for rate limit? |
|---|---|---|---|
| **F5 XC generated** | WAF block (403), Rate limit (429), Service Policy deny (403), Bot Defense block | Security enforcement terminated the request before it reached origin. The user is being blocked. | ❌ NO — this is exactly the traffic rate limiting is meant to stop |
| **Origin/upstream generated** | App returns 404 (page not found), 400 (bad form input), 401 (not logged in), 409 (conflict), 422 (validation error) | A real user made a real request that reached the origin server. The app responded with an error. | ✅ YES — this is a legitimate user generating load on the origin |

**How to distinguish F5-generated vs Origin-generated 4xx:**

```
Method 1: Cross-reference req_id with security events (MOST RELIABLE)
┌─────────────────────────────────────────────────────────────┐
│  Access log entry: rsp_code=403, req_id="abc-123"          │
│                                                              │
│  Search security events for req_id="abc-123"                │
│    ├─ FOUND with action=block → F5 XC generated 403        │
│    └─ NOT FOUND            → Origin generated 403           │
└─────────────────────────────────────────────────────────────┘

Method 2: Check upstream timing fields in access log
┌─────────────────────────────────────────────────────────────┐
│  time_to_first_upstream_rx_byte = 0 or missing              │
│    → Request never reached origin → F5 generated            │
│                                                              │
│  time_to_first_upstream_rx_byte > 0                         │
│    → Origin received and responded → Origin generated       │
└─────────────────────────────────────────────────────────────┘

Method 3: rsp_code value itself
┌─────────────────────────────────────────────────────────────┐
│  rsp_code = 0    → F5 blocked (documented behavior)        │
│  rsp_code = 429  → Check if rate limiter is configured      │
│                    on this LB. If yes → likely F5 generated │
│                    If no → origin generated                  │
│  rsp_code = 403  → Ambiguous. Must use Method 1 or 2.      │
└─────────────────────────────────────────────────────────────┘

Combined decision engine (applied to every access log entry):
  IF rsp_code == 0:
    → F5_BLOCKED (definitely blocked, never reached origin)
  ELIF req_id exists in security_events with action=block:
    → F5_BLOCKED (security event confirms F5 terminated it)
  ELIF time_to_first_upstream_rx_byte == 0 or missing:
    → F5_BLOCKED (no upstream response = F5 terminated)
  ELSE:
    → ORIGIN_RESPONSE (request reached origin, response is genuine)
```

**Final response code buckets for rate analysis:**

| Bucket | Response Codes | Source | Count in baseline? |
|---|---|---|---|
| **Successful** | 2xx | Origin | ✅ Yes |
| **Redirects** | 3xx | Origin | ✅ Yes |
| **App Errors** | 4xx from origin | Origin | ✅ Yes (real user load) |
| **Server Errors** | 5xx from origin | Origin | ✅ Yes (still user-generated load) |
| **Security Blocks** | 0, 4xx from F5 XC | F5 XC | ❌ No (this IS the abuse) |

The UI shows this breakdown with toggles so the operator can verify and override if needed.

### Source 2: Security Events (Threat Intelligence)

```
POST /api/data/namespaces/{ns}/app_security/events
Body: { query, namespace, start_time, end_time, scroll: true }
```

**Security event types and how we use them:**

| Event Type (`sec_event_type`) | Fields We Extract | How It Enriches Rate Analysis |
|---|---|---|
| `waf_sec_event` | `src_ip`, `user`, `action` (allow/report/block), `attack_types`, `violations`, `calculated_action` | IPs that trigger WAF = potential attackers. Their request rate should NOT be used as baseline for legitimate traffic. If WAF blocked them, they represent abuse we're trying to prevent. |
| `bot_defense_sec_event` | `src_ip`, `user`, `bot_classification` (Malicious/Suspicious/Benign), `bot_info.name`, `bot_info.type` | **Benign bots** (Googlebot, Bingbot, monitoring): Keep in analysis but recommend separate rate limits. **Malicious/Suspicious bots**: Exclude from baseline — their traffic pattern represents exactly what we're rate limiting against. |
| `svc_policy_sec_event` | `src_ip`, `user`, `action`, `policy_name`, `rule_name` | Service policy blocks = already-identified bad actors. Exclude from baseline. |
| `api_sec_event` | `src_ip`, `user`, `api_sec_detail` | API validation violations = misuse patterns. Flag these users. |

### The Enrichment Pipeline

```
Step 1: Pull ALL access logs (7 days, paginate through everything)
Step 2: Pull ALL security events (7 days, same period)
Step 3: Build "Security Event Index" — index all security events by req_id
        This enables O(1) lookup when classifying 4xx responses
Step 4: Classify every access log entry's response:
   - rsp_code == 0 → F5_BLOCKED
   - req_id found in security events with action=block → F5_BLOCKED
   - time_to_first_upstream_rx_byte == 0 → F5_BLOCKED
   - Everything else → ORIGIN_RESPONSE (legitimate traffic)
Step 5: Build "User Reputation Map" from security events:
   - For each src_ip/user, count:
     - WAF events (blocked vs reported)
     - Bot classification (malicious/suspicious/benign)
     - Service policy blocks
     - API violations
   - Assign reputation score: CLEAN / FLAGGED / MALICIOUS
Step 6: Tag every access log entry with:
   - Response origin (F5_BLOCKED vs ORIGIN_RESPONSE)
   - User reputation (CLEAN / FLAGGED / MALICIOUS / BENIGN_BOT)
Step 7: Generate THREE separate analyses:
   A. "Clean Traffic Only" — ORIGIN_RESPONSE entries from CLEAN users only
   B. "All Legitimate Traffic" — ORIGIN_RESPONSE entries from CLEAN + Benign bots + FLAGGED
   C. "Total Traffic" — everything including F5_BLOCKED and MALICIOUS users
Step 8: Show all three to the operator with clear explanation
```

**Why this matters for rate limiting:**
If a customer currently has 100 RPS, and 30 RPS comes from malicious bot traffic that WAF is already blocking, the rate limit should be based on the 70 RPS legitimate baseline — not 100. Without security event enrichment, we'd recommend a limit that's 43% higher than necessary.

### Bot Handling (CORRECTED — No Blind Exclusion)

Bots are NOT automatically excluded. The tool categorizes them:

| Category | Examples | Treatment |
|---|---|---|
| **Verified Benign** | Googlebot, Bingbot, Monitoring (Pingdom, UptimeRobot) | Include in analysis. Show separately. Recommend allowlist for these in rate limiter IP exceptions. |
| **Unverified/Unknown** | Generic scrapers, headless browsers with no WAF/Bot Defense classification | Include in analysis. Flag in UI for operator review. |
| **Malicious** (from Bot Defense events) | Credential stuffers, content scrapers, attack tools | Exclude from baseline calculation. Show in "Suspicious Traffic" panel. |

---

## 3. THE ALGORITHM — ALL THREE APPROACHES, USER DECIDES

The tool computes ALL three statistical models and presents them side-by-side. The operator picks the approach that matches their risk tolerance.

### Approach A: Percentile-Based (P95/P99 + Safety Margin)

```
How it works:
  1. For each user, compute requests per [second|minute|hour]
  2. Take the distribution across ALL users
  3. Find the P95 or P99 value
  4. Multiply by a safety margin (user-configurable, default 1.5x)

Example:
  P95 of per-user requests/minute = 30
  Safety margin = 1.5x
  Recommendation = 30 × 1.5 = 45 requests/minute

Strengths:
  ✓ Robust against outliers (P95 ignores top 5% of users)
  ✓ Well-understood statistical approach
  ✓ Safety margin is intuitive to configure

Weaknesses:
  ✗ Assumes traffic distribution is stable
  ✗ Can be too conservative if top 5% are legitimate power users

Best for: Applications with many users, relatively uniform usage patterns
```

### Approach B: Mean + Standard Deviations

```
How it works:
  1. For each user, compute requests per [second|minute|hour]
  2. Calculate mean (μ) and standard deviation (σ) across all users
  3. Recommendation = μ + (N × σ), where N is user-configurable (default 3)

Example:
  Mean per-user requests/minute = 12
  Standard deviation = 8
  N = 3 (three sigma)
  Recommendation = 12 + (3 × 8) = 36 requests/minute

Strengths:
  ✓ Mathematically precise — 3σ covers 99.7% of normal distribution
  ✓ Automatically adapts to traffic variance
  ✓ Can tune N for different confidence levels

Weaknesses:
  ✗ Assumes roughly normal distribution (traffic often has long tails)
  ✗ Single outlier can skew σ significantly
  ✗ Less intuitive for non-technical operators

Best for: Applications with normally distributed traffic, technical operators
```

### Approach C: Peak Observed Rate + Buffer

```
How it works:
  1. For each user, find their MAXIMUM request rate in the analysis window
  2. Take the peak across ALL users (or P99 of peaks to exclude extreme outliers)
  3. Add buffer percentage (user-configurable, default 20%)

Example:
  Peak observed per-user requests/minute = 120
  Buffer = 20%
  Recommendation = 120 × 1.2 = 144 requests/minute

Strengths:
  ✓ Guarantees no legitimate user was blocked during analysis period
  ✓ Simplest to understand and explain
  ✓ Most conservative — lowest risk of false positives

Weaknesses:
  ✗ Can be very high if there was any anomalous legitimate spike
  ✗ Doesn't distinguish sustained load from momentary burst
  ✗ May not provide meaningful protection if peak was already high

Best for: Mission-critical apps where blocking legitimate users is unacceptable
```

### Side-by-Side Presentation in UI

```
┌─────────────────────────────────────────────────────────────────┐
│                  RATE LIMIT RECOMMENDATIONS                      │
│                                                                   │
│  ┌── Percentile ──┐  ┌── Mean+StdDev ──┐  ┌── Peak+Buffer ──┐  │
│  │                 │  │                  │  │                  │  │
│  │  Per Second: 8  │  │  Per Second: 6   │  │  Per Second: 24  │  │
│  │  Per Minute: 45 │  │  Per Minute: 36  │  │  Per Minute: 144 │  │
│  │  Burst: 2x      │  │  Burst: 3x       │  │  Burst: 1x       │  │
│  │                 │  │                  │  │                  │  │
│  │  Users affected │  │  Users affected  │  │  Users affected  │  │
│  │  if applied: 5% │  │  if applied: 3%  │  │  if applied: 0%  │  │
│  │                 │  │                  │  │                  │  │
│  │  [Tune Margin]  │  │  [Tune N sigma]  │  │  [Tune Buffer %] │  │
│  │  [Select ✓]     │  │  [Select ✓]      │  │  [Select ✓]      │  │
│  └─────────────────┘  └──────────────────┘  └──────────────────┘  │
│                                                                   │
│  Each card shows: which real users from the 7-day window would    │
│  have been blocked, so the operator can make an informed choice.  │
└───────────────────────────────────────────────────────────────────┘
```

For each approach, the tool computes a **"would have been blocked" simulation** — replaying the 7 days of access logs against the proposed limit and showing exactly which users would have been rate-limited, how many times, and on which paths.

---

## 4. TIME GRANULARITY — SHOW ALL, USER PICKS

F5 XC supports `SECOND`, `MINUTE`, `HOUR` as rate limit periods. Instead of choosing for the operator, we show analysis for all three and let them pick.

### Per-Second Analysis
- Buckets: 1-second windows over 7 days
- Best for: Burst protection, DDoS mitigation
- Challenge: Very granular, needs high-volume data to be meaningful
- F5 XC max: 8192 per second

### Per-Minute Analysis
- Buckets: 1-minute windows over 7 days
- Best for: General API rate limiting, most common use case
- Challenge: Allows short bursts within the minute
- F5 XC max: 8192 per minute

### Per-Hour Analysis
- Buckets: 1-hour windows over 7 days
- Best for: Quota-style limiting, heavy API consumers
- Challenge: Very permissive — allows significant bursts within the hour
- F5 XC max: 8192 per hour

### UI Presentation

```
┌──────────────────────────────────────────────────────┐
│  TIME GRANULARITY ANALYSIS                            │
│                                                        │
│  [Per Second] [Per Minute] [Per Hour]  ← Tab selector │
│                                                        │
│  Currently viewing: Per Minute                         │
│                                                        │
│  Distribution Chart:                                   │
│  ████████████████████████████░░░░ p50: 5               │
│  ████████████████████████████████████░░ p75: 12        │
│  ██████████████████████████████████████████░ p90: 28   │
│  █████████████████████████████████████████████ p95: 45 │
│  ███████████████████████████████████████████████ p99: 78│
│  ████████████████████████████████████████████████ max:120│
│                                                        │
│  ☑ Use Per Minute for recommendation                   │
│  ☐ Also generate Per Second rule                       │
│  ☐ Also generate Per Hour rule                         │
└──────────────────────────────────────────────────────┘
```

The operator can select one or multiple granularities. If they select both Per Second and Per Minute, the tool generates a rate limiter config for each.

---

## 5. BURST MULTIPLIER ANALYSIS

The F5 XC `burst_multiplier` allows temporary spikes above the configured rate. We analyze traffic spikes to recommend this.

### How We Calculate Burst Multiplier

```
1. For each user, compute their request rate in rolling windows
2. Identify "spike events" — windows where rate exceeds the recommended base limit
3. For each spike: calculate (peak_during_spike / base_rate)
4. Burst multiplier = P90 of all spike ratios (rounded up to integer)

Example:
  Recommended base rate: 30 req/min
  User A had a spike of 60 req/min → ratio = 2.0
  User B had a spike of 45 req/min → ratio = 1.5
  User C had a spike of 90 req/min → ratio = 3.0
  P90 of ratios = 2.5 → Burst multiplier = 3

Displayed as:
  "Your legitimate users occasionally burst up to 3x the normal rate.
   We recommend a burst multiplier of 3 to accommodate these spikes
   without triggering rate limiting."
```

### Spike Pattern Visualization

The UI shows a timeline highlighting when bursts occurred, helping the operator understand if spikes are:
- **Periodic** (e.g., every Monday at 9 AM — work starts) → Burst is expected, set higher multiplier
- **Random** (scattered throughout the week) → Normal variance, moderate multiplier
- **Concentrated on few users** (one IP causing all spikes) → May be an outlier, lower multiplier

---

## 6. COMPLETE ANALYSIS PIPELINE

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1: DATA COLLECTION                                        │
│                                                                   │
│  ┌─ Access Logs ────────┐    ┌─ Security Events ────────────┐   │
│  │ Scroll through ALL   │    │ Pull WAF events              │   │
│  │ 7 days of logs       │    │ Pull Bot Defense events      │   │
│  │ Progress: ████░ 80%  │    │ Pull Service Policy events   │   │
│  │ Records: 45,231      │    │ Pull API Security events     │   │
│  └──────────────────────┘    │ Records: 1,847              │   │
│                               └──────────────────────────────┘   │
├──────────────────────────────────────────────────────────────────┤
│  PHASE 2: ENRICHMENT + RESPONSE CLASSIFICATION                    │
│                                                                   │
│  4xx Classification (F5 XC vs Origin):                            │
│  - 45,231 total access log entries                                │
│  - 2,340 have 4xx response codes                                  │
│    - 1,890 matched security events (req_id) → F5 BLOCKED         │
│    - 127 had no upstream timing → F5 BLOCKED                     │
│    - 323 confirmed origin-generated → LEGITIMATE 4xx              │
│                                                                   │
│  Build User Reputation Map:                                       │
│  - 3,241 unique users found in access logs                       │
│  - 127 users had WAF events (89 blocked, 38 reported)            │
│  - 43 users flagged as malicious bots                            │
│  - 12 users flagged as benign bots (Googlebot, etc.)             │
│  - 8 users had service policy blocks                             │
│  - 3,071 users are CLEAN                                         │
│                                                                   │
│  Baseline traffic (after removing F5-blocked entries):            │
│  - 43,214 legitimate requests (2xx + 3xx + origin 4xx + 5xx)    │
│  - 2,017 F5-blocked requests excluded from baseline              │
│                                                                   │
│  User categories:                                                 │
│  ■ CLEAN: 3,071 (94.8%)                                         │
│  ■ BENIGN_BOT: 12 (0.4%)                                        │
│  ■ FLAGGED: 115 (3.5%)  ← WAF reported but not blocked          │
│  ■ MALICIOUS: 43 (1.3%) ← WAF blocked + malicious bots          │
├──────────────────────────────────────────────────────────────────┤
│  PHASE 3: STATISTICAL ANALYSIS                                    │
│                                                                   │
│  For EACH traffic segment (Clean / All-Legit / Total):           │
│  For EACH time granularity (Second / Minute / Hour):             │
│  Compute:                                                         │
│  - Percentiles: p50, p75, p90, p95, p99, max                    │
│  - Mean + Standard Deviation                                      │
│  - Peak observed rate + spike patterns                            │
│  - Burst ratio distribution                                       │
├──────────────────────────────────────────────────────────────────┤
│  PHASE 4: RECOMMENDATION GENERATION                               │
│                                                                   │
│  For EACH algorithm (Percentile / Mean+σ / Peak+Buffer):         │
│  For EACH selected time granularity:                              │
│  Generate:                                                        │
│  - Recommended threshold number                                   │
│  - Recommended burst multiplier                                   │
│  - "Would-have-been-blocked" simulation                           │
│  - JSON config snippet                                            │
├──────────────────────────────────────────────────────────────────┤
│  PHASE 5: PATH-SPECIFIC ANALYSIS (Optional)                      │
│                                                                   │
│  Group by normalized path → per-path statistics                   │
│  Auto-detect sensitive endpoints (login, auth, admin, search)     │
│  Generate Rate Limiter Policy rules for top-N paths               │
└──────────────────────────────────────────────────────────────────┘
```

---

## 6B. VALIDATED CONFIG SCHEMAS (From Real LB Data)

All schemas below are confirmed from the sample LB config (`test` in namespace `ambarish-rb18`).

### How Rate Limiting Is Structured on a Real LB

```
HTTP Load Balancer "test"
│
├── user_identification: "test-oo7"              ← WHO is the user?
│   └── Rules: IP + JA4 TLS Fingerprint
│       → Produces: "IP-169.254.253.254-JA4TLSFingerprint-t13d091000..."
│
├── rate_limit:                                   ← GLOBAL rate limit
│   ├── rate_limiter:
│   │   ├── unit: "MINUTE"
│   │   ├── total_number: 200                     ← Current: 200 req/min per user
│   │   ├── burst_multiplier: 1                   ← No burst allowance
│   │   └── period_multiplier: 1
│   ├── no_ip_allowed_list: {}                    ← No IPs exempted
│   └── policies:
│       └── "rlp-tst-rb18-weekend"                ← Path-specific policy
│           └── rules:
│               └── Rule: GET /maps on idpxc.f5xc.support
│                   → Uses rate_limiter "test-abc"
│
├── trusted_clients:                              ← Users exempt from security
│   ├── "IP-169.254.253.254-JA4..." → skip MUM
│   └── "IP-204.134.187.142-JA4..." → skip all
│
└── Three domains: kdot, jean-paul-sartre, jsxc
    └── Each with separate origin pool via routes
```

### "Current vs Analyzed" Comparison (Key Feature)

The tool reads the existing `rate_limit` config from the LB and shows it side-by-side with the analysis:

```
┌─ CURRENT CONFIG ──────────────────┐  ┌─ YOUR ANALYSIS SAYS ──────────┐
│                                    │  │                                │
│  Global: 200 req/min per user      │  │  P95 of clean users: 42/min   │
│  Burst: 1x (no burst allowed)     │  │  Suggested range: 45-63/min   │
│  Policy: rlp-tst-rb18-weekend     │  │  Burst analysis: 2-3x needed  │
│  IP allowlist: None                │  │  Benign bots: consider allow  │
│                                    │  │                                │
│  ⚠ Current limit (200) is 3.2x    │  │  At 200/min: 0% of clean      │
│    above P99 (78). This provides   │  │  users would have been blocked │
│    minimal protection against      │  │  in the past 7 days.           │
│    abuse while allowing all        │  │                                │
│    legitimate traffic through.     │  │  Even your heaviest user only  │
│                                    │  │  peaked at 120/min.            │
└────────────────────────────────────┘  └────────────────────────────────┘

ⓘ "Your current limit of 200 req/min is well above all observed legitimate
   traffic. The most active user peaked at 120 req/min. An attacker could
   send up to 200 req/min per IP before being limited. Consider tightening
   to 63-78 req/min range based on the analysis."
```

### Config Objects the Tool Generates (Validated Schemas)

**A. Rate Limiter (inline on LB — `spec.rate_limit.rate_limiter`)**
```json
{
  "rate_limiter": {
    "unit": "MINUTE",
    "total_number": 45,
    "burst_multiplier": 2,
    "period_multiplier": 1
  },
  "no_ip_allowed_list": {},
  "policies": {
    "policies": []
  }
}
```
ⓘ "This replaces the current `rate_limit` block on your LB config."

**B. Rate Limiter Policy (for path-specific rules)**
```json
{
  "metadata": {
    "name": "rl-advisor-{lb_name}-{date}",
    "namespace": "{namespace}",
    "description": "Generated by Rate Limit Advisor. Based on 7-day analysis."
  },
  "spec": {
    "rules": [
      {
        "metadata": {
          "name": "login-endpoint-limit"
        },
        "spec": {
          "custom_rate_limiter": {
            "namespace": "{namespace}",
            "name": "rl-advisor-login-{lb_name}",
            "kind": "rate_limiter"
          },
          "any_ip": {},
          "any_asn": {},
          "any_country": {},
          "http_method": {
            "methods": ["POST"],
            "invert_matcher": false
          },
          "domain_matcher": {
            "exact_values": ["jean-paul-sartre.f5xc.support"]
          },
          "path": {
            "prefix_values": ["/login"],
            "exact_values": [],
            "regex_values": [],
            "suffix_values": [],
            "transformers": [],
            "invert_matcher": false
          },
          "headers": []
        }
      }
    ]
  }
}
```
ⓘ "Each rule references a separate rate_limiter shared object with its own threshold."

**C. Rate Limiter Shared Object (referenced by policies)**
```json
{
  "metadata": {
    "name": "rl-advisor-login-{lb_name}",
    "namespace": "{namespace}",
    "description": "5 req/min for POST /login. Based on P95=3, margin 1.5x."
  },
  "spec": {
    "total_number": 5,
    "unit": "MINUTE",
    "burst_multiplier": 1
  }
}
```

### Fields the Tool Reads from Existing LB Config

When the operator selects an LB, we fetch its full config via `GET /api/config/namespaces/{ns}/http_loadbalancers/{name}` and extract:

| Field Path | What We Learn | How We Use It |
|---|---|---|
| `spec.rate_limit.rate_limiter` | Current global rate limit | "Current vs Analyzed" comparison |
| `spec.rate_limit.policies` | Existing rate limiter policies | Show in comparison, avoid conflicts |
| `spec.user_identification` | User ID policy reference | Explain what `user` field in logs represents |
| `spec.domains` | All domains on this LB | Per-domain analysis if multi-domain |
| `spec.routes` | Route → origin pool mapping | Map paths to specific origin pools |
| `spec.app_firewall` | WAF policy reference | Context for security events |
| `spec.trusted_clients` | Users exempt from security | Flag in analysis: "these users bypass rate limiting" |
| `spec.disable_bot_defense` / `spec.bot_defense` | Bot Defense status | If disabled, bot_class in logs may be less reliable |
| `spec.enable_api_discovery` | API Discovery status | If enabled, we might get richer path data |
| `spec.blocked_clients` | Already-blocked users | Cross-reference with our malicious user findings |

---

## 7. UI DESIGN — TRANSPARENCY-FIRST, NO BLACK BOX

The UI is a guided analysis journey, NOT a dashboard. Each section builds on the previous, every number has a "show me why" drill-down, and the operator makes the final decision — not the tool.

### Section 1: Data Collection Report (Always Visible)
Shows: total logs pulled, sampling rates per entry (from `sample_rate` field), estimated actual volume, response classification breakdown (origin 2xx/3xx/4xx/5xx vs F5-blocked using `rsp_code_details`). Every category is expandable with actual counts, top paths, and explanation of why each was included or excluded from baseline.

### Section 2: User Landscape
Shows: user reputation breakdown (CLEAN/BENIGN_BOT/FLAGGED/MALICIOUS), with drill-down tables for each category. Malicious users show WAF block count, attack types, request rate — so operator can verify exclusion is justified. Benign bots show name, type, volume — with note to consider IP allowlist. Top 20 users table with click-through to individual user traffic timelines.

### Section 3: Traffic Patterns
Shows: 7-day RPS timeline (Recharts), day×hour heatmap for peak identification, path distribution with per-path per-user rates. Every chart has inline annotations explaining what the pattern means for rate limiting ("Peak is Tuesday 10am at 118 RPM — your limit must accommodate this").

### Section 4: Distribution Analysis (Full Math Transparency)
Shows: histogram of per-user request rates, percentile table where EVERY row explains what it means ("P95 = 42 means 95% of users stay below 42 req/min"), and each percentile is clickable to show the actual users at that threshold. Mean and standard deviation shown with explanation of what they represent for non-statisticians.

### Section 5: INTERACTIVE IMPACT SIMULATOR (Centerpiece)
The operator drags a slider to set any rate limit value. In real time, the tool replays 7 days of actual traffic against that limit and shows:
- Exact number and percentage of users that would have been rate-limited
- Table of affected users (named, with their peak rate and average rate)
- Timeline of when blocks would have occurred (clustered at peak hours?)
- Which paths see the most blocks
- Burst multiplier slider with spike event overlay

Three algorithm presets (Percentile P95×1.5, Mean+3σ, Peak+20%) are shown as clickable starting points — NOT as recommendations. Each shows the math: "P95=42, margin=1.5x, result=63". The operator can click any preset to move the slider there, then adjust further.

### Section 6: Decision + Config
The operator's chosen value generates: an auto-written rationale paragraph (editable) explaining the decision with data backing, JSON config snippets with copy/download, and an exportable analysis report (CSV of all raw data + PDF summary for customer presentation).

Key principle: The rationale is generated FROM the data the operator already reviewed, not invented. It traces back: "45 req/min was selected because P95=42, with 1.5x margin. At this limit, 154/3,071 users (5%) would have been temporarily rate-limited during peak hours. Burst multiplier of 2x accommodates 67/90 observed spike events."

---

## 8. FILES TO CREATE

```
src/
├── pages/
│   └── RateLimitAdvisor.tsx                    // Main page (~2000 lines)
├── services/
│   └── rate-limit-advisor/
│       ├── index.ts                             // Exports
│       ├── types.ts                             // All TypeScript interfaces
│       ├── log-collector.ts                     // Access log + Security event fetching
│       ├── response-classifier.ts               // 4xx origin detection (F5 vs upstream)
│       ├── user-reputation.ts                   // Security event → reputation scoring
│       ├── traffic-analyzer.ts                  // Bucketing, percentiles, mean/σ, peaks
│       ├── burst-analyzer.ts                    // Burst pattern + multiplier calculation
│       ├── recommendation-engine.ts             // Three algorithms + simulation
│       ├── path-analyzer.ts                     // Path normalization + per-path analysis
│       └── config-generator.ts                  // F5 XC JSON config generation
```

### Changes to Existing Files

| File | Change |
|---|---|
| `src/App.tsx` | Add route: `/rate-limit-advisor` |
| `src/pages/Home.tsx` | Add tool card with featured badge |
| `src/services/api.ts` | Add: `getAccessLogs()`, `scrollAccessLogs()`, `getSecurityEvents()`, `scrollSecurityEvents()`, `getRateLimiters()`, `createRateLimiter()`, `getUserIdentificationPolicies()`, `createUserIdentificationPolicy()`, `getRateLimiterPolicies()`, `createRateLimiterPolicy()` |
| `src/types/index.ts` | Add: AccessLog, SecurityEvent, UserReputation, RateAnalysis, RateRecommendation, RateLimiterConfig interfaces |

---

## 9. DEVELOPMENT PHASES

### Phase 1: Data Collection + Basic Analysis (MVP)
- [ ] Page skeleton with namespace/LB selector
- [ ] Access logs API integration with full scroll pagination
- [ ] Progress tracking UI (log count, elapsed time)
- [ ] Basic per-user rate bucketing (second/minute/hour)
- [ ] Percentile table display
- [ ] Single recommendation card (Percentile approach only)
- [ ] JSON config generation and display

### Phase 2: Security Enrichment + Response Classification
- [ ] Security events API integration (WAF, Bot, Service Policy)
- [ ] Response classifier engine (F5-generated vs origin-generated 4xx)
- [ ] req_id cross-reference index for O(1) security event lookups
- [ ] Upstream timing check (time_to_first_upstream_rx_byte)
- [ ] User reputation scoring engine
- [ ] Traffic segmentation (Clean / All-Legit / Total)
- [ ] Security enrichment tab with threat summary
- [ ] Response origin breakdown panel (F5-blocked vs origin-responded)
- [ ] Toggle for traffic segment in analysis

### Phase 3: Full Algorithm Suite + Visualization
- [ ] All three algorithms (Percentile / Mean+σ / Peak+Buffer)
- [ ] Side-by-side recommendation cards with tuning sliders
- [ ] "Would-have-been-blocked" simulation
- [ ] RPS time-series chart (Recharts)
- [ ] User distribution histogram + CDF
- [ ] Heatmap (day × hour)

### Phase 4: Burst Analysis + Path-Specific
- [ ] Burst multiplier calculation engine
- [ ] Spike pattern detection and visualization
- [ ] Path normalization + grouping
- [ ] Sensitive endpoint detection
- [ ] Rate Limiter Policy generation for per-path rules

### Phase 5: Polish + Config Application
- [ ] Current vs Recommended comparison view
- [ ] Plain-text summary generation
- [ ] Copy-to-clipboard for all configs
- [ ] Response code filter toggles
- [ ] Error handling for API limits/timeouts
- [ ] Sampling factor disclosure + adjustment

---

## 10. VALIDATED FINDINGS FROM REAL SAMPLE DATA (Mar 9, 2026)

Sample data received: 500 access log entries + 500 security events from LB `test` in namespace `ambarish-rb18`, tenant `sdc-support-yqpfidyt`. All findings below are confirmed from real logs.

### ✅ Field Mappings Confirmed

| Field | Value in Real Logs | Implication for Tool |
|---|---|---|
| `user` | `IP-169.254.253.254-JA4TLSFingerprint-t13d091000_f91f431d341e_78e6aca7449b` | Compound identifier (IP + JA4 TLS fingerprint). XC resolves this based on User ID Policy. We use this field directly — no need to compute it. |
| `vh_name` | `ves-io-http-loadbalancer-test` | Format: `ves-io-http-loadbalancer-{lb_name}`. NO namespace suffix. Query filter: `{vh_name="ves-io-http-loadbalancer-{name}"}` |
| `rsp_code_details` | `via_upstream` or `cluster_not_found` | **THE key field for 4xx classification.** `via_upstream` = origin responded. Anything else = F5 XC generated. Simplifies our 3-method detection to a single field check. |
| `sample_rate` | `1` or `0.999` | **PER-ENTRY sampling factor.** We can use `1/sample_rate` as exact extrapolation weight per log entry. No guessing needed. |
| `bot_class` | `suspicious` | Present in ACCESS logs, not just security events. Can classify bots without cross-referencing. |
| `time_to_first_upstream_rx_byte` | `0.105...` or `0` | Confirms: `0` = no upstream response = F5 terminated. Backup signal for `rsp_code_details`. |
| `policy_hits.rate_limiter_action` | `pass` | Shows whether existing rate limiter evaluated this request. Useful for "current config" comparison. |
| `has_sec_event` | `true` / `false` | Quick filter: does this request have a corresponding security event? |
| `@timestamp` | `2026-03-09T08:32:47.254Z` | ISO 8601 format. Use for time bucketing. |
| `req_id` | UUID | Cross-reference key between access logs and security events. 75% match rate in sample (373/500). |

### ✅ Security Event Fields Confirmed

| Field | Value in Real Logs | Usage |
|---|---|---|
| `sec_event_type` | `waf_sec_event` | Event type classifier. Will also see `bot_defense_sec_event`, `svc_policy_sec_event` in production traffic. |
| `action` | `allow` | The ACTUAL action taken (allow/block). Key for determining if request was terminated. |
| `recommended_action` | `report` | WAF's RECOMMENDATION (may differ from action if WAF mode is monitoring). |
| `waf_mode` | `report` | WAF is in reporting/monitoring mode on this LB. |
| `enforcement_mode` | `Blocking` | The WAF policy enforcement mode setting. |
| `bot_info.classification` | `suspicious` | Bot classification from Bot Defense. Values: `suspicious`, `malicious`, `benign`. |
| `rsp_code` in sec events | `0`, `200`, `503` | `rsp_code=0` in security events = request was blocked before any response. `200` = WAF inspected but allowed. |
| `violation_rating` | `1` | Severity indicator for the security event. |

### ✅ 4xx Classification — Simplified

Real data confirms `rsp_code_details` is the definitive field:

```typescript
function isOriginResponse(log: AccessLog): boolean {
  return log.rsp_code_details === 'via_upstream';
}

// Backup check for edge cases
function isF5Generated(log: AccessLog): boolean {
  return log.rsp_code_details !== 'via_upstream'
    || log.rsp_code === '0'
    || (log.time_to_first_upstream_rx_byte === 0 && log.dst === 'NOT-APPLICABLE');
}
```

503s with `cluster_not_found` confirmed: `dst=NOT-APPLICABLE`, `dst_instance=NOT-APPLICABLE`, `time_to_first_upstream_rx_byte=0`. All signals align.

### ✅ Sampling — Precise Per-Entry Extrapolation

```typescript
// Each log entry has its own sampling weight
function getEstimatedCount(log: AccessLog): number {
  return 1 / log.sample_rate;  // sample_rate=1 → weight=1, sample_rate=0.1 → weight=10
}

// Total estimated requests = sum of weights across all entries
const estimatedTotal = logs.reduce((sum, log) => sum + getEstimatedCount(log), 0);
```

### Remaining Item to Validate
- **Rate Limiter API schema**: Need `GET /api/config/namespaces/{ns}/rate_limiters` response to confirm exact create/replace JSON body. Can proceed with development using documented schema and validate when available.

---

## 11. ALGORITHM COMPARISON (ALL THREE SHOWN TO OPERATOR)

These are **starting points**, not recommendations. The operator sees the math behind each and uses the interactive slider to fine-tune.

| Criteria | Percentile (P95/P99) | Mean + N×StdDev | Peak + Buffer |
|---|---|---|---|
| **Protection level** | High | Highest | Lowest |
| **False positive risk** | Low | Medium | Very Low |
| **Handles outliers** | Well (ignores top N%) | Poorly (outliers inflate σ) | Poorly (one spike sets limit) |
| **Handles skewed distributions** | Well | Poorly (assumes normal) | N/A |
| **Intuitive to explain** | Yes ("95% of your users stay below this") | Medium ("average plus 3 times the spread") | Yes ("your busiest user plus 20% headroom") |
| **Best for** | General-purpose APIs | Uniform traffic patterns | Mission-critical apps |
| **Default slider position** | ✓ Yes | | |

The tool explains each algorithm in plain language with the actual numbers from the operator's data. No Greek letters without context — "σ=15 means your users' request rates vary by about 15 requests/min from the average."
