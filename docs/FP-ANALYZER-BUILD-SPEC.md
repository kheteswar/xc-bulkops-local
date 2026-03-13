# FALSE POSITIVE ANALYZER — COMPLETE BUILD SPECIFICATION

## For: Claude Code / Developer building this tool in the xc-app-store repo

---

## TABLE OF CONTENTS
1. Project Context & Reusable Patterns
2. Design Philosophy
3. All False Positive Scenarios (12 Types)
4. The 7 Detection Signals — Complete Logic
5. Composite Scoring Algorithm
6. Analysis Strategy Per Security Control
7. Data Volume Strategy (Streaming Aggregation)
8. API Integration (Endpoints, Fields, Real Samples)
9. TypeScript Interfaces (Complete)
10. Service Layer Implementation (All Modules)
11. Exclusion Rule Generation (Complete Schema)
12. UI Component Specification
13. Files to Create & Modify
14. Development Phases

---

## 1. PROJECT CONTEXT

### Repository & Stack
Same as the Rate Limit Advisor — `xc-app-store` repo, React 18 + TypeScript + Vite + TailwindCSS + Recharts. Dark theme, Lucide icons.

### Reusable Components from Rate Limit Advisor
The following can be shared/imported from `src/services/rate-limit-advisor/`:
- **`log-collector.ts`** — Parallel chunked fetching with scroll pagination, retry logic, progress reporting. The FP Analyzer uses the same collection mechanism but with a different **processing pipeline** (stream-and-aggregate instead of store-all).
- **`types.ts`** — `AccessLogEntry`, `SecurityEventEntry`, `AccessLogQuery`, `SecurityEventQuery`, `CollectionProgress` interfaces are identical.
- **`response-classifier.ts`** — `classifyResponse()` for `rsp_code_details` → origin vs F5.

### Key Differences from Rate Limit Advisor
| Aspect | Rate Limit Advisor | FP Analyzer |
|---|---|---|
| Data volume | 10K-100K logs manageable in memory | Potentially millions — MUST stream-aggregate |
| Primary data | Access logs (with sec events for enrichment) | Security events (with access logs for denominators) |
| Analysis unit | Per-user rates | Per-signature/violation/rule |
| Output | Rate limiter JSON config | WAF exclusion rule JSON |
| User flow | Select LB → Analyze → Slider → Config | Select LB → Select domain → Select control type → Analyze → Review per-signature → Generate exclusions |

---

## 2. DESIGN PHILOSOPHY

Same as Rate Limit Advisor: **transparent analysis workbench, not black box.**

For EVERY signature/violation flagged, the tool must show:
1. **WHY it thinks it's FP or TP** — all 7 signals individually with actual numbers
2. **The evidence** — sample triggering values, client profiles, path distribution
3. **What would happen if excluded** — how many events this exclusion would suppress
4. **The exact exclusion rule** — ready-to-apply JSON that the operator can review before applying

The tool GUIDES, the operator DECIDES. Language: "Highly Likely FP" not "This IS a FP."

---

## 3. ALL FALSE POSITIVE SCENARIOS (12 Types)

The analysis engine must detect and correctly classify all of these:

### SCENARIO 1: Broad Application-Wide FP
**Example:** Signature "windows access" (200010019) triggers on search parameter `q` across `/search`, `/api/search`, `/docs/*` — any path where users type text.
**Detection signals:** HIGH user ratio (>50%) + HIGH request ratio (>50%) + MANY paths (>5)
**Root cause:** Common English word or technology name appears naturally in user input.
**Exclusion:** Signature ID + CONTEXT_PARAMETER + parameter name, with broad path regex or no path restriction.

### SCENARIO 2: Path-Specific Application Logic FP ★ CRITICAL
**Example:** `/admin/sql-console` — a legitimate database query tool. EVERY request to this path contains SQL statements, triggering SQL injection signatures.
**Example:** `/api/content-editor` — CMS endpoint where users paste HTML/CSS, triggering XSS signatures.
**Example:** `/api/xml-import` — XML processing endpoint triggering XXE signatures.
**Example:** `/callback?token=base64...` — OAuth callback with encoded tokens triggering encoding signatures.
**Example:** `/api/upload` — File upload endpoint where binary data triggers file include signatures.
**Detection signals:** LOW user count (maybe 5-20 admin users) BUT HIGH request ratio on specific path (>80%). Few paths affected (1-3). Users have legitimate profiles (real browsers, high trust).
**Critical additional signal:** Check `rsp_code` in the access log for the SAME request. If the request got `rsp_code=200` from origin (via_upstream), the APPLICATION ACCEPTED the input — strong FP signal. The app was designed to receive this input.
**Root cause:** The application's business logic requires input that happens to match attack signatures.
**Exclusion:** Signature ID + context + context_name, scoped to the specific path.
**IMPORTANT:** This scenario looks SIMILAR to a targeted attack (few users, specific paths) but the key differentiator is the REQUEST RATIO on the path. If 95% of ALL requests to `/admin/sql-console` trigger SQL injection sigs, it's the path's function, not attacks. If only 3% trigger it, specific users are injecting malicious SQL.

### SCENARIO 3: Cookie/Session FP
**Example:** Session cookie `JSESSIONID` or `.ASPXANONYMOUS` contains base64/encoded data that matches signatures.
**Detection signals:** Context is `"cookie (name)"` + signature triggers for ALL users on ALL paths (because the cookie is sent with every request).
**Root cause:** App-generated cookies contain encoded data. Users don't control cookie content.
**Exclusion:** Signature ID + CONTEXT_COOKIE + cookie name. Usually no path restriction needed (applies globally).
**Special FP indicator:** If the SAME signature + SAME context triggers across >80% of ALL paths, it's almost certainly a cookie/session FP.

### SCENARIO 4: Header-Based FP
**Example:** Custom app header `X-Auth-Token` contains JWT that triggers encoding signatures.
**Example:** `Authorization: Bearer <JWT>` header triggers base64 signatures.
**Detection signals:** Context is `"header (name)"` + high user ratio.
**Root cause:** Application uses custom headers with structured/encoded data.
**Exclusion:** Signature ID + CONTEXT_HEADER + header name.
**Exception:** `User-Agent` header IS user-controlled. Signatures matching UA patterns need separate investigation.

### SCENARIO 5: WAF in Monitoring Mode — 200 OK in Security Event
**Example:** WAF detects attack pattern, logs security event with `recommended_action: "report"`, but `rsp_code=200` because WAF didn't block (monitoring mode).
**Analysis complexity:** The 200 means the request reached origin and was accepted. Two possibilities:
  - a) The attack payload was in the request but the app wasn't vulnerable (attack failed) — this is TP (the sig correctly detected the attack, even though the app wasn't harmed)
  - b) The "attack payload" is actually normal app input — this is FP
**How to distinguish:** Check user breadth. If many normal users trigger it → (b) FP. If only suspicious IPs trigger it → (a) TP.

### SCENARIO 6: Single-Source Targeted Attack (TP)
**Example:** One IP sends 500 requests to `/login` with different SQL injection payloads in the `username` parameter.
**Detection signals:** LOW user count (1-3 IPs) + LOW request ratio (<5%) + HIGH violation_rating (3-5) + attack payloads visible in `matching_info` + scripting tool user agent.
**Root cause:** Actual attack or vulnerability scan.
**Action:** Keep blocking. Flag as confirmed TP.

### SCENARIO 7: Automated Vulnerability Scanner (TP)
**Example:** Same IP hits `/index.php`, `/wp-admin`, `/phpmyadmin`, `/etc/passwd`, `/shell.php` in rapid succession with different exploit payloads.
**Detection signals:** Single user hitting MANY different paths with DIFFERENT attack payloads. User agent = scripting tool. Paths include known exploit paths that don't exist in the real app.
**Root cause:** Automated scanner testing for known vulnerabilities.
**Action:** Keep blocking. These are textbook TP.
**Additional signal:** Check if the paths actually exist in the app (do they return 404 from origin?). If the app returns 404 for these paths, the attacker is probing non-existent endpoints.

### SCENARIO 8: Benign Bot Being Flagged
**Example:** Bingbot (UA `compatible; bingbot/2.0`) crawling `/Portals/0/uploads/ThePioneer159English.pdf` triggers file include signatures because the URL contains "Portals" and file paths.
**Detection signals:** `user_agent` contains known bot identifier + `bot_info.classification = "benign"` (if Bot Defense is enabled) + browsing pattern is sequential crawling.
**Root cause:** Bot accessing legitimate content whose URL structure happens to match attack patterns.
**Exclusion:** `exclude_bot_name_contexts` with the bot name, OR trusted client entry with `SKIP_PROCESSING_WAF`.
**IMPORTANT:** The ThreatMesh sample shows exactly this: Bingbot IP `207.46.13.87` flagged by Threat Mesh with 1,258 events across 2 tenants, but it's a real Microsoft bot.

### SCENARIO 9: IP Reputation / Geo FP
**Example:** Corporate VPN exit IP flagged as `PROXY` category. Trust score = 15, but users behind it are legitimate employees.
**Detection signals:** `ip_threat_categories = "PROXY"` but user agents are real browsers + browsing pattern is normal (multiple pages, sessions, form submissions).
**Root cause:** Shared/proxy IPs get flagged based on other users' behavior.
**Exclusion:** IP allowlist in service policy, or trusted client entry.

### SCENARIO 10: Low-Accuracy Signature on Benign Content
**Example:** Signature with `accuracy: "low_accuracy"` matching the word "select" in a dropdown menu's form parameter.
**Detection signals:** `accuracy = "low_accuracy"` + high user ratio + `matching_info` shows common word/pattern.
**Root cause:** Low-accuracy signatures cast a wide net and match benign content.
**Exclusion:** Signature ID + context + context_name.
**Note:** High-accuracy signatures with AI confirmation (`req_risk_reasons` contains "AI has confirmed") are much less likely to be FP.

### SCENARIO 11: Form Submission FP
**Example:** POST `/contact-us` where the `message` body field contains "I got an SQL error when..." — triggers SQL injection sig.
**Example:** POST `/support/ticket` with `description` containing `<script>` tags because user is describing a frontend bug.
**Detection signals:** POST method + form-type content + user ratio is moderate (some users describe technical issues) + context is body/parameter.
**Root cause:** User-submitted free text naturally contains technical terms.
**Exclusion:** Signature ID + CONTEXT_PARAMETER + parameter name (e.g., "message", "description") scoped to the form path.

### SCENARIO 12: API JSON Payload FP
**Example:** POST `/api/config` accepting JSON payloads that contain code snippets, file paths, or SQL queries as part of the application's function.
**Detection signals:** Method = POST + content-type = application/json + API-style path + high request ratio.
**Root cause:** APIs processing structured data that includes patterns matching attack signatures.
**Exclusion:** Signature ID + CONTEXT_BODY, scoped to the API path.

---

## 4. THE 7 DETECTION SIGNALS — COMPLETE LOGIC

For EVERY unique (signature_id + context + path) combination, compute all 7 signals:

### Signal 1: User Breadth (Weight: 25%)

```typescript
// For a specific signature on a specific path:
const flaggedUsers = uniqueUsersWhoTriggeredThisSigOnThisPath;
const totalUsers = totalUniqueUsersWhoAccessedThisPath; // from access logs

const userRatio = flaggedUsers / totalUsers;

// Score (0 = strong TP, 100 = strong FP):
function scoreUserBreadth(userRatio: number, flaggedUsers: number): number {
  if (flaggedUsers <= 2) return 5;           // Only 1-2 users → strong TP
  if (userRatio > 0.80) return 95;           // >80% of users → very strong FP
  if (userRatio > 0.50) return 80;           // >50% → strong FP
  if (userRatio > 0.30) return 60;           // >30% → moderate FP
  if (userRatio > 0.10) return 40;           // >10% → ambiguous
  if (userRatio > 0.05) return 25;           // 5-10% → lean TP
  return 10;                                  // <5% → strong TP
}
```

### Signal 2: Request Breadth (Weight: 25%)

```typescript
// For a specific signature on a specific path:
const flaggedRequests = requestsTriggeredByThisSigOnThisPath;
const totalRequests = totalRequestsToThisPath; // from access logs

const requestRatio = flaggedRequests / totalRequests;

function scoreRequestBreadth(requestRatio: number): number {
  if (requestRatio > 0.90) return 95;        // >90% → very strong FP (almost every request)
  if (requestRatio > 0.70) return 85;        // >70% → strong FP
  if (requestRatio > 0.50) return 70;        // >50% → moderate FP
  if (requestRatio > 0.30) return 55;        // >30% → lean FP
  if (requestRatio > 0.10) return 35;        // 10-30% → ambiguous
  if (requestRatio > 0.05) return 20;        // 5-10% → lean TP
  return 10;                                  // <5% → strong TP
}
```

### Signal 3: Path Breadth (Weight: 10%)

```typescript
// How many different paths trigger this same signature?
const pathCount = uniquePathsWhereSigTriggered;

function scorePathBreadth(pathCount: number, totalAppPaths: number): number {
  const pathRatio = pathCount / totalAppPaths;
  if (pathRatio > 0.50) return 95;           // >50% of all paths → definitely FP
  if (pathCount > 20) return 85;             // Many paths → strong FP
  if (pathCount > 10) return 70;             // Moderate paths → lean FP
  if (pathCount > 5) return 50;              // Several paths → ambiguous
  if (pathCount > 2) return 30;              // Few paths → lean TP (but check Scenario 2)
  return 15;                                  // 1-2 paths → investigate deeper
}

// EXCEPTION: If pathCount is low (1-3) but requestRatio is >80% on those paths,
// this is Scenario 2 (path-specific application logic FP), NOT TP.
// The path breadth score should be OVERRIDDEN upward in this case.
```

### Signal 4: Context Analysis (Weight: 10%)

```typescript
interface ContextScore {
  score: number;        // 0-100 FP likelihood
  reason: string;       // Human-readable explanation
}

function scoreContext(context: string, contextName: string, signatureName: string): ContextScore {
  const ctx = context.toLowerCase();
  
  // Cookies are almost always FP (app-generated, not user-controlled)
  if (ctx.includes('cookie')) {
    return { score: 90, reason: `Cookie "${contextName}" is app-generated. Users don't control cookie content.` };
  }
  
  // Custom headers are usually FP (app-set headers)
  if (ctx.includes('header')) {
    if (/user-agent/i.test(contextName)) {
      return { score: 30, reason: 'User-Agent is client-controlled. Investigate further.' };
    }
    if (/authorization|auth|token|x-/i.test(contextName)) {
      return { score: 85, reason: `Header "${contextName}" is likely app-generated (auth/token header).` };
    }
    return { score: 60, reason: `Custom header "${contextName}" — check if app-generated or user-controlled.` };
  }
  
  // URL/path context
  if (ctx.includes('url') || ctx.includes('uri')) {
    return { score: 40, reason: 'URL pattern match — could be legitimate path structure or attack path.' };
  }
  
  // Request body — depends on content type
  if (ctx.includes('body')) {
    return { score: 50, reason: 'Request body match — check if the endpoint accepts user-controlled body data.' };
  }
  
  // Parameters — the most nuanced case
  if (ctx.includes('parameter')) {
    // Known safe parameter names (search, query, filter)
    if (/^(q|query|search|filter|keyword|term|s)$/i.test(contextName)) {
      return { score: 75, reason: `Parameter "${contextName}" is a search/filter field — likely contains user text that triggers signatures.` };
    }
    // Known sensitive parameter names (should have attack patterns)
    if (/^(cmd|exec|command|eval|system|shell|code)$/i.test(contextName)) {
      return { score: 15, reason: `Parameter "${contextName}" has a dangerous name — likely a real attack vector.` };
    }
    return { score: 45, reason: `Parameter "${contextName}" — investigate what data this field normally contains.` };
  }
  
  return { score: 50, reason: 'Unknown context — manual investigation needed.' };
}
```

### Signal 5: Client Profile (Weight: 10%)

```typescript
function scoreClientProfile(
  flaggedUserAgents: Map<string, number>,      // UA → count
  flaggedCountries: Map<string, number>,       // country → count
  flaggedTrustScores: number[],                // IP trust scores of flagged clients
  normalUserAgents: Map<string, number>,       // UA distribution of ALL users on this path
  normalCountries: Map<string, number>,        // Country distribution of ALL users
  botClassifications: Map<string, number>      // bot_class → count
): { score: number; reason: string } {
  
  let score = 50; // neutral starting point
  const reasons: string[] = [];
  
  // Check if flagged clients use real browsers
  const browserUAs = [...flaggedUserAgents.entries()]
    .filter(([ua]) => /Chrome|Firefox|Safari|Edge|Opera/i.test(ua) && !/bot|spider|crawler/i.test(ua));
  const browserPct = browserUAs.reduce((s, [,c]) => s + c, 0) / 
    [...flaggedUserAgents.values()].reduce((s, c) => s + c, 1);
  
  if (browserPct > 0.80) {
    score += 20;
    reasons.push(`${(browserPct * 100).toFixed(0)}% of flagged clients use real browsers`);
  } else if (browserPct < 0.20) {
    score -= 25;
    reasons.push(`Only ${(browserPct * 100).toFixed(0)}% real browsers — mostly scripting tools`);
  }
  
  // Check bot classifications
  const maliciousBots = botClassifications.get('malicious') || 0;
  const totalBotFlags = [...botClassifications.values()].reduce((s, c) => s + c, 0);
  if (maliciousBots > 0 && maliciousBots / totalBotFlags > 0.5) {
    score -= 30;
    reasons.push(`${maliciousBots} flagged as malicious bots`);
  }
  
  // Check IP trust scores
  const avgTrust = flaggedTrustScores.length > 0
    ? flaggedTrustScores.reduce((a, b) => a + b, 0) / flaggedTrustScores.length
    : 50;
  if (avgTrust > 70) {
    score += 15;
    reasons.push(`Average IP trust: ${avgTrust.toFixed(0)} (high trust)`);
  } else if (avgTrust < 30) {
    score -= 20;
    reasons.push(`Average IP trust: ${avgTrust.toFixed(0)} (low trust)`);
  }
  
  // Check if flagged geo matches normal geo
  // (simplified: check if top country is same in both sets)
  const topFlaggedCountry = [...flaggedCountries.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
  const topNormalCountry = [...normalCountries.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
  if (topFlaggedCountry === topNormalCountry) {
    score += 5;
    reasons.push('Geo distribution matches normal traffic');
  }
  
  return { score: Math.max(0, Math.min(100, score)), reason: reasons.join('. ') || 'No strong client signals.' };
}
```

### Signal 6: Temporal Pattern (Weight: 10%)

```typescript
function scoreTemporalPattern(
  flaggedTimestamps: string[],    // timestamps of flagged events
  normalTimestamps: string[],     // timestamps of all requests to this path
): { score: number; reason: string } {
  
  if (flaggedTimestamps.length < 5) {
    return { score: 50, reason: 'Too few events for temporal analysis.' };
  }
  
  // Bucket into hours
  const flaggedHours = new Map<number, number>();
  const normalHours = new Map<number, number>();
  
  for (const ts of flaggedTimestamps) {
    const h = new Date(ts).getUTCHours();
    flaggedHours.set(h, (flaggedHours.get(h) || 0) + 1);
  }
  for (const ts of normalTimestamps) {
    const h = new Date(ts).getUTCHours();
    normalHours.set(h, (normalHours.get(h) || 0) + 1);
  }
  
  // Check if flagged pattern matches normal business hours pattern
  // Correlation between hour distributions
  let correlation = 0;
  const hours = Array.from({ length: 24 }, (_, i) => i);
  const flaggedVals = hours.map(h => (flaggedHours.get(h) || 0) / flaggedTimestamps.length);
  const normalVals = hours.map(h => (normalHours.get(h) || 0) / normalTimestamps.length);
  
  // Simple correlation: if distributions look similar → FP
  const diff = flaggedVals.reduce((sum, v, i) => sum + Math.abs(v - normalVals[i]), 0);
  
  if (diff < 0.3) {
    return { score: 80, reason: 'Flagged events follow normal traffic pattern — constant, not attack-like.' };
  } else if (diff < 0.6) {
    return { score: 55, reason: 'Flagged events partially match normal pattern.' };
  } else {
    return { score: 20, reason: 'Flagged events cluster at unusual times — possible attack campaign.' };
  }
}
```

### Signal 7: Signature Accuracy + AI Confirmation (Weight: 10%)

```typescript
function scoreSignatureAccuracy(
  accuracy: string,                    // "high_accuracy", "medium_accuracy", "low_accuracy"
  reqRiskReasons: string[],            // from req_risk_reasons array
  violationRating: number,             // 1-5
  state: string                        // "Enabled" or "AutoSuppressed"
): { score: number; reason: string } {
  
  let score = 50;
  const reasons: string[] = [];
  
  // AI confirmation is the strongest signal
  const aiConfirmed = reqRiskReasons.some(r => /AI.*confirm.*100%/i.test(r));
  if (aiConfirmed) {
    score -= 40;
    reasons.push('F5 AI confirmed 100% accurate detection — very unlikely FP');
  }
  
  // AutoSuppressed means F5's ML already thinks it's FP
  if (state === 'AutoSuppressed') {
    score += 30;
    reasons.push('F5 ML auto-suppressed this signature — F5 itself thinks it\'s FP');
  }
  
  // Accuracy level
  if (accuracy === 'high_accuracy') {
    score -= 15;
    reasons.push('High accuracy signature — precise matching, less likely FP');
  } else if (accuracy === 'low_accuracy') {
    score += 20;
    reasons.push('Low accuracy signature — broad matching, more likely FP');
  }
  
  // Violation rating (1=low severity, 5=high severity)
  if (violationRating >= 4) {
    score -= 15;
    reasons.push(`High violation rating (${violationRating}/5) — confident detection`);
  } else if (violationRating <= 2) {
    score += 10;
    reasons.push(`Low violation rating (${violationRating}/5) — less confident`);
  }
  
  return { score: Math.max(0, Math.min(100, score)), reason: reasons.join('. ') };
}
```

### Signal Combination — Scenario 2 Override

```typescript
// CRITICAL: After computing all 7 signals, check for Scenario 2 (path-specific app logic FP)
function applyScenario2Override(
  signals: SignalResult,
  requestRatioOnPath: number,
  userCountOnPath: number,
  pathCount: number,
  originResponseCode: string          // most common rsp_code for these requests
): SignalResult {
  
  // Scenario 2 detection: Few paths (1-3) + HIGH request ratio + app accepted the request
  if (
    pathCount <= 3 &&
    requestRatioOnPath > 0.80 &&       // >80% of requests to this path trigger the sig
    userCountOnPath <= 30              // Not a mass-traffic path
  ) {
    // This looks like an application-logic FP
    // Path breadth signal would normally score LOW (few paths → TP),
    // but in this case, the HIGH request ratio means the path's FUNCTION triggers the sig
    
    let fpBoost = 0;
    const reasons: string[] = [];
    
    // If origin returned 200 for these requests, the app ACCEPTED the input
    if (originResponseCode === '200') {
      fpBoost += 25;
      reasons.push(`Origin returned 200 OK for flagged requests — app accepted this input as valid.`);
    }
    
    // The request ratio itself is a strong signal
    fpBoost += 20;
    reasons.push(`${(requestRatioOnPath * 100).toFixed(0)}% of ALL requests to this path trigger this signature — this is the path\'s normal function.`);
    
    signals.compositeScore = Math.min(100, signals.compositeScore + fpBoost);
    signals.overrideApplied = 'SCENARIO_2_PATH_SPECIFIC_FP';
    signals.overrideReason = reasons.join(' ');
  }
  
  return signals;
}
```

---

## 5. COMPOSITE SCORING

```typescript
interface SignalResult {
  userBreadth: { score: number; raw: number; reason: string };
  requestBreadth: { score: number; raw: number; reason: string };
  pathBreadth: { score: number; raw: number; reason: string };
  contextAnalysis: { score: number; reason: string };
  clientProfile: { score: number; reason: string };
  temporalPattern: { score: number; reason: string };
  signatureAccuracy: { score: number; reason: string };
  compositeScore: number;
  verdict: 'highly_likely_fp' | 'likely_fp' | 'ambiguous' | 'likely_tp' | 'confirmed_tp';
  overrideApplied?: string;
  overrideReason?: string;
}

function computeCompositeScore(signals: Omit<SignalResult, 'compositeScore' | 'verdict'>): SignalResult {
  const composite = Math.round(
    signals.userBreadth.score * 0.25 +
    signals.requestBreadth.score * 0.25 +
    signals.pathBreadth.score * 0.10 +
    signals.contextAnalysis.score * 0.10 +
    signals.clientProfile.score * 0.10 +
    signals.temporalPattern.score * 0.10 +
    signals.signatureAccuracy.score * 0.10
  );
  
  let verdict: SignalResult['verdict'];
  if (composite > 75) verdict = 'highly_likely_fp';
  else if (composite > 55) verdict = 'likely_fp';
  else if (composite > 35) verdict = 'ambiguous';
  else if (composite > 15) verdict = 'likely_tp';
  else verdict = 'confirmed_tp';
  
  return { ...signals, compositeScore: composite, verdict };
}
```

---

## 6. ANALYSIS STRATEGY PER SECURITY CONTROL

### WAF Signatures (sec_event_type: "waf_sec_event", has `signatures[]` array)

```
PRIMARY GROUPING: By signature_id
  For each unique signature:
    SECONDARY GROUPING: By (path + context + context_name)
      This creates analysis units like:
        "Sig 200010019 on parameter 'q' at /search"
        "Sig 200010019 on url at /docs/*"
        "Sig 200003669 on cookie 'dtSa' at /eiris/login"
      
      For each unit, compute all 7 signals.

PATH GROUPING OPTIMIZATION:
  If a signature triggers on >50 unique paths with SAME context:
    → Group into "Application-Wide" bucket
    → Show top 10 paths + aggregate stats
    → Score using aggregate user/request ratios
  
  If a signature triggers on 5-50 paths:
    → Show each path individually with its own signals
    
  If a signature triggers on 1-3 paths:
    → Deep detail per path
    → Apply Scenario 2 check (path-specific app logic FP)

MULTIPLE SIGNATURES PER EVENT:
  One security event can contain multiple signatures[].
  Analyze each signature INDEPENDENTLY.
  But when generating exclusion rules, GROUP signatures that share
  the same path + context into a single exclusion rule.
```

### WAF Violations (sec_event_type: "waf_sec_event", has `violations[]` array)

```
PRIMARY GROUPING: By violation name (e.g., VIOL_JSON_MALFORMED)
  SECONDARY GROUPING: By path

Violations are protocol-level, so the detection logic differs:
  
  ALWAYS TP VIOLATIONS (don't suggest excluding these):
    VIOL_EVASION_DIRECTORY_TRAVERSALS
    VIOL_EVASION_BAD_UNESCAPE
    VIOL_EVASION_MULTIPLE_DECODING
    VIOL_ATTACK_SIGNATURE   (this is a meta-violation, actual sig matters)
  
  OFTEN FP VIOLATIONS (investigate deeply):
    VIOL_JSON_MALFORMED      → App sends non-standard JSON (common with APIs)
    VIOL_XML_MALFORMED       → App sends non-standard XML
    VIOL_HTTP_PROTOCOL_*     → App uses non-standard HTTP (websockets, chunked)
    VIOL_PARAMETER_*         → App uses unusual parameter formats
    VIOL_URL_LENGTH          → App has long URLs (SPAs with encoded state)
    VIOL_HEADER_LENGTH       → App sends large headers (JWTs, cookies)
    VIOL_POST_DATA_LENGTH    → App accepts large form submissions
    VIOL_REQUEST_MAX_LENGTH  → Large requests (file uploads)
    VIOL_COOKIE_LENGTH       → Large cookies (session data)
  
  Compute same 7 signals, but replace "signature accuracy" with
  "violation severity" based on the above classification.
```

### Threat Mesh (sec_event_name: "Threat Mesh")

```
PRIMARY GROUPING: By source IP (each Threat Mesh event is about a specific IP)

For each flagged IP, the analysis combines:
  A) Threat Mesh intelligence (from threat_mesh_details):
     - attack_types: what attacks this IP was involved in globally
     - events: total events across F5 network
     - tenant_count: how many OTHER tenants flagged this IP
     - high_accuracy_signatures: how many high-confidence detections
     - malicious_bot_events: bot-related events
  
  B) This IP's ACTUAL behavior on THIS app (from access logs):
     - What paths did they access?
     - What user agent did they use?
     - How many total requests?
     - Were their requests normal browsing or targeted probing?
     - Did they trigger ANY WAF events (separate from Threat Mesh)?
     - What was the response code distribution?

FP SCORING for Threat Mesh:
  Compute a custom score instead of the standard 7 signals:
  
  STRONG TP SIGNALS (lower FP score):
    - tenant_count >= 5 (many other customers saw this IP)
    - events >= 1000 (high volume of attacks)
    - high_accuracy_signatures > 0 (confident detections elsewhere)
    - IP also triggered WAF events on THIS app
    - User agent is scripting tool
    - Browsing pattern: hitting exploit paths (/wp-admin, /phpmyadmin, etc.)
  
  STRONG FP SIGNALS (higher FP score):
    - User agent is known search engine bot (Bingbot, Googlebot)
    - IP is from known CDN/proxy provider (Cloudflare, Akamai, Google Cloud)
    - Browsing pattern: sequential page crawling, hitting real content paths
    - No WAF events on THIS app (only Threat Mesh flagged them)
    - Low tenant_count (1-2) — maybe a shared IP issue
```

### Service Policy / L7 Policy (sec_event_type: "svc_policy_sec_event")

```
PRIMARY GROUPING: By (policy_name + policy_rule)

For each rule, analyze:
  - Total requests blocked by this rule
  - IP reputation categories of blocked clients (PROXY, BOTNETS, etc.)
  - Client profiles of blocked users vs. allowed users
  
SPECIFIC ANALYSIS for IP Reputation Rules:
  For each ip_threat_category (PROXY, SCANNERS, BOTNETS, etc.):
    - How many IPs blocked?
    - What's their browsing behavior on this app?
    - Do they use real browsers or scripting tools?
    - What's their IP trust score distribution?
    
  PROXY category is the most FP-prone:
    Corporate VPNs, legitimate proxy services, and CDNs get categorized as PROXY.
    If blocked PROXY IPs have:
      - Real browser user agents (Chrome, Firefox, Safari)
      - IP trust score > 40
      - Normal browsing patterns (multiple pages, form submissions)
    → Likely FP for those specific IPs
    
  BOTNETS, SCANNERS, WEB_ATTACKS categories are usually TP.
```

---

## 7. DATA VOLUME STRATEGY (Streaming Aggregation for Millions of Logs)

### Memory Architecture

```
PHASE 1: Fetch ALL security events (smaller dataset, fully in memory)
  Expected: 10K-200K events for 7-14 days
  Memory: ~50-200MB
  
  Build these in-memory indexes:
  
  signatureIndex: Map<signature_id, {
    name: string,
    accuracy: string,
    attackType: string,
    contexts: Map<contextKey, {                // contextKey = "path|context|contextName"
      path: string,
      context: string,
      contextName: string,
      eventCount: number,
      uniqueUsers: Set<string>,
      uniqueIPs: Set<string>,
      userAgents: Map<string, number>,
      countries: Map<string, number>,
      trustScores: number[],
      botClassifications: Map<string, number>,
      methods: Map<string, number>,
      sampleMatchingInfo: string[],           // first 10 matching_info strings
      sampleReqParams: string[],              // first 10 req_params values  
      timestamps: string[],                    // all timestamps (for temporal analysis)
      rspCodes: Map<string, number>,           // rsp_code distribution
      violationRatings: number[],
      reqRiskReasons: string[],                // all unique risk reasons
      aiConfirmed: boolean,
    }>
  }>
  
  violationIndex: Map<violation_name, { similar structure }>
  
  threatMeshIndex: Map<src_ip, { 
    threatDetails: ThreatMeshDetails,
    eventCount: number,
    paths: Map<string, number>,
    userAgents: Map<string, number>,
    timestamps: string[],
  }>
  
  policyIndex: Map<policy_rule, {
    policy: string,
    eventCount: number,
    blockedIPs: Map<string, { count, ua, trustScore, threatCategories }>,
  }>
  
  reqIdSet: Set<string>   // ALL req_ids from security events (for access log cross-reference)

PHASE 2: Stream access logs in chunks, aggregate on the fly
  For EACH chunk of 500 access logs:
    For each log entry:
      1. Increment pathStats[path].totalRequests
      2. Add user to pathStats[path].totalUsers (use Set or HyperLogLog)
      3. If req_id is in reqIdSet → increment pathStats[path].flaggedRequests
      4. Track pathStats[path].normalUserAgents, normalCountries, normalTimestamps
      5. Track pathStats[path].rspCodeDistribution
      6. DO NOT store the full log entry
  
  After all chunks processed:
    pathStats: Map<normalizedPath, {
      totalRequests: number,
      totalUsers: number,                      // approximate unique count
      flaggedRequests: number,                 // requests that also appear in security events
      flaggedUsers: number,
      normalUserAgents: Map<string, number>,
      normalCountries: Map<string, number>,
      normalTimestamps: string[],              // sampled — keep every Nth for temporal analysis
      rspCodes: Map<string, number>,
      methods: Map<string, number>,
    }>

PHASE 3: Compute signals
  For each signature context unit:
    Merge signatureIndex data with pathStats data
    Compute all 7 signals
    Apply Scenario 2 override check
    Generate composite score + verdict

MEMORY BUDGET:
  Security events index: ~200MB max
  Path stats (streaming result): ~5MB for 10K paths
  Signal results: ~1MB for 500 signatures
  Total: ~210MB regardless of access log volume
```

### Unique User Counting at Scale

For paths with millions of requests, maintaining a `Set<string>` of all user IDs consumes significant memory. Use approximate counting:

```typescript
// Simple approach: if unique users < 10,000, use exact Set
// If more, switch to a probabilistic counter (HyperLogLog-like)
// For this tool, exact Set is fine for most paths — few paths have >10K unique users

class UserCounter {
  private exact: Set<string> | null = new Set();
  private approximate = 0;
  private readonly THRESHOLD = 10000;
  
  add(userId: string) {
    if (this.exact) {
      this.exact.add(userId);
      if (this.exact.size > this.THRESHOLD) {
        this.approximate = this.exact.size;
        this.exact = null; // free memory
      }
    } else {
      // Simple probabilistic estimate: hash and sample
      this.approximate++;
    }
  }
  
  get count(): number {
    return this.exact ? this.exact.size : this.approximate;
  }
}
```

### Progress UX

```
┌─────────────────────────────────────────────────────────────────┐
│  Phase 1: Security Events  ████████████████████████████████ 100% │
│  → 12,847 events loaded                                         │
│  → 247 unique signatures · 34 violations · 89 Threat Mesh IPs  │
│                                                                   │
│  Phase 2: Access Logs      ██████████████░░░░░░░░░░░░░░░░  45%  │
│  → 892,340 of ~2,000,000 logs streamed                          │
│  → 3,241 unique paths aggregated                                │
│  → Estimated: ~3 minutes remaining                               │
│                                                                   │
│  Phase 3: Analysis         ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0%   │
│  → Waiting for access log streaming to complete                  │
│                                                                   │
│  ℹ Logs are processed in streaming mode — only aggregate         │
│    statistics are kept in memory.                                │
└─────────────────────────────────────────────────────────────────┘
```

---

## 8. API INTEGRATION

### Security Events API
```
POST /api/data/namespaces/{ns}/app_security/events
Body: {
  "query": "{vh_name=\"ves-io-http-loadbalancer-{lb_name}\"}",
  "namespace": "{ns}",
  "start_time": "2026-03-02T00:00:00.000Z",
  "end_time": "2026-03-09T00:00:00.000Z",
  "scroll": true,
  "limit": 500
}
Scroll: POST /api/data/namespaces/{ns}/app_security/events/scroll
```

### Key Security Event Fields (from real samples)

**WAF Signature Event:**
```json
{
  "sec_event_type": "waf_sec_event",
  "sec_event_name": "WAF",
  "action": "block",
  "recommended_action": "block",
  "waf_mode": "block",
  "enforcement_mode": "Blocking",
  "app_firewall_name": "prd-example-domain-qa-app-waf",
  "violation_rating": "3",
  "req_risk": "high",
  "req_risk_reasons": ["The AI has confirmed that the detected attack signature 200022013 provides 100% accurate detection"],
  "signatures": [
    {
      "id": "200022013",
      "name": "PHP remote file include attempt - filter",
      "attack_type": "ATTACK_TYPE_REMOTE_FILE_INCLUDE",
      "accuracy": "high_accuracy",
      "risk": "Medium",
      "context": "parameter (input_file)",
      "matching_info": "Matched 12 characters on offset 11 against value: 'input_file=php://filter/resource=/etc/passwd'.",
      "state": "Enabled"
    }
  ],
  "violations": [
    {
      "name": "VIOL_HTTP_PROTOCOL_NULL_IN_REQUEST",
      "attack_type": "ATTACK_TYPE_HTTP_PARSER_ATTACK",
      "state": "Enabled"
    }
  ],
  "attack_types": [{ "name": "ATTACK_TYPE_REMOTE_FILE_INCLUDE" }],
  "req_params": "input_file=php://filter/resource=/etc/passwd",
  "bot_info": { "classification": "suspicious", "anomaly": "Suspicious HTTP Headers", "name": "UNKNOWN", "type": "UNKNOWN" },
  "src_ip": "1.1.1.1",
  "user": "IP-34.55.156.54-JA4TLSFingerprint-...",
  "user_agent": "Mozilla/5.0 ...",
  "req_path": "/plugins/buddypress-component-stats/lib/dompdf/dompdf.php",
  "method": "GET",
  "domain": "www.example-domain.qa",
  "rsp_code": "200",
  "rsp_code_class": "2xx",
  "country": "US",
  "as_org": "google llc",
  "req_id": "e8f3daa0-9626-4f21-aab1-c2b89615ab70"
}
```

**Threat Mesh Event:**
```json
{
  "sec_event_type": "svc_policy_sec_event",
  "sec_event_name": "Threat Mesh",
  "action": "block",
  "threat_mesh_details": {
    "description": "IP (207.46.13.87) has triggered attack_type ATTACK_TYPE_ABUSE_OF_FUNCTIONALITY and 3 other attack_types",
    "attack_types": ["ATTACK_TYPE_ABUSE_OF_FUNCTIONALITY", "ATTACK_TYPE_OTHER_APPLICATION_ATTACKS", "ATTACK_TYPE_PATH_TRAVERSAL", "ATTACK_TYPE_MALICIOUS_FILE_UPLOAD"],
    "events": 1258,
    "tenant_count": 2,
    "high_accuracy_signatures": 2,
    "tls_count": 11,
    "malicious_bot_events": 0
  },
  "policy_hits": { "policy_hits": [{ "result": "block", "policy_set": "threat_mesh" }] },
  "user_agent": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
  "src_ip": "207.46.13.87",
  "req_path": "/Portals/0/DNNGalleryPro/uploads/2024/3/18/ThePioneer159English.pdf"
}
```

**L7 Policy / Service Policy Event:**
```json
{
  "sec_event_type": "svc_policy_sec_event",
  "sec_event_name": "L7 Policy Violation",
  "action": "block",
  "policy_hits": {
    "policy_hits": [{
      "result": "deny",
      "ip_threat_categories": "PROXY",
      "ip_trustscore": "15",
      "ip_trustworthiness": "LOW",
      "ip_risk": "HIGH_RISK",
      "policy": "ves-io-http-loadbalancer-ip-reputation-www-example-domain-qa",
      "policy_rule": "ves-io-service-policy-ves-io-http-loadbalancer-ip-reputation-www-example-domain-qa-ip-threat-rule",
      "policy_namespace": "default"
    }]
  },
  "rsp_code_details": "ext_authz_denied",
  "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
}
```

**Malicious User Mitigation Event:**
```json
{
  "sec_event_name": "Malicious User Mitigation",
  "message": "MUM_BLOCK_TEMPORARILY",
  "policy_hits": {
    "policy_hits": [{
      "malicious_user_mitigate_action": "MUM_BLOCK_TEMPORARILY"
    }]
  }
}
```

### Access Logs API (same as Rate Limit Advisor)
```
POST /api/data/namespaces/{ns}/access_logs
Scroll: POST /api/data/namespaces/{ns}/access_logs/scroll
```

Key access log fields for FP analysis:
- `req_id` — cross-reference with security events
- `req_path`, `method`, `domain` — path/method matching
- `user`, `src_ip` — user counting
- `user_agent` — client profiling
- `rsp_code`, `rsp_code_details` — did origin accept the request?
- `country`, `as_org` — geo profiling
- `sample_rate` — volume estimation
- `policy_hits.ip_trustscore` — trust score
- `bot_class` — bot classification

### LB Config API (to get WAF policy, domains, service policies)
```
GET /api/config/namespaces/{ns}/http_loadbalancers/{name}
```

Key fields:
- `spec.app_firewall` — WAF policy name
- `spec.domains` — domains served
- `spec.waf_exclusion.waf_exclusion_inline_rules.rules` — existing exclusion rules
- `spec.no_service_policies` / `spec.active_service_policies` — service policies
- `spec.trusted_clients` — already-trusted users

---

## 9. TYPESCRIPT INTERFACES

Place in `src/services/fp-analyzer/types.ts`:

```typescript
// ═══════════════════════════════════════════════════════════════
// SECURITY EVENT TYPES (enriched from raw API response)
// ═══════════════════════════════════════════════════════════════

export type AnalysisScope = 'waf_signatures' | 'waf_violations' | 'threat_mesh' | 'service_policy';

export interface WafSignature {
  id: string;
  name: string;
  attackType: string;
  accuracy: 'high_accuracy' | 'medium_accuracy' | 'low_accuracy';
  risk: string;
  context: string;             // Raw: "parameter (input_file)"
  contextType: string;         // Parsed: "CONTEXT_PARAMETER"
  contextName: string;         // Parsed: "input_file"
  matchingInfo: string;
  state: string;
}

export interface WafViolation {
  name: string;                // "VIOL_JSON_MALFORMED"
  attackType: string;
  state: string;
}

export interface ThreatMeshDetails {
  description: string;
  attackTypes: string[];
  events: number;
  tenantCount: number;
  highAccuracySignatures: number;
  tlsCount: number;
  maliciousBotEvents: number;
}

export interface PolicyHitDetails {
  result: string;
  policy: string;
  policyRule: string;
  policyNamespace: string;
  ipThreatCategories: string;
  ipTrustScore: number;
  ipTrustWorthiness: string;
  ipRisk: string;
  rateLimiterAction: string;
}

// ═══════════════════════════════════════════════════════════════
// ANALYSIS ENGINE TYPES
// ═══════════════════════════════════════════════════════════════

export type FPVerdict = 'highly_likely_fp' | 'likely_fp' | 'ambiguous' | 'likely_tp' | 'confirmed_tp';

export interface SignalScore {
  score: number;               // 0-100 (0 = strong TP, 100 = strong FP)
  rawValue: number | string;   // The underlying metric (e.g., 0.78 for 78% user ratio)
  reason: string;              // Human-readable explanation
}

export interface SignalResult {
  userBreadth: SignalScore;
  requestBreadth: SignalScore;
  pathBreadth: SignalScore;
  contextAnalysis: SignalScore;
  clientProfile: SignalScore;
  temporalPattern: SignalScore;
  signatureAccuracy: SignalScore;
  compositeScore: number;
  verdict: FPVerdict;
  overrideApplied?: string;
  overrideReason?: string;
}

// ═══════════════════════════════════════════════════════════════
// SIGNATURE ANALYSIS UNIT — the fundamental analysis entity
// One unit = one (signature_id + context + path) combination
// ═══════════════════════════════════════════════════════════════

export interface SignatureAnalysisUnit {
  signatureId: string;
  signatureName: string;
  attackType: string;
  accuracy: string;
  
  // Context where this signature matched
  contextType: string;         // "CONTEXT_PARAMETER"
  contextName: string;         // "input_file"
  contextRaw: string;          // "parameter (input_file)"
  
  // Path scope
  path: string;                // Normalized path or "ALL_PATHS" if >50 paths
  rawPaths: string[];          // Original un-normalized paths (max 10 samples)
  pathCount: number;           // How many unique paths this sig+context triggers on
  
  // Counts
  eventCount: number;          // Security events for this unit
  flaggedUsers: number;        // Unique users who triggered this
  flaggedIPs: number;          // Unique IPs
  
  // Denominators from access logs
  totalRequestsOnPath: number;
  totalUsersOnPath: number;
  
  // Ratios
  userRatio: number;           // flaggedUsers / totalUsersOnPath
  requestRatio: number;        // eventCount / totalRequestsOnPath
  
  // Client profile of flagged users
  userAgents: Map<string, number>;
  countries: Map<string, number>;
  trustScores: number[];
  botClassifications: Map<string, number>;
  methods: Map<string, number>;
  
  // Evidence samples
  sampleMatchingInfos: string[];    // First 10 matching_info strings
  sampleReqParams: string[];        // First 10 req_params values
  
  // Temporal
  timestamps: string[];
  
  // Response codes (from security events)
  rspCodes: Map<string, number>;
  originAcceptedCount: number;      // How many had rsp_code=200 (monitored, not blocked)
  
  // F5 AI / accuracy signals
  violationRatings: number[];
  reqRiskReasons: string[];
  aiConfirmed: boolean;
  sigState: string;
  
  // Computed signals
  signals: SignalResult;
  
  // Generated exclusion rule (if verdict is FP)
  suggestedExclusion?: WafExclusionRule;
}

// ═══════════════════════════════════════════════════════════════
// VIOLATION ANALYSIS UNIT
// ═══════════════════════════════════════════════════════════════

export interface ViolationAnalysisUnit {
  violationName: string;
  attackType: string;
  path: string;
  rawPaths: string[];
  pathCount: number;
  eventCount: number;
  flaggedUsers: number;
  totalRequestsOnPath: number;
  totalUsersOnPath: number;
  userRatio: number;
  requestRatio: number;
  userAgents: Map<string, number>;
  countries: Map<string, number>;
  methods: Map<string, number>;
  sampleMatchingInfos: string[];
  timestamps: string[];
  signals: SignalResult;
  suggestedExclusion?: WafExclusionRule;
}

// ═══════════════════════════════════════════════════════════════
// THREAT MESH ANALYSIS UNIT
// ═══════════════════════════════════════════════════════════════

export interface ThreatMeshAnalysisUnit {
  srcIp: string;
  user: string;
  
  // Threat Mesh intelligence
  threatDetails: ThreatMeshDetails;
  
  // Behavior on THIS app (from access logs)
  totalRequestsOnApp: number;
  pathsAccessed: Map<string, number>;
  userAgent: string;
  country: string;
  asOrg: string;
  rspCodes: Map<string, number>;
  
  // Also triggered WAF events?
  wafEventsFromThisIP: number;
  
  // Scoring
  fpScore: number;
  verdict: FPVerdict;
  reasons: string[];
  
  // Suggested action
  suggestedAction?: 'trusted_client' | 'no_action';
  suggestedConfig?: object;
}

// ═══════════════════════════════════════════════════════════════
// SERVICE POLICY ANALYSIS UNIT
// ═══════════════════════════════════════════════════════════════

export interface ServicePolicyAnalysisUnit {
  policyName: string;
  ruleName: string;
  
  totalBlocked: number;
  blockedIPs: Array<{
    ip: string;
    user: string;
    count: number;
    userAgent: string;
    trustScore: number;
    threatCategories: string;
    country: string;
    topPaths: string[];
    verdict: FPVerdict;
    reason: string;
  }>;
  
  // Aggregate stats
  realBrowserPct: number;
  avgTrustScore: number;
  
  fpScore: number;
  verdict: FPVerdict;
  reasons: string[];
}

// ═══════════════════════════════════════════════════════════════
// STREAMING AGGREGATION TYPES
// ═══════════════════════════════════════════════════════════════

export interface PathStats {
  totalRequests: number;
  totalUsers: number;
  flaggedRequests: number;
  flaggedUsers: number;
  userAgents: Map<string, number>;
  countries: Map<string, number>;
  rspCodes: Map<string, number>;
  methods: Map<string, number>;
  timestampSamples: string[];      // Sampled every Nth entry for temporal analysis
}

export interface StreamingAggregation {
  pathStats: Map<string, PathStats>;
  totalAccessLogs: number;
  totalUniqueUsers: number;
  avgSampleRate: number;
}

// ═══════════════════════════════════════════════════════════════
// WAF EXCLUSION RULE (output — ready to apply)
// ═══════════════════════════════════════════════════════════════

export interface WafExclusionRule {
  metadata: {
    name: string;
    disable: boolean;
    description?: string;        // Generated rationale
  };
  exact_value: string;           // Domain
  path_regex: string;            // Regex-escaped path
  methods: string[];             // ["GET", "POST"]
  app_firewall_detection_control: {
    exclude_signature_contexts: Array<{
      signature_id: number;
      context: string;           // "CONTEXT_PARAMETER"
      context_name: string;      // "q"
    }>;
    exclude_violation_contexts: Array<{
      exclude_violation: string; // "VIOL_JSON_MALFORMED"
      context: string;           // "CONTEXT_BODY"
      context_name?: string;
    }>;
    exclude_attack_type_contexts: Array<{
      context: string;
      exclude_attack_type: string;
    }>;
    exclude_bot_name_contexts: Array<{
      bot_name: string;
    }>;
  };
}

// ═══════════════════════════════════════════════════════════════
// OVERALL ANALYSIS RESULTS
// ═══════════════════════════════════════════════════════════════

export interface FPAnalysisResults {
  // Metadata
  lbName: string;
  namespace: string;
  domain: string;
  analysisScope: AnalysisScope;
  wafPolicyName?: string;
  analysisStart: string;
  analysisEnd: string;
  generatedAt: string;
  
  // Collection stats
  totalSecurityEvents: number;
  totalAccessLogs: number;
  totalAccessLogsStreamed: number;
  avgSampleRate: number;
  
  // Results (populated based on analysisScope)
  signatureUnits?: SignatureAnalysisUnit[];
  violationUnits?: ViolationAnalysisUnit[];
  threatMeshUnits?: ThreatMeshAnalysisUnit[];
  servicePolicyUnits?: ServicePolicyAnalysisUnit[];
  
  // Summary counts
  summary: {
    totalAnalyzed: number;
    highlyLikelyFP: number;
    likelyFP: number;
    ambiguous: number;
    likelyTP: number;
    confirmedTP: number;
  };
  
  // Generated exclusion rules
  suggestedExclusions: WafExclusionRule[];
  
  // Existing exclusion rules (from LB config, for comparison)
  existingExclusions: WafExclusionRule[];
}

// ═══════════════════════════════════════════════════════════════
// COLLECTION PROGRESS
// ═══════════════════════════════════════════════════════════════

export interface FPCollectionProgress {
  phase: 'idle' | 'fetching_security' | 'streaming_access' | 'analyzing' | 'complete' | 'error';
  message: string;
  progress: number;                  // 0-100
  securityEventsCount: number;
  accessLogsStreamed: number;
  accessLogsEstimatedTotal: number;
  pathsAggregated: number;
  signaturesFound: number;
  violationsFound: number;
  error?: string;
}
```

---

## 10. SERVICE LAYER IMPLEMENTATION

### File: `src/services/fp-analyzer/streaming-aggregator.ts`

This is the most critical module — it processes millions of access logs without holding them in memory.

```typescript
// Core logic: called for EACH batch of 500 access logs during streaming
export function aggregateBatch(
  batch: AccessLogEntry[],
  pathStats: Map<string, PathStats>,
  reqIdSet: Set<string>,                // req_ids from security events
  sampleEveryN: number = 100            // temporal sampling rate
): void {
  for (const log of batch) {
    const path = normalizePath(log.req_path);
    
    if (!pathStats.has(path)) {
      pathStats.set(path, {
        totalRequests: 0,
        totalUsers: 0,    // updated via UserCounter
        flaggedRequests: 0,
        flaggedUsers: 0,
        userAgents: new Map(),
        countries: new Map(),
        rspCodes: new Map(),
        methods: new Map(),
        timestampSamples: [],
      });
    }
    
    const stats = pathStats.get(path)!;
    const weight = 1 / (log.sample_rate || 1);
    
    stats.totalRequests += weight;
    
    const userId = log.user || log.src_ip || 'unknown';
    // Note: totalUsers needs approximate unique counting — see UserCounter
    
    if (reqIdSet.has(log.req_id)) {
      stats.flaggedRequests += weight;
    }
    
    // Aggregate distributions
    const ua = log.user_agent || 'unknown';
    stats.userAgents.set(ua, (stats.userAgents.get(ua) || 0) + 1);
    
    const country = log.country || 'unknown';
    stats.countries.set(country, (stats.countries.get(country) || 0) + 1);
    
    const rspCode = log.rsp_code || '0';
    stats.rspCodes.set(rspCode, (stats.rspCodes.get(rspCode) || 0) + 1);
    
    const method = log.method || 'GET';
    stats.methods.set(method, (stats.methods.get(method) || 0) + 1);
    
    // Temporal sampling
    if (stats.totalRequests % sampleEveryN < 1) {
      stats.timestampSamples.push(log['@timestamp'] || log.time || '');
    }
  }
}
```

### File: `src/services/fp-analyzer/signal-calculator.ts`

Contains all 7 signal scoring functions as specified in Section 4.

### File: `src/services/fp-analyzer/signature-analyzer.ts`

```typescript
// Main entry point for WAF signature analysis
export function analyzeSignatures(
  signatureIndex: Map<string, SignatureIndexEntry>,
  pathStats: Map<string, PathStats>,
  domain: string
): SignatureAnalysisUnit[] {
  const units: SignatureAnalysisUnit[] = [];
  
  for (const [sigId, sigData] of signatureIndex) {
    // Group by context within this signature
    for (const [contextKey, contextData] of sigData.contexts) {
      // Compute all 7 signals
      const pathStat = pathStats.get(contextData.path);
      const totalOnPath = pathStat?.totalRequests || 0;
      const totalUsersOnPath = pathStat?.totalUsers || 0;
      
      const signals = computeAllSignals({
        flaggedUsers: contextData.uniqueUsers.size,
        totalUsersOnPath,
        flaggedRequests: contextData.eventCount,
        totalRequestsOnPath: totalOnPath,
        pathCount: sigData.contexts.size,
        totalAppPaths: pathStats.size,
        context: contextData.context,
        contextName: contextData.contextName,
        flaggedUserAgents: contextData.userAgents,
        flaggedCountries: contextData.countries,
        flaggedTrustScores: contextData.trustScores,
        normalUserAgents: pathStat?.userAgents || new Map(),
        normalCountries: pathStat?.countries || new Map(),
        botClassifications: contextData.botClassifications,
        flaggedTimestamps: contextData.timestamps,
        normalTimestamps: pathStat?.timestampSamples || [],
        accuracy: sigData.accuracy,
        reqRiskReasons: contextData.reqRiskReasons,
        violationRating: Math.max(...contextData.violationRatings, 0),
        sigState: sigData.state || 'Enabled',
      });
      
      // Apply Scenario 2 override
      const requestRatio = totalOnPath > 0 ? contextData.eventCount / totalOnPath : 0;
      const mostCommonRspCode = getMostCommon(contextData.rspCodes);
      applyScenario2Override(signals, requestRatio, contextData.uniqueUsers.size, sigData.contexts.size, mostCommonRspCode);
      
      // Generate exclusion rule if FP verdict
      let suggestedExclusion: WafExclusionRule | undefined;
      if (signals.verdict === 'highly_likely_fp' || signals.verdict === 'likely_fp') {
        suggestedExclusion = generateSignatureExclusion(
          sigId, contextData.context, contextData.contextName,
          domain, contextData.path, [...contextData.methods.keys()]
        );
      }
      
      units.push({
        signatureId: sigId,
        signatureName: sigData.name,
        attackType: sigData.attackType,
        accuracy: sigData.accuracy,
        contextType: contextData.context,
        contextName: contextData.contextName,
        contextRaw: contextData.contextRaw,
        path: contextData.path,
        rawPaths: contextData.rawPaths,
        pathCount: sigData.contexts.size,
        eventCount: contextData.eventCount,
        flaggedUsers: contextData.uniqueUsers.size,
        flaggedIPs: contextData.uniqueIPs.size,
        totalRequestsOnPath: totalOnPath,
        totalUsersOnPath,
        userRatio: totalUsersOnPath > 0 ? contextData.uniqueUsers.size / totalUsersOnPath : 0,
        requestRatio: totalOnPath > 0 ? contextData.eventCount / totalOnPath : 0,
        userAgents: contextData.userAgents,
        countries: contextData.countries,
        trustScores: contextData.trustScores,
        botClassifications: contextData.botClassifications,
        methods: contextData.methods,
        sampleMatchingInfos: contextData.sampleMatchingInfo,
        sampleReqParams: contextData.sampleReqParams,
        timestamps: contextData.timestamps,
        rspCodes: contextData.rspCodes,
        originAcceptedCount: contextData.rspCodes.get('200') || 0,
        violationRatings: contextData.violationRatings,
        reqRiskReasons: contextData.reqRiskReasons,
        aiConfirmed: contextData.aiConfirmed,
        sigState: sigData.state || 'Enabled',
        signals,
        suggestedExclusion,
      });
    }
  }
  
  // Sort: FP score descending (most likely FP first)
  return units.sort((a, b) => b.signals.compositeScore - a.signals.compositeScore);
}
```

### File: `src/services/fp-analyzer/exclusion-generator.ts`

```typescript
// Parse security event context → exclusion rule context
export function parseContext(contextStr: string): { context: string; contextName: string } {
  const str = (contextStr || '').trim();
  const match = str.match(/^(parameter|cookie|header)\s*\(([^)]+)\)/i);
  if (match) {
    const typeMap: Record<string, string> = {
      'parameter': 'CONTEXT_PARAMETER',
      'cookie': 'CONTEXT_COOKIE',
      'header': 'CONTEXT_HEADER',
    };
    return { context: typeMap[match[1].toLowerCase()], contextName: match[2].trim() };
  }
  if (/url|uri/i.test(str)) return { context: 'CONTEXT_URL', contextName: '' };
  if (/body/i.test(str)) return { context: 'CONTEXT_BODY', contextName: '' };
  return { context: 'CONTEXT_PARAMETER', contextName: '' };
}

// Escape path for regex use
export function pathToRegex(path: string): string {
  const escaped = path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return `^${escaped}/?$`;
}

// Generate signature exclusion rule
export function generateSignatureExclusion(
  sigId: string,
  context: string,
  contextName: string,
  domain: string,
  path: string,
  methods: string[]
): WafExclusionRule {
  const hash = sigId.slice(-6) + Math.random().toString(36).slice(2, 6);
  return {
    metadata: {
      name: `fp-sig${sigId}-${hash}`,
      disable: false,
      description: `FP Analyzer: Exclude signature ${sigId} for ${context} "${contextName}" on ${path}`,
    },
    exact_value: domain,
    path_regex: pathToRegex(path),
    methods: methods.length > 0 ? methods : ['GET', 'POST', 'PUT', 'DELETE'],
    app_firewall_detection_control: {
      exclude_signature_contexts: [{
        signature_id: parseInt(sigId, 10),
        context,
        context_name: contextName,
      }],
      exclude_violation_contexts: [],
      exclude_attack_type_contexts: [],
      exclude_bot_name_contexts: [],
    },
  };
}

// Generate violation exclusion rule
export function generateViolationExclusion(
  violationName: string,
  context: string,
  contextName: string,
  domain: string,
  path: string,
  methods: string[]
): WafExclusionRule {
  const hash = Math.random().toString(36).slice(2, 8);
  return {
    metadata: {
      name: `fp-viol-${hash}`,
      disable: false,
      description: `FP Analyzer: Exclude ${violationName} on ${path}`,
    },
    exact_value: domain,
    path_regex: pathToRegex(path),
    methods: methods.length > 0 ? methods : ['GET', 'POST', 'PUT', 'DELETE'],
    app_firewall_detection_control: {
      exclude_signature_contexts: [],
      exclude_violation_contexts: [{
        exclude_violation: violationName,
        context,
        context_name: contextName,
      }],
      exclude_attack_type_contexts: [],
      exclude_bot_name_contexts: [],
    },
  };
}

// Group multiple signature exclusions for same path into one rule
export function groupExclusionRules(rules: WafExclusionRule[]): WafExclusionRule[] {
  // Group by (domain + path_regex + methods)
  const groups = new Map<string, WafExclusionRule>();
  
  for (const rule of rules) {
    const key = `${rule.exact_value}|${rule.path_regex}|${rule.methods.sort().join(',')}`;
    if (!groups.has(key)) {
      groups.set(key, { ...rule });
    } else {
      const existing = groups.get(key)!;
      // Merge signature exclusions
      existing.app_firewall_detection_control.exclude_signature_contexts.push(
        ...rule.app_firewall_detection_control.exclude_signature_contexts
      );
      existing.app_firewall_detection_control.exclude_violation_contexts.push(
        ...rule.app_firewall_detection_control.exclude_violation_contexts
      );
      // Update description
      existing.metadata.description += ` + ${rule.metadata.description}`;
    }
  }
  
  return [...groups.values()];
}
```

---

## 11. UI COMPONENT SPECIFICATION

### Page: `src/pages/FPAnalyzer.tsx`

Layout as scrollable single page with 4 main sections:

**Section 1: Scope Selection**
- Namespace dropdown → LB dropdown → Domain dropdown (if multi-domain)
- Analysis scope selector: [WAF Signatures] [WAF Violations] [Threat Mesh] [Service Policy]
- WAF policy name auto-detected from LB config
- Period selector (last 7/14/30 days)
- [Start Analysis] button

**Section 2: Progress + Collection Stats**
- Three-phase progress bar (security events → stream access logs → analyze)
- Real-time counts: events loaded, logs streamed, paths aggregated

**Section 3: Results Overview**
- Summary cards: X highly likely FP, Y likely FP, Z ambiguous, W likely TP, V confirmed TP
- Sortable/filterable table of all analysis units
- Color-coded verdict badges (red=FP, green=TP, yellow=ambiguous)
- Click any row to expand detailed view

**Section 4: Per-Unit Detail (expanded view)**
- All 7 signal scores as visual bars (0-100 scale)
- Evidence: sample matching values, client profiles, path distribution
- Scenario 2 override indicator (if applied)
- [Generate Exclusion Rule] button → shows JSON preview
- [Add to Exclusion Bundle] button → adds to export collection

**Section 5: Export**
- [Download All Exclusion Rules as JSON] — ready to merge into LB config
- [Download Analysis Report as CSV]
- [Copy Exclusion Rules to Clipboard]
- Show existing exclusion rules from LB config for comparison

---

## 12. FILES TO CREATE & MODIFY

### New Files (13)
```
src/services/fp-analyzer/
├── types.ts                        // All interfaces from Section 9
├── index.ts                        // Re-exports
├── streaming-aggregator.ts         // Memory-efficient access log processing
├── security-event-indexer.ts       // Build in-memory indexes from security events
├── signal-calculator.ts            // All 7 signal scoring functions
├── fp-scorer.ts                    // Composite score + verdict + scenario overrides
├── signature-analyzer.ts           // WAF signature FP analysis
├── violation-analyzer.ts           // WAF violation FP analysis
├── threat-mesh-analyzer.ts         // Threat Mesh FP analysis
├── service-policy-analyzer.ts      // Service policy FP analysis
├── exclusion-generator.ts          // Generate WAF exclusion rule JSON
├── context-parser.ts               // Parse security event context → exclusion context
└── report-generator.ts             // Export CSV/JSON reports

src/pages/
└── FPAnalyzer.tsx                  // Main page component
```

### Files to Modify
- `src/App.tsx` — Add route `/fp-analyzer`
- `src/pages/Home.tsx` — Add tool card (icon: `ShieldAlert` from lucide-react)
- `src/services/api.ts` — Reuse existing access log + security event methods (already added for Rate Limit Advisor)

### Reusable from Rate Limit Advisor
- `src/services/rate-limit-advisor/log-collector.ts` — `collectAccessLogs()`, `collectSecurityEvents()` with parallel chunked fetching
- `src/services/rate-limit-advisor/types.ts` — `AccessLogEntry`, `SecurityEventEntry`, `CollectionProgress`
- `src/services/rate-limit-advisor/response-classifier.ts` — `classifyResponse()`
- `src/services/rate-limit-advisor/path-analyzer.ts` — `normalizePath()`, `isSensitiveEndpoint()`

---

## 13. DEVELOPMENT PHASES

### Phase 1: Foundation
- Types, security event indexer, streaming aggregator skeleton
- Scope selection UI, progress bar, data collection
- Test with WAF signatures scope

### Phase 2: WAF Signature Analysis
- All 7 signal scoring functions
- Composite scorer with Scenario 2 override
- Signature analysis results table
- Per-signature detail view with signal bars

### Phase 3: Exclusion Rule Generation
- Context parser (security event → exclusion rule context)
- Signature and violation exclusion generators
- Rule grouping (merge same path+context into one rule)
- JSON preview + copy/download

### Phase 4: Other Security Controls
- Violation analyzer
- Threat Mesh analyzer
- Service Policy analyzer

### Phase 5: Polish
- Export: CSV analysis report, JSON exclusion bundle
- Existing exclusion rules comparison
- Evidence presentation: sample matching values, client sparklines
- Large dataset performance testing
