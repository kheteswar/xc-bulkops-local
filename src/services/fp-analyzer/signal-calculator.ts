import type { SignalScore, PathStats, QuickVerdict, ConfidenceLevel, SignatureSummary } from './types';

// ═══════════════════════════════════════════════════════════════
// SIGNAL 1: USER BREADTH (weight 25%)
// ═══════════════════════════════════════════════════════════════

export function scoreUserBreadth(flaggedUsers: number, totalUsers: number): SignalScore {
  if (totalUsers === 0) return { score: 50, rawValue: 0, reason: 'No access log data for this path' };

  if (flaggedUsers <= 2) {
    return { score: 5, rawValue: flaggedUsers, reason: `Only ${flaggedUsers} user(s) triggered this — likely targeted` };
  }

  const ratio = flaggedUsers / totalUsers;
  if (ratio > 0.80) return { score: 95, rawValue: ratio, reason: `${(ratio * 100).toFixed(0)}% of users trigger this — very strong FP` };
  if (ratio > 0.50) return { score: 80, rawValue: ratio, reason: `${(ratio * 100).toFixed(0)}% of users trigger this — strong FP` };
  if (ratio > 0.30) return { score: 60, rawValue: ratio, reason: `${(ratio * 100).toFixed(0)}% of users trigger this — moderate FP` };
  if (ratio > 0.10) return { score: 40, rawValue: ratio, reason: `${(ratio * 100).toFixed(0)}% of users trigger this — ambiguous` };
  if (ratio > 0.05) return { score: 25, rawValue: ratio, reason: `${(ratio * 100).toFixed(0)}% of users trigger this — lean TP` };
  return { score: 10, rawValue: ratio, reason: `Only ${(ratio * 100).toFixed(1)}% of users — strong TP` };
}

// ═══════════════════════════════════════════════════════════════
// SIGNAL 2: REQUEST BREADTH (weight 25%)
// ═══════════════════════════════════════════════════════════════

export function scoreRequestBreadth(flaggedRequests: number, totalRequests: number): SignalScore {
  if (totalRequests === 0) return { score: 50, rawValue: 0, reason: 'No access log data for this path' };

  const ratio = flaggedRequests / totalRequests;
  if (ratio > 0.90) return { score: 95, rawValue: ratio, reason: `${(ratio * 100).toFixed(0)}% of requests trigger this — very strong FP` };
  if (ratio > 0.70) return { score: 85, rawValue: ratio, reason: `${(ratio * 100).toFixed(0)}% of requests trigger this — strong FP` };
  if (ratio > 0.50) return { score: 70, rawValue: ratio, reason: `${(ratio * 100).toFixed(0)}% of requests trigger this — moderate FP` };
  if (ratio > 0.30) return { score: 55, rawValue: ratio, reason: `${(ratio * 100).toFixed(0)}% of requests trigger this — lean FP` };
  if (ratio > 0.10) return { score: 35, rawValue: ratio, reason: `${(ratio * 100).toFixed(0)}% of requests — ambiguous` };
  if (ratio > 0.05) return { score: 20, rawValue: ratio, reason: `${(ratio * 100).toFixed(0)}% of requests — lean TP` };
  return { score: 10, rawValue: ratio, reason: `Only ${(ratio * 100).toFixed(1)}% of requests — strong TP` };
}

// ═══════════════════════════════════════════════════════════════
// SIGNAL 3: PATH BREADTH (weight 10%)
// ═══════════════════════════════════════════════════════════════

export function scorePathBreadth(pathCount: number, totalAppPaths: number): SignalScore {
  if (totalAppPaths === 0) return { score: 50, rawValue: pathCount, reason: 'No path data available' };

  const ratio = pathCount / totalAppPaths;
  if (ratio > 0.50) return { score: 95, rawValue: pathCount, reason: `Triggers on ${pathCount}/${totalAppPaths} paths (${(ratio * 100).toFixed(0)}%) — definitely FP` };
  if (pathCount > 20) return { score: 85, rawValue: pathCount, reason: `Triggers on ${pathCount} paths — strong FP` };
  if (pathCount > 10) return { score: 70, rawValue: pathCount, reason: `Triggers on ${pathCount} paths — lean FP` };
  if (pathCount > 5) return { score: 50, rawValue: pathCount, reason: `Triggers on ${pathCount} paths — ambiguous` };
  if (pathCount > 2) return { score: 30, rawValue: pathCount, reason: `Triggers on ${pathCount} paths — lean TP (check Scenario 2)` };
  return { score: 15, rawValue: pathCount, reason: `Only ${pathCount} path(s) — investigate deeper` };
}

// ═══════════════════════════════════════════════════════════════
// SIGNAL 4: CONTEXT ANALYSIS (weight 10%)
// ═══════════════════════════════════════════════════════════════

export function scoreContext(contextType: string, contextName: string): SignalScore {
  const ctLower = contextType.toLowerCase();
  const cnLower = contextName.toLowerCase();

  if (ctLower.includes('cookie')) {
    return { score: 90, rawValue: `${contextType}(${contextName})`, reason: 'Cookie context — app-generated, users don\'t control cookie content' };
  }

  if (ctLower.includes('header')) {
    if (cnLower === 'user-agent') {
      return { score: 30, rawValue: `header(${contextName})`, reason: 'User-Agent header — client-controlled, needs investigation' };
    }
    if (/authorization|auth|token|x-/i.test(cnLower)) {
      return { score: 85, rawValue: `header(${contextName})`, reason: `Header "${contextName}" — likely app-generated auth/token header` };
    }
    return { score: 60, rawValue: `header(${contextName})`, reason: `Header "${contextName}" — may be app-generated or user-controlled` };
  }

  if (ctLower.includes('url') || ctLower.includes('uri')) {
    return { score: 40, rawValue: `url(${contextName})`, reason: 'URL context — could be legitimate path structure or attack path' };
  }

  if (ctLower.includes('body')) {
    return { score: 50, rawValue: `body(${contextName})`, reason: 'Body context — check if endpoint accepts user-controlled body data' };
  }

  if (ctLower.includes('parameter')) {
    if (/^(q|query|search|filter|keyword|term|s)$/i.test(cnLower)) {
      return { score: 75, rawValue: `param(${contextName})`, reason: `Search/filter parameter "${contextName}" — likely contains user text` };
    }
    if (/^(cmd|exec|command|eval|system|shell|code)$/i.test(cnLower)) {
      return { score: 15, rawValue: `param(${contextName})`, reason: `Dangerous parameter "${contextName}" — likely real attack vector` };
    }
    return { score: 45, rawValue: `param(${contextName})`, reason: `Parameter "${contextName}" — needs investigation` };
  }

  return { score: 50, rawValue: contextType || 'unknown', reason: 'Unknown context — manual investigation needed' };
}

// ═══════════════════════════════════════════════════════════════
// SIGNAL 5: CLIENT PROFILE (weight 10%)
// ═══════════════════════════════════════════════════════════════

const REAL_BROWSER_RE = /chrome|firefox|safari|edge|opera/i;
const BOT_RE = /bot|spider|crawler|crawl/i;

export function scoreClientProfile(
  flaggedUserAgents: Record<string, number>,
  flaggedBotClassifications: Record<string, number>,
  flaggedTrustScores: number[],
  flaggedCountries: Record<string, number>,
  normalCountries: Record<string, number>,
): SignalScore {
  let score = 50;
  const reasons: string[] = [];

  // Sub-check A: Real browser user agents
  const uaEntries = Object.entries(flaggedUserAgents);
  if (uaEntries.length > 0) {
    let browserCount = 0;
    let total = 0;
    for (const [ua, count] of uaEntries) {
      total += count;
      if (REAL_BROWSER_RE.test(ua) && !BOT_RE.test(ua)) browserCount += count;
    }
    const browserPct = browserCount / total;
    if (browserPct > 0.80) {
      score += 20;
      reasons.push(`${(browserPct * 100).toFixed(0)}% of flagged clients use real browsers`);
    } else if (browserPct < 0.20) {
      score -= 25;
      reasons.push('Mostly scripting tools or non-browser clients');
    }
  }

  // Sub-check B: Bot classifications
  const botEntries = Object.entries(flaggedBotClassifications);
  if (botEntries.length > 0) {
    let maliciousCount = 0;
    let totalBot = 0;
    for (const [cls, count] of botEntries) {
      totalBot += count;
      if (/malicious/i.test(cls)) maliciousCount += count;
    }
    if (maliciousCount > 0 && totalBot > 0 && (maliciousCount / totalBot) > 0.5) {
      score -= 30;
      reasons.push(`${maliciousCount}/${totalBot} bot classifications are malicious`);
    }
  }

  // Sub-check C: IP trust scores
  if (flaggedTrustScores.length > 0) {
    const avgTrust = flaggedTrustScores.reduce((a, b) => a + b, 0) / flaggedTrustScores.length;
    if (avgTrust > 70) {
      score += 15;
      reasons.push(`High avg trust score (${avgTrust.toFixed(0)})`);
    } else if (avgTrust < 30) {
      score -= 20;
      reasons.push(`Low avg trust score (${avgTrust.toFixed(0)})`);
    }
  }

  // Sub-check D: Geographic match
  const topFlagged = getTopKey(flaggedCountries);
  const topNormal = getTopKey(normalCountries);
  if (topFlagged && topNormal && topFlagged === topNormal) {
    score += 5;
    reasons.push('Geo distribution matches normal traffic');
  }

  score = Math.max(0, Math.min(100, score));
  return { score, rawValue: score, reason: reasons.length > 0 ? reasons.join('; ') : 'Neutral client profile' };
}

function getTopKey(map: Record<string, number>): string | null {
  let top = '';
  let max = 0;
  for (const [k, v] of Object.entries(map)) {
    if (v > max) { max = v; top = k; }
  }
  return top || null;
}

// ═══════════════════════════════════════════════════════════════
// SIGNAL 6: TEMPORAL PATTERN (weight 10%)
// ═══════════════════════════════════════════════════════════════

export function scoreTemporalPattern(
  flaggedTimestamps: string[],
  normalTimestampSamples: string[],
): SignalScore {
  if (flaggedTimestamps.length < 5) {
    return { score: 50, rawValue: flaggedTimestamps.length, reason: 'Too few events for temporal analysis' };
  }

  const flaggedBuckets = bucketByHour(flaggedTimestamps);
  const normalBuckets = bucketByHour(normalTimestampSamples);

  let diff = 0;
  for (let h = 0; h < 24; h++) {
    diff += Math.abs(flaggedBuckets[h] - normalBuckets[h]);
  }

  if (diff < 0.3) return { score: 80, rawValue: diff, reason: 'Flagged events follow normal traffic pattern — not attack-like' };
  if (diff < 0.6) return { score: 55, rawValue: diff, reason: 'Partially matches normal traffic pattern' };
  return { score: 20, rawValue: diff, reason: 'Events cluster at unusual times — possible attack campaign' };
}

function bucketByHour(timestamps: string[]): number[] {
  const buckets = new Array(24).fill(0);
  let total = 0;
  for (const ts of timestamps) {
    try {
      const hour = new Date(ts).getUTCHours();
      buckets[hour]++;
      total++;
    } catch { /* skip invalid */ }
  }
  if (total > 0) {
    for (let i = 0; i < 24; i++) buckets[i] /= total;
  }
  return buckets;
}

// ═══════════════════════════════════════════════════════════════
// SIGNAL 7: SIGNATURE ACCURACY + AI CONFIRMATION (weight 10%)
// ═══════════════════════════════════════════════════════════════

export function scoreSignatureAccuracy(
  accuracy: string,
  state: string,
  aiConfirmed: boolean,
  violationRatings: number[],
): SignalScore {
  let score = 50;
  const reasons: string[] = [];

  // AI confirmation overrides strongly toward TP
  if (aiConfirmed) {
    score -= 40;
    reasons.push('AI confirmed 100% — very unlikely FP');
  }

  // AutoSuppressed = F5 ML thinks it's FP
  if (state === 'AutoSuppressed') {
    score += 30;
    reasons.push('AutoSuppressed by F5 ML');
  }

  // Accuracy
  if (accuracy === 'high_accuracy') {
    score -= 15;
    reasons.push('High accuracy signature — precise matching');
  } else if (accuracy === 'low_accuracy') {
    score += 20;
    reasons.push('Low accuracy signature — broad matching');
  }

  // Violation rating
  if (violationRatings.length > 0) {
    const avgRating = violationRatings.reduce((a, b) => a + b, 0) / violationRatings.length;
    if (avgRating >= 4) {
      score -= 15;
      reasons.push(`High violation rating (avg ${avgRating.toFixed(1)})`);
    } else if (avgRating <= 2) {
      score += 10;
      reasons.push(`Low violation rating (avg ${avgRating.toFixed(1)})`);
    }
  }

  score = Math.max(0, Math.min(100, score));
  return { score, rawValue: score, reason: reasons.length > 0 ? reasons.join('; ') : 'Neutral accuracy assessment' };
}

// ═══════════════════════════════════════════════════════════════
// UTILITY: Merge Map<string, number> to Record<string, number>
// ═══════════════════════════════════════════════════════════════

export function mapToRecord(map: Map<string, number>): Record<string, number> {
  const rec: Record<string, number> = {};
  for (const [k, v] of map) rec[k] = v;
  return rec;
}

export function mergeNormalTimestamps(pathStats: Map<string, PathStats>): string[] {
  const all: string[] = [];
  for (const ps of pathStats.values()) {
    all.push(...ps.timestampSamples);
  }
  return all;
}

export function mergeNormalCountries(pathStats: Map<string, PathStats>): Record<string, number> {
  const merged: Record<string, number> = {};
  for (const ps of pathStats.values()) {
    for (const [k, v] of ps.countries) {
      merged[k] = (merged[k] || 0) + v;
    }
  }
  return merged;
}

// ═══════════════════════════════════════════════════════════════
// QUICK MODE SCORING (absolute counts, no access log denominators)
// ═══════════════════════════════════════════════════════════════

export function scoreUserBreadthQuick(flaggedUsers: number): SignalScore {
  if (flaggedUsers > 200) return { score: 95, rawValue: flaggedUsers, reason: `${flaggedUsers} unique users — very strong FP` };
  if (flaggedUsers > 100) return { score: 85, rawValue: flaggedUsers, reason: `${flaggedUsers} unique users — strong FP` };
  if (flaggedUsers > 50) return { score: 75, rawValue: flaggedUsers, reason: `${flaggedUsers} unique users — moderate FP` };
  if (flaggedUsers > 20) return { score: 60, rawValue: flaggedUsers, reason: `${flaggedUsers} unique users — lean FP` };
  if (flaggedUsers > 10) return { score: 45, rawValue: flaggedUsers, reason: `${flaggedUsers} unique users — ambiguous` };
  if (flaggedUsers > 5) return { score: 30, rawValue: flaggedUsers, reason: `${flaggedUsers} unique users — lean TP` };
  if (flaggedUsers > 2) return { score: 15, rawValue: flaggedUsers, reason: `${flaggedUsers} unique users — likely targeted` };
  return { score: 5, rawValue: flaggedUsers, reason: `Only ${flaggedUsers} user(s) — strong TP indicator` };
}

export function scoreRequestBreadthQuick(eventCount: number, rspCode200Pct: number): SignalScore {
  let score: number;
  let reason: string;

  if (eventCount > 1000) { score = 90; reason = `${eventCount} events — massive volume`; }
  else if (eventCount > 500) { score = 80; reason = `${eventCount} events — high volume`; }
  else if (eventCount > 100) { score = 65; reason = `${eventCount} events — moderate volume`; }
  else if (eventCount > 50) { score = 50; reason = `${eventCount} events — ambiguous`; }
  else if (eventCount > 10) { score = 30; reason = `${eventCount} events — low volume`; }
  else { score = 10; reason = `Only ${eventCount} events — very low`; }

  // Boost if origin accepted (rsp_code=200)
  if (rspCode200Pct > 0.80) {
    score = Math.min(100, score + 15);
    reason += ` + ${(rspCode200Pct * 100).toFixed(0)}% origin accepted`;
  }

  return { score, rawValue: eventCount, reason };
}

export function scoreSignatureAccuracyEnhanced(
  accuracy: string,
  state: string,
  aiConfirmed: boolean,
  violationRatings: number[],
  calculatedAction?: string,
  rspCode200Pct?: number,
): SignalScore {
  let score = 50;
  const reasons: string[] = [];

  if (aiConfirmed) { score -= 40; reasons.push('AI confirmed — very unlikely FP'); }
  if (state === 'AutoSuppressed') { score += 35; reasons.push('AutoSuppressed by F5 ML'); }
  if (calculatedAction === 'report') { score += 10; reasons.push('WAF calculated_action=report (not confident)'); }
  if (calculatedAction === 'block') { score -= 10; reasons.push('WAF calculated_action=block (confident)'); }
  if (accuracy === 'high_accuracy') { score -= 15; reasons.push('High accuracy signature'); }
  else if (accuracy === 'low_accuracy') { score += 20; reasons.push('Low accuracy signature'); }
  if (rspCode200Pct !== undefined && rspCode200Pct > 0.80) { score += 15; reasons.push('Origin accepted >80% of requests'); }
  if (rspCode200Pct !== undefined && rspCode200Pct < 0.20) { score -= 5; reasons.push('Most requests blocked'); }

  if (violationRatings.length > 0) {
    const avg = violationRatings.reduce((a, b) => a + b, 0) / violationRatings.length;
    if (avg >= 4) { score -= 15; reasons.push(`High violation rating (${avg.toFixed(1)})`); }
    else if (avg <= 2) { score += 10; reasons.push(`Low violation rating (${avg.toFixed(1)})`); }
  }

  score = Math.max(0, Math.min(100, score));
  return { score, rawValue: score, reason: reasons.join('; ') || 'Neutral' };
}

export function scoreClientProfileQuick(
  userAgents: Record<string, number>,
  botClassifications: Record<string, number>,
  trustScores: number[],
  countries: Record<string, number>,
  botAnomalies?: Record<string, number>,
): SignalScore {
  let score = 50;
  const reasons: string[] = [];

  // Browser analysis
  const uaEntries = Object.entries(userAgents);
  if (uaEntries.length > 0) {
    let browserCount = 0; let total = 0;
    for (const [ua, count] of uaEntries) {
      total += count;
      if (REAL_BROWSER_RE.test(ua) && !BOT_RE.test(ua)) browserCount += count;
    }
    const pct = browserCount / total;
    if (pct > 0.80) { score += 25; reasons.push(`${(pct * 100).toFixed(0)}% real browsers`); }
    else if (pct < 0.20) { score -= 25; reasons.push('Mostly scripting tools'); }
  }

  // Bot classifications
  const botEntries = Object.entries(botClassifications);
  if (botEntries.length > 0) {
    let malicious = 0; let benign = 0; let total = 0;
    for (const [cls, count] of botEntries) {
      total += count;
      if (/malicious/i.test(cls)) malicious += count;
      if (/benign/i.test(cls)) benign += count;
    }
    if (benign > 0 && total > 0 && benign / total > 0.5) { score += 30; reasons.push('Mostly benign bots being flagged'); }
    if (malicious > 0 && total > 0 && malicious / total > 0.5) { score -= 30; reasons.push('Mostly malicious bots'); }
  }

  // Bot anomaly reasons
  if (botAnomalies) {
    for (const [anomaly, count] of Object.entries(botAnomalies)) {
      if (/verification failed/i.test(anomaly) && count > 0) { score -= 10; reasons.push('Bot verification failed'); }
      if (/invalid.*headers/i.test(anomaly) && count > 0) { score -= 5; reasons.push('Invalid HTTP headers detected'); }
    }
  }

  // Trust scores
  if (trustScores.length > 0) {
    const avg = trustScores.reduce((a, b) => a + b, 0) / trustScores.length;
    if (avg > 70) { score += 15; reasons.push(`High trust (${avg.toFixed(0)})`); }
    else if (avg < 30) { score -= 20; reasons.push(`Low trust (${avg.toFixed(0)})`); }
  }

  // Geo diversity
  const countryCount = Object.keys(countries).length;
  if (countryCount > 10) { score += 10; reasons.push(`${countryCount} countries — diverse traffic`); }
  else if (countryCount <= 2) { score -= 5; reasons.push('Concentrated geo'); }

  score = Math.max(0, Math.min(100, score));
  return { score, rawValue: score, reason: reasons.join('; ') || 'Neutral' };
}

// ═══════════════════════════════════════════════════════════════
// QUICK VERDICT (summary table — from counts alone)
// ═══════════════════════════════════════════════════════════════

export function computeQuickVerdict(sig: SignatureSummary): { verdict: QuickVerdict; confidence: ConfidenceLevel } {
  if (sig.uniqueUsers > 100 && sig.uniquePaths > 5) return { verdict: 'likely_fp', confidence: 'high' };
  if (sig.autoSuppressed) return { verdict: 'likely_fp', confidence: 'high' };
  if (sig.uniqueUsers > 50 && sig.accuracy === 'low_accuracy') return { verdict: 'likely_fp', confidence: 'medium' };

  if (sig.uniqueUsers <= 2 && sig.accuracy === 'high_accuracy') return { verdict: 'likely_tp', confidence: 'high' };
  if (sig.uniqueUsers <= 3 && sig.uniquePaths > 20) return { verdict: 'likely_tp', confidence: 'high' };

  return { verdict: 'investigate', confidence: 'low' };
}

// ═══════════════════════════════════════════════════════════════
// CONFIDENCE FROM COMPOSITE SCORE (Quick Mode)
// ═══════════════════════════════════════════════════════════════

export function getScoreConfidence(compositeScore: number): ConfidenceLevel {
  if (compositeScore > 75 || compositeScore < 15) return 'high';
  if (compositeScore > 55 || compositeScore < 35) return 'medium';
  return 'low';
}
