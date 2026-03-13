import type {
  ServicePolicyAnalysisUnit,
  PathStats,
  SecurityEventIndexes,
  FPVerdict,
} from './types';
import { analysisLogger } from './analysis-logger';

// ═══════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════

const REAL_BROWSER_RE = /chrome|firefox|safari|edge|opera/i;
const BOT_RE = /bot|spider|crawler/i;
const USUALLY_TP_CATEGORIES = /BOTNETS|SCANNERS|WEB_ATTACKS/i;

// ═══════════════════════════════════════════════════════════════
// ANALYZE SERVICE POLICIES
// ═══════════════════════════════════════════════════════════════

export function analyzeServicePolicies(
  indexes: SecurityEventIndexes,
  _pathStats: Map<string, PathStats>,
): ServicePolicyAnalysisUnit[] {
  const units: ServicePolicyAnalysisUnit[] = [];

  for (const [policyRule, entry] of indexes.policyIndex) {
    const blockedIPs: ServicePolicyAnalysisUnit['blockedIPs'] = [];
    let totalTrustScore = 0;
    let totalRealBrowser = 0;
    let totalIPs = 0;

    for (const [ip, ipData] of entry.blockedIPs) {
      totalIPs++;
      const isRealBrowser = REAL_BROWSER_RE.test(ipData.userAgent || '') && !BOT_RE.test(ipData.userAgent || '');
      if (isRealBrowser) totalRealBrowser++;
      totalTrustScore += ipData.trustScore;

      // Per-IP scoring
      const { verdict, reason } = scoreBlockedIP(
        ipData.trustScore,
        ipData.threatCategories,
        ipData.userAgent || '',
        ipData.count,
        ipData.paths.size,
      );

      const topPaths = [...ipData.paths.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([p]) => p);

      blockedIPs.push({
        ip,
        user: ipData.user,
        count: ipData.count,
        userAgent: ipData.userAgent || '',
        trustScore: ipData.trustScore,
        threatCategories: ipData.threatCategories,
        country: ipData.country || '',
        topPaths,
        verdict,
        reason,
      });
    }

    // Sort blocked IPs by count descending
    blockedIPs.sort((a, b) => b.count - a.count);

    // Aggregate policy-level stats
    const realBrowserPct = totalIPs > 0 ? totalRealBrowser / totalIPs : 0;
    const avgTrustScore = totalIPs > 0 ? totalTrustScore / totalIPs : 0;

    // Compute policy-level FP score
    let fpScore = 50;
    const reasons: string[] = [];

    // Real browser percentage
    if (realBrowserPct > 0.7) {
      fpScore += 20;
      reasons.push(`${(realBrowserPct * 100).toFixed(0)}% of blocked IPs use real browsers`);
    } else if (realBrowserPct < 0.2) {
      fpScore -= 15;
      reasons.push('Most blocked IPs use non-browser clients');
    }

    // Average trust score
    if (avgTrustScore > 60) {
      fpScore += 15;
      reasons.push(`High avg trust score (${avgTrustScore.toFixed(0)})`);
    } else if (avgTrustScore < 30) {
      fpScore -= 15;
      reasons.push(`Low avg trust score (${avgTrustScore.toFixed(0)})`);
    }

    // Distribution of per-IP verdicts
    const fpIPs = blockedIPs.filter(ip => ip.verdict === 'highly_likely_fp' || ip.verdict === 'likely_fp').length;
    const tpIPs = blockedIPs.filter(ip => ip.verdict === 'likely_tp' || ip.verdict === 'confirmed_tp').length;
    if (totalIPs > 0) {
      if (fpIPs / totalIPs > 0.5) {
        fpScore += 15;
        reasons.push(`${fpIPs}/${totalIPs} blocked IPs scored as FP`);
      } else if (tpIPs / totalIPs > 0.7) {
        fpScore -= 15;
        reasons.push(`${tpIPs}/${totalIPs} blocked IPs scored as TP`);
      }
    }

    // Threat category baseline
    const hasProxyIPs = blockedIPs.some(ip => /PROXY/i.test(ip.threatCategories));
    if (hasProxyIPs) {
      fpScore += 10;
      reasons.push('Contains PROXY-categorized IPs — most FP-prone category');
    }

    fpScore = Math.max(0, Math.min(100, fpScore));
    const verdict = scoreToVerdict(fpScore);

    units.push({
      policyName: entry.policy,
      ruleName: policyRule,
      totalBlocked: entry.eventCount,
      blockedIPs,
      realBrowserPct,
      avgTrustScore,
      fpScore,
      verdict,
      reasons,
    });

    analysisLogger.logServicePolicyAnalysis(policyRule, fpScore, verdict, entry.blockedIPs.size);
  }

  units.sort((a, b) => b.fpScore - a.fpScore);
  return units;
}

// ═══════════════════════════════════════════════════════════════
// PER-IP SCORING
// ═══════════════════════════════════════════════════════════════

function scoreBlockedIP(
  trustScore: number,
  threatCategories: string,
  userAgent: string,
  _count: number,
  pathCount: number,
): { verdict: FPVerdict; reason: string; score: number } {
  let score = 50;
  const reasons: string[] = [];

  const isRealBrowser = REAL_BROWSER_RE.test(userAgent) && !BOT_RE.test(userAgent);

  // PROXY category — most FP-prone
  if (/PROXY/i.test(threatCategories)) {
    if (isRealBrowser && trustScore > 40) {
      score += 25;
      reasons.push('PROXY IP with real browser and trust > 40 — likely corporate VPN/CDN');
    } else if (isRealBrowser) {
      score += 10;
      reasons.push('PROXY IP with real browser');
    }
  }

  // Usually-TP categories
  if (USUALLY_TP_CATEGORIES.test(threatCategories)) {
    score -= 20;
    reasons.push(`${threatCategories} — usually TP`);
  }

  // Trust score
  if (trustScore > 70) {
    score += 15;
    reasons.push(`High trust score (${trustScore})`);
  } else if (trustScore < 20) {
    score -= 15;
    reasons.push(`Low trust score (${trustScore})`);
  }

  // Browser signal
  if (isRealBrowser) {
    score += 10;
    reasons.push('Real browser user agent');
  } else if (!userAgent || BOT_RE.test(userAgent)) {
    score -= 10;
    reasons.push('Non-browser or bot user agent');
  }

  // Browsing pattern (multiple pages = more likely legitimate)
  if (pathCount > 5 && isRealBrowser) {
    score += 5;
    reasons.push(`Accessed ${pathCount} different paths — browsing pattern`);
  }

  score = Math.max(0, Math.min(100, score));
  const verdict = scoreToVerdict(score);
  return { verdict, reason: reasons.join('; '), score };
}

function scoreToVerdict(score: number): FPVerdict {
  if (score > 75) return 'highly_likely_fp';
  if (score > 55) return 'likely_fp';
  if (score > 35) return 'ambiguous';
  if (score > 15) return 'likely_tp';
  return 'confirmed_tp';
}
