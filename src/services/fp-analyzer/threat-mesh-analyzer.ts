import type {
  ThreatMeshAnalysisUnit,
  PathStats,
  SecurityEventIndexes,
  FPVerdict,
} from './types';
import { mapToRecord } from './signal-calculator';
import { analysisLogger } from './analysis-logger';

// ═══════════════════════════════════════════════════════════════
// KNOWN BOT PATTERNS
// ═══════════════════════════════════════════════════════════════

const BENIGN_BOT_RE = /bingbot|googlebot|yandexbot|baiduspider|slurp|duckduckbot|facebot|applebot|linkedinbot|twitterbot|pinterestbot/i;
const SCRIPTING_TOOL_RE = /python|curl|wget|httpie|go-http|java|axios|node-fetch|ruby|perl/i;
const EXPLOIT_PATHS = /\/wp-admin|\/phpmyadmin|\/\.env|\/cgi-bin|\/actuator|\/\.git|\/admin|\/shell|\/eval|\/exec/i;
const CDN_PROXY_ORGS = /cloudflare|akamai|fastly|google cloud|amazon|azure|microsoft/i;

// ═══════════════════════════════════════════════════════════════
// ANALYZE THREAT MESH
// ═══════════════════════════════════════════════════════════════

export function analyzeThreatMesh(
  indexes: SecurityEventIndexes,
  pathStats: Map<string, PathStats>,
): ThreatMeshAnalysisUnit[] {
  const units: ThreatMeshAnalysisUnit[] = [];

  // Check if IP also triggered WAF events (cross-reference signatureIndex)
  const wafIPs = new Map<string, number>();
  for (const sigEntry of indexes.signatureIndex.values()) {
    for (const ctx of sigEntry.contexts.values()) {
      for (const ip of ctx.uniqueIPs) {
        wafIPs.set(ip, (wafIPs.get(ip) || 0) + ctx.eventCount);
      }
    }
  }

  for (const [srcIp, entry] of indexes.threatMeshIndex) {
    const wafEventsFromThisIP = wafIPs.get(srcIp) || 0;

    // Get the primary user agent and country
    const topUA = getTopEntry(entry.userAgents) || '';
    const topCountry = getTopEntry(entry.countries) || '';

    // Compute total requests on app from access logs for this IP pattern
    let totalRequestsOnApp = 0;
    const rspCodes = new Map<string, number>();
    for (const [path, count] of entry.paths) {
      const ps = pathStats.get(path);
      if (ps) {
        totalRequestsOnApp += count; // events hitting this path
        for (const [code, cnt] of ps.rspCodes) {
          rspCodes.set(code, (rspCodes.get(code) || 0) + cnt);
        }
      }
    }

    // Custom scoring
    let fpScore = 50;
    const reasons: string[] = [];

    // --- TP signals (lower the FP score) ---

    // Tenant count
    if (entry.threatDetails.tenantCount >= 5) {
      fpScore -= 20;
      reasons.push(`Flagged by ${entry.threatDetails.tenantCount} tenants — widely recognized threat`);
    } else if (entry.threatDetails.tenantCount >= 3) {
      fpScore -= 10;
      reasons.push(`Flagged by ${entry.threatDetails.tenantCount} tenants`);
    }

    // Global event volume
    if (entry.threatDetails.events >= 1000) {
      fpScore -= 15;
      reasons.push(`${entry.threatDetails.events.toLocaleString()} attack events globally`);
    } else if (entry.threatDetails.events >= 100) {
      fpScore -= 5;
      reasons.push(`${entry.threatDetails.events} attack events globally`);
    }

    // High accuracy signatures on other tenants
    if (entry.threatDetails.highAccuracySignatures > 0) {
      fpScore -= 10;
      reasons.push(`${entry.threatDetails.highAccuracySignatures} high-accuracy signature matches on other tenants`);
    }

    // Also triggered WAF on this app
    if (wafEventsFromThisIP > 0) {
      fpScore -= 15;
      reasons.push(`Also triggered ${wafEventsFromThisIP} WAF events on this app`);
    }

    // Scripting tool user agent
    if (SCRIPTING_TOOL_RE.test(topUA)) {
      fpScore -= 10;
      reasons.push('Uses scripting tool user agent');
    }

    // Exploit path scanning
    const pathKeys = [...entry.paths.keys()];
    const exploitPathCount = pathKeys.filter(p => EXPLOIT_PATHS.test(p)).length;
    if (exploitPathCount > 0) {
      fpScore -= 10;
      reasons.push(`Probed ${exploitPathCount} exploit paths (wp-admin, phpmyadmin, etc.)`);
    }

    // --- FP signals (raise the FP score) ---

    // Known benign bot
    if (BENIGN_BOT_RE.test(topUA)) {
      fpScore += 30;
      reasons.push('Known search engine bot (Bingbot, Googlebot, etc.)');
    }

    // CDN/proxy ASN
    if (CDN_PROXY_ORGS.test(entry.asOrg)) {
      fpScore += 15;
      reasons.push(`IP from CDN/proxy provider: ${entry.asOrg}`);
    }

    // No WAF events on this app
    if (wafEventsFromThisIP === 0) {
      fpScore += 15;
      reasons.push('No WAF events on this app — only Threat Mesh flagged this IP');
    }

    // Low tenant count
    if (entry.threatDetails.tenantCount <= 2) {
      fpScore += 10;
      reasons.push(`Low tenant count (${entry.threatDetails.tenantCount}) — possibly shared IP`);
    }

    // Sequential page crawling (many different content paths)
    const uniquePaths = pathKeys.length;
    if (uniquePaths > 10 && exploitPathCount === 0) {
      fpScore += 10;
      reasons.push(`Accessed ${uniquePaths} unique content paths — sequential crawling pattern`);
    }

    fpScore = Math.max(0, Math.min(100, fpScore));
    const verdict = scoreToVerdict(fpScore);

    // Suggested action
    let suggestedAction: 'trusted_client' | 'no_action' | undefined;
    if (verdict === 'highly_likely_fp' || verdict === 'likely_fp') {
      suggestedAction = 'trusted_client';
    }

    units.push({
      srcIp,
      user: entry.user,
      threatDetails: entry.threatDetails,
      totalRequestsOnApp,
      pathsAccessed: mapToRecord(entry.paths),
      userAgent: topUA,
      country: topCountry,
      asOrg: entry.asOrg,
      rspCodes: mapToRecord(rspCodes),
      wafEventsFromThisIP,
      fpScore,
      verdict,
      reasons,
      suggestedAction,
    });

    analysisLogger.logThreatMeshAnalysis(srcIp, fpScore, verdict, reasons);
  }

  units.sort((a, b) => b.fpScore - a.fpScore);
  return units;
}

function getTopEntry(map: Map<string, number>): string | null {
  let top = '';
  let max = 0;
  for (const [k, v] of map) {
    if (v > max) { max = v; top = k; }
  }
  return top || null;
}

function scoreToVerdict(score: number): FPVerdict {
  if (score > 75) return 'highly_likely_fp';
  if (score > 55) return 'likely_fp';
  if (score > 35) return 'ambiguous';
  if (score > 15) return 'likely_tp';
  return 'confirmed_tp';
}
