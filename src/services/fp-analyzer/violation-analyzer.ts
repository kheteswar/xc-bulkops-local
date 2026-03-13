import type {
  ViolationAnalysisUnit,
  PathStats,
  SecurityEventIndexes,
  SignalResult,
  FPVerdict,
} from './types';
import { computeAllSignals } from './fp-scorer';
import {
  mapToRecord,
  mergeNormalTimestamps,
  mergeNormalCountries,
} from './signal-calculator';
import { generateViolationExclusion } from './exclusion-generator';
import { analysisLogger } from './analysis-logger';

// ═══════════════════════════════════════════════════════════════
// ALWAYS-TP VIOLATIONS (never suggest excluding these)
// ═══════════════════════════════════════════════════════════════

const ALWAYS_TP_VIOLATIONS = new Set([
  'VIOL_EVASION_DIRECTORY_TRAVERSALS',
  'VIOL_EVASION_BAD_UNESCAPE',
  'VIOL_EVASION_MULTIPLE_DECODING',
  'VIOL_ATTACK_SIGNATURE',
]);

// ═══════════════════════════════════════════════════════════════
// OFTEN-FP VIOLATIONS (high FP severity score)
// ═══════════════════════════════════════════════════════════════

const OFTEN_FP_VIOLATIONS = new Set([
  'VIOL_JSON_MALFORMED',
  'VIOL_XML_MALFORMED',
  'VIOL_HTTP_PROTOCOL',
  'VIOL_PARAMETER_VALUE_LENGTH',
  'VIOL_PARAMETER_DATA_TYPE',
  'VIOL_PARAMETER_NUMERIC_VALUE',
  'VIOL_URL_LENGTH',
  'VIOL_HEADER_LENGTH',
  'VIOL_POST_DATA_LENGTH',
  'VIOL_REQUEST_MAX_LENGTH',
  'VIOL_COOKIE_LENGTH',
]);

/**
 * Compute violation severity signal (replaces Signal 7: Signature Accuracy)
 */
function violationSeverityScore(violationName: string): { score: number; reason: string } {
  if (ALWAYS_TP_VIOLATIONS.has(violationName)) {
    return { score: 5, reason: `${violationName} is an always-TP violation — never exclude` };
  }
  if (OFTEN_FP_VIOLATIONS.has(violationName)) {
    return { score: 80, reason: `${violationName} is an often-FP violation — protocol/format mismatch` };
  }
  // Check partial matches for HTTP protocol variants
  if (violationName.startsWith('VIOL_HTTP_PROTOCOL')) {
    return { score: 70, reason: `HTTP protocol violation — often caused by non-standard clients` };
  }
  return { score: 50, reason: `Unknown violation severity — needs investigation` };
}

// ═══════════════════════════════════════════════════════════════
// ANALYZE VIOLATIONS
// ═══════════════════════════════════════════════════════════════

export function analyzeViolations(
  indexes: SecurityEventIndexes,
  pathStats: Map<string, PathStats>,
): ViolationAnalysisUnit[] {
  const units: ViolationAnalysisUnit[] = [];
  const totalAppPaths = pathStats.size;
  const normalTimestamps = mergeNormalTimestamps(pathStats);
  const normalCountries = mergeNormalCountries(pathStats);

  // Count paths per violation
  const violPathCounts = new Map<string, number>();
  for (const [violName, violEntry] of indexes.violationIndex) {
    violPathCounts.set(violName, violEntry.contexts.size);
  }

  for (const [violName, violEntry] of indexes.violationIndex) {
    const pathCount = violPathCounts.get(violName) || 1;

    for (const [, ctx] of violEntry.contexts) {
      const ps = pathStats.get(ctx.path);
      const totalRequestsOnPath = ps?.totalRequests || 0;
      const totalUsersOnPath = ps?.totalUsers || 0;
      const flaggedUsers = ctx.uniqueUsers.size;
      const requestRatio = totalRequestsOnPath > 0 ? ctx.eventCount / totalRequestsOnPath : 0;
      const userRatio = totalUsersOnPath > 0 ? flaggedUsers / totalUsersOnPath : 0;

      const uaRecord = mapToRecord(ctx.userAgents);
      const countriesRecord = mapToRecord(ctx.countries);
      const methodsRecord = mapToRecord(ctx.methods);

      // Compute standard 6 signals
      const baseSignals = computeAllSignals({
        flaggedUsers,
        flaggedIPs: flaggedUsers, // violations don't track IPs separately
        eventCount: ctx.eventCount,
        totalUsersOnPath,
        totalRequestsOnPath,
        pathCount,
        totalAppPaths,
        contextType: 'violation',
        contextName: violName,
        userAgents: uaRecord,
        botClassifications: {},
        trustScores: [],
        countries: countriesRecord,
        normalCountries,
        timestamps: ctx.timestamps,
        normalTimestamps,
        accuracy: 'medium_accuracy',
        sigState: 'Enabled',
        aiConfirmed: false,
        violationRatings: [],
      });

      // Override Signal 7 with violation severity
      const violSeverity = violationSeverityScore(violName);
      const adjustedSignals: SignalResult = {
        ...baseSignals,
        signatureAccuracy: {
          score: violSeverity.score,
          rawValue: violSeverity.score,
          reason: violSeverity.reason,
        },
      };

      // Recompute composite with the overridden signal
      const composite = Math.round(
        adjustedSignals.userBreadth.score * 0.25 +
        adjustedSignals.requestBreadth.score * 0.25 +
        adjustedSignals.pathBreadth.score * 0.10 +
        adjustedSignals.contextAnalysis.score * 0.10 +
        adjustedSignals.clientProfile.score * 0.10 +
        adjustedSignals.temporalPattern.score * 0.10 +
        adjustedSignals.signatureAccuracy.score * 0.10,
      );
      adjustedSignals.compositeScore = composite;
      adjustedSignals.verdict = scoreToVerdict(composite);

      // Force always-TP violations to TP verdict
      if (ALWAYS_TP_VIOLATIONS.has(violName)) {
        adjustedSignals.compositeScore = Math.min(adjustedSignals.compositeScore, 15);
        adjustedSignals.verdict = 'confirmed_tp';
        adjustedSignals.overrideApplied = 'ALWAYS_TP_VIOLATION';
        adjustedSignals.overrideReason = `${violName} is classified as always-TP — never exclude`;
      }

      const unit: ViolationAnalysisUnit = {
        violationName: violName,
        attackType: violEntry.attackType,
        path: ctx.path,
        rawPaths: ctx.rawPaths,
        pathCount,
        pathCounts: ctx.rawPaths.reduce<Record<string, number>>((acc, p) => { acc[p] = (acc[p] || 0) + 1; return acc; }, {}),
        eventCount: ctx.eventCount,
        flaggedUsers,
        flaggedIPs: flaggedUsers,
        ipCounts: {},
        totalRequestsOnPath,
        totalUsersOnPath,
        userRatio,
        requestRatio,
        userAgents: uaRecord,
        countries: countriesRecord,
        methods: methodsRecord,
        sampleMatchingInfos: ctx.sampleMatchingInfos,
        timestamps: ctx.timestamps,
        signals: adjustedSignals,
      };

      // Generate exclusion for FP verdicts
      if (
        (adjustedSignals.verdict === 'highly_likely_fp' || adjustedSignals.verdict === 'likely_fp')
        && !ALWAYS_TP_VIOLATIONS.has(violName)
      ) {
        unit.suggestedExclusion = generateViolationExclusion(
          violName, 'CONTEXT_BODY', '', '*', ctx.path, Object.keys(ctx.methods),
        );
      }

      units.push(unit);

      analysisLogger.logViolationAnalysis(violName, ctx.path, adjustedSignals.compositeScore, adjustedSignals.verdict);
    }
  }

  units.sort((a, b) => b.signals.compositeScore - a.signals.compositeScore);
  return units;
}

function scoreToVerdict(score: number): FPVerdict {
  if (score > 75) return 'highly_likely_fp';
  if (score > 55) return 'likely_fp';
  if (score > 35) return 'ambiguous';
  if (score > 15) return 'likely_tp';
  return 'confirmed_tp';
}
