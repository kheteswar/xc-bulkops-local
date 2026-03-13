import type {
  SignatureIndexEntry,
  SignatureAnalysisUnit,
  PathStats,
  SecurityEventIndexes,
} from './types';
import { computeAllSignals, applyScenario2Override } from './fp-scorer';
import {
  mapToRecord,
  mergeNormalTimestamps,
  mergeNormalCountries,
} from './signal-calculator';
import { analysisLogger, sanitizePath } from './analysis-logger';

// ═══════════════════════════════════════════════════════════════
// SIGNATURE ANALYZER
// ═══════════════════════════════════════════════════════════════

/**
 * Analyze all WAF signatures from the security event index.
 * Each analysis unit = (signature_id + context + path).
 * Returns units sorted by composite score descending (most likely FP first).
 */
export function analyzeSignatures(
  indexes: SecurityEventIndexes,
  pathStats: Map<string, PathStats>,
): SignatureAnalysisUnit[] {
  const units: SignatureAnalysisUnit[] = [];
  const totalAppPaths = pathStats.size;
  const normalTimestamps = mergeNormalTimestamps(pathStats);
  const normalCountries = mergeNormalCountries(pathStats);

  // Count total unique paths per signature (for pathBreadth)
  const sigPathCounts = new Map<string, Set<string>>();
  for (const [sigId, sigEntry] of indexes.signatureIndex) {
    const paths = new Set<string>();
    for (const ctx of sigEntry.contexts.values()) {
      paths.add(ctx.path);
    }
    sigPathCounts.set(sigId, paths);
  }

  for (const [sigId, sigEntry] of indexes.signatureIndex) {
    const pathCount = sigPathCounts.get(sigId)?.size || 1;

    // If too many contexts (>50 paths for same sig), aggregate into app-wide bucket
    if (sigEntry.contexts.size > 50) {
      const aggregated = buildAggregatedUnit(sigId, sigEntry, pathStats, totalAppPaths, pathCount, normalTimestamps, normalCountries);
      if (aggregated) units.push(aggregated);
      continue;
    }

    for (const [, ctx] of sigEntry.contexts) {
      const ps = pathStats.get(ctx.path);
      const totalRequestsOnPath = ps?.totalRequests || 0;
      const totalUsersOnPath = ps?.totalUsers || 0;
      const flaggedUsers = ctx.uniqueUsers.size;
      const flaggedIPs = ctx.uniqueIPs.size;
      const requestRatio = totalRequestsOnPath > 0 ? ctx.eventCount / totalRequestsOnPath : 0;
      const userRatio = totalUsersOnPath > 0 ? flaggedUsers / totalUsersOnPath : 0;

      const uaRecord = mapToRecord(ctx.userAgents);
      const countriesRecord = mapToRecord(ctx.countries);
      const botRecord = mapToRecord(ctx.botClassifications);
      const methodsRecord = mapToRecord(ctx.methods);
      const rspCodesRecord = mapToRecord(ctx.rspCodes);

      const originAcceptedCount = ctx.rspCodes.get('200') || 0;

      // Compute all 7 signals
      let signals = computeAllSignals({
        flaggedUsers,
        flaggedIPs,
        eventCount: ctx.eventCount,
        totalUsersOnPath,
        totalRequestsOnPath,
        pathCount,
        totalAppPaths,
        contextType: ctx.context,
        contextName: ctx.contextName,
        userAgents: uaRecord,
        botClassifications: botRecord,
        trustScores: ctx.trustScores,
        countries: countriesRecord,
        normalCountries,
        timestamps: ctx.timestamps,
        normalTimestamps,
        accuracy: sigEntry.accuracy,
        sigState: sigEntry.state,
        aiConfirmed: ctx.aiConfirmed,
        violationRatings: ctx.violationRatings,
      });

      // Apply Scenario 2 override
      signals = applyScenario2Override(
        signals,
        pathCount,
        requestRatio,
        totalUsersOnPath,
        rspCodesRecord,
      );

      units.push({
        signatureId: sigId,
        signatureName: sigEntry.name,
        attackType: sigEntry.attackType,
        accuracy: sigEntry.accuracy,
        contextType: ctx.context,
        contextName: ctx.contextName,
        contextRaw: ctx.contextRaw,
        path: ctx.path,
        rawPaths: ctx.rawPaths,
        pathCount,
        pathCounts: ctx.rawPaths.reduce<Record<string, number>>((acc, p) => { acc[p] = (acc[p] || 0) + 1; return acc; }, {}),
        eventCount: ctx.eventCount,
        flaggedUsers,
        flaggedIPs,
        ipCounts: {},
        totalRequestsOnPath,
        totalUsersOnPath,
        userRatio,
        requestRatio,
        userAgents: uaRecord,
        countries: countriesRecord,
        trustScores: ctx.trustScores,
        botClassifications: botRecord,
        methods: methodsRecord,
        sampleMatchingInfos: ctx.sampleMatchingInfo,
        sampleReqParams: ctx.sampleReqParams,
        timestamps: ctx.timestamps,
        rspCodes: rspCodesRecord,
        originAcceptedCount,
        violationRatings: ctx.violationRatings,
        reqRiskReasons: ctx.reqRiskReasons,
        aiConfirmed: ctx.aiConfirmed,
        sigState: sigEntry.state,
        signals,
      });

      analysisLogger.logSignatureAnalysis(sigId, sigEntry.name, sanitizePath(ctx.path), {
        composite: signals.compositeScore,
        verdict: signals.verdict,
        userBreadth: signals.userBreadth.score,
        requestBreadth: signals.requestBreadth.score,
        pathBreadth: signals.pathBreadth.score,
        contextAnalysis: signals.contextAnalysis.score,
        clientProfile: signals.clientProfile.score,
        temporalPattern: signals.temporalPattern.score,
        signatureAccuracy: signals.signatureAccuracy.score,
        override: signals.overrideApplied,
        flaggedUsers,
        totalUsers: totalUsersOnPath,
        flaggedRequests: ctx.eventCount,
        totalRequests: totalRequestsOnPath,
        pathCount,
      });
    }
  }

  // Sort by composite score descending (most likely FP first)
  units.sort((a, b) => b.signals.compositeScore - a.signals.compositeScore);

  return units;
}

// ═══════════════════════════════════════════════════════════════
// AGGREGATED UNIT FOR HIGH-PATH-COUNT SIGNATURES
// ═══════════════════════════════════════════════════════════════

function buildAggregatedUnit(
  sigId: string,
  sigEntry: SignatureIndexEntry,
  pathStats: Map<string, PathStats>,
  totalAppPaths: number,
  pathCount: number,
  normalTimestamps: string[],
  normalCountries: Record<string, number>,
): SignatureAnalysisUnit | null {
  let totalEvents = 0;
  const allUsers = new Set<string>();
  const allIPs = new Set<string>();
  const allUA = new Map<string, number>();
  const allCountries = new Map<string, number>();
  const allBots = new Map<string, number>();
  const allMethods = new Map<string, number>();
  const allRspCodes = new Map<string, number>();
  const allTimestamps: string[] = [];
  const allTrustScores: number[] = [];
  const allViolRatings: number[] = [];
  const sampleMatching: string[] = [];
  const sampleParams: string[] = [];
  const rawPaths: string[] = [];
  let aiConfirmed = false;
  const reqRiskReasons: string[] = [];
  let totalRequestsAgg = 0;
  let totalUsersAgg = 0;

  // Use first context for type info
  let firstCtxType = '';
  let firstCtxName = '';
  let firstCtxRaw = '';

  for (const ctx of sigEntry.contexts.values()) {
    if (!firstCtxType) { firstCtxType = ctx.context; firstCtxName = ctx.contextName; firstCtxRaw = ctx.contextRaw; }

    totalEvents += ctx.eventCount;
    for (const u of ctx.uniqueUsers) allUsers.add(u);
    for (const ip of ctx.uniqueIPs) allIPs.add(ip);
    mergeMap(allUA, ctx.userAgents);
    mergeMap(allCountries, ctx.countries);
    mergeMap(allBots, ctx.botClassifications);
    mergeMap(allMethods, ctx.methods);
    mergeMap(allRspCodes, ctx.rspCodes);
    allTimestamps.push(...ctx.timestamps.slice(0, 100));
    allTrustScores.push(...ctx.trustScores);
    allViolRatings.push(...ctx.violationRatings);
    if (sampleMatching.length < 10) sampleMatching.push(...ctx.sampleMatchingInfo.slice(0, 10 - sampleMatching.length));
    if (sampleParams.length < 10) sampleParams.push(...ctx.sampleReqParams.slice(0, 10 - sampleParams.length));
    if (rawPaths.length < 10 && !rawPaths.includes(ctx.path)) rawPaths.push(ctx.path);
    if (ctx.aiConfirmed) aiConfirmed = true;
    for (const r of ctx.reqRiskReasons) {
      if (!reqRiskReasons.includes(r)) reqRiskReasons.push(r);
    }

    const ps = pathStats.get(ctx.path);
    if (ps) {
      totalRequestsAgg += ps.totalRequests;
      totalUsersAgg += ps.totalUsers;
    }
  }

  const flaggedUsers = allUsers.size;
  const flaggedIPs = allIPs.size;
  const requestRatio = totalRequestsAgg > 0 ? totalEvents / totalRequestsAgg : 0;
  const userRatio = totalUsersAgg > 0 ? flaggedUsers / totalUsersAgg : 0;

  const uaRecord = mapToRecord(allUA);
  const countriesRecord = mapToRecord(allCountries);
  const botRecord = mapToRecord(allBots);
  const methodsRecord = mapToRecord(allMethods);
  const rspCodesRecord = mapToRecord(allRspCodes);
  const originAcceptedCount = allRspCodes.get('200') || 0;

  const signals = computeAllSignals({
    flaggedUsers,
    flaggedIPs,
    eventCount: totalEvents,
    totalUsersOnPath: totalUsersAgg,
    totalRequestsOnPath: totalRequestsAgg,
    pathCount,
    totalAppPaths,
    contextType: firstCtxType,
    contextName: firstCtxName,
    userAgents: uaRecord,
    botClassifications: botRecord,
    trustScores: allTrustScores,
    countries: countriesRecord,
    normalCountries,
    timestamps: allTimestamps,
    normalTimestamps,
    accuracy: sigEntry.accuracy,
    sigState: sigEntry.state,
    aiConfirmed,
    violationRatings: allViolRatings,
  });

  return {
    signatureId: sigId,
    signatureName: sigEntry.name,
    attackType: sigEntry.attackType,
    accuracy: sigEntry.accuracy,
    contextType: firstCtxType,
    contextName: firstCtxName,
    contextRaw: firstCtxRaw,
    path: '(Application-Wide)',
    rawPaths,
    pathCount,
    pathCounts: rawPaths.reduce<Record<string, number>>((acc, p) => { acc[p] = (acc[p] || 0) + 1; return acc; }, {}),
    eventCount: totalEvents,
    flaggedUsers,
    flaggedIPs,
    ipCounts: {},
    totalRequestsOnPath: totalRequestsAgg,
    totalUsersOnPath: totalUsersAgg,
    userRatio,
    requestRatio,
    userAgents: uaRecord,
    countries: countriesRecord,
    trustScores: allTrustScores,
    botClassifications: botRecord,
    methods: methodsRecord,
    sampleMatchingInfos: sampleMatching,
    sampleReqParams: sampleParams,
    timestamps: allTimestamps,
    rspCodes: rspCodesRecord,
    originAcceptedCount,
    violationRatings: allViolRatings,
    reqRiskReasons,
    aiConfirmed,
    sigState: sigEntry.state,
    signals,
  };
}

function mergeMap(target: Map<string, number>, source: Map<string, number>): void {
  for (const [k, v] of source) {
    target.set(k, (target.get(k) || 0) + v);
  }
}
