import { normalizePath } from '../rate-limit-advisor/path-analyzer';
import { parseContext } from './context-parser';
import type {
  SecurityEventEntry,
  SecurityEventIndexes,
  SignatureIndexEntry,
  SignatureContextData,
  ViolationIndexEntry,
  ThreatMeshIndexEntry,
  ThreatMeshDetails,
  PolicyIndexEntry,
} from './types';

function incMap(map: Map<string, number>, key: string): void {
  map.set(key, (map.get(key) || 0) + 1);
}

function getField(event: SecurityEventEntry, ...fields: string[]): string {
  for (const f of fields) {
    const val = (event as Record<string, unknown>)[f];
    if (val != null && val !== '') return String(val);
  }
  return '';
}

function getNumField(event: SecurityEventEntry, ...fields: string[]): number {
  for (const f of fields) {
    const val = (event as Record<string, unknown>)[f];
    if (val != null) {
      const n = Number(val);
      if (!isNaN(n)) return n;
    }
  }
  return 0;
}

function createSignatureContextData(path: string, contextType: string, contextName: string, contextRaw: string): SignatureContextData {
  return {
    path,
    context: contextType,
    contextName,
    contextRaw,
    eventCount: 0,
    uniqueUsers: new Set(),
    uniqueIPs: new Set(),
    userAgents: new Map(),
    countries: new Map(),
    trustScores: [],
    botClassifications: new Map(),
    methods: new Map(),
    sampleMatchingInfo: [],
    sampleReqParams: [],
    timestamps: [],
    rspCodes: new Map(),
    violationRatings: [],
    reqRiskReasons: [],
    aiConfirmed: false,
    rawPaths: [],
  };
}

function processWafSignatures(
  event: SecurityEventEntry,
  signatureIndex: Map<string, SignatureIndexEntry>,
  userId: string,
  srcIp: string
): void {
  const sigs = (event as Record<string, unknown>).signatures as Array<Record<string, unknown>> | undefined;
  if (!sigs || !Array.isArray(sigs)) return;

  const rawPath = getField(event, 'req_path');
  const path = normalizePath(rawPath);
  const method = getField(event, 'method') || 'GET';
  const country = getField(event, 'country');
  const ua = getField(event, 'user_agent');
  const rspCode = getField(event, 'rsp_code');
  const violationRating = getNumField(event, 'violation_rating');
  const timestamp = getField(event, '@timestamp', 'time');
  const reqParams = getField(event, 'req_params');
  const botClass = getField(event, 'bot_info.classification');

  const riskReasons = (event as Record<string, unknown>).req_risk_reasons;
  const reqRiskArr: string[] = Array.isArray(riskReasons) ? riskReasons.map(String) : [];
  const aiConfirmed = reqRiskArr.some(r => /AI.*confirm.*100%/i.test(r));

  // Extract trust score from policy_hits
  let trustScore = 0;
  const policyHits = (event as Record<string, unknown>).policy_hits as Record<string, unknown> | undefined;
  if (policyHits) {
    const hits = policyHits.policy_hits as Array<Record<string, unknown>> | undefined;
    if (hits && hits.length > 0) {
      trustScore = Number(hits[0].ip_trustscore) || 0;
    }
  }

  for (const sig of sigs) {
    const sigId = String(sig.id || '');
    if (!sigId) continue;

    if (!signatureIndex.has(sigId)) {
      signatureIndex.set(sigId, {
        name: String(sig.name || ''),
        attackType: String(sig.attack_type || ''),
        accuracy: String(sig.accuracy || 'medium_accuracy'),
        risk: String(sig.risk || ''),
        state: String(sig.state || 'Enabled'),
        contexts: new Map(),
      });
    }

    const sigEntry = signatureIndex.get(sigId)!;
    const contextRaw = String(sig.context || '');
    const { contextType, contextName } = parseContext(contextRaw);
    const contextKey = `${path}|${contextType}|${contextName}`;

    if (!sigEntry.contexts.has(contextKey)) {
      sigEntry.contexts.set(contextKey, createSignatureContextData(path, contextType, contextName, contextRaw));
    }

    const ctx = sigEntry.contexts.get(contextKey)!;
    ctx.eventCount++;
    ctx.uniqueUsers.add(userId);
    ctx.uniqueIPs.add(srcIp);
    if (ua) incMap(ctx.userAgents, ua);
    if (country) incMap(ctx.countries, country);
    if (trustScore > 0) ctx.trustScores.push(trustScore);
    if (botClass) incMap(ctx.botClassifications, botClass);
    incMap(ctx.methods, method);
    if (rspCode) incMap(ctx.rspCodes, rspCode);
    if (timestamp) ctx.timestamps.push(timestamp);
    if (violationRating > 0) ctx.violationRatings.push(violationRating);

    if (sig.matching_info && ctx.sampleMatchingInfo.length < 10) {
      ctx.sampleMatchingInfo.push(String(sig.matching_info));
    }
    if (reqParams && ctx.sampleReqParams.length < 10) {
      ctx.sampleReqParams.push(reqParams);
    }
    if (aiConfirmed) ctx.aiConfirmed = true;
    for (const r of reqRiskArr) {
      if (!ctx.reqRiskReasons.includes(r)) ctx.reqRiskReasons.push(r);
    }
    if (ctx.rawPaths.length < 10 && !ctx.rawPaths.includes(rawPath)) {
      ctx.rawPaths.push(rawPath);
    }
  }
}

function processWafViolations(
  event: SecurityEventEntry,
  violationIndex: Map<string, ViolationIndexEntry>,
  userId: string
): void {
  const viols = (event as Record<string, unknown>).violations as Array<Record<string, unknown>> | undefined;
  if (!viols || !Array.isArray(viols)) return;

  const rawPath = getField(event, 'req_path');
  const path = normalizePath(rawPath);
  const method = getField(event, 'method') || 'GET';
  const country = getField(event, 'country');
  const ua = getField(event, 'user_agent');
  const timestamp = getField(event, '@timestamp', 'time');

  for (const viol of viols) {
    const violName = String(viol.name || '');
    if (!violName) continue;

    if (!violationIndex.has(violName)) {
      violationIndex.set(violName, {
        attackType: String(viol.attack_type || ''),
        state: String(viol.state || 'Enabled'),
        contexts: new Map(),
      });
    }

    const violEntry = violationIndex.get(violName)!;
    if (!violEntry.contexts.has(path)) {
      violEntry.contexts.set(path, {
        path,
        eventCount: 0,
        uniqueUsers: new Set(),
        userAgents: new Map(),
        countries: new Map(),
        methods: new Map(),
        timestamps: [],
        rawPaths: [],
        sampleMatchingInfos: [],
      });
    }

    const ctx = violEntry.contexts.get(path)!;
    ctx.eventCount++;
    ctx.uniqueUsers.add(userId);
    if (ua) incMap(ctx.userAgents, ua);
    if (country) incMap(ctx.countries, country);
    incMap(ctx.methods, method);
    if (timestamp) ctx.timestamps.push(timestamp);
    if (ctx.rawPaths.length < 10 && !ctx.rawPaths.includes(rawPath)) {
      ctx.rawPaths.push(rawPath);
    }
  }
}

function processThreatMesh(
  event: SecurityEventEntry,
  threatMeshIndex: Map<string, ThreatMeshIndexEntry>,
  srcIp: string
): void {
  const tmDetails = (event as Record<string, unknown>).threat_mesh_details as Record<string, unknown> | undefined;

  const details: ThreatMeshDetails = {
    description: tmDetails ? String(tmDetails.description || '') : '',
    attackTypes: Array.isArray(tmDetails?.attack_types) ? (tmDetails.attack_types as string[]) : [],
    events: Number(tmDetails?.events) || 0,
    tenantCount: Number(tmDetails?.tenant_count) || 0,
    highAccuracySignatures: Number(tmDetails?.high_accuracy_signatures) || 0,
    tlsCount: Number(tmDetails?.tls_count) || 0,
    maliciousBotEvents: Number(tmDetails?.malicious_bot_events) || 0,
  };

  const rawPath = getField(event, 'req_path');
  const path = normalizePath(rawPath);
  const ua = getField(event, 'user_agent');
  const country = getField(event, 'country');
  const timestamp = getField(event, '@timestamp', 'time');
  const asOrg = getField(event, 'as_org');
  const user = getField(event, 'user');

  if (!threatMeshIndex.has(srcIp)) {
    threatMeshIndex.set(srcIp, {
      threatDetails: details,
      user: user || srcIp,
      eventCount: 0,
      paths: new Map(),
      userAgents: new Map(),
      countries: new Map(),
      timestamps: [],
      asOrg,
    });
  }

  const entry = threatMeshIndex.get(srcIp)!;
  entry.eventCount++;
  incMap(entry.paths, path);
  if (ua) incMap(entry.userAgents, ua);
  if (country) incMap(entry.countries, country);
  if (timestamp) entry.timestamps.push(timestamp);
  // Update threat details if this event has more info
  if (details.events > entry.threatDetails.events) {
    entry.threatDetails = details;
  }
}

function processServicePolicy(
  event: SecurityEventEntry,
  policyIndex: Map<string, PolicyIndexEntry>,
  srcIp: string
): void {
  const policyHits = (event as Record<string, unknown>).policy_hits as Record<string, unknown> | undefined;
  if (!policyHits) return;

  const hits = policyHits.policy_hits as Array<Record<string, unknown>> | undefined;
  if (!hits || !Array.isArray(hits)) return;

  const rawPath = getField(event, 'req_path');
  const path = normalizePath(rawPath);
  const ua = getField(event, 'user_agent');
  const country = getField(event, 'country');
  const user = getField(event, 'user');

  for (const hit of hits) {
    const policyRule = String(hit.policy_rule || hit.policy_set || 'unknown');
    const policy = String(hit.policy || '');
    const trustScore = Number(hit.ip_trustscore) || 0;
    const threatCats = String(hit.ip_threat_categories || '');

    if (!policyIndex.has(policyRule)) {
      policyIndex.set(policyRule, {
        policy,
        eventCount: 0,
        blockedIPs: new Map(),
      });
    }

    const entry = policyIndex.get(policyRule)!;
    entry.eventCount++;

    if (!entry.blockedIPs.has(srcIp)) {
      entry.blockedIPs.set(srcIp, {
        count: 0,
        user: user || srcIp,
        userAgent: ua,
        trustScore,
        threatCategories: threatCats,
        country,
        paths: new Map(),
      });
    }

    const ipEntry = entry.blockedIPs.get(srcIp)!;
    ipEntry.count++;
    incMap(ipEntry.paths, path);
  }
}

/**
 * Build in-memory indexes from security events for all 4 analysis scopes.
 */
export function buildSecurityEventIndexes(events: SecurityEventEntry[]): SecurityEventIndexes {
  const signatureIndex = new Map<string, SignatureIndexEntry>();
  const violationIndex = new Map<string, ViolationIndexEntry>();
  const threatMeshIndex = new Map<string, ThreatMeshIndexEntry>();
  const policyIndex = new Map<string, PolicyIndexEntry>();
  const reqIdSet = new Set<string>();

  let wafEvents = 0;
  let threatMeshEvents = 0;
  let policyEvents = 0;

  for (const event of events) {
    const reqId = getField(event, 'req_id');
    if (reqId) reqIdSet.add(reqId);

    const srcIp = getField(event, 'src_ip');
    const userId = getField(event, 'user') || srcIp || 'unknown';
    const secEventType = getField(event, 'sec_event_type');
    const secEventName = getField(event, 'sec_event_name');

    if (secEventType === 'waf_sec_event') {
      wafEvents++;
      processWafSignatures(event, signatureIndex, userId, srcIp);
      processWafViolations(event, violationIndex, userId);
    } else if (secEventName === 'Threat Mesh') {
      threatMeshEvents++;
      processThreatMesh(event, threatMeshIndex, srcIp);
    } else if (secEventType === 'svc_policy_sec_event') {
      policyEvents++;
      processServicePolicy(event, policyIndex, srcIp);
    }
  }

  return {
    signatureIndex,
    violationIndex,
    threatMeshIndex,
    policyIndex,
    reqIdSet,
    stats: {
      totalEvents: events.length,
      wafEvents,
      threatMeshEvents,
      policyEvents,
      uniqueSignatures: signatureIndex.size,
      uniqueViolations: violationIndex.size,
      uniqueThreatMeshIPs: threatMeshIndex.size,
    },
  };
}
