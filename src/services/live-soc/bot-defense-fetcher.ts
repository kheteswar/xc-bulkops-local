// =============================================================================
// Live SOC Monitoring Room — Bot Defense Fetcher
// Wrapper around the Bot Defense Reporting API endpoints.
// Returns null gracefully if Bot Defense is not enabled for the load balancer.
// =============================================================================

import { apiClient } from '../api';
import type { BotTrafficOverview } from './types';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Safely extract a numeric value from an API response field. */
function safeNum(val: unknown, fallback = 0): number {
  const n = Number(val);
  return isNaN(n) ? fallback : n;
}

/** Build the base path for Bot Defense data API. */
function bdBasePath(namespace: string, lbName: string): string {
  return `/api/data/namespaces/${namespace}/bot_defense/virtual_host/${lbName}`;
}

// ---------------------------------------------------------------------------
// Sub-fetchers — each wraps a single Bot Defense API call
// ---------------------------------------------------------------------------

interface TrafficOverviewResponse {
  total?: number;
  human?: number;
  good_bot?: number;
  malicious_bot?: number;
  human_pct?: number;
  good_bot_pct?: number;
  malicious_bot_pct?: number;
}

async function fetchTrafficOverview(
  namespace: string,
  lbName: string,
  startTime: string,
  endTime: string,
): Promise<TrafficOverviewResponse | null> {
  try {
    return await apiClient.post<TrafficOverviewResponse>(
      `${bdBasePath(namespace, lbName)}/traffic/overview`,
      { start_time: startTime, end_time: endTime, namespace },
    );
  } catch {
    return null;
  }
}

interface AttackIntentItem {
  key?: string;
  name?: string;
  intent?: string;
  count?: number;
  doc_count?: number;
  pct?: number;
}

async function fetchAttackIntent(
  namespace: string,
  lbName: string,
  startTime: string,
  endTime: string,
): Promise<AttackIntentItem[]> {
  try {
    const res = await apiClient.post<{ items?: AttackIntentItem[]; buckets?: AttackIntentItem[] }>(
      `${bdBasePath(namespace, lbName)}/top/type/malicious/dimension/attackintent`,
      { start_time: startTime, end_time: endTime, namespace },
    );
    return res.items ?? res.buckets ?? [];
  } catch {
    return [];
  }
}

interface MaliciousIpItem {
  key?: string;
  ip?: string;
  count?: number;
  doc_count?: number;
}

async function fetchTopMaliciousIps(
  namespace: string,
  lbName: string,
  startTime: string,
  endTime: string,
): Promise<MaliciousIpItem[]> {
  try {
    const res = await apiClient.post<{ items?: MaliciousIpItem[]; buckets?: MaliciousIpItem[] }>(
      `${bdBasePath(namespace, lbName)}/top/type/malicious/dimension/ip`,
      { start_time: startTime, end_time: endTime, namespace },
    );
    return res.items ?? res.buckets ?? [];
  } catch {
    return [];
  }
}

interface CredStuffingResponse {
  detected?: boolean;
  is_active?: boolean;
  attack_detected?: boolean;
  events?: unknown[];
}

async function fetchCredentialStuffing(
  namespace: string,
  lbName: string,
  startTime: string,
  endTime: string,
): Promise<boolean> {
  try {
    const res = await apiClient.post<CredStuffingResponse>(
      `${bdBasePath(namespace, lbName)}/insight/credential-stuffing-attack`,
      { start_time: startTime, end_time: endTime, namespace },
    );
    return (
      res.detected === true ||
      res.is_active === true ||
      res.attack_detected === true ||
      (Array.isArray(res.events) && res.events.length > 0)
    );
  } catch {
    return false;
  }
}

interface MitigationActionItem {
  key?: string;
  action?: string;
  count?: number;
  doc_count?: number;
  pct?: number;
}

async function fetchMitigationActions(
  namespace: string,
  lbName: string,
  startTime: string,
  endTime: string,
): Promise<MitigationActionItem[]> {
  try {
    const res = await apiClient.post<{ items?: MitigationActionItem[]; buckets?: MitigationActionItem[] }>(
      `${bdBasePath(namespace, lbName)}/traffic/malicious/overview/actions`,
      { start_time: startTime, end_time: endTime, namespace },
    );
    return res.items ?? res.buckets ?? [];
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// fetchBotOverview — main public function
// ---------------------------------------------------------------------------

/**
 * Fetch a comprehensive Bot Defense overview for a given load balancer.
 *
 * Calls five Bot Defense Reporting API endpoints in parallel. Each sub-call
 * is independently try-caught so a partial failure does not lose all data.
 *
 * Returns `null` if the traffic overview call fails (which typically means
 * Bot Defense is not enabled for this virtual host).
 *
 * @param namespace - XC namespace
 * @param lbName   - HTTP load balancer name
 * @param startTime - ISO start time (defaults to 5 min ago)
 * @param endTime   - ISO end time (defaults to now)
 */
export async function fetchBotOverview(
  namespace: string,
  lbName: string,
  startTime?: string,
  endTime?: string,
): Promise<BotTrafficOverview | null> {
  const end = endTime ?? new Date().toISOString();
  const start =
    startTime ?? new Date(Date.now() - 5 * 60 * 1000).toISOString();

  // Fire all sub-fetchers concurrently
  const [overview, attackIntentItems, maliciousIps, credStuffing, mitigationItems] =
    await Promise.all([
      fetchTrafficOverview(namespace, lbName, start, end),
      fetchAttackIntent(namespace, lbName, start, end),
      fetchTopMaliciousIps(namespace, lbName, start, end),
      fetchCredentialStuffing(namespace, lbName, start, end),
      fetchMitigationActions(namespace, lbName, start, end),
    ]);

  // If the main traffic overview failed, Bot Defense is likely not enabled
  if (!overview) {
    return null;
  }

  const totalRequests = safeNum(overview.total, 0);

  // Compute percentages — API may provide them directly or we derive from counts
  const humanPct =
    safeNum(overview.human_pct) ||
    (totalRequests > 0 ? (safeNum(overview.human) / totalRequests) * 100 : 0);
  const goodBotPct =
    safeNum(overview.good_bot_pct) ||
    (totalRequests > 0 ? (safeNum(overview.good_bot) / totalRequests) * 100 : 0);
  const maliciousBotPct =
    safeNum(overview.malicious_bot_pct) ||
    (totalRequests > 0 ? (safeNum(overview.malicious_bot) / totalRequests) * 100 : 0);

  // Map attack intent
  const attackIntent = attackIntentItems.map((item) => {
    const count = safeNum(item.count ?? item.doc_count);
    return {
      intent: item.key ?? item.name ?? item.intent ?? 'unknown',
      count,
      pct: safeNum(item.pct) || (totalRequests > 0 ? (count / totalRequests) * 100 : 0),
    };
  });

  // Map top malicious IPs
  const topMaliciousIps = maliciousIps
    .map((item) => ({
      ip: item.key ?? item.ip ?? 'unknown',
      count: safeNum(item.count ?? item.doc_count),
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  // Map mitigation actions
  const mitigationActions = mitigationItems.map((item) => {
    const count = safeNum(item.count ?? item.doc_count);
    return {
      action: item.key ?? item.action ?? 'unknown',
      count,
      pct: safeNum(item.pct) || (totalRequests > 0 ? (count / totalRequests) * 100 : 0),
    };
  });

  return {
    humanPct: Math.round(humanPct * 100) / 100,
    goodBotPct: Math.round(goodBotPct * 100) / 100,
    maliciousBotPct: Math.round(maliciousBotPct * 100) / 100,
    totalRequests,
    attackIntent,
    topMaliciousIps,
    topMaliciousUAs: [], // UA dimension not fetched here — can be extended
    credentialStuffingDetected: credStuffing,
    mitigationActions,
  };
}
