// =============================================================================
// Live SOC Monitoring Room — Aggregation Query Builder
// =============================================================================
// Builds POST bodies for F5 XC aggregation APIs (Track 2).
//
// Access Log Aggregations (A1-A8):
//   A1: by rsp_code             → Response code distribution panel
//   A2: by rsp_code_details     → Error diagnosis panel
//   A3: by country              → Geo distribution panel
//   A4: by dst_ip               → Per-origin health grid
//   A5: by req_path (top 30)    → Hot paths panel
//   A6: by src_ip (top 30)      → Top talkers (non-security)
//   A7: by domain               → Per-domain breakdown
//   A8: by waf_action           → WAF action distribution
//
// Security Event Aggregations (S1-S5):
//   S1: by sec_event_name       → Security breakdown donut
//   S2: by signatures.id (top 20) → Top WAF signatures
//   S3: by src_ip (top 20)      → Top attacking IPs
//   S4: by country              → Security geo distribution
//   S5: by violations.name      → Top violations
// =============================================================================

import type { AggregationQuery } from './types';

// ---------------------------------------------------------------------------
// LB Query Builder
// ---------------------------------------------------------------------------

/**
 * Builds the vh_name filter query string for aggregation API calls.
 *
 * Single LB:  `{vh_name="ves-io-http-loadbalancer-lbname"}`
 * Multi-LB:   `{vh_name=~"ves-io-http-loadbalancer-lb1|ves-io-http-loadbalancer-lb2"}`
 */
export function buildLBQuery(lbNames: string[]): string {
  if (!lbNames || lbNames.length === 0) {
    return '{}';
  }

  const prefixed = lbNames.map((name) => {
    // Add the VES prefix if not already present
    if (name.startsWith('ves-io-http-loadbalancer-')) {
      return name;
    }
    return `ves-io-http-loadbalancer-${name}`;
  });

  if (prefixed.length === 1) {
    return `{vh_name="${prefixed[0]}"}`;
  }

  // Regex match for multiple LBs
  return `{vh_name=~"${prefixed.join('|')}"}`;
}

// ---------------------------------------------------------------------------
// Aggregation Body Builder
// ---------------------------------------------------------------------------

function buildAggBody(
  namespace: string,
  query: string,
  startTime: string,
  endTime: string,
  fieldName: string,
  topk: number = 30
): Record<string, unknown> {
  return {
    namespace,
    query,
    start_time: startTime,
    end_time: endTime,
    aggs: {
      [`${fieldName}_agg`]: {
        field: fieldName,
        topk,
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Access Log Aggregation Queries (A1-A8)
// ---------------------------------------------------------------------------

/**
 * Builds 8 aggregation queries for access log data (Track 2).
 * Endpoint: /api/data/namespaces/${ns}/access_logs/aggregation
 */
export function buildAccessLogAggregations(
  namespace: string,
  lbNames: string[],
  startTime: string,
  endTime: string
): AggregationQuery[] {
  const query = buildLBQuery(lbNames);
  const endpoint = `/api/data/namespaces/${namespace}/access_logs/aggregation`;

  return [
    // A1: Response code distribution
    {
      id: 'A1',
      endpoint,
      body: buildAggBody(namespace, query, startTime, endTime, 'rsp_code'),
    },
    // A2: Error diagnosis (rsp_code_details)
    {
      id: 'A2',
      endpoint,
      body: buildAggBody(namespace, query, startTime, endTime, 'rsp_code_details'),
    },
    // A3: Geo distribution
    {
      id: 'A3',
      endpoint,
      body: buildAggBody(namespace, query, startTime, endTime, 'country'),
    },
    // A4: Per-origin health (dst_ip)
    {
      id: 'A4',
      endpoint,
      body: buildAggBody(namespace, query, startTime, endTime, 'dst_ip'),
    },
    // A5: Hot paths (top 30)
    {
      id: 'A5',
      endpoint,
      body: buildAggBody(namespace, query, startTime, endTime, 'req_path', 30),
    },
    // A6: Top talkers — source IPs (top 30)
    {
      id: 'A6',
      endpoint,
      body: buildAggBody(namespace, query, startTime, endTime, 'src_ip', 30),
    },
    // A7: Per-domain breakdown
    {
      id: 'A7',
      endpoint,
      body: buildAggBody(namespace, query, startTime, endTime, 'domain'),
    },
    // A8: WAF action distribution
    {
      id: 'A8',
      endpoint,
      body: buildAggBody(namespace, query, startTime, endTime, 'waf_action'),
    },
  ];
}

// ---------------------------------------------------------------------------
// Security Event Aggregation Queries (S1-S5)
// ---------------------------------------------------------------------------

/**
 * Builds 5 aggregation queries for security event data (Track 2).
 * Endpoint: /api/data/namespaces/${ns}/app_security/events/aggregation
 */
export function buildSecurityEventAggregations(
  namespace: string,
  lbNames: string[],
  startTime: string,
  endTime: string
): AggregationQuery[] {
  const query = buildLBQuery(lbNames);
  const endpoint = `/api/data/namespaces/${namespace}/app_security/events/aggregation`;

  return [
    // S1: Security breakdown (sec_event_name → WAF/ThreatMesh/Bot/Policy)
    {
      id: 'S1',
      endpoint,
      body: buildAggBody(namespace, query, startTime, endTime, 'sec_event_name'),
    },
    // S2: Top WAF signatures (top 20)
    {
      id: 'S2',
      endpoint,
      body: buildAggBody(namespace, query, startTime, endTime, 'signatures.id', 20),
    },
    // S3: Top attacking IPs (top 20)
    {
      id: 'S3',
      endpoint,
      body: buildAggBody(namespace, query, startTime, endTime, 'src_ip', 20),
    },
    // S4: Security geo distribution
    {
      id: 'S4',
      endpoint,
      body: buildAggBody(namespace, query, startTime, endTime, 'country'),
    },
    // S5: Top violations
    {
      id: 'S5',
      endpoint,
      body: buildAggBody(namespace, query, startTime, endTime, 'violations.name'),
    },
  ];
}

// ---------------------------------------------------------------------------
// Combined Builder (convenience)
// ---------------------------------------------------------------------------

/**
 * Builds all 13 aggregation queries (A1-A8 + S1-S5) for a complete cycle.
 */
export function buildAllAggregations(
  namespace: string,
  lbNames: string[],
  startTime: string,
  endTime: string
): AggregationQuery[] {
  return [
    ...buildAccessLogAggregations(namespace, lbNames, startTime, endTime),
    ...buildSecurityEventAggregations(namespace, lbNames, startTime, endTime),
  ];
}

// ---------------------------------------------------------------------------
// Time Window Helpers
// ---------------------------------------------------------------------------

/**
 * Computes start and end time strings for a given window.
 * Returns ISO 8601 timestamps.
 *
 * @param windowMinutes - Data window size (5, 10, or 15 minutes)
 * @param endDate - End of the window (defaults to now)
 */
export function computeTimeWindow(
  windowMinutes: number,
  endDate?: Date
): { startTime: string; endTime: string } {
  const end = endDate ?? new Date();
  const start = new Date(end.getTime() - windowMinutes * 60 * 1000);

  return {
    startTime: start.toISOString(),
    endTime: end.toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Heartbeat Query Builders
// ---------------------------------------------------------------------------

/**
 * Builds the heartbeat probe body for access logs (Track 1).
 * POST /api/data/namespaces/${ns}/access_logs with limit=1 to get total_hits.
 */
export function buildAccessLogProbe(
  namespace: string,
  lbNames: string[],
  startTime: string,
  endTime: string
): { endpoint: string; body: Record<string, unknown> } {
  return {
    endpoint: `/api/data/namespaces/${namespace}/access_logs`,
    body: {
      namespace,
      query: buildLBQuery(lbNames),
      start_time: startTime,
      end_time: endTime,
      limit: 1,
      sort: 'DESCENDING',
    },
  };
}

/**
 * Builds the heartbeat probe body for security events (Track 1).
 * POST /api/data/namespaces/${ns}/app_security/events with limit=1 to get total_hits.
 */
export function buildSecurityEventProbe(
  namespace: string,
  lbNames: string[],
  startTime: string,
  endTime: string
): { endpoint: string; body: Record<string, unknown> } {
  return {
    endpoint: `/api/data/namespaces/${namespace}/app_security/events`,
    body: {
      namespace,
      query: buildLBQuery(lbNames),
      start_time: startTime,
      end_time: endTime,
      limit: 1,
      sort: 'DESCENDING',
    },
  };
}

// ---------------------------------------------------------------------------
// Raw Log Query Builder (Track 3)
// ---------------------------------------------------------------------------

/**
 * Builds the raw access log fetch body for Track 3 (detail fetch).
 * Used for: live event feed, latency waterfall, JA4 analysis.
 */
export function buildRawAccessLogQuery(
  namespace: string,
  lbNames: string[],
  startTime: string,
  endTime: string,
  limit: number = 500
): { endpoint: string; body: Record<string, unknown> } {
  return {
    endpoint: `/api/data/namespaces/${namespace}/access_logs`,
    body: {
      namespace,
      query: buildLBQuery(lbNames),
      start_time: startTime,
      end_time: endTime,
      limit,
      sort: 'DESCENDING',
    },
  };
}

/**
 * Builds the raw security event fetch body for Track 3.
 */
export function buildRawSecurityEventQuery(
  namespace: string,
  lbNames: string[],
  startTime: string,
  endTime: string,
  limit: number = 200
): { endpoint: string; body: Record<string, unknown> } {
  return {
    endpoint: `/api/data/namespaces/${namespace}/app_security/events`,
    body: {
      namespace,
      query: buildLBQuery(lbNames),
      start_time: startTime,
      end_time: endTime,
      limit,
      sort: 'DESCENDING',
    },
  };
}
