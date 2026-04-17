// =============================================================================
// Live SOC Monitoring Room — Error Diagnosis Knowledge Base
// =============================================================================
// Sourced from K000146828: complete rsp_code_details → root cause mapping.
// 19 patterns covering config, origin, security, and network error categories.
// =============================================================================

import type { ErrorDiagnosisEntry, LatencyWaterfall } from './types';

// ---------------------------------------------------------------------------
// K000146828 Knowledge Base — 19 rsp_code_details Patterns
// ---------------------------------------------------------------------------

export const ERROR_DIAGNOSIS_KB: ErrorDiagnosisEntry[] = [
  {
    rspCode: '403',
    pattern: 'csrf_origin_mismatch',
    category: 'config',
    severity: 'MEDIUM',
    isOriginError: false,
    rootCause: 'CSRF check — missing Origin/Referer header',
    autoAction: 'Check if POST requests lack Origin header',
    remediation: 'Review CSRF policy; check SPA CORS config',
  },
  {
    rspCode: '403',
    pattern: 'ext_authz_denied',
    category: 'config',
    severity: 'MEDIUM',
    isOriginError: false,
    rootCause: 'Service Policy blocked request',
    autoAction: 'Fetch active service policies, identify blocking rule',
    remediation: 'Review service policy rules; check audit log for changes',
  },
  {
    rspCode: '404',
    pattern: 'route_not_found',
    category: 'config',
    severity: 'HIGH',
    isOriginError: false,
    rootCause: 'No matching route/domain; or all health checks failed',
    autoAction: 'Check LB domains vs request authority; check all origin health',
    remediation: 'Verify domain config, route rules, health checks',
  },
  {
    rspCode: '408',
    pattern: 'request_overall_timeout',
    category: 'config',
    severity: 'MEDIUM',
    isOriginError: false,
    rootCause: 'Slow DDoS mitigation timeout',
    autoAction: 'Check slow_ddos_mitigation.request_timeout in LB config',
    remediation: 'Increase timeout or adjust slow DDoS settings',
  },
  {
    rspCode: '413',
    pattern: 'request_payload_too_large',
    category: 'config',
    severity: 'INFO',
    isOriginError: false,
    rootCause: 'Buffer Policy limit exceeded',
    autoAction: 'Check Buffer Policy config on LB/route',
    remediation: 'Increase Max Request Bytes (max 10485760) or disable Buffer Policy',
  },
  {
    rspCode: '421',
    pattern: 'misdirected_request',
    category: 'config',
    severity: 'MEDIUM',
    isOriginError: false,
    rootCause: 'HTTP/2 + wildcard cert TLS coalescing',
    autoAction: 'Check if multiple LBs share same wildcard cert',
    remediation: 'Ensure consistent TLS config across LBs, use separate certs, or disable HTTP/2',
  },
  {
    rspCode: '503',
    pattern: 'cluster_not_found',
    category: 'origin',
    severity: 'CRITICAL',
    isOriginError: false,
    rootCause: 'No upstream endpoint (k8s/DNS/cluster)',
    autoAction: 'Check origin pool status, k8s service discovery, Quad-A DNS records',
    remediation: 'Set LB_Override, check Endpoint Selection, verify cluster status',
  },
  {
    rspCode: '503',
    pattern: 'upstream_reset.*connection_failure',
    category: 'origin',
    severity: 'CRITICAL',
    isOriginError: false,
    rootCause: 'Cannot TCP connect to origin',
    autoAction: 'Check firewall rules for F5 XC egress IPs, verify origin accessibility',
    remediation: 'Whitelist F5 XC IPs (docs.cloud.f5.com/docs/reference/network-cloud-ref), increase timeout',
  },
  {
    rspCode: '503',
    pattern: 'no_healthy_upstream',
    category: 'origin',
    severity: 'CRITICAL',
    isOriginError: false,
    rootCause: 'All health checks failed',
    autoAction: 'Fetch health check config, check origin server status',
    remediation: 'Fix origin server, adjust health check parameters',
  },
  {
    rspCode: '503',
    pattern: 'via_upstream',
    category: 'origin',
    severity: 'HIGH',
    isOriginError: true,
    rootCause: 'Origin itself returned 503',
    autoAction: 'Origin is the source — check origin directly',
    remediation: 'This is NOT an F5 XC issue; investigate origin server health',
  },
  {
    rspCode: '503',
    pattern: 'remote_reset',
    category: 'origin',
    severity: 'HIGH',
    isOriginError: false,
    rootCause: 'HTTP version incompatibility',
    autoAction: 'Check HTTP protocol negotiation between XC and origin',
    remediation: 'Test HTTP/1.1 vs HTTP/2 against origin; adjust origin pool protocol',
  },
  {
    rspCode: '503',
    pattern: 'upstream_reset.*TLS_error.*Connection_reset',
    category: 'origin',
    severity: 'HIGH',
    isOriginError: false,
    rootCause: 'TLS handshake failure',
    autoAction: 'Check origin TLS config, certificate chain',
    remediation: 'Configure TLS verification in Origin Pool or skip verification (K000147459)',
  },
  {
    rspCode: '503',
    pattern: 'upstream_reset.*WRONG_VERSION_NUMBER',
    category: 'origin',
    severity: 'HIGH',
    isOriginError: false,
    rootCause: 'TLS vs plaintext mismatch',
    autoAction: 'Check if origin port expects TLS or plaintext',
    remediation: 'Verify "Use TLS" in origin pool matches origin port\'s actual protocol',
  },
  {
    rspCode: '503',
    pattern: 'upstream_reset.*CERTIFICATE_VERIFY_FAILED',
    category: 'origin',
    severity: 'HIGH',
    isOriginError: false,
    rootCause: 'Origin cert validation failed',
    autoAction: 'Check origin cert chain, CA trust store',
    remediation: 'Skip verification OR configure custom CA list in origin pool TLS config',
  },
  {
    rspCode: '503',
    pattern: 'upstream_reset.*connection_termination',
    category: 'origin',
    severity: 'MEDIUM',
    isOriginError: false,
    rootCause: 'Idle timeout mismatch (origin closing)',
    autoAction: 'Check idle timeout alignment',
    remediation: 'Set XC origin-pool idle-timeout LOWER than origin server\'s timeout',
  },
  {
    rspCode: '503',
    pattern: 'upstream_reset.*protocol_error',
    category: 'origin',
    severity: 'MEDIUM',
    isOriginError: false,
    rootCause: 'HTTP response header parsing error',
    autoAction: 'Check origin response headers for duplicates/malformed values',
    remediation: 'Fix origin response headers (often duplicate Content-Length)',
  },
  {
    rspCode: '503',
    pattern: 'upstream_reset.*delayed_connect_error.*111',
    category: 'origin',
    severity: 'CRITICAL',
    isOriginError: false,
    rootCause: 'TCP connection refused (no SYN-ACK)',
    autoAction: 'No TCP connectivity; time_to_last_downstream_tx_byte shows timeout',
    remediation: 'Check network connectivity, firewall, origin server status',
  },
  {
    rspCode: '503',
    pattern: 'upstream_reset.*remote_refused_stream_reset',
    category: 'origin',
    severity: 'MEDIUM',
    isOriginError: false,
    rootCause: 'HTTP/2 max concurrent streams exceeded',
    autoAction: 'Check SETTINGS_MAX_CONCURRENT_STREAMS on origin',
    remediation: 'Adjust HTTP/2 stream limit or reduce concurrent connections',
  },
  {
    rspCode: '503',
    pattern: 'response_payload_too_large',
    category: 'config',
    severity: 'MEDIUM',
    isOriginError: false,
    rootCause: 'DataGuard + HTTP/1.1 limit',
    autoAction: 'Check DataGuard config and response size',
    remediation: 'Enable HTTP/2 on origin OR add Skip DataGuard rule for affected paths',
  },
  {
    rspCode: '504',
    pattern: 'stream_idle_timeout',
    category: 'origin',
    severity: 'HIGH',
    isOriginError: false,
    rootCause: 'Origin exceeded idle timeout',
    autoAction: 'Check idle timeout config on HTTP LB',
    remediation: 'Increase idle timeout on the HTTP LB',
  },
  {
    rspCode: '504',
    pattern: 'upstream_response_timeout',
    category: 'origin',
    severity: 'HIGH',
    isOriginError: false,
    rootCause: 'Origin exceeded route timeout',
    autoAction: 'Check route timeout vs origin processing time',
    remediation: 'Increase timeout in LB miscellaneous options',
  },
];

// ---------------------------------------------------------------------------
// Diagnosis Matching
// ---------------------------------------------------------------------------

/**
 * Matches a rsp_code + rsp_code_details string against the KB.
 * The pattern field uses regex matching against the rsp_code_details value.
 * Returns the first matching entry, or null if no match.
 */
export function diagnoseError(
  rspCode: string,
  rspCodeDetails: string
): ErrorDiagnosisEntry | null {
  if (!rspCodeDetails) return null;

  for (const entry of ERROR_DIAGNOSIS_KB) {
    // First check if the response code matches (if provided)
    if (rspCode && entry.rspCode !== rspCode) continue;

    try {
      const regex = new RegExp(entry.pattern, 'i');
      if (regex.test(rspCodeDetails)) {
        return entry;
      }
    } catch {
      // If the pattern is not valid regex, try exact substring match
      if (rspCodeDetails.toLowerCase().includes(entry.pattern.toLowerCase())) {
        return entry;
      }
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Latency Bottleneck Classification (Section 6.2 auto-diagnosis tree)
// ---------------------------------------------------------------------------

/**
 * Analyzes a latency waterfall to identify the primary bottleneck.
 * Implements the auto-diagnosis tree from spec Section 6.2:
 *
 * 1. first_upstream_rx high → Origin slow (server processing)
 * 2. last_upstream_rx - first_upstream_rx high → Large response body
 * 3. first_downstream_tx - last_upstream_rx high → F5 XC processing (WAF inspection)
 * 4. last_downstream_tx - first_downstream_tx high → Slow client
 */
export function classifyLatencyBottleneck(
  waterfall: LatencyWaterfall
): { bottleneck: string; description: string } {
  const {
    toFirstUpstreamTx,
    toFirstUpstreamRx,
    toLastUpstreamRx,
    toFirstDownstreamTx,
    toLastDownstreamTx,
  } = waterfall;

  // Use P95 values for bottleneck classification
  const originProcessing = toFirstUpstreamRx.p95;
  const responseTransfer = toLastUpstreamRx.p95 - toFirstUpstreamRx.p95;
  const xcProcessing = toFirstDownstreamTx.p95 - toLastUpstreamRx.p95;
  const clientDelivery = toLastDownstreamTx.p95 - toFirstDownstreamTx.p95;
  const upstreamConnect = toFirstUpstreamTx.p95;

  // Calculate total for ratio analysis
  const total = toLastDownstreamTx.p95;
  if (total <= 0) {
    return {
      bottleneck: 'insufficient_data',
      description: 'Not enough latency data to determine bottleneck',
    };
  }

  // Find the dominant phase (highest absolute contribution)
  const phases = [
    { name: 'upstream_connect', value: upstreamConnect },
    { name: 'origin_processing', value: originProcessing },
    { name: 'response_transfer', value: responseTransfer },
    { name: 'xc_processing', value: xcProcessing },
    { name: 'client_delivery', value: clientDelivery },
  ].filter((p) => p.value > 0);

  if (phases.length === 0) {
    return {
      bottleneck: 'insufficient_data',
      description: 'All waterfall phases are zero',
    };
  }

  phases.sort((a, b) => b.value - a.value);
  const dominant = phases[0];
  const ratio = dominant.value / total;

  // Apply the diagnosis tree in priority order
  // Check #1: Origin slow (TTFB from origin is the dominant factor)
  if (dominant.name === 'origin_processing' && ratio > 0.4) {
    return {
      bottleneck: 'origin_slow',
      description: `Origin server processing is the bottleneck (${Math.round(originProcessing)}ms P95 TTFB, ${Math.round(ratio * 100)}% of total latency). Investigate origin application performance.`,
    };
  }

  // Check #2: Large response body
  if (dominant.name === 'response_transfer' && ratio > 0.3) {
    return {
      bottleneck: 'large_response_body',
      description: `Large response body transfer is the bottleneck (${Math.round(responseTransfer)}ms P95, ${Math.round(ratio * 100)}% of total). Consider enabling compression or reducing payload size.`,
    };
  }

  // Check #3: F5 XC processing (WAF/security inspection)
  if (dominant.name === 'xc_processing' && ratio > 0.3) {
    return {
      bottleneck: 'xc_processing',
      description: `F5 XC processing (WAF/security inspection) is the bottleneck (${Math.round(xcProcessing)}ms P95, ${Math.round(ratio * 100)}% of total). Review WAF rules and security policies for optimization.`,
    };
  }

  // Check #4: Slow client
  if (dominant.name === 'client_delivery' && ratio > 0.3) {
    return {
      bottleneck: 'slow_client',
      description: `Client-side delivery is the bottleneck (${Math.round(clientDelivery)}ms P95, ${Math.round(ratio * 100)}% of total). Clients may be on slow connections.`,
    };
  }

  // Check #5: Upstream connect delay
  if (dominant.name === 'upstream_connect' && ratio > 0.3) {
    return {
      bottleneck: 'upstream_connect',
      description: `Upstream connection establishment is slow (${Math.round(upstreamConnect)}ms P95, ${Math.round(ratio * 100)}% of total). Check cross-site routing or origin pool connectivity.`,
    };
  }

  // No single dominant factor — balanced distribution
  return {
    bottleneck: 'balanced',
    description: `Latency is distributed across phases. Dominant: ${dominant.name} (${Math.round(dominant.value)}ms P95, ${Math.round(ratio * 100)}% of ${Math.round(total)}ms total).`,
  };
}
