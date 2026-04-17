// =============================================================================
// Live SOC Monitoring Room — API Security Monitor
// Fetches API endpoint inventory, vulnerabilities, and sensitive data
// exposure for a virtual host. Returns empty summary if not enabled.
// =============================================================================

import { apiClient } from '../api';
import type { APISecuritySummary } from './types';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function safeStr(val: unknown, fallback = ''): string {
  return typeof val === 'string' ? val : fallback;
}

function safeNum(val: unknown, fallback = 0): number {
  const n = Number(val);
  return isNaN(n) ? fallback : n;
}

// ---------------------------------------------------------------------------
// Empty result — returned when API Security is not enabled or API fails
// ---------------------------------------------------------------------------

function emptyAPISecuritySummary(): APISecuritySummary {
  return {
    totalEndpoints: 0,
    shadowEndpoints: 0,
    vulnerabilities: [],
    sensitiveData: [],
    unauthenticatedEndpoints: 0,
  };
}

// ---------------------------------------------------------------------------
// Sub-fetchers
// ---------------------------------------------------------------------------

interface EndpointStatsResponse {
  total_endpoints?: number;
  total?: number;
  shadow_endpoints?: number;
  shadow?: number;
  unauthenticated_endpoints?: number;
  unauthenticated?: number;
  items?: Array<Record<string, unknown>>;
  endpoints?: Array<Record<string, unknown>>;
}

async function fetchEndpointStats(
  namespace: string,
  lbName: string,
): Promise<EndpointStatsResponse | null> {
  try {
    return await apiClient.post<EndpointStatsResponse>(
      `/api/data/namespaces/${namespace}/virtual_host.api_endpoints/stats`,
      { namespace, virtual_host: lbName },
    );
  } catch {
    return null;
  }
}

interface VulnerabilityItem {
  id?: string;
  vulnerability_id?: string;
  severity?: string;
  endpoint?: string;
  path?: string;
  method?: string;
  description?: string;
  summary?: string;
  title?: string;
}

interface VulnerabilitiesResponse {
  items?: VulnerabilityItem[];
  vulnerabilities?: VulnerabilityItem[];
  total?: number;
}

async function fetchVulnerabilities(
  namespace: string,
  lbName: string,
): Promise<VulnerabilitiesResponse | null> {
  try {
    return await apiClient.post<VulnerabilitiesResponse>(
      `/api/data/namespaces/${namespace}/virtual_host.vulnerabilities`,
      { namespace, virtual_host: lbName },
    );
  } catch {
    return null;
  }
}

interface SensitiveDataItem {
  type?: string;
  data_type?: string;
  category?: string;
  endpoint?: string;
  path?: string;
  risk_level?: string;
  severity?: string;
}

interface SensitiveDataResponse {
  items?: SensitiveDataItem[];
  data?: SensitiveDataItem[];
  endpoints?: SensitiveDataItem[];
}

async function fetchSensitiveData(
  namespace: string,
  lbName: string,
): Promise<SensitiveDataResponse | null> {
  try {
    return await apiClient.post<SensitiveDataResponse>(
      `/api/data/namespaces/${namespace}/virtual_host.api_endpoints/summary/top_sensitive`,
      { namespace, virtual_host: lbName },
    );
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// fetchAPISecuritySummary — main public function
// ---------------------------------------------------------------------------

/**
 * Fetch API Security summary for a virtual host (load balancer).
 *
 * Uses three endpoints in parallel:
 *  - virtual_host.api_endpoints/stats — endpoint inventory & counts
 *  - virtual_host.vulnerabilities — discovered API vulnerabilities
 *  - virtual_host.api_endpoints/summary/top_sensitive — sensitive data exposure
 *
 * Returns an empty APISecuritySummary if API Security is not enabled or
 * all calls fail.
 */
export async function fetchAPISecuritySummary(
  namespace: string,
  lbName: string,
): Promise<APISecuritySummary> {
  try {
    const [endpointStats, vulnResponse, sensitiveResponse] = await Promise.all([
      fetchEndpointStats(namespace, lbName),
      fetchVulnerabilities(namespace, lbName),
      fetchSensitiveData(namespace, lbName),
    ]);

    // If endpoint stats returned nothing, API Security likely not enabled
    if (!endpointStats && !vulnResponse && !sensitiveResponse) {
      return emptyAPISecuritySummary();
    }

    // Endpoint counts
    const totalEndpoints = endpointStats
      ? safeNum(endpointStats.total_endpoints ?? endpointStats.total)
      : 0;

    const shadowEndpoints = endpointStats
      ? safeNum(endpointStats.shadow_endpoints ?? endpointStats.shadow)
      : 0;

    const unauthenticatedEndpoints = endpointStats
      ? safeNum(endpointStats.unauthenticated_endpoints ?? endpointStats.unauthenticated)
      : 0;

    // Vulnerabilities
    const rawVulns = vulnResponse
      ? (vulnResponse.items ?? vulnResponse.vulnerabilities ?? [])
      : [];

    const vulnerabilities = rawVulns.map((v) => ({
      id: safeStr(
        v.id ?? v.vulnerability_id,
        `vuln-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      ),
      severity: safeStr(v.severity, 'medium').toLowerCase(),
      endpoint: safeStr(v.endpoint ?? v.path, 'unknown'),
      description: safeStr(v.description ?? v.summary ?? v.title, ''),
    }));

    // Sort vulnerabilities by severity (critical > high > medium > low)
    const severityOrder: Record<string, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4,
    };
    vulnerabilities.sort(
      (a, b) =>
        (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5),
    );

    // Sensitive data
    const rawSensitive = sensitiveResponse
      ? (sensitiveResponse.items ?? sensitiveResponse.data ?? sensitiveResponse.endpoints ?? [])
      : [];

    const sensitiveData = rawSensitive.map((s) => ({
      type: safeStr(s.type ?? s.data_type ?? s.category, 'unknown'),
      endpoint: safeStr(s.endpoint ?? s.path, 'unknown'),
      riskLevel: safeStr(s.risk_level ?? s.severity, 'medium').toLowerCase(),
    }));

    return {
      totalEndpoints,
      shadowEndpoints,
      vulnerabilities,
      sensitiveData,
      unauthenticatedEndpoints,
    };
  } catch (err) {
    console.warn(
      `[SOC] API Security fetch failed for "${namespace}/${lbName}":`,
      err instanceof Error ? err.message : err,
    );
    return emptyAPISecuritySummary();
  }
}
