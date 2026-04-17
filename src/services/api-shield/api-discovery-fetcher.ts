/**
 * API Shield Advisor — API Discovery Fetcher
 *
 * Fetches API discovery data from F5 XC to identify discovered endpoints,
 * shadow APIs, PII exposure, and authentication gaps. Uses the API discovery
 * and API definition endpoints to correlate discovered vs. documented APIs.
 */

import { apiClient } from '../api';
import type {
  APIDiscoveryInsight,
  DiscoveredEndpoint,
  LBSecurityConfig,
} from './types';

// ═══════════════════════════════════════════════════════════════════
// TYPES (internal API response shapes)
// ═══════════════════════════════════════════════════════════════════

interface APIDefinitionItem {
  metadata?: {
    name?: string;
    namespace?: string;
  };
  spec?: {
    swagger_specs?: string[];
    endpoints?: Array<{
      path?: string;
      method?: string;
    }>;
  };
}

interface APIDefinitionsResponse {
  items?: APIDefinitionItem[];
}

interface DiscoveredEndpointRaw {
  method?: string;
  path?: string;
  api_endpoint_id?: string;
  collapsed_url?: string;
  discovered_at?: string;
  last_seen_at?: string;
  request_count?: number;
  has_auth_token?: boolean;
  pdf_info?: {
    has_pdf?: boolean;
    detected_pii_types?: string[];
  };
  pii_detected?: boolean;
  pii_types?: string[];
  sensitive_data_types?: string[];
  risk_score?: number;
  shadow?: boolean;
  in_api_definition?: boolean;
  schema_validation_status?: string;
}

interface EndpointsResponse {
  items?: DiscoveredEndpointRaw[];
  endpoints?: DiscoveredEndpointRaw[];
}

interface EndpointStatsResponse {
  items?: Array<{
    api_endpoint_id?: string;
    path?: string;
    method?: string;
    request_count?: number;
    error_count?: number;
    avg_latency_ms?: number;
    last_seen?: string;
  }>;
}

interface SensitiveDataResponse {
  items?: Array<{
    api_endpoint_id?: string;
    path?: string;
    method?: string;
    pii_types?: string[];
    sensitive_data_types?: string[];
    detection_info?: {
      types?: string[];
    };
  }>;
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

/**
 * Extracts the virtual host name for a given LB,
 * following the F5 XC naming convention.
 */
function getLBVirtualHostName(lbName: string): string {
  return `ves-io-http-loadbalancer-${lbName}`;
}

/**
 * Fetches API definitions from config endpoint.
 * Returns the list of defined API definitions in the namespace.
 */
async function fetchAPIDefinitions(namespace: string): Promise<APIDefinitionItem[]> {
  try {
    const response = await apiClient.get<APIDefinitionsResponse>(
      `/api/config/namespaces/${namespace}/api_definitions`
    );
    return response.items || [];
  } catch (err) {
    console.warn('[APIDiscoveryFetcher] Failed to fetch API definitions:', err);
    return [];
  }
}

/**
 * Fetches discovered endpoints for a specific LB.
 * Uses the virtual_host data API to get discovered API endpoints.
 */
async function fetchDiscoveredEndpoints(
  namespace: string,
  lbName: string
): Promise<DiscoveredEndpointRaw[]> {
  const vhName = getLBVirtualHostName(lbName);

  try {
    const response = await apiClient.post<EndpointsResponse>(
      `/api/data/namespaces/${namespace}/virtual_host/api_endpoints`,
      {
        namespace,
        virtual_host: vhName,
      }
    );
    return response.items || response.endpoints || [];
  } catch (err) {
    console.warn(`[APIDiscoveryFetcher] Failed to fetch endpoints for ${lbName}:`, err);
    return [];
  }
}

/**
 * Fetches endpoint statistics (request counts, latency, errors).
 */
async function fetchEndpointStats(
  namespace: string,
  lbName: string
): Promise<Map<string, { requestCount: number }>> {
  const vhName = getLBVirtualHostName(lbName);
  const statsMap = new Map<string, { requestCount: number }>();

  try {
    const response = await apiClient.post<EndpointStatsResponse>(
      `/api/data/namespaces/${namespace}/virtual_host/api_endpoints/stats`,
      {
        namespace,
        virtual_host: vhName,
      }
    );

    if (response.items) {
      for (const item of response.items) {
        const key = `${item.method || 'GET'}:${item.path || '/'}`;
        statsMap.set(key, {
          requestCount: item.request_count || 0,
        });
      }
    }
  } catch (err) {
    console.warn(`[APIDiscoveryFetcher] Failed to fetch endpoint stats for ${lbName}:`, err);
  }

  return statsMap;
}

/**
 * Fetches sensitive data (PII) information for discovered endpoints.
 */
async function fetchSensitiveData(
  namespace: string,
  lbName: string
): Promise<Map<string, string[]>> {
  const vhName = getLBVirtualHostName(lbName);
  const piiMap = new Map<string, string[]>();

  try {
    const response = await apiClient.post<SensitiveDataResponse>(
      `/api/data/namespaces/${namespace}/virtual_host/api_endpoints/summary/top_sensitive`,
      {
        namespace,
        virtual_host: vhName,
      }
    );

    if (response.items) {
      for (const item of response.items) {
        const key = `${item.method || 'GET'}:${item.path || '/'}`;
        const types = item.pii_types || item.sensitive_data_types || item.detection_info?.types || [];
        if (types.length > 0) {
          piiMap.set(key, types);
        }
      }
    }
  } catch (err) {
    console.warn(`[APIDiscoveryFetcher] Failed to fetch sensitive data for ${lbName}:`, err);
  }

  return piiMap;
}

/**
 * Checks whether a specific LB has an API spec/definition uploaded
 * by looking at the API definitions list and matching by LB config.
 */
function hasSpecUploaded(
  lbConfig: LBSecurityConfig | undefined,
  definitions: APIDefinitionItem[]
): boolean {
  if (!lbConfig) return false;
  if (lbConfig.apiDefinitionAttached) return true;
  if (lbConfig.schemaValidationEnabled) return true;
  // Check if any definition exists in the namespace
  return definitions.length > 0;
}

// ═══════════════════════════════════════════════════════════════════
// PUBLIC: FETCH API DISCOVERY DATA
// ═══════════════════════════════════════════════════════════════════

/**
 * Fetches comprehensive API discovery data for the given load balancers.
 * Collects discovered endpoints, shadow APIs, PII exposure, and auth status.
 *
 * For each LB:
 * 1. Fetches discovered endpoints from the data API
 * 2. Fetches endpoint stats (request counts)
 * 3. Fetches sensitive data / PII information
 * 4. Cross-references against API definitions
 *
 * Returns partial data if some API calls fail.
 */
export async function fetchAPIDiscoveryData(
  namespace: string,
  lbNames: string[],
  onProgress: (msg: string, pct: number) => void,
  lbConfigs?: LBSecurityConfig[]
): Promise<APIDiscoveryInsight> {
  const allEndpoints: DiscoveredEndpoint[] = [];
  const allPiiTypes = new Set<string>();
  const discoveryEnabledLBs: string[] = [];
  const specUploadedLBs: string[] = [];
  const lbInsights: APIDiscoveryInsight['lbInsights'] = [];

  // Step 1: Fetch API definitions (shared across all LBs)
  onProgress('Fetching API definitions...', 5);
  const definitions = await fetchAPIDefinitions(namespace);
  console.log(`[APIDiscoveryFetcher] Found ${definitions.length} API definitions in namespace`);

  // Build a set of defined endpoint paths for shadow API detection
  const definedPaths = new Set<string>();
  for (const def of definitions) {
    if (def.spec?.endpoints) {
      for (const ep of def.spec.endpoints) {
        if (ep.path) {
          definedPaths.add(`${(ep.method || 'GET').toUpperCase()}:${ep.path}`);
        }
      }
    }
  }

  // Step 2: For each LB, fetch discovery data
  const total = lbNames.length;
  for (let i = 0; i < total; i++) {
    const lbName = lbNames[i];
    const basePct = Math.round(10 + ((i / total) * 80));
    onProgress(`Fetching discovery data: ${lbName} (${i + 1}/${total})`, basePct);

    const lbConfig = lbConfigs?.find(c => c.name === lbName);

    // Track discovery status
    const discoveryEnabled = lbConfig?.apiDiscoveryEnabled ?? false;
    if (discoveryEnabled) discoveryEnabledLBs.push(lbName);

    const specUploaded = hasSpecUploaded(lbConfig, definitions);
    if (specUploaded) specUploadedLBs.push(lbName);

    // Fetch discovered endpoints
    const rawEndpoints = await fetchDiscoveredEndpoints(namespace, lbName);

    if (rawEndpoints.length === 0) {
      lbInsights.push({
        lbName,
        discoveryEnabled,
        specUploaded,
        endpointCount: 0,
        shadowCount: 0,
      });
      continue;
    }

    // Fetch stats and sensitive data in parallel
    onProgress(`Fetching endpoint details: ${lbName}`, basePct + 5);
    const [statsMap, piiMap] = await Promise.all([
      fetchEndpointStats(namespace, lbName),
      fetchSensitiveData(namespace, lbName),
    ]);

    // Process endpoints
    let shadowCount = 0;
    for (const raw of rawEndpoints) {
      const method = (raw.method || 'GET').toUpperCase();
      const path = raw.path || raw.collapsed_url || '/unknown';
      const key = `${method}:${path}`;

      // Determine if this is a shadow API
      const isInDefinition = raw.in_api_definition === true ||
        !raw.shadow && definedPaths.has(key);
      const isShadow = raw.shadow === true || !isInDefinition;
      if (isShadow) shadowCount++;

      // PII types
      const piiTypes: string[] = [];
      if (raw.pii_types && raw.pii_types.length > 0) {
        piiTypes.push(...raw.pii_types);
      }
      if (raw.sensitive_data_types && raw.sensitive_data_types.length > 0) {
        piiTypes.push(...raw.sensitive_data_types);
      }
      if (raw.pdf_info?.detected_pii_types) {
        piiTypes.push(...raw.pdf_info.detected_pii_types);
      }
      // Merge from sensitive data API
      const extraPii = piiMap.get(key);
      if (extraPii) {
        piiTypes.push(...extraPii);
      }
      const uniquePii = [...new Set(piiTypes)];
      for (const t of uniquePii) allPiiTypes.add(t);

      // Stats
      const stats = statsMap.get(key);
      const requestCount = raw.request_count || stats?.requestCount || 0;

      allEndpoints.push({
        path,
        method,
        discoveredAt: raw.discovered_at || raw.last_seen_at || '',
        isInDefinition,
        riskScore: raw.risk_score ?? (isShadow ? 7 : uniquePii.length > 0 ? 5 : 2),
        piiTypes: uniquePii,
        requestCount,
        authenticated: raw.has_auth_token ?? false,
      });
    }

    lbInsights.push({
      lbName,
      discoveryEnabled,
      specUploaded,
      endpointCount: rawEndpoints.length,
      shadowCount,
    });
  }

  // Compute aggregates
  const shadowApiCount = allEndpoints.filter(e => !e.isInDefinition).length;
  const authenticatedEndpoints = allEndpoints.filter(e => e.authenticated).length;
  const unauthenticatedEndpoints = allEndpoints.filter(e => !e.authenticated).length;

  onProgress('API discovery data collected', 95);

  const result: APIDiscoveryInsight = {
    totalDiscoveredEndpoints: allEndpoints.length,
    shadowApiCount,
    authenticatedEndpoints,
    unauthenticatedEndpoints,
    piiTypesFound: [...allPiiTypes],
    endpoints: allEndpoints,
    discoveryEnabledLBs,
    specUploadedLBs,
    lbInsights,
  };

  console.log(
    `[APIDiscoveryFetcher] Discovery complete: ${allEndpoints.length} endpoints, ` +
    `${shadowApiCount} shadow APIs, ${allPiiTypes.size} PII types`
  );

  return result;
}
