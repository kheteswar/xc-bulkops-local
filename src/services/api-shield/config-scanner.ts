/**
 * API Shield Advisor — Config Scanner
 *
 * Scans F5 XC HTTP load balancer configurations to determine which
 * security controls are enabled. Extracts WAF, API discovery, bot defense,
 * DDoS, rate limiting, mTLS, CORS, data guard, and other security settings
 * from each LB's spec object.
 */

import { apiClient } from '../api';
import type {
  LBSecurityConfig,
  ControlStatus,
  ControlStatusValue,
} from './types';

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

/** Check if a value is a non-empty object (not null, not array) */
function isNonEmptyObject(val: unknown): boolean {
  return val != null && typeof val === 'object' && !Array.isArray(val) && Object.keys(val as Record<string, unknown>).length > 0;
}

/** Check if a value is a non-empty string reference */
function isNonEmptyRef(val: unknown): boolean {
  if (typeof val === 'string') return val.length > 0;
  if (val != null && typeof val === 'object') {
    const obj = val as Record<string, unknown>;
    return !!(obj.name || obj.namespace);
  }
  return false;
}

/** Extract name from a reference object { name, namespace, tenant } */
function extractRefName(val: unknown): string | null {
  if (typeof val === 'string') return val;
  if (val != null && typeof val === 'object') {
    const obj = val as Record<string, unknown>;
    if (typeof obj.name === 'string') return obj.name;
  }
  return null;
}

/** Count origin pools referenced in routes */
function countOriginPools(spec: Record<string, unknown>): number {
  const poolSet = new Set<string>();
  const routes = spec.routes as Array<Record<string, unknown>> | undefined;

  if (!Array.isArray(routes)) return 0;

  for (const route of routes) {
    // Direct origin pool reference on route
    const directPool = route.origin_pools as Array<Record<string, unknown>> | undefined;
    if (Array.isArray(directPool)) {
      for (const pool of directPool) {
        const ref = pool.pool as Record<string, unknown> | undefined;
        const name = ref?.name as string | undefined;
        if (name) poolSet.add(name);
      }
    }

    // Route action with origin pools
    const routeAction = route.route_action as Record<string, unknown> | undefined;
    if (routeAction) {
      // single_default_pool
      const singlePool = routeAction.single_default_pool as Record<string, unknown> | undefined;
      if (singlePool) {
        const ref = singlePool.pool as Record<string, unknown> | undefined;
        const name = ref?.name as string | undefined;
        if (name) poolSet.add(name);
      }

      // weighted_pools
      const weightedPools = routeAction.weighted_pools as Record<string, unknown> | undefined;
      const wpPools = weightedPools?.pools as Array<Record<string, unknown>> | undefined;
      if (Array.isArray(wpPools)) {
        for (const wp of wpPools) {
          const ref = wp.pool as Record<string, unknown> | undefined;
          const name = ref?.name as string | undefined;
          if (name) poolSet.add(name);
        }
      }
    }

    // Check for simple_route_action
    const simpleAction = route.simple_route_action as Record<string, unknown> | undefined;
    if (simpleAction) {
      const pools = simpleAction.origin_pools as Array<Record<string, unknown>> | undefined;
      if (Array.isArray(pools)) {
        for (const pool of pools) {
          const ref = pool.pool as Record<string, unknown> | undefined;
          const name = ref?.name as string | undefined;
          if (name) poolSet.add(name);
        }
      }
    }
  }

  // Also check top-level default_route_pools
  const defaultPools = spec.default_route_pools as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(defaultPools)) {
    for (const pool of defaultPools) {
      const ref = pool.pool as Record<string, unknown> | undefined;
      const name = ref?.name as string | undefined;
      if (name) poolSet.add(name);
    }
  }

  return poolSet.size;
}

// ═══════════════════════════════════════════════════════════════════
// EXTRACT LB SECURITY CONFIG
// ═══════════════════════════════════════════════════════════════════

/**
 * Parses a load balancer's full config object and extracts
 * all security-relevant fields into a normalized structure.
 */
function extractSecurityConfig(
  name: string,
  namespace: string,
  lbData: Record<string, unknown>
): LBSecurityConfig {
  const spec = (lbData.spec || lbData.get_spec || lbData) as Record<string, unknown>;

  // --- WAF ---
  const appFirewall = spec.app_firewall;
  const wafEnabled = isNonEmptyRef(appFirewall) ||
    spec.disable_waf === undefined && appFirewall !== undefined;
  const wafPolicyName = extractRefName(appFirewall);

  // --- API Discovery ---
  // Match Config Visualizer logic: !disable && !!enable
  const apiDiscoveryEnabled = !spec.disable_api_discovery && !!spec.enable_api_discovery;

  // --- API Definition ---
  const apiDef = spec.api_definition;
  const apiDefinitionAttached = isNonEmptyRef(apiDef);

  // --- Schema Validation ---
  const apiSpec = spec.api_specification;
  const apiProtRules = spec.api_protection_rules as Record<string, unknown> | undefined;
  const apiProtSpec = apiProtRules?.api_specification;
  const apiProtGroups = apiProtRules?.api_groups as Array<unknown> | undefined;
  const schemaValidationEnabled = isNonEmptyObject(apiSpec) ||
    isNonEmptyObject(apiProtSpec) ||
    (Array.isArray(apiProtGroups) && apiProtGroups.length > 0);

  // --- Bot Defense ---
  // F5 XC: bot_defense object (with policy ref) or disable_bot_defense boolean
  const botDefense = spec.bot_defense;
  const disableBotDefense = spec.disable_bot_defense !== undefined;
  const botDefenseEnabled = !disableBotDefense && isNonEmptyObject(botDefense);

  // --- DDoS Protection ---
  const l7Ddos = spec.l7_ddos_protection;
  const ddosMitRules = spec.ddos_mitigation_rules;
  const ddosProtectionEnabled = isNonEmptyObject(l7Ddos) ||
    (Array.isArray(ddosMitRules) && ddosMitRules.length > 0);

  // --- Slow DDoS ---
  const slowDdos = spec.slow_ddos_mitigation as Record<string, unknown> | undefined;
  const slowDdosProtectionEnabled = isNonEmptyObject(slowDdos) &&
    (slowDdos?.request_headers_timeout !== undefined || slowDdos?.request_timeout !== undefined);

  // --- Rate Limiting ---
  const rateLimiter = spec.rate_limiter;
  const apiRateLimit = spec.api_rate_limit;
  const rateLimit = spec.rate_limit;
  const rateLimitEnabled = isNonEmptyObject(rateLimiter) ||
    isNonEmptyObject(apiRateLimit) ||
    isNonEmptyObject(rateLimit);

  // --- Service Policies ---
  const servicePolicies: string[] = [];
  const activeSvcPolicies = spec.active_service_policies as Record<string, unknown> | undefined;
  if (activeSvcPolicies) {
    const policies = activeSvcPolicies.policies as Array<Record<string, unknown>> | undefined;
    if (Array.isArray(policies)) {
      for (const p of policies) {
        const pName = extractRefName(p);
        if (pName) servicePolicies.push(pName);
      }
    }
  }
  if (spec.service_policies_from_namespace !== undefined) {
    servicePolicies.push('(from namespace)');
  }

  // --- CORS ---
  const corsPolicy = spec.cors_policy;
  const corsEnabled = isNonEmptyObject(corsPolicy);

  // --- mTLS ---
  let mtlsEnabled = false;
  const downstreamTls = spec.downstream_tls_certificate as Record<string, unknown> | undefined;
  if (downstreamTls) {
    // Check for client certificate requirement (mTLS)
    const clientAuth = downstreamTls.client_certificate_required;
    const mtlsAuth = spec.mtls_policy || spec.mutual_tls;
    mtlsEnabled = clientAuth !== undefined || isNonEmptyObject(mtlsAuth);
  }
  // Also check top-level mTLS fields
  if (spec.enable_mtls !== undefined || isNonEmptyObject(spec.mtls_policy)) {
    mtlsEnabled = true;
  }

  // --- Data Guard ---
  const dataGuardRules = spec.data_guard_rules;
  const dataGuardEnabled = isNonEmptyObject(dataGuardRules);

  // --- Sensitive Data Discovery ---
  const sensitiveDataPolicy = spec.sensitive_data_policy || spec.sensitive_data_disclosure_rules || spec.default_sensitive_data_policy;
  const sensitiveDataDiscoveryEnabled = sensitiveDataPolicy !== undefined && sensitiveDataPolicy !== null;

  // --- Malicious User Detection ---
  // F5 XC: presence of enable_malicious_user_detection key = enabled
  const maliciousUserDetectionEnabled = spec.enable_malicious_user_detection !== undefined ||
    isNonEmptyObject(spec.malicious_user_mitigation);

  // --- IP Reputation ---
  // F5 XC: presence of enable_ip_reputation key = enabled
  const ipReputationEnabled = spec.enable_ip_reputation !== undefined;

  // --- User Identification ---
  const userIdentificationEnabled = isNonEmptyRef(spec.user_identification) ||
    isNonEmptyObject(spec.user_id_policy);

  // --- Domains ---
  const rawDomains = spec.domains as string[] | undefined;
  const domains = Array.isArray(rawDomains) ? rawDomains : [];

  // --- Routes ---
  const routes = spec.routes as Array<unknown> | undefined;
  const routeCount = Array.isArray(routes) ? routes.length : 0;

  // --- Origin Pools ---
  const originPoolCount = countOriginPools(spec);

  const config = {
    name,
    namespace,
    wafEnabled,
    wafPolicyName,
    apiDiscoveryEnabled,
    apiDefinitionAttached,
    schemaValidationEnabled,
    botDefenseEnabled,
    ddosProtectionEnabled,
    slowDdosProtectionEnabled,
    rateLimitEnabled,
    servicePolicies,
    corsEnabled,
    mtlsEnabled,
    dataGuardEnabled,
    sensitiveDataDiscoveryEnabled,
    maliciousUserDetectionEnabled,
    ipReputationEnabled,
    userIdentificationEnabled,
    domains,
    routeCount,
    originPoolCount,
    rawSpec: spec,
  };

  console.log(`[API Shield] ${name} config scan:`, {
    waf: wafEnabled, apiDisc: apiDiscoveryEnabled, apiDef: apiDefinitionAttached,
    schema: schemaValidationEnabled, bot: botDefenseEnabled, ddos: ddosProtectionEnabled,
    rateLimit: rateLimitEnabled, cors: corsEnabled, mtls: mtlsEnabled,
    dataGuard: dataGuardEnabled, sensitiveData: sensitiveDataDiscoveryEnabled,
    malUser: maliciousUserDetectionEnabled, ipRep: ipReputationEnabled,
  });

  return config;
}

// ═══════════════════════════════════════════════════════════════════
// PUBLIC: SCAN LB CONFIGS
// ═══════════════════════════════════════════════════════════════════

/**
 * Scans load balancer configurations to extract security control statuses.
 * Fetches each LB's full config via the API and normalizes the result.
 */
export async function scanLBConfigs(
  namespace: string,
  lbNames: string[],
  onProgress: (msg: string, pct: number) => void
): Promise<LBSecurityConfig[]> {
  const configs: LBSecurityConfig[] = [];
  const total = lbNames.length;

  for (let i = 0; i < total; i++) {
    const name = lbNames[i];
    const pct = Math.round(((i + 1) / total) * 100);
    onProgress(`Scanning config: ${name} (${i + 1}/${total})`, pct);

    try {
      const lbData = await apiClient.getLoadBalancer(namespace, name) as unknown as Record<string, unknown>;
      const config = extractSecurityConfig(name, namespace, lbData);
      configs.push(config);
    } catch (err) {
      console.warn(`[ConfigScanner] Failed to fetch LB ${name}:`, err);
      // Push a disabled-everything config so the LB still appears in results
      configs.push({
        name,
        namespace,
        wafEnabled: false,
        wafPolicyName: null,
        apiDiscoveryEnabled: false,
        apiDefinitionAttached: false,
        schemaValidationEnabled: false,
        botDefenseEnabled: false,
        ddosProtectionEnabled: false,
        slowDdosProtectionEnabled: false,
        rateLimitEnabled: false,
        servicePolicies: [],
        corsEnabled: false,
        mtlsEnabled: false,
        dataGuardEnabled: false,
        sensitiveDataDiscoveryEnabled: false,
        maliciousUserDetectionEnabled: false,
        ipReputationEnabled: false,
        userIdentificationEnabled: false,
        domains: [],
        routeCount: 0,
        originPoolCount: 0,
        rawSpec: {},
      });
    }
  }

  console.log(`[ConfigScanner] Scanned ${configs.length} LB configs`);
  return configs;
}

// ═══════════════════════════════════════════════════════════════════
// CONTROL DEFINITION REGISTRY
// ═══════════════════════════════════════════════════════════════════

/**
 * Maps a control ID to the config field(s) used to determine its status.
 * Each entry specifies which LBSecurityConfig fields to check and how
 * to interpret them.
 */
interface ControlFieldMapping {
  /** Primary boolean field on LBSecurityConfig */
  fields: (keyof LBSecurityConfig)[];
  /** If true, ALL fields must be enabled for "enabled" status */
  requireAll?: boolean;
}

const CONTROL_FIELD_MAP: Record<string, ControlFieldMapping> = {
  'waf': { fields: ['wafEnabled'] },
  'api-discovery': { fields: ['apiDiscoveryEnabled'] },
  'api-definition': { fields: ['apiDefinitionAttached'] },
  'schema-validation': { fields: ['schemaValidationEnabled'] },
  'bot-defense': { fields: ['botDefenseEnabled'] },
  'ddos-protection': { fields: ['ddosProtectionEnabled'] },
  'slow-ddos': { fields: ['slowDdosProtectionEnabled'] },
  'rate-limiting': { fields: ['rateLimitEnabled'] },
  'cors': { fields: ['corsEnabled'] },
  'mtls': { fields: ['mtlsEnabled'] },
  'data-guard': { fields: ['dataGuardEnabled'] },
  'sensitive-data': { fields: ['sensitiveDataDiscoveryEnabled'] },
  'malicious-user': { fields: ['maliciousUserDetectionEnabled'] },
  'ip-reputation': { fields: ['ipReputationEnabled'] },
  'user-identification': { fields: ['userIdentificationEnabled'] },
  'service-policy': { fields: ['servicePolicies'] },
  'api-protection': { fields: ['schemaValidationEnabled', 'apiDefinitionAttached'], requireAll: true },
};

// ═══════════════════════════════════════════════════════════════════
// PUBLIC: ASSESS CONTROL STATUS
// ═══════════════════════════════════════════════════════════════════

/**
 * Determines whether a specific security control is enabled, partially
 * enabled, or disabled across all scanned LB configs.
 */
export function assessControlStatus(
  configs: LBSecurityConfig[],
  controlId: string
): ControlStatus {
  const mapping = CONTROL_FIELD_MAP[controlId];

  if (!mapping || configs.length === 0) {
    return {
      controlId,
      status: 'unknown',
      enabledCount: 0,
      totalCount: configs.length,
      details: mapping ? 'No LB configs available' : `Unknown control: ${controlId}`,
    };
  }

  let enabledCount = 0;
  const totalCount = configs.length;

  for (const config of configs) {
    const fieldResults = mapping.fields.map(field => {
      const value = config[field];
      if (typeof value === 'boolean') return value;
      if (Array.isArray(value)) return value.length > 0;
      if (typeof value === 'string') return value.length > 0;
      return false;
    });

    const isEnabled = mapping.requireAll
      ? fieldResults.every(Boolean)
      : fieldResults.some(Boolean);

    if (isEnabled) enabledCount++;
  }

  let status: ControlStatusValue;
  if (enabledCount === totalCount) {
    status = 'enabled';
  } else if (enabledCount > 0) {
    status = 'partial';
  } else {
    status = 'disabled';
  }

  const details = `${enabledCount}/${totalCount} LBs have ${controlId} enabled`;

  return {
    controlId,
    status,
    enabledCount,
    totalCount,
    details,
  };
}
