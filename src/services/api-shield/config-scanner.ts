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

  // Debug: log which keys exist in the spec for feature detection
  console.log(`[ConfigScanner] ${lbData.metadata ? (lbData.metadata as Record<string,unknown>).name : 'unknown'}: spec keys =`, Object.keys(spec).filter(k =>
    k.includes('api') || k.includes('waf') || k.includes('bot') || k.includes('ddos') ||
    k.includes('rate') || k.includes('malicious') || k.includes('ip_rep') || k.includes('threat') ||
    k.includes('disable') || k.includes('enable')
  ));

  // --- WAF ---
  const appFirewall = spec.app_firewall;
  const wafEnabled = isNonEmptyRef(appFirewall) ||
    (spec.disable_waf === undefined && appFirewall !== undefined);
  const wafPolicyName = extractRefName(appFirewall);

  // --- API Discovery ---
  // F5 XC pattern: enable_api_discovery: {...} = enabled, disable_api_discovery: {} = disabled
  const hasEnableApiDiscovery = spec.enable_api_discovery !== undefined && spec.enable_api_discovery !== null;
  const hasDisableApiDiscovery = spec.disable_api_discovery !== undefined && spec.disable_api_discovery !== null;
  const apiDiscoveryEnabled = hasEnableApiDiscovery && !hasDisableApiDiscovery;
  console.log(`[ConfigScanner] API Discovery: enable_key=${hasEnableApiDiscovery} (type=${typeof spec.enable_api_discovery}), disable_key=${hasDisableApiDiscovery} (type=${typeof spec.disable_api_discovery}), result=${apiDiscoveryEnabled}`);
  console.log(`[ConfigScanner] spec has 'enable_api_discovery'? ${'enable_api_discovery' in spec}, value:`, spec.enable_api_discovery);
  console.log(`[ConfigScanner] spec has 'disable_api_discovery'? ${'disable_api_discovery' in spec}, value:`, spec.disable_api_discovery);

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
  // F5 XC: l7_ddos_protection even as {} means it's configured
  const l7Ddos = spec.l7_ddos_protection;
  const ddosMitRules = spec.ddos_mitigation_rules;
  const ddosProtectionEnabled = (l7Ddos != null && typeof l7Ddos === 'object') ||
    (Array.isArray(ddosMitRules) && ddosMitRules.length > 0);

  // --- Slow DDoS ---
  const slowDdos = spec.slow_ddos_mitigation as Record<string, unknown> | undefined;
  const slowDdosProtectionEnabled = isNonEmptyObject(slowDdos) &&
    (slowDdos?.request_headers_timeout !== undefined || slowDdos?.request_timeout !== undefined);

  // --- Rate Limiting ---
  // F5 XC uses disable_rate_limit: {} when disabled, rate_limiter/rate_limit when enabled
  const rateLimiter = spec.rate_limiter;
  const apiRateLimit = spec.api_rate_limit;
  const rateLimit = spec.rate_limit;
  const rateLimitDisabled = spec.disable_rate_limit !== undefined;
  const rateLimitEnabled = !rateLimitDisabled && (
    isNonEmptyObject(rateLimiter) ||
    isNonEmptyObject(apiRateLimit) ||
    isNonEmptyObject(rateLimit)
  );

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
  // F5 XC: disable_malicious_user_detection: {} = disabled, enable_malicious_user_detection = enabled
  const maliciousUserDetectionEnabled =
    spec.disable_malicious_user_detection === undefined &&
    (spec.enable_malicious_user_detection !== undefined ||
     isNonEmptyObject(spec.malicious_user_mitigation));

  // --- IP Reputation ---
  // F5 XC: presence of enable_ip_reputation key = enabled
  const ipReputationEnabled = spec.enable_ip_reputation !== undefined;

  // --- User Identification ---
  // F5 XC: user_id_client_ip: {} (basic), user_identification: {ref} (advanced), user_id_policy (custom)
  const userIdentificationEnabled = isNonEmptyRef(spec.user_identification) ||
    isNonEmptyObject(spec.user_id_policy) ||
    spec.user_id_client_ip !== undefined;

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

  console.log(`[ConfigScanner] ${name} feature flags:`, {
    waf: wafEnabled, apiDisc: apiDiscoveryEnabled, apiDef: apiDefinitionAttached,
    schema: schemaValidationEnabled, bot: botDefenseEnabled, ddos: ddosProtectionEnabled,
    rateLimit: rateLimitEnabled, mud: maliciousUserDetectionEnabled, ipRep: ipReputationEnabled,
    userId: userIdentificationEnabled, cors: corsEnabled, mtls: mtlsEnabled,
    dataGuard: dataGuardEnabled, sensitiveData: sensitiveDataDiscoveryEnabled,
  });

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
  // Internal assessor IDs
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

  // Catalog control IDs → map to the same LBSecurityConfig booleans
  // WAF controls
  'waf_app_firewall': { fields: ['wafEnabled'] },
  'waf_blocking_mode': { fields: ['wafEnabled'] },
  'waf_high_medium_signatures': { fields: ['wafEnabled'] },
  'waf_attack_types_all': { fields: ['wafEnabled'] },
  'waf_api_specific_signatures': { fields: ['wafEnabled'] },
  'waf_exclusion_rules': { fields: ['wafEnabled'] },
  'waf_bot_signature_detection': { fields: ['wafEnabled'] },
  'waf_csrf_protection': { fields: ['wafEnabled'] },
  'waf_graphql_protection': { fields: ['wafEnabled'] },
  'waf_allowed_methods': { fields: ['wafEnabled'] },

  // API Discovery controls
  'discovery_traffic_based': { fields: ['apiDiscoveryEnabled'] },
  'discovery_sensitive_data': { fields: ['apiDiscoveryEnabled'] },
  'discovery_shadow_api_detection': { fields: ['apiDiscoveryEnabled'] },
  'discovery_authentication_state': { fields: ['apiDiscoveryEnabled'] },
  'discovery_api_groups': { fields: ['apiDiscoveryEnabled'] },
  'discovery_inventory_review': { fields: ['apiDiscoveryEnabled'] },
  'discovery_learnt_schema': { fields: ['apiDiscoveryEnabled'] },
  'discovery_zombie_api_detection': { fields: ['apiDiscoveryEnabled'] },
  'discovery_endpoint_risk_scoring': { fields: ['apiDiscoveryEnabled'] },

  // Schema / API Definition controls
  'schema_oas_upload': { fields: ['apiDefinitionAttached'] },
  'schema_api_definition_attach': { fields: ['apiDefinitionAttached'] },
  'schema_request_validation': { fields: ['schemaValidationEnabled'] },
  'schema_response_validation': { fields: ['schemaValidationEnabled'] },
  'schema_parameter_validation': { fields: ['schemaValidationEnabled'] },
  'schema_content_type_enforcement': { fields: ['schemaValidationEnabled'] },
  'schema_validation_mode_block': { fields: ['schemaValidationEnabled'] },
  'schema_validation_mode_report': { fields: ['schemaValidationEnabled'] },
  'schema_custom_rules': { fields: ['schemaValidationEnabled'] },
  'schema_version_management': { fields: ['apiDefinitionAttached'] },

  // Bot Defense controls
  'bot_defense_enable': { fields: ['botDefenseEnabled'] },
  'bot_defense_api_endpoints': { fields: ['botDefenseEnabled'] },
  'bot_defense_behavioral_analysis': { fields: ['botDefenseEnabled'] },
  'bot_defense_js_challenge': { fields: ['botDefenseEnabled'] },
  'bot_defense_captcha': { fields: ['botDefenseEnabled'] },
  'bot_defense_good_bot_allowlist': { fields: ['botDefenseEnabled'] },
  'bot_defense_mobile_sdk': { fields: ['botDefenseEnabled'] },

  // DDoS controls
  'ddos_l7_protection': { fields: ['ddosProtectionEnabled'] },
  'ddos_auto_mitigation': { fields: ['ddosProtectionEnabled'] },
  'ddos_custom_rps_threshold': { fields: ['ddosProtectionEnabled'] },
  'ddos_mitigation_rules': { fields: ['ddosProtectionEnabled'] },
  'ddos_slow_request': { fields: ['slowDdosProtectionEnabled'] },
  'ddos_js_challenge_delay': { fields: ['ddosProtectionEnabled'] },

  // Rate Limiting controls
  'rate_limit_global': { fields: ['rateLimitEnabled'] },
  'rate_limit_per_client': { fields: ['rateLimitEnabled'] },
  'rate_limit_per_endpoint': { fields: ['rateLimitEnabled'] },
  'rate_limit_burst_control': { fields: ['rateLimitEnabled'] },
  'rate_limit_write_endpoints': { fields: ['rateLimitEnabled'] },
  'rate_limit_custom_identifier': { fields: ['rateLimitEnabled'] },
  'rate_limit_response_headers': { fields: ['rateLimitEnabled'] },
  'rate_limit_service_policy': { fields: ['servicePolicies'] },

  // Access Control controls
  'access_service_policy': { fields: ['servicePolicies'] },
  'access_cors_policy': { fields: ['corsEnabled'] },
  'access_mtls': { fields: ['mtlsEnabled'] },
  'access_ip_allowlist': { fields: ['servicePolicies'] },
  'access_jwt_validation': { fields: ['servicePolicies'] },
  'access_api_key_policy': { fields: ['servicePolicies'] },
  'access_per_route_policies': { fields: ['servicePolicies'] },
  'access_geo_filtering': { fields: ['servicePolicies'] },
  'access_header_manipulation': { fields: ['servicePolicies'] },
  'access_oauth2_integration': { fields: ['servicePolicies'] },

  // Sensitive Data controls
  'sensitive_data_guard': { fields: ['dataGuardEnabled'] },
  'sensitive_data_discovery': { fields: ['sensitiveDataDiscoveryEnabled'] },
  'sensitive_data_response_masking': { fields: ['dataGuardEnabled'] },
  'sensitive_data_pci_compliance': { fields: ['dataGuardEnabled'] },
  'sensitive_data_custom_patterns': { fields: ['sensitiveDataDiscoveryEnabled'] },
  'sensitive_data_log_redaction': { fields: ['sensitiveDataDiscoveryEnabled'] },
  'sensitive_data_error_sanitization': { fields: ['sensitiveDataDiscoveryEnabled'] },

  // Threat Detection controls
  'threat_ip_reputation': { fields: ['ipReputationEnabled'] },
  'threat_ip_categories': { fields: ['ipReputationEnabled'] },
  'threat_mesh': { fields: ['ipReputationEnabled'] },
  'threat_malicious_user': { fields: ['maliciousUserDetectionEnabled'] },
  'threat_user_identification': { fields: ['userIdentificationEnabled'] },
  'threat_api_abuse_detection': { fields: ['maliciousUserDetectionEnabled'] },
  'threat_geo_anomaly_detection': { fields: ['ipReputationEnabled'] },
  'threat_failed_auth_tracking': { fields: ['maliciousUserDetectionEnabled'] },

  // Monitoring controls — these can't be detected from LB config alone
  'monitor_security_dashboard': { fields: ['wafEnabled'] },
  'monitor_log_streaming': { fields: ['wafEnabled'] },
  'monitor_alert_policies': { fields: ['wafEnabled'] },
  'monitor_alert_receivers': { fields: ['wafEnabled'] },
  'monitor_security_event_logging': { fields: ['wafEnabled'] },
  'monitor_api_traffic_anomalies': { fields: ['apiDiscoveryEnabled'] },
  'monitor_compliance_reporting': { fields: ['wafEnabled'] },
  'monitor_incident_response_plan': { fields: ['wafEnabled'] },
  'monitor_custom_dashboards': { fields: ['wafEnabled'] },
  'monitor_sla_tracking': { fields: ['apiDiscoveryEnabled'] },
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
