import type { CurrentDdosConfig } from './types';

/**
 * Parses an HTTP Load Balancer spec object and extracts all DDoS-related configuration.
 * The spec comes from GET /api/config/namespaces/{ns}/http_loadbalancers/{name}
 */
export function assessCurrentConfig(spec: Record<string, unknown>): CurrentDdosConfig {
  const l7 = spec.l7_ddos_protection as Record<string, unknown> | undefined;
  const slowDdos = spec.slow_ddos_mitigation as Record<string, unknown> | undefined;
  const ddosRules = spec.ddos_mitigation_rules as Array<Record<string, unknown>> | undefined;
  const ipRep = spec.enable_ip_reputation as Record<string, unknown> | undefined;

  // L7 DDoS Protection
  const hasL7DdosProtection = !!l7;
  let rpsThreshold: number | null = null;
  let isDefaultRpsThreshold = true;

  if (l7) {
    if (l7.rps_threshold !== undefined && typeof l7.rps_threshold === 'number') {
      rpsThreshold = l7.rps_threshold;
      isDefaultRpsThreshold = false;
    } else if (l7.default_rps_threshold !== undefined) {
      rpsThreshold = 10000; // system default
      isDefaultRpsThreshold = true;
    }
  }

  // Mitigation action
  let mitigationAction: CurrentDdosConfig['mitigationAction'] = 'not_configured';
  if (l7) {
    if (l7.mitigation_block !== undefined) mitigationAction = 'block';
    else if (l7.mitigation_js_challenge !== undefined) mitigationAction = 'js_challenge';
    else if (l7.mitigation_captcha_challenge !== undefined) mitigationAction = 'captcha_challenge';
    else if (l7.mitigation_none !== undefined) mitigationAction = 'none';
  }

  // JS Challenge settings
  let jsChallenge: CurrentDdosConfig['jsChallenge'] = undefined;
  if (l7?.mitigation_js_challenge && typeof l7.mitigation_js_challenge === 'object') {
    const jsc = l7.mitigation_js_challenge as Record<string, unknown>;
    jsChallenge = {
      jsScriptDelay: typeof jsc.js_script_delay === 'number' ? jsc.js_script_delay : undefined,
      cookieExpiry: typeof jsc.cookie_expiry === 'number' ? jsc.cookie_expiry : undefined,
    };
  }

  // Client-side action
  let clientsideAction: CurrentDdosConfig['clientsideAction'] = 'not_configured';
  if (l7) {
    if (l7.clientside_action_none !== undefined) clientsideAction = 'none';
    else if (l7.clientside_action_js_challenge !== undefined) clientsideAction = 'js_challenge';
    else if (l7.clientside_action_captcha_challenge !== undefined) clientsideAction = 'captcha_challenge';
  }

  // DDoS custom policy
  let ddosPolicy: string | null = null;
  if (l7?.ddos_policy_custom && typeof l7.ddos_policy_custom === 'object') {
    const dp = l7.ddos_policy_custom as Record<string, unknown>;
    ddosPolicy = (dp.name as string) || null;
  }

  // DDoS mitigation rules
  const mitigationRules: CurrentDdosConfig['mitigationRules'] = [];
  if (ddosRules && Array.isArray(ddosRules)) {
    for (const rule of ddosRules) {
      const meta = rule.metadata as Record<string, unknown> | undefined;
      const name = (meta?.name as string) || 'unnamed';

      if (rule.ip_prefix_list) {
        const pl = rule.ip_prefix_list as Record<string, unknown>;
        const prefixes = (pl.ip_prefixes as string[]) || [];
        mitigationRules.push({
          name,
          type: 'ip_prefix',
          detail: `${prefixes.length} IP prefix(es): ${prefixes.slice(0, 3).join(', ')}${prefixes.length > 3 ? '...' : ''}`,
        });
      } else if (rule.ddos_client_source) {
        const cs = rule.ddos_client_source as Record<string, unknown>;
        const countries = (cs.country_list as string[]) || [];
        const asns = (cs.asn_list as number[]) || [];
        const parts: string[] = [];
        if (countries.length) parts.push(`${countries.length} countries`);
        if (asns.length) parts.push(`${asns.length} ASNs`);
        mitigationRules.push({
          name,
          type: 'client_source',
          detail: parts.join(', ') || 'empty',
        });
      }
    }
  }

  // Slow DDoS
  const hasSlowDdosMitigation = !!slowDdos && (slowDdos.request_headers_timeout !== undefined || slowDdos.request_timeout !== undefined);
  const slowDdosHeadersTimeout = typeof slowDdos?.request_headers_timeout === 'number' ? slowDdos.request_headers_timeout : null;
  const slowDdosRequestTimeout = typeof slowDdos?.request_timeout === 'number' ? slowDdos.request_timeout : null;

  // Threat Mesh
  const threatMeshEnabled = spec.enable_threat_mesh !== undefined;

  // IP Reputation
  const ipReputationEnabled = !!ipRep;
  const ipThreatCategories = (ipRep?.ip_threat_categories as string[]) || [];

  // Malicious User Detection
  const maliciousUserDetectionEnabled = spec.enable_malicious_user_detection !== undefined;

  // Bot Defense
  const botDefenseEnabled = spec.disable_bot_defense === undefined && (
    spec.enable_bot_defense !== undefined ||
    spec.bot_defense !== undefined
  );

  return {
    hasL7DdosProtection,
    rpsThreshold,
    isDefaultRpsThreshold,
    mitigationAction,
    clientsideAction,
    jsChallenge,
    ddosPolicy,
    mitigationRules,
    hasSlowDdosMitigation,
    slowDdosHeadersTimeout,
    slowDdosRequestTimeout,
    threatMeshEnabled,
    ipReputationEnabled,
    ipThreatCategories,
    maliciousUserDetectionEnabled,
    botDefenseEnabled,
  };
}
