// =============================================================================
// Rule Suggestion API Wrappers — 11 endpoints
// =============================================================================

import { apiClient } from '../api';
import type { RuleSuggestionType } from './types';

interface RuleSuggestionResult {
  type: RuleSuggestionType;
  rules: unknown[];
  raw: unknown;
}

// Mapping of suggestion type to API endpoint template
const SUGGESTION_ENDPOINTS: Record<RuleSuggestionType, { prefix: string; path: string }> = {
  waf_exclusion:            { prefix: 'http_loadbalancers', path: 'waf_exclusion/suggestion' },
  block_client:             { prefix: 'http_loadbalancers', path: 'block_client/suggestion' },
  trust_client:             { prefix: 'http_loadbalancers', path: 'trust_client/suggestion' },
  ddos_mitigation:          { prefix: 'http_loadbalancers', path: 'ddos_mitigation/suggestion' },
  rate_limit:               { prefix: 'http_loadbalancers', path: 'rate_limit/suggestion' },
  oas_validation:           { prefix: 'http_loadbalancers', path: 'oas_validation/suggestion' },
  data_exposure:            { prefix: 'http_loadbalancers', path: 'data_exposure/suggestion' },
  api_endpoint_protection:  { prefix: 'http_loadbalancers', path: 'api_endpoint_protection/suggestion' },
  cdn_waf_exclusion:        { prefix: 'cdn_loadbalancers', path: 'waf_exclusion/suggestion' },
  cdn_block_client:         { prefix: 'cdn_loadbalancers', path: 'block_client/suggestion' },
  cdn_ddos_mitigation:      { prefix: 'cdn_loadbalancers', path: 'ddos_mitigation/suggestion' },
};

/**
 * Fetch rule suggestions from F5 XC for a specific suggestion type.
 * Returns the suggested rules or empty array if the API doesn't return any.
 */
export async function fetchRuleSuggestion(
  namespace: string,
  lbName: string,
  suggestionType: RuleSuggestionType,
  context?: {
    srcIps?: string[];
    signatureIds?: string[];
    paths?: string[];
    countries?: string[];
    startTime?: string;
    endTime?: string;
  },
): Promise<RuleSuggestionResult> {
  const config = SUGGESTION_ENDPOINTS[suggestionType];
  if (!config) {
    return { type: suggestionType, rules: [], raw: null };
  }

  const endpoint = `/api/config/namespaces/${namespace}/${config.prefix}/${lbName}/${config.path}`;

  try {
    const body: Record<string, unknown> = {
      namespace,
      name: lbName,
    };

    if (context?.startTime && context?.endTime) {
      body.start_time = context.startTime;
      body.end_time = context.endTime;
    }

    // Add context-specific fields based on suggestion type
    if (context?.srcIps?.length) {
      body.src_ips = context.srcIps;
    }
    if (context?.signatureIds?.length) {
      body.signature_ids = context.signatureIds;
    }
    if (context?.paths?.length) {
      body.paths = context.paths;
    }
    if (context?.countries?.length) {
      body.countries = context.countries;
    }

    const response = await apiClient.post<Record<string, unknown>>(endpoint, body);

    // Extract rules from response — F5 XC typically returns suggested_rules or items array
    const rules = extractRules(response, suggestionType);

    return { type: suggestionType, rules, raw: response };
  } catch {
    // API may 404 if feature not configured — graceful fallback
    return { type: suggestionType, rules: [], raw: null };
  }
}

function extractRules(response: Record<string, unknown>, type: RuleSuggestionType): unknown[] {
  if (!response) return [];

  // Try common response shapes
  if (Array.isArray(response)) return response;

  const possibleKeys = [
    'suggested_rules', 'rules', 'items', 'suggestions',
    'waf_exclusion_rules', 'block_rules', 'trust_rules',
    'ddos_mitigation_rules', 'rate_limit_rules',
  ];

  for (const key of possibleKeys) {
    const val = response[key];
    if (Array.isArray(val)) return val;
  }

  // For specific types, look at type-specific keys
  switch (type) {
    case 'waf_exclusion':
    case 'cdn_waf_exclusion': {
      const exc = response.exclusion_rule || response.exclusion_rules;
      return Array.isArray(exc) ? exc : exc ? [exc] : [];
    }
    case 'block_client':
    case 'cdn_block_client': {
      const blk = response.block_rule || response.block_rules;
      return Array.isArray(blk) ? blk : blk ? [blk] : [];
    }
    case 'ddos_mitigation':
    case 'cdn_ddos_mitigation': {
      const ddos = response.ddos_mitigation_rule || response.mitigation_rules;
      return Array.isArray(ddos) ? ddos : ddos ? [ddos] : [];
    }
    case 'rate_limit': {
      const rl = response.rate_limit_rule || response.rate_limiter;
      return Array.isArray(rl) ? rl : rl ? [rl] : [];
    }
    default:
      return [];
  }
}

/**
 * Fetch multiple types of suggestions in parallel for an investigation.
 */
export async function fetchMultipleSuggestions(
  namespace: string,
  lbName: string,
  types: RuleSuggestionType[],
  context?: {
    srcIps?: string[];
    signatureIds?: string[];
    paths?: string[];
    countries?: string[];
    startTime?: string;
    endTime?: string;
  },
): Promise<RuleSuggestionResult[]> {
  const results = await Promise.allSettled(
    types.map(type => fetchRuleSuggestion(namespace, lbName, type, context))
  );

  return results
    .filter((r): r is PromiseFulfilledResult<RuleSuggestionResult> => r.status === 'fulfilled')
    .map(r => r.value);
}

/**
 * Check if a CDN load balancer and use CDN-specific suggestion endpoints.
 */
export function getSuggestionType(baseSuggestion: 'waf_exclusion' | 'block_client' | 'ddos_mitigation', isCDN: boolean): RuleSuggestionType {
  if (!isCDN) return baseSuggestion;
  switch (baseSuggestion) {
    case 'waf_exclusion': return 'cdn_waf_exclusion';
    case 'block_client': return 'cdn_block_client';
    case 'ddos_mitigation': return 'cdn_ddos_mitigation';
  }
}
