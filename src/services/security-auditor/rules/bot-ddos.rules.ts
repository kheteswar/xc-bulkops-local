// ═══════════════════════════════════════════════════════════════════════════
// Bot Defense and DDoS Protection Rules
// SEC-011, SEC-013, SEC-017
// ═══════════════════════════════════════════════════════════════════════════

import type { SecurityRule, CheckResult, AuditContext } from '../types';

// Helper to safely get spec from object
const getSpec = (obj: unknown): Record<string, unknown> => {
  const o = obj as Record<string, unknown>;
  return (o?.get_spec || o?.spec || {}) as Record<string, unknown>;
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-011: Bot Protection Enabled
// ───────────────────────────────────────────────────────────────────────────

export const SEC011_BotProtection: SecurityRule = {
  id: 'SEC-011',
  name: 'Bot Protection Enabled',
  description:
    'Bot protection should be enabled, especially for sensitive endpoints like login pages, ' +
    'to detect and block credential stuffing, carding, and scraping attacks.',
  category: 'BOT_DEFENSE',
  severity: 'HIGH',
  appliesTo: ['http_loadbalancer'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    // Check if bot defense is enabled
    const botDefense = spec?.bot_defense as Record<string, unknown>;
    const disableBotDefense = spec?.disable_bot_defense === true;

    if (disableBotDefense) {
      return {
        status: 'FAIL',
        message: 'Bot defense is explicitly disabled',
        currentValue: 'disabled',
        expectedValue: 'Bot defense enabled',
      };
    }

    if (botDefense && botDefense?.policy) {
      const policyName = (botDefense.policy as Record<string, unknown>)?.name || 'configured';
      return {
        status: 'PASS',
        message: `Bot defense is enabled with policy: ${policyName}`,
        currentValue: policyName,
        expectedValue: 'Bot defense enabled',
      };
    }

    // Check for regional endpoint configuration
    if (botDefense?.regional_endpoint) {
      return {
        status: 'PASS',
        message: 'Bot defense is enabled with regional endpoint',
        currentValue: botDefense.regional_endpoint,
        expectedValue: 'Bot defense enabled',
      };
    }

    return {
      status: 'WARN',
      message: 'Bot defense is not configured - consider enabling for sensitive endpoints',
      currentValue: null,
      expectedValue: 'Bot defense enabled',
    };
  },

  remediation: `To enable bot protection:
1. Ensure Bot Defense is enabled in your tenant (contact F5 if not available)
2. Navigate to HTTP Load Balancer → Security Configuration
3. In "Bot Defense" section, select "Enable"
4. Configure or select a bot defense policy
5. Focus protection on sensitive endpoints like:
   - Login pages (/login, /auth)
   - Account creation
   - Payment pages
   - API endpoints handling PII`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-security/bot-defense',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-013: L7 DDoS Auto-Mitigation
// ───────────────────────────────────────────────────────────────────────────

export const SEC013_L7DDoS: SecurityRule = {
  id: 'SEC-013',
  name: 'L7 DDoS Auto-Mitigation',
  description:
    'L7 DDoS auto-mitigation should be reviewed and threshold tuned to match ' +
    'backend server capacity (default is 10K RPS per LB).',
  category: 'DDOS',
  severity: 'MEDIUM',
  appliesTo: ['http_loadbalancer'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    // Check DDoS mitigation settings
    const ddosMitigation = spec?.ddos_mitigation_rules as Array<Record<string, unknown>>;
    const l7DdosProtection = spec?.l7_ddos_protection as Record<string, unknown>;
    const enableDdosDetection = spec?.enable_ddos_detection;
    const disableDdosDetection = spec?.disable_ddos_detection === true;

    if (disableDdosDetection) {
      return {
        status: 'WARN',
        message: 'DDoS detection is disabled',
        currentValue: 'disabled',
        expectedValue: 'DDoS protection configured',
      };
    }

    // Check L7 DDoS protection configuration
    if (l7DdosProtection) {
      return {
        status: 'PASS',
        message: 'L7 DDoS protection is configured',
        currentValue: l7DdosProtection,
        expectedValue: 'DDoS protection configured',
        details: {
          note: 'Review threshold matches backend capacity (default: 10K RPS)',
        },
      };
    }

    // Check for mitigation rules
    if (ddosMitigation && ddosMitigation.length > 0) {
      return {
        status: 'PASS',
        message: `${ddosMitigation.length} DDoS mitigation rule(s) configured`,
        currentValue: ddosMitigation.length,
        expectedValue: 'DDoS mitigation configured',
      };
    }

    // Check if detection is enabled
    if (enableDdosDetection) {
      return {
        status: 'PASS',
        message: 'DDoS detection is enabled (using default settings)',
        currentValue: 'default',
        expectedValue: 'DDoS protection configured',
        details: {
          note: 'Default threshold is 10K RPS - raise support ticket to adjust if needed',
        },
      };
    }

    return {
      status: 'WARN',
      message: 'DDoS protection not explicitly configured - using platform defaults',
      currentValue: 'default',
      expectedValue: 'DDoS protection explicitly configured',
      details: {
        note: 'Default L7 DDoS threshold is 10K RPS per LB',
        action: 'Raise support ticket to adjust threshold based on backend capacity',
      },
    };
  },

  remediation: `To configure L7 DDoS protection:
1. Default threshold is 10K RPS per load balancer
2. If your backend can handle less, raise a support ticket to lower the threshold
3. Recommended: Set threshold to 80% of backend peak capacity
   - E.g., for 5K RPS backend, set threshold to 4K RPS
4. Navigate to HTTP Load Balancer → DDoS Mitigation to configure rules
5. Contact F5 Support to adjust auto-mitigation threshold`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-security/ddos-mitigation',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-017: Malicious User Detection (MUD)
// ───────────────────────────────────────────────────────────────────────────

export const SEC017_MaliciousUserDetection: SecurityRule = {
  id: 'SEC-017',
  name: 'Malicious User Detection',
  description:
    'Malicious User Detection (MUD) uses AI/ML to monitor, identify, and automatically ' +
    'mitigate suspicious activities like forbidden access attempts or login failures.',
  category: 'BOT_DEFENSE',
  severity: 'HIGH',
  appliesTo: ['http_loadbalancer'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    // Check for MUD settings
    const enableMud = spec?.enable_malicious_user_detection === true;
    const disableMud = spec?.disable_malicious_user_detection === true;
    const mudConfig = spec?.malicious_user_detection;
    const mudMitigation = spec?.malicious_user_mitigation as Record<string, unknown>;

    if (disableMud) {
      return {
        status: 'FAIL',
        message: 'Malicious User Detection is explicitly disabled',
        currentValue: 'disabled',
        expectedValue: 'MUD enabled',
      };
    }

    if (enableMud || mudConfig || mudMitigation) {
      const mitigationPolicy = mudMitigation?.name || 'default';
      return {
        status: 'PASS',
        message: `Malicious User Detection is enabled${mudMitigation ? ` with policy: ${mitigationPolicy}` : ''}`,
        currentValue: mitigationPolicy,
        expectedValue: 'MUD enabled',
      };
    }

    return {
      status: 'WARN',
      message: 'Malicious User Detection is not configured',
      currentValue: null,
      expectedValue: 'MUD enabled',
    };
  },

  remediation: `To enable Malicious User Detection:
1. Navigate to HTTP Load Balancer → Security Configuration
2. Enable "Malicious User Detection"
3. Configure mitigation actions:
   - Temporary blocking
   - CAPTCHA challenges
   - JavaScript challenges
4. MUD leverages AI/ML to detect:
   - Forbidden access attempts
   - Repeated login failures
   - Suspicious behavior patterns
5. Review malicious user events in Security Analytics`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-security/malicious-user-detection',
};

// Export all Bot Defense and DDoS rules
export const botDdosRules: SecurityRule[] = [
  SEC011_BotProtection,
  SEC013_L7DDoS,
  SEC017_MaliciousUserDetection,
];
