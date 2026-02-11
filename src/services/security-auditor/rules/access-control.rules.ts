// ═══════════════════════════════════════════════════════════════════════════
// Access Control, API Security, Rate Limiting, and Client Security Rules
// SEC-012, SEC-014, SEC-015, SEC-016, SEC-018, SEC-019, SEC-020, SEC-021
// ═══════════════════════════════════════════════════════════════════════════

import type { SecurityRule, CheckResult, AuditContext } from '../types';

// Helper to safely get spec from object
const getSpec = (obj: unknown): Record<string, unknown> => {
  const o = obj as Record<string, unknown>;
  return (o?.get_spec || o?.spec || {}) as Record<string, unknown>;
};

const getMetadata = (obj: unknown): Record<string, unknown> => {
  const o = obj as Record<string, unknown>;
  return (o?.metadata || {}) as Record<string, unknown>;
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-012: API Protection Enabled
// ───────────────────────────────────────────────────────────────────────────

export const SEC012_APIProtection: SecurityRule = {
  id: 'SEC-012',
  name: 'API Protection Enabled',
  description:
    'API Protection should be enabled for applications serving APIs to defend against ' +
    'BOLA, injection attacks, abuse of undocumented APIs, and data theft.',
  category: 'API_SECURITY',
  severity: 'MEDIUM',
  appliesTo: ['http_loadbalancer'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    // Check for API definition/protection
    const apiDefinition = spec?.api_definition as Record<string, unknown>;
    const disableApiDefinition = spec?.disable_api_definition === true;
    const apiProtectionRules = spec?.api_protection_rules as Record<string, unknown>;
    const enableApiDiscovery = spec?.enable_api_discovery;
    const disableApiDiscovery = spec?.disable_api_discovery === true;

    if (disableApiDefinition && disableApiDiscovery) {
      return {
        status: 'WARN',
        message: 'API definition and discovery are disabled',
        currentValue: 'disabled',
        expectedValue: 'API protection configured (if serving APIs)',
      };
    }

    const features: string[] = [];

    if (apiDefinition?.name) {
      features.push(`API Definition: ${apiDefinition.name}`);
    }

    if (apiProtectionRules) {
      features.push('API Protection Rules configured');
    }

    if (enableApiDiscovery && !disableApiDiscovery) {
      features.push('API Discovery enabled');
    }

    if (features.length > 0) {
      return {
        status: 'PASS',
        message: `API protection configured: ${features.join(', ')}`,
        currentValue: features,
        expectedValue: 'API protection configured',
      };
    }

    return {
      status: 'INFO',
      message: 'API protection not configured - enable if this LB serves APIs',
      currentValue: null,
      expectedValue: 'API protection configured (if serving APIs)',
    };
  },

  remediation: `To enable API Protection:
1. Navigate to HTTP Load Balancer → API Protection
2. Enable API Discovery to auto-discover API endpoints
3. Upload OpenAPI specification if available
4. Configure API Protection Rules for:
   - Schema validation
   - Rate limiting per endpoint
   - Authentication requirements
5. Review discovered APIs and mark shadow APIs`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-security/api-protection',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-014: Client-Side Defense
// ───────────────────────────────────────────────────────────────────────────

export const SEC014_ClientSideDefense: SecurityRule = {
  id: 'SEC-014',
  name: 'Client-Side Defense',
  description:
    'Client-Side Defense protects against malicious scripts running in the browser, ' +
    'such as formjacking, Magecart attacks, and supply chain compromises.',
  category: 'CLIENT_SECURITY',
  severity: 'MEDIUM',
  appliesTo: ['http_loadbalancer'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    const clientSideDefense = spec?.client_side_defense as Record<string, unknown>;
    const disableCsd = spec?.disable_client_side_defense === true;

    if (disableCsd) {
      return {
        status: 'WARN',
        message: 'Client-Side Defense is disabled',
        currentValue: 'disabled',
        expectedValue: 'Client-Side Defense enabled',
      };
    }

    if (clientSideDefense?.policy) {
      const policyName = (clientSideDefense.policy as Record<string, unknown>)?.name || 'configured';
      return {
        status: 'PASS',
        message: `Client-Side Defense enabled with policy: ${policyName}`,
        currentValue: policyName,
        expectedValue: 'Client-Side Defense enabled',
      };
    }

    return {
      status: 'INFO',
      message: 'Client-Side Defense not configured - consider enabling for e-commerce/payment sites',
      currentValue: null,
      expectedValue: 'Client-Side Defense enabled',
    };
  },

  remediation: `To enable Client-Side Defense:
1. Check your contract for Client-Side Defense availability
2. Navigate to HTTP Load Balancer → Client-Side Defense
3. Enable and configure a policy
4. Recommended for:
   - E-commerce sites
   - Payment pages
   - Sites with sensitive form data
5. Monitor for detected malicious scripts

Learn more: https://docs.cloud.f5.com/docs-v2/client-side-defense/how-tos/configure-csd`,

  referenceUrl: 'https://docs.cloud.f5.com/docs-v2/client-side-defense/how-tos/configure-csd',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-015: IP Reputation
// ───────────────────────────────────────────────────────────────────────────

export const SEC015_IPReputation: SecurityRule = {
  id: 'SEC-015',
  name: 'IP Reputation Enabled',
  description:
    'IP Reputation automatically detects and blocks traffic from known malicious IPs ' +
    'including spam sources, botnets, scanners, and phishing sources.',
  category: 'ACCESS_CONTROL',
  severity: 'HIGH',
  appliesTo: ['http_loadbalancer'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    const enableIpReputation = spec?.enable_ip_reputation;
    const ipReputation = spec?.ip_reputation;
    const disableIpReputation = spec?.disable_ip_reputation === true;

    if (disableIpReputation) {
      return {
        status: 'FAIL',
        message: 'IP Reputation is explicitly disabled',
        currentValue: 'disabled',
        expectedValue: 'IP Reputation enabled',
      };
    }

    if (enableIpReputation || ipReputation) {
      const categories = (enableIpReputation as Record<string, unknown>)?.ip_threat_categories as string[];
      if (categories && categories.length > 0) {
        return {
          status: 'PASS',
          message: `IP Reputation enabled with ${categories.length} threat categories`,
          currentValue: categories,
          expectedValue: 'IP Reputation enabled',
        };
      }

      return {
        status: 'PASS',
        message: 'IP Reputation is enabled',
        currentValue: 'enabled',
        expectedValue: 'IP Reputation enabled',
      };
    }

    return {
      status: 'WARN',
      message: 'IP Reputation is not enabled',
      currentValue: null,
      expectedValue: 'IP Reputation enabled',
    };
  },

  remediation: `To enable IP Reputation:
1. Navigate to HTTP Load Balancer → Security Configuration
2. Enable "IP Reputation"
3. Select threat categories to block:
   - Spam Sources
   - Windows Exploits
   - Web Attacks
   - Botnets
   - Scanners
   - Denial of Service
   - Phishing
4. Configure exceptions for known good IPs if needed

Reference: https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/adv-security/configure-ip-reputation`,

  referenceUrl: 'https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/adv-security/configure-ip-reputation',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-016: User Identification Configuration
// ───────────────────────────────────────────────────────────────────────────

export const SEC016_UserIdentification: SecurityRule = {
  id: 'SEC-016',
  name: 'User Identification Configuration',
  description:
    'User Identification should use Client IP plus an additional identifier (like TLS fingerprint) ' +
    'for accurate user tracking, especially when multiple users share an IP (corporate proxy).',
  category: 'USER_IDENTIFICATION',
  severity: 'MEDIUM',
  appliesTo: ['http_loadbalancer'],

  check: (obj: unknown, context: AuditContext): CheckResult => {
    const spec = getSpec(obj);
    const metadata = getMetadata(obj);
    const namespace = (metadata?.namespace as string) || 'default';

    // Check for user identification policy
    const userIdentification = spec?.user_identification as Record<string, unknown>;
    const userIdClientIp = spec?.user_id_client_ip;

    if (userIdClientIp !== undefined) {
      return {
        status: 'WARN',
        message: 'Using Client IP only for user identification - may affect multiple users behind same IP',
        currentValue: 'client_ip_only',
        expectedValue: 'Client IP + additional identifier',
      };
    }

    if (userIdentification?.name) {
      const policyName = userIdentification.name as string;
      
      // Try to get details from the policy
      const policyKey = `${userIdentification.namespace || namespace}/${policyName}`;
      const policy = context.configs.userIdentifications.get(policyKey);
      
      if (policy) {
        const policySpec = getSpec(policy);
        // Check if using multiple identifiers
        const rules = policySpec?.rules as Array<Record<string, unknown>>;
        const hasMultipleIdentifiers = rules && rules.length > 1;
        
        if (hasMultipleIdentifiers) {
          return {
            status: 'PASS',
            message: `User identification policy "${policyName}" with multiple identifiers`,
            currentValue: policyName,
            expectedValue: 'Client IP + additional identifier',
          };
        }
      }

      return {
        status: 'PASS',
        message: `User identification policy configured: ${policyName}`,
        currentValue: policyName,
        expectedValue: 'User identification configured',
      };
    }

    return {
      status: 'WARN',
      message: 'No user identification policy configured - using default (Client IP only)',
      currentValue: 'default',
      expectedValue: 'Client IP + TLS fingerprint (JA4)',
    };
  },

  remediation: `To configure User Identification:
1. Create a User Identification Policy:
   - Navigate to Shared Configuration → User Identification
   - Create policy with "Client IP and JA4 TLS Fingerprint"
2. Assign to Load Balancer:
   - Edit HTTP Load Balancer
   - Select the user identification policy
3. Benefits:
   - More granular user tracking
   - Better handling of users behind corporate proxies
   - Improved security action accuracy`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-security/user-identification',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-018: Rate Limiting
// ───────────────────────────────────────────────────────────────────────────

export const SEC018_RateLimiting: SecurityRule = {
  id: 'SEC-018',
  name: 'Rate Limiting Configured',
  description:
    'Rate limiting should be configured to protect applications from overload, ' +
    'abuse, and brute force attacks by limiting requests per user/client.',
  category: 'RATE_LIMITING',
  severity: 'HIGH',
  appliesTo: ['http_loadbalancer'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    const rateLimiter = spec?.rate_limiter as Record<string, unknown>;
    const rateLimit = spec?.rate_limit as Record<string, unknown>;

    if (rateLimiter?.name) {
      return {
        status: 'PASS',
        message: `Rate limiter configured: ${rateLimiter.name}`,
        currentValue: rateLimiter.name,
        expectedValue: 'Rate limiting configured',
      };
    }

    if (rateLimit) {
      return {
        status: 'PASS',
        message: 'Rate limiting is configured',
        currentValue: rateLimit,
        expectedValue: 'Rate limiting configured',
      };
    }

    return {
      status: 'WARN',
      message: 'Rate limiting is not configured',
      currentValue: null,
      expectedValue: 'Rate limiting configured',
    };
  },

  remediation: `To configure Rate Limiting:
1. Create a Rate Limiter:
   - Navigate to Shared Configuration → Rate Limiters
   - Define rate limits (e.g., 100 requests per minute per client)
2. Assign to Load Balancer:
   - Edit HTTP Load Balancer
   - Select the rate limiter policy
3. Consider per-endpoint rate limits for:
   - Login endpoints (prevent brute force)
   - API endpoints (prevent abuse)
   - Search/query endpoints (prevent scraping)`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-security/rate-limiting',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-019: Trusted Client Rules
// ───────────────────────────────────────────────────────────────────────────

export const SEC019_TrustedClients: SecurityRule = {
  id: 'SEC-019',
  name: 'Trusted Client Rules',
  description:
    'Trusted Client Rules should be reviewed to allow known safe traffic ' +
    '(monitoring tools, internal apps) without WAF/Bot enforcement.',
  category: 'ACCESS_CONTROL',
  severity: 'LOW',
  appliesTo: ['http_loadbalancer'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    const trustedClients = spec?.trusted_clients as Array<Record<string, unknown>>;

    if (trustedClients && trustedClients.length > 0) {
      const clientCount = trustedClients.length;
      return {
        status: 'PASS',
        message: `${clientCount} trusted client rule(s) configured`,
        currentValue: clientCount,
        expectedValue: 'Trusted clients reviewed',
        details: {
          note: 'Periodically review trusted clients to ensure they are still valid',
        },
      };
    }

    return {
      status: 'INFO',
      message: 'No trusted client rules configured - add for monitoring tools and known internal traffic',
      currentValue: 0,
      expectedValue: 'Trusted clients configured (if applicable)',
    };
  },

  remediation: `To configure Trusted Client Rules:
1. Navigate to HTTP Load Balancer → Trusted Clients
2. Add rules for:
   - Monitoring tools (e.g., Pingdom, DataDog)
   - Internal applications
   - Known partner IPs
3. Trusted clients bypass:
   - WAF inspection
   - Bot detection
   - Malicious User Detection
4. Use sparingly and review periodically`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-networking/http-load-balancer',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-020: Alert Policies Defined
// ───────────────────────────────────────────────────────────────────────────

export const SEC020_AlertPolicies: SecurityRule = {
  id: 'SEC-020',
  name: 'Alert Policies Defined',
  description:
    'Alert policies should be defined for critical events like SSL certificate expiry, ' +
    'origin health failures, and security incidents.',
  category: 'ALERTING',
  severity: 'MEDIUM',
  appliesTo: ['alert_policy'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);
    const metadata = getMetadata(obj);

    const receivers = spec?.receivers as Array<Record<string, unknown>>;
    const routes = spec?.routes as Array<Record<string, unknown>>;
    const disabled = metadata?.disable === true;

    if (disabled) {
      return {
        status: 'WARN',
        message: 'Alert policy is disabled',
        currentValue: 'disabled',
        expectedValue: 'Alert policy active',
      };
    }

    if (!receivers || receivers.length === 0) {
      return {
        status: 'WARN',
        message: 'Alert policy has no receivers configured',
        currentValue: { receivers: 0 },
        expectedValue: 'At least one receiver configured',
      };
    }

    if (!routes || routes.length === 0) {
      return {
        status: 'WARN',
        message: 'Alert policy has no routes configured',
        currentValue: { routes: 0 },
        expectedValue: 'At least one route configured',
      };
    }

    return {
      status: 'PASS',
      message: `Alert policy configured with ${receivers.length} receiver(s) and ${routes.length} route(s)`,
      currentValue: { receivers: receivers.length, routes: routes.length },
      expectedValue: 'Alert policy properly configured',
    };
  },

  remediation: `To configure Alert Policies:
1. Navigate to Shared Configuration → Alert Management → Alert Policies
2. Create alert policies for:
   - SSL Certificate Expiry (Critical)
   - Origin Health Failures (Major)
   - WAF Attack Events (Warning)
   - DDoS Attacks (Critical)
3. Configure routes to match alert severity
4. Assign receivers (email, Slack, PagerDuty)

Reference: https://docs.cloud.f5.com/docs-v2/shared-configuration/how-tos/alerting/alerts-email-sms`,

  referenceUrl: 'https://docs.cloud.f5.com/docs-v2/shared-configuration/how-tos/alerting/alerts-email-sms',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-021: Alert Receivers Configured
// ───────────────────────────────────────────────────────────────────────────

export const SEC021_AlertReceivers: SecurityRule = {
  id: 'SEC-021',
  name: 'Alert Receivers Configured',
  description:
    'Alert receivers should be configured to receive notifications via email, Slack, ' +
    'PagerDuty, or webhooks for security and operational events.',
  category: 'ALERTING',
  severity: 'MEDIUM',
  appliesTo: ['alert_receiver'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);
    const metadata = getMetadata(obj);

    const disabled = metadata?.disable === true;

    if (disabled) {
      return {
        status: 'WARN',
        message: 'Alert receiver is disabled',
        currentValue: 'disabled',
        expectedValue: 'Alert receiver active',
      };
    }

    // Check receiver type
    const hasEmail = spec?.email !== undefined;
    const hasSlack = spec?.slack !== undefined;
    const hasPagerDuty = spec?.pagerduty !== undefined;
    const hasWebhook = spec?.webhook !== undefined;
    const hasOpsgenie = spec?.opsgenie !== undefined;

    const types: string[] = [];
    if (hasEmail) types.push('Email');
    if (hasSlack) types.push('Slack');
    if (hasPagerDuty) types.push('PagerDuty');
    if (hasWebhook) types.push('Webhook');
    if (hasOpsgenie) types.push('Opsgenie');

    if (types.length === 0) {
      return {
        status: 'WARN',
        message: 'Alert receiver has no notification method configured',
        currentValue: 'none',
        expectedValue: 'At least one notification method',
      };
    }

    return {
      status: 'PASS',
      message: `Alert receiver configured: ${types.join(', ')}`,
      currentValue: types,
      expectedValue: 'Notification method configured',
    };
  },

  remediation: `To configure Alert Receivers:
1. Navigate to Shared Configuration → Alert Management → Alert Receivers
2. Create receivers for your notification channels:
   - Email: For general notifications
   - Slack: For team collaboration
   - PagerDuty: For on-call alerting
   - Webhook: For custom integrations
3. Test receivers to ensure delivery
4. Assign receivers to alert policies`,

  referenceUrl: 'https://docs.cloud.f5.com/docs-v2/shared-configuration/how-tos/alerting/alerts-email-sms',
};

// Export all Access Control and related rules
export const accessControlRules: SecurityRule[] = [
  SEC012_APIProtection,
  SEC014_ClientSideDefense,
  SEC015_IPReputation,
  SEC016_UserIdentification,
  SEC018_RateLimiting,
  SEC019_TrustedClients,
  SEC020_AlertPolicies,
  SEC021_AlertReceivers,
];
