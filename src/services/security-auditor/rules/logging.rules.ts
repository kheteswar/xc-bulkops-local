// ═══════════════════════════════════════════════════════════════════════════
// Logging, Service Policy, and Additional Rules
// SEC-022, SEC-023, SEC-024, SEC-025, SEC-026, SEC-028-LB
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
// SEC-022: Service Policy Geo Blocking
// ───────────────────────────────────────────────────────────────────────────

export const SEC022_GeoBlocking: SecurityRule = {
  id: 'SEC-022',
  name: 'Service Policy - Geo Blocking',
  description:
    'Service policies should be reviewed for geo-blocking configuration to restrict ' +
    'traffic from high-risk or non-business regions.',
  category: 'ACCESS_CONTROL',
  severity: 'MEDIUM',
  appliesTo: ['service_policy'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);
    const rules = (spec?.rules || spec?.rule_list?.rules || []) as Array<Record<string, unknown>>;

    let hasGeoRule = false;
    const geoRules: string[] = [];

    for (const rule of rules) {
      const match = rule?.match as Record<string, unknown>;
      const ruleSpec = rule?.spec as Record<string, unknown>;
      
      const geoMatch = match?.geo_ip || match?.source_geo_location || 
                       ruleSpec?.geo_ip || ruleSpec?.source_geo_location;

      if (geoMatch) {
        hasGeoRule = true;
        geoRules.push((rule?.metadata as Record<string, unknown>)?.name as string || 'geo-rule');
      }
    }

    if (hasGeoRule) {
      return {
        status: 'PASS',
        message: `Geo-blocking rules configured: ${geoRules.length} rule(s)`,
        currentValue: geoRules,
        expectedValue: 'Geo-blocking configured',
      };
    }

    return {
      status: 'INFO',
      message: 'No geo-blocking rules found in this service policy',
      currentValue: null,
      expectedValue: 'Geo-blocking configured (if needed)',
    };
  },

  remediation: `To configure Geo Blocking:
1. Navigate to Shared Configuration → Service Policies
2. Create or edit a service policy
3. Add rules to block traffic from unwanted countries
4. Apply the service policy to HTTP Load Balancers

References:
- https://f5cloud.zendesk.com/hc/en-us/articles/7798225223447`,

  referenceUrl: 'https://f5cloud.zendesk.com/hc/en-us/articles/7798225223447-How-to-block-by-IP-or-Geolocation',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-023: Allowed HTTP Methods
// ───────────────────────────────────────────────────────────────────────────

export const SEC023_HTTPMethods: SecurityRule = {
  id: 'SEC-023',
  name: 'Service Policy - HTTP Methods Restriction',
  description:
    'Only required HTTP methods (GET, POST) should be allowed. ' +
    'Dangerous methods like PUT, DELETE, TRACE should be denied if not needed.',
  category: 'ACCESS_CONTROL',
  severity: 'MEDIUM',
  appliesTo: ['service_policy'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);
    const rules = (spec?.rules || spec?.rule_list?.rules || []) as Array<Record<string, unknown>>;

    let hasMethodRestriction = false;

    for (const rule of rules) {
      const match = rule?.match as Record<string, unknown>;
      const ruleSpec = rule?.spec as Record<string, unknown>;
      
      const httpMethod = match?.http_method || ruleSpec?.http_method || match?.methods;

      if (httpMethod) {
        hasMethodRestriction = true;
        break;
      }
    }

    if (hasMethodRestriction) {
      return {
        status: 'PASS',
        message: 'HTTP method restrictions configured',
        currentValue: 'configured',
        expectedValue: 'HTTP methods restricted',
      };
    }

    return {
      status: 'INFO',
      message: 'No HTTP method restrictions in this service policy',
      currentValue: null,
      expectedValue: 'Consider restricting to GET, POST, HEAD only',
    };
  },

  remediation: `To restrict HTTP methods:
1. Navigate to Shared Configuration → Service Policies
2. Create or edit a service policy
3. Add a rule to deny unwanted methods (TRACE, PUT, DELETE)
4. Allow only methods your application needs`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-security/service-policy',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-024: Global Log Receiver (SIEM Integration)
// ───────────────────────────────────────────────────────────────────────────

export const SEC024_GlobalLogReceiver: SecurityRule = {
  id: 'SEC-024',
  name: 'Global Log Receiver (SIEM)',
  description:
    'Logs should be streamed to a SIEM server for centralized monitoring, ' +
    'incident response, and compliance requirements.',
  category: 'LOGGING',
  severity: 'HIGH',
  appliesTo: ['global_log_receiver'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);
    const metadata = getMetadata(obj);

    const disabled = metadata?.disable === true;
    const name = metadata?.name as string || 'unknown';

    if (disabled) {
      return {
        status: 'WARN',
        message: `Global Log Receiver "${name}" is disabled`,
        currentValue: 'disabled',
        expectedValue: 'Active log receiver',
      };
    }

    // Check receiver type
    const receiverType = spec?.receiver || spec?.receiver_cfg;
    const logType = spec?.log_type as string || 'request_logs';

    const configuredReceivers: string[] = [];
    
    if (spec?.splunk_receiver) configuredReceivers.push('Splunk');
    if (spec?.datadog_receiver) configuredReceivers.push('Datadog');
    if (spec?.s3_receiver) configuredReceivers.push('AWS S3');
    if (spec?.azure_receiver || spec?.azure_blob_receiver) configuredReceivers.push('Azure');
    if (spec?.gcp_bucket_receiver) configuredReceivers.push('GCP');
    if (spec?.kafka_receiver) configuredReceivers.push('Kafka');
    if (spec?.http_receiver) configuredReceivers.push('HTTP');
    if (spec?.sumo_logic_receiver) configuredReceivers.push('Sumo Logic');
    if (spec?.qradar_receiver) configuredReceivers.push('QRadar');
    if (spec?.newrelic_receiver) configuredReceivers.push('New Relic');

    if (configuredReceivers.length > 0) {
      return {
        status: 'PASS',
        message: `Log streaming to ${configuredReceivers.join(', ')} (${logType})`,
        currentValue: { receivers: configuredReceivers, logType },
        expectedValue: 'SIEM integration configured',
      };
    }

    if (receiverType) {
      return {
        status: 'PASS',
        message: `Global Log Receiver configured for ${logType}`,
        currentValue: { logType },
        expectedValue: 'Log streaming configured',
      };
    }

    return {
      status: 'WARN',
      message: 'Global Log Receiver exists but no destination configured',
      currentValue: null,
      expectedValue: 'Log destination configured',
    };
  },

  remediation: `To configure Global Log Receiver:
1. Navigate to Shared Configuration → Global Log Receiver
2. Create a new log receiver
3. Select log type (Request Logs, Security Events)
4. Configure destination (Splunk, Datadog, S3, etc.)
5. Test log delivery to SIEM

Reference: https://docs.cloud.f5.com/docs-v2/multi-cloud-network-connect/how-tos/others/global-log-streaming`,

  referenceUrl: 'https://docs.cloud.f5.com/docs-v2/multi-cloud-network-connect/how-tos/others/global-log-streaming',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-024-CHECK: Tenant has Global Log Receiver
// ───────────────────────────────────────────────────────────────────────────

export const SEC024_TenantLogReceiver: SecurityRule = {
  id: 'SEC-024-TENANT',
  name: 'Tenant SIEM Integration',
  description:
    'At least one Global Log Receiver should be configured for the tenant ' +
    'to stream security events to a SIEM for monitoring and incident response.',
  category: 'LOGGING',
  severity: 'HIGH',
  appliesTo: ['http_loadbalancer'], // Run once per LB to check tenant-wide

  check: (_obj: unknown, context: AuditContext): CheckResult => {
    const glrCount = context.configs.globalLogReceivers.size;

    if (glrCount > 0) {
      return {
        status: 'PASS',
        message: `${glrCount} Global Log Receiver(s) configured for tenant`,
        currentValue: glrCount,
        expectedValue: 'At least one GLR configured',
      };
    }

    return {
      status: 'WARN',
      message: 'No Global Log Receivers configured - security events not streaming to SIEM',
      currentValue: 0,
      expectedValue: 'At least one Global Log Receiver',
    };
  },

  remediation: `To set up SIEM integration:
1. Navigate to Shared Configuration → Global Log Receiver
2. Create receivers for:
   - Security Events (WAF, Bot, DDoS)
   - Request Logs (access logs)
3. Integrate with your SIEM (Splunk, Datadog, etc.)
4. Set up dashboards and alerts in SIEM`,

  referenceUrl: 'https://docs.cloud.f5.com/docs-v2/multi-cloud-network-connect/how-tos/others/global-log-streaming',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-026: Custom Error Pages
// ───────────────────────────────────────────────────────────────────────────

export const SEC026_CustomErrorPages: SecurityRule = {
  id: 'SEC-026',
  name: 'Custom Error Response Pages',
  description:
    'Custom error pages should be configured for user-friendly experience and ' +
    'to avoid exposing infrastructure details in default error messages.',
  category: 'CLIENT_SECURITY',
  severity: 'LOW',
  appliesTo: ['http_loadbalancer'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    const customErrors = spec?.custom_errors as Record<string, string>;
    const moreOption = spec?.more_option as Record<string, unknown>;
    const moreCustomErrors = moreOption?.custom_errors as Record<string, string>;
    const disableDefaultErrors = moreOption?.disable_default_error_pages === true;

    const effectiveCustomErrors = customErrors || moreCustomErrors;

    if (effectiveCustomErrors && Object.keys(effectiveCustomErrors).length > 0) {
      const errorCodes = Object.keys(effectiveCustomErrors);
      return {
        status: 'PASS',
        message: `Custom error pages configured for: ${errorCodes.join(', ')}`,
        currentValue: errorCodes,
        expectedValue: 'Custom error pages configured',
      };
    }

    if (disableDefaultErrors) {
      return {
        status: 'WARN',
        message: 'Default error pages disabled but no custom pages configured',
        currentValue: 'disabled_no_custom',
        expectedValue: 'Custom error pages configured',
      };
    }

    return {
      status: 'INFO',
      message: 'Using default error pages - consider custom pages for better UX',
      currentValue: 'default',
      expectedValue: 'Custom error pages (optional)',
    };
  },

  remediation: `To configure custom error pages:
1. Navigate to HTTP Load Balancer → Advanced Configuration
2. In "Custom Errors" section, add custom HTML for:
   - 403 (Forbidden/WAF blocked)
   - 404 (Not Found)
   - 500 (Server Error)
   - 503 (Service Unavailable)
3. Benefits:
   - Better user experience
   - Hides infrastructure details
   - Consistent branding during outages`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-networking/http-load-balancer',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-028-LB: Service Policy Assigned to Load Balancer
// ───────────────────────────────────────────────────────────────────────────

export const SEC028_ServicePolicyAssigned: SecurityRule = {
  id: 'SEC-028-LB',
  name: 'Service Policy Assigned',
  description:
    'HTTP Load Balancers should have service policies assigned for access control, ' +
    'rate limiting, and geo-blocking enforcement.',
  category: 'ACCESS_CONTROL',
  severity: 'LOW',
  appliesTo: ['http_loadbalancer'],

  check: (obj: unknown, context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    const activeServicePolicies = spec?.active_service_policies as Record<string, unknown>;
    const servicePoliciesFromNs = spec?.service_policies_from_namespace;
    const noServicePolicies = spec?.no_service_policies === true;

    if (noServicePolicies) {
      return {
        status: 'INFO',
        message: 'Service policies explicitly disabled on this load balancer',
        currentValue: 'disabled',
        expectedValue: 'Service policy (optional)',
      };
    }

    if (activeServicePolicies?.policies) {
      const policies = activeServicePolicies.policies as Array<Record<string, unknown>>;
      const policyNames = policies.map(p => p?.name || 'unknown');
      return {
        status: 'PASS',
        message: `Service policies assigned: ${policyNames.join(', ')}`,
        currentValue: policyNames,
        expectedValue: 'Service policy assigned',
      };
    }

    if (servicePoliciesFromNs) {
      return {
        status: 'PASS',
        message: 'Using service policies from namespace',
        currentValue: 'from_namespace',
        expectedValue: 'Service policy assigned',
      };
    }

    return {
      status: 'INFO',
      message: 'No service policy assigned - consider adding for access control',
      currentValue: null,
      expectedValue: 'Service policy (recommended)',
    };
  },

  remediation: `To assign a service policy:
1. Create a service policy in Shared Configuration → Service Policies
2. Edit HTTP Load Balancer
3. In "Service Policies" section, select:
   - "Apply Specified Service Policies" to use specific policies
   - Or inherit from namespace
4. Service policies provide:
   - IP-based access control
   - Geo-blocking
   - Custom rate limiting`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-security/service-policy',
};

// Export all logging and service policy rules
export const loggingRules: SecurityRule[] = [
  SEC022_GeoBlocking,
  SEC023_HTTPMethods,
  SEC024_GlobalLogReceiver,
  SEC024_TenantLogReceiver,
  SEC026_CustomErrorPages,
  SEC028_ServicePolicyAssigned,
];
