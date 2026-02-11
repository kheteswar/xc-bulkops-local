// ═══════════════════════════════════════════════════════════════════════════
// Origin Security Rules
// SEC-006, SEC-007
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
// SEC-006: Connection Timeout Configuration
// ───────────────────────────────────────────────────────────────────────────

export const SEC006_ConnectionTimeout: SecurityRule = {
  id: 'SEC-006',
  name: 'Origin Connection Timeout',
  description:
    'Connection timeout should be properly configured (typically ≥10s) to prevent ' +
    'intermittent errors or excessive 503 errors during origin server heavy loads.',
  category: 'ORIGIN',
  severity: 'MEDIUM',
  appliesTo: ['origin_pool'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    // Get connection timeout - could be in various formats
    const connectionTimeout = spec?.connection_timeout as number | string | undefined;
    const advancedOptions = spec?.advanced_options as Record<string, unknown>;
    const timeout = advancedOptions?.connection_timeout as number | string | undefined;

    const effectiveTimeout = connectionTimeout || timeout;

    if (effectiveTimeout === undefined) {
      return {
        status: 'WARN',
        message: 'Connection timeout not explicitly configured - using default',
        currentValue: 'default',
        expectedValue: '≥10000ms (10 seconds)',
      };
    }

    // Parse timeout value (could be number in ms or string like "10s")
    let timeoutMs: number;
    if (typeof effectiveTimeout === 'number') {
      timeoutMs = effectiveTimeout;
    } else if (typeof effectiveTimeout === 'string') {
      if (effectiveTimeout.endsWith('s')) {
        timeoutMs = parseFloat(effectiveTimeout) * 1000;
      } else if (effectiveTimeout.endsWith('ms')) {
        timeoutMs = parseFloat(effectiveTimeout);
      } else {
        timeoutMs = parseFloat(effectiveTimeout);
      }
    } else {
      timeoutMs = 0;
    }

    if (timeoutMs >= 10000) {
      return {
        status: 'PASS',
        message: `Connection timeout is ${timeoutMs}ms (${timeoutMs / 1000}s)`,
        currentValue: timeoutMs,
        expectedValue: '≥10000ms (10 seconds)',
      };
    }

    if (timeoutMs > 0 && timeoutMs < 10000) {
      return {
        status: 'WARN',
        message: `Connection timeout is ${timeoutMs}ms - consider increasing to ≥10s for reliability`,
        currentValue: timeoutMs,
        expectedValue: '≥10000ms (10 seconds)',
      };
    }

    return {
      status: 'WARN',
      message: 'Could not determine connection timeout value',
      currentValue: effectiveTimeout,
      expectedValue: '≥10000ms (10 seconds)',
    };
  },

  remediation: `To configure connection timeout:
1. Navigate to Multi-Cloud App Connect → Load Balancers → Origin Pools
2. Edit the origin pool
3. In Advanced Options, set "Connection Timeout" to at least 10000ms (10 seconds)
4. Adjust based on your origin server's response times

Reference: https://my.f5.com/manage/s/article/K000146828 for common error codes`,

  referenceUrl: 'https://my.f5.com/manage/s/article/K000146828',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-007: Health Check Configured
// ───────────────────────────────────────────────────────────────────────────

export const SEC007_HealthCheck: SecurityRule = {
  id: 'SEC-007',
  name: 'Health Check Configured',
  description:
    'Health checks should be configured for origin pools to detect and ' +
    'stop routing traffic to unhealthy or unresponsive servers.',
  category: 'ORIGIN',
  severity: 'HIGH',
  appliesTo: ['origin_pool'],

  check: (obj: unknown, context: AuditContext): CheckResult => {
    const spec = getSpec(obj);
    const metadata = getMetadata(obj);
    const namespace = (metadata?.namespace as string) || 'default';

    // Check if health check is referenced
    const healthCheckRefs = (spec?.healthcheck || spec?.health_check || spec?.health_checks || []) as Array<Record<string, unknown> | string>;

    if (!healthCheckRefs || healthCheckRefs.length === 0) {
      return {
        status: 'FAIL',
        message: 'No health check configured for this origin pool',
        currentValue: null,
        expectedValue: 'At least one health check configured',
      };
    }

    // Validate that referenced health checks exist
    const validHealthChecks: string[] = [];
    const missingHealthChecks: string[] = [];

    for (const hcRef of healthCheckRefs) {
      let hcName: string;
      let hcNamespace: string;

      if (typeof hcRef === 'string') {
        hcName = hcRef;
        hcNamespace = namespace;
      } else {
        hcName = (hcRef?.name as string) || '';
        hcNamespace = (hcRef?.namespace as string) || namespace;
      }

      if (!hcName) continue;

      const key = `${hcNamespace}/${hcName}`;
      const healthCheck = context.configs.healthChecks.get(key);

      if (healthCheck) {
        validHealthChecks.push(hcName);
      } else {
        // Health check referenced but not fetched - might still exist
        missingHealthChecks.push(hcName);
      }
    }

    if (validHealthChecks.length === 0 && missingHealthChecks.length > 0) {
      return {
        status: 'WARN',
        message: `Health check(s) referenced but could not be verified: ${missingHealthChecks.join(', ')}`,
        currentValue: { referenced: missingHealthChecks },
        expectedValue: 'Valid health check configured',
      };
    }

    if (validHealthChecks.length > 0) {
      return {
        status: 'PASS',
        message: `Health check(s) configured: ${validHealthChecks.join(', ')}`,
        currentValue: validHealthChecks,
        expectedValue: 'Health check configured',
      };
    }

    // Has references but couldn't validate
    return {
      status: 'PASS',
      message: 'Health check is configured',
      currentValue: healthCheckRefs.length,
      expectedValue: 'Health check configured',
    };
  },

  remediation: `To configure health checks:
1. First, create a health check:
   - Navigate to Multi-Cloud App Connect → Health Checks
   - Create an HTTP or TCP health check
   - Configure appropriate path, interval, and thresholds
2. Then, assign to origin pool:
   - Edit the origin pool
   - Add the health check reference
3. Monitor health status in the dashboard`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-networking/origin-pools#health-checks',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-030: Origin Server Uses Private IPs (Informational)
// ───────────────────────────────────────────────────────────────────────────

export const SEC030_OriginPrivateIP: SecurityRule = {
  id: 'SEC-030',
  name: 'Origin Server IP Visibility',
  description:
    'Informational check to identify if origin servers are using public IPs. ' +
    'Origin servers should ideally be whitelisted to only receive traffic from F5 PoPs.',
  category: 'ORIGIN',
  severity: 'INFO',
  appliesTo: ['origin_pool'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    const originServers = (spec?.origin_servers || []) as Array<Record<string, unknown>>;

    if (originServers.length === 0) {
      return {
        status: 'SKIP',
        message: 'No origin servers configured',
      };
    }

    const publicIPs: string[] = [];
    const privateIPs: string[] = [];
    const domains: string[] = [];

    for (const server of originServers) {
      // Check for public IP
      const publicIP = server?.public_ip as Record<string, unknown>;
      if (publicIP?.ip) {
        publicIPs.push(publicIP.ip as string);
        continue;
      }

      // Check for private IP
      const privateIP = server?.private_ip as Record<string, unknown>;
      if (privateIP?.ip) {
        privateIPs.push(privateIP.ip as string);
        continue;
      }

      // Check for public name (FQDN)
      const publicName = server?.public_name as Record<string, unknown>;
      if (publicName?.dns_name) {
        domains.push(publicName.dns_name as string);
        continue;
      }

      // Check for private name
      const privateName = server?.private_name as Record<string, unknown>;
      if (privateName?.dns_name) {
        domains.push(`(private) ${privateName.dns_name}`);
      }
    }

    if (publicIPs.length > 0) {
      return {
        status: 'WARN',
        message: `Origin uses public IP(s): ${publicIPs.join(', ')} - ensure firewall restricts to F5 PoP IPs only`,
        currentValue: { publicIPs, privateIPs, domains },
        expectedValue: 'Origin restricted to F5 PoP traffic',
        details: {
          recommendation: 'Whitelist only F5 XC PoP IP ranges on origin firewall',
          reference: 'https://docs.cloud.f5.com/docs-v2/platform/reference/network-cloud-ref',
        },
      };
    }

    return {
      status: 'PASS',
      message: 'Origin servers configured',
      currentValue: { privateIPs, domains },
      expectedValue: 'Origin configured',
    };
  },

  remediation: `To secure origin access:
1. Restrict origin server firewall to only allow traffic from F5 XC PoP IP ranges
2. Refer to F5 PoP IP list: https://docs.cloud.f5.com/docs-v2/platform/reference/network-cloud-ref
3. Block all other inbound traffic to origin on the application port
4. This ensures only legitimate traffic from F5 can reach your origin`,

  referenceUrl: 'https://docs.cloud.f5.com/docs-v2/platform/reference/network-cloud-ref',
};

// Export all Origin rules
export const originRules: SecurityRule[] = [
  SEC006_ConnectionTimeout,
  SEC007_HealthCheck,
  SEC030_OriginPrivateIP,
];
