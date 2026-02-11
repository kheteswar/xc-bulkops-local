// ═══════════════════════════════════════════════════════════════════════════
// TLS/SSL Security Rules
// SEC-001 through SEC-005
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
// SEC-001: HTTP to HTTPS Redirect
// ───────────────────────────────────────────────────────────────────────────

export const SEC001_HttpRedirect: SecurityRule = {
  id: 'SEC-001',
  name: 'HTTP to HTTPS Redirect',
  description:
    'HTTP traffic should be automatically redirected to HTTPS to enforce ' +
    'secure communication between users and your application.',
  category: 'TLS_SSL',
  severity: 'HIGH',
  appliesTo: ['http_loadbalancer'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    // Check various possible locations for http_redirect setting
    const httpRedirect =
      spec?.http_redirect === true ||
      (spec?.http as Record<string, unknown>)?.http_redirect === true ||
      spec?.redirect_to_https === true;

    if (httpRedirect) {
      return {
        status: 'PASS',
        message: 'HTTP to HTTPS redirect is enabled',
        currentValue: true,
        expectedValue: true,
      };
    }

    return {
      status: 'FAIL',
      message: 'HTTP to HTTPS redirect is NOT enabled - traffic may be unencrypted',
      currentValue: false,
      expectedValue: true,
    };
  },

  remediation: `To enable HTTP to HTTPS redirect:
1. Navigate to Multi-Cloud App Connect → Load Balancers → HTTP Load Balancers
2. Edit the load balancer configuration
3. In the "HTTP" section, enable "HTTP Redirect to HTTPS"
4. Save and apply the configuration`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-networking/http-load-balancer',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-002: HSTS Header Enabled
// ───────────────────────────────────────────────────────────────────────────

export const SEC002_HSTSHeader: SecurityRule = {
  id: 'SEC-002',
  name: 'HSTS Header Enabled',
  description:
    'HSTS (HTTP Strict Transport Security) tells browsers to only access the ' +
    'application using HTTPS, preventing protocol downgrade attacks.',
  category: 'TLS_SSL',
  severity: 'HIGH',
  appliesTo: ['http_loadbalancer'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    const hstsEnabled =
      spec?.add_hsts_header === true ||
      (spec?.https as Record<string, unknown>)?.add_hsts_header === true ||
      (spec?.https_auto_cert as Record<string, unknown>)?.add_hsts_header === true;

    if (hstsEnabled) {
      return {
        status: 'PASS',
        message: 'HSTS header is enabled',
        currentValue: true,
        expectedValue: true,
      };
    }

    return {
      status: 'FAIL',
      message: 'HSTS header is NOT enabled - browsers may accept insecure connections',
      currentValue: false,
      expectedValue: true,
    };
  },

  remediation: `To enable HSTS header:
1. Navigate to Multi-Cloud App Connect → Load Balancers → HTTP Load Balancers
2. Edit the load balancer configuration
3. Enable "Add HSTS Header" option
4. Save and apply the configuration

Note: Ensure all resources are served over HTTPS before enabling HSTS.`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-networking/http-load-balancer',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-003: SSL Certificate Blindfolded
// ───────────────────────────────────────────────────────────────────────────

export const SEC003_CertificateBlindfolded: SecurityRule = {
  id: 'SEC-003',
  name: 'SSL Certificate Blindfolded',
  description:
    'SSL private keys should be blindfolded (encrypted) before uploading to F5 XC, ' +
    'ensuring no one can view or access the key in plaintext.',
  category: 'TLS_SSL',
  severity: 'MEDIUM',
  appliesTo: ['http_loadbalancer'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    // Check if using auto cert (no custom cert to blindfold)
    if (spec?.https_auto_cert || spec?.automatic_certificate) {
      return {
        status: 'PASS',
        message: 'Using automatic certificate - no custom private key to blindfold',
        currentValue: 'auto_cert',
        expectedValue: 'blindfolded or auto_cert',
      };
    }

    // Check for custom TLS config
    const httpsConfig = (spec?.https || spec?.tls_parameters || {}) as Record<string, unknown>;
    const tlsCert = httpsConfig?.tls_certificates as Array<Record<string, unknown>>;

    if (!tlsCert || tlsCert.length === 0) {
      return {
        status: 'SKIP',
        message: 'No custom TLS certificate configured',
      };
    }

    // Check if private key is blindfolded
    for (const cert of tlsCert) {
      const privateKey = cert?.private_key as Record<string, unknown>;
      const isBlindfolded =
        privateKey?.blindfold_secret_info !== undefined ||
        privateKey?.blindfolded_secret !== undefined ||
        privateKey?.secret_encoding_type === 'EncodingBlindfolded';

      if (!isBlindfolded && privateKey) {
        return {
          status: 'FAIL',
          message: 'SSL private key is NOT blindfolded - key may be accessible in plaintext',
          currentValue: 'not_blindfolded',
          expectedValue: 'blindfolded',
        };
      }
    }

    return {
      status: 'PASS',
      message: 'SSL certificate private key is blindfolded',
      currentValue: 'blindfolded',
      expectedValue: 'blindfolded',
    };
  },

  remediation: `To blindfold SSL certificate:
1. When uploading a certificate, use the "Blindfold" option
2. This encrypts the private key locally before uploading
3. For existing certificates, re-upload with blindfolding enabled

Reference: https://docs.cloud.f5.com/docs-v2/platform/concepts/security#secrets-management-and-blindfold`,

  referenceUrl: 'https://docs.cloud.f5.com/docs-v2/platform/concepts/security#secrets-management-and-blindfold',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-004: Origin Pool TLS Enabled
// ───────────────────────────────────────────────────────────────────────────

export const SEC004_OriginTLS: SecurityRule = {
  id: 'SEC-004',
  name: 'Origin Pool TLS Enabled',
  description:
    'SSL/TLS should be enabled between F5 XC and origin servers to ensure ' +
    'end-to-end encryption and prevent plaintext exposure.',
  category: 'TLS_SSL',
  severity: 'HIGH',
  appliesTo: ['origin_pool'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    // Check for TLS configuration
    const useTls = spec?.use_tls;
    const hasTlsConfig = spec?.tls_config !== undefined;
    const port = (spec?.port as number) || 
                 ((spec?.origin_servers as Array<Record<string, unknown>>)?.[0]?.port as number) || 
                 80;

    // TLS is enabled if use_tls is set OR tls_config exists OR port is 443
    const tlsEnabled = useTls || hasTlsConfig || port === 443;

    if (tlsEnabled) {
      return {
        status: 'PASS',
        message: 'TLS is enabled for origin connectivity',
        currentValue: { useTls: !!useTls, hasTlsConfig, port },
        expectedValue: 'TLS enabled',
      };
    }

    return {
      status: 'FAIL',
      message: 'TLS is NOT enabled - traffic to origin is unencrypted',
      currentValue: { useTls: false, port },
      expectedValue: 'TLS enabled (use_tls: true or port: 443)',
    };
  },

  remediation: `To enable TLS for origin connectivity:
1. Navigate to Multi-Cloud App Connect → Load Balancers → Origin Pools
2. Edit the origin pool configuration
3. Enable "TLS" in the origin server settings
4. Configure appropriate TLS settings (minimum TLS 1.2)
5. Save and verify connectivity`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-networking/origin-pools',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-005: TLS 1.2 Minimum Version
// ───────────────────────────────────────────────────────────────────────────

export const SEC005_TLSVersion: SecurityRule = {
  id: 'SEC-005',
  name: 'TLS 1.2+ for Origin',
  description:
    'TLS 1.2 or higher should be enforced for all backend connections. ' +
    'Older versions (TLS 1.0, 1.1) have known vulnerabilities like BEAST and POODLE.',
  category: 'TLS_SSL',
  severity: 'HIGH',
  appliesTo: ['origin_pool'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    // If TLS is not enabled, skip this check
    if (!spec?.use_tls && !spec?.tls_config) {
      return {
        status: 'SKIP',
        message: 'TLS not enabled on this origin pool - skipping version check',
      };
    }

    const tlsConfig = spec?.tls_config as Record<string, unknown>;
    const minVersion =
      (tlsConfig?.min_version as string) ||
      (tlsConfig?.minimum_protocol_version as string) ||
      'TLS_AUTO';

    // Acceptable versions
    const secureVersions = ['TLS_1_2', 'TLS_1_3', 'TLSv1.2', 'TLSv1.3', 'TLS12', 'TLS13'];
    const normalizedVersion = minVersion.toUpperCase().replace(/[.\-]/g, '_').replace('V', '_');
    const isSecure = secureVersions.some((v) => normalizedVersion.includes(v.replace('.', '_')));

    if (isSecure) {
      return {
        status: 'PASS',
        message: `TLS minimum version is ${minVersion}`,
        currentValue: minVersion,
        expectedValue: 'TLS 1.2 or higher',
      };
    }

    // TLS_AUTO might be okay but worth warning
    if (minVersion === 'TLS_AUTO' || minVersion === 'AUTO') {
      return {
        status: 'WARN',
        message: 'TLS version is set to AUTO - consider explicitly setting TLS 1.2+',
        currentValue: minVersion,
        expectedValue: 'TLS 1.2 or higher (explicit)',
      };
    }

    return {
      status: 'FAIL',
      message: `TLS minimum version ${minVersion} is insecure`,
      currentValue: minVersion,
      expectedValue: 'TLS 1.2 or higher',
    };
  },

  remediation: `To enforce TLS 1.2 minimum:
1. Edit the origin pool configuration
2. In TLS settings, set "Minimum TLS Version" to "TLS 1.2"
3. Verify your origin server supports TLS 1.2+
4. Save and test connectivity`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-networking/origin-pools',
};

// Export all TLS/SSL rules
export const tlsSslRules: SecurityRule[] = [
  SEC001_HttpRedirect,
  SEC002_HSTSHeader,
  SEC003_CertificateBlindfolded,
  SEC004_OriginTLS,
  SEC005_TLSVersion,
];
