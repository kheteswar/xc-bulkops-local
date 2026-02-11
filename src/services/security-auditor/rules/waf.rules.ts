// ═══════════════════════════════════════════════════════════════════════════
// WAF Security Rules
// SEC-008 through SEC-010
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
// SEC-008: WAF Blocking Mode
// ───────────────────────────────────────────────────────────────────────────

export const SEC008_WAFBlocking: SecurityRule = {
  id: 'SEC-008',
  name: 'WAF Blocking Mode',
  description:
    'Web Application Firewall must be in Blocking mode in production to ' +
    'actively stop malicious traffic like SQLi, XSS, and command injection.',
  category: 'WAF',
  severity: 'CRITICAL',
  appliesTo: ['app_firewall'],

  check: (obj: unknown, context: AuditContext): CheckResult => {
    const spec = getSpec(obj);
    const metadata = getMetadata(obj);
    const wafName = metadata?.name as string || 'unknown';
    const wafNamespace = metadata?.namespace as string || 'default';

    // Check enforcement mode
    const mode = (spec?.enforcement_mode as string) || 'unknown';
    const isBlocking =
      mode === 'ENFORCEMENT_MODE_BLOCKING' ||
      mode === 'blocking' ||
      mode.toLowerCase().includes('block');

    // Find which load balancers use this WAF
    const affectedLoadBalancers: string[] = [];

    for (const [key, lb] of context.configs.httpLoadBalancers) {
      const lbSpec = getSpec(lb);
      const wafRef = lbSpec?.app_firewall as Record<string, unknown>;

      if (wafRef?.name === wafName) {
        const lbMeta = getMetadata(lb);
        affectedLoadBalancers.push((lbMeta?.name as string) || key);
      }
    }

    if (isBlocking) {
      return {
        status: 'PASS',
        message: 'WAF is in Blocking mode',
        currentValue: mode,
        expectedValue: 'ENFORCEMENT_MODE_BLOCKING',
        details: {
          usedByLoadBalancers: affectedLoadBalancers,
        },
      };
    }

    return {
      status: 'FAIL',
      message: `WAF is in ${mode} mode - malicious requests are NOT being blocked!`,
      currentValue: mode,
      expectedValue: 'ENFORCEMENT_MODE_BLOCKING',
      details: {
        usedByLoadBalancers: affectedLoadBalancers,
        impact:
          affectedLoadBalancers.length > 0
            ? `Affects ${affectedLoadBalancers.length} load balancer(s): ${affectedLoadBalancers.join(', ')}`
            : 'WAF not currently assigned to any load balancer',
      },
    };
  },

  remediation: `To enable WAF blocking mode:
1. Navigate to Web App & API Protection → App Firewalls
2. Edit the firewall policy
3. Change "Enforcement Mode" from "Monitoring" to "Blocking"
4. IMPORTANT: Test in staging environment first to avoid blocking legitimate traffic
5. Review WAF events after enabling to tune false positives`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-security/waf-policy',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-009: WAF Signature Accuracy
// ───────────────────────────────────────────────────────────────────────────

export const SEC009_WAFSignatureAccuracy: SecurityRule = {
  id: 'SEC-009',
  name: 'WAF High & Medium Accuracy Signatures',
  description:
    'WAF should have High and Medium accuracy attack signatures enabled ' +
    'to detect common attack patterns while minimizing false positives.',
  category: 'WAF',
  severity: 'HIGH',
  appliesTo: ['app_firewall'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    // Check detection settings
    const detectionSettings = spec?.detection_settings as Record<string, unknown>;
    const signatureSelection = spec?.signature_selection_by_accuracy as Record<string, unknown>;
    
    // Check if using default or custom signature settings
    const useDefaultSignatures = spec?.default_detection_settings !== undefined;
    
    if (useDefaultSignatures) {
      return {
        status: 'PASS',
        message: 'Using default detection settings (High & Medium signatures enabled)',
        currentValue: 'default_detection_settings',
        expectedValue: 'High and Medium accuracy signatures enabled',
      };
    }

    // Check custom signature settings
    const highAccuracy = 
      signatureSelection?.high_accuracy_signatures !== false &&
      detectionSettings?.signature_selection?.high_and_medium_accuracy_signatures !== undefined;
    
    const mediumAccuracy = 
      signatureSelection?.medium_accuracy_signatures !== false;

    // Check for disabled signatures
    const disableSignatures = spec?.disable_detection_settings !== undefined;
    
    if (disableSignatures) {
      return {
        status: 'FAIL',
        message: 'Detection settings are DISABLED - no attack signatures active',
        currentValue: 'disabled',
        expectedValue: 'High and Medium accuracy signatures enabled',
      };
    }

    // Try to determine signature status from various fields
    const enabledModes: string[] = [];
    
    if (detectionSettings?.enable_signature_based_detection !== false) {
      if (signatureSelection?.high_accuracy_signatures !== false) {
        enabledModes.push('High');
      }
      if (signatureSelection?.medium_accuracy_signatures !== false) {
        enabledModes.push('Medium');
      }
      if (signatureSelection?.low_accuracy_signatures === true) {
        enabledModes.push('Low');
      }
    }

    // If we found explicit settings
    if (enabledModes.length > 0) {
      const hasHighAndMedium = enabledModes.includes('High') && enabledModes.includes('Medium');
      
      if (hasHighAndMedium) {
        return {
          status: 'PASS',
          message: `Attack signatures enabled: ${enabledModes.join(', ')} accuracy`,
          currentValue: enabledModes,
          expectedValue: ['High', 'Medium'],
        };
      }
      
      return {
        status: 'WARN',
        message: `Only ${enabledModes.join(', ')} accuracy signatures enabled`,
        currentValue: enabledModes,
        expectedValue: ['High', 'Medium'],
      };
    }

    // Assume default if no explicit settings found
    return {
      status: 'PASS',
      message: 'Signature settings appear to use defaults (High & Medium enabled)',
      currentValue: 'implicit_default',
      expectedValue: 'High and Medium accuracy signatures enabled',
    };
  },

  remediation: `To configure WAF signature accuracy:
1. Navigate to Web App & API Protection → App Firewalls
2. Edit the firewall policy
3. In Detection Settings, ensure:
   - High accuracy signatures: Enabled
   - Medium accuracy signatures: Enabled
4. Optionally enable Low accuracy for stricter protection (may cause more false positives)
5. Test thoroughly before deploying to production`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-security/waf-policy',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-010: WAF Attack Types Active
// ───────────────────────────────────────────────────────────────────────────

export const SEC010_WAFAttackTypes: SecurityRule = {
  id: 'SEC-010',
  name: 'WAF Attack Types Active',
  description:
    'All standard attack signature types should be active including ' +
    'SQLi, XSS, Command Injection, and other OWASP Top 10 attack categories.',
  category: 'WAF',
  severity: 'MEDIUM',
  appliesTo: ['app_firewall'],

  check: (obj: unknown, _context: AuditContext): CheckResult => {
    const spec = getSpec(obj);

    // Check if all attack types are enabled
    const attackTypeSettings = spec?.attack_type_settings as Record<string, unknown>;
    const disabledAttackTypes = spec?.disabled_attack_types as string[];

    // Check for disabled detection
    if (spec?.disable_detection_settings !== undefined) {
      return {
        status: 'FAIL',
        message: 'Detection settings are disabled - no attack types active',
        currentValue: 'disabled',
        expectedValue: 'All attack types active',
      };
    }

    // If disabled_attack_types is specified, some are disabled
    if (disabledAttackTypes && disabledAttackTypes.length > 0) {
      return {
        status: 'WARN',
        message: `Some attack types are disabled: ${disabledAttackTypes.join(', ')}`,
        currentValue: { disabledTypes: disabledAttackTypes },
        expectedValue: 'All attack types active',
      };
    }

    // Check if using default (all enabled) or custom settings
    if (attackTypeSettings?.disabled_attack_types) {
      const disabled = attackTypeSettings.disabled_attack_types as string[];
      if (disabled.length > 0) {
        return {
          status: 'WARN',
          message: `Some attack types are disabled: ${disabled.join(', ')}`,
          currentValue: { disabledTypes: disabled },
          expectedValue: 'All attack types active',
        };
      }
    }

    return {
      status: 'PASS',
      message: 'All attack signature types are active',
      currentValue: 'all_active',
      expectedValue: 'All attack types active',
    };
  },

  remediation: `To enable all attack types:
1. Navigate to Web App & API Protection → App Firewalls
2. Edit the firewall policy
3. In Attack Type Settings, ensure all categories are enabled:
   - SQL Injection
   - Cross-Site Scripting (XSS)
   - Command Injection
   - Path Traversal
   - And other OWASP categories
4. Review any disabled types and enable if appropriate for your application`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-security/waf-policy',
};

// ───────────────────────────────────────────────────────────────────────────
// SEC-008-LB: Load Balancer has WAF Assigned
// ───────────────────────────────────────────────────────────────────────────

export const SEC008_LB_WAFAssigned: SecurityRule = {
  id: 'SEC-008-LB',
  name: 'WAF Policy Assigned to Load Balancer',
  description:
    'Each HTTP Load Balancer should have a Web Application Firewall policy assigned ' +
    'to protect against common web attacks.',
  category: 'WAF',
  severity: 'CRITICAL',
  appliesTo: ['http_loadbalancer'],

  check: (obj: unknown, context: AuditContext): CheckResult => {
    const spec = getSpec(obj);
    const metadata = getMetadata(obj);
    const lbNamespace = metadata?.namespace as string || 'default';

    // Check if WAF is assigned
    const appFirewall = spec?.app_firewall as Record<string, unknown>;
    const disableWaf = spec?.disable_waf === true;

    if (disableWaf) {
      return {
        status: 'FAIL',
        message: 'WAF is explicitly disabled on this load balancer',
        currentValue: 'disabled',
        expectedValue: 'WAF policy assigned',
      };
    }

    if (!appFirewall || !appFirewall?.name) {
      return {
        status: 'FAIL',
        message: 'No WAF policy assigned to this load balancer',
        currentValue: null,
        expectedValue: 'WAF policy assigned',
      };
    }

    // Verify the WAF policy exists
    const wafName = appFirewall.name as string;
    const wafNamespace = (appFirewall.namespace as string) || lbNamespace;
    const wafKey = `${wafNamespace}/${wafName}`;
    const wafExists = context.configs.appFirewalls.has(wafKey);

    if (!wafExists) {
      return {
        status: 'WARN',
        message: `WAF policy "${wafName}" is referenced but could not be verified`,
        currentValue: wafName,
        expectedValue: 'Valid WAF policy assigned',
      };
    }

    return {
      status: 'PASS',
      message: `WAF policy "${wafName}" is assigned`,
      currentValue: wafName,
      expectedValue: 'WAF policy assigned',
    };
  },

  remediation: `To assign a WAF policy:
1. Navigate to Multi-Cloud App Connect → Load Balancers → HTTP Load Balancers
2. Edit the load balancer
3. In the "Security" section, select a Web Application Firewall policy
4. If no policy exists, create one first under App Firewalls
5. Save the configuration`,

  referenceUrl: 'https://docs.cloud.f5.com/docs/how-to/app-security/waf-policy',
};

// Export all WAF rules
export const wafRules: SecurityRule[] = [
  SEC008_WAFBlocking,
  SEC008_LB_WAFAssigned,
  SEC009_WAFSignatureAccuracy,
  SEC010_WAFAttackTypes,
];
