// ═══════════════════════════════════════════════════════════════════════════
// Security Audit Engine
// Core engine that fetches configs and runs security rules
// ═══════════════════════════════════════════════════════════════════════════

import { apiClient } from '../api';
import { allRules } from './rules';
import type {
  SecurityRule,
  AuditContext,
  AuditFinding,
  AuditReport,
  AuditProgress,
  AuditOptions,
  AuditSummary,
  ConfigSnapshot,
  ConfigObjectType,
  Severity,
  RuleCategory,
} from './types';

// Helper to safely get metadata from object
const getMetadata = (obj: unknown): Record<string, unknown> => {
  const o = obj as Record<string, unknown>;
  return (o?.metadata || {}) as Record<string, unknown>;
};

export class AuditEngine {
  private rules: SecurityRule[] = allRules;
  private onProgress?: (progress: AuditProgress) => void;
  private aborted = false;

  constructor(onProgress?: (progress: AuditProgress) => void) {
    this.onProgress = onProgress;
  }

  abort() {
    this.aborted = true;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // MAIN ENTRY POINT
  // ─────────────────────────────────────────────────────────────────────────

  async runAudit(namespaces: string[], options?: AuditOptions): Promise<AuditReport> {
    this.aborted = false;
    const startTime = Date.now();
    const findings: AuditFinding[] = [];

    // PHASE 1: Fetch all configurations
    this.reportProgress({
      phase: 'fetching',
      message: 'Fetching configurations...',
      progress: 0,
    });

    const context = await this.fetchAllConfigs(namespaces);

    if (this.aborted) {
      throw new Error('Audit aborted');
    }

    // PHASE 2: Run all rules against all objects
    this.reportProgress({
      phase: 'scanning',
      message: 'Running security checks...',
      progress: 20,
    });

    // Filter rules based on options
    let rulesToRun = this.rules;

    if (options?.categories && options.categories.length > 0) {
      rulesToRun = rulesToRun.filter((r) => options.categories!.includes(r.category));
    }

    if (options?.minSeverity) {
      rulesToRun = rulesToRun.filter((r) => this.meetsMinSeverity(r.severity, options.minSeverity!));
    }

    let rulesChecked = 0;
    const totalRules = rulesToRun.length;

    // Track which tenant-level checks have been run (to avoid duplicates)
    const tenantChecksRun = new Set<string>();

    for (const rule of rulesToRun) {
      if (this.aborted) {
        throw new Error('Audit aborted');
      }

      // Special handling for tenant-level rules (run once, not per object)
      if (rule.id.includes('TENANT')) {
        if (tenantChecksRun.has(rule.id)) {
          continue;
        }
        tenantChecksRun.add(rule.id);

        // Run tenant-level check once with a dummy object
        try {
          const result = rule.check({}, context);

          const finding: AuditFinding = {
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            category: rule.category,
            namespace: 'tenant-wide',
            objectType: 'http_loadbalancer',
            objectName: 'Tenant Configuration',
            status: result.status,
            message: result.message || '',
            currentValue: result.currentValue,
            expectedValue: result.expectedValue,
            remediation: rule.remediation,
            referenceUrl: rule.referenceUrl,
            details: result.details,
          };

          if (options?.includePassedChecks || result.status !== 'PASS') {
            findings.push(finding);
          } else if (result.status === 'PASS') {
            findings.push(finding); // Always include passed for stats
          }
        } catch (error) {
          findings.push({
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            category: rule.category,
            namespace: 'tenant-wide',
            objectType: 'http_loadbalancer',
            objectName: 'Tenant Configuration',
            status: 'ERROR',
            message: `Error running check: ${(error as Error).message}`,
            remediation: rule.remediation,
          });
        }

        rulesChecked++;
        continue;
      }

      // Get objects this rule applies to
      const objectsToCheck = this.getObjectsForRule(rule, context);

      // Run the rule against each applicable object
      for (const { object, namespace, objectType } of objectsToCheck) {
        try {
          const result = rule.check(object, context);

          const metadata = getMetadata(object);
          const finding: AuditFinding = {
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            category: rule.category,
            namespace,
            objectType,
            objectName: (metadata?.name as string) || 'unknown',
            status: result.status,
            message: result.message || '',
            currentValue: result.currentValue,
            expectedValue: result.expectedValue,
            remediation: rule.remediation,
            referenceUrl: rule.referenceUrl,
            details: result.details,
          };

          findings.push(finding);
        } catch (error) {
          const metadata = getMetadata(object);
          findings.push({
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            category: rule.category,
            namespace,
            objectType,
            objectName: (metadata?.name as string) || 'unknown',
            status: 'ERROR',
            message: `Error running check: ${(error as Error).message}`,
            remediation: rule.remediation,
          });
        }
      }

      rulesChecked++;
      this.reportProgress({
        phase: 'scanning',
        message: `Checking rule ${rule.id}: ${rule.name}`,
        progress: 20 + Math.round((rulesChecked / totalRules) * 70),
        rulesChecked,
        totalRules,
        findingsCount: findings.filter((f) => f.status === 'FAIL').length,
      });
    }

    // PHASE 3: Generate report
    this.reportProgress({
      phase: 'reporting',
      message: 'Generating report...',
      progress: 95,
    });

    const report = this.generateReport(findings, context, namespaces, startTime, options);

    this.reportProgress({
      phase: 'complete',
      message: 'Audit complete!',
      progress: 100,
    });

    return report;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // PHASE 1: FETCH ALL CONFIGURATIONS
  // ─────────────────────────────────────────────────────────────────────────

  private async fetchAllConfigs(namespaces: string[]): Promise<AuditContext> {
    const configs: AuditContext['configs'] = {
      httpLoadBalancers: new Map(),
      originPools: new Map(),
      appFirewalls: new Map(),
      healthChecks: new Map(),
      servicePolicies: new Map(),
      certificates: new Map(),
      alertPolicies: new Map(),
      alertReceivers: new Map(),
      globalLogReceivers: new Map(),
      userIdentifications: new Map(),
    };

    let totalFetched = 0;
    const totalNamespaces = namespaces.length;

    // Fetch from each namespace
    for (let i = 0; i < namespaces.length; i++) {
      const namespace = namespaces[i];

      if (this.aborted) break;

      this.reportProgress({
        phase: 'fetching',
        message: `Fetching from namespace: ${namespace}`,
        progress: Math.round(((i + 1) / totalNamespaces) * 20),
        currentNamespace: namespace,
      });

      // Fetch all object types in parallel for this namespace
      const results = await Promise.allSettled([
        this.fetchLoadBalancers(namespace),
        this.fetchOriginPools(namespace),
        this.fetchAppFirewalls(namespace),
        this.fetchHealthChecks(namespace),
        this.fetchServicePolicies(namespace),
        this.fetchAlertPolicies(namespace),
        this.fetchAlertReceivers(namespace),
        this.fetchUserIdentifications(namespace),
      ]);

      // Process results
      if (results[0].status === 'fulfilled') {
        for (const [key, value] of results[0].value) {
          configs.httpLoadBalancers.set(key, value);
          totalFetched++;
        }
      }

      if (results[1].status === 'fulfilled') {
        for (const [key, value] of results[1].value) {
          configs.originPools.set(key, value);
          totalFetched++;
        }
      }

      if (results[2].status === 'fulfilled') {
        for (const [key, value] of results[2].value) {
          configs.appFirewalls.set(key, value);
          totalFetched++;
        }
      }

      if (results[3].status === 'fulfilled') {
        for (const [key, value] of results[3].value) {
          configs.healthChecks.set(key, value);
          totalFetched++;
        }
      }

      if (results[4].status === 'fulfilled') {
        for (const [key, value] of results[4].value) {
          configs.servicePolicies.set(key, value);
          totalFetched++;
        }
      }

      if (results[5].status === 'fulfilled') {
        for (const [key, value] of results[5].value) {
          configs.alertPolicies.set(key, value);
          totalFetched++;
        }
      }

      if (results[6].status === 'fulfilled') {
        for (const [key, value] of results[6].value) {
          configs.alertReceivers.set(key, value);
          totalFetched++;
        }
      }

      if (results[7].status === 'fulfilled') {
        for (const [key, value] of results[7].value) {
          configs.userIdentifications.set(key, value);
          totalFetched++;
        }
      }
    }

    // Fetch global objects (shared namespace)
    try {
      const glrMap = await this.fetchGlobalLogReceivers();
      for (const [key, value] of glrMap) {
        configs.globalLogReceivers.set(key, value);
        totalFetched++;
      }
    } catch (e) {
      console.warn('Could not fetch global log receivers:', e);
    }

    // Build context with helper methods
    const context: AuditContext = {
      tenant: apiClient.getTenant() || '',
      configs,
      getOriginPool: (ns, name) => configs.originPools.get(`${ns}/${name}`),
      getAppFirewall: (ns, name) => configs.appFirewalls.get(`${ns}/${name}`),
      getHealthCheck: (ns, name) => configs.healthChecks.get(`${ns}/${name}`),
      getCertificate: (ns, name) => configs.certificates.get(`${ns}/${name}`),
      getServicePolicy: (ns, name) => configs.servicePolicies.get(`${ns}/${name}`),
      getUserIdentification: (ns, name) => configs.userIdentifications.get(`${ns}/${name}`),
    };

    return context;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // FETCH METHODS FOR EACH OBJECT TYPE
  // ─────────────────────────────────────────────────────────────────────────

  private async fetchLoadBalancers(namespace: string): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    try {
      const resp = await apiClient.getLoadBalancers(namespace);
      for (const item of resp.items || []) {
        const name = item.metadata?.name || item.name;
        if (!name) continue;

        try {
          const full = await apiClient.getLoadBalancer(namespace, name);
          result.set(`${namespace}/${name}`, full);
        } catch {
          result.set(`${namespace}/${name}`, item);
        }
      }
    } catch (e) {
      console.warn(`Failed to fetch load balancers from ${namespace}:`, e);
    }
    return result;
  }

  private async fetchOriginPools(namespace: string): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    try {
      const resp = await apiClient.get<{ items: Array<{ metadata?: { name: string }; name?: string }> }>(
        `/api/config/namespaces/${namespace}/origin_pools`
      );
      for (const item of resp.items || []) {
        const name = item.metadata?.name || item.name;
        if (!name) continue;

        try {
          const full = await apiClient.getOriginPool(namespace, name);
          result.set(`${namespace}/${name}`, full);
        } catch {
          result.set(`${namespace}/${name}`, item);
        }
      }
    } catch (e) {
      console.warn(`Failed to fetch origin pools from ${namespace}:`, e);
    }
    return result;
  }

  private async fetchAppFirewalls(namespace: string): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    try {
      const resp = await apiClient.get<{ items: Array<{ metadata?: { name: string }; name?: string }> }>(
        `/api/config/namespaces/${namespace}/app_firewalls`
      );
      for (const item of resp.items || []) {
        const name = item.metadata?.name || item.name;
        if (!name) continue;

        try {
          const full = await apiClient.getWAFPolicy(namespace, name);
          result.set(`${namespace}/${name}`, full);
        } catch {
          result.set(`${namespace}/${name}`, item);
        }
      }
    } catch (e) {
      console.warn(`Failed to fetch app firewalls from ${namespace}:`, e);
    }
    return result;
  }

  private async fetchHealthChecks(namespace: string): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    try {
      const resp = await apiClient.get<{ items: Array<{ metadata?: { name: string }; name?: string }> }>(
        `/api/config/namespaces/${namespace}/healthchecks`
      );
      for (const item of resp.items || []) {
        const name = item.metadata?.name || item.name;
        if (!name) continue;

        try {
          const full = await apiClient.getHealthCheck(namespace, name);
          result.set(`${namespace}/${name}`, full);
        } catch {
          result.set(`${namespace}/${name}`, item);
        }
      }
    } catch (e) {
      console.warn(`Failed to fetch health checks from ${namespace}:`, e);
    }
    return result;
  }

  private async fetchServicePolicies(namespace: string): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    try {
      const resp = await apiClient.get<{ items: Array<{ metadata?: { name: string }; name?: string }> }>(
        `/api/config/namespaces/${namespace}/service_policys`
      );
      for (const item of resp.items || []) {
        const name = item.metadata?.name || item.name;
        if (!name) continue;

        try {
          const full = await apiClient.getServicePolicy(namespace, name);
          result.set(`${namespace}/${name}`, full);
        } catch {
          result.set(`${namespace}/${name}`, item);
        }
      }
    } catch (e) {
      console.warn(`Failed to fetch service policies from ${namespace}:`, e);
    }
    return result;
  }

  private async fetchAlertPolicies(namespace: string): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    try {
      const resp = await apiClient.getAlertPolicies(namespace);
      for (const item of resp.items || []) {
        const name = item.metadata?.name || item.name;
        if (!name) continue;

        try {
          const full = await apiClient.getAlertPolicy(namespace, name);
          result.set(`${namespace}/${name}`, full);
        } catch {
          result.set(`${namespace}/${name}`, item);
        }
      }
    } catch (e) {
      console.warn(`Failed to fetch alert policies from ${namespace}:`, e);
    }
    return result;
  }

  private async fetchAlertReceivers(namespace: string): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    try {
      const resp = await apiClient.getAlertReceivers(namespace);
      for (const item of resp.items || []) {
        const name = item.metadata?.name || item.name;
        if (!name) continue;

        try {
          const full = await apiClient.getAlertReceiver(namespace, name);
          result.set(`${namespace}/${name}`, full);
        } catch {
          result.set(`${namespace}/${name}`, item);
        }
      }
    } catch (e) {
      console.warn(`Failed to fetch alert receivers from ${namespace}:`, e);
    }
    return result;
  }

  private async fetchUserIdentifications(namespace: string): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    try {
      const resp = await apiClient.get<{ items: Array<{ metadata?: { name: string }; name?: string }> }>(
        `/api/config/namespaces/${namespace}/user_identifications`
      );
      for (const item of resp.items || []) {
        const name = item.metadata?.name || item.name;
        if (!name) continue;

        try {
          const full = await apiClient.getUserIdentificationPolicy(namespace, name);
          result.set(`${namespace}/${name}`, full);
        } catch {
          result.set(`${namespace}/${name}`, item);
        }
      }
    } catch (e) {
      console.warn(`Failed to fetch user identifications from ${namespace}:`, e);
    }
    return result;
  }

  private async fetchGlobalLogReceivers(): Promise<Map<string, unknown>> {
    const result = new Map<string, unknown>();
    try {
      const resp = await apiClient.get<{ items: Array<{ metadata?: { name: string }; name?: string }> }>(
        `/api/config/namespaces/shared/global_log_receivers`
      );
      for (const item of resp.items || []) {
        const name = item.metadata?.name || item.name;
        if (name) {
          result.set(`shared/${name}`, item);
        }
      }
    } catch (e) {
      console.warn('Failed to fetch global log receivers:', e);
    }
    return result;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // GET OBJECTS FOR A RULE
  // ─────────────────────────────────────────────────────────────────────────

  private getObjectsForRule(
    rule: SecurityRule,
    context: AuditContext
  ): Array<{ object: unknown; namespace: string; objectType: ConfigObjectType }> {
    const objects: Array<{ object: unknown; namespace: string; objectType: ConfigObjectType }> = [];

    for (const objectType of rule.appliesTo) {
      let configMap: Map<string, unknown>;

      switch (objectType) {
        case 'http_loadbalancer':
          configMap = context.configs.httpLoadBalancers;
          break;
        case 'origin_pool':
          configMap = context.configs.originPools;
          break;
        case 'app_firewall':
          configMap = context.configs.appFirewalls;
          break;
        case 'healthcheck':
          configMap = context.configs.healthChecks;
          break;
        case 'service_policy':
          configMap = context.configs.servicePolicies;
          break;
        case 'certificate':
          configMap = context.configs.certificates;
          break;
        case 'alert_policy':
          configMap = context.configs.alertPolicies;
          break;
        case 'alert_receiver':
          configMap = context.configs.alertReceivers;
          break;
        case 'global_log_receiver':
          configMap = context.configs.globalLogReceivers;
          break;
        case 'user_identification':
          configMap = context.configs.userIdentifications;
          break;
        default:
          continue;
      }

      for (const [key, object] of configMap) {
        const [namespace] = key.split('/');
        objects.push({ object, namespace, objectType });
      }
    }

    return objects;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // GENERATE FINAL REPORT
  // ─────────────────────────────────────────────────────────────────────────

  private generateReport(
    findings: AuditFinding[],
    context: AuditContext,
    namespaces: string[],
    startTime: number,
    options?: AuditOptions
  ): AuditReport {
    // Filter out passed checks if not requested
    let reportFindings = findings;
    if (!options?.includePassedChecks) {
      reportFindings = findings.filter((f) => f.status !== 'PASS');
    }

    // Calculate summary
    const summary: AuditSummary = {
      total: findings.length,
      critical: findings.filter((f) => f.status === 'FAIL' && f.severity === 'CRITICAL').length,
      high: findings.filter((f) => f.status === 'FAIL' && f.severity === 'HIGH').length,
      medium: findings.filter((f) => f.status === 'FAIL' && f.severity === 'MEDIUM').length,
      low: findings.filter((f) => f.status === 'FAIL' && f.severity === 'LOW').length,
      info: findings.filter((f) => f.status === 'FAIL' && f.severity === 'INFO').length,
      passed: findings.filter((f) => f.status === 'PASS').length,
      warnings: findings.filter((f) => f.status === 'WARN').length,
      errors: findings.filter((f) => f.status === 'ERROR').length,
      skipped: findings.filter((f) => f.status === 'SKIP').length,
    };

    // Calculate security score (0-100)
    const totalChecks = findings.filter((f) => f.status !== 'SKIP' && f.status !== 'ERROR').length;
    const passedChecks = summary.passed;
    const score = totalChecks > 0 ? Math.round((passedChecks / totalChecks) * 100) : 0;

    // Config snapshot
    const configSnapshot: ConfigSnapshot = {
      loadBalancers: context.configs.httpLoadBalancers.size,
      originPools: context.configs.originPools.size,
      wafPolicies: context.configs.appFirewalls.size,
      healthChecks: context.configs.healthChecks.size,
      servicePolicies: context.configs.servicePolicies.size,
      certificates: context.configs.certificates.size,
      alertPolicies: context.configs.alertPolicies.size,
      alertReceivers: context.configs.alertReceivers.size,
      globalLogReceivers: context.configs.globalLogReceivers.size,
      userIdentifications: context.configs.userIdentifications.size,
    };

    return {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      tenant: context.tenant,
      namespaces,
      durationMs: Date.now() - startTime,
      summary,
      score,
      findings: reportFindings.sort((a, b) => {
        // Sort by severity (CRITICAL first), then by status (FAIL first)
        const severityOrder: Record<Severity, number> = {
          CRITICAL: 0,
          HIGH: 1,
          MEDIUM: 2,
          LOW: 3,
          INFO: 4,
        };
        const statusOrder: Record<string, number> = {
          FAIL: 0,
          WARN: 1,
          ERROR: 2,
          PASS: 3,
          SKIP: 4,
        };

        const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
        if (sevDiff !== 0) return sevDiff;

        return (statusOrder[a.status] || 5) - (statusOrder[b.status] || 5);
      }),
      configSnapshot,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // HELPER METHODS
  // ─────────────────────────────────────────────────────────────────────────

  private reportProgress(progress: AuditProgress) {
    if (this.onProgress) {
      this.onProgress(progress);
    }
  }

  private meetsMinSeverity(ruleSeverity: Severity, minSeverity: Severity): boolean {
    const order: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 1,
      MEDIUM: 2,
      LOW: 3,
      INFO: 4,
    };
    return order[ruleSeverity] <= order[minSeverity];
  }
}
