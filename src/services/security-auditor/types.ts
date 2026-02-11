// ═══════════════════════════════════════════════════════════════════════════
// Security Auditor Types
// ═══════════════════════════════════════════════════════════════════════════

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type RuleCategory =
  | 'TLS_SSL'
  | 'WAF'
  | 'BOT_DEFENSE'
  | 'API_SECURITY'
  | 'DDOS'
  | 'ORIGIN'
  | 'ACCESS_CONTROL'
  | 'LOGGING'
  | 'ALERTING'
  | 'USER_IDENTIFICATION'
  | 'RATE_LIMITING'
  | 'CLIENT_SECURITY';

export type ConfigObjectType =
  | 'http_loadbalancer'
  | 'origin_pool'
  | 'app_firewall'
  | 'service_policy'
  | 'healthcheck'
  | 'user_identification'
  | 'alert_policy'
  | 'alert_receiver'
  | 'certificate'
  | 'global_log_receiver';

export type CheckStatus = 'PASS' | 'FAIL' | 'WARN' | 'SKIP' | 'ERROR';

// ═══════════════════════════════════════════════════════════════════════════
// Check Result - Output from running a rule against one object
// ═══════════════════════════════════════════════════════════════════════════

export interface CheckResult {
  status: CheckStatus;
  message?: string;
  currentValue?: unknown;
  expectedValue?: unknown;
  details?: Record<string, unknown>;
}

// ═══════════════════════════════════════════════════════════════════════════
// Audit Context - Shared context available to all rules
// ═══════════════════════════════════════════════════════════════════════════

export interface AuditContext {
  tenant: string;
  configs: {
    httpLoadBalancers: Map<string, unknown>;
    originPools: Map<string, unknown>;
    appFirewalls: Map<string, unknown>;
    healthChecks: Map<string, unknown>;
    servicePolicies: Map<string, unknown>;
    certificates: Map<string, unknown>;
    alertPolicies: Map<string, unknown>;
    alertReceivers: Map<string, unknown>;
    globalLogReceivers: Map<string, unknown>;
    userIdentifications: Map<string, unknown>;
  };
  // Helper methods for cross-referencing
  getOriginPool: (namespace: string, name: string) => unknown | undefined;
  getAppFirewall: (namespace: string, name: string) => unknown | undefined;
  getHealthCheck: (namespace: string, name: string) => unknown | undefined;
  getCertificate: (namespace: string, name: string) => unknown | undefined;
  getServicePolicy: (namespace: string, name: string) => unknown | undefined;
  getUserIdentification: (namespace: string, name: string) => unknown | undefined;
}

// ═══════════════════════════════════════════════════════════════════════════
// Security Rule Definition
// ═══════════════════════════════════════════════════════════════════════════

export interface SecurityRule {
  id: string;
  name: string;
  description: string;
  category: RuleCategory;
  severity: Severity;
  appliesTo: ConfigObjectType[];
  check: (object: unknown, context: AuditContext) => CheckResult;
  remediation: string;
  referenceUrl?: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// Audit Finding - Final recorded finding
// ═══════════════════════════════════════════════════════════════════════════

export interface AuditFinding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  category: RuleCategory;
  namespace: string;
  objectType: ConfigObjectType;
  objectName: string;
  status: CheckStatus;
  message: string;
  currentValue?: unknown;
  expectedValue?: unknown;
  remediation: string;
  referenceUrl?: string;
  details?: Record<string, unknown>;
  rawConfig?: unknown;
}

// ═══════════════════════════════════════════════════════════════════════════
// Audit Progress
// ═══════════════════════════════════════════════════════════════════════════

export interface AuditProgress {
  phase: 'fetching' | 'scanning' | 'reporting' | 'complete';
  message: string;
  progress?: number;
  currentNamespace?: string;
  rulesChecked?: number;
  totalRules?: number;
  objectsFetched?: number;
  totalObjects?: number;
  findingsCount?: number;
}

// ═══════════════════════════════════════════════════════════════════════════
// Audit Report
// ═══════════════════════════════════════════════════════════════════════════

export interface AuditSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  passed: number;
  warnings: number;
  errors: number;
  skipped: number;
}

export interface ConfigSnapshot {
  loadBalancers: number;
  originPools: number;
  wafPolicies: number;
  healthChecks: number;
  servicePolicies: number;
  certificates: number;
  alertPolicies: number;
  alertReceivers: number;
  globalLogReceivers: number;
  userIdentifications: number;
}

export interface AuditReport {
  id: string;
  timestamp: string;
  tenant: string;
  namespaces: string[];
  durationMs: number;
  summary: AuditSummary;
  score: number;
  findings: AuditFinding[];
  configSnapshot: ConfigSnapshot;
}

// ═══════════════════════════════════════════════════════════════════════════
// Audit Options
// ═══════════════════════════════════════════════════════════════════════════

export interface AuditOptions {
  categories?: RuleCategory[];
  minSeverity?: Severity;
  includePassedChecks?: boolean;
}

// ═══════════════════════════════════════════════════════════════════════════
// Category and Severity Metadata
// ═══════════════════════════════════════════════════════════════════════════

export const CATEGORY_INFO: Record<RuleCategory, { label: string; icon: string; description: string }> = {
  TLS_SSL: { label: 'TLS/SSL Security', icon: '🔒', description: 'Certificate and encryption settings' },
  WAF: { label: 'Web Application Firewall', icon: '🛡️', description: 'WAF configuration and policies' },
  BOT_DEFENSE: { label: 'Bot Defense', icon: '🤖', description: 'Bot detection and mitigation' },
  API_SECURITY: { label: 'API Security', icon: '🔌', description: 'API protection settings' },
  DDOS: { label: 'DDoS Protection', icon: '⚡', description: 'DDoS mitigation settings' },
  ORIGIN: { label: 'Origin Security', icon: '🏠', description: 'Origin pool and backend settings' },
  ACCESS_CONTROL: { label: 'Access Control', icon: '🚪', description: 'Service policies and geo-blocking' },
  LOGGING: { label: 'Logging & Monitoring', icon: '📊', description: 'Log streaming and SIEM integration' },
  ALERTING: { label: 'Alerting', icon: '🔔', description: 'Alert policies and notifications' },
  USER_IDENTIFICATION: { label: 'User Identification', icon: '👤', description: 'User tracking and identification' },
  RATE_LIMITING: { label: 'Rate Limiting', icon: '⏱️', description: 'Rate limiting configuration' },
  CLIENT_SECURITY: { label: 'Client-Side Security', icon: '🖥️', description: 'Client-side defense settings' },
};

export const SEVERITY_INFO: Record<Severity, { label: string; color: string; bgColor: string; order: number }> = {
  CRITICAL: { label: 'Critical', color: 'text-red-400', bgColor: 'bg-red-500/20', order: 0 },
  HIGH: { label: 'High', color: 'text-orange-400', bgColor: 'bg-orange-500/20', order: 1 },
  MEDIUM: { label: 'Medium', color: 'text-yellow-400', bgColor: 'bg-yellow-500/20', order: 2 },
  LOW: { label: 'Low', color: 'text-blue-400', bgColor: 'bg-blue-500/20', order: 3 },
  INFO: { label: 'Info', color: 'text-slate-400', bgColor: 'bg-slate-500/20', order: 4 },
};

export const STATUS_INFO: Record<CheckStatus, { label: string; color: string; bgColor: string; icon: string }> = {
  PASS: { label: 'Passed', color: 'text-green-400', bgColor: 'bg-green-500/20', icon: '✓' },
  FAIL: { label: 'Failed', color: 'text-red-400', bgColor: 'bg-red-500/20', icon: '✗' },
  WARN: { label: 'Warning', color: 'text-yellow-400', bgColor: 'bg-yellow-500/20', icon: '⚠' },
  SKIP: { label: 'Skipped', color: 'text-slate-400', bgColor: 'bg-slate-500/20', icon: '○' },
  ERROR: { label: 'Error', color: 'text-purple-400', bgColor: 'bg-purple-500/20', icon: '!' },
};
