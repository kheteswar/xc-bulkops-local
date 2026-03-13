/**
 * FP Analysis Excel Report Generator
 *
 * Generates a well-formatted Excel workbook using SheetJS (xlsx).
 * Each scope gets its own sheet with proper headers, column widths, and styling.
 * Designed for easy copy-paste into emails and reports.
 */

import * as XLSX from 'xlsx';
import type {
  AnalysisScope,
  AnalysisMode,
  SummaryResult,
  ThreatMeshAnalysisUnit,
  SignatureAnalysisUnit,
  ViolationAnalysisUnit,
  WafExclusionPolicyObject,
} from './types';

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

export interface FPExcelReportOptions {
  summary: SummaryResult;
  scopes: AnalysisScope[];
  namespace: string;
  lbName: string;
  mode: AnalysisMode;
  threatMeshDetails?: ThreatMeshAnalysisUnit[];
  signatureDetails?: SignatureAnalysisUnit[];
  violationDetails?: ViolationAnalysisUnit[];
  exclusionPolicy?: WafExclusionPolicyObject;
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

function setColWidths(ws: XLSX.WorkSheet, widths: number[]): void {
  ws['!cols'] = widths.map(w => ({ wch: w }));
}

function topEntries(record: Record<string, number>, count = 5): string {
  return Object.entries(record)
    .sort((a, b) => b[1] - a[1])
    .slice(0, count)
    .map(([k, v]) => `${k} (${v})`)
    .join(', ');
}

function verdictLabel(verdict: string): string {
  switch (verdict) {
    case 'highly_likely_fp': return 'Highly Likely FP';
    case 'likely_fp': return 'Likely FP';
    case 'ambiguous': return 'Ambiguous';
    case 'likely_tp': return 'Likely TP';
    case 'confirmed_tp': return 'Confirmed TP';
    case 'investigate': return 'Investigate';
    default: return verdict;
  }
}

// ═══════════════════════════════════════════════════════════════════
// SHEET BUILDERS
// ═══════════════════════════════════════════════════════════════════

function buildSummarySheet(opts: FPExcelReportOptions): XLSX.WorkSheet {
  const rows: (string | number)[][] = [];

  rows.push(['FP Analysis Report — Executive Summary']);
  rows.push([]);
  rows.push(['Load Balancer', opts.lbName]);
  rows.push(['Namespace', opts.namespace]);
  rows.push(['Mode', opts.mode]);
  rows.push(['Scopes', opts.scopes.join(', ')]);
  rows.push(['Period Start', opts.summary.period.start]);
  rows.push(['Period End', opts.summary.period.end]);
  rows.push(['Generated', new Date().toISOString()]);
  rows.push([]);
  rows.push(['Metric', 'Value']);
  rows.push(['Total Events', opts.summary.totalEvents]);
  rows.push(['Unique Signatures', opts.summary.signatures.length]);
  rows.push(['Unique Violations', opts.summary.violations.length]);
  rows.push(['Threat Mesh IPs', opts.summary.threatMeshIPs.length]);
  rows.push(['Service Policy Rules', opts.summary.policyRules.length]);

  const ws = XLSX.utils.aoa_to_sheet(rows);
  setColWidths(ws, [25, 50]);
  return ws;
}

function buildSignaturesSheet(opts: FPExcelReportOptions): XLSX.WorkSheet {
  const header = [
    'Sig ID', 'Name', 'Attack Type', 'Accuracy', 'Events', 'Unique Users',
    'Unique IPs', 'Unique Paths', 'Top Paths', 'Auto Suppressed',
    'Block Actions', 'Report Actions', 'FP Score', 'FP Verdict', 'Quick Verdict', 'Confidence',
  ];

  const dataRows = opts.summary.signatures.map(s => [
    s.sigId,
    s.name,
    s.attackType,
    s.accuracy,
    s.totalEvents,
    s.uniqueUsers,
    s.uniqueIPs,
    s.uniquePaths,
    s.topPaths.map(p => `${p.path} (${p.count})`).join('\n'),
    s.autoSuppressed ? 'Yes' : 'No',
    s.actions.block,
    s.actions.report,
    s.fpScore,
    verdictLabel(s.fpVerdict),
    verdictLabel(s.quickVerdict),
    s.quickConfidence,
  ]);

  const ws = XLSX.utils.aoa_to_sheet([header, ...dataRows]);
  setColWidths(ws, [15, 35, 20, 15, 10, 12, 12, 12, 50, 12, 12, 12, 10, 18, 18, 12]);
  return ws;
}

function buildViolationsSheet(opts: FPExcelReportOptions): XLSX.WorkSheet {
  const header = [
    'Violation Name', 'Attack Type', 'Events', 'Unique Users',
    'Unique Paths', 'Top Paths', 'Quick Verdict', 'Confidence',
  ];

  const dataRows = opts.summary.violations.map(v => [
    v.violationName,
    v.attackType,
    v.totalEvents,
    v.uniqueUsers,
    v.uniquePaths,
    v.topPaths.map(p => `${p.path} (${p.count})`).join('\n'),
    verdictLabel(v.quickVerdict),
    v.quickConfidence,
  ]);

  const ws = XLSX.utils.aoa_to_sheet([header, ...dataRows]);
  setColWidths(ws, [40, 20, 10, 12, 12, 50, 18, 12]);
  return ws;
}

function buildPerPathAnalysisSheet(
  sigDetails: SignatureAnalysisUnit[],
  violDetails: ViolationAnalysisUnit[],
): XLSX.WorkSheet {
  const header = [
    'Type', 'ID/Name', 'Path', 'Events', 'Users', 'IPs',
    'Methods', 'FP Score', 'Verdict', 'Reasons',
  ];

  const dataRows: (string | number)[][] = [];

  for (const unit of sigDetails) {
    if (!unit.pathAnalyses) continue;
    for (const pa of unit.pathAnalyses) {
      dataRows.push([
        'Signature',
        `${unit.signatureId} - ${unit.signatureName}`,
        pa.path,
        pa.eventCount,
        pa.uniqueUsers,
        pa.uniqueIPs,
        Object.keys(pa.methods).join(', '),
        pa.fpScore,
        verdictLabel(pa.verdict),
        pa.reasons.join('; '),
      ]);
    }
  }

  for (const unit of violDetails) {
    if (!unit.pathAnalyses) continue;
    for (const pa of unit.pathAnalyses) {
      dataRows.push([
        'Violation',
        unit.violationName,
        pa.path,
        pa.eventCount,
        pa.uniqueUsers,
        pa.uniqueIPs,
        Object.keys(pa.methods).join(', '),
        pa.fpScore,
        verdictLabel(pa.verdict),
        pa.reasons.join('; '),
      ]);
    }
  }

  const ws = XLSX.utils.aoa_to_sheet([header, ...dataRows]);
  setColWidths(ws, [12, 40, 50, 10, 10, 10, 25, 10, 18, 60]);
  return ws;
}

function buildExclusionRulesSheet(policy: WafExclusionPolicyObject): XLSX.WorkSheet {
  const header = [
    'Rule Name', 'Domain', 'Path', 'Methods',
    'Sig Exclusions', 'Violation Exclusions', 'Attack Type Exclusions',
    'Description',
  ];

  const dataRows = policy.spec.waf_exclusion_rules.map(rule => [
    rule.metadata.name,
    rule.any_domain ? 'any' : rule.exact_value || '',
    rule.any_path ? 'any' : rule.path_prefix || rule.path_regex || '',
    rule.methods.join(', ') || 'any',
    rule.app_firewall_detection_control.exclude_signature_contexts
      .map(s => `${s.signature_id} (${s.context}${s.context_name ? ': ' + s.context_name : ''})`)
      .join('\n'),
    rule.app_firewall_detection_control.exclude_violation_contexts
      .map(v => `${v.exclude_violation} (${v.context})`)
      .join('\n'),
    rule.app_firewall_detection_control.exclude_attack_type_contexts
      .map(a => `${a.exclude_attack_type} (${a.context})`)
      .join('\n'),
    rule.metadata.description || '',
  ]);

  const ws = XLSX.utils.aoa_to_sheet([header, ...dataRows]);
  setColWidths(ws, [25, 15, 40, 20, 50, 50, 40, 50]);
  return ws;
}

function buildThreatMeshSummarySheet(opts: FPExcelReportOptions): XLSX.WorkSheet {
  const header = [
    'Source IP', 'Country', 'AS Organization', 'Sec Events', 'Access Log Reqs',
    'Success Rate', 'Avg Req/Hour', 'Paths', 'Description', 'Action',
    'User Agent', 'Attack Types', 'Tenant Count',
    'Quick Verdict', 'Enriched Verdict', 'Enriched Score',
  ];

  const dataRows = opts.summary.threatMeshIPs.map(ip => [
    ip.srcIp,
    ip.country || '',
    ip.asOrg || '',
    ip.eventCount,
    ip.accessLogRequests ?? '',
    ip.successRate != null ? `${(ip.successRate * 100).toFixed(1)}%` : '',
    ip.avgReqPerHour != null ? ip.avgReqPerHour.toFixed(1) : '',
    ip.paths,
    ip.description,
    ip.action || '',
    ip.userAgent || '',
    (ip.attackTypes || []).join(', '),
    ip.tenantCount || 0,
    verdictLabel(ip.quickVerdict),
    ip.enrichedVerdict ? verdictLabel(ip.enrichedVerdict) : '',
    ip.enrichedScore ?? '',
  ]);

  const ws = XLSX.utils.aoa_to_sheet([header, ...dataRows]);
  setColWidths(ws, [18, 12, 25, 12, 14, 12, 12, 8, 40, 10, 35, 30, 12, 18, 18, 12]);
  return ws;
}

function buildThreatMeshDetailSheet(details: ThreatMeshAnalysisUnit[]): XLSX.WorkSheet {
  const header = [
    'Source IP', 'User', 'Country', 'AS Org', 'User Agent',
    'Event Count', 'Total Requests on App', 'WAF Events from IP',
    'Description', 'Attack Types', 'Tenant Count', 'Global Events',
    'High Accuracy Sigs', 'TLS Events', 'Malicious Bot Events',
    'Paths Accessed', 'Response Codes',
    'FP Score', 'Verdict', 'Reasons',
    'Suggested Action',
  ];

  const dataRows = details.map(ip => [
    ip.srcIp,
    ip.user || '',
    ip.country || '',
    ip.asOrg || '',
    ip.userAgent || '',
    ip.totalRequestsOnApp || 0,
    ip.totalRequestsOnApp || 0,
    ip.wafEventsFromThisIP || 0,
    ip.threatDetails?.description || '',
    (ip.threatDetails?.attackTypes || []).join(', '),
    ip.threatDetails?.tenantCount || 0,
    ip.threatDetails?.events || 0,
    ip.threatDetails?.highAccuracySignatures || 0,
    ip.threatDetails?.tlsCount || 0,
    ip.threatDetails?.maliciousBotEvents || 0,
    ip.pathsAccessed ? topEntries(ip.pathsAccessed, 10) : '',
    ip.rspCodes ? topEntries(ip.rspCodes) : '',
    ip.fpScore,
    verdictLabel(ip.verdict),
    (ip.reasons || []).join('\n'),
    ip.suggestedAction || 'no_action',
  ]);

  const ws = XLSX.utils.aoa_to_sheet([header, ...dataRows]);
  setColWidths(ws, [
    18, 20, 12, 25, 35,
    12, 15, 12,
    40, 30, 12, 12,
    15, 12, 15,
    50, 30,
    10, 18, 50,
    18,
  ]);
  return ws;
}

function buildPolicyRulesSheet(opts: FPExcelReportOptions): XLSX.WorkSheet {
  const header = ['Rule Name', 'Policy Name', 'Total Blocked', 'Unique IPs'];

  const dataRows = opts.summary.policyRules.map(r => [
    r.ruleName,
    r.policyName,
    r.totalBlocked,
    r.uniqueIPs,
  ]);

  const ws = XLSX.utils.aoa_to_sheet([header, ...dataRows]);
  setColWidths(ws, [30, 30, 15, 12]);
  return ws;
}

// ═══════════════════════════════════════════════════════════════════
// MAIN EXPORT
// ═══════════════════════════════════════════════════════════════════

export function generateFPAnalysisExcel(opts: FPExcelReportOptions): void {
  const wb = XLSX.utils.book_new();

  // Always add summary sheet
  XLSX.utils.book_append_sheet(wb, buildSummarySheet(opts), 'Summary');

  if (opts.scopes.includes('waf_signatures') && opts.summary.signatures.length > 0) {
    XLSX.utils.book_append_sheet(wb, buildSignaturesSheet(opts), 'WAF Signatures');
  }

  if (opts.scopes.includes('waf_violations') && opts.summary.violations.length > 0) {
    XLSX.utils.book_append_sheet(wb, buildViolationsSheet(opts), 'WAF Violations');
  }

  // Per-path analysis sheet (if detailed data available)
  const sigDetails = opts.signatureDetails || [];
  const violDetails = opts.violationDetails || [];
  if (sigDetails.length > 0 || violDetails.length > 0) {
    XLSX.utils.book_append_sheet(wb, buildPerPathAnalysisSheet(sigDetails, violDetails), 'Per-Path Analysis');
  }

  if (opts.scopes.includes('threat_mesh') && opts.summary.threatMeshIPs.length > 0) {
    XLSX.utils.book_append_sheet(wb, buildThreatMeshSummarySheet(opts), 'Threat Mesh Summary');

    if (opts.threatMeshDetails && opts.threatMeshDetails.length > 0) {
      XLSX.utils.book_append_sheet(wb, buildThreatMeshDetailSheet(opts.threatMeshDetails), 'Threat Mesh Details');
    }
  }

  if (opts.scopes.includes('service_policy') && opts.summary.policyRules.length > 0) {
    XLSX.utils.book_append_sheet(wb, buildPolicyRulesSheet(opts), 'Service Policy');
  }

  // WAF Exclusion Rules sheet
  if (opts.exclusionPolicy && opts.exclusionPolicy.spec.waf_exclusion_rules.length > 0) {
    XLSX.utils.book_append_sheet(wb, buildExclusionRulesSheet(opts.exclusionPolicy), 'WAF Exclusion Rules');
  }

  // Write and download
  const wbout = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
  const blob = new Blob([wbout], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `fp-analysis-${opts.lbName}-${new Date().toISOString().split('T')[0]}.xlsx`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
