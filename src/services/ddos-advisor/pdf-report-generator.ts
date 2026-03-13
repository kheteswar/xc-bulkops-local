import jsPDF from 'jspdf';
import autoTablePlugin from 'jspdf-autotable';
import type { DdosAnalysisResults } from './types';

const BLUE = [59, 130, 246] as const;
const DARK = [30, 41, 59] as const;
const GRAY = [100, 116, 139] as const;
const GREEN = [34, 197, 94] as const;
const PAGE_MARGIN = 20;
const CONTENT_WIDTH = 170;

function ensureSpace(doc: jsPDF, y: number, needed: number): number {
  if (y + needed > doc.internal.pageSize.getHeight() - 25) {
    doc.addPage();
    return PAGE_MARGIN;
  }
  return y;
}

function sectionTitle(doc: jsPDF, title: string, y: number): number {
  y = ensureSpace(doc, y, 20);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...BLUE);
  doc.text(title, PAGE_MARGIN, y);
  y += 2;
  doc.setDrawColor(...BLUE);
  doc.setLineWidth(0.5);
  doc.line(PAGE_MARGIN, y, PAGE_MARGIN + CONTENT_WIDTH, y);
  doc.setTextColor(...DARK);
  return y + 8;
}

function n(num: number): string {
  return num.toLocaleString();
}

function autoTable(doc: jsPDF, opts: Record<string, unknown>): number {
  autoTablePlugin(doc, opts);
  return (doc as any).lastAutoTable.finalY + 8;
}

function severityColor(severity: string): number[] {
  switch (severity) {
    case 'critical': return [239, 68, 68];    // red-500
    case 'high': return [249, 115, 22];       // orange-500
    case 'medium': return [234, 179, 8];      // yellow-500
    case 'low': return [59, 130, 246];        // blue-500
    default: return [100, 116, 139];           // gray
  }
}

export interface DdosPdfOptions {
  results: DdosAnalysisResults;
  chartImage?: string;
}

export async function generateDdosPdfReport(opts: DdosPdfOptions): Promise<void> {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const r = opts.results;
  let y = 25;

  // Header
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...BLUE);
  doc.text('DDoS Settings Advisor Report', PAGE_MARGIN, y);
  y += 10;

  doc.setFontSize(11);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(...GRAY);
  doc.text(`Load Balancer: ${r.lbName}`, PAGE_MARGIN, y); y += 5;
  doc.text(`Namespace: ${r.namespace}`, PAGE_MARGIN, y); y += 5;
  if (r.domains.length > 0) {
    doc.text(`Domains: ${r.domains.slice(0, 3).join(', ')}${r.domains.length > 3 ? '...' : ''}`, PAGE_MARGIN, y); y += 5;
  }
  const start = new Date(r.analysisStart).toLocaleString();
  const end = new Date(r.analysisEnd).toLocaleString();
  doc.text(`Analysis Period: ${start}  —  ${end}`, PAGE_MARGIN, y); y += 5;
  doc.text(`Generated: ${new Date(r.generatedAt).toLocaleString()}`, PAGE_MARGIN, y); y += 3;
  doc.setDrawColor(...BLUE);
  doc.setLineWidth(1);
  doc.line(PAGE_MARGIN, y, PAGE_MARGIN + CONTENT_WIDTH, y);
  y += 10;

  // Executive Summary
  y = sectionTitle(doc, 'Executive Summary', y);
  const col1 = PAGE_MARGIN; const col2 = PAGE_MARGIN + 57; const col3 = PAGE_MARGIN + 114;

  doc.setFontSize(9); doc.setFont('helvetica', 'bold'); doc.setTextColor(...GRAY);
  doc.text('Total Requests', col1, y);
  doc.text('Peak RPS', col2, y);
  doc.text('Security Events', col3, y);
  y += 5;
  doc.setFontSize(12); doc.setFont('helvetica', 'bold'); doc.setTextColor(...DARK);
  doc.text(n(r.trafficStats.totalRequests), col1, y);
  doc.text(n(r.trafficStats.peakRps), col2, y);
  doc.text(n(r.trafficStats.totalSecurityEvents), col3, y);
  y += 12;

  // Traffic Profile
  const profile = r.trafficStats.trafficProfile;
  doc.setFontSize(9); doc.setFont('helvetica', 'bold'); doc.setTextColor(...GRAY);
  doc.text('Traffic Type', col1, y);
  doc.text('API Traffic %', col2, y);
  doc.text('Recommended Threshold (3× Peak)', col3, y);
  y += 5;
  doc.setFontSize(10); doc.setFont('helvetica', 'normal'); doc.setTextColor(...DARK);
  doc.text(profile.type.toUpperCase(), col1, y);
  doc.text(`${profile.apiTrafficPct}%`, col2, y);
  const recThreshold = r.rpsRecommendations[0]?.rpsThreshold;
  doc.text(recThreshold ? n(recThreshold) + ' RPS' : '-', col3, y);
  y += 10;

  // Current config
  const cfg = r.currentConfig;
  doc.setFontSize(9); doc.setFont('helvetica', 'bold'); doc.setTextColor(...GRAY);
  doc.text('Current RPS Threshold', col1, y);
  doc.text('Mitigation Action', col2, y);
  doc.text('Key Features', col3, y);
  y += 5;
  doc.setFontSize(10); doc.setFont('helvetica', 'normal'); doc.setTextColor(...DARK);
  doc.text(cfg.rpsThreshold ? n(cfg.rpsThreshold) + (cfg.isDefaultRpsThreshold ? ' (default)' : '') : 'Not set', col1, y);
  doc.text(cfg.mitigationAction, col2, y);
  const features = [cfg.threatMeshEnabled && 'Threat Mesh', cfg.ipReputationEnabled && 'IP Rep', cfg.botDefenseEnabled && 'Bot Defense'].filter(Boolean).join(', ') || 'None';
  doc.text(features, col3, y);
  y += 12;

  // Findings
  y = sectionTitle(doc, `Findings (${r.findings.length})`, y);
  if (r.findings.length > 0) {
    const rows = r.findings.map(f => [
      f.severity.toUpperCase(),
      f.title,
      f.currentValue.length > 25 ? f.currentValue.slice(0, 22) + '...' : f.currentValue,
      f.recommendedValue.length > 35 ? f.recommendedValue.slice(0, 32) + '...' : f.recommendedValue,
    ]);
    y = autoTable(doc, {
      startY: y,
      head: [['Severity', 'Finding', 'Current', 'Recommended']],
      body: rows,
      theme: 'striped',
      headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 8 },
      styles: { fontSize: 8, cellPadding: 2 },
      margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 0) {
          const sev = String(data.cell.raw).toLowerCase();
          data.cell.styles.textColor = severityColor(sev);
          data.cell.styles.fontStyle = 'bold';
        }
      },
    });
  }

  // RPS Recommendations
  y = sectionTitle(doc, 'RPS Threshold Recommendations', y);
  const rpsRows = r.rpsRecommendations.map(rec => [
    rec.label + (rec.isRecommended ? ' ★' : ''),
    n(rec.rpsThreshold) + ' RPS',
    rec.formula,
  ]);
  y = autoTable(doc, {
    startY: y,
    head: [['Algorithm', 'Threshold', 'Formula']],
    body: rpsRows,
    theme: 'striped',
    headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 9 },
    styles: { fontSize: 9, cellPadding: 2 },
    margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
    columnStyles: { 1: { fontStyle: 'bold' } },
  });

  // Traffic chart
  if (opts.chartImage) {
    y = sectionTitle(doc, 'Traffic Pattern', y);
    y = ensureSpace(doc, y, 80);
    doc.addImage(opts.chartImage, 'PNG', PAGE_MARGIN, y, CONTENT_WIDTH, CONTENT_WIDTH * 0.35);
    y += CONTENT_WIDTH * 0.35 + 8;
  }

  // Aggregate RPS distribution
  y = sectionTitle(doc, 'Aggregate RPS Distribution', y);
  const rpsStats = r.trafficStats.aggregateRps;
  const distRows = [
    ['P50 (Median)', String(rpsStats.p50), '50% of seconds had this RPS or less'],
    ['P75', String(rpsStats.p75), '75% of seconds had this RPS or less'],
    ['P90', String(rpsStats.p90), '90% of seconds had this RPS or less'],
    ['P95', String(rpsStats.p95), '95% of seconds had this RPS or less'],
    ['P99', String(rpsStats.p99), '99% of seconds had this RPS or less'],
    ['Max (Peak)', String(rpsStats.max), 'Highest observed aggregate RPS'],
    ['Mean', rpsStats.mean.toFixed(1), 'Average across all seconds'],
    ['Std Dev', rpsStats.stdDev.toFixed(1), 'Traffic variability'],
  ];
  y = autoTable(doc, {
    startY: y,
    head: [['Metric', 'Value (RPS)', 'Description']],
    body: distRows,
    theme: 'striped',
    headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 9 },
    styles: { fontSize: 9, cellPadding: 2 },
    margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
    columnStyles: { 1: { halign: 'right', fontStyle: 'bold' } },
  });

  // Recommended config JSON
  y = sectionTitle(doc, 'Recommended Configuration', y);
  const jsonStr = JSON.stringify(r.recommendedConfig, null, 2);
  doc.setFontSize(8);
  doc.setFont('courier', 'normal');
  doc.setTextColor(...GREEN);
  const jsonLines = doc.splitTextToSize(jsonStr, CONTENT_WIDTH - 10);
  const boxHeight = jsonLines.length * 3.5 + 6;
  y = ensureSpace(doc, y, boxHeight + 5);
  doc.setFillColor(15, 23, 42);
  doc.roundedRect(PAGE_MARGIN, y - 3, CONTENT_WIDTH, boxHeight, 2, 2, 'F');
  doc.text(jsonLines, PAGE_MARGIN + 5, y + 2);
  y += boxHeight + 10;

  // Footers
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    const pageH = doc.internal.pageSize.getHeight();
    const pageW = doc.internal.pageSize.getWidth();
    doc.setFontSize(8);
    doc.setTextColor(150, 150, 150);
    doc.text(`Page ${i} of ${pageCount}`, pageW / 2, pageH - 10, { align: 'center' });
    doc.text('XC App Store — DDoS Settings Advisor', PAGE_MARGIN, pageH - 10);
  }

  // Download
  const blob = doc.output('blob');
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ddos-report-${r.lbName}-${new Date().toISOString().split('T')[0]}.pdf`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
