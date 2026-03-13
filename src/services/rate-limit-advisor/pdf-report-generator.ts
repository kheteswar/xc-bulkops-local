import jsPDF from 'jspdf';
import autoTablePlugin from 'jspdf-autotable';
import type {
  AnalysisResults, TimeGranularity, TrafficSegment,
  ImpactSimulation, GeneratedRateLimitConfig, RateStats,
} from './types';
import { formatConfigJSON } from './config-generator';

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

export interface AlgorithmConfigEntry {
  label: string;
  config: GeneratedRateLimitConfig;
  rateLimit: number;
  burstMultiplier: number;
  granularity: TimeGranularity;
}

export interface PdfReportOptions {
  results: AnalysisResults;
  config: GeneratedRateLimitConfig;
  algorithmConfigs: AlgorithmConfigEntry[];
  sliderValue: number;
  burstMultiplier: number;
  selectedGranularity: TimeGranularity;
  selectedSegment: TrafficSegment;
  impactResult: ImpactSimulation | null;
  chartImages: {
    timeSeries?: string;
    heatmap?: string;
  };
}

// ═══════════════════════════════════════════════════════════════════
// COLORS & CONSTANTS
// ═══════════════════════════════════════════════════════════════════

const BLUE = [59, 130, 246] as const;    // #3b82f6
const DARK = [30, 41, 59] as const;      // #1e293b
const GRAY = [100, 116, 139] as const;   // #64748b
const PAGE_MARGIN = 20;
const CONTENT_WIDTH = 170; // A4 width (210) - 2×margin

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

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

function label(doc: jsPDF, text: string, y: number, x = PAGE_MARGIN): number {
  doc.setFontSize(9);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...GRAY);
  doc.text(text, x, y);
  return y;
}

function value(doc: jsPDF, text: string, y: number, x: number): void {
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(...DARK);
  doc.text(text, x, y);
}

function pct(num: number, total: number): string {
  if (total === 0) return '0.0%';
  return ((num / total) * 100).toFixed(1) + '%';
}

function n(num: number): string {
  return num.toLocaleString();
}

function autoTable(doc: jsPDF, opts: Record<string, unknown>): number {
  autoTablePlugin(doc, opts);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (doc as any).lastAutoTable.finalY + 8;
}

// ═══════════════════════════════════════════════════════════════════
// PDF SECTIONS
// ═══════════════════════════════════════════════════════════════════

function addHeader(doc: jsPDF, r: AnalysisResults): number {
  let y = 25;

  // Title
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...BLUE);
  doc.text('Rate Limit Analysis Report', PAGE_MARGIN, y);
  y += 10;

  // Subtitle
  doc.setFontSize(11);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(...GRAY);
  doc.text(`Load Balancer: ${r.lbName}`, PAGE_MARGIN, y);
  y += 5;
  doc.text(`Namespace: ${r.namespace}`, PAGE_MARGIN, y);
  y += 5;

  const start = new Date(r.analysisStart).toLocaleString();
  const end = new Date(r.analysisEnd).toLocaleString();
  doc.text(`Analysis Period: ${start}  —  ${end}`, PAGE_MARGIN, y);
  y += 5;
  doc.text(`Generated: ${new Date(r.generatedAt).toLocaleString()}`, PAGE_MARGIN, y);
  y += 3;

  // Divider
  doc.setDrawColor(...BLUE);
  doc.setLineWidth(1);
  doc.line(PAGE_MARGIN, y, PAGE_MARGIN + CONTENT_WIDTH, y);

  return y + 10;
}

function addExecutiveSummary(doc: jsPDF, r: AnalysisResults, y: number): number {
  y = sectionTitle(doc, 'Executive Summary', y);

  const col1 = PAGE_MARGIN;
  const col2 = PAGE_MARGIN + 45;
  const col3 = PAGE_MARGIN + 90;
  const col4 = PAGE_MARGIN + 135;

  label(doc, 'Total Access Logs', y, col1);
  label(doc, 'Security Events', y, col2);
  label(doc, 'Avg Sample Rate', y, col3);
  label(doc, 'Est. Actual Requests', y, col4);
  y += 5;
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...DARK);
  doc.text(n(r.totalAccessLogs), col1, y);
  doc.text(n(r.totalSecurityEvents), col2, y);
  doc.text(r.avgSampleRate.toFixed(3), col3, y);
  doc.text(n(r.estimatedActualRequests), col4, y);
  y += 10;

  // User reputation summary
  const rep = r.userReputationSummary;
  const totalUsers = rep.clean + rep.benignBot + rep.flagged + rep.malicious;
  label(doc, 'Users:', y, col1);
  value(doc, `${n(totalUsers)} total — ${n(rep.clean)} clean, ${n(rep.benignBot)} benign bot, ${n(rep.flagged)} flagged, ${n(rep.malicious)} malicious`, y, col1 + 15);

  return y + 12;
}

function addResponseClassification(doc: jsPDF, r: AnalysisResults, y: number): number {
  y = sectionTitle(doc, 'Response Classification', y);
  const rb = r.responseBreakdown;
  const total = rb.origin2xx + rb.origin3xx + rb.origin4xx + rb.origin5xx + (rb.originOther || 0) + rb.f5Blocked;

  const rows = [
    ['2xx (Success)', n(rb.origin2xx), pct(rb.origin2xx, total), 'Yes'],
    ['3xx (Redirects)', n(rb.origin3xx), pct(rb.origin3xx, total), 'Yes'],
    ['4xx (Origin errors)', n(rb.origin4xx), pct(rb.origin4xx, total), 'Yes'],
    ['5xx (Server errors)', n(rb.origin5xx), pct(rb.origin5xx, total), 'Yes'],
  ];
  if (rb.originOther > 0) {
    rows.push(['Other (code unknown)', n(rb.originOther), pct(rb.originOther, total), 'Yes']);
  }
  rows.push(['F5 XC Blocked', n(rb.f5Blocked), pct(rb.f5Blocked, total), 'No']);

  return autoTable(doc, {
    startY: y,
    head: [['Category', 'Count', '%', 'In Baseline?']],
    body: rows,
    theme: 'striped',
    headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 9 },
    styles: { fontSize: 9, cellPadding: 2 },
    margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
    columnStyles: { 1: { halign: 'right' }, 2: { halign: 'right' } },
  });
}

function addUserLandscape(doc: jsPDF, r: AnalysisResults, y: number): number {
  y = sectionTitle(doc, 'User Landscape', y);

  // Top 20 users table
  const topUsers = r.users.slice(0, 20);
  const rows = topUsers.map((u, i) => [
    String(i + 1),
    u.identifier.length > 30 ? u.identifier.slice(0, 27) + '...' : u.identifier,
    u.reputation,
    n(u.totalRequests),
    String(u.rateStats.minute.max),
    u.rateStats.minute.mean.toFixed(1),
    u.topPaths[0]?.path || '-',
  ]);

  y = autoTable(doc, {
    startY: y,
    head: [['#', 'User', 'Reputation', 'Requests', 'Peak/min', 'Avg/min', 'Top Path']],
    body: rows,
    theme: 'striped',
    headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 8 },
    styles: { fontSize: 7, cellPadding: 1.5 },
    margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
    columnStyles: {
      0: { cellWidth: 8 },
      3: { halign: 'right' },
      4: { halign: 'right' },
      5: { halign: 'right' },
    },
  });

  if (r.users.length > 20) {
    doc.setFontSize(8);
    doc.setTextColor(...GRAY);
    doc.text(`Showing top 20 of ${r.users.length} users`, PAGE_MARGIN, y - 3);
    y += 2;
  }

  return y;
}

function addChartImages(doc: jsPDF, images: PdfReportOptions['chartImages'], y: number): number {
  if (!images.timeSeries && !images.heatmap) return y;

  y = sectionTitle(doc, 'Traffic Patterns', y);

  const imgWidth = CONTENT_WIDTH;

  if (images.timeSeries) {
    y = ensureSpace(doc, y, 80);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...DARK);
    doc.text('Requests Over Time (per minute avg)', PAGE_MARGIN, y);
    y += 3;
    doc.addImage(images.timeSeries, 'PNG', PAGE_MARGIN, y, imgWidth, imgWidth * 0.35);
    y += imgWidth * 0.35 + 8;
  }

  if (images.heatmap) {
    y = ensureSpace(doc, y, 60);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...DARK);
    doc.text('Day x Hour Heatmap (avg req/min)', PAGE_MARGIN, y);
    y += 3;
    doc.addImage(images.heatmap, 'PNG', PAGE_MARGIN, y, imgWidth, imgWidth * 0.25);
    y += imgWidth * 0.25 + 8;
  }

  return y;
}

function addDistributionAnalysis(doc: jsPDF, r: AnalysisResults, segment: TrafficSegment, granularity: TimeGranularity, y: number): number {
  y = sectionTitle(doc, 'Distribution Analysis', y);

  const segData = r.rateAnalysis[segment];
  if (!segData) return y;
  const stats: RateStats = segData[granularity];

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(...GRAY);
  doc.text(`Segment: ${segment.replace('_', ' ')}  |  Granularity: per ${granularity}  |  ${segData.userCount} users, ${n(segData.requestCount)} requests`, PAGE_MARGIN, y);
  y += 6;

  // Percentile table
  const rows = [
    ['P50 (Median)', String(stats.p50), '50% of users stay below this'],
    ['P75', String(stats.p75), '75% of users stay below this'],
    ['P90', String(stats.p90), '90% of users stay below this'],
    ['P95', String(stats.p95), '95% of users stay below this'],
    ['P99', String(stats.p99), '99% of users stay below this'],
    ['Max', String(stats.max), 'Highest observed per-user rate'],
    ['Mean (avg)', stats.mean.toFixed(1), 'Average across all users'],
    ['Std Dev', stats.stdDev.toFixed(1), `Spread: rates vary by ~${stats.stdDev.toFixed(1)} from mean`],
  ];

  y = autoTable(doc, {
    startY: y,
    head: [['Metric', `Value (req/${granularity})`, 'Meaning']],
    body: rows,
    theme: 'striped',
    headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 9 },
    styles: { fontSize: 9, cellPadding: 2 },
    margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
    columnStyles: { 1: { halign: 'right', fontStyle: 'bold' } },
  });

  return y;
}

function addAlgorithmRecommendations(doc: jsPDF, r: AnalysisResults, y: number): number {
  y = sectionTitle(doc, 'Algorithm Recommendations', y);

  const rows = r.algorithms.map(a => [
    a.label,
    `${a.rateLimit} req/${a.granularity}`,
    a.formula,
    a.description,
  ]);

  return autoTable(doc, {
    startY: y,
    head: [['Algorithm', 'Recommendation', 'Formula', 'Description']],
    body: rows,
    theme: 'striped',
    headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 8 },
    styles: { fontSize: 8, cellPadding: 2 },
    margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
    columnStyles: { 1: { fontStyle: 'bold' } },
  });
}

function addConfiguration(doc: jsPDF, opts: PdfReportOptions, y: number): number {
  y = sectionTitle(doc, 'Decision & Configuration', y);

  // Rationale
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...DARK);
  doc.text('Analysis Rationale', PAGE_MARGIN, y);
  y += 5;

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(...GRAY);
  const rationaleLines = doc.splitTextToSize(opts.config.rationale, CONTENT_WIDTH);
  doc.text(rationaleLines, PAGE_MARGIN, y);
  y += rationaleLines.length * 4 + 8;

  // JSON configs for each algorithm
  for (const entry of opts.algorithmConfigs) {
    y = ensureSpace(doc, y, 30);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...DARK);
    doc.text(`${entry.label} — Rate Limit Config (spec.rate_limit)`, PAGE_MARGIN, y);
    y += 4;
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(...GRAY);
    doc.text(`Base: ${entry.rateLimit} req/${entry.granularity}  |  Burst: ${entry.burstMultiplier}x  |  Effective: ${entry.rateLimit * entry.burstMultiplier}`, PAGE_MARGIN, y);
    y += 5;

    const jsonStr = formatConfigJSON({
      rate_limit: {
        rate_limiter: entry.config.rateLimiter,
        no_ip_allowed_list: {},
        policies: { policies: [] },
      },
    });

    doc.setFontSize(8);
    doc.setFont('courier', 'normal');
    doc.setTextColor(34, 197, 94); // green
    const jsonLines = doc.splitTextToSize(jsonStr, CONTENT_WIDTH - 10);

    const boxHeight = jsonLines.length * 3.5 + 6;
    y = ensureSpace(doc, y, boxHeight + 5);
    doc.setFillColor(15, 23, 42); // slate-950
    doc.roundedRect(PAGE_MARGIN, y - 3, CONTENT_WIDTH, boxHeight, 2, 2, 'F');

    doc.text(jsonLines, PAGE_MARGIN + 5, y + 2);
    y += boxHeight + 10;
  }

  return y;
}

function addPathAnalysis(doc: jsPDF, r: AnalysisResults, y: number): number {
  if (r.paths.length === 0) return y;

  y = sectionTitle(doc, 'Path Analysis', y);

  const rows = r.paths.slice(0, 30).map(p => [
    p.normalizedPath.length > 40 ? p.normalizedPath.slice(0, 37) + '...' : p.normalizedPath,
    n(p.totalRequests),
    String(p.uniqueUsers),
    String(p.rateStats.minute.p95),
    String(p.rateStats.minute.max),
    Object.keys(p.methods).join(', '),
    p.isSensitive ? 'Yes' : '',
  ]);

  y = autoTable(doc, {
    startY: y,
    head: [['Path', 'Requests', 'Users', 'P95/min', 'Max/min', 'Methods', 'Sensitive']],
    body: rows,
    theme: 'striped',
    headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 7 },
    styles: { fontSize: 7, cellPadding: 1.5 },
    margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
    columnStyles: {
      1: { halign: 'right' },
      2: { halign: 'right' },
      3: { halign: 'right' },
      4: { halign: 'right' },
    },
  });

  if (r.paths.length > 30) {
    doc.setFontSize(8);
    doc.setTextColor(...GRAY);
    doc.text(`Showing top 30 of ${r.paths.length} paths`, PAGE_MARGIN, y - 3);
  }

  return y;
}

function addFooters(doc: jsPDF) {
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    const pageH = doc.internal.pageSize.getHeight();
    const pageW = doc.internal.pageSize.getWidth();
    doc.setFontSize(8);
    doc.setTextColor(150, 150, 150);
    doc.text(`Page ${i} of ${pageCount}`, pageW / 2, pageH - 10, { align: 'center' });
    doc.text('XC App Store — Rate Limit Advisor', PAGE_MARGIN, pageH - 10);
  }
}

// ═══════════════════════════════════════════════════════════════════
// MAIN EXPORT
// ═══════════════════════════════════════════════════════════════════

export async function generatePdfReport(opts: PdfReportOptions): Promise<void> {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const r = opts.results;

  let y = addHeader(doc, r);
  y = addExecutiveSummary(doc, r, y);
  y = addResponseClassification(doc, r, y);
  y = addUserLandscape(doc, r, y);
  y = addChartImages(doc, opts.chartImages, y);
  y = addDistributionAnalysis(doc, r, opts.selectedSegment, opts.selectedGranularity, y);
  y = addAlgorithmRecommendations(doc, r, y);
  y = addConfiguration(doc, opts, y);
  addPathAnalysis(doc, r, y);

  addFooters(doc);

  // Manual blob download — avoids doc.save() which creates an <a> element
  // that React Router can intercept, causing unwanted navigation.
  const blob = doc.output('blob');
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `rate-limit-report-${r.lbName}-${new Date().toISOString().split('T')[0]}.pdf`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
