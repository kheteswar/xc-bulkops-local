import jsPDF from 'jspdf';
import autoTablePlugin from 'jspdf-autotable';

// ═══════════════════════════════════════════════════════════════════
// Types (mirrors the page component types)
// ═══════════════════════════════════════════════════════════════════

interface TlsCertInfo {
  subject: string;
  issuer: string;
  issuerOrg: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint256: string;
  subjectAltName: string;
  protocol: string;
}

interface RequestResult {
  status: number | string;
  statusText: string;
  size: number;
  headers: Record<string, string>;
  body: string;
  normalizedBody: string;
  duration: number;
  isBotChallenge: boolean;
  debugInfo?: string;
  error?: string;
  connectedIp?: string;
  tlsCert?: TlsCertInfo | null;
}

interface SpoofedResult {
  ip: string;
  result: RequestResult;
  score: number;
  statusMatch: boolean;
  passed: boolean;
}

interface TestRow {
  id: string;
  domain: string;
  targetIps: string[];
  path: string;
}

interface ComparisonResult {
  row: TestRow;
  public: RequestResult;
  spoofedResults: SpoofedResult[];
  overallPassed: boolean;
  reasons: string[];
  timestamp: string;
}

// ═══════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════

const BLUE = [59, 130, 246] as const;
const DARK = [30, 41, 59] as const;
const GRAY = [100, 116, 139] as const;
const GREEN = [34, 197, 94] as const;
const RED = [239, 68, 68] as const;
const AMBER = [245, 158, 11] as const;
const PAGE_MARGIN = 20;
const CONTENT_WIDTH = 170;

const IGNORED_HEADERS = new Set([
  'date', 'server', 'connection', 'keep-alive', 'age',
  'transfer-encoding', 'set-cookie', 'content-length',
  'etag', 'last-modified', 'strict-transport-security',
  'x-akamai-staging', 'x-akamai-transformed'
]);

// ═══════════════════════════════════════════════════════════════════
// Helpers
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

function subTitle(doc: jsPDF, title: string, y: number): number {
  y = ensureSpace(doc, y, 12);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...DARK);
  doc.text(title, PAGE_MARGIN, y);
  return y + 6;
}

function autoTable(doc: jsPDF, opts: Record<string, unknown>): number {
  autoTablePlugin(doc, opts);
  return (doc as any).lastAutoTable.finalY + 8;
}

function trunc(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

function addFooters(doc: jsPDF) {
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(7);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(...GRAY);
    const pageH = doc.internal.pageSize.getHeight();
    doc.text(`Page ${i} of ${pageCount}  |  Live vs Spoof HTTP Sanity Checker  |  XC App Store`, PAGE_MARGIN, pageH - 10);
  }
}

// ═══════════════════════════════════════════════════════════════════
// Main export
// ═══════════════════════════════════════════════════════════════════

export function generateSanityCheckPdf(results: ComparisonResult[]): void {
  if (results.length === 0) return;

  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  let y = PAGE_MARGIN;

  const passCount = results.filter(r => r.overallPassed).length;
  const failCount = results.length - passCount;
  const domains = new Set(results.map(r => r.row.domain));

  // ── Title ──────────────────────────────────────────────────────
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...BLUE);
  doc.text('Live vs Spoof Sanity Check Report', PAGE_MARGIN, y);
  y += 10;

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(...GRAY);
  doc.text(`Generated: ${new Date().toLocaleString()}`, PAGE_MARGIN, y);
  y += 5;
  doc.text(`Domains: ${domains.size}  |  Tests: ${results.length}  |  Passed: ${passCount}  |  Failed: ${failCount}`, PAGE_MARGIN, y);
  y += 10;

  // ── Executive Summary Table ────────────────────────────────────
  y = sectionTitle(doc, 'Executive Summary', y);

  const summaryRows = results.map(r => {
    const spoofSummary = r.spoofedResults.map(s =>
      `${s.ip}: ${s.result.status} (${s.score}%)`
    ).join(', ');
    return [
      r.row.domain,
      trunc(r.row.path, 40),
      String(r.public.status),
      spoofSummary,
      r.overallPassed ? 'PASS' : 'FAIL',
    ];
  });

  y = autoTable(doc, {
    startY: y,
    head: [['Live Domain', 'Path', 'Live Status', 'Spoof Results', 'Verdict']],
    body: summaryRows,
    margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
    styles: { fontSize: 7, cellPadding: 1.5 },
    headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 7 },
    columnStyles: {
      0: { cellWidth: 35 },
      1: { cellWidth: 35 },
      2: { cellWidth: 18, halign: 'center' },
      3: { cellWidth: 55 },
      4: { cellWidth: 18, halign: 'center', fontStyle: 'bold' },
    },
    theme: 'striped',
    didParseCell: (data: any) => {
      if (data.section === 'body' && data.column.index === 4) {
        const val = data.cell.raw;
        data.cell.styles.textColor = val === 'PASS' ? [...GREEN] : [...RED];
      }
    },
  });

  // ── Detailed Results ───────────────────────────────────────────
  y = sectionTitle(doc, 'Detailed Results', y);

  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    const fullUrl = `https://${r.row.domain}${r.row.path}`;

    // Result header
    y = ensureSpace(doc, y, 35);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    const verdictColor = r.overallPassed ? GREEN : RED;
    doc.setTextColor(verdictColor[0], verdictColor[1], verdictColor[2]);
    doc.text(`${r.overallPassed ? '✓ PASS' : '✗ FAIL'}`, PAGE_MARGIN, y);
    doc.setTextColor(...DARK);
    doc.text(`  #${i + 1}  ${trunc(r.row.domain, 50)}`, PAGE_MARGIN + 18, y);
    y += 5;

    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(...GRAY);
    doc.text(trunc(fullUrl, 90), PAGE_MARGIN, y);
    y += 4;
    doc.text(`Timestamp: ${r.timestamp}`, PAGE_MARGIN, y);
    y += 6;

    // Drift reasons
    if (r.reasons.length > 0) {
      y = ensureSpace(doc, y, 10 + r.reasons.length * 4);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...AMBER);
      doc.text('Drift Detected:', PAGE_MARGIN, y);
      y += 4;
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7);
      for (const reason of r.reasons) {
        doc.text(`  • ${trunc(reason, 100)}`, PAGE_MARGIN, y);
        y += 3.5;
      }
      y += 3;
    }

    // Comparison table
    y = subTitle(doc, 'Side-by-Side Comparison', y);

    const compHead = ['Metric', 'LIVE', ...r.spoofedResults.map((s, si) => `Spoof ${si + 1} (${s.ip})`)];
    const compRows = [
      ['Status', String(r.public.status), ...r.spoofedResults.map(s => String(s.result.status))],
      ['Duration', `${r.public.duration}ms`, ...r.spoofedResults.map(s => `${s.result.duration}ms`)],
      ['Size', r.public.size > 0 ? `${(r.public.size / 1024).toFixed(1)} KB` : '—', ...r.spoofedResults.map(s => s.result.size > 0 ? `${(s.result.size / 1024).toFixed(1)} KB` : '—')],
      ['Bot Challenge', r.public.isBotChallenge ? 'Yes' : 'No', ...r.spoofedResults.map(s => s.result.isBotChallenge ? 'Yes' : 'No')],
      ['Connected IP', r.public.connectedIp || '—', ...r.spoofedResults.map(s => s.result.connectedIp || '—')],
      ['Similarity', 'baseline', ...r.spoofedResults.map(s => `${s.score}%`)],
    ];

    y = autoTable(doc, {
      startY: y,
      head: [compHead],
      body: compRows,
      margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
      styles: { fontSize: 7, cellPadding: 1.5 },
      headStyles: { fillColor: [...BLUE], textColor: 255, fontSize: 7 },
      theme: 'striped',
      didParseCell: (data: any) => {
        if (data.section === 'body') {
          // Highlight similarity
          if (data.row.index === 5 && data.column.index > 0) {
            const raw = String(data.cell.raw);
            const pct = parseInt(raw);
            if (!isNaN(pct)) {
              data.cell.styles.textColor = pct >= 95 ? [...GREEN] : [...RED];
              data.cell.styles.fontStyle = 'bold';
            }
          }
          // Highlight status drift
          if (data.row.index === 0 && data.column.index > 0) {
            const liveStatus = String(r.public.status);
            if (String(data.cell.raw) !== liveStatus) {
              data.cell.styles.textColor = [...AMBER];
              data.cell.styles.fontStyle = 'bold';
            }
          }
        }
      },
    });

    // Header diff (significant diffs only)
    const significantDiffs: string[][] = [];
    for (const spoof of r.spoofedResults) {
      const allKeys = new Set([...Object.keys(r.public.headers), ...Object.keys(spoof.result.headers)]);
      for (const key of Array.from(allKeys).sort()) {
        if (IGNORED_HEADERS.has(key)) continue;
        const liveVal = r.public.headers[key] || '';
        const spoofVal = spoof.result.headers[key] || '';
        if (liveVal !== spoofVal) {
          significantDiffs.push([
            key,
            trunc(liveVal || '(missing)', 50),
            trunc(spoofVal || '(missing)', 50),
            spoof.ip,
          ]);
        }
      }
    }

    if (significantDiffs.length > 0) {
      y = subTitle(doc, 'Significant Header Differences', y);
      y = autoTable(doc, {
        startY: y,
        head: [['Header', 'Live Value', 'Spoof Value', 'Spoof IP']],
        body: significantDiffs,
        margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
        styles: { fontSize: 6.5, cellPadding: 1.5 },
        headStyles: { fillColor: [...AMBER], textColor: 255, fontSize: 7 },
        theme: 'striped',
      });
    }

    // TLS Certificate comparison
    const liveCert = r.public.tlsCert;
    const hasCerts = liveCert || r.spoofedResults.some(s => s.result.tlsCert);
    if (hasCerts) {
      y = subTitle(doc, 'TLS Certificate Comparison', y);

      const certHead = ['Field', 'LIVE', ...r.spoofedResults.map((_s, si) => `Spoof ${si + 1}`)];
      const fmtDate = (d: string) => {
        if (!d) return '—';
        try { return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }); }
        catch { return d; }
      };
      const certRows = [
        ['Subject (CN)', liveCert?.subject || '—', ...r.spoofedResults.map(s => s.result.tlsCert?.subject || '—')],
        ['Issuer', liveCert ? `${liveCert.issuer}${liveCert.issuerOrg ? ` (${liveCert.issuerOrg})` : ''}` : '—',
          ...r.spoofedResults.map(s => s.result.tlsCert ? `${s.result.tlsCert.issuer}${s.result.tlsCert.issuerOrg ? ` (${s.result.tlsCert.issuerOrg})` : ''}` : '—')],
        ['Valid From', fmtDate(liveCert?.validFrom || ''), ...r.spoofedResults.map(s => fmtDate(s.result.tlsCert?.validFrom || ''))],
        ['Valid To', fmtDate(liveCert?.validTo || ''), ...r.spoofedResults.map(s => fmtDate(s.result.tlsCert?.validTo || ''))],
        ['TLS Protocol', liveCert?.protocol || '—', ...r.spoofedResults.map(s => s.result.tlsCert?.protocol || '—')],
        ['SANs', trunc(liveCert?.subjectAltName?.replace(/DNS:/g, '').replace(/,/g, ', ') || '—', 60),
          ...r.spoofedResults.map(s => trunc(s.result.tlsCert?.subjectAltName?.replace(/DNS:/g, '').replace(/,/g, ', ') || '—', 60))],
      ];

      y = autoTable(doc, {
        startY: y,
        head: [certHead],
        body: certRows,
        margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
        styles: { fontSize: 6.5, cellPadding: 1.5 },
        headStyles: { fillColor: [100, 116, 139], textColor: 255, fontSize: 7 },
        theme: 'striped',
        didParseCell: (data: any) => {
          if (data.section === 'body') {
            // Highlight expired certs
            if (data.row.index === 3 && data.column.index > 0) {
              const raw = String(data.cell.raw);
              if (raw !== '—') {
                try {
                  if (new Date(raw) < new Date()) {
                    data.cell.styles.textColor = [...RED];
                    data.cell.styles.fontStyle = 'bold';
                  }
                } catch { /* ignore */ }
              }
            }
            // Highlight issuer/protocol drift
            if ((data.row.index === 1 || data.row.index === 4) && data.column.index > 1) {
              const liveVal = certRows[data.row.index][1];
              if (String(data.cell.raw) !== liveVal) {
                data.cell.styles.textColor = [...AMBER];
                data.cell.styles.fontStyle = 'bold';
              }
            }
          }
        },
      });
    }

    // Separator between results
    if (i < results.length - 1) {
      y = ensureSpace(doc, y, 10);
      doc.setDrawColor(200, 200, 200);
      doc.setLineWidth(0.2);
      doc.line(PAGE_MARGIN, y, PAGE_MARGIN + CONTENT_WIDTH, y);
      y += 8;
    }
  }

  // ── Footers ────────────────────────────────────────────────────
  addFooters(doc);

  // ── Download ───────────────────────────────────────────────────
  const blob = doc.output('blob');
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `sanity-check-report-${new Date().toISOString().slice(0, 10)}.pdf`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
