// ═══════════════════════════════════════════════════════════════════════════
// CONFIG DUMP - PDF GENERATOR (Enhanced)
// TOC, better formatting, larger fonts, error handling
// ═══════════════════════════════════════════════════════════════════════════

import jsPDF from 'jspdf';
import 'jspdf-autotable';
import type { FetchedObject } from './types';
import { sanitizeFilename } from './resolver';

interface TocEntry {
  label: string;
  type: string;
  page: number;
  depth: number;
}

/**
 * Generate a PDF report containing the full config of a fetched object tree.
 * Includes a table of contents and improved formatting.
 */
export function generateConfigPDF(obj: FetchedObject): jsPDF {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();
  const margin = 14;
  let y = 20;

  const tocEntries: TocEntry[] = [];

  const addPage = () => {
    doc.addPage();
    y = 20;
  };

  const checkPage = (needed: number) => {
    if (y + needed > pageH - 20) {
      addPage();
    }
  };

  // ── Cover / Header Page ────────────────────────────────────────
  doc.setFillColor(30, 41, 59); // slate-800
  doc.rect(0, 0, pageW, 50, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(22);
  doc.setTextColor(226, 232, 240); // slate-200
  doc.text('F5 XC Config Dump', margin, 22);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(148, 163, 184); // slate-400
  doc.text(`Object: ${obj.name}`, margin, 32);
  doc.text(`Type: ${obj.type}  |  Namespace: ${obj.namespace}`, margin, 40);
  doc.text(`Generated: ${new Date().toISOString()}`, margin, 48);
  y = 60;

  // ── TOC placeholder (we'll fill it after rendering) ────────────
  // We'll render content first, track pages, then insert TOC at page 1
  // Actually, let's render content pages starting from page 2, then insert TOC on page 1

  // ── Render main object ─────────────────────────────────────────
  tocEntries.push({
    label: obj.name,
    type: obj.type,
    page: doc.getNumberOfPages(),
    depth: 0,
  });

  doc.setTextColor(30, 41, 59);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.text(obj.name, margin, y);
  y += 7;
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(100, 116, 139);
  doc.text(`Type: ${obj.type}  |  Namespace: ${obj.namespace}`, margin, y);
  y += 10;

  // Render JSON as wrapped text
  const renderJson = (json: any, label: string) => {
    const jsonStr = JSON.stringify(json, null, 2);
    const lines = jsonStr.split('\n');

    checkPage(14);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(30, 41, 59);
    doc.text(label, margin, y);
    y += 6;

    doc.setFont('courier', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(51, 65, 85);

    for (const line of lines) {
      checkPage(4);
      const trimmed = line.substring(0, 130);
      doc.text(trimmed, margin, y);
      y += 3.5;
    }
    y += 5;
  };

  renderJson(obj.config, 'Configuration:');

  // ── Child Objects ──────────────────────────────────────────────
  function renderChildren(node: FetchedObject, depth: number) {
    for (const childGroup of node.children) {
      checkPage(20);

      // Section divider
      doc.setDrawColor(148, 163, 184);
      doc.setLineWidth(0.3);
      const indent = margin + depth * 6;
      doc.line(indent, y, pageW - margin, y);
      y += 6;

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(11);
      doc.setTextColor(59, 130, 246); // blue-500
      doc.text(`${childGroup.label} (${childGroup.objects.length})`, indent, y);
      y += 7;

      for (const child of childGroup.objects) {
        tocEntries.push({
          label: child.name,
          type: child.type,
          page: doc.getNumberOfPages(),
          depth: depth + 1,
        });

        checkPage(14);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(10);
        doc.setTextColor(30, 41, 59);
        doc.text(child.name, indent + 3, y);
        y += 5;
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8);
        doc.setTextColor(100, 116, 139);
        doc.text(`Type: ${child.type}  |  Namespace: ${child.namespace}`, indent + 3, y);
        y += 6;

        renderJson(child.config, 'Config:');

        if (child.children.length > 0) {
          renderChildren(child, depth + 1);
        }
      }
    }
  }

  renderChildren(obj, 0);

  // ── Table of Contents (at end of doc, after content) ───────────
  if (tocEntries.length > 1) {
    addPage();
    const tocPage = doc.getNumberOfPages();

    doc.setFillColor(30, 41, 59);
    doc.rect(0, 0, pageW, 30, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(16);
    doc.setTextColor(226, 232, 240);
    doc.text('Table of Contents', margin, 20);
    y = 40;

    for (const entry of tocEntries) {
      checkPage(8);
      const indent = margin + entry.depth * 8;
      doc.setFont('helvetica', entry.depth === 0 ? 'bold' : 'normal');
      doc.setFontSize(entry.depth === 0 ? 10 : 9);
      doc.setTextColor(entry.depth === 0 ? 30 : 100, entry.depth === 0 ? 41 : 116, entry.depth === 0 ? 59 : 139);
      doc.text(`${entry.label}`, indent, y);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(148, 163, 184);
      doc.text(`[${entry.type}] - p.${entry.page}`, pageW - margin - 40, y);
      y += 6;
    }

    // Move TOC page to after the cover (page 2)
    // jsPDF doesn't natively support moving pages, so we note the TOC page in the footer
    // We'll indicate in footer where the TOC is
    void tocPage; // TOC is appended at the end
  }

  // ── Footer on each page ────────────────────────────────────────
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.text(
      `Page ${i} of ${pageCount}  |  XC App Store - Config Dump  |  ${obj.name}`,
      pageW / 2,
      pageH - 8,
      { align: 'center' }
    );
  }

  return doc;
}

/**
 * Safely download a PDF, catching errors.
 */
export function safeDownloadPDF(obj: FetchedObject): { success: boolean; error?: string } {
  try {
    const doc = generateConfigPDF(obj);
    const filename = `${sanitizeFilename(obj.type)}_${sanitizeFilename(obj.namespace)}_${sanitizeFilename(obj.name)}.pdf`;
    doc.save(filename);
    return { success: true };
  } catch (e: any) {
    return { success: false, error: e?.message || 'Failed to generate PDF' };
  }
}
