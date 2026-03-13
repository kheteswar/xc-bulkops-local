import type { AccessLogEntry } from '../rate-limit-advisor/types';

export function exportAsJSON(logs: AccessLogEntry[], filename: string = 'log-analysis.json'): void {
  const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportAsCSV(logs: AccessLogEntry[], fields: string[], filename: string = 'log-analysis.csv'): void {
  if (logs.length === 0) return;

  const escape = (v: unknown): string => {
    const s = v === undefined || v === null ? '' : String(v);
    if (s.includes(',') || s.includes('"') || s.includes('\n')) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  };

  const header = fields.map(escape).join(',');
  const rows = logs.map(log =>
    fields.map(f => escape((log as Record<string, unknown>)[f])).join(',')
  );

  const csv = [header, ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
