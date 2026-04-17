import React, { useMemo, useState } from 'react';
import { CheckCircle, ChevronDown, ChevronUp, Search } from 'lucide-react';
import DeltaBadge from './DeltaBadge';
import type { DashboardMetrics } from '../../services/live-soc/types';

interface ErrorDiagnosisProps {
  diagnosis: DashboardMetrics['errorDiagnosis'];
  onInvestigate?: (rspCodeDetails: string) => void;
}

type SortField = 'count' | 'severity' | 'rspCode';
type SortDirection = 'asc' | 'desc';

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  INFO: 3,
};

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: 'bg-[#ff0040]/15 text-[#ff0040] border-[#ff0040]/30',
  HIGH: 'bg-[#ff6b35]/15 text-[#ff6b35] border-[#ff6b35]/30',
  MEDIUM: 'bg-[#ffbe0b]/15 text-[#ffbe0b] border-[#ffbe0b]/30',
  INFO: 'bg-[#00d4ff]/15 text-[#00d4ff] border-[#00d4ff]/30',
};

const CATEGORY_STYLES: Record<string, string> = {
  config: 'text-[#00d4ff]',
  origin: 'text-[#ff6b35]',
  security: 'text-[#ff0040]',
  network: 'text-[#ffbe0b]',
};

function SeverityBadge({ severity }: { severity: string }) {
  const style = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.INFO;
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider border ${style}`}>
      {severity}
    </span>
  );
}

export default function ErrorDiagnosis({ diagnosis, onInvestigate }: ErrorDiagnosisProps) {
  const [sortField, setSortField] = useState<SortField>('count');
  const [sortDir, setSortDir] = useState<SortDirection>('desc');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);

  const sorted = useMemo(() => {
    const items = [...diagnosis];
    items.sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case 'count':
          cmp = a.count - b.count;
          break;
        case 'severity':
          cmp = (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
          break;
        case 'rspCode':
          cmp = a.rspCode.localeCompare(b.rspCode);
          break;
      }
      return sortDir === 'desc' ? -cmp : cmp;
    });
    return items;
  }, [diagnosis, sortField, sortDir]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === 'desc' ? 'asc' : 'desc'));
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  };

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return null;
    return sortDir === 'desc' ? (
      <ChevronDown className="w-3 h-3 inline ml-0.5" />
    ) : (
      <ChevronUp className="w-3 h-3 inline ml-0.5" />
    );
  };

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
        Error Diagnosis <span className="text-gray-600 text-xs font-normal">(K000146828)</span>
      </h3>

      {sorted.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-10 gap-2">
          <CheckCircle className="w-10 h-10 text-[#00ff88]/40" />
          <span className="text-sm text-gray-500">No errors detected</span>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="text-gray-500 uppercase tracking-wider text-[10px] border-b border-[#1a2332]">
                <th
                  className="py-2 px-2 text-left cursor-pointer hover:text-gray-300 transition-colors"
                  onClick={() => handleSort('rspCode')}
                >
                  Code <SortIcon field="rspCode" />
                </th>
                <th className="py-2 px-2 text-left">Details</th>
                <th
                  className="py-2 px-2 text-right cursor-pointer hover:text-gray-300 transition-colors"
                  onClick={() => handleSort('count')}
                >
                  Count <SortIcon field="count" />
                </th>
                <th className="py-2 px-2 text-center">Trend</th>
                <th className="py-2 px-2 text-left">Category</th>
                <th className="py-2 px-2 text-left">Root Cause</th>
                <th
                  className="py-2 px-2 text-center cursor-pointer hover:text-gray-300 transition-colors"
                  onClick={() => handleSort('severity')}
                >
                  Severity <SortIcon field="severity" />
                </th>
                {onInvestigate && <th className="py-2 px-2 text-center">Action</th>}
              </tr>
            </thead>
            <tbody>
              {sorted.map((entry) => {
                const isExpanded = expandedRow === entry.rspCodeDetails;
                return (
                  <React.Fragment key={entry.rspCodeDetails}>
                    <tr
                      className="border-b border-[#1a2332]/50 hover:bg-[#1a2332]/30 cursor-pointer transition-colors"
                      onClick={() => setExpandedRow(isExpanded ? null : entry.rspCodeDetails)}
                    >
                      <td className="py-2 px-2 font-semibold text-gray-200">{entry.rspCode}</td>
                      <td className="py-2 px-2 text-gray-400 max-w-[200px] truncate" title={entry.rspCodeDetails}>
                        {entry.rspCodeDetails}
                      </td>
                      <td className="py-2 px-2 text-right text-gray-200">{entry.count.toLocaleString()}</td>
                      <td className="py-2 px-2 text-center">
                        <DeltaBadge current={entry.count} previous={entry.prevCount} inverse />
                      </td>
                      <td className="py-2 px-2">
                        <span className={`capitalize ${CATEGORY_STYLES[entry.category] ?? 'text-gray-400'}`}>
                          {entry.category}
                        </span>
                      </td>
                      <td className="py-2 px-2 text-gray-400 max-w-[180px] truncate" title={entry.rootCause}>
                        {entry.rootCause}
                      </td>
                      <td className="py-2 px-2 text-center">
                        <SeverityBadge severity={entry.severity} />
                      </td>
                      {onInvestigate && (
                        <td className="py-2 px-2 text-center">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onInvestigate(entry.rspCodeDetails);
                            }}
                            className="p-1 rounded hover:bg-[#00d4ff]/10 text-[#00d4ff] transition-colors"
                            title="Investigate"
                          >
                            <Search className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      )}
                    </tr>

                    {/* Expanded remediation row */}
                    {isExpanded && (
                      <tr className="bg-[#0a0e1a]/60">
                        <td colSpan={onInvestigate ? 8 : 7} className="px-4 py-3">
                          <div className="flex flex-col gap-1">
                            <span className="text-[10px] uppercase tracking-wider text-gray-500">Remediation</span>
                            <span className="text-xs text-gray-300">{entry.remediation}</span>
                            {entry.isOriginError && (
                              <span className="text-[10px] text-[#ff6b35] mt-1">
                                Origin-side error -- check backend health
                              </span>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
