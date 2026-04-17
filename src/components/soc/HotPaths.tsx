import React, { useState, useMemo } from 'react';
import { Route, ArrowUpDown } from 'lucide-react';

interface PathEntry {
  path: string;
  count: number;
  errorCount: number;
  errorRate: number;
}

interface HotPathsProps {
  paths: PathEntry[];
}

type SortField = 'path' | 'count' | 'errorCount' | 'errorRate';
type SortDirection = 'asc' | 'desc';

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

function errorRateColor(rate: number): string {
  if (rate < 1) return '#00ff88';
  if (rate < 5) return '#ffbe0b';
  return '#ff0040';
}

function errorRateBgClass(rate: number): string {
  if (rate < 1) return 'bg-[#00ff88]/10';
  if (rate < 5) return 'bg-[#ffbe0b]/10';
  return 'bg-[#ff0040]/10';
}

export default function HotPaths({ paths }: HotPathsProps) {
  const [sortField, setSortField] = useState<SortField>('count');
  const [sortDir, setSortDir] = useState<SortDirection>('desc');

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  };

  const sortedPaths = useMemo(() => {
    return [...paths].sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case 'path':
          cmp = a.path.localeCompare(b.path);
          break;
        case 'count':
          cmp = a.count - b.count;
          break;
        case 'errorCount':
          cmp = a.errorCount - b.errorCount;
          break;
        case 'errorRate':
          cmp = a.errorRate - b.errorRate;
          break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
  }, [paths, sortField, sortDir]);

  const maxCount = useMemo(
    () => Math.max(...paths.map((p) => p.count), 1),
    [paths]
  );

  const SortHeader = ({
    field,
    children,
    align = 'left',
  }: {
    field: SortField;
    children: React.ReactNode;
    align?: 'left' | 'right';
  }) => (
    <button
      onClick={() => handleSort(field)}
      className={`flex items-center gap-0.5 text-[10px] text-gray-500 uppercase tracking-wider hover:text-gray-300 transition-colors ${
        align === 'right' ? 'justify-end ml-auto' : ''
      }`}
    >
      {children}
      <ArrowUpDown
        className={`w-2.5 h-2.5 ${sortField === field ? 'text-[#00d4ff]' : 'text-gray-600'}`}
      />
    </button>
  );

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Route className="w-4 h-4 text-[#00d4ff]" />
          <h3 className="text-sm font-semibold text-gray-200">Hot Paths</h3>
        </div>
        <span className="text-xs font-mono text-gray-500">
          {paths.length} paths
        </span>
      </div>

      {paths.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-8 text-gray-500">
          <Route className="w-8 h-8 mb-2 opacity-30" />
          <p className="text-xs">No path data available</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1a2332]">
                <th className="text-left py-1.5 pr-3">
                  <SortHeader field="path">Path</SortHeader>
                </th>
                <th className="text-right py-1.5 pr-3 w-24">
                  <SortHeader field="count" align="right">Requests</SortHeader>
                </th>
                <th className="text-right py-1.5 pr-3 w-20">
                  <SortHeader field="errorCount" align="right">Errors</SortHeader>
                </th>
                <th className="text-right py-1.5 w-24">
                  <SortHeader field="errorRate" align="right">Error %</SortHeader>
                </th>
              </tr>
            </thead>
            <tbody>
              {sortedPaths.map((entry) => {
                const barPct = (entry.count / maxCount) * 100;

                return (
                  <tr
                    key={entry.path}
                    className="border-b border-[#1a2332]/50 hover:bg-[#1a2332]/30 transition-colors group"
                  >
                    <td className="py-2 pr-3">
                      <div className="relative">
                        {/* Background bar */}
                        <div
                          className="absolute inset-y-0 left-0 bg-[#00d4ff]/5 rounded"
                          style={{ width: `${barPct}%` }}
                        />
                        <span className="relative text-xs font-mono text-gray-300 truncate max-w-[300px] inline-block">
                          {entry.path}
                        </span>
                      </div>
                    </td>
                    <td className="py-2 pr-3 text-right">
                      <span className="text-xs font-mono text-gray-300">
                        {formatNumber(entry.count)}
                      </span>
                    </td>
                    <td className="py-2 pr-3 text-right">
                      <span className="text-xs font-mono text-gray-400">
                        {entry.errorCount > 0 ? formatNumber(entry.errorCount) : '—'}
                      </span>
                    </td>
                    <td className="py-2 text-right">
                      <span
                        className={`inline-block text-xs font-mono font-medium px-1.5 py-0.5 rounded ${errorRateBgClass(
                          entry.errorRate
                        )}`}
                        style={{ color: errorRateColor(entry.errorRate) }}
                      >
                        {entry.errorRate.toFixed(2)}%
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
