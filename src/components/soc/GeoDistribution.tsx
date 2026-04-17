import { useMemo } from 'react';
import { Globe2, AlertTriangle } from 'lucide-react';

interface GeoEntry {
  country: string;
  count: number;
  pct: number;
  isNew: boolean;
}

interface GeoDistributionProps {
  data: GeoEntry[];
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

const BAR_COLOR = '#00d4ff';
const NEW_COLOR = '#ffbe0b';

export default function GeoDistribution({ data }: GeoDistributionProps) {
  const top15 = useMemo(() => data.slice(0, 15), [data]);
  const maxCount = useMemo(() => Math.max(...top15.map((d) => d.count), 1), [top15]);
  const newCountries = useMemo(() => top15.filter((d) => d.isNew), [top15]);

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Globe2 className="w-4 h-4 text-[#00d4ff]" />
          <h3 className="text-sm font-semibold text-gray-200">Geo Distribution</h3>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-gray-500">
            {data.length} countries
          </span>
          {newCountries.length > 0 && (
            <span className="text-[10px] text-[#ffbe0b] bg-[#ffbe0b]/10 px-1.5 py-0.5 rounded font-medium">
              {newCountries.length} new
            </span>
          )}
        </div>
      </div>

      {/* New Country Anomaly Alert */}
      {newCountries.length > 0 && (
        <div className="mb-3 flex items-start gap-2 bg-[#ffbe0b]/8 border border-[#ffbe0b]/20 rounded-lg p-2.5">
          <AlertTriangle className="w-3.5 h-3.5 text-[#ffbe0b] flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-xs text-[#ffbe0b] font-semibold">New Traffic Sources</p>
            <p className="text-[11px] text-gray-400 mt-0.5">
              Traffic detected from{' '}
              {newCountries.map((c) => c.country).join(', ')} — not seen in baseline
            </p>
          </div>
        </div>
      )}

      {top15.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-8 text-gray-500">
          <Globe2 className="w-8 h-8 mb-2 opacity-30" />
          <p className="text-xs">No geo data available</p>
        </div>
      ) : (
        <div className="space-y-1">
          {/* Column headers */}
          <div className="grid grid-cols-[auto_1fr_auto_auto] gap-2 text-[10px] text-gray-500 uppercase tracking-wider pb-1 border-b border-[#1a2332] px-1 items-center">
            <span className="w-4">#</span>
            <span>Country</span>
            <span className="text-right w-16">Count</span>
            <span className="text-right w-12">%</span>
          </div>

          {top15.map((entry, i) => {
            const barPct = (entry.count / maxCount) * 100;
            const isNewEntry = entry.isNew;

            return (
              <div
                key={entry.country}
                className="relative group rounded hover:bg-[#1a2332]/30 transition-colors"
              >
                {/* Background bar */}
                <div
                  className="absolute inset-y-0 left-0 rounded opacity-15"
                  style={{
                    width: `${barPct}%`,
                    backgroundColor: isNewEntry ? NEW_COLOR : BAR_COLOR,
                  }}
                />

                <div className="relative grid grid-cols-[auto_1fr_auto_auto] gap-2 py-1.5 px-1 items-center">
                  <span className="text-[10px] text-gray-600 font-mono w-4">{i + 1}</span>
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-xs text-gray-300 truncate">{entry.country}</span>
                    {isNewEntry && (
                      <span className="flex-shrink-0 text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-[#ffbe0b]/15 text-[#ffbe0b] border border-[#ffbe0b]/30 animate-pulse">
                        NEW
                      </span>
                    )}
                  </div>
                  <span className="text-xs font-mono text-gray-300 text-right w-16">
                    {formatNumber(entry.count)}
                  </span>
                  <span className="text-xs font-mono text-gray-500 text-right w-12">
                    {entry.pct.toFixed(1)}%
                  </span>
                </div>
              </div>
            );
          })}

          {/* Remaining count */}
          {data.length > 15 && (
            <div className="pt-2 px-1">
              <span className="text-[10px] text-gray-600 italic">
                +{data.length - 15} more countries ({formatNumber(
                  data.slice(15).reduce((acc, d) => acc + d.count, 0)
                )} requests)
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
