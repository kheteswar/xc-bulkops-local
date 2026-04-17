import { useMemo } from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { Shield, AlertTriangle, Fingerprint } from 'lucide-react';

interface SecurityBreakdownProps {
  breakdown: Array<{ eventName: string; count: number; pct: number }>;
  topSignatures: Array<{ id: string; count: number }>;
  topViolations: Array<{ name: string; count: number }>;
}

const EVENT_COLORS: Record<string, string> = {
  waf: '#ff0040',
  bot: '#a855f7',
  threatmesh: '#ffbe0b',
  servicepolicy: '#00d4ff',
  ratelimit: '#00ff88',
};

const DEFAULT_COLOR = '#6b7280';

function getEventColor(eventName: string): string {
  const lower = eventName.toLowerCase();
  if (lower.includes('waf') || lower.includes('app_firewall')) return EVENT_COLORS.waf;
  if (lower.includes('bot')) return EVENT_COLORS.bot;
  if (lower.includes('threat') || lower.includes('mesh')) return EVENT_COLORS.threatmesh;
  if (lower.includes('service_policy') || lower.includes('servicepolicy') || lower.includes('policy'))
    return EVENT_COLORS.servicepolicy;
  if (lower.includes('rate_limit') || lower.includes('ratelimit')) return EVENT_COLORS.ratelimit;
  return DEFAULT_COLOR;
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: Array<{ payload: { eventName: string; count: number; pct: number } }>;
}

function CustomPieTooltip({ active, payload }: CustomTooltipProps) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div className="bg-[#0f1423]/95 backdrop-blur-xl border border-[#1a2332] rounded-lg px-3 py-2 shadow-xl">
      <p className="text-xs font-medium text-gray-200">{d.eventName}</p>
      <p className="text-xs text-gray-400 mt-0.5">
        {formatNumber(d.count)} events ({d.pct.toFixed(1)}%)
      </p>
    </div>
  );
}

function CustomLegend({ payload }: { payload?: Array<{ value: string; color: string }> }) {
  if (!payload) return null;
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 justify-center mt-2">
      {payload.map((entry, i) => (
        <div key={i} className="flex items-center gap-1.5">
          <span
            className="inline-block w-2.5 h-2.5 rounded-full"
            style={{ backgroundColor: entry.color }}
          />
          <span className="text-[11px] text-gray-400">{entry.value}</span>
        </div>
      ))}
    </div>
  );
}

export default function SecurityBreakdown({
  breakdown,
  topSignatures,
  topViolations,
}: SecurityBreakdownProps) {
  const totalEvents = useMemo(
    () => breakdown.reduce((acc, b) => acc + b.count, 0),
    [breakdown]
  );

  const chartData = useMemo(
    () =>
      breakdown.map((b) => ({
        ...b,
        fill: getEventColor(b.eventName),
      })),
    [breakdown]
  );

  const displayedSignatures = topSignatures.slice(0, 5);
  const displayedViolations = topViolations.slice(0, 5);

  const hasData = breakdown.length > 0;

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-[#ff0040]" />
          <h3 className="text-sm font-semibold text-gray-200">Security Events</h3>
        </div>
        <span className="text-xs font-mono text-gray-500">
          {formatNumber(totalEvents)} total
        </span>
      </div>

      {!hasData ? (
        <div className="flex flex-col items-center justify-center py-12 text-gray-500">
          <Shield className="w-8 h-8 mb-2 opacity-40" />
          <p className="text-xs">No security events in current window</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Donut Chart */}
          <div className="lg:col-span-1">
            <div className="relative">
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={chartData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={2}
                    dataKey="count"
                    nameKey="eventName"
                    stroke="none"
                  >
                    {chartData.map((entry, index) => (
                      <Cell key={index} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomPieTooltip />} />
                  <Legend content={<CustomLegend />} />
                </PieChart>
              </ResponsiveContainer>

              {/* Center label */}
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none" style={{ marginBottom: 24 }}>
                <div className="text-center">
                  <span className="block text-lg font-bold text-gray-100 font-mono">
                    {formatNumber(totalEvents)}
                  </span>
                  <span className="block text-[10px] text-gray-500 uppercase tracking-wider">
                    Events
                  </span>
                </div>
              </div>
            </div>

            {/* Breakdown list */}
            <div className="mt-3 space-y-1.5">
              {breakdown.map((b) => (
                <div key={b.eventName} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span
                      className="inline-block w-2 h-2 rounded-full"
                      style={{ backgroundColor: getEventColor(b.eventName) }}
                    />
                    <span className="text-xs text-gray-400 truncate max-w-[120px]">
                      {b.eventName}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-gray-300">
                      {formatNumber(b.count)}
                    </span>
                    <span className="text-[10px] font-mono text-gray-500 w-10 text-right">
                      {b.pct.toFixed(1)}%
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Top Signatures */}
          <div className="lg:col-span-1">
            <div className="flex items-center gap-1.5 mb-3">
              <Fingerprint className="w-3.5 h-3.5 text-[#ff0040]" />
              <h4 className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
                Top Signatures
              </h4>
            </div>

            {displayedSignatures.length === 0 ? (
              <p className="text-xs text-gray-600 italic">No signatures fired</p>
            ) : (
              <div className="space-y-1">
                <div className="grid grid-cols-[1fr_auto] gap-2 text-[10px] text-gray-500 uppercase tracking-wider pb-1 border-b border-[#1a2332]">
                  <span>Signature ID</span>
                  <span className="text-right">Hits</span>
                </div>
                {displayedSignatures.map((sig, i) => {
                  const maxCount = displayedSignatures[0]?.count || 1;
                  const barPct = (sig.count / maxCount) * 100;
                  return (
                    <div key={sig.id} className="relative group">
                      {/* Background bar */}
                      <div
                        className="absolute inset-y-0 left-0 bg-[#ff0040]/10 rounded"
                        style={{ width: `${barPct}%` }}
                      />
                      <div className="relative grid grid-cols-[1fr_auto] gap-2 py-1.5 px-1">
                        <div className="flex items-center gap-1.5">
                          <span className="text-[10px] text-gray-600 font-mono w-3">
                            {i + 1}
                          </span>
                          <span className="text-xs font-mono text-gray-300 truncate">
                            {sig.id}
                          </span>
                        </div>
                        <span className="text-xs font-mono text-[#ff0040] font-medium">
                          {formatNumber(sig.count)}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Top Violations */}
          <div className="lg:col-span-1">
            <div className="flex items-center gap-1.5 mb-3">
              <AlertTriangle className="w-3.5 h-3.5 text-[#ffbe0b]" />
              <h4 className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
                Top Violations
              </h4>
            </div>

            {displayedViolations.length === 0 ? (
              <p className="text-xs text-gray-600 italic">No violations detected</p>
            ) : (
              <div className="space-y-1">
                <div className="grid grid-cols-[1fr_auto] gap-2 text-[10px] text-gray-500 uppercase tracking-wider pb-1 border-b border-[#1a2332]">
                  <span>Violation</span>
                  <span className="text-right">Count</span>
                </div>
                {displayedViolations.map((viol, i) => {
                  const maxCount = displayedViolations[0]?.count || 1;
                  const barPct = (viol.count / maxCount) * 100;
                  return (
                    <div key={viol.name} className="relative group">
                      <div
                        className="absolute inset-y-0 left-0 bg-[#ffbe0b]/10 rounded"
                        style={{ width: `${barPct}%` }}
                      />
                      <div className="relative grid grid-cols-[1fr_auto] gap-2 py-1.5 px-1">
                        <div className="flex items-center gap-1.5">
                          <span className="text-[10px] text-gray-600 font-mono w-3">
                            {i + 1}
                          </span>
                          <span className="text-xs text-gray-300 truncate">
                            {viol.name}
                          </span>
                        </div>
                        <span className="text-xs font-mono text-[#ffbe0b] font-medium">
                          {formatNumber(viol.count)}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
