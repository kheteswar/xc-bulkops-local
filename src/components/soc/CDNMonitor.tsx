import { useMemo } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import { HardDrive, ArrowDownToLine, Cookie } from 'lucide-react';

interface CDNMonitorProps {
  hitRatio: number | null;
  missReasons?: Array<{ reason: string; count: number }>;
  tsCookieIssue?: boolean;
  originPullRate?: number;
}

function formatPct(n: number): string {
  return `${n.toFixed(1)}%`;
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

function getHitRatioColor(ratio: number): string {
  if (ratio >= 90) return '#00ff88';
  if (ratio >= 70) return '#ffbe0b';
  return '#ff0040';
}

export default function CDNMonitor({
  hitRatio,
  missReasons,
  tsCookieIssue,
  originPullRate,
}: CDNMonitorProps) {
  if (hitRatio === null || hitRatio === undefined) {
    return (
      <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
        <div className="flex items-center gap-2 mb-4">
          <HardDrive className="w-4 h-4 text-[#00d4ff]" />
          <h3 className="text-sm font-semibold text-gray-200">CDN Performance</h3>
        </div>
        <div className="flex flex-col items-center justify-center py-12 text-gray-500">
          <HardDrive className="w-10 h-10 mb-3 opacity-30" />
          <p className="text-sm font-medium text-gray-400">CDN Not Configured</p>
          <p className="text-xs text-gray-600 mt-1">
            No CDN distribution is associated with this room
          </p>
        </div>
      </div>
    );
  }

  const hitColor = getHitRatioColor(hitRatio);
  const missRatio = 100 - hitRatio;

  const gaugeData = useMemo(
    () => [
      { name: 'Hit', value: hitRatio },
      { name: 'Miss', value: missRatio },
    ],
    [hitRatio, missRatio]
  );

  const totalMisses = useMemo(
    () => (missReasons || []).reduce((acc, r) => acc + r.count, 0),
    [missReasons]
  );

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <HardDrive className="w-4 h-4 text-[#00d4ff]" />
          <h3 className="text-sm font-semibold text-gray-200">CDN Performance</h3>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Hit Ratio Gauge */}
        <div className="flex flex-col items-center">
          <h4 className="text-[11px] text-gray-500 uppercase tracking-wider mb-2">
            Cache Hit Ratio
          </h4>
          <div className="relative w-40 h-24">
            <ResponsiveContainer width="100%" height={100}>
              <PieChart>
                <Pie
                  data={gaugeData}
                  cx="50%"
                  cy="100%"
                  startAngle={180}
                  endAngle={0}
                  innerRadius={55}
                  outerRadius={75}
                  paddingAngle={1}
                  dataKey="value"
                  stroke="none"
                >
                  <Cell fill={hitColor} />
                  <Cell fill="#1a2332" />
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-x-0 bottom-0 flex flex-col items-center">
              <span
                className="text-2xl font-bold font-mono"
                style={{ color: hitColor }}
              >
                {hitRatio.toFixed(1)}%
              </span>
              <span className="text-[10px] text-gray-500 uppercase">Hit Rate</span>
            </div>
          </div>

          {/* Origin Pull Rate */}
          {originPullRate !== undefined && originPullRate !== null && (
            <div className="mt-4 w-full">
              <div className="flex items-center gap-1.5 mb-2">
                <ArrowDownToLine className="w-3.5 h-3.5 text-gray-400" />
                <span className="text-[11px] text-gray-500 uppercase tracking-wider">
                  Origin Pull Rate
                </span>
              </div>
              <div className="flex items-center gap-3">
                <div className="flex-1 h-3 bg-[#1a2332] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${Math.min(originPullRate, 100)}%`,
                      backgroundColor: originPullRate < 20 ? '#00ff88' : originPullRate < 40 ? '#ffbe0b' : '#ff0040',
                    }}
                  />
                </div>
                <span
                  className="text-sm font-mono font-semibold"
                  style={{
                    color: originPullRate < 20 ? '#00ff88' : originPullRate < 40 ? '#ffbe0b' : '#ff0040',
                  }}
                >
                  {formatPct(originPullRate)}
                </span>
              </div>
              <p className="text-[10px] text-gray-600 mt-1">
                {originPullRate < 20
                  ? 'Excellent — minimal origin load'
                  : originPullRate < 40
                    ? 'Moderate — review cache policies'
                    : 'High — most requests hitting origin'}
              </p>
            </div>
          )}
        </div>

        {/* Miss Reasons */}
        <div>
          <h4 className="text-[11px] text-gray-500 uppercase tracking-wider mb-2">
            Cache Miss Reasons
          </h4>
          {!missReasons || missReasons.length === 0 ? (
            <p className="text-xs text-gray-600 italic py-2">No miss data available</p>
          ) : (
            <div className="space-y-1">
              <div className="grid grid-cols-[1fr_auto_auto] gap-2 text-[10px] text-gray-500 uppercase tracking-wider pb-1 border-b border-[#1a2332]">
                <span>Reason</span>
                <span className="text-right">Count</span>
                <span className="text-right w-12">%</span>
              </div>
              {missReasons.map((reason) => {
                const pct = totalMisses > 0 ? (reason.count / totalMisses) * 100 : 0;
                return (
                  <div
                    key={reason.reason}
                    className="grid grid-cols-[1fr_auto_auto] gap-2 py-1.5 px-1 rounded hover:bg-[#1a2332]/50 transition-colors"
                  >
                    <span className="text-xs text-gray-300 truncate">{reason.reason}</span>
                    <span className="text-xs font-mono text-gray-400 text-right">
                      {formatNumber(reason.count)}
                    </span>
                    <span className="text-xs font-mono text-gray-500 text-right w-12">
                      {pct.toFixed(1)}%
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* TS Cookie Warning */}
      {tsCookieIssue && (
        <div className="mt-4 pt-4 border-t border-[#1a2332]">
          <div className="flex items-start gap-2 bg-[#ffbe0b]/10 border border-[#ffbe0b]/30 rounded-lg p-3">
            <Cookie className="w-4 h-4 text-[#ffbe0b] flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-bold text-[#ffbe0b]">TS Cookie Causing Cache Misses</p>
              <p className="text-[11px] text-gray-400 mt-0.5">
                F5 WAF TS-prefixed set-cookie headers are preventing cache hits. Configure{' '}
                <span className="font-mono text-gray-300">Ignore-Response-Cookie</span> in the CDN
                distribution to resolve.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
