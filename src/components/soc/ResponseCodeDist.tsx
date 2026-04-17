import { useMemo } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import type { TimeSeriesPoint } from '../../services/live-soc/types';

interface ResponseCodeDistProps {
  history: TimeSeriesPoint[];
  currentDist: Array<{ code: string; count: number; pct: number }>;
}

const CODE_COLORS: Record<string, string> = {
  '2xx': '#00ff88',
  '3xx': '#00d4ff',
  '4xx': '#ffbe0b',
  '5xx': '#ff0040',
};

function formatTime(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return ts;
  }
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: Array<{ name: string; value: number; color: string }>;
  label?: string;
}

function CustomTooltip({ active, payload, label }: CustomTooltipProps) {
  if (!active || !payload) return null;
  return (
    <div className="bg-[#0f1423]/95 backdrop-blur-lg border border-[#1a2332] rounded-lg px-3 py-2 shadow-xl">
      <p className="text-[10px] text-gray-400 font-mono mb-1">{label}</p>
      {payload.map((entry) => (
        <p key={entry.name} className="text-xs font-mono" style={{ color: entry.color }}>
          {entry.name}: {entry.value.toFixed(1)}%
        </p>
      ))}
    </div>
  );
}

function DistBar({ code, pct, count }: { code: string; pct: number; count: number }) {
  const color = CODE_COLORS[code] ?? '#6b7280';
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="font-mono font-semibold w-7" style={{ color }}>
        {code}
      </span>
      <div className="flex-1 h-3 bg-[#0a0e1a] rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${Math.min(100, pct)}%`, backgroundColor: color, opacity: 0.7 }}
        />
      </div>
      <span className="font-mono text-gray-400 w-12 text-right">{pct.toFixed(1)}%</span>
      <span className="font-mono text-gray-600 w-14 text-right">{count.toLocaleString()}</span>
    </div>
  );
}

export default function ResponseCodeDist({ history, currentDist }: ResponseCodeDistProps) {
  // Build stacked chart data by deriving code class percentages from each point's errorRate
  const chartData = useMemo(() => {
    return history.map((p) => {
      const err = p.errorRate;
      // Approximate breakdown: 5xx ~ half of errorRate, 4xx ~ half, remainder is 2xx+3xx
      const fiveXx = Math.min(err, p.errorRate * 0.5);
      const fourXx = err - fiveXx;
      const success = 100 - err;
      return {
        time: formatTime(p.timestamp),
        '2xx': Math.max(0, success * 0.92),
        '3xx': Math.max(0, success * 0.08),
        '4xx': Math.max(0, fourXx),
        '5xx': Math.max(0, fiveXx),
      };
    });
  }, [history]);

  // Group current distribution into code classes
  const grouped = useMemo(() => {
    const groups: Record<string, { count: number; pct: number }> = {
      '2xx': { count: 0, pct: 0 },
      '3xx': { count: 0, pct: 0 },
      '4xx': { count: 0, pct: 0 },
      '5xx': { count: 0, pct: 0 },
    };

    for (const entry of currentDist) {
      const codeClass = entry.code.startsWith('2')
        ? '2xx'
        : entry.code.startsWith('3')
          ? '3xx'
          : entry.code.startsWith('4')
            ? '4xx'
            : entry.code.startsWith('5')
              ? '5xx'
              : null;
      if (codeClass && groups[codeClass]) {
        groups[codeClass].count += entry.count;
        groups[codeClass].pct += entry.pct;
      }
    }

    return Object.entries(groups)
      .map(([code, data]) => ({ code, ...data }))
      .filter((g) => g.count > 0 || g.code === '2xx');
  }, [currentDist]);

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
        Response Code Distribution
      </h3>

      <div className="flex gap-4">
        {/* Left: Stacked area chart */}
        <div className="flex-1 min-w-0">
          {history.length === 0 ? (
            <div className="flex items-center justify-center h-48 text-gray-600 text-sm font-mono">
              Awaiting data...
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={chartData} margin={{ top: 5, right: 10, left: 0, bottom: 0 }}>
                <defs>
                  {Object.entries(CODE_COLORS).map(([key, color]) => (
                    <linearGradient key={key} id={`soc-code-${key}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={color} stopOpacity={0.4} />
                      <stop offset="100%" stopColor={color} stopOpacity={0.05} />
                    </linearGradient>
                  ))}
                </defs>

                <CartesianGrid strokeDasharray="3 3" stroke="#1a2332" vertical={false} />
                <XAxis
                  dataKey="time"
                  tick={{ fontSize: 10, fill: '#6b7280' }}
                  stroke="#1a2332"
                  tickLine={false}
                  interval="preserveStartEnd"
                />
                <YAxis
                  domain={[0, 100]}
                  tick={{ fontSize: 10, fill: '#6b7280' }}
                  stroke="#1a2332"
                  tickLine={false}
                  axisLine={false}
                  tickFormatter={(v: number) => `${v}%`}
                  width={40}
                />
                <Tooltip content={<CustomTooltip />} />

                <Area
                  type="monotone"
                  dataKey="5xx"
                  stackId="1"
                  stroke={CODE_COLORS['5xx']}
                  fill={`url(#soc-code-5xx)`}
                  strokeWidth={1}
                  isAnimationActive={false}
                />
                <Area
                  type="monotone"
                  dataKey="4xx"
                  stackId="1"
                  stroke={CODE_COLORS['4xx']}
                  fill={`url(#soc-code-4xx)`}
                  strokeWidth={1}
                  isAnimationActive={false}
                />
                <Area
                  type="monotone"
                  dataKey="3xx"
                  stackId="1"
                  stroke={CODE_COLORS['3xx']}
                  fill={`url(#soc-code-3xx)`}
                  strokeWidth={1}
                  isAnimationActive={false}
                />
                <Area
                  type="monotone"
                  dataKey="2xx"
                  stackId="1"
                  stroke={CODE_COLORS['2xx']}
                  fill={`url(#soc-code-2xx)`}
                  strokeWidth={1}
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Right: Current distribution bars */}
        <div className="w-56 flex flex-col justify-center gap-2 flex-shrink-0">
          <span className="text-[10px] uppercase tracking-wider text-gray-500 mb-1">Current</span>
          {grouped.map((g) => (
            <DistBar key={g.code} code={g.code} pct={g.pct} count={g.count} />
          ))}
        </div>
      </div>
    </div>
  );
}
