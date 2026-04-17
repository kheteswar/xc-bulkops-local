import { useMemo } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
  ReferenceArea,
  Dot,
} from 'recharts';
import type { TimeSeriesPoint } from '../../services/live-soc/types';
import { THREAT_COLORS } from '../../services/live-soc/types';

interface TrafficTimeSeriesProps {
  history: TimeSeriesPoint[];
  baseline: { avgRps: number; stdDevRps: number };
}

function formatTime(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return ts;
  }
}

function formatRps(val: number): string {
  if (val >= 1000) return `${(val / 1000).toFixed(1)}k`;
  return val.toFixed(1);
}

interface CustomDotProps {
  cx?: number;
  cy?: number;
  payload?: TimeSeriesPoint;
}

function AnomalyDot({ cx, cy, payload }: CustomDotProps) {
  if (!payload || !cx || !cy || payload.threatLevel === 'NOMINAL') return null;
  const color = THREAT_COLORS[payload.threatLevel];
  return (
    <Dot
      cx={cx}
      cy={cy}
      r={4}
      fill={color}
      stroke={color}
      strokeWidth={2}
      opacity={0.9}
    />
  );
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: Array<{ payload: TimeSeriesPoint }>;
}

function CustomTooltip({ active, payload }: CustomTooltipProps) {
  if (!active || !payload?.[0]) return null;
  const point = payload[0].payload;
  const threatColor = THREAT_COLORS[point.threatLevel];

  return (
    <div className="bg-[#0f1423]/95 backdrop-blur-lg border border-[#1a2332] rounded-lg px-3 py-2 shadow-xl">
      <p className="text-[10px] text-gray-400 font-mono">{formatTime(point.timestamp)}</p>
      <p className="text-sm font-mono font-semibold text-gray-100 mt-0.5">
        {formatRps(point.rps)} <span className="text-gray-500 text-xs">rps</span>
      </p>
      <p className="text-[10px] font-mono mt-0.5" style={{ color: threatColor }}>
        {point.threatLevel}
      </p>
    </div>
  );
}

export default function TrafficTimeSeries({ history, baseline }: TrafficTimeSeriesProps) {
  const chartData = useMemo(
    () =>
      history.map((p) => ({
        ...p,
        time: formatTime(p.timestamp),
        baselineAvg: baseline.avgRps,
        bandUpper: baseline.avgRps + baseline.stdDevRps,
        bandLower: Math.max(0, baseline.avgRps - baseline.stdDevRps),
      })),
    [history, baseline],
  );

  const maxRps = useMemo(() => {
    const maxFromData = Math.max(...history.map((p) => p.rps), 0);
    const maxFromBaseline = baseline.avgRps + baseline.stdDevRps * 2;
    return Math.max(maxFromData, maxFromBaseline) * 1.15 || 10;
  }, [history, baseline]);

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
        Traffic Volume
      </h3>

      {history.length === 0 ? (
        <div className="flex items-center justify-center h-48 text-gray-600 text-sm font-mono">
          Awaiting data...
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={chartData} margin={{ top: 5, right: 10, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="soc-rps-gradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#00d4ff" stopOpacity={0.3} />
                <stop offset="100%" stopColor="#00d4ff" stopOpacity={0.02} />
              </linearGradient>
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
              domain={[0, maxRps]}
              tick={{ fontSize: 10, fill: '#6b7280' }}
              stroke="#1a2332"
              tickLine={false}
              axisLine={false}
              tickFormatter={formatRps}
              width={45}
            />

            <Tooltip content={<CustomTooltip />} />

            {/* Baseline +/- 1 sigma band */}
            {baseline.stdDevRps > 0 && (
              <ReferenceArea
                y1={Math.max(0, baseline.avgRps - baseline.stdDevRps)}
                y2={baseline.avgRps + baseline.stdDevRps}
                fill="#6b7280"
                fillOpacity={0.06}
                strokeOpacity={0}
              />
            )}

            {/* Baseline average line */}
            {baseline.avgRps > 0 && (
              <ReferenceLine
                y={baseline.avgRps}
                stroke="#6b7280"
                strokeDasharray="6 4"
                strokeWidth={1}
                label={{
                  value: `avg ${formatRps(baseline.avgRps)}`,
                  position: 'insideTopRight',
                  fill: '#6b7280',
                  fontSize: 10,
                }}
              />
            )}

            {/* RPS area */}
            <Area
              type="monotone"
              dataKey="rps"
              stroke="#00d4ff"
              strokeWidth={2}
              fill="url(#soc-rps-gradient)"
              dot={<AnomalyDot />}
              activeDot={{ r: 5, fill: '#00d4ff', strokeWidth: 0 }}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
