import { useState, useMemo } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { Timer, AlertCircle, Server } from 'lucide-react';
import type { LatencyWaterfall as LatencyWaterfallType, LatencyStats } from '../../services/live-soc/types';

interface LatencyWaterfallProps {
  waterfall: LatencyWaterfallType;
  perOrigin: LatencyStats['perOrigin'];
  diagnosis?: { bottleneck: string; description: string };
}

const PHASE_COLORS = {
  upstream: '#00d4ff',
  origin: '#ffbe0b',
  downstream: '#00ff88',
};

function formatMs(ms: number): string {
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`;
  if (ms < 1) return `${(ms * 1000).toFixed(0)}\u00B5s`;
  return `${ms.toFixed(0)}ms`;
}

function computePhases(wf: LatencyWaterfallType, percentile: 'p50' | 'p95') {
  const clientToXc = wf.toFirstUpstreamTx[percentile];
  const xcToOrigin = Math.max(0, wf.toFirstUpstreamRx[percentile] - wf.toFirstUpstreamTx[percentile]);
  const originProcessing = Math.max(0, wf.toLastUpstreamRx[percentile] - wf.toFirstUpstreamRx[percentile]);
  const originToXc = Math.max(0, wf.toFirstDownstreamTx[percentile] - wf.toLastUpstreamRx[percentile]);
  const xcToClient = Math.max(0, wf.toLastDownstreamTx[percentile] - wf.toFirstDownstreamTx[percentile]);

  return [
    { name: 'Client \u2192 XC', value: clientToXc, color: PHASE_COLORS.upstream },
    { name: 'XC \u2192 Origin', value: xcToOrigin, color: PHASE_COLORS.upstream },
    { name: 'Origin Processing', value: originProcessing, color: PHASE_COLORS.origin },
    { name: 'Origin \u2192 XC', value: originToXc, color: PHASE_COLORS.downstream },
    { name: 'XC \u2192 Client', value: xcToClient, color: PHASE_COLORS.downstream },
  ];
}

interface WaterfallTooltipProps {
  active?: boolean;
  payload?: Array<{ payload: { name: string; p50: number; p95: number } }>;
}

function WaterfallTooltip({ active, payload }: WaterfallTooltipProps) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div className="bg-[#0f1423]/95 backdrop-blur-xl border border-[#1a2332] rounded-lg px-3 py-2 shadow-xl">
      <p className="text-xs font-medium text-gray-200">{d.name}</p>
      <div className="mt-1 space-y-0.5">
        <p className="text-[11px] text-gray-400">
          P50: <span className="text-gray-200 font-mono">{formatMs(d.p50)}</span>
        </p>
        <p className="text-[11px] text-gray-400">
          P95: <span className="text-gray-200 font-mono">{formatMs(d.p95)}</span>
        </p>
      </div>
    </div>
  );
}

export default function LatencyWaterfall({
  waterfall,
  perOrigin,
  diagnosis,
}: LatencyWaterfallProps) {
  const [selectedOrigin, setSelectedOrigin] = useState<string | null>(null);
  const [percentile, setPercentile] = useState<'p50' | 'p95'>('p95');

  const phases = useMemo(() => computePhases(waterfall, percentile), [waterfall, percentile]);

  const chartData = useMemo(() => {
    return phases.map((phase) => ({
      name: phase.name,
      p50: computePhases(waterfall, 'p50').find((p) => p.name === phase.name)?.value || 0,
      p95: computePhases(waterfall, 'p95').find((p) => p.name === phase.name)?.value || 0,
      color: phase.color,
    }));
  }, [waterfall, phases]);

  const totalMs = useMemo(
    () => phases.reduce((acc, p) => acc + p.value, 0),
    [phases]
  );

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Timer className="w-4 h-4 text-[#00d4ff]" />
          <h3 className="text-sm font-semibold text-gray-200">Latency Waterfall</h3>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-500">Total:</span>
          <span className="text-sm font-mono font-semibold text-gray-200">
            {formatMs(totalMs)}
          </span>
          <div className="flex bg-[#1a2332] rounded-md overflow-hidden ml-2">
            <button
              onClick={() => setPercentile('p50')}
              className={`px-2 py-0.5 text-[10px] font-mono transition-colors ${
                percentile === 'p50'
                  ? 'bg-[#00d4ff]/20 text-[#00d4ff]'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              P50
            </button>
            <button
              onClick={() => setPercentile('p95')}
              className={`px-2 py-0.5 text-[10px] font-mono transition-colors ${
                percentile === 'p95'
                  ? 'bg-[#00d4ff]/20 text-[#00d4ff]'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              P95
            </button>
          </div>
        </div>
      </div>

      {/* Horizontal stacked bars */}
      <div className="space-y-2 mb-4">
        {phases.map((phase) => {
          const pct = totalMs > 0 ? (phase.value / totalMs) * 100 : 0;
          return (
            <div key={phase.name} className="group">
              <div className="flex items-center justify-between mb-0.5">
                <span className="text-[11px] text-gray-400">{phase.name}</span>
                <span className="text-[11px] font-mono text-gray-300">
                  {formatMs(phase.value)}
                  <span className="text-gray-600 ml-1">({pct.toFixed(1)}%)</span>
                </span>
              </div>
              <div className="w-full h-3 bg-[#1a2332] rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${Math.max(pct, 0.5)}%`,
                    backgroundColor: phase.color,
                    boxShadow: `0 0 8px ${phase.color}40`,
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>

      {/* Stacked bar chart comparison */}
      <div className="h-40 mt-4">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} layout="vertical" barCategoryGap="20%">
            <XAxis
              type="number"
              tick={{ fill: '#6b7280', fontSize: 10 }}
              tickFormatter={(v: number) => formatMs(v)}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              type="category"
              dataKey="name"
              width={110}
              tick={{ fill: '#9ca3af', fontSize: 10 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip content={<WaterfallTooltip />} />
            <Bar dataKey="p50" fill={`${PHASE_COLORS.upstream}60`} radius={[0, 2, 2, 0]} name="P50" />
            <Bar dataKey="p95" fill={PHASE_COLORS.upstream} radius={[0, 2, 2, 0]} name="P95" />
            <Legend
              wrapperStyle={{ fontSize: '10px', paddingTop: 4 }}
              iconSize={8}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Per-Origin Tabs */}
      {perOrigin.length > 0 && (
        <div className="mt-4 pt-4 border-t border-[#1a2332]">
          <div className="flex items-center gap-2 mb-3">
            <Server className="w-3.5 h-3.5 text-gray-400" />
            <h4 className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
              Per-Origin Latency
            </h4>
          </div>

          {/* Origin tabs */}
          <div className="flex gap-1 mb-3 overflow-x-auto pb-1">
            {perOrigin.map((origin) => (
              <button
                key={origin.dstIp}
                onClick={() =>
                  setSelectedOrigin(
                    selectedOrigin === origin.dstIp ? null : origin.dstIp
                  )
                }
                className={`flex-shrink-0 px-2.5 py-1 rounded-md text-[11px] font-mono transition-colors ${
                  selectedOrigin === origin.dstIp
                    ? 'bg-[#00d4ff]/15 text-[#00d4ff] border border-[#00d4ff]/30'
                    : 'bg-[#1a2332] text-gray-400 border border-transparent hover:text-gray-200'
                }`}
              >
                {origin.dstIp}
              </button>
            ))}
          </div>

          {/* Selected origin details */}
          {selectedOrigin && (
            <div className="bg-[#0a0e1a]/50 rounded-lg p-3">
              {perOrigin
                .filter((o) => o.dstIp === selectedOrigin)
                .map((origin) => (
                  <div key={origin.dstIp} className="space-y-2">
                    <div className="grid grid-cols-4 gap-3">
                      <div>
                        <span className="text-[10px] text-gray-500 uppercase">P50</span>
                        <p className="text-sm font-mono text-gray-200">{formatMs(origin.p50)}</p>
                      </div>
                      <div>
                        <span className="text-[10px] text-gray-500 uppercase">P95</span>
                        <p className="text-sm font-mono text-gray-200">{formatMs(origin.p95)}</p>
                      </div>
                      <div>
                        <span className="text-[10px] text-gray-500 uppercase">Origin TTFB P95</span>
                        <p className="text-sm font-mono text-[#ffbe0b]">
                          {formatMs(origin.originTTFB_p95)}
                        </p>
                      </div>
                      <div>
                        <span className="text-[10px] text-gray-500 uppercase">Requests</span>
                        <p className="text-sm font-mono text-gray-200">
                          {origin.count.toLocaleString()}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
            </div>
          )}

          {/* Unselected summary table */}
          {!selectedOrigin && (
            <div className="space-y-0.5">
              <div className="grid grid-cols-5 gap-2 text-[10px] text-gray-500 uppercase tracking-wider pb-1 px-1">
                <span>Origin IP</span>
                <span className="text-right">P50</span>
                <span className="text-right">P95</span>
                <span className="text-right">TTFB P95</span>
                <span className="text-right">Reqs</span>
              </div>
              {perOrigin.map((origin) => (
                <button
                  key={origin.dstIp}
                  onClick={() => setSelectedOrigin(origin.dstIp)}
                  className="grid grid-cols-5 gap-2 w-full text-left py-1.5 px-1 rounded hover:bg-[#1a2332]/50 transition-colors"
                >
                  <span className="text-xs font-mono text-gray-300 truncate">{origin.dstIp}</span>
                  <span className="text-xs font-mono text-gray-400 text-right">{formatMs(origin.p50)}</span>
                  <span className="text-xs font-mono text-gray-400 text-right">{formatMs(origin.p95)}</span>
                  <span className="text-xs font-mono text-[#ffbe0b] text-right">
                    {formatMs(origin.originTTFB_p95)}
                  </span>
                  <span className="text-xs font-mono text-gray-500 text-right">
                    {origin.count.toLocaleString()}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Auto-Diagnosis Callout */}
      {diagnosis && (
        <div className="mt-4 pt-4 border-t border-[#1a2332]">
          <div className="flex items-start gap-2 bg-[#ffbe0b]/5 border border-[#ffbe0b]/20 rounded-lg p-3">
            <AlertCircle className="w-4 h-4 text-[#ffbe0b] flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-semibold text-[#ffbe0b]">
                Bottleneck: {diagnosis.bottleneck}
              </p>
              <p className="text-xs text-gray-400 mt-0.5">{diagnosis.description}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
