import { Server } from 'lucide-react';
import type { DashboardMetrics } from '../../services/live-soc/types';

interface OriginHealthGridProps {
  origins: DashboardMetrics['originHealth'];
}

function statusColor(errorRate: number): { led: string; glow: string; label: string } {
  if (errorRate < 1) {
    return {
      led: 'bg-[#00ff88]',
      glow: 'shadow-[0_0_8px_#00ff8866]',
      label: 'Healthy',
    };
  }
  if (errorRate < 5) {
    return {
      led: 'bg-[#ffbe0b]',
      glow: 'shadow-[0_0_8px_#ffbe0b66]',
      label: 'Degraded',
    };
  }
  return {
    led: 'bg-[#ff0040]',
    glow: 'shadow-[0_0_8px_#ff004066]',
    label: 'Unhealthy',
  };
}

function fmtMs(v: number): string {
  if (v >= 1000) return `${(v / 1000).toFixed(2)}s`;
  return `${Math.round(v)}ms`;
}

function fmtCount(v: number): string {
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`;
  if (v >= 1000) return `${(v / 1000).toFixed(1)}k`;
  return v.toString();
}

function OriginCard({
  origin,
}: {
  origin: DashboardMetrics['originHealth'][number];
}) {
  const status = statusColor(origin.errorRate);

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-lg p-3 hover:border-[#1a2332]/80 transition-colors">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2 min-w-0">
          <Server className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" />
          <span className="font-mono text-xs text-gray-200 truncate" title={origin.dstIp}>
            {origin.dstIp}
          </span>
        </div>
        <div className="flex items-center gap-1.5 flex-shrink-0">
          <div className={`w-2.5 h-2.5 rounded-full ${status.led} ${status.glow}`} />
          <span className="text-[10px] text-gray-500 uppercase">{status.label}</span>
        </div>
      </div>

      {/* Metrics grid */}
      <div className="grid grid-cols-3 gap-2">
        <div className="flex flex-col">
          <span className="text-[9px] uppercase tracking-wider text-gray-600">Requests</span>
          <span className="text-sm font-mono font-semibold text-gray-200">{fmtCount(origin.totalCount)}</span>
        </div>
        <div className="flex flex-col">
          <span className="text-[9px] uppercase tracking-wider text-gray-600">Err%</span>
          <span
            className={`text-sm font-mono font-semibold ${
              origin.errorRate >= 5
                ? 'text-[#ff0040]'
                : origin.errorRate >= 1
                  ? 'text-[#ffbe0b]'
                  : 'text-[#00ff88]'
            }`}
          >
            {origin.errorRate.toFixed(2)}%
          </span>
        </div>
        <div className="flex flex-col">
          <span className="text-[9px] uppercase tracking-wider text-gray-600">P95</span>
          <span className="text-sm font-mono font-semibold text-gray-200">{fmtMs(origin.p95Latency)}</span>
        </div>
      </div>

      {/* Error rate bar */}
      <div className="mt-2.5">
        <div className="w-full h-1 bg-[#0a0e1a] rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-700"
            style={{
              width: `${Math.min(100, origin.errorRate * 10)}%`,
              backgroundColor:
                origin.errorRate >= 5 ? '#ff0040' : origin.errorRate >= 1 ? '#ffbe0b' : '#00ff88',
              opacity: 0.6,
            }}
          />
        </div>
      </div>
    </div>
  );
}

export default function OriginHealthGrid({ origins }: OriginHealthGridProps) {
  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      <h3 className="text-sm font-semibold text-gray-300 mb-3 tracking-wide uppercase">
        Origin Health
      </h3>

      {origins.length === 0 ? (
        <div className="flex items-center justify-center py-8 text-gray-600 text-sm font-mono">
          No origin data available
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
          {origins.map((origin) => (
            <OriginCard key={origin.dstIp} origin={origin} />
          ))}
        </div>
      )}
    </div>
  );
}
