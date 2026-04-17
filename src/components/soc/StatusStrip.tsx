import { useMemo } from 'react';
import { Activity, ChevronDown, Database, Pause, History } from 'lucide-react';
import ThreatLevelOrb from './ThreatLevelOrb';
import DeltaBadge from './DeltaBadge';
import type {
  DashboardMetrics,
  HeartbeatResult,
  LatencyStats,
  ThreatLevel,
  PollingStatus,
  SOCRoomConfig,
} from '../../services/live-soc/types';
import { THREAT_COLORS } from '../../services/live-soc/types';

interface StatusStripProps {
  metrics: DashboardMetrics;
  heartbeat: HeartbeatResult;
  latencyStats: LatencyStats;
  threatLevel: ThreatLevel;
  countdown: number;
  pollingStatus: PollingStatus;
  rateState: string;
  selectedDomain: string | null;
  domains: string[];
  onDomainChange: (d: string | null) => void;
  historyMode: boolean;
  room: SOCRoomConfig;
}

interface GaugeProps {
  label: string;
  value: string;
  current: number;
  previous: number;
  format?: 'number' | 'percent';
  inverse?: boolean;
  icon?: React.ReactNode;
}

function Gauge({ label, value, current, previous, format, inverse, icon }: GaugeProps) {
  return (
    <div className="flex flex-col items-center gap-0.5 px-3 min-w-0">
      <span className="text-[10px] uppercase tracking-wider text-gray-500 truncate flex items-center gap-1">
        {icon}
        {label}
      </span>
      <span className="text-sm font-mono font-semibold text-gray-100">{value}</span>
      <DeltaBadge current={current} previous={previous} format={format} inverse={inverse} />
    </div>
  );
}

interface StatusDotProps {
  label: string;
  healthy: boolean | null;
}

function StatusDot({ label, healthy }: StatusDotProps) {
  const color =
    healthy === null ? 'bg-gray-600' : healthy ? 'bg-[#00ff88]' : 'bg-[#ff0040]';
  const glow =
    healthy === null
      ? ''
      : healthy
        ? 'shadow-[0_0_6px_#00ff8866]'
        : 'shadow-[0_0_6px_#ff004066]';

  return (
    <div className="flex flex-col items-center gap-0.5 px-2">
      <span className="text-[10px] uppercase tracking-wider text-gray-500">{label}</span>
      <div className={`w-2.5 h-2.5 rounded-full ${color} ${glow}`} />
    </div>
  );
}

function CountdownRing({ countdown, total }: { countdown: number; total: number }) {
  const radius = 16;
  const circumference = 2 * Math.PI * radius;
  const progress = total > 0 ? Math.max(0, countdown / total) : 0;
  const dashOffset = circumference * (1 - progress);

  return (
    <div className="relative flex items-center justify-center w-10 h-10">
      <svg className="w-10 h-10 -rotate-90" viewBox="0 0 40 40">
        <circle cx="20" cy="20" r={radius} fill="none" stroke="#1a2332" strokeWidth="2.5" />
        <circle
          cx="20"
          cy="20"
          r={radius}
          fill="none"
          stroke="#00d4ff"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          className="transition-[stroke-dashoffset] duration-1000 ease-linear"
        />
      </svg>
      <span className="absolute text-[10px] font-mono text-gray-300">{countdown}s</span>
    </div>
  );
}

export default function StatusStrip(props: StatusStripProps) {
  const {
    metrics,
    latencyStats,
    threatLevel,
    countdown,
    pollingStatus,
    rateState,
    selectedDomain,
    domains,
    onDomainChange,
    historyMode,
    room,
  } = props;
  const threatColor = THREAT_COLORS[threatLevel];
  const sampleRate = room.pollingIntervalSec > 120 ? Math.ceil(room.pollingIntervalSec / 60) : 1;
  const isSampled = sampleRate > 1;
  const isPaused = pollingStatus === 'paused';

  const dnsHealthy = useMemo(() => {
    if (room.dnsLoadBalancers.length === 0) return null;
    return true; // Will be driven by state in real integration
  }, [room.dnsLoadBalancers]);

  const syntheticHealthy = useMemo(() => {
    if (!room.features.syntheticMonitorsEnabled) return null;
    return true;
  }, [room.features.syntheticMonitorsEnabled]);

  const fmtRps = (v: number) => (v >= 1000 ? `${(v / 1000).toFixed(1)}k` : v.toFixed(1));
  const fmtPct = (v: number) => `${v.toFixed(2)}%`;
  const fmtMs = (v: number) => (v >= 1000 ? `${(v / 1000).toFixed(2)}s` : `${Math.round(v)}ms`);

  return (
    <div className="relative bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl px-4 py-2.5">
      {/* Paused overlay */}
      {isPaused && (
        <div className="absolute inset-0 bg-black/50 backdrop-blur-sm rounded-xl z-20 flex items-center justify-center gap-2">
          <Pause className="w-5 h-5 text-[#ffbe0b]" />
          <span className="text-[#ffbe0b] font-semibold tracking-widest text-sm uppercase">Paused</span>
        </div>
      )}

      {/* History mode badge */}
      {historyMode && (
        <div className="absolute top-0 right-0 bg-[#00d4ff]/10 border border-[#00d4ff]/30 rounded-bl-lg rounded-tr-xl px-3 py-1 z-10 flex items-center gap-1.5">
          <History className="w-3.5 h-3.5 text-[#00d4ff]" />
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[#00d4ff]">History</span>
        </div>
      )}

      <div className="flex items-center gap-3">
        {/* Left: Threat level */}
        <div className="flex items-center gap-2 pr-3 border-r border-[#1a2332]">
          <ThreatLevelOrb level={threatLevel} size="sm" />
          <div className="flex flex-col">
            <span
              className="text-xs font-bold tracking-widest uppercase"
              style={{ color: threatColor }}
            >
              {threatLevel}
            </span>
            {rateState !== 'normal' && (
              <span className="text-[9px] text-[#ffbe0b] uppercase">{rateState}</span>
            )}
          </div>
        </div>

        {/* Center: Gauges */}
        <div className="flex items-center divide-x divide-[#1a2332] flex-1 overflow-x-auto scrollbar-thin">
          <Gauge
            label="RPS"
            value={fmtRps(metrics.rps)}
            current={metrics.rps}
            previous={metrics.prevRps}
            icon={<Activity className="w-3 h-3" />}
          />
          <Gauge
            label="Err%"
            value={fmtPct(metrics.errorRate)}
            current={metrics.errorRate}
            previous={metrics.prevErrorRate}
            format="percent"
            inverse
          />
          <Gauge
            label="Sec Events"
            value={metrics.totalSecEvents.toLocaleString()}
            current={metrics.totalSecEvents}
            previous={metrics.prevTotalSecEvents}
            inverse
          />
          <Gauge
            label="Origin P95"
            value={fmtMs(latencyStats.p95)}
            current={latencyStats.p95}
            previous={0}
          />
          <Gauge
            label="CDN Hit%"
            value={metrics.cacheHitRatio !== null ? fmtPct(metrics.cacheHitRatio) : 'N/A'}
            current={metrics.cacheHitRatio ?? 0}
            previous={0}
          />
          <Gauge
            label="Bot%"
            value={metrics.botRatio !== null ? fmtPct(metrics.botRatio) : 'N/A'}
            current={metrics.botRatio ?? 0}
            previous={0}
            inverse
          />
          <StatusDot label="DNS" healthy={dnsHealthy} />
          <StatusDot label="Synth" healthy={syntheticHealthy} />
        </div>

        {/* Sampled indicator */}
        {isSampled && (
          <div className="flex items-center gap-1 px-2 py-0.5 bg-[#ffbe0b]/10 border border-[#ffbe0b]/20 rounded text-[9px] text-[#ffbe0b] uppercase font-semibold">
            <Database className="w-3 h-3" />
            1:{sampleRate}
          </div>
        )}

        {/* Right: Countdown + Domain selector */}
        <div className="flex items-center gap-3 pl-3 border-l border-[#1a2332]">
          <CountdownRing countdown={countdown} total={room.pollingIntervalSec} />

          {domains.length > 0 && (
            <div className="relative">
              <select
                value={selectedDomain ?? '__all__'}
                onChange={(e) => onDomainChange(e.target.value === '__all__' ? null : e.target.value)}
                className="appearance-none bg-[#0a0e1a] border border-[#1a2332] rounded-lg px-3 py-1.5 pr-7 text-xs font-mono text-gray-300 focus:outline-none focus:border-[#00d4ff]/50 cursor-pointer"
              >
                <option value="__all__">All Domains</option>
                {domains.map((d) => (
                  <option key={d} value={d}>
                    {d}
                  </option>
                ))}
              </select>
              <ChevronDown className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
