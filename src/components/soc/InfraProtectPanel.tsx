import { Shield, Zap, Network, AlertTriangle } from 'lucide-react';
import type { InfraProtectSummary } from '../../services/live-soc/types';

interface InfraProtectPanelProps {
  data: InfraProtectSummary | null;
}

function severityColor(severity: string): string {
  const s = severity.toLowerCase();
  if (s === 'critical') return 'text-[#ff0040] bg-[#ff0040]/10 border-[#ff0040]/30';
  if (s === 'high') return 'text-[#ff6b35] bg-[#ff6b35]/10 border-[#ff6b35]/30';
  if (s === 'major' || s === 'medium') return 'text-[#ffbe0b] bg-[#ffbe0b]/10 border-[#ffbe0b]/30';
  return 'text-gray-400 bg-gray-400/10 border-gray-400/30';
}

function formatBps(bps: number): string {
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(1)} Gbps`;
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbps`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} Kbps`;
  return `${bps} bps`;
}

function formatPps(pps: number): string {
  if (pps >= 1_000_000) return `${(pps / 1_000_000).toFixed(1)}M pps`;
  if (pps >= 1_000) return `${(pps / 1_000).toFixed(1)}K pps`;
  return `${pps} pps`;
}

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch {
    return ts;
  }
}

export default function InfraProtectPanel({ data }: InfraProtectPanelProps) {
  if (!data) {
    return (
      <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
        <div className="flex items-center gap-2 mb-4">
          <Shield className="w-4 h-4 text-[#00d4ff]" />
          <h3 className="text-sm font-semibold text-gray-200">Infrastructure Protection</h3>
        </div>
        <div className="flex flex-col items-center justify-center py-12 text-gray-500">
          <Shield className="w-10 h-10 mb-3 opacity-30" />
          <p className="text-sm font-medium text-gray-400">InfraProtect Not Enabled</p>
          <p className="text-xs text-gray-600 mt-1">
            Enable L3/L4 DDoS protection to monitor infrastructure attacks
          </p>
        </div>
      </div>
    );
  }

  const hasAlerts = data.alerts.length > 0;
  const hasMitigations = data.activeMitigations.length > 0;
  const hasTalkers = data.topTalkers.length > 0;

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-[#00d4ff]" />
          <h3 className="text-sm font-semibold text-gray-200">Infrastructure Protection</h3>
        </div>
        <div className="flex items-center gap-2">
          {hasAlerts && (
            <span className="text-[10px] text-[#ff0040] bg-[#ff0040]/10 px-1.5 py-0.5 rounded font-medium">
              {data.alerts.length} alert{data.alerts.length > 1 ? 's' : ''}
            </span>
          )}
          {hasMitigations && (
            <span className="text-[10px] text-[#00d4ff] bg-[#00d4ff]/10 px-1.5 py-0.5 rounded font-medium">
              {data.activeMitigations.length} mitigating
            </span>
          )}
        </div>
      </div>

      {/* Active Alerts */}
      <div className="mb-4">
        <div className="flex items-center gap-1.5 mb-2">
          <AlertTriangle className="w-3.5 h-3.5 text-[#ffbe0b]" />
          <h4 className="text-[11px] text-gray-500 uppercase tracking-wider">Active Alerts</h4>
        </div>
        {!hasAlerts ? (
          <div className="flex items-center gap-2 py-2 px-2 bg-[#00ff88]/5 border border-[#00ff88]/15 rounded-lg">
            <span className="w-2 h-2 rounded-full bg-[#00ff88]" />
            <span className="text-xs text-gray-400">No active alerts — infrastructure nominal</span>
          </div>
        ) : (
          <div className="space-y-1.5">
            {data.alerts.map((alert) => (
              <div
                key={alert.id}
                className="flex items-center justify-between py-2 px-2.5 bg-[#0a0e1a]/50 rounded-lg border border-[#1a2332]"
              >
                <div className="flex items-center gap-2 flex-1 min-w-0">
                  <span
                    className={`text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded border flex-shrink-0 ${severityColor(
                      alert.severity
                    )}`}
                  >
                    {alert.severity}
                  </span>
                  <div className="min-w-0">
                    <span className="text-xs text-gray-300 block truncate">
                      Target: {alert.targetNetwork}
                    </span>
                    <span className="text-[10px] text-gray-500">
                      {formatTimestamp(alert.createdAt)} — {alert.status}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Active Mitigations */}
      {hasMitigations && (
        <div className="mb-4">
          <div className="flex items-center gap-1.5 mb-2">
            <Zap className="w-3.5 h-3.5 text-[#00d4ff]" />
            <h4 className="text-[11px] text-gray-500 uppercase tracking-wider">
              Active Mitigations
            </h4>
          </div>
          <div className="space-y-1.5">
            {data.activeMitigations.map((mit) => (
              <div
                key={mit.id}
                className="flex items-center justify-between py-2 px-2.5 bg-[#00d4ff]/5 border border-[#00d4ff]/15 rounded-lg"
              >
                <div className="flex items-center gap-2 flex-1 min-w-0">
                  <Network className="w-3.5 h-3.5 text-[#00d4ff] flex-shrink-0" />
                  <div className="min-w-0">
                    <span className="text-xs text-gray-300 block truncate">
                      {mit.targetNetwork}
                    </span>
                    <span className="text-[10px] text-gray-500">
                      Since {formatTimestamp(mit.startedAt)}
                    </span>
                  </div>
                </div>
                <span className="text-xs font-mono text-[#00d4ff] flex-shrink-0 ml-2">
                  {mit.mitigatedIps.toLocaleString()} IPs
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Top Volumetric Talkers */}
      {hasTalkers && (
        <div className="pt-3 border-t border-[#1a2332]">
          <div className="flex items-center gap-1.5 mb-2">
            <Zap className="w-3.5 h-3.5 text-[#ff0040]" />
            <h4 className="text-[11px] text-gray-500 uppercase tracking-wider">
              Top Volumetric Talkers
            </h4>
          </div>
          <div className="space-y-0.5">
            <div className="grid grid-cols-3 gap-2 text-[10px] text-gray-500 uppercase tracking-wider pb-1 border-b border-[#1a2332] px-1">
              <span>IP Address</span>
              <span className="text-right">Bandwidth</span>
              <span className="text-right">Packet Rate</span>
            </div>
            {data.topTalkers.map((talker) => (
              <div
                key={talker.ip}
                className="grid grid-cols-3 gap-2 py-1.5 px-1 rounded hover:bg-[#1a2332]/50 transition-colors"
              >
                <span className="text-xs font-mono text-gray-300">{talker.ip}</span>
                <span className="text-xs font-mono text-[#ff0040] text-right">
                  {formatBps(talker.bps)}
                </span>
                <span className="text-xs font-mono text-gray-400 text-right">
                  {formatPps(talker.pps)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
