import { useMemo } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import { Activity, ShieldCheck, Clock, AlertTriangle } from 'lucide-react';
import type { SyntheticHealthSummary } from '../../services/live-soc/types';

interface SyntheticHealthProps {
  data: SyntheticHealthSummary | null;
}

function statusLedColor(status: string): string {
  switch (status) {
    case 'healthy':
      return '#00ff88';
    case 'unhealthy':
      return '#ff0040';
    default:
      return '#6b7280';
  }
}

function certStatusColor(status: string): string {
  switch (status) {
    case 'ok':
      return 'text-[#00ff88]';
    case 'warning':
      return 'text-[#ffbe0b]';
    case 'critical':
      return 'text-[#ff0040]';
    default:
      return 'text-gray-400';
  }
}

function certBadgeClass(status: string): string {
  switch (status) {
    case 'ok':
      return 'bg-[#00ff88]/10 border-[#00ff88]/30 text-[#00ff88]';
    case 'warning':
      return 'bg-[#ffbe0b]/10 border-[#ffbe0b]/30 text-[#ffbe0b]';
    case 'critical':
      return 'bg-[#ff0040]/10 border-[#ff0040]/30 text-[#ff0040]';
    default:
      return 'bg-gray-400/10 border-gray-400/30 text-gray-400';
  }
}

function formatTime(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch {
    return ts;
  }
}

function getAvailabilityColor(pct: number): string {
  if (pct >= 99.5) return '#00ff88';
  if (pct >= 95) return '#ffbe0b';
  return '#ff0040';
}

export default function SyntheticHealth({ data }: SyntheticHealthProps) {
  if (!data) {
    return (
      <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
        <div className="flex items-center gap-2 mb-4">
          <Activity className="w-4 h-4 text-[#00ff88]" />
          <h3 className="text-sm font-semibold text-gray-200">Synthetic Monitoring</h3>
        </div>
        <div className="flex flex-col items-center justify-center py-12 text-gray-500">
          <Activity className="w-10 h-10 mb-3 opacity-30" />
          <p className="text-sm font-medium text-gray-400">Synthetic Monitors Not Configured</p>
          <p className="text-xs text-gray-600 mt-1">
            Configure synthetic monitors to track external availability
          </p>
        </div>
      </div>
    );
  }

  const healthyCount = data.monitors.filter((m) => m.status === 'healthy').length;
  const unhealthyCount = data.monitors.filter((m) => m.status === 'unhealthy').length;
  const availColor = getAvailabilityColor(data.globalAvailabilityPct);

  const gaugeData = useMemo(
    () => [
      { name: 'Available', value: data.globalAvailabilityPct },
      { name: 'Unavailable', value: 100 - data.globalAvailabilityPct },
    ],
    [data.globalAvailabilityPct]
  );

  const expiringCerts = data.tlsCerts.filter((c) => c.status !== 'ok');

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-[#00ff88]" />
          <h3 className="text-sm font-semibold text-gray-200">Synthetic Monitoring</h3>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-[#00ff88] bg-[#00ff88]/10 px-1.5 py-0.5 rounded font-medium">
            {healthyCount} up
          </span>
          {unhealthyCount > 0 && (
            <span className="text-[10px] text-[#ff0040] bg-[#ff0040]/10 px-1.5 py-0.5 rounded font-medium">
              {unhealthyCount} down
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Global Availability Gauge */}
        <div className="flex flex-col items-center">
          <h4 className="text-[11px] text-gray-500 uppercase tracking-wider mb-2">
            Global Availability
          </h4>
          <div className="relative w-32 h-20">
            <ResponsiveContainer width="100%" height={80}>
              <PieChart>
                <Pie
                  data={gaugeData}
                  cx="50%"
                  cy="100%"
                  startAngle={180}
                  endAngle={0}
                  innerRadius={42}
                  outerRadius={58}
                  paddingAngle={1}
                  dataKey="value"
                  stroke="none"
                >
                  <Cell fill={availColor} />
                  <Cell fill="#1a2332" />
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-x-0 bottom-0 flex flex-col items-center">
              <span className="text-xl font-bold font-mono" style={{ color: availColor }}>
                {data.globalAvailabilityPct.toFixed(1)}%
              </span>
            </div>
          </div>
        </div>

        {/* Monitor Grid */}
        <div className="lg:col-span-2">
          <h4 className="text-[11px] text-gray-500 uppercase tracking-wider mb-2">
            Monitor Status
          </h4>
          <div className="space-y-0.5">
            <div className="grid grid-cols-[1fr_auto_auto_auto_auto] gap-2 text-[10px] text-gray-500 uppercase tracking-wider pb-1 border-b border-[#1a2332] px-1">
              <span>Name</span>
              <span>Type</span>
              <span className="text-center">Status</span>
              <span className="text-right">Avail</span>
              <span className="text-right">Checked</span>
            </div>
            {data.monitors.map((monitor) => (
              <div
                key={monitor.name}
                className="grid grid-cols-[1fr_auto_auto_auto_auto] gap-2 py-1.5 px-1 rounded hover:bg-[#1a2332]/50 transition-colors"
              >
                <span className="text-xs text-gray-300 truncate">{monitor.name}</span>
                <span className="text-[10px] font-mono text-gray-500 uppercase w-8 text-center">
                  {monitor.type}
                </span>
                <span className="flex items-center justify-center">
                  <span
                    className="inline-block w-2.5 h-2.5 rounded-full"
                    style={{
                      backgroundColor: statusLedColor(monitor.status),
                      boxShadow: `0 0 6px ${statusLedColor(monitor.status)}60`,
                    }}
                  />
                </span>
                <span
                  className="text-xs font-mono text-right"
                  style={{ color: getAvailabilityColor(monitor.availabilityPct) }}
                >
                  {monitor.availabilityPct.toFixed(1)}%
                </span>
                <span className="text-[10px] font-mono text-gray-500 text-right">
                  {formatTime(monitor.lastCheckTime)}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* TLS Cert Expiry Warnings */}
      {data.tlsCerts.length > 0 && (
        <div className="mt-4 pt-4 border-t border-[#1a2332]">
          <div className="flex items-center gap-1.5 mb-2">
            <ShieldCheck className="w-3.5 h-3.5 text-gray-400" />
            <h4 className="text-[11px] text-gray-500 uppercase tracking-wider">
              TLS Certificate Status
            </h4>
          </div>
          <div className="space-y-1">
            {data.tlsCerts.map((cert) => (
              <div
                key={cert.domain}
                className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-[#1a2332]/50 transition-colors"
              >
                <div className="flex items-center gap-2">
                  {cert.status !== 'ok' && (
                    <AlertTriangle className={`w-3.5 h-3.5 flex-shrink-0 ${certStatusColor(cert.status)}`} />
                  )}
                  <span className="text-xs font-mono text-gray-300">{cert.domain}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`text-xs font-mono ${certStatusColor(cert.status)}`}>
                    {cert.daysUntilExpiry}d
                  </span>
                  <span
                    className={`text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded border ${certBadgeClass(
                      cert.status
                    )}`}
                  >
                    {cert.status === 'ok'
                      ? 'Valid'
                      : cert.status === 'warning'
                        ? 'Expiring'
                        : 'Critical'}
                  </span>
                </div>
              </div>
            ))}
          </div>

          {expiringCerts.length > 0 && (
            <div className="mt-2 flex items-start gap-2 bg-[#ffbe0b]/5 border border-[#ffbe0b]/15 rounded-lg p-2.5">
              <Clock className="w-3.5 h-3.5 text-[#ffbe0b] flex-shrink-0 mt-0.5" />
              <p className="text-[11px] text-gray-400">
                <span className="text-[#ffbe0b] font-semibold">{expiringCerts.length}</span>{' '}
                certificate{expiringCerts.length > 1 ? 's' : ''} need{expiringCerts.length === 1 ? 's' : ''}{' '}
                attention. Renew before expiry to avoid service disruption.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
