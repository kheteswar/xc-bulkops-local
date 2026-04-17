import { Globe, AlertCircle } from 'lucide-react';
import type { DNSHealthStatus } from '../../services/live-soc/types';

interface DNSHealthProps {
  data: DNSHealthStatus | null;
}

function statusColor(status: string): string {
  switch (status) {
    case 'healthy':
      return '#00ff88';
    case 'degraded':
      return '#ffbe0b';
    case 'down':
    case 'unhealthy':
      return '#ff0040';
    default:
      return '#6b7280';
  }
}

function statusBgClass(status: string): string {
  switch (status) {
    case 'healthy':
      return 'bg-[#00ff88]/10 border-[#00ff88]/30 text-[#00ff88]';
    case 'degraded':
      return 'bg-[#ffbe0b]/10 border-[#ffbe0b]/30 text-[#ffbe0b]';
    case 'down':
    case 'unhealthy':
      return 'bg-[#ff0040]/10 border-[#ff0040]/30 text-[#ff0040]';
    default:
      return 'bg-gray-500/10 border-gray-500/30 text-gray-400';
  }
}

export default function DNSHealth({ data }: DNSHealthProps) {
  if (!data) {
    return (
      <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
        <div className="flex items-center gap-2 mb-4">
          <Globe className="w-4 h-4 text-[#00d4ff]" />
          <h3 className="text-sm font-semibold text-gray-200">DNS Health</h3>
        </div>
        <div className="flex flex-col items-center justify-center py-12 text-gray-500">
          <Globe className="w-10 h-10 mb-3 opacity-30" />
          <p className="text-sm font-medium text-gray-400">DNS Not Configured</p>
          <p className="text-xs text-gray-600 mt-1">
            No DNS zones or load balancers are monitored in this room
          </p>
        </div>
      </div>
    );
  }

  const totalMembers = data.loadBalancers.reduce(
    (acc, lb) => acc + lb.pools.reduce((a, p) => a + p.members.length, 0),
    0
  );
  const unhealthyMembers = data.loadBalancers.reduce(
    (acc, lb) =>
      acc +
      lb.pools.reduce(
        (a, p) => a + p.members.filter((m) => m.status === 'unhealthy').length,
        0
      ),
    0
  );

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-[#00d4ff]" />
          <h3 className="text-sm font-semibold text-gray-200">DNS Health</h3>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs font-mono text-gray-500">
            {totalMembers - unhealthyMembers}/{totalMembers} healthy
          </span>
          {unhealthyMembers > 0 && (
            <span className="text-[10px] text-[#ff0040] bg-[#ff0040]/10 px-1.5 py-0.5 rounded font-medium">
              {unhealthyMembers} down
            </span>
          )}
        </div>
      </div>

      {/* Query Metrics */}
      {data.queryMetrics && (
        <div className="grid grid-cols-3 gap-3 mb-4">
          <div className="bg-[#0a0e1a]/50 rounded-lg p-2.5 text-center">
            <span className="block text-lg font-bold font-mono text-gray-200">
              {data.queryMetrics.totalQueries.toLocaleString()}
            </span>
            <span className="text-[10px] text-gray-500 uppercase">Total Queries</span>
          </div>
          <div className="bg-[#0a0e1a]/50 rounded-lg p-2.5 text-center">
            <span className="block text-lg font-bold font-mono text-[#ff0040]">
              {data.queryMetrics.errorCount.toLocaleString()}
            </span>
            <span className="text-[10px] text-gray-500 uppercase">Errors</span>
          </div>
          <div className="bg-[#0a0e1a]/50 rounded-lg p-2.5 text-center">
            <span
              className="block text-lg font-bold font-mono"
              style={{
                color:
                  data.queryMetrics.errorRate < 1
                    ? '#00ff88'
                    : data.queryMetrics.errorRate < 5
                      ? '#ffbe0b'
                      : '#ff0040',
              }}
            >
              {data.queryMetrics.errorRate.toFixed(2)}%
            </span>
            <span className="text-[10px] text-gray-500 uppercase">Error Rate</span>
          </div>
        </div>
      )}

      {/* DNS LB Health Grid */}
      <div className="space-y-3">
        {data.loadBalancers.map((lb) => (
          <div key={lb.name} className="bg-[#0a0e1a]/50 rounded-lg p-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-gray-300">{lb.name}</span>
              <span
                className={`text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded border ${statusBgClass(
                  lb.status
                )}`}
              >
                {lb.status}
              </span>
            </div>

            {lb.pools.map((pool) => (
              <div key={pool.name} className="mb-2 last:mb-0">
                <span className="text-[10px] text-gray-500 uppercase tracking-wider">
                  {pool.name}
                </span>
                <div className="flex flex-wrap gap-2 mt-1">
                  {pool.members.map((member) => (
                    <div
                      key={member.address}
                      className="flex items-center gap-1.5 bg-[#1a2332]/70 rounded px-2 py-1"
                      title={`Last change: ${member.lastChangeTime}`}
                    >
                      {/* Status LED */}
                      <span
                        className="inline-block w-2 h-2 rounded-full flex-shrink-0"
                        style={{
                          backgroundColor: statusColor(member.status),
                          boxShadow: `0 0 6px ${statusColor(member.status)}60`,
                        }}
                      />
                      <span className="text-[11px] font-mono text-gray-300">
                        {member.address}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        ))}
      </div>

      {/* Warning if any unhealthy */}
      {unhealthyMembers > 0 && (
        <div className="mt-3 flex items-start gap-2 bg-[#ff0040]/5 border border-[#ff0040]/20 rounded-lg p-2.5">
          <AlertCircle className="w-3.5 h-3.5 text-[#ff0040] flex-shrink-0 mt-0.5" />
          <p className="text-[11px] text-gray-400">
            <span className="text-[#ff0040] font-semibold">{unhealthyMembers}</span> pool member
            {unhealthyMembers > 1 ? 's are' : ' is'} unhealthy. DNS traffic may be routing to
            degraded origins.
          </p>
        </div>
      )}
    </div>
  );
}
