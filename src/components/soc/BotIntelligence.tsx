import { useMemo } from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis } from 'recharts';
import { Bot, ShieldAlert, Skull, Users, Lock } from 'lucide-react';
import type { BotTrafficOverview } from '../../services/live-soc/types';

interface BotIntelligenceProps {
  data: BotTrafficOverview | null;
}

const DONUT_COLORS = {
  human: '#00ff88',
  goodBot: '#00d4ff',
  malicious: '#ff0040',
};

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

interface DonutTooltipProps {
  active?: boolean;
  payload?: Array<{ payload: { name: string; value: number; pct: number } }>;
}

function DonutTooltip({ active, payload }: DonutTooltipProps) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div className="bg-[#0f1423]/95 backdrop-blur-xl border border-[#1a2332] rounded-lg px-3 py-2 shadow-xl">
      <p className="text-xs font-medium text-gray-200">{d.name}</p>
      <p className="text-[11px] text-gray-400 mt-0.5">
        {d.pct.toFixed(1)}% ({formatNumber(d.value)} reqs)
      </p>
    </div>
  );
}

export default function BotIntelligence({ data }: BotIntelligenceProps) {
  if (!data) {
    return (
      <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
        <div className="flex items-center gap-2 mb-4">
          <Bot className="w-4 h-4 text-[#a855f7]" />
          <h3 className="text-sm font-semibold text-gray-200">Bot Intelligence</h3>
        </div>
        <div className="flex flex-col items-center justify-center py-12 text-gray-500">
          <Bot className="w-10 h-10 mb-3 opacity-30" />
          <p className="text-sm font-medium text-gray-400">Bot Defense Not Enabled</p>
          <p className="text-xs text-gray-600 mt-1">
            Enable Bot Defense on the load balancer to see bot analytics
          </p>
        </div>
      </div>
    );
  }

  const donutData = useMemo(
    () => [
      { name: 'Human', value: Math.round(data.totalRequests * data.humanPct / 100), pct: data.humanPct, color: DONUT_COLORS.human },
      { name: 'Good Bots', value: Math.round(data.totalRequests * data.goodBotPct / 100), pct: data.goodBotPct, color: DONUT_COLORS.goodBot },
      { name: 'Malicious', value: Math.round(data.totalRequests * data.maliciousBotPct / 100), pct: data.maliciousBotPct, color: DONUT_COLORS.malicious },
    ],
    [data]
  );

  const attackIntentMax = useMemo(
    () => Math.max(...data.attackIntent.map((a) => a.count), 1),
    [data.attackIntent]
  );

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Bot className="w-4 h-4 text-[#a855f7]" />
          <h3 className="text-sm font-semibold text-gray-200">Bot Intelligence</h3>
        </div>
        <span className="text-xs font-mono text-gray-500">
          {formatNumber(data.totalRequests)} requests
        </span>
      </div>

      {/* Credential Stuffing Alert */}
      {data.credentialStuffingDetected && (
        <div className="mb-4 flex items-start gap-2 bg-[#ff0040]/10 border border-[#ff0040]/30 rounded-lg p-3 animate-pulse">
          <Lock className="w-4 h-4 text-[#ff0040] flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-xs font-bold text-[#ff0040] uppercase tracking-wider">
              Credential Stuffing Detected
            </p>
            <p className="text-[11px] text-gray-400 mt-0.5">
              Automated credential testing in progress. Review affected endpoints immediately.
            </p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Traffic Donut */}
        <div>
          <h4 className="text-[11px] text-gray-500 uppercase tracking-wider mb-2">
            Traffic Classification
          </h4>
          <div className="relative">
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie
                  data={donutData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={72}
                  paddingAngle={2}
                  dataKey="value"
                  nameKey="name"
                  stroke="none"
                >
                  {donutData.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip content={<DonutTooltip />} />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
              <div className="text-center">
                <Users className="w-4 h-4 text-gray-500 mx-auto mb-0.5" />
                <span className="block text-[10px] text-gray-500">Traffic</span>
              </div>
            </div>
          </div>

          {/* Legend */}
          <div className="flex justify-center gap-4 mt-1">
            {donutData.map((entry) => (
              <div key={entry.name} className="flex items-center gap-1.5">
                <span
                  className="inline-block w-2 h-2 rounded-full"
                  style={{ backgroundColor: entry.color }}
                />
                <span className="text-[11px] text-gray-400">
                  {entry.name}{' '}
                  <span className="font-mono text-gray-300">{entry.pct.toFixed(1)}%</span>
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Attack Intent Breakdown */}
        <div>
          <h4 className="text-[11px] text-gray-500 uppercase tracking-wider mb-2">
            Attack Intent
          </h4>
          {data.attackIntent.length === 0 ? (
            <p className="text-xs text-gray-600 italic py-4">No attack intents detected</p>
          ) : (
            <div className="space-y-1.5">
              {data.attackIntent.map((intent) => {
                const barPct = (intent.count / attackIntentMax) * 100;
                return (
                  <div key={intent.intent}>
                    <div className="flex items-center justify-between mb-0.5">
                      <span className="text-[11px] text-gray-400 truncate max-w-[150px]">
                        {intent.intent}
                      </span>
                      <span className="text-[11px] font-mono text-gray-300 ml-2">
                        {formatNumber(intent.count)}
                        <span className="text-gray-600 ml-1">({intent.pct.toFixed(1)}%)</span>
                      </span>
                    </div>
                    <div className="w-full h-2 bg-[#1a2332] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full bg-[#a855f7] transition-all duration-500"
                        style={{ width: `${barPct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Bottom Row: Top Malicious IPs + Mitigation */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mt-4 pt-4 border-t border-[#1a2332]">
        {/* Top Malicious IPs */}
        <div>
          <div className="flex items-center gap-1.5 mb-2">
            <Skull className="w-3.5 h-3.5 text-[#ff0040]" />
            <h4 className="text-[11px] text-gray-500 uppercase tracking-wider">
              Top Malicious IPs
            </h4>
          </div>
          {data.topMaliciousIps.length === 0 ? (
            <p className="text-xs text-gray-600 italic">No malicious IPs identified</p>
          ) : (
            <div className="space-y-0.5">
              {data.topMaliciousIps.slice(0, 8).map((ip, i) => (
                <div
                  key={ip.ip}
                  className="flex items-center justify-between py-1 px-1 rounded hover:bg-[#1a2332]/50 transition-colors"
                >
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-gray-600 font-mono w-4">{i + 1}</span>
                    <span className="text-xs font-mono text-gray-300">{ip.ip}</span>
                  </div>
                  <span className="text-xs font-mono text-[#ff0040]">
                    {formatNumber(ip.count)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Mitigation Effectiveness */}
        <div>
          <div className="flex items-center gap-1.5 mb-2">
            <ShieldAlert className="w-3.5 h-3.5 text-[#00d4ff]" />
            <h4 className="text-[11px] text-gray-500 uppercase tracking-wider">
              Mitigation Actions
            </h4>
          </div>
          {data.mitigationActions.length === 0 ? (
            <p className="text-xs text-gray-600 italic">No mitigation data</p>
          ) : (
            <>
              <div className="h-28">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={data.mitigationActions} layout="vertical" barCategoryGap="30%">
                    <XAxis
                      type="number"
                      tick={{ fill: '#6b7280', fontSize: 10 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <YAxis
                      type="category"
                      dataKey="action"
                      width={70}
                      tick={{ fill: '#9ca3af', fontSize: 10 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Bar
                      dataKey="count"
                      radius={[0, 4, 4, 0]}
                      fill="#00d4ff"
                    />
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div className="flex flex-wrap gap-2 mt-2">
                {data.mitigationActions.map((action) => {
                  const actionColor =
                    action.action.toLowerCase().includes('block')
                      ? '#ff0040'
                      : action.action.toLowerCase().includes('challenge')
                        ? '#ffbe0b'
                        : '#00ff88';
                  return (
                    <div
                      key={action.action}
                      className="flex items-center gap-1.5 bg-[#1a2332] rounded px-2 py-1"
                    >
                      <span
                        className="w-1.5 h-1.5 rounded-full"
                        style={{ backgroundColor: actionColor }}
                      />
                      <span className="text-[10px] text-gray-400">{action.action}</span>
                      <span className="text-[10px] font-mono text-gray-300">{action.pct.toFixed(1)}%</span>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
