import React, { useState, useMemo } from 'react';
import { Crosshair, Fingerprint, ArrowUpDown } from 'lucide-react';
import type { JA4Cluster } from '../../services/live-soc/types';

interface AttackerEntry {
  ip: string;
  count: number;
  country?: string;
  asn?: string;
}

interface AttackerTableProps {
  attackers: AttackerEntry[];
  ja4Clusters: JA4Cluster[];
}

type SortField = 'ip' | 'count' | 'country' | 'asn';
type SortDirection = 'asc' | 'desc';

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

function getJA4ForIp(ip: string, clusters: JA4Cluster[]): JA4Cluster | undefined {
  return clusters.find((c) => c.ips.includes(ip));
}

function getAttackerType(ip: string, clusters: JA4Cluster[]): string[] {
  const types: string[] = [];
  const cluster = getJA4ForIp(ip, clusters);
  if (cluster && cluster.ips.length > 3) types.push('Coordinated');
  if (cluster?.topUa?.toLowerCase().includes('bot')) types.push('Bot');
  return types;
}

export default function AttackerTable({ attackers, ja4Clusters }: AttackerTableProps) {
  const [sortField, setSortField] = useState<SortField>('count');
  const [sortDir, setSortDir] = useState<SortDirection>('desc');

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  };

  const sortedAttackers = useMemo(() => {
    const sorted = [...attackers].sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case 'ip':
          cmp = a.ip.localeCompare(b.ip);
          break;
        case 'count':
          cmp = a.count - b.count;
          break;
        case 'country':
          cmp = (a.country || '').localeCompare(b.country || '');
          break;
        case 'asn':
          cmp = (a.asn || '').localeCompare(b.asn || '');
          break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return sorted;
  }, [attackers, sortField, sortDir]);

  // JA4 clustering insight
  const uniqueJa4Count = ja4Clusters.length;
  const totalClusteredIps = ja4Clusters.reduce((acc, c) => acc + c.ips.length, 0);
  const hasClusteringInsight = uniqueJa4Count > 0 && totalClusteredIps > uniqueJa4Count * 2;

  const SortHeader = ({
    field,
    children,
    align = 'left',
  }: {
    field: SortField;
    children: React.ReactNode;
    align?: 'left' | 'right';
  }) => (
    <button
      onClick={() => handleSort(field)}
      className={`flex items-center gap-0.5 text-[10px] text-gray-500 uppercase tracking-wider hover:text-gray-300 transition-colors ${
        align === 'right' ? 'justify-end ml-auto' : ''
      }`}
    >
      {children}
      <ArrowUpDown
        className={`w-2.5 h-2.5 ${sortField === field ? 'text-[#00d4ff]' : 'text-gray-600'}`}
      />
    </button>
  );

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Crosshair className="w-4 h-4 text-[#ff0040]" />
          <h3 className="text-sm font-semibold text-gray-200">Top Attackers</h3>
        </div>
        <span className="text-xs font-mono text-gray-500">
          {attackers.length} source{attackers.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* JA4 Clustering Insight */}
      {hasClusteringInsight && (
        <div className="mb-3 flex items-start gap-2 bg-[#a855f7]/8 border border-[#a855f7]/20 rounded-lg p-2.5">
          <Fingerprint className="w-4 h-4 text-[#a855f7] flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-xs text-[#a855f7] font-semibold">JA4 Fingerprint Clustering</p>
            <p className="text-[11px] text-gray-400 mt-0.5">
              {totalClusteredIps} IPs share only{' '}
              <span className="text-gray-200 font-mono">{uniqueJa4Count}</span> JA4 fingerprint
              {uniqueJa4Count > 1 ? 's' : ''} — likely coordinated botnet activity
            </p>
          </div>
        </div>
      )}

      {/* JA4 Cluster Details */}
      {ja4Clusters.length > 0 && (
        <div className="mb-3 flex flex-wrap gap-2">
          {ja4Clusters.slice(0, 5).map((cluster) => (
            <div
              key={cluster.fingerprint}
              className="bg-[#1a2332]/70 border border-[#1a2332] rounded-lg px-2.5 py-1.5"
            >
              <div className="flex items-center gap-1.5">
                <Fingerprint className="w-3 h-3 text-[#a855f7]" />
                <span className="text-[10px] font-mono text-gray-300 truncate max-w-[120px]">
                  {cluster.fingerprint}
                </span>
              </div>
              <div className="flex items-center gap-2 mt-0.5">
                <span className="text-[10px] text-gray-500">
                  {cluster.ips.length} IPs
                </span>
                <span className="text-[10px] text-gray-500">
                  {formatNumber(cluster.count)} hits
                </span>
              </div>
              {cluster.topUa && (
                <p className="text-[9px] text-gray-600 truncate max-w-[200px] mt-0.5">
                  UA: {cluster.topUa}
                </p>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Attacker Table */}
      {attackers.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-8 text-gray-500">
          <Crosshair className="w-8 h-8 mb-2 opacity-30" />
          <p className="text-xs">No attacking sources detected</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1a2332]">
                <th className="text-left py-1.5 pr-2">
                  <SortHeader field="ip">IP Address</SortHeader>
                </th>
                <th className="text-left py-1.5 pr-2">
                  <SortHeader field="country">Country</SortHeader>
                </th>
                <th className="text-left py-1.5 pr-2">
                  <SortHeader field="asn">ASN</SortHeader>
                </th>
                <th className="text-right py-1.5 pr-2">
                  <SortHeader field="count" align="right">Events</SortHeader>
                </th>
                <th className="text-left py-1.5 pr-2">
                  <span className="text-[10px] text-gray-500 uppercase tracking-wider">JA4</span>
                </th>
                <th className="text-left py-1.5">
                  <span className="text-[10px] text-gray-500 uppercase tracking-wider">Type</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {sortedAttackers.map((attacker) => {
                const ja4Cluster = getJA4ForIp(attacker.ip, ja4Clusters);
                const types = getAttackerType(attacker.ip, ja4Clusters);
                const maxCount = sortedAttackers[0]?.count || 1;
                const intensity = Math.min(attacker.count / maxCount, 1);

                return (
                  <tr
                    key={attacker.ip}
                    className="border-b border-[#1a2332]/50 hover:bg-[#1a2332]/30 transition-colors"
                    style={{
                      backgroundColor: `rgba(255, 0, 64, ${intensity * 0.05})`,
                    }}
                  >
                    <td className="py-1.5 pr-2">
                      <span className="text-xs font-mono text-gray-300">{attacker.ip}</span>
                    </td>
                    <td className="py-1.5 pr-2">
                      <span className="text-xs text-gray-400">{attacker.country || '—'}</span>
                    </td>
                    <td className="py-1.5 pr-2">
                      <span className="text-xs text-gray-400 truncate max-w-[100px] inline-block">
                        {attacker.asn || '—'}
                      </span>
                    </td>
                    <td className="py-1.5 pr-2 text-right">
                      <span className="text-xs font-mono text-[#ff0040] font-medium">
                        {formatNumber(attacker.count)}
                      </span>
                    </td>
                    <td className="py-1.5 pr-2">
                      {ja4Cluster ? (
                        <span className="text-[10px] font-mono text-[#a855f7] truncate max-w-[80px] inline-block">
                          {ja4Cluster.fingerprint.substring(0, 12)}...
                        </span>
                      ) : (
                        <span className="text-[10px] text-gray-600">—</span>
                      )}
                    </td>
                    <td className="py-1.5">
                      <div className="flex gap-1">
                        {types.map((type) => (
                          <span
                            key={type}
                            className="text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded bg-[#ff0040]/10 text-[#ff0040] border border-[#ff0040]/20"
                          >
                            {type}
                          </span>
                        ))}
                        {ja4Cluster && ja4Cluster.ips.length > 5 && (
                          <span className="text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded bg-[#a855f7]/10 text-[#a855f7] border border-[#a855f7]/20">
                            Multi-Vector
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
