// ═══════════════════════════════════════════════════════════════════════════
// Log Analyzer — General-purpose access log analytics dashboard
// ═══════════════════════════════════════════════════════════════════════════

import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowLeft, BarChart2, Loader2, Play, Search, ExternalLink,
  ChevronDown, ChevronUp, Plus, X, Download,
  Hash, Type, Filter, Table, FileJson, FileSpreadsheet,
  AlertTriangle, Zap, Shield, Users, HelpCircle,
} from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip as RTooltip, ResponsiveContainer, Cell,
} from 'recharts';
import { apiClient } from '../services/api';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import { ConnectionPanel } from '../components/ConnectionPanel';
import type { Namespace } from '../types';
import {
  type TimePeriod, type LogSource, type QueryFilter, type ClientFilter,
  type LogCollectionProgress, type NumericFieldStats, type StringFieldStats,
  type LogSummary, type AccessLogEntry, type BreakdownResult,
  type ErrorAnalysis, type PerformanceAnalysis, type SecurityInsights,
  type TopTalker, type StatusTimeSeriesPoint, type AggregatedLogData,
  TIME_PERIOD_HOURS, TIME_PERIOD_LABELS,
  FIELD_DEFINITIONS, PRE_FETCH_FILTER_FIELDS, FIELD_GROUP_LABELS, getFieldsForSource,
  collectWithAggregations, buildQuery, probeLogs,
  computeNumericStats, computeStringStats, computeBooleanStats,
  computeBreakdown, resolveField,
  computeSummary, applyClientFilters,
  computeErrorAnalysis, computePerformanceAnalysis,
  computeSecurityInsights, computeTopTalkers, buildStatusTimeSeries,
  buildStringStatsFromBuckets, buildSummaryFromAggregations,
  buildErrorAnalysisFromAgg, buildSecurityInsightsFromAgg,
  buildTopTalkersFromAgg, buildStatusTimeSeriesFromAgg,
  exportAsJSON, exportAsCSV,
  exportBreakdownAsCSV, exportBreakdownAsExcel, exportBreakdownAsPDF,
} from '../services/log-analyzer';

// ═══════════════════════════════════════════════════════════════════
// INLINE COMPONENTS
// ═══════════════════════════════════════════════════════════════════

function SearchableSelect({ label, options, value, onChange, placeholder, disabled }: {
  label: string;
  options: Array<{ value: string; label: string }>;
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  disabled?: boolean;
}) {
  const [isOpen, setIsOpen] = useState(false);
  const [filter, setFilter] = useState('');
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setIsOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const filtered = options.filter(o => o.label.toLowerCase().includes(filter.toLowerCase()));

  return (
    <div ref={ref} className="relative">
      <label className="block text-xs font-medium text-slate-400 mb-1">{label}</label>
      <button
        onClick={() => !disabled && setIsOpen(!isOpen)}
        disabled={disabled}
        className="w-full flex items-center justify-between px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-sm text-slate-200 hover:border-slate-500 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        <span className={value ? 'text-slate-200' : 'text-slate-500'}>
          {value ? options.find(o => o.value === value)?.label || value : placeholder}
        </span>
        <ChevronDown className="w-4 h-4 text-slate-400" />
      </button>
      {isOpen && (
        <div className="absolute z-50 mt-1 w-full bg-slate-800 border border-slate-600 rounded-lg shadow-xl max-h-60 overflow-hidden">
          <div className="p-2 border-b border-slate-700">
            <div className="flex items-center gap-2 px-2 py-1 bg-slate-900 rounded">
              <Search className="w-3 h-3 text-slate-500" />
              <input type="text" value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter..."
                className="bg-transparent text-sm text-slate-200 outline-none w-full" autoFocus />
            </div>
          </div>
          <div className="max-h-48 overflow-y-auto">
            {filtered.map(o => (
              <button key={o.value} onClick={() => { onChange(o.value); setIsOpen(false); setFilter(''); }}
                className={`w-full text-left px-3 py-2 text-sm hover:bg-slate-700 ${o.value === value ? 'bg-slate-700 text-blue-400' : 'text-slate-300'}`}>
                {o.label}
              </button>
            ))}
            {filtered.length === 0 && <div className="px-3 py-4 text-sm text-slate-500 text-center">No matches</div>}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Distribution Section (reusable for Common / Access / Security field groups) ──
function DistributionSection({ title, subtitle, accent, distributions, onFilter, onDrillDown }: {
  title: string;
  subtitle: string;
  accent: 'blue' | 'cyan' | 'red';
  distributions: Array<{ key: string; label: string; group: string; uniqueCount: number; totalCount: number; topValues: Array<{ value: string; count: number; pct: number }> }>;
  onFilter: (field: string, value: string) => void;
  onDrillDown: (fieldKey: string) => void;
}) {
  const accentColors = {
    blue: { border: 'border-blue-500/20', bar: 'bg-blue-500/70', tag: 'bg-blue-500/10 text-blue-400', hdr: 'text-blue-400' },
    cyan: { border: 'border-cyan-500/20', bar: 'bg-cyan-500/70', tag: 'bg-cyan-500/10 text-cyan-400', hdr: 'text-cyan-400' },
    red: { border: 'border-red-500/20', bar: 'bg-red-500/70', tag: 'bg-red-500/10 text-red-400', hdr: 'text-red-400' },
  }[accent];

  // Group distributions by their field group for sub-headers
  const grouped = new Map<string, typeof distributions>();
  for (const dist of distributions) {
    const g = dist.group;
    if (!grouped.has(g)) grouped.set(g, []);
    grouped.get(g)!.push(dist);
  }

  return (
    <div className="mb-6">
      <div className={`flex items-center gap-2 mb-3 mt-2 pb-2 border-b ${accentColors.border}`}>
        <h3 className={`text-sm font-semibold ${accentColors.hdr}`}>{title}</h3>
        <span className="text-xs text-slate-500">{subtitle}</span>
      </div>
      {[...grouped.entries()].map(([group, groupDists]) => (
        <div key={group} className="mb-4">
          <div className="flex items-center gap-2 mb-2">
            <span className={`text-[11px] font-semibold ${accentColors.hdr} opacity-70`}>{FIELD_GROUP_LABELS[group] || group}</span>
            <div className="flex-1 border-t border-slate-700/50" />
            <span className="text-[10px] text-slate-600">{groupDists.length} fields</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {groupDists.map(dist => (
              <div key={dist.key} className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <button
                    onClick={() => onDrillDown(dist.key)}
                    className="text-xs font-semibold text-slate-400 truncate hover:text-blue-400 transition-colors flex items-center gap-1 max-w-[60%]"
                    title={`${dist.label} (${dist.key}) — click to view all ${dist.uniqueCount} values in Field Analysis`}
                  >
                    {dist.label}
                    <ExternalLink className="w-3 h-3 opacity-50" />
                  </button>
                  <button
                    onClick={() => onDrillDown(dist.key)}
                    className="text-[10px] text-slate-600 hover:text-blue-400 transition-colors cursor-pointer shrink-0"
                    title={`${dist.key} — ${dist.uniqueCount} unique values, ${dist.totalCount} total`}
                  >
                    {dist.uniqueCount} unique →
                  </button>
                </div>
            {dist.topValues.map((tv, i) => (
              <button
                key={i}
                onClick={() => onFilter(dist.key, tv.value)}
                className="flex items-center justify-between py-1 px-1.5 -mx-1.5 rounded hover:bg-blue-500/10 group transition-colors w-full text-left"
                title={`Filter: ${dist.label} = "${tv.value}"`}
              >
                <div className="flex items-center gap-1 truncate max-w-[55%]">
                  <Filter className="w-3 h-3 text-slate-600 group-hover:text-blue-400 shrink-0 transition-colors" />
                  <span className="text-xs text-slate-300 group-hover:text-blue-400 font-mono truncate transition-colors" title={tv.value}>{tv.value}</span>
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  <div className="w-16 bg-slate-700 rounded-full h-1">
                    <div className={`h-1 rounded-full ${accentColors.bar}`} style={{ width: `${Math.min(tv.pct, 100)}%` }} />
                  </div>
                  <span className="text-[10px] text-slate-500 w-14 text-right">{tv.count.toLocaleString()} <span className="text-slate-600">({tv.pct.toFixed(0)}%)</span></span>
                </div>
              </button>
            ))}
            {dist.uniqueCount > 10 && (
              <button
                onClick={() => onDrillDown(dist.key)}
                className="w-full mt-2 py-1.5 text-[10px] text-slate-500 hover:text-blue-400 hover:bg-blue-500/5 rounded transition-colors text-center"
              >
                View all {dist.uniqueCount} values →
              </button>
            )}
          </div>
        ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
      <div className="text-xs text-slate-400 mb-1">{label}</div>
      <div className={`text-xl font-bold ${color || 'text-slate-100'}`}>{typeof value === 'number' ? value.toLocaleString() : value}</div>
      {sub && <div className="text-xs text-slate-500 mt-1">{sub}</div>}
    </div>
  );
}

function MiniTable({ headers, rows, onRowClick }: {
  headers: string[];
  rows: Array<Array<string | number>>;
  onRowClick?: (row: Array<string | number>) => void;
}) {
  return (
    <div className="overflow-auto max-h-[400px]">
      <table className="w-full text-xs">
        <thead className="sticky top-0 bg-slate-800">
          <tr>{headers.map((h, i) => <th key={i} className={`py-2 px-3 text-slate-400 font-medium ${i === 0 ? 'text-left' : 'text-right'}`}>{h}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className={`border-t border-slate-700/50 hover:bg-slate-700/30 ${onRowClick ? 'cursor-pointer' : ''}`}
              onClick={() => onRowClick?.(row)}>
              {row.map((cell, j) => (
                <td key={j} className={`py-1.5 px-3 ${j === 0 ? 'text-left text-slate-200 font-mono break-all max-w-[250px]' : 'text-right text-slate-300 whitespace-nowrap'}`}
                  title={typeof cell === 'number' ? (Number.isInteger(cell) ? cell.toLocaleString() : cell.toFixed(2)) : String(cell ?? '')}>
                  {typeof cell === 'number' ? (Number.isInteger(cell) ? cell.toLocaleString() : cell.toFixed(1)) : cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function BreakdownMultiSelect({ groupedFields, groupLabels, selected, onChange, excludeField }: {
  groupedFields: Record<string, Array<{ key: string; label: string; type: string }>>;
  groupLabels: Record<string, string>;
  selected: string[];
  onChange: (v: string[]) => void;
  excludeField: string;
}) {
  const [isOpen, setIsOpen] = useState(false);
  const [filter, setFilter] = useState('');
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setIsOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const toggle = (key: string) => {
    if (selected.includes(key)) onChange(selected.filter(k => k !== key));
    else onChange([...selected, key]);
  };

  return (
    <div ref={ref} className="relative">
      <button onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between px-3 py-2 bg-slate-900 border border-slate-600 rounded-lg text-sm text-slate-200 hover:border-slate-500">
        <span className={selected.length > 0 ? 'text-slate-200' : 'text-slate-500'}>
          {selected.length > 0 ? `${selected.length} field${selected.length > 1 ? 's' : ''} selected` : 'Select breakdown fields...'}
        </span>
        <ChevronDown className="w-4 h-4 text-slate-400" />
      </button>
      {isOpen && (
        <div className="absolute z-50 mt-1 w-full bg-slate-800 border border-slate-600 rounded-lg shadow-xl max-h-72 overflow-hidden">
          <div className="p-2 border-b border-slate-700">
            <div className="flex items-center gap-2 px-2 py-1 bg-slate-900 rounded">
              <Search className="w-3 h-3 text-slate-500" />
              <input type="text" value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter fields..."
                className="bg-transparent text-sm text-slate-200 outline-none w-full" autoFocus />
            </div>
          </div>
          <div className="max-h-56 overflow-y-auto">
            {Object.entries(groupedFields).map(([group, fields]) => {
              const filtered = fields.filter(f =>
                f.key !== excludeField && f.label.toLowerCase().includes(filter.toLowerCase())
              );
              if (filtered.length === 0) return null;
              return (
                <div key={group}>
                  <div className="px-3 py-1 text-[10px] font-semibold text-slate-500 uppercase bg-slate-900/50">{groupLabels[group] || group}</div>
                  {filtered.map(f => (
                    <button key={f.key} onClick={() => toggle(f.key)}
                      className={`w-full text-left px-3 py-1.5 text-sm flex items-center gap-2 hover:bg-slate-700 ${selected.includes(f.key) ? 'text-blue-400' : 'text-slate-300'}`}>
                      <div className={`w-3.5 h-3.5 rounded border flex items-center justify-center ${selected.includes(f.key) ? 'bg-blue-600 border-blue-600' : 'border-slate-500'}`}>
                        {selected.includes(f.key) && <span className="text-white text-[10px]">&#10003;</span>}
                      </div>
                      {f.label}
                    </button>
                  ))}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

function BreakdownRow({ entry, breakdownFields, isExpanded, onToggle }: {
  entry: import('../services/log-analyzer/types').BreakdownEntry;
  breakdownFields: Array<{ key: string; label: string }>;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  return (
    <>
      <tr className="border-t border-slate-700/50 hover:bg-slate-700/30 cursor-pointer" onClick={onToggle}>
        <td className="py-1.5 px-3 text-slate-500">
          {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </td>
        <td className="py-1.5 px-3 text-slate-200 font-mono text-xs break-all">{entry.primaryValue}</td>
        <td className="py-1.5 px-3 text-right text-slate-300 font-medium">{entry.primaryCount.toLocaleString()}</td>
        {breakdownFields.map(bf => (
          <td key={bf.key} className="py-1.5 px-3 text-right text-slate-400">{entry.breakdowns[bf.key]?.length ?? 0}</td>
        ))}
      </tr>
      {isExpanded && (
        <tr>
          <td colSpan={3 + breakdownFields.length} className="p-0">
            <div className="bg-slate-900/60 px-6 py-3 border-y border-slate-700/30">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {breakdownFields.map(bf => {
                  const subs = entry.breakdowns[bf.key] || [];
                  return (
                    <div key={bf.key}>
                      <div className="text-xs font-medium text-slate-400 mb-1.5">{bf.label} <span className="text-slate-600">({subs.length} unique)</span></div>
                      <div className="overflow-auto max-h-[250px]">
                        <table className="w-full text-xs">
                          <thead className="sticky top-0 bg-slate-900">
                            <tr><th className="text-left py-1 px-2 text-slate-500">Value</th><th className="text-right py-1 px-2 text-slate-500">Count</th></tr>
                          </thead>
                          <tbody>
                            {subs.slice(0, 30).map((s, i) => (
                              <tr key={i} className="border-t border-slate-800 hover:bg-slate-800/50">
                                <td className="py-0.5 px-2 text-slate-300 font-mono break-all">{s.value}</td>
                                <td className="py-0.5 px-2 text-right text-slate-400">{s.count.toLocaleString()}</td>
                              </tr>
                            ))}
                            {subs.length > 30 && (
                              <tr><td colSpan={2} className="py-1 px-2 text-center text-slate-600 text-[10px]">...and {subs.length - 30} more</td></tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

const BAR_COLORS = [
  '#3b82f6', '#8b5cf6', '#06b6d4', '#10b981', '#f59e0b',
  '#ef4444', '#ec4899', '#6366f1', '#14b8a6', '#f97316',
  '#84cc16', '#a855f7', '#22d3ee', '#34d399', '#fbbf24',
  '#f87171', '#fb7185', '#818cf8', '#2dd4bf', '#fb923c',
];

const STATUS_COLORS: Record<string, string> = {
  '2xx': '#10b981', '3xx': '#3b82f6', '4xx': '#f59e0b', '5xx': '#ef4444', other: '#6b7280',
};

type InsightTab = 'overview' | 'errors' | 'performance' | 'security' | 'top-talkers' | 'field-analysis';

// ═══════════════════════════════════════════════════════════════════
// MAIN COMPONENT
// ═══════════════════════════════════════════════════════════════════

export function LogAnalyzer() {
  const { isConnected } = useApp();
  const toast = useToast();

  // ── Config ─────────────────────────────────────────────────────
  const [namespaces, setNamespaces] = useState<Namespace[]>([]);
  const [selectedNs, setSelectedNs] = useState('');
  const [loadBalancers, setLoadBalancers] = useState<{ name: string }[]>([]);
  const [selectedLb, setSelectedLb] = useState('');
  const [timePeriod, setTimePeriod] = useState<TimePeriod>('24h');
  const [logSource, setLogSource] = useState<LogSource>('access');
  const [preFetchFilters, setPreFetchFilters] = useState<QueryFilter[]>([]);
  const [clientFilters, setClientFilters] = useState<ClientFilter[]>([]);
  const [showClientFilters, setShowClientFilters] = useState(false);
  const [newFilterField, setNewFilterField] = useState('');
  const [newFilterValue, setNewFilterValue] = useState('');
  const [newCfField, setNewCfField] = useState('');
  const [newCfOp, setNewCfOp] = useState<ClientFilter['operator']>('equals');
  const [newCfValue, setNewCfValue] = useState('');

  // ── Data ───────────────────────────────────────────────────────
  const [logs, setLogs] = useState<AccessLogEntry[]>([]);
  const [aggData, setAggData] = useState<AggregatedLogData | null>(null);
  const [summary, setSummary] = useState<LogSummary | null>(null);
  const [statusTimeSeries, setStatusTimeSeries] = useState<StatusTimeSeriesPoint[]>([]);

  // ── Insights ───────────────────────────────────────────────────
  const [activeTab, setActiveTab] = useState<InsightTab>('overview');
  const [errorAnalysis, setErrorAnalysis] = useState<ErrorAnalysis | null>(null);
  const [perfAnalysis, setPerfAnalysis] = useState<PerformanceAnalysis | null>(null);
  const [securityInsights, setSecurityInsights] = useState<SecurityInsights | null>(null);
  const [topTalkers, setTopTalkers] = useState<TopTalker[]>([]);

  // ── Field analysis ─────────────────────────────────────────────
  const [selectedField, setSelectedField] = useState('rsp_code');
  const [numericStats, setNumericStats] = useState<NumericFieldStats | null>(null);
  const [stringStats, setStringStats] = useState<StringFieldStats | null>(null);
  const [breakdownFields, setBreakdownFields] = useState<string[]>([]);
  const [fieldStatsPage, setFieldStatsPage] = useState(0);
  const FIELD_STATS_PAGE_SIZE = 25;
  const [breakdownResult, setBreakdownResult] = useState<BreakdownResult | null>(null);
  const [expandedPrimary, setExpandedPrimary] = useState<Set<string>>(new Set());

  // ── Progress ───────────────────────────────────────────────────
  const [progress, setProgress] = useState<LogCollectionProgress>({
    phase: 'idle', message: '', progress: 0, logsCollected: 0, estimatedTotal: 0,
  });
  const [isRunning, setIsRunning] = useState(false);
  const [showResults, setShowResults] = useState(false);

  // ── Table ──────────────────────────────────────────────────────
  const [showTable, setShowTable] = useState(false);
  const [tablePage, setTablePage] = useState(0);
  const [sortField, setSortField] = useState<string>('@timestamp');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const TABLE_PAGE_SIZE = 50;

  // ── Probe ──────────────────────────────────────────────────────
  const [probeValues, setProbeValues] = useState<Record<string, string[]>>({});

  // ═══════════════════════════════════════════════════════════════
  // EFFECTS
  // ═══════════════════════════════════════════════════════════════

  useEffect(() => {
    if (!isConnected) return;
    apiClient.getNamespaces().then(res => setNamespaces(res.items || [])).catch(() => {});
  }, [isConnected]);

  // Fetch LBs when namespace changes
  useEffect(() => {
    if (!selectedNs) { setLoadBalancers([]); setSelectedLb(''); return; }
    apiClient.getLoadBalancers(selectedNs)
      .then(res => {
        const items = (res?.items || []).map((lb: { name: string }) => ({ name: lb.name }));
        setLoadBalancers(items);
      })
      .catch(() => setLoadBalancers([]));
  }, [selectedNs]);

  useEffect(() => {
    if (!selectedNs) return;
    const endTime = new Date().toISOString();
    const startTime = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const probeQuery = selectedLb ? `{vh_name="ves-io-http-loadbalancer-${selectedLb}"}` : '{}';
    probeLogs(selectedNs, probeQuery, startTime, endTime, 100)
      .then(({ logs: sample }) => {
        const vals: Record<string, string[]> = {};
        const fieldsToDiscover = ['domain', 'vh_name', 'dst_site', 'src_site', 'method', 'rsp_code', 'country', 'waf_action', 'bot_class', 'tls_version', 'protocol', 'app_type', 'device_type'];
        for (const key of fieldsToDiscover) {
          const unique = new Set<string>();
          for (const log of sample) {
            const v = (log as Record<string, unknown>)[key];
            if (v !== undefined && v !== null && v !== '') unique.add(String(v));
          }
          if (unique.size > 0) vals[key] = [...unique].sort();
        }
        setProbeValues(vals);
      })
      .catch(() => {});
  }, [selectedNs, selectedLb]);

  const filteredLogs = useMemo(() => applyClientFilters(logs, clientFilters), [logs, clientFilters]);

  // Recompute all insights — prefer aggregation data, fall back to sample logs
  useEffect(() => {
    if (!showResults) return;
    if (aggData) {
      // Fast path: aggregation-based analytics (full dataset accuracy)
      setSummary(buildSummaryFromAggregations(aggData));
      setStatusTimeSeries(buildStatusTimeSeriesFromAgg(aggData));
      setErrorAnalysis(buildErrorAnalysisFromAgg(aggData));
      setPerfAnalysis(computePerformanceAnalysis(filteredLogs)); // sample-based, latency only
      setSecurityInsights(buildSecurityInsightsFromAgg(aggData));
      setTopTalkers(buildTopTalkersFromAgg(aggData, 25));
    } else if (filteredLogs.length > 0) {
      // Fallback: raw log analytics (client-side from sample)
      setSummary(computeSummary(filteredLogs));
      setStatusTimeSeries(buildStatusTimeSeries(filteredLogs, TIME_PERIOD_HOURS[timePeriod]));
      setErrorAnalysis(computeErrorAnalysis(filteredLogs));
      setPerfAnalysis(computePerformanceAnalysis(filteredLogs));
      setSecurityInsights(computeSecurityInsights(filteredLogs));
      setTopTalkers(computeTopTalkers(filteredLogs, 25));
    }
  }, [filteredLogs, aggData, showResults, timePeriod]);

  // Field analysis — use aggregation buckets for string fields when available
  useEffect(() => {
    if (!showResults) return;
    const def = FIELD_DEFINITIONS.find(f => f.key === selectedField);
    if (!def) return;
    if (def.type === 'numeric') {
      // Numeric stats still need raw logs (need actual values for percentiles)
      if (filteredLogs.length > 0) setNumericStats(computeNumericStats(filteredLogs, selectedField));
      setStringStats(null);
    } else if (def.type === 'boolean') {
      if (aggData) {
        const buckets = aggData.accessAggs[selectedField] ?? aggData.securityAggs[selectedField] ?? [];
        if (buckets.length > 0) { setStringStats(buildStringStatsFromBuckets(buckets, selectedField, aggData.totalHits)); setNumericStats(null); return; }
      }
      if (filteredLogs.length > 0) setStringStats(computeBooleanStats(filteredLogs, selectedField));
      setNumericStats(null);
    } else {
      // String field — prefer aggregation buckets (full dataset)
      if (aggData) {
        const buckets = aggData.accessAggs[selectedField] ?? aggData.securityAggs[selectedField] ?? [];
        if (buckets.length > 0) { setStringStats(buildStringStatsFromBuckets(buckets, selectedField, aggData.totalHits)); setNumericStats(null); return; }
      }
      if (filteredLogs.length > 0) setStringStats(computeStringStats(filteredLogs, selectedField));
      setNumericStats(null);
    }
  }, [filteredLogs, aggData, selectedField, showResults]);

  // Breakdown computation
  useEffect(() => {
    if (filteredLogs.length === 0 || breakdownFields.length === 0) {
      setBreakdownResult(null);
      return;
    }
    setBreakdownResult(computeBreakdown(filteredLogs, selectedField, breakdownFields));
    setExpandedPrimary(new Set());
  }, [filteredLogs, selectedField, breakdownFields]);

  // ═══════════════════════════════════════════════════════════════
  // ACTIONS
  // ═══════════════════════════════════════════════════════════════

  const handleAnalyze = useCallback(async () => {
    if (!selectedNs || isRunning) return;
    setIsRunning(true);
    setShowResults(false);
    setLogs([]);
    setAggData(null);
    setClientFilters([]);
    setTablePage(0);
    setActiveTab('overview');

    const endTime = new Date().toISOString();
    const startTime = new Date(Date.now() - TIME_PERIOD_HOURS[timePeriod] * 60 * 60 * 1000).toISOString();

    // Build query with LB filter if selected
    const allFilters = [...preFetchFilters];
    if (selectedLb) {
      allFilters.push({ field: 'vh_name', value: `ves-io-http-loadbalancer-${selectedLb}` });
    }
    const query = buildQuery(allFilters);

    try {
      // Aggregation-based fast path — replaces full raw log scrolling
      const data = await collectWithAggregations(selectedNs, query, startTime, endTime, setProgress);
      setAggData(data);
      setLogs(data.sampleLogs); // sample for table view + latency
      setShowResults(true);

      const sourceLabel = logSource === 'security'
        ? `${data.totalSecurityEvents.toLocaleString()} security events`
        : logSource === 'both'
        ? `~${data.estimatedRequests.toLocaleString()} requests · ${data.totalSecurityEvents.toLocaleString()} security events`
        : `~${data.estimatedRequests.toLocaleString()} requests`;
      toast.success(`Analyzed ${sourceLabel} (${data.sampleLogs.length} in table)`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setProgress(p => ({ ...p, phase: 'error', error: msg }));
      toast.error(`Failed: ${msg}`);
    } finally {
      setIsRunning(false);
    }
  }, [selectedNs, selectedLb, isRunning, timePeriod, logSource, preFetchFilters, toast]);

  const addPreFetchFilter = () => {
    if (!newFilterField || !newFilterValue) return;
    setPreFetchFilters(prev => [...prev, { field: newFilterField, value: newFilterValue }]);
    setNewFilterField('');
    setNewFilterValue('');
  };
  const removePreFetchFilter = (idx: number) => setPreFetchFilters(prev => prev.filter((_, i) => i !== idx));

  const addClientFilter = () => {
    if (!newCfField || !newCfValue) return;
    setClientFilters(prev => [...prev, { field: newCfField, operator: newCfOp, value: newCfValue }]);
    setNewCfField('');
    setNewCfValue('');
  };
  const removeClientFilter = (idx: number) => setClientFilters(prev => prev.filter((_, i) => i !== idx));

  const drillDownToField = useCallback((fieldKey: string) => {
    setSelectedField(fieldKey);
    setBreakdownFields([]);
    setFieldStatsPage(0);
    setActiveTab('field-analysis');
  }, []);

  const addFilterFromFieldAnalysis = (field: string, value: string) => {
    if (clientFilters.some(f => f.field === field && f.value === value && f.operator === 'equals')) return;
    setClientFilters(prev => [...prev, { field, operator: 'equals', value }]);
    setShowClientFilters(true);
    toast.success(`Filter added: ${field} = "${value}"`);
  };

  // ═══════════════════════════════════════════════════════════════
  // TABLE
  // ═══════════════════════════════════════════════════════════════

  const tableCols = ['@timestamp', 'method', 'req_path', 'domain', 'rsp_code', 'rsp_code_details', 'src_ip', 'total_duration_seconds', 'rsp_size', 'country', 'response_flags'];

  const sortedLogs = useMemo(() => {
    return [...filteredLogs].sort((a, b) => {
      const sa = String((a as Record<string, unknown>)[sortField] ?? '');
      const sb = String((b as Record<string, unknown>)[sortField] ?? '');
      const cmp = sa.localeCompare(sb, undefined, { numeric: true });
      return sortDir === 'asc' ? cmp : -cmp;
    });
  }, [filteredLogs, sortField, sortDir]);

  const pageCount = Math.ceil(sortedLogs.length / TABLE_PAGE_SIZE);
  const tableRows = sortedLogs.slice(tablePage * TABLE_PAGE_SIZE, (tablePage + 1) * TABLE_PAGE_SIZE);

  // Fields filtered by selected log source
  const sourceFields = useMemo(() => getFieldsForSource(logSource), [logSource]);

  // Overview distributions — compute top values for ALL string fields.
  // Separated into 3 sections: Common (both), Access-only, Security-only.
  // Fields present in both log types use access log values (source of truth).
  type DistEntry = { key: string; label: string; group: string; uniqueCount: number; totalCount: number; topValues: Array<{ value: string; count: number; pct: number }>; _priority: number; _interestingness: number; _coverage: number };
  type DistSections = { access: DistEntry[]; security: DistEntry[] };
  type DistSortMode = 'smart' | 'priority' | 'coverage' | 'unique_asc' | 'unique_desc' | 'alpha' | 'group';
  const [distSortMode, setDistSortMode] = useState<DistSortMode>('smart');

  const overviewDistributions = useMemo((): DistSections => {
    const empty: DistSections = { access: [], security: [] };
    if (filteredLogs.length === 0) return empty;

    const skipFields = new Set(['req_id', 'messageid', 'message_key', 'req_headers', 'rsp_headers']);
    const distributionFields = sourceFields.filter(f => f.type === 'string' && !skipFields.has(f.key));

    // Analysis-priority ordering: fields security analysts look at first
    // Higher number = shown earlier (more important for analysis)
    const FIELD_PRIORITY: Record<string, number> = {
      // Security / WAF — most critical for investigation
      'sec_event_name': 100, 'sec_event_type': 99, 'action': 98, 'recommended_action': 97,
      'waf_action': 96, 'waf_mode': 95, 'enforcement_mode': 94, 'app_firewall_name': 93,
      'violation_rating': 92, 'req_risk': 91, 'req_risk_reasons': 90,
      // Bot detection
      'bot_info.classification': 89, 'bot_info.type': 88, 'bot_info.name': 87, 'bot_info.anomaly': 86,
      'bot_class': 85,
      // Signatures & violations
      'signatures.name': 84, 'signatures.attack_type': 83, 'signatures.id': 82,
      'signatures.risk': 81, 'signatures.accuracy': 80,
      'violations.name': 79, 'violations.context': 78,
      'attack_types': 77,
      // Threat intel
      'threat_campaigns.name': 76, 'threat_campaigns.id': 75,
      // Traffic patterns — what's being accessed
      'rsp_code': 70, 'rsp_code_class': 69, 'rsp_code_details': 68, 'method': 67,
      'domain': 66, 'api_endpoint': 65, 'app_type': 64,
      // Source identity — who's making requests
      'src_ip': 60, 'country': 59, 'city': 58, 'region': 57,
      'asn': 56, 'as_org': 55, 'as_number': 54,
      'user': 53, 'browser_type': 52, 'device_type': 51, 'user_agent': 50,
      // Policy & reputation
      'policy_hits.policy_hits.result': 48, 'policy_hits.policy_hits.policy': 47,
      'policy_hits.policy_hits.policy_rule': 46, 'policy_hits.policy_hits.ip_risk': 45,
      'policy_hits.policy_hits.ip_trustworthiness': 44, 'policy_hits.policy_hits.ip_trustscore': 43,
      'policy_hits.policy_hits.rate_limiter_action': 42, 'policy_hits.policy_hits.malicious_user_mitigate_action': 41,
      // Routing & infrastructure
      'dst_ip': 35, 'dst_port': 34, 'src_site': 33, 'dst_site': 32, 'site': 31,
      'vh_name': 30, 'cluster_name': 29, 'hostname': 28,
      // TLS
      'tls_version': 25, 'tls_cipher_suite': 24, 'ja4_tls_fingerprint': 23, 'tls_fingerprint': 22, 'sni': 21,
      // Response details
      'response_flags': 20,
      // Meta
      'namespace': 10, 'tenant': 9, 'app': 8, 'stream': 7,
    };

    const computeDist = (fields: typeof distributionFields): DistEntry[] => {
      const results: DistEntry[] = [];
      for (const field of fields) {
        const counts = new Map<string, number>();
        let total = 0;
        for (const log of filteredLogs) {
          const raw = resolveField(log as Record<string, unknown>, field.key);
          if (raw === undefined || raw === null || raw === '') continue;
          const val = String(raw);
          counts.set(val, (counts.get(val) || 0) + 1);
          total++;
        }
        if (total === 0) continue;
        const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);

        // Compute interestingness: fields with 2-20 unique values and good data coverage are most useful
        const coverage = total / filteredLogs.length; // 0-1: how many logs have this field
        const entropyRatio = counts.size > 1 ? Math.min(counts.size / 20, 1) : 0; // sweet spot: 2-20 unique
        const interestingness = coverage * (counts.size === 1 ? 0.1 : entropyRatio);

        results.push({
          key: field.key, label: field.label, group: field.group,
          uniqueCount: counts.size, totalCount: total,
          topValues: sorted.slice(0, 10).map(([value, count]) => ({ value, count, pct: (count / total) * 100 })),
          _priority: FIELD_PRIORITY[field.key] || 0,
          _interestingness: interestingness,
          _coverage: coverage,
        } as DistEntry & { _priority: number; _interestingness: number; _coverage: number });
      }
      return results;
    };

    // Sort function based on selected mode
    const sortDist = (entries: DistEntry[]): DistEntry[] => {
      const sorted = [...entries];
      switch (distSortMode) {
        case 'smart':
          // Weighted: 60% analysis priority + 40% interestingness
          sorted.sort((a, b) => {
            const scoreA = (a._priority * 0.6) + (a._interestingness * 100 * 0.4);
            const scoreB = (b._priority * 0.6) + (b._interestingness * 100 * 0.4);
            // Single-value fields always go last
            if (a.uniqueCount === 1 && b.uniqueCount > 1) return 1;
            if (b.uniqueCount === 1 && a.uniqueCount > 1) return -1;
            return scoreB - scoreA;
          });
          break;
        case 'priority':
          sorted.sort((a, b) => b._priority - a._priority || b.totalCount - a.totalCount);
          break;
        case 'coverage':
          sorted.sort((a, b) => b._coverage - a._coverage || b.totalCount - a.totalCount);
          break;
        case 'unique_asc':
          sorted.sort((a, b) => a.uniqueCount - b.uniqueCount || b.totalCount - a.totalCount);
          break;
        case 'unique_desc':
          sorted.sort((a, b) => b.uniqueCount - a.uniqueCount || b.totalCount - a.totalCount);
          break;
        case 'alpha':
          sorted.sort((a, b) => a.label.localeCompare(b.label));
          break;
        case 'group':
          sorted.sort((a, b) => a.group.localeCompare(b.group) || b._priority - a._priority);
          break;
      }
      return sorted;
    };

    if (logSource === 'access') {
      return { access: sortDist(computeDist(distributionFields)), security: [] };
    }
    if (logSource === 'security') {
      return { access: [], security: sortDist(computeDist(distributionFields)) };
    }

    // Merged (both): 2 sections only
    // Access = access-only + common (both) fields — common fields use access log data
    // Security = security-only fields
    const accessAndCommonFields = distributionFields.filter(f => (f.source || 'access') !== 'security');
    const securityOnlyFields = distributionFields.filter(f => f.source === 'security');

    return {
      access: sortDist(computeDist(accessAndCommonFields)),
      security: sortDist(computeDist(securityOnlyFields)),
    };
  }, [filteredLogs, sourceFields, logSource, distSortMode]);

  const groupedFields = useMemo(() => {
    const groups: Record<string, Array<{ key: string; label: string; type: string }>> = {};
    for (const f of sourceFields) {
      if (!groups[f.group]) groups[f.group] = [];
      groups[f.group].push({ key: f.key, label: f.label, type: f.type });
    }
    return groups;
  }, [sourceFields]);

  // ═══════════════════════════════════════════════════════════════
  // RENDER
  // ═══════════════════════════════════════════════════════════════

  if (!isConnected) {
    return <main className="max-w-7xl mx-auto px-6 py-8"><ConnectionPanel /></main>;
  }

  const TABS: Array<{ id: InsightTab; label: string; icon: typeof BarChart2 }> = [
    { id: 'overview', label: 'Overview', icon: BarChart2 },
    { id: 'errors', label: 'Errors', icon: AlertTriangle },
    { id: 'performance', label: 'Performance', icon: Zap },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'top-talkers', label: 'Top Talkers', icon: Users },
    { id: 'field-analysis', label: 'Field Analysis', icon: Hash },
  ];

  return (
    <main className="max-w-7xl mx-auto px-6 py-8">
      {/* ── Header ──────────────────────────────────────────── */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-4">
          <Link to="/" className="p-2 hover:bg-slate-800 rounded-lg transition-colors">
            <ArrowLeft className="w-5 h-5 text-slate-400" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
              <BarChart2 className="w-6 h-6 text-blue-400" /> Log Analyzer
            </h1>
            <p className="text-sm text-slate-400 mt-1">Access & security log analytics — errors, performance, WAF events, and field-level insights</p>
          </div>
          <Link to="/explainer/log-analyzer" className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-400 hover:text-blue-400 rounded-lg text-xs transition-colors">
            <HelpCircle className="w-3.5 h-3.5" /> How does this work?
          </Link>
        </div>
        {showResults && (
          <div className="flex items-center gap-2">
            <button onClick={() => exportAsJSON(filteredLogs)} className="flex items-center gap-1.5 px-3 py-2 text-sm bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg transition-colors">
              <FileJson className="w-4 h-4" /> JSON
            </button>
            <button onClick={() => exportAsCSV(filteredLogs, tableCols)} className="flex items-center gap-1.5 px-3 py-2 text-sm bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg transition-colors">
              <FileSpreadsheet className="w-4 h-4" /> CSV
            </button>
          </div>
        )}
      </div>

      {/* ── Config Panel ────────────────────────────────────── */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <SearchableSelect label="Namespace" options={namespaces.map(ns => ({ value: ns.name, label: ns.name }))} value={selectedNs}
            onChange={v => { setSelectedNs(v); setSelectedLb(''); setPreFetchFilters([]); setShowResults(false); setLogs([]); }} placeholder="Select namespace..." />
          <SearchableSelect
            label="Load Balancer (optional)"
            options={[{ value: '', label: 'All Load Balancers' }, ...loadBalancers.map(lb => ({ value: lb.name, label: lb.name }))]}
            value={selectedLb}
            onChange={setSelectedLb}
            placeholder="Type to search LBs..."
            disabled={!selectedNs || loadBalancers.length === 0}
          />
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Time Range</label>
            <div className="flex gap-1">
              {(Object.keys(TIME_PERIOD_HOURS) as TimePeriod[]).map(tp => (
                <button key={tp} onClick={() => setTimePeriod(tp)}
                  className={`flex-1 px-3 py-2 text-sm rounded-lg transition-colors ${timePeriod === tp ? 'bg-blue-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'}`}>{tp}</button>
              ))}
            </div>
          </div>
        </div>
        <div className="mb-4">
          <label className="block text-xs font-medium text-slate-400 mb-1">Log Source</label>
          <div className="flex gap-1">
            {([['access', 'Access Logs'], ['security', 'Security Events'], ['both', 'Both (Merged)']] as const).map(([src, lbl]) => (
              <button key={src} onClick={() => setLogSource(src)}
                className={`flex-1 px-3 py-2 text-sm rounded-lg transition-colors ${logSource === src ? 'bg-blue-600 text-white' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'}`}>{lbl}</button>
            ))}
          </div>
          {logSource === 'both' && (
            <p className="text-xs text-slate-500 mt-1">Access logs are primary. Security events are merged by request ID to enrich matching entries.</p>
          )}
          {logSource === 'security' && (
            <p className="text-xs text-slate-500 mt-1">Only WAF/security events are fetched. Some access-log-specific analytics may be limited.</p>
          )}
        </div>
        <div className="mb-4">
          <label className="block text-xs font-medium text-slate-400 mb-2">API Query Filters</label>
          {preFetchFilters.length > 0 && (
            <div className="flex flex-wrap gap-2 mb-2">
              {preFetchFilters.map((f, i) => (
                <span key={i} className="inline-flex items-center gap-1 px-2.5 py-1 bg-blue-600/20 border border-blue-500/30 text-blue-300 text-xs rounded-full">
                  {f.field}="{f.value}"
                  <button onClick={() => removePreFetchFilter(i)} className="hover:text-red-400"><X className="w-3 h-3" /></button>
                </span>
              ))}
            </div>
          )}
          <div className="flex items-end gap-2">
            <div className="flex-1">
              <select value={newFilterField} onChange={e => { setNewFilterValue(''); setNewFilterField(e.target.value); }}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-lg text-sm text-slate-200">
                <option value="">Select field...</option>
                {PRE_FETCH_FILTER_FIELDS
                  .filter(f => { const def = FIELD_DEFINITIONS.find(d => d.key === f); const s = def?.source || 'access'; return logSource === 'both' || s === logSource || s === 'both'; })
                  .map(f => <option key={f} value={f}>{FIELD_DEFINITIONS.find(d => d.key === f)?.label || f}</option>)}
              </select>
            </div>
            <div className="flex-1">
              {newFilterField && probeValues[newFilterField] ? (
                <select value={newFilterValue} onChange={e => setNewFilterValue(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-lg text-sm text-slate-200">
                  <option value="">Select value...</option>
                  {probeValues[newFilterField].map(v => <option key={v} value={v}>{v}</option>)}
                </select>
              ) : (
                <input type="text" value={newFilterValue} onChange={e => setNewFilterValue(e.target.value)} placeholder="Value..."
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-lg text-sm text-slate-200"
                  onKeyDown={e => e.key === 'Enter' && addPreFetchFilter()} />
              )}
            </div>
            <button onClick={addPreFetchFilter} disabled={!newFilterField || !newFilterValue}
              className="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm disabled:opacity-50 disabled:cursor-not-allowed">
              <Plus className="w-4 h-4" />
            </button>
          </div>
        </div>
        <button onClick={handleAnalyze} disabled={!selectedNs || isRunning}
          className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-700 disabled:text-slate-500 text-white font-medium rounded-lg transition-colors">
          {isRunning ? <><Loader2 className="w-5 h-5 animate-spin" /> Fetching {logSource === 'security' ? 'Security Events' : 'Logs'}...</> : <><Play className="w-5 h-5" /> Analyze {logSource === 'security' ? 'Security Events' : logSource === 'both' ? 'Logs + Security' : 'Logs'} — {TIME_PERIOD_LABELS[timePeriod]}</>}
        </button>
      </div>

      {/* ── Progress ────────────────────────────────────────── */}
      {(isRunning || progress.phase === 'error') && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4 mb-6">
          <div className="flex items-center justify-between text-sm mb-2">
            <span className={progress.phase === 'error' ? 'text-red-400' : 'text-slate-300'}>{progress.message}</span>
            <span className="text-slate-500">{progress.progress}%</span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div className={`h-2 rounded-full transition-all duration-300 ${progress.phase === 'error' ? 'bg-red-500' : 'bg-blue-500'}`} style={{ width: `${progress.progress}%` }} />
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════ */}
      {/* RESULTS                                                */}
      {/* ═══════════════════════════════════════════════════════ */}
      {showResults && summary && (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
            <StatCard label="Total Logs" value={summary.totalLogs} />
            <StatCard label="Unique IPs" value={summary.uniqueIPs} />
            <StatCard label="Unique Paths" value={summary.uniquePaths} />
            <StatCard label="Unique Domains" value={summary.uniqueDomains} />
            <StatCard label="Avg Duration" value={`${(summary.avgDurationMs || 0).toFixed(1)}ms`} />
            <StatCard label="Error Rate" value={`${summary.errorRate.toFixed(1)}%`} sub="4xx + 5xx"
              color={summary.errorRate > 10 ? 'text-red-400' : summary.errorRate > 5 ? 'text-amber-400' : 'text-emerald-400'} />
          </div>

          {/* ── Slice & Dice ────────────────────────────────── */}
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl mb-6">
            <button onClick={() => setShowClientFilters(!showClientFilters)}
              className="w-full flex items-center justify-between px-5 py-3 text-sm font-semibold text-slate-300 hover:text-slate-100">
              <span className="flex items-center gap-2">
                <Filter className="w-4 h-4" /> Slice & Dice — Client-Side Filters
                {clientFilters.length > 0 && <span className="px-2 py-0.5 text-xs bg-blue-600/20 text-blue-300 rounded-full">{clientFilters.length} active</span>}
              </span>
              {showClientFilters ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
            {showClientFilters && (
              <div className="px-5 pb-4 border-t border-slate-700">
                {clientFilters.length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-3 mb-3">
                    {clientFilters.map((f, i) => (
                      <span key={i} className="inline-flex items-center gap-1 px-2.5 py-1 bg-violet-600/20 border border-violet-500/30 text-violet-300 text-xs rounded-full">
                        {f.field} {f.operator} "{f.value}"
                        <button onClick={() => removeClientFilter(i)} className="hover:text-red-400"><X className="w-3 h-3" /></button>
                      </span>
                    ))}
                    <button onClick={() => setClientFilters([])} className="text-xs text-red-400 hover:text-red-300 px-2 py-1">Clear all</button>
                  </div>
                )}
                <div className="flex items-end gap-2 mt-3">
                  <div className="flex-1">
                    <select value={newCfField} onChange={e => setNewCfField(e.target.value)}
                      className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-lg text-sm text-slate-200">
                      <option value="">Field...</option>
                      {sourceFields.map(f => <option key={f.key} value={f.key}>{f.label}</option>)}
                    </select>
                  </div>
                  <div className="w-32">
                    <select value={newCfOp} onChange={e => setNewCfOp(e.target.value as ClientFilter['operator'])}
                      className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-lg text-sm text-slate-200">
                      <option value="equals">equals</option>
                      <option value="not_equals">not equals</option>
                      <option value="contains">contains</option>
                      <option value="regex">regex</option>
                    </select>
                  </div>
                  <div className="flex-1">
                    <input type="text" value={newCfValue} onChange={e => setNewCfValue(e.target.value)} placeholder="Value..."
                      className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-lg text-sm text-slate-200"
                      onKeyDown={e => e.key === 'Enter' && addClientFilter()} />
                  </div>
                  <button onClick={addClientFilter} disabled={!newCfField || !newCfValue}
                    className="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm disabled:opacity-50">
                    <Plus className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Client filter indicator */}
          {clientFilters.length > 0 && (
            <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg px-4 py-2 mb-4 text-sm text-amber-300">
              <Filter className="w-4 h-4 inline mr-1" />
              Showing {filteredLogs.length.toLocaleString()} of {logs.length.toLocaleString()} logs (filtered)
            </div>
          )}

          {/* ── Tab Navigation ──────────────────────────────── */}
          <div className="flex gap-1 mb-6 overflow-x-auto pb-1">
            {TABS.map(tab => (
              <button key={tab.id} onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-1.5 px-4 py-2 text-sm font-medium rounded-lg whitespace-nowrap transition-colors ${
                  activeTab === tab.id ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700'}`}>
                <tab.icon className="w-4 h-4" /> {tab.label}
              </button>
            ))}
          </div>

          {/* ═══ TAB: Overview ═══════════════════════════════ */}
          {activeTab === 'overview' && (
            <>
              {/* Key stats at a glance */}
              {summary && (
                <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 xl:grid-cols-8 gap-3 mb-6">
                  {(() => {
                    // Compute log type counts correctly based on the original_topic_name or field presence
                    // Access log indicator: has total_duration_seconds or original_topic_name contains 'apiaccess'
                    // Security log indicator: has sec_event_type or original_topic_name contains 'secevent'
                    // Standalone security: has sec_event_type but NO total_duration_seconds (not merged with access)
                    const isAccessLog = (l: Record<string, unknown>) =>
                      l.total_duration_seconds !== undefined || l.rsp_code_details !== undefined ||
                      (l.original_topic_name && String(l.original_topic_name).includes('apiaccess'));
                    const isSecLog = (l: Record<string, unknown>) =>
                      l.sec_event_type !== undefined || l.sec_event_name !== undefined ||
                      (l.original_topic_name && String(l.original_topic_name).includes('secevent'));

                    const accessCount = filteredLogs.filter(l => isAccessLog(l as Record<string, unknown>)).length;
                    const secCount = filteredLogs.filter(l => isSecLog(l as Record<string, unknown>)).length;
                    const matchedCount = filteredLogs.filter(l => {
                      const r = l as Record<string, unknown>;
                      return isAccessLog(r) && r.has_sec_event === true;
                    }).length;
                    const standaloneSecCount = filteredLogs.filter(l => {
                      const r = l as Record<string, unknown>;
                      return isSecLog(r) && !isAccessLog(r);
                    }).length;

                    return (<>
                      <StatCard label="Total Logs" value={filteredLogs.length} color="text-blue-400" />
                      {logSource === 'both' && <StatCard label="Access Logs" value={accessCount} color="text-cyan-400" />}
                      {logSource === 'both' && <StatCard label="Security Logs" value={secCount} color="text-red-400" />}
                      {logSource === 'both' && <StatCard label="Matched" value={matchedCount} color="text-emerald-400" sub="access+sec" />}
                      {logSource === 'both' && standaloneSecCount > 0 && <StatCard label="Standalone Sec" value={standaloneSecCount} color="text-amber-400" sub="no access log" />}
                      <StatCard label="Unique IPs" value={summary.uniqueIPs} />
                      <StatCard label="Unique Paths" value={summary.uniquePaths} />
                      <StatCard label="Unique Domains" value={summary.uniqueDomains} />
                      <StatCard label="Error Rate" value={`${(errorAnalysis?.errorRate ?? 0).toFixed(1)}%`}
                        color={(errorAnalysis?.errorRate ?? 0) > 5 ? 'text-red-400' : (errorAnalysis?.errorRate ?? 0) > 1 ? 'text-amber-400' : 'text-emerald-400'} />
                      <StatCard label="Avg Latency" value={`${(summary.avgDurationMs || 0).toFixed(0)}ms`}
                        color={(summary.avgDurationMs || 0) > 1000 ? 'text-amber-400' : 'text-slate-100'} />
                      {perfAnalysis && <StatCard label="P95 Latency" value={`${(perfAnalysis.overall.p95 * 1000).toFixed(0)}ms`}
                        color={perfAnalysis.overall.p95 > 1 ? 'text-red-400' : 'text-slate-100'} />}
                      {securityInsights && <StatCard label="WAF Events" value={securityInsights.wafActions.reduce((s, a) => s + (a.action !== '(none)' && a.action !== 'allow' ? a.count : 0), 0)} color="text-red-400" />}
                      {securityInsights && securityInsights.botClasses.length > 0 && (
                        <StatCard label="Bot Traffic" value={`${securityInsights.botClasses.filter(b => b.cls !== '(none)' && b.cls !== 'human').reduce((s, b) => s + b.pct, 0).toFixed(1)}%`}
                          color="text-amber-400" />
                      )}
                      <StatCard label="Time Range" value={timePeriod} />
                    </>);
                  })()}
                </div>
              )}

              {/* Stacked status time series */}
              {statusTimeSeries.length > 0 && (
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-6">
                  <h3 className="text-sm font-semibold text-slate-300 mb-3">Requests Over Time by Status</h3>
                  <ResponsiveContainer width="100%" height={280}>
                    <AreaChart data={statusTimeSeries}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis dataKey="label" tick={{ fontSize: 11, fill: '#94a3b8' }} interval="preserveStartEnd" />
                      <YAxis tick={{ fontSize: 11, fill: '#94a3b8' }} />
                      <RTooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }} />
                      <Area type="monotone" dataKey="2xx" stackId="1" stroke={STATUS_COLORS['2xx']} fill={STATUS_COLORS['2xx']} fillOpacity={0.6} name="2xx" />
                      <Area type="monotone" dataKey="3xx" stackId="1" stroke={STATUS_COLORS['3xx']} fill={STATUS_COLORS['3xx']} fillOpacity={0.6} name="3xx" />
                      <Area type="monotone" dataKey="4xx" stackId="1" stroke={STATUS_COLORS['4xx']} fill={STATUS_COLORS['4xx']} fillOpacity={0.6} name="4xx" />
                      <Area type="monotone" dataKey="5xx" stackId="1" stroke={STATUS_COLORS['5xx']} fill={STATUS_COLORS['5xx']} fillOpacity={0.6} name="5xx" />
                      <Area type="monotone" dataKey="other" stackId="1" stroke={STATUS_COLORS.other} fill={STATUS_COLORS.other} fillOpacity={0.6} name="Other" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
              {/* Quick breakdown cards */}
              {filteredLogs.length > 0 && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
                  {/* Response Code Distribution — ALL logs (not just errors) */}
                  <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                    <h4 className="text-xs font-semibold text-slate-400 mb-3">Response Code Distribution <span className="text-slate-600">(all logs)</span></h4>
                    {(() => {
                      const codeCounts = new Map<string, number>();
                      for (const log of filteredLogs) {
                        const code = String((log as Record<string,unknown>).rsp_code || '');
                        if (!code) continue;
                        codeCounts.set(code, (codeCounts.get(code) || 0) + 1);
                      }
                      const total = [...codeCounts.values()].reduce((s, c) => s + c, 0);
                      const sorted = [...codeCounts.entries()].sort((a, b) => b[1] - a[1]);
                      return sorted.slice(0, 10).map(([code, count], i) => {
                        const pct = total > 0 ? (count / total) * 100 : 0;
                        const color = code.startsWith('2') ? 'bg-emerald-500' : code.startsWith('3') ? 'bg-blue-500' : code.startsWith('4') ? 'bg-amber-500' : code.startsWith('5') ? 'bg-red-500' : 'bg-slate-500';
                        return (
                          <div key={i} className="flex items-center justify-between py-1">
                            <button onClick={() => addFilterFromFieldAnalysis('rsp_code', code)} className="text-sm text-slate-200 hover:text-blue-400 font-mono">{code}</button>
                            <div className="flex items-center gap-2">
                              <div className="w-24 bg-slate-700 rounded-full h-1.5"><div className={`h-1.5 rounded-full ${color}`} style={{ width: `${pct}%` }} /></div>
                              <span className="text-xs text-slate-400 w-20 text-right">{count.toLocaleString()} ({pct.toFixed(1)}%)</span>
                            </div>
                          </div>
                        );
                      });
                    })()}
                  </div>

                  {/* Error Codes Only — from errorAnalysis */}
                  {errorAnalysis && errorAnalysis.byCode.length > 0 && (
                    <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                      <h4 className="text-xs font-semibold text-slate-400 mb-3">Error Codes <span className="text-slate-600">(4xx/5xx only)</span></h4>
                      {errorAnalysis.byCode.slice(0, 8).map((c, i) => (
                        <div key={i} className="flex items-center justify-between py-1">
                          <button onClick={() => addFilterFromFieldAnalysis('rsp_code', c.code)} className="text-sm text-slate-200 hover:text-blue-400 font-mono">{c.code}</button>
                          <div className="flex items-center gap-2">
                            <div className="w-24 bg-slate-700 rounded-full h-1.5"><div className="h-1.5 rounded-full bg-red-500" style={{ width: `${c.pct}%` }} /></div>
                            <span className="text-xs text-slate-400 w-16 text-right">{c.count.toLocaleString()}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Response Details + Response Flags */}
                  {errorAnalysis && (
                    <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                      <h4 className="text-xs font-semibold text-slate-400 mb-3">Response Details <span className="text-slate-600">(error diagnosis)</span></h4>
                      {errorAnalysis.byDetail.slice(0, 8).map((d, i) => (
                        <div key={i} className="flex items-center justify-between py-1">
                          <button onClick={() => addFilterFromFieldAnalysis('rsp_code_details', d.detail)} className="text-sm text-slate-200 hover:text-blue-400 font-mono truncate max-w-[180px]" title={d.detail}>{d.detail}</button>
                          <span className="text-xs text-slate-400 ml-2">{d.count.toLocaleString()}</span>
                        </div>
                      ))}
                      {errorAnalysis.byDetail.length === 0 && <p className="text-xs text-slate-600">No error details</p>}
                    </div>
                  )}
                </div>
              )}

              {/* Field Distributions — separated by log source */}
              {(overviewDistributions.access.length > 0 || overviewDistributions.security.length > 0) && (
                <>
                  {/* Sort controls */}
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs text-slate-500">Sort fields by:</span>
                    <div className="flex gap-1">
                      {([
                        ['smart', 'Smart'] as const,
                        ['priority', 'Analysis Priority'] as const,
                        ['coverage', 'Data Coverage'] as const,
                        ['unique_asc', 'Least Unique'] as const,
                        ['unique_desc', 'Most Unique'] as const,
                        ['group', 'Category'] as const,
                        ['alpha', 'A → Z'] as const,
                      ]).map(([mode, label]) => (
                        <button key={mode} onClick={() => setDistSortMode(mode)}
                          className={`px-2 py-1 text-[10px] rounded transition-colors ${distSortMode === mode ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-500 hover:text-slate-300 hover:bg-slate-700'}`}>
                          {label}
                        </button>
                      ))}
                    </div>
                  </div>
                  {/* Access log fields (includes common fields) */}
                  {overviewDistributions.access.length > 0 && (
                    <DistributionSection
                      title={logSource === 'security' ? 'Field Distributions' : 'Access Log Fields'}
                      subtitle={`${overviewDistributions.access.length} fields`}
                      accent="cyan"
                      distributions={overviewDistributions.access}
                      onFilter={addFilterFromFieldAnalysis}
                      onDrillDown={drillDownToField}
                    />
                  )}

                  {/* Security event fields */}
                  {overviewDistributions.security.length > 0 && (
                    <DistributionSection
                      title={logSource === 'access' ? 'Field Distributions' : 'Security Event Fields'}
                      subtitle={`${overviewDistributions.security.length} fields`}
                      accent="red"
                      distributions={overviewDistributions.security}
                      onFilter={addFilterFromFieldAnalysis}
                      onDrillDown={drillDownToField}
                    />
                  )}
                </>
              )}
            </>
          )}

          {/* ═══ TAB: Errors ═════════════════════════════════ */}
          {activeTab === 'errors' && errorAnalysis && (
            <div className="space-y-6">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <StatCard label="Total Errors" value={errorAnalysis.totalErrors} color="text-red-400" />
                <StatCard label="Error Rate" value={`${errorAnalysis.errorRate.toFixed(1)}%`} color={errorAnalysis.errorRate > 10 ? 'text-red-400' : 'text-amber-400'} />
                <StatCard label="Error Codes" value={errorAnalysis.byCode.length} />
                <StatCard label="Error Sources" value={errorAnalysis.bySource.length} sub="unique IPs" />
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Errors by Response Code</h4>
                  <ResponsiveContainer width="100%" height={Math.max(150, errorAnalysis.byCode.length * 30)}>
                    <BarChart data={errorAnalysis.byCode.slice(0, 15)} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis type="number" tick={{ fontSize: 11, fill: '#94a3b8' }} />
                      <YAxis type="category" dataKey="code" tick={{ fontSize: 11, fill: '#94a3b8' }} width={60} />
                      <RTooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }} />
                      <Bar dataKey="count" name="Errors" radius={[0, 4, 4, 0]}>
                        {errorAnalysis.byCode.map((_, i) => <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />)}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Response Flags Breakdown</h4>
                  <ResponsiveContainer width="100%" height={Math.max(150, errorAnalysis.byResponseFlag.length * 30)}>
                    <BarChart data={errorAnalysis.byResponseFlag} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis type="number" tick={{ fontSize: 11, fill: '#94a3b8' }} />
                      <YAxis type="category" dataKey="flag" tick={{ fontSize: 10, fill: '#94a3b8' }} width={180}
                        tickFormatter={(v: string) => v.length > 30 ? v.slice(0, 27) + '...' : v} />
                      <RTooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }} />
                      <Bar dataKey="count" name="Count" radius={[0, 4, 4, 0]}>
                        {errorAnalysis.byResponseFlag.map((_, i) => <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />)}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Top Error Paths</h4>
                  <MiniTable headers={['Path', 'Errors', 'Error Rate %']}
                    rows={errorAnalysis.byPath.map(p => [p.path, p.count, p.errorRate])}
                    onRowClick={row => addFilterFromFieldAnalysis('req_path', String(row[0]))} />
                </div>
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Top Error Sources</h4>
                  <MiniTable headers={['Source IP', 'Country', 'Errors', 'Error Rate %']}
                    rows={errorAnalysis.bySource.map(s => [s.ip, s.country, s.count, s.errorRate])}
                    onRowClick={row => addFilterFromFieldAnalysis('src_ip', String(row[0]))} />
                </div>
              </div>
            </div>
          )}

          {/* ═══ TAB: Performance ════════════════════════════ */}
          {activeTab === 'performance' && perfAnalysis && (
            <div className="space-y-6">
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                <StatCard label="P50 Latency" value={`${(perfAnalysis.overall.p50 * 1000).toFixed(1)}ms`} />
                <StatCard label="P90 Latency" value={`${(perfAnalysis.overall.p90 * 1000).toFixed(1)}ms`} />
                <StatCard label="P95 Latency" value={`${(perfAnalysis.overall.p95 * 1000).toFixed(1)}ms`}
                  color={perfAnalysis.overall.p95 > 1 ? 'text-amber-400' : 'text-slate-100'} />
                <StatCard label="P99 Latency" value={`${(perfAnalysis.overall.p99 * 1000).toFixed(1)}ms`}
                  color={perfAnalysis.overall.p99 > 2 ? 'text-red-400' : 'text-slate-100'} />
                <StatCard label="Max Latency" value={`${(perfAnalysis.overall.max * 1000).toFixed(0)}ms`} color="text-red-400" />
                <StatCard label="Mean Latency" value={`${(perfAnalysis.overall.mean * 1000).toFixed(1)}ms`} />
              </div>

              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                <h4 className="text-sm font-semibold text-slate-300 mb-3">Slowest Requests</h4>
                <MiniTable headers={['Timestamp', 'Method', 'Path', 'Code', 'Duration (s)', 'Source IP', 'Country', 'Detail']}
                  rows={perfAnalysis.slowRequests.map(r => [
                    r.timestamp.replace('T', ' ').slice(0, 19), r.method, r.path,
                    r.code, r.durationS, r.srcIp, r.country, r.detail
                  ])} />
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Latency by Path (P95 ms)</h4>
                  <MiniTable headers={['Path', 'Count', 'Avg (ms)', 'P95 (ms)', 'Max (ms)']}
                    rows={perfAnalysis.byPath.map(p => [p.path, p.count, p.avgMs, p.p95Ms, p.maxMs])}
                    onRowClick={row => addFilterFromFieldAnalysis('req_path', String(row[0]))} />
                </div>
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Latency by Country (P95 ms)</h4>
                  <MiniTable headers={['Country', 'Count', 'Avg (ms)', 'P95 (ms)']}
                    rows={perfAnalysis.byCountry.map(c => [c.country, c.count, c.avgMs, c.p95Ms])}
                    onRowClick={row => addFilterFromFieldAnalysis('country', String(row[0]))} />
                </div>
              </div>

              {perfAnalysis.bySite.length > 1 && (
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Latency by Site / PoP</h4>
                  <MiniTable headers={['Site', 'Count', 'Avg (ms)', 'P95 (ms)']}
                    rows={perfAnalysis.bySite.map(s => [s.site, s.count, s.avgMs, s.p95Ms])} />
                </div>
              )}
            </div>
          )}

          {/* ═══ TAB: Security ═══════════════════════════════ */}
          {activeTab === 'security' && securityInsights && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                  <h4 className="text-xs font-semibold text-slate-400 mb-3">WAF Actions</h4>
                  {securityInsights.wafActions.map((a, i) => (
                    <div key={i} className="flex items-center justify-between py-1.5">
                      <button onClick={() => addFilterFromFieldAnalysis('waf_action', a.action === '(none)' ? '' : a.action)}
                        className={`text-sm font-mono hover:text-blue-400 ${a.action === 'block' ? 'text-red-400' : a.action === 'allow' ? 'text-emerald-400' : 'text-slate-300'}`}>{a.action}</button>
                      <span className="text-xs text-slate-400">{a.count.toLocaleString()} ({a.pct.toFixed(1)}%)</span>
                    </div>
                  ))}
                </div>
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                  <h4 className="text-xs font-semibold text-slate-400 mb-3">Bot Classification</h4>
                  {securityInsights.botClasses.map((b, i) => (
                    <div key={i} className="flex items-center justify-between py-1.5">
                      <button onClick={() => addFilterFromFieldAnalysis('bot_class', b.cls === '(none)' ? '' : b.cls)}
                        className={`text-sm font-mono hover:text-blue-400 ${b.cls === 'suspicious' ? 'text-amber-400' : b.cls === 'malicious' ? 'text-red-400' : 'text-slate-300'}`}>{b.cls}</button>
                      <span className="text-xs text-slate-400">{b.count.toLocaleString()} ({b.pct.toFixed(1)}%)</span>
                    </div>
                  ))}
                </div>
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                  <h4 className="text-xs font-semibold text-slate-400 mb-3">Policy Hit Results</h4>
                  {securityInsights.policyHitResults.map((p, i) => (
                    <div key={i} className="flex items-center justify-between py-1.5">
                      <span className={`text-sm font-mono ${p.result === 'deny' ? 'text-red-400' : p.result === 'allow' ? 'text-emerald-400' : 'text-slate-300'}`}>{p.result}</span>
                      <span className="text-xs text-slate-400">{p.count.toLocaleString()} ({p.pct.toFixed(1)}%)</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Top Blocked IPs</h4>
                  <MiniTable headers={['Source IP', 'Country', 'Blocked', 'Action']}
                    rows={securityInsights.topBlockedIPs.map(b => [b.ip, b.country, b.count, b.wafAction])}
                    onRowClick={row => addFilterFromFieldAnalysis('src_ip', String(row[0]))} />
                </div>
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                  <h4 className="text-sm font-semibold text-slate-300 mb-3">Suspicious Paths (High Block Rate)</h4>
                  <MiniTable headers={['Path', 'Blocked', 'Block Rate %']}
                    rows={securityInsights.suspiciousPaths.map(p => [p.path, p.count, p.blockedPct])}
                    onRowClick={row => addFilterFromFieldAnalysis('req_path', String(row[0]))} />
                </div>
              </div>
            </div>
          )}

          {/* ═══ TAB: Top Talkers ════════════════════════════ */}
          {activeTab === 'top-talkers' && topTalkers.length > 0 && (
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
              <h4 className="text-sm font-semibold text-slate-300 mb-3">Top 25 Source IPs by Request Volume</h4>
              <MiniTable
                headers={['Source IP', 'Country', 'AS Org', 'Requests', 'Errors', 'Err %', 'WAF Blocked', 'Bandwidth', 'Bot', 'Top Path']}
                rows={topTalkers.map(t => [
                  t.ip, t.country, t.asOrg.slice(0, 20), t.requests, t.errors,
                  t.errorRate, t.wafBlocked, formatBytes(t.bandwidth), t.botClass || '-', t.topPath,
                ])}
                onRowClick={row => addFilterFromFieldAnalysis('src_ip', String(row[0]))}
              />
            </div>
          )}

          {/* ═══ TAB: Field Analysis ═════════════════════════ */}
          {activeTab === 'field-analysis' && (
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
              {/* Field selectors */}
              <div className="flex flex-col md:flex-row gap-4 mb-4">
                <div className="flex-1">
                  <label className="block text-xs font-medium text-slate-400 mb-1">Primary Field</label>
                  <select value={selectedField} onChange={e => { setSelectedField(e.target.value); setBreakdownFields([]); setFieldStatsPage(0); }}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-lg text-sm text-slate-200">
                    {Object.entries(groupedFields).map(([group, fields]) => (
                      <optgroup key={group} label={FIELD_GROUP_LABELS[group] || group}>
                        {fields.map(f => <option key={f.key} value={f.key}>{f.label}</option>)}
                      </optgroup>
                    ))}
                  </select>
                </div>
                <div className="flex-1">
                  <label className="block text-xs font-medium text-slate-400 mb-1">Breakdown By (multi-select)</label>
                  <BreakdownMultiSelect
                    groupedFields={groupedFields}
                    groupLabels={FIELD_GROUP_LABELS}
                    selected={breakdownFields}
                    onChange={setBreakdownFields}
                    excludeField={selectedField}
                  />
                </div>
              </div>

              {/* Breakdown tags */}
              {breakdownFields.length > 0 && (
                <div className="flex flex-wrap gap-1.5 mb-4">
                  {breakdownFields.map(bf => {
                    const def = sourceFields.find(f => f.key === bf) || FIELD_DEFINITIONS.find(f => f.key === bf);
                    return (
                      <span key={bf} className="inline-flex items-center gap-1 px-2 py-0.5 bg-violet-600/20 border border-violet-500/30 text-violet-300 text-xs rounded-full">
                        {def?.label || bf}
                        <button onClick={() => setBreakdownFields(prev => prev.filter(f => f !== bf))} className="hover:text-red-400"><X className="w-3 h-3" /></button>
                      </span>
                    );
                  })}
                  <button onClick={() => setBreakdownFields([])} className="text-xs text-slate-500 hover:text-slate-300 px-2">Clear all</button>
                </div>
              )}

              {numericStats && (
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <Hash className="w-4 h-4 text-blue-400" />
                    <span className="text-sm font-medium text-slate-200">{numericStats.label}</span>
                    <span className="text-xs text-slate-500">({numericStats.count.toLocaleString()} values)</span>
                  </div>
                  <div className="grid grid-cols-3 md:grid-cols-5 lg:grid-cols-9 gap-2 mb-4">
                    {[
                      { l: 'Min', v: numericStats.min }, { l: 'Max', v: numericStats.max },
                      { l: 'Mean', v: numericStats.mean }, { l: 'Median', v: numericStats.median },
                      { l: 'Std Dev', v: numericStats.stdDev }, { l: 'P90', v: numericStats.p90 },
                      { l: 'P95', v: numericStats.p95 }, { l: 'P99', v: numericStats.p99 },
                      { l: 'Sum', v: numericStats.sum },
                    ].map(s => (
                      <div key={s.l} className="bg-slate-900/50 rounded-lg p-2 text-center">
                        <div className="text-[10px] text-slate-500 uppercase">{s.l}</div>
                        <div className="text-sm font-mono text-slate-200">{formatNum(s.v)}</div>
                      </div>
                    ))}
                  </div>
                  {numericStats.histogram.length > 1 && (
                    <ResponsiveContainer width="100%" height={200}>
                      <BarChart data={numericStats.histogram}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                        <XAxis dataKey="bucket" tick={{ fontSize: 10, fill: '#94a3b8' }} interval={0} angle={-35} textAnchor="end" height={60} />
                        <YAxis tick={{ fontSize: 11, fill: '#94a3b8' }} />
                        <RTooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }} labelStyle={{ color: '#94a3b8' }} />
                        <Bar dataKey="count" name="Count" radius={[4, 4, 0, 0]}>
                          {numericStats.histogram.map((_, i) => <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />)}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  )}
                </div>
              )}

              {stringStats && (
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <Type className="w-4 h-4 text-violet-400" />
                    <span className="text-sm font-medium text-slate-200">{stringStats.label}</span>
                    <span className="text-xs text-slate-500">{stringStats.uniqueCount.toLocaleString()} unique / {stringStats.totalCount.toLocaleString()} total</span>
                  </div>
                  {stringStats.topValues.length > 0 && (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <div>
                        <ResponsiveContainer width="100%" height={Math.max(200, Math.min(stringStats.topValues.length, 20) * 28)}>
                          <BarChart data={stringStats.topValues.slice(0, 20)} layout="vertical" margin={{ left: 10, right: 20 }}
                            onClick={(state: unknown) => {
                              const s = state as { activePayload?: Array<{ payload?: { value?: string } }> } | null;
                              if (s?.activePayload?.[0]?.payload?.value) addFilterFromFieldAnalysis(selectedField, s.activePayload[0].payload.value);
                            }} style={{ cursor: 'pointer' }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                            <XAxis type="number" tick={{ fontSize: 11, fill: '#94a3b8' }} />
                            <YAxis type="category" dataKey="value" tick={{ fontSize: 11, fill: '#94a3b8' }} width={150}
                              tickFormatter={(v: string) => v.length > 25 ? v.slice(0, 22) + '...' : v} />
                            <RTooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                              formatter={(val: unknown, _name: unknown, props: unknown) => {
                                const v = typeof val === 'number' ? val : 0;
                                const p = (props as { payload?: { percentage?: number } })?.payload?.percentage ?? 0;
                                return [`${v.toLocaleString()} (${p.toFixed(1)}%)`, 'Count'];
                              }} />
                            <Bar dataKey="count" name="Count" radius={[0, 4, 4, 0]}>
                              {stringStats.topValues.slice(0, 20).map((_, i) => <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} className="cursor-pointer" />)}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                      {(() => {
                        const totalValues = stringStats.topValues.length;
                        const totalPages = Math.ceil(totalValues / FIELD_STATS_PAGE_SIZE);
                        const pageStart = fieldStatsPage * FIELD_STATS_PAGE_SIZE;
                        const pageEnd = Math.min(pageStart + FIELD_STATS_PAGE_SIZE, totalValues);
                        const pageValues = stringStats.topValues.slice(pageStart, pageEnd);

                        return (
                          <div>
                            {/* Pagination header */}
                            {totalPages > 1 && (
                              <div className="flex items-center justify-between mb-2 px-1">
                                <span className="text-xs text-slate-500">
                                  Showing {pageStart + 1}–{pageEnd} of {totalValues} values
                                </span>
                                <div className="flex items-center gap-1">
                                  <button
                                    onClick={() => setFieldStatsPage(p => Math.max(0, p - 1))}
                                    disabled={fieldStatsPage === 0}
                                    className="px-2 py-1 text-xs bg-slate-700 hover:bg-slate-600 text-slate-300 rounded disabled:opacity-30 disabled:cursor-not-allowed"
                                  >
                                    ← Prev
                                  </button>
                                  <span className="text-xs text-slate-500 px-2">
                                    {fieldStatsPage + 1} / {totalPages}
                                  </span>
                                  <button
                                    onClick={() => setFieldStatsPage(p => Math.min(totalPages - 1, p + 1))}
                                    disabled={fieldStatsPage >= totalPages - 1}
                                    className="px-2 py-1 text-xs bg-slate-700 hover:bg-slate-600 text-slate-300 rounded disabled:opacity-30 disabled:cursor-not-allowed"
                                  >
                                    Next →
                                  </button>
                                </div>
                              </div>
                            )}

                            <div className="overflow-auto max-h-[600px]">
                              <table className="w-full text-sm">
                                <thead className="sticky top-0 bg-slate-800">
                                  <tr className="text-slate-400 text-xs">
                                    <th className="text-left py-2 px-3 w-12">#</th>
                                    <th className="text-left py-2 px-3">Value</th>
                                    <th className="text-right py-2 px-3 w-20">Count</th>
                                    <th className="text-right py-2 px-3 w-16">%</th>
                                    <th className="text-center py-2 px-3 w-10"></th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {pageValues.map((v, i) => (
                                    <tr key={pageStart + i} className="border-t border-slate-700/50 hover:bg-slate-700/30">
                                      <td className="py-1.5 px-3 text-slate-500">{pageStart + i + 1}</td>
                                      <td className="py-1.5 px-3 text-slate-200 font-mono text-xs break-all">{v.value}</td>
                                      <td className="py-1.5 px-3 text-right text-slate-300">{v.count.toLocaleString()}</td>
                                      <td className="py-1.5 px-3 text-right text-slate-400">{v.percentage.toFixed(1)}%</td>
                                      <td className="py-1.5 px-3 text-center">
                                        <button onClick={() => addFilterFromFieldAnalysis(selectedField, v.value)}
                                          title={`Filter by ${selectedField} = "${v.value}"`}
                                          className="p-1 text-slate-500 hover:text-blue-400 hover:bg-blue-500/10 rounded transition-colors">
                                          <Filter className="w-3.5 h-3.5" />
                                        </button>
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>

                            {/* Pagination footer */}
                            {totalPages > 1 && (
                              <div className="flex items-center justify-center gap-1 mt-2">
                                {Array.from({ length: Math.min(totalPages, 10) }, (_, i) => {
                                  // Show first few, current area, last few
                                  const page = totalPages <= 10 ? i
                                    : i < 3 ? i
                                    : i === 3 && fieldStatsPage > 4 ? -1 // ellipsis
                                    : i < 7 ? Math.max(3, fieldStatsPage - 1) + (i - 3)
                                    : i === 7 && fieldStatsPage < totalPages - 4 ? -1
                                    : totalPages - (10 - i);
                                  if (page === -1) return <span key={i} className="text-xs text-slate-600 px-1">...</span>;
                                  if (page < 0 || page >= totalPages) return null;
                                  return (
                                    <button key={i} onClick={() => setFieldStatsPage(page)}
                                      className={`w-7 h-7 text-xs rounded ${fieldStatsPage === page ? 'bg-blue-600 text-white' : 'bg-slate-700 text-slate-400 hover:bg-slate-600'}`}>
                                      {page + 1}
                                    </button>
                                  );
                                })}
                              </div>
                            )}
                          </div>
                        );
                      })()}
                    </div>
                  )}
                </div>
              )}

              {/* ── Breakdown Results ─────────────────────────── */}
              {breakdownResult && breakdownResult.entries.length > 0 && (
                <div className="mt-6 border-t border-slate-700 pt-5">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <Hash className="w-4 h-4 text-emerald-400" />
                      <span className="text-sm font-medium text-slate-200">Breakdown: {breakdownResult.primaryLabel}</span>
                      <span className="text-xs text-slate-500">by {breakdownResult.breakdownFields.map(f => f.label).join(', ')}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <button onClick={() => exportBreakdownAsCSV(breakdownResult)}
                        className="flex items-center gap-1 px-2 py-1 text-xs bg-slate-700 hover:bg-slate-600 text-slate-300 rounded transition-colors" title="Export CSV">
                        <FileSpreadsheet className="w-3 h-3" /> CSV
                      </button>
                      <button onClick={() => exportBreakdownAsExcel(breakdownResult)}
                        className="flex items-center gap-1 px-2 py-1 text-xs bg-slate-700 hover:bg-slate-600 text-slate-300 rounded transition-colors" title="Export Excel">
                        <Download className="w-3 h-3" /> Excel
                      </button>
                      <button onClick={() => exportBreakdownAsPDF(breakdownResult)}
                        className="flex items-center gap-1 px-2 py-1 text-xs bg-slate-700 hover:bg-slate-600 text-slate-300 rounded transition-colors" title="Export PDF">
                        <FileJson className="w-3 h-3" /> PDF
                      </button>
                    </div>
                  </div>
                  <div className="overflow-auto max-h-[700px]">
                    <table className="w-full text-sm">
                      <thead className="sticky top-0 bg-slate-800 z-10">
                        <tr className="text-slate-400 text-xs">
                          <th className="text-left py-2 px-3 w-8"></th>
                          <th className="text-left py-2 px-3">{breakdownResult.primaryLabel}</th>
                          <th className="text-right py-2 px-3">Count</th>
                          {breakdownResult.breakdownFields.map(bf => (
                            <th key={bf.key} className="text-right py-2 px-3">Unique {bf.label}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {breakdownResult.entries.map((entry) => {
                          const isExpanded = expandedPrimary.has(entry.primaryValue);
                          return (
                            <BreakdownRow
                              key={entry.primaryValue}
                              entry={entry}
                              breakdownFields={breakdownResult.breakdownFields}
                              isExpanded={isExpanded}
                              onToggle={() => {
                                setExpandedPrimary(prev => {
                                  const next = new Set(prev);
                                  if (next.has(entry.primaryValue)) next.delete(entry.primaryValue);
                                  else next.add(entry.primaryValue);
                                  return next;
                                });
                              }}
                            />
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── Raw Data Table ──────────────────────────────── */}
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl mb-6">
            <button onClick={() => setShowTable(!showTable)}
              className="w-full flex items-center justify-between px-5 py-3 text-sm font-semibold text-slate-300 hover:text-slate-100">
              <span className="flex items-center gap-2"><Table className="w-4 h-4" /> Raw Data ({filteredLogs.length.toLocaleString()} rows)</span>
              {showTable ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
            {showTable && (
              <div className="border-t border-slate-700">
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead className="sticky top-0 bg-slate-800">
                      <tr>
                        {tableCols.map(col => (
                          <th key={col} onClick={() => {
                            if (sortField === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
                            else { setSortField(col); setSortDir('asc'); }
                          }} className="text-left py-2 px-3 text-slate-400 cursor-pointer hover:text-slate-200 whitespace-nowrap select-none"
                            title={`${FIELD_DEFINITIONS.find(f => f.key === col)?.label || col} (${col}) — click to sort`}>
                            {FIELD_DEFINITIONS.find(f => f.key === col)?.label || col}
                            {sortField === col && (sortDir === 'asc' ? ' ▲' : ' ▼')}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {tableRows.map((row, i) => (
                        <tr key={i} className="border-t border-slate-700/50 hover:bg-slate-700/30">
                          {tableCols.map(col => {
                            const val = (row as Record<string, unknown>)[col];
                            const display = val === undefined || val === null ? '' : String(val);
                            return <td key={col} className="py-1.5 px-3 text-slate-300 whitespace-nowrap max-w-[200px] truncate font-mono" title={display}>
                              {display}
                            </td>;
                          })}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {pageCount > 1 && (
                  <div className="flex items-center justify-between px-5 py-3 border-t border-slate-700">
                    <span className="text-xs text-slate-500">Page {tablePage + 1} of {pageCount}</span>
                    <div className="flex gap-1">
                      <button onClick={() => setTablePage(p => Math.max(0, p - 1))} disabled={tablePage === 0}
                        className="px-3 py-1 text-xs bg-slate-700 hover:bg-slate-600 text-slate-300 rounded disabled:opacity-50">Prev</button>
                      <button onClick={() => setTablePage(p => Math.min(pageCount - 1, p + 1))} disabled={tablePage >= pageCount - 1}
                        className="px-3 py-1 text-xs bg-slate-700 hover:bg-slate-600 text-slate-300 rounded disabled:opacity-50">Next</button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </>
      )}
    </main>
  );
}

// ═══════════════════════════════════════════════════════════════════
// UTILS
// ═══════════════════════════════════════════════════════════════════

function formatNum(v: number): string {
  if (!isFinite(v)) return '0';
  if (Number.isInteger(v)) return v.toLocaleString();
  if (Math.abs(v) < 0.001 && v !== 0) return v.toExponential(2);
  return parseFloat(v.toFixed(3)).toLocaleString();
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
