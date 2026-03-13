// ═══════════════════════════════════════════════════════════════════════════
// Log Analyzer — General-purpose access log analytics dashboard
// ═══════════════════════════════════════════════════════════════════════════

import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowLeft, BarChart2, Loader2, Play, Search,
  ChevronDown, ChevronUp, Plus, X,
  Hash, Type, Filter, Table, FileJson, FileSpreadsheet,
  AlertTriangle, Zap, Shield, Users,
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
  type TimePeriod, type QueryFilter, type ClientFilter,
  type LogCollectionProgress, type NumericFieldStats, type StringFieldStats,
  type LogSummary, type AccessLogEntry,
  type ErrorAnalysis, type PerformanceAnalysis, type SecurityInsights,
  type TopTalker, type StatusTimeSeriesPoint,
  TIME_PERIOD_HOURS, TIME_PERIOD_LABELS,
  FIELD_DEFINITIONS, PRE_FETCH_FILTER_FIELDS, FIELD_GROUP_LABELS,
  collectLogs, buildQuery, probeLogs,
  computeNumericStats, computeStringStats, computeBooleanStats,
  computeSummary, applyClientFilters,
  computeErrorAnalysis, computePerformanceAnalysis,
  computeSecurityInsights, computeTopTalkers, buildStatusTimeSeries,
  exportAsJSON, exportAsCSV,
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
                <td key={j} className={`py-1.5 px-3 ${j === 0 ? 'text-left text-slate-200 font-mono break-all max-w-[250px]' : 'text-right text-slate-300 whitespace-nowrap'}`}>
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
  const [timePeriod, setTimePeriod] = useState<TimePeriod>('24h');
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

  useEffect(() => {
    if (!selectedNs) return;
    const endTime = new Date().toISOString();
    const startTime = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    probeLogs(selectedNs, '{}', startTime, endTime, 100)
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
  }, [selectedNs]);

  const filteredLogs = useMemo(() => applyClientFilters(logs, clientFilters), [logs, clientFilters]);

  // Recompute all insights when filtered logs change
  useEffect(() => {
    if (filteredLogs.length === 0 && !showResults) return;
    setSummary(computeSummary(filteredLogs));
    setStatusTimeSeries(buildStatusTimeSeries(filteredLogs, TIME_PERIOD_HOURS[timePeriod]));
    setErrorAnalysis(computeErrorAnalysis(filteredLogs));
    setPerfAnalysis(computePerformanceAnalysis(filteredLogs));
    setSecurityInsights(computeSecurityInsights(filteredLogs));
    setTopTalkers(computeTopTalkers(filteredLogs, 25));
  }, [filteredLogs, showResults, timePeriod]);

  // Field analysis
  useEffect(() => {
    if (filteredLogs.length === 0) return;
    const def = FIELD_DEFINITIONS.find(f => f.key === selectedField);
    if (!def) return;
    if (def.type === 'numeric') {
      setNumericStats(computeNumericStats(filteredLogs, selectedField));
      setStringStats(null);
    } else if (def.type === 'boolean') {
      setStringStats(computeBooleanStats(filteredLogs, selectedField));
      setNumericStats(null);
    } else {
      setStringStats(computeStringStats(filteredLogs, selectedField));
      setNumericStats(null);
    }
  }, [filteredLogs, selectedField]);

  // ═══════════════════════════════════════════════════════════════
  // ACTIONS
  // ═══════════════════════════════════════════════════════════════

  const handleAnalyze = useCallback(async () => {
    if (!selectedNs || isRunning) return;
    setIsRunning(true);
    setShowResults(false);
    setLogs([]);
    setClientFilters([]);
    setTablePage(0);
    setActiveTab('overview');

    const endTime = new Date().toISOString();
    const startTime = new Date(Date.now() - TIME_PERIOD_HOURS[timePeriod] * 60 * 60 * 1000).toISOString();
    const query = buildQuery(preFetchFilters);

    try {
      const result = await collectLogs(selectedNs, query, startTime, endTime, setProgress);
      setLogs(result);
      setShowResults(true);
      toast.success(`Fetched ${result.length.toLocaleString()} access logs`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setProgress(p => ({ ...p, phase: 'error', error: msg }));
      toast.error(`Failed: ${msg}`);
    } finally {
      setIsRunning(false);
    }
  }, [selectedNs, isRunning, timePeriod, preFetchFilters, toast]);

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

  const groupedFields = useMemo(() => {
    const groups: Record<string, Array<{ key: string; label: string; type: string }>> = {};
    for (const f of FIELD_DEFINITIONS) {
      if (!groups[f.group]) groups[f.group] = [];
      groups[f.group].push({ key: f.key, label: f.label, type: f.type });
    }
    return groups;
  }, []);

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
            <p className="text-sm text-slate-400 mt-1">Access log analytics — errors, performance, security, and field-level insights</p>
          </div>
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
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <SearchableSelect label="Namespace" options={namespaces.map(ns => ({ value: ns.name, label: ns.name }))} value={selectedNs}
            onChange={v => { setSelectedNs(v); setPreFetchFilters([]); setShowResults(false); setLogs([]); }} placeholder="Select namespace..." />
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
                {PRE_FETCH_FILTER_FIELDS.map(f => <option key={f} value={f}>{FIELD_DEFINITIONS.find(d => d.key === f)?.label || f}</option>)}
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
          {isRunning ? <><Loader2 className="w-5 h-5 animate-spin" /> Fetching Logs...</> : <><Play className="w-5 h-5" /> Analyze Logs — {TIME_PERIOD_LABELS[timePeriod]}</>}
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
            <StatCard label="Avg Duration" value={`${summary.avgDurationMs.toFixed(1)}ms`} />
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
                      {FIELD_DEFINITIONS.map(f => <option key={f.key} value={f.key}>{f.label}</option>)}
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
              {errorAnalysis && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
                  <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                    <h4 className="text-xs font-semibold text-slate-400 mb-3">Response Code Distribution</h4>
                    {errorAnalysis.byCode.slice(0, 8).map((c, i) => (
                      <div key={i} className="flex items-center justify-between py-1">
                        <button onClick={() => addFilterFromFieldAnalysis('rsp_code', c.code)} className="text-sm text-slate-200 hover:text-blue-400 font-mono">{c.code}</button>
                        <div className="flex items-center gap-2">
                          <div className="w-24 bg-slate-700 rounded-full h-1.5"><div className="h-1.5 rounded-full bg-blue-500" style={{ width: `${c.pct}%` }} /></div>
                          <span className="text-xs text-slate-400 w-16 text-right">{c.count.toLocaleString()}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                    <h4 className="text-xs font-semibold text-slate-400 mb-3">Response Details</h4>
                    {errorAnalysis.byDetail.slice(0, 8).map((d, i) => (
                      <div key={i} className="flex items-center justify-between py-1">
                        <button onClick={() => addFilterFromFieldAnalysis('rsp_code_details', d.detail)} className="text-sm text-slate-200 hover:text-blue-400 font-mono truncate max-w-[180px]">{d.detail}</button>
                        <span className="text-xs text-slate-400 ml-2">{d.count.toLocaleString()}</span>
                      </div>
                    ))}
                  </div>
                  <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                    <h4 className="text-xs font-semibold text-slate-400 mb-3">Response Flags (Infrastructure)</h4>
                    {errorAnalysis.byResponseFlag.slice(0, 8).map((f, i) => (
                      <div key={i} className="flex items-center justify-between py-1">
                        <span className="text-sm text-slate-200 font-mono truncate max-w-[200px]">{f.flag}</span>
                        <span className="text-xs text-slate-400 ml-2">{f.count.toLocaleString()} ({f.pct.toFixed(1)}%)</span>
                      </div>
                    ))}
                  </div>
                </div>
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
              <div className="mb-4">
                <select value={selectedField} onChange={e => setSelectedField(e.target.value)}
                  className="w-full md:w-80 px-3 py-2 bg-slate-900 border border-slate-600 rounded-lg text-sm text-slate-200">
                  {Object.entries(groupedFields).map(([group, fields]) => (
                    <optgroup key={group} label={FIELD_GROUP_LABELS[group] || group}>
                      {fields.map(f => <option key={f.key} value={f.key}>{f.label}</option>)}
                    </optgroup>
                  ))}
                </select>
              </div>

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
                      <div className="overflow-auto max-h-[500px]">
                        <table className="w-full text-sm">
                          <thead className="sticky top-0 bg-slate-800">
                            <tr className="text-slate-400 text-xs">
                              <th className="text-left py-2 px-3">#</th>
                              <th className="text-left py-2 px-3">Value</th>
                              <th className="text-right py-2 px-3">Count</th>
                              <th className="text-right py-2 px-3">%</th>
                              <th className="text-center py-2 px-3 w-10"></th>
                            </tr>
                          </thead>
                          <tbody>
                            {stringStats.topValues.map((v, i) => (
                              <tr key={i} className="border-t border-slate-700/50 hover:bg-slate-700/30">
                                <td className="py-1.5 px-3 text-slate-500">{i + 1}</td>
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
                    </div>
                  )}
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
                          }} className="text-left py-2 px-3 text-slate-400 cursor-pointer hover:text-slate-200 whitespace-nowrap select-none">
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
                            return <td key={col} className="py-1.5 px-3 text-slate-300 whitespace-nowrap max-w-[200px] truncate font-mono">
                              {val === undefined || val === null ? '' : String(val)}
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
