// ═══════════════════════════════════════════════════════════════════════════
// API Report Dashboard – Namespace & per-LB API discovery stats, swagger
// spec parsing, detailed endpoint data, and consolidated Excel export.
// ═══════════════════════════════════════════════════════════════════════════

import { useState, useEffect, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowLeft, BarChart2, Loader2, Play, Search,
  ChevronDown, FileSpreadsheet,
  Globe, Layers, Database, Eye, EyeOff, CheckSquare, Square, HelpCircle,
} from 'lucide-react';
import { apiClient } from '../services/api';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import { ConnectionPanel } from '../components/ConnectionPanel';
import type { Namespace, LoadBalancer } from '../types';
import {
  runFullReport,
  exportAsExcel,
} from '../services/api-report';
import type {
  ApiReportResults,
  FetchProgress,
} from '../services/api-report';
import { COLUMN_KEYS } from '../services/api-report';

// ─── SearchableSelect ────────────────────────────────────────────────────────

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

  const filtered = options.filter(o =>
    o.label.toLowerCase().includes(filter.toLowerCase())
  );

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
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" />
              <input
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                className="w-full pl-7 pr-3 py-1.5 bg-slate-700 rounded text-sm text-slate-200 placeholder-slate-500 outline-none"
                placeholder="Filter..."
                autoFocus
              />
            </div>
          </div>
          <div className="max-h-48 overflow-y-auto">
            {filtered.map(o => (
              <button
                key={o.value}
                onClick={() => { onChange(o.value); setIsOpen(false); setFilter(''); }}
                className={`w-full text-left px-3 py-2 text-sm hover:bg-slate-700 ${
                  o.value === value ? 'bg-slate-700 text-blue-400' : 'text-slate-300'
                }`}
              >
                {o.label}
              </button>
            ))}
            {filtered.length === 0 && (
              <div className="px-3 py-4 text-center text-xs text-slate-500">No results</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Stat Card ───────────────────────────────────────────────────────────────

function StatCard({ label, value, icon: Icon, color }: {
  label: string; value: number | string; icon: typeof Globe; color: string;
}) {
  const colorMap: Record<string, string> = {
    blue: 'bg-blue-500/10 border-blue-500/30 text-blue-400',
    emerald: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
    amber: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
    red: 'bg-red-500/10 border-red-500/30 text-red-400',
    violet: 'bg-violet-500/10 border-violet-500/30 text-violet-400',
    cyan: 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400',
  };
  return (
    <div className={`px-4 py-3 rounded-xl border ${colorMap[color] || colorMap.blue}`}>
      <div className="flex items-center gap-2 mb-1">
        <Icon className="w-4 h-4" />
        <span className="text-xs font-medium text-slate-400">{label}</span>
      </div>
      <div className="text-2xl font-bold">{value}</div>
    </div>
  );
}

// ─── Time Range Options ──────────────────────────────────────────────────────

const TIME_RANGES = [
  { label: '7 days', value: 7 },
  { label: '14 days', value: 14 },
  { label: '30 days', value: 30 },
  { label: '60 days', value: 60 },
  { label: '90 days', value: 90 },
];

// ─── Main Component ──────────────────────────────────────────────────────────

export function APIReport() {
  const { isConnected } = useApp();
  const toast = useToast();

  // Step 1: Configuration
  const [namespaces, setNamespaces] = useState<Namespace[]>([]);
  const [selectedNs, setSelectedNs] = useState('');
  const [loadBalancers, setLoadBalancers] = useState<LoadBalancer[]>([]);
  const [selectedLBs, setSelectedLBs] = useState<Set<string>>(new Set());
  const [timeRange, setTimeRange] = useState(30);
  const [loadingNs, setLoadingNs] = useState(false);
  const [loadingLBs, setLoadingLBs] = useState(false);

  // Step 2: Running
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<FetchProgress | null>(null);
  const cancelledRef = useRef(false);

  // Step 3: Results
  const [results, setResults] = useState<ApiReportResults | null>(null);
  const [activeTab, setActiveTab] = useState<'stats' | 'swagger' | 'endpoints'>('stats');
  const [searchFilter, setSearchFilter] = useState('');
  const [exporting, setExporting] = useState(false);

  // ─── Load namespaces ─────────────────────────────────────────────────────
  useEffect(() => {
    if (!isConnected) return;
    setLoadingNs(true);
    apiClient.getNamespaces()
      .then(res => setNamespaces(res.items || []))
      .catch(() => toast.error('Failed to load namespaces'))
      .finally(() => setLoadingNs(false));
  }, [isConnected]);

  // ─── Load LBs when namespace changes ─────────────────────────────────────
  useEffect(() => {
    if (!selectedNs) { setLoadBalancers([]); setSelectedLBs(new Set()); return; }
    setLoadingLBs(true);
    setSelectedLBs(new Set());
    apiClient.getLoadBalancers(selectedNs)
      .then(res => setLoadBalancers(res.items || []))
      .catch(() => toast.error('Failed to load load balancers'))
      .finally(() => setLoadingLBs(false));
  }, [selectedNs]);

  // ─── LB selection helpers ────────────────────────────────────────────────
  const toggleLB = useCallback((name: string) => {
    setSelectedLBs(prev => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name); else next.add(name);
      return next;
    });
  }, []);

  const selectAll = useCallback(() => {
    setSelectedLBs(new Set(loadBalancers.map(lb => lb.metadata?.name || lb.name)));
  }, [loadBalancers]);

  const deselectAll = useCallback(() => setSelectedLBs(new Set()), []);

  // ─── Run Report ──────────────────────────────────────────────────────────
  const handleRun = useCallback(async () => {
    if (!selectedNs || selectedLBs.size === 0) return;
    setRunning(true);
    setResults(null);
    cancelledRef.current = false;

    try {
      const lbNames = Array.from(selectedLBs);
      const report = await runFullReport(selectedNs, lbNames, timeRange, (p) => {
        if (!cancelledRef.current) setProgress(p);
      });
      if (!cancelledRef.current) {
        setResults(report);
        toast.success(`Report generated for ${lbNames.length} load balancer(s)`);
      }
    } catch (err: unknown) {
      toast.error(`Report failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setRunning(false);
      setProgress(null);
    }
  }, [selectedNs, selectedLBs, timeRange, toast]);

  // ─── Export ──────────────────────────────────────────────────────────────
  const handleExport = useCallback(async () => {
    if (!results) return;
    setExporting(true);
    try {
      await exportAsExcel(results, selectedNs);
      toast.success('Excel report downloaded');
    } catch {
      toast.error('Export failed');
    } finally {
      setExporting(false);
    }
  }, [results, selectedNs, toast]);

  // ─── Detect API Discovery status from LB spec ───────────────────────────
  const hasApiDiscovery = (lb: LoadBalancer): boolean => {
    const spec = (lb as any).spec || (lb as any).get_spec;
    return spec ? !!spec.enable_api_discovery && !spec.disable_api_discovery : false;
  };

  // ─── Filtered data for current tab ───────────────────────────────────────
  const filteredSwagger = results?.swaggerEndpoints.filter(e =>
    !searchFilter ||
    e.lb.toLowerCase().includes(searchFilter.toLowerCase()) ||
    e.path.toLowerCase().includes(searchFilter.toLowerCase()) ||
    e.fqdn.toLowerCase().includes(searchFilter.toLowerCase())
  ) ?? [];

  const filteredEndpoints = results?.endpointRows.filter(r =>
    !searchFilter ||
    Object.values(r).some(v => String(v).toLowerCase().includes(searchFilter.toLowerCase()))
  ) ?? [];

  // ─── Progress stats ──────────────────────────────────────────────────────
  const totalPhases = selectedLBs.size * 3; // stats + swagger + endpoints
  const currentPhaseOffset = progress
    ? (progress.phase === 'stats' ? 0 : progress.phase === 'swagger' ? selectedLBs.size : selectedLBs.size * 2)
    : 0;
  const progressPercent = progress
    ? Math.round(((currentPhaseOffset + progress.current) / totalPhases) * 100)
    : 0;

  // ─── RENDER ──────────────────────────────────────────────────────────────

  if (!isConnected) {
    return (
      <div className="max-w-7xl mx-auto px-6 py-8">
        <ConnectionPanel />
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-6 py-8 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link to="/" className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <div className="flex items-center gap-3">
          <div className="p-2 bg-violet-500/15 rounded-lg">
            <BarChart2 className="w-5 h-5 text-violet-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-100">API Report Dashboard</h1>
            <p className="text-sm text-slate-400">API discovery stats, learnt schema, and detailed endpoint report</p>
          </div>
        </div>
        <Link to="/explainer/api-report" className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-400 hover:text-blue-400 rounded-lg text-xs transition-colors">
          <HelpCircle className="w-3.5 h-3.5" /> How does this work?
        </Link>
      </div>

      {/* Step 1: Configuration */}
      <section className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 space-y-4">
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Configuration</h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <SearchableSelect
            label="Namespace"
            options={namespaces.map(n => ({ value: n.name, label: n.name }))}
            value={selectedNs}
            onChange={setSelectedNs}
            placeholder={loadingNs ? 'Loading...' : 'Select namespace'}
            disabled={loadingNs || running}
          />

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Time Range</label>
            <div className="flex gap-1">
              {TIME_RANGES.map(t => (
                <button
                  key={t.value}
                  onClick={() => setTimeRange(t.value)}
                  disabled={running}
                  className={`px-3 py-2 text-xs rounded-lg border transition-colors disabled:opacity-50 ${
                    timeRange === t.value
                      ? 'bg-blue-500/20 border-blue-500/40 text-blue-400'
                      : 'bg-slate-800 border-slate-600 text-slate-400 hover:border-slate-500'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-end gap-2">
            <button
              onClick={handleRun}
              disabled={running || !selectedNs || selectedLBs.size === 0}
              className="flex items-center gap-2 px-5 py-2 bg-blue-500 hover:bg-blue-600 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {running ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              {running ? 'Running...' : 'Generate Report'}
            </button>
            {results && (
              <button
                onClick={handleExport}
                disabled={exporting}
                className="flex items-center gap-2 px-4 py-2 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 text-sm font-medium rounded-lg border border-emerald-500/30 transition-colors disabled:opacity-50"
              >
                {exporting ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileSpreadsheet className="w-4 h-4" />}
                Export Excel
              </button>
            )}
          </div>
        </div>

        {/* LB Selection */}
        {selectedNs && (
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-medium text-slate-400">
                Load Balancers {loadingLBs ? '(loading...)' : `(${selectedLBs.size}/${loadBalancers.length} selected)`}
              </label>
              <div className="flex gap-2">
                <button onClick={selectAll} disabled={running || loadingLBs} className="text-xs text-blue-400 hover:text-blue-300 disabled:opacity-50">Select All</button>
                <span className="text-slate-600">|</span>
                <button onClick={deselectAll} disabled={running || loadingLBs} className="text-xs text-slate-400 hover:text-slate-300 disabled:opacity-50">Clear</button>
              </div>
            </div>

            {loadingLBs ? (
              <div className="flex items-center gap-2 py-4 text-slate-500 text-sm">
                <Loader2 className="w-4 h-4 animate-spin" /> Loading load balancers...
              </div>
            ) : loadBalancers.length === 0 ? (
              <div className="py-4 text-center text-sm text-slate-500">No HTTP load balancers in this namespace</div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 max-h-60 overflow-y-auto pr-1">
                {loadBalancers.map(lb => {
                  const name = lb.metadata?.name || lb.name;
                  const selected = selectedLBs.has(name);
                  const apid = hasApiDiscovery(lb);
                  return (
                    <button
                      key={name}
                      onClick={() => toggleLB(name)}
                      disabled={running}
                      className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-left text-sm transition-colors disabled:opacity-50 ${
                        selected
                          ? 'bg-blue-500/10 border-blue-500/40 text-blue-300'
                          : 'bg-slate-800/50 border-slate-700 text-slate-400 hover:border-slate-600'
                      }`}
                    >
                      {selected
                        ? <CheckSquare className="w-4 h-4 text-blue-400 shrink-0" />
                        : <Square className="w-4 h-4 text-slate-600 shrink-0" />
                      }
                      <span className="truncate flex-1">{name}</span>
                      {apid ? (
                        <span className="px-1.5 py-0.5 text-[10px] rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 shrink-0">APID</span>
                      ) : (
                        <span className="px-1.5 py-0.5 text-[10px] rounded bg-slate-700/50 text-slate-500 border border-slate-600 shrink-0">No APID</span>
                      )}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </section>

      {/* Progress */}
      {running && progress && (
        <section className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2 text-sm text-slate-300">
              <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
              {progress.message}
            </div>
            <span className="text-xs text-slate-500">{progressPercent}%</span>
          </div>
          <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-blue-500 to-cyan-500 transition-all duration-300"
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        </section>
      )}

      {/* Results */}
      {results && (
        <>
          {/* Summary Cards — aggregated from selected LBs */}
          {results.lbStats.length > 0 && (() => {
            const agg = results.lbStats.reduce((a, s) => ({
              total_endpoints: a.total_endpoints + s.total_endpoints,
              discovered: a.discovered + s.discovered,
              inventory: a.inventory + s.inventory,
              shadow: a.shadow + s.shadow,
              pii_detected: a.pii_detected + s.pii_detected,
            }), { total_endpoints: 0, discovered: 0, inventory: 0, shadow: 0, pii_detected: 0 });
            return (
              <section className="grid grid-cols-2 md:grid-cols-5 gap-3">
                <StatCard label="Total Endpoints" value={agg.total_endpoints} icon={Globe} color="blue" />
                <StatCard label="Discovered" value={agg.discovered} icon={Eye} color="emerald" />
                <StatCard label="Inventory" value={agg.inventory} icon={Database} color="cyan" />
                <StatCard label="Shadow" value={agg.shadow} icon={EyeOff} color="amber" />
                <StatCard label="PII Detected" value={agg.pii_detected} icon={Layers} color="red" />
              </section>
            );
          })()}

          {/* Tabs */}
          <section className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-700 px-4">
              <div className="flex">
                {([
                  { key: 'stats' as const, label: 'LB Stats', count: results.lbStats.length },
                  { key: 'swagger' as const, label: 'Learnt Schema', count: results.swaggerEndpoints.length },
                  { key: 'endpoints' as const, label: 'API Endpoints', count: results.endpointRows.length },
                ]).map(tab => (
                  <button
                    key={tab.key}
                    onClick={() => setActiveTab(tab.key)}
                    className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                      activeTab === tab.key
                        ? 'border-blue-400 text-blue-400'
                        : 'border-transparent text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {tab.label}
                    <span className="ml-1.5 px-1.5 py-0.5 rounded text-[10px] bg-slate-700 text-slate-400">{tab.count}</span>
                  </button>
                ))}
              </div>

              {(activeTab === 'swagger' || activeTab === 'endpoints') && (
                <div className="relative">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
                  <input
                    value={searchFilter}
                    onChange={(e) => setSearchFilter(e.target.value)}
                    className="pl-8 pr-3 py-1.5 bg-slate-700/50 border border-slate-600 rounded-lg text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-slate-500 w-56"
                    placeholder="Filter..."
                  />
                </div>
              )}
            </div>

            {/* Stats Tab */}
            {activeTab === 'stats' && (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-slate-700/30">
                      <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase">Load Balancer</th>
                      <th className="px-4 py-3 text-right text-xs font-medium text-slate-400 uppercase">Total</th>
                      <th className="px-4 py-3 text-right text-xs font-medium text-slate-400 uppercase">Discovered</th>
                      <th className="px-4 py-3 text-right text-xs font-medium text-slate-400 uppercase">Inventory</th>
                      <th className="px-4 py-3 text-right text-xs font-medium text-slate-400 uppercase">Shadow</th>
                      <th className="px-4 py-3 text-right text-xs font-medium text-slate-400 uppercase">PII</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.lbStats.map((s, i) => (
                      <tr key={i} className="border-t border-slate-700/50 hover:bg-slate-700/20">
                        <td className="px-4 py-3 text-slate-200 font-mono text-xs">{s.scope}</td>
                        <td className="px-4 py-3 text-right text-slate-300">{s.total_endpoints}</td>
                        <td className="px-4 py-3 text-right text-emerald-400">{s.discovered}</td>
                        <td className="px-4 py-3 text-right text-cyan-400">{s.inventory}</td>
                        <td className="px-4 py-3 text-right text-amber-400">{s.shadow}</td>
                        <td className="px-4 py-3 text-right text-red-400">{s.pii_detected}</td>
                      </tr>
                    ))}
                    {results.lbStats.length === 0 && (
                      <tr><td colSpan={6} className="px-4 py-8 text-center text-slate-500">No stats available</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {/* Swagger Tab */}
            {activeTab === 'swagger' && (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-slate-700/30">
                      <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase">Load Balancer</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase">FQDN</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase">API Endpoint</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase">Method</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase">Content Type</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredSwagger.map((e, i) => (
                      <tr key={i} className="border-t border-slate-700/50 hover:bg-slate-700/20">
                        <td className="px-4 py-2.5 text-slate-300 font-mono text-xs">{e.lb}</td>
                        <td className="px-4 py-2.5 text-cyan-400 text-xs max-w-xs truncate">{e.fqdn}</td>
                        <td className="px-4 py-2.5 text-slate-200 font-mono text-xs">{e.path}</td>
                        <td className="px-4 py-2.5">
                          <MethodBadge method={e.method} />
                        </td>
                        <td className="px-4 py-2.5 text-slate-400 text-xs">{e.contentType}</td>
                      </tr>
                    ))}
                    {filteredSwagger.length === 0 && (
                      <tr><td colSpan={5} className="px-4 py-8 text-center text-slate-500">No swagger specs available</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {/* Endpoints Tab */}
            {activeTab === 'endpoints' && (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-slate-700/30">
                      <th className="px-3 py-3 text-left text-xs font-medium text-slate-400 uppercase whitespace-nowrap">LB</th>
                      {COLUMN_KEYS.map(col => (
                        <th key={col} className="px-3 py-3 text-left text-xs font-medium text-slate-400 uppercase whitespace-nowrap">{col}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEndpoints.slice(0, 500).map((row, i) => (
                      <tr key={i} className="border-t border-slate-700/50 hover:bg-slate-700/20">
                        <td className="px-3 py-2 text-slate-300 font-mono text-xs whitespace-nowrap">{row.lb}</td>
                        {COLUMN_KEYS.map(col => (
                          <td key={col} className="px-3 py-2 text-slate-300 text-xs max-w-[200px] truncate" title={String(row[col] ?? '')}>
                            {col === 'Method' ? <MethodBadge method={String(row[col] ?? '-')} /> : String(row[col] ?? '—')}
                          </td>
                        ))}
                      </tr>
                    ))}
                    {filteredEndpoints.length === 0 && (
                      <tr><td colSpan={COLUMN_KEYS.length + 1} className="px-4 py-8 text-center text-slate-500">No endpoint data available</td></tr>
                    )}
                    {filteredEndpoints.length > 500 && (
                      <tr><td colSpan={COLUMN_KEYS.length + 1} className="px-4 py-3 text-center text-xs text-slate-500">
                        Showing 500 of {filteredEndpoints.length} rows. Export to Excel for the full dataset.
                      </td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}

// ─── HTTP Method Badge ───────────────────────────────────────────────────────

function MethodBadge({ method }: { method: string }) {
  const m = method.toUpperCase();
  const colorMap: Record<string, string> = {
    GET: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    POST: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
    PUT: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    DELETE: 'bg-red-500/15 text-red-400 border-red-500/30',
    PATCH: 'bg-violet-500/15 text-violet-400 border-violet-500/30',
  };
  const cls = colorMap[m] || 'bg-slate-700 text-slate-400 border-slate-600';
  return (
    <span className={`px-1.5 py-0.5 text-[10px] font-medium rounded border ${cls}`}>{m}</span>
  );
}
