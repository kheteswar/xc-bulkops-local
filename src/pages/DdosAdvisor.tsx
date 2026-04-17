// ═══════════════════════════════════════════════════════════════════════════
// DDoS Settings Advisor - Analyze traffic and recommend L7 DDoS protection
// settings based on actual traffic patterns and security best practices.
// ═══════════════════════════════════════════════════════════════════════════

import { useState, useEffect, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowLeft, Shield, Loader2, Play, Search,
  ChevronDown, ChevronUp, AlertTriangle, CheckCircle,
  XCircle, Download, Copy, Check, Zap,
  Activity, Server, HelpCircle,
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import html2canvas from 'html2canvas';
import { apiClient } from '../services/api';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import { ConnectionPanel } from '../components/ConnectionPanel';
import type { Namespace, LoadBalancer } from '../types';
import {
  assessCurrentConfig,
  analyzeFromScan,
  generateRpsRecommendations,
  generateFindings,
  generateRecommendedConfig,
  generateDdosPdfReport,
  scanTraffic,
} from '../services/ddos-advisor';
import type {
  TimePeriod,
  DdosAnalysisProgress,
  DdosAnalysisResults,
  DdosFinding,
  SeverityLevel,
  ScanProgress,
} from '../services/ddos-advisor';
import { TIME_PERIOD_HOURS, TIME_PERIOD_LABELS } from '../services/ddos-advisor';

// ─── Inline SearchableSelect (single) ────────────────────────────────────────

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
            <div className="flex items-center gap-2 px-2 py-1 bg-slate-900 rounded">
              <Search className="w-3 h-3 text-slate-500" />
              <input
                type="text"
                value={filter}
                onChange={e => setFilter(e.target.value)}
                placeholder="Filter..."
                className="bg-transparent text-sm text-slate-200 outline-none w-full"
                autoFocus
              />
            </div>
          </div>
          <div className="max-h-48 overflow-y-auto">
            {filtered.map(o => (
              <button
                key={o.value}
                onClick={() => { onChange(o.value); setIsOpen(false); setFilter(''); }}
                className={`w-full text-left px-3 py-2 text-sm hover:bg-slate-700 ${o.value === value ? 'bg-slate-700 text-blue-400' : 'text-slate-300'}`}
              >
                {o.label}
              </button>
            ))}
            {filtered.length === 0 && (
              <div className="px-3 py-4 text-sm text-slate-500 text-center">No matches</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Multi-select dropdown for Load Balancers ────────────────────────────────

function MultiSelectLb({ label, options, selected, onToggle, onSelectAll, onDeselectAll, placeholder, disabled }: {
  label: string;
  options: Array<{ value: string; label: string }>;
  selected: Set<string>;
  onToggle: (v: string) => void;
  onSelectAll: () => void;
  onDeselectAll: () => void;
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
        className="w-full flex items-center justify-between px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-sm text-slate-200 hover:border-slate-500 disabled:opacity-50 disabled:cursor-not-allowed min-h-[38px]"
      >
        <span className={selected.size > 0 ? 'text-slate-200' : 'text-slate-500'}>
          {selected.size > 0 ? `${selected.size} load balancer${selected.size > 1 ? 's' : ''} selected` : placeholder}
        </span>
        <ChevronDown className="w-4 h-4 text-slate-400" />
      </button>
      {isOpen && (
        <div className="absolute z-50 mt-1 w-full bg-slate-800 border border-slate-600 rounded-lg shadow-xl max-h-72 overflow-hidden">
          <div className="p-2 border-b border-slate-700 space-y-2">
            <div className="flex items-center gap-2 px-2 py-1 bg-slate-900 rounded">
              <Search className="w-3 h-3 text-slate-500" />
              <input
                type="text"
                value={filter}
                onChange={e => setFilter(e.target.value)}
                placeholder="Filter load balancers..."
                className="bg-transparent text-sm text-slate-200 outline-none w-full"
                autoFocus
              />
            </div>
            <div className="flex gap-2 px-1">
              <button onClick={onSelectAll} className="text-xs text-blue-400 hover:text-blue-300">Select All</button>
              <span className="text-slate-600">|</span>
              <button onClick={onDeselectAll} className="text-xs text-slate-400 hover:text-slate-300">Deselect All</button>
            </div>
          </div>
          <div className="max-h-52 overflow-y-auto">
            {filtered.map(o => (
              <button
                key={o.value}
                onClick={() => onToggle(o.value)}
                className={`w-full flex items-center gap-2 text-left px-3 py-2 text-sm hover:bg-slate-700 ${selected.has(o.value) ? 'bg-slate-700/50' : ''} text-slate-300`}
              >
                <span className={`w-4 h-4 rounded border flex items-center justify-center text-xs ${selected.has(o.value) ? 'bg-blue-600 border-blue-500 text-white' : 'border-slate-500'}`}>
                  {selected.has(o.value) && '✓'}
                </span>
                <span className="truncate">{o.label}</span>
              </button>
            ))}
            {filtered.length === 0 && (
              <div className="px-3 py-4 text-sm text-slate-500 text-center">No matches</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Helper Components ───────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: SeverityLevel }) {
  const colors: Record<SeverityLevel, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    info: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${colors[severity]}`}>
      {severity.toUpperCase()}
    </span>
  );
}

function ConfigStatusBadge({ enabled, label }: { enabled: boolean; label: string }) {
  return (
    <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${enabled ? 'bg-emerald-500/10 border-emerald-500/30' : 'bg-red-500/10 border-red-500/30'}`}>
      {enabled ? <CheckCircle className="w-4 h-4 text-emerald-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
      <span className={`text-sm font-medium ${enabled ? 'text-emerald-400' : 'text-red-400'}`}>{label}</span>
    </div>
  );
}

function FindingRow({ finding }: { finding: DdosFinding }) {
  const [expanded, setExpanded] = useState(false);
  const severityAccent: Record<SeverityLevel, string> = {
    critical: 'border-l-red-500',
    high: 'border-l-orange-500',
    medium: 'border-l-yellow-500',
    low: 'border-l-blue-500',
    info: 'border-l-slate-500',
  };
  return (
    <div className={`border-l-2 ${severityAccent[finding.severity]} ${expanded ? 'bg-slate-800/30' : ''}`}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-slate-800/50 transition-colors text-left"
      >
        <SeverityBadge severity={finding.severity} />
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-slate-200">{finding.title}</div>
          <div className="text-xs text-slate-500 mt-0.5 flex flex-wrap gap-x-4 gap-y-0.5">
            <span>Current: <span className="text-slate-400">{finding.currentValue}</span></span>
            <span>→ <span className="text-blue-400">{finding.recommendedValue}</span></span>
          </div>
        </div>
        {expanded ? <ChevronUp className="w-4 h-4 text-slate-500 shrink-0" /> : <ChevronDown className="w-4 h-4 text-slate-500 shrink-0" />}
      </button>
      {expanded && (
        <div className="px-4 pb-4 pl-[4.5rem] space-y-2">
          <p className="text-sm text-slate-300">{finding.description}</p>
          <div className="bg-slate-900/50 rounded-lg p-3">
            <div className="text-xs font-semibold text-slate-500 mb-1">Rationale</div>
            <p className="text-xs text-slate-400 leading-relaxed">{finding.rationale}</p>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main Component ──────────────────────────────────────────────────────────

export function DdosAdvisor() {
  const { isConnected } = useApp();
  const toast = useToast();

  // Config state
  const [namespaces, setNamespaces] = useState<Namespace[]>([]);
  const [selectedNs, setSelectedNs] = useState('');
  const [loadBalancers, setLoadBalancers] = useState<LoadBalancer[]>([]);
  const [selectedLbs, setSelectedLbs] = useState<Set<string>>(new Set());
  const [timePeriod, setTimePeriod] = useState<TimePeriod>('7d');
  const [customStart, setCustomStart] = useState('');
  const [customEnd, setCustomEnd] = useState('');

  // Progress state
  const [progress, setProgress] = useState<DdosAnalysisProgress>({
    phase: 'idle', message: '', progress: 0, accessLogsCount: 0, securityEventsCount: 0,
  });
  const [isRunning, setIsRunning] = useState(false);
  const [currentLbIndex, setCurrentLbIndex] = useState(0);
  const [totalLbCount, setTotalLbCount] = useState(0);

  // Results state — one per LB
  const [allResults, setAllResults] = useState<DdosAnalysisResults[]>([]);
  const [activeResultIdx, setActiveResultIdx] = useState(0);

  // UI state
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    config: true, traffic: true, findings: true, recommendations: true, generatedConfig: false,
  });
  const [copiedJson, setCopiedJson] = useState(false);

  // Chart ref for PDF
  const chartRef = useRef<HTMLDivElement>(null);

  // Load namespaces on connect
  useEffect(() => {
    if (isConnected) {
      apiClient.getNamespaces().then(data => {
        const items = ((data as any).items || []) as Namespace[];
        setNamespaces(items);
      }).catch(() => toast.error('Failed to load namespaces'));
    }
  }, [isConnected]);

  // Load LBs when namespace changes
  useEffect(() => {
    if (!selectedNs) { setLoadBalancers([]); setSelectedLbs(new Set()); return; }
    apiClient.getLoadBalancers(selectedNs).then(data => {
      const items = ((data as any).items || []) as LoadBalancer[];
      setLoadBalancers(items);
      setSelectedLbs(new Set());
    }).catch(() => toast.error('Failed to load load balancers'));
  }, [selectedNs]);

  // LB multi-select handlers
  const toggleLb = useCallback((name: string) => {
    setSelectedLbs(prev => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name); else next.add(name);
      return next;
    });
  }, []);
  const selectAllLbs = useCallback(() => {
    setSelectedLbs(new Set(loadBalancers.map(lb => lb.metadata?.name || lb.name)));
  }, [loadBalancers]);
  const deselectAllLbs = useCallback(() => setSelectedLbs(new Set()), []);

  const toggleSection = (key: string) => {
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  // ── Run Analysis (loop over all selected LBs) ──────────────────────────

  const runAnalysis = useCallback(async () => {
    if (!selectedNs || selectedLbs.size === 0) return;
    const lbNames = [...selectedLbs];
    setIsRunning(true);
    setAllResults([]);
    setActiveResultIdx(0);
    setTotalLbCount(lbNames.length);

    let endTime: string;
    let startTime: string;
    if (timePeriod === 'custom') {
      if (!customStart || !customEnd) { toast.error('Select both start and end dates'); setIsRunning(false); return; }
      startTime = new Date(customStart).toISOString();
      endTime = new Date(customEnd).toISOString();
      if (new Date(startTime) >= new Date(endTime)) { toast.error('Start date must be before end date'); setIsRunning(false); return; }
    } else {
      endTime = new Date().toISOString();
      startTime = new Date(Date.now() - TIME_PERIOD_HOURS[timePeriod] * 60 * 60 * 1000).toISOString();
    }
    const collected: DdosAnalysisResults[] = [];
    let hadError = false;

    for (let i = 0; i < lbNames.length; i++) {
      const lbName = lbNames[i];
      setCurrentLbIndex(i + 1);
      const prefix = lbNames.length > 1 ? `[${i + 1}/${lbNames.length}] ${lbName}: ` : '';

      try {
        // Phase 1: Fetch LB config
        setProgress({ phase: 'fetching_config', message: `${prefix}Fetching load balancer configuration...`, progress: 2, accessLogsCount: 0, securityEventsCount: 0 });
        const lbData = await apiClient.getLoadBalancer(selectedNs, lbName) as any;
        const spec = lbData?.spec || lbData?.object?.spec || {};
        const domains = spec.domains || [];
        const currentConfig = assessCurrentConfig(spec);

        // Phase 2-4: Traffic scan (hourly probes + aggregation + small sample)
        const scanResult = await scanTraffic(selectedNs, lbName, startTime, endTime, (p: ScanProgress) => {
          setProgress({
            phase: p.phase === 'scanning' ? 'fetching_logs' : p.phase === 'fetching_peaks' ? 'fetching_logs' : p.phase === 'fetching_security' ? 'fetching_security' : 'analyzing',
            message: `${prefix}${p.message}`,
            progress: p.progress,
            accessLogsCount: 0,
            securityEventsCount: 0,
          });
        });

        // Phase 5: Analyze
        setProgress({ phase: 'analyzing', message: `${prefix}Analyzing traffic patterns...`, progress: 95, accessLogsCount: scanResult.peakLogs.length, securityEventsCount: scanResult.securityEventCount });

        const trafficStats = analyzeFromScan(scanResult);
        const rpsRecommendations = generateRpsRecommendations(trafficStats);
        const findings = generateFindings(currentConfig, trafficStats, rpsRecommendations);
        const recommendedConfig = generateRecommendedConfig(trafficStats, rpsRecommendations, currentConfig);

        collected.push({
          lbName,
          namespace: selectedNs,
          domains,
          analysisStart: startTime,
          analysisEnd: endTime,
          generatedAt: new Date().toISOString(),
          currentConfig,
          trafficStats,
          findings,
          rpsRecommendations,
          recommendedConfig,
        });

        // Update results progressively so user can see completed LBs
        setAllResults([...collected]);
        toast.success(`${lbName}: ${findings.length} findings (~${scanResult.totalRequestsEstimate.toLocaleString()} est. requests)`);

      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        toast.error(`${lbName}: Analysis failed — ${msg}`);
        hadError = true;
        // Continue to next LB
      }
    }

    if (collected.length > 0) {
      setProgress({ phase: 'complete', message: `Analysis complete — ${collected.length}/${lbNames.length} LB(s)`, progress: 100, accessLogsCount: 0, securityEventsCount: 0 });
    } else {
      setProgress({ phase: 'error', message: 'All analyses failed', progress: 0, accessLogsCount: 0, securityEventsCount: 0, error: 'All analyses failed' });
    }

    if (!hadError && collected.length > 1) {
      toast.success(`All ${collected.length} load balancers analyzed successfully`);
    }

    setIsRunning(false);
  }, [selectedNs, selectedLbs, timePeriod, customStart, customEnd, toast]);

  // Active result (derived)
  const results = allResults.length > 0 ? allResults[activeResultIdx] || allResults[0] : null;

  // ── PDF Export ───────────────────────────────────────────────────────────

  const exportPdf = useCallback(async () => {
    if (!results) return;
    try {
      let chartImage: string | undefined;
      if (chartRef.current) {
        const canvas = await html2canvas(chartRef.current, { backgroundColor: '#0f172a', scale: 2 });
        chartImage = canvas.toDataURL('image/png');
      }
      await generateDdosPdfReport({ results, chartImage });
      toast.success('PDF report downloaded');
    } catch {
      toast.error('Failed to generate PDF');
    }
  }, [results, toast]);

  const exportAllPdfs = useCallback(async () => {
    if (allResults.length === 0) return;
    for (const r of allResults) {
      try {
        await generateDdosPdfReport({ results: r });
      } catch {
        toast.error(`Failed to generate PDF for ${r.lbName}`);
      }
    }
    toast.success(`${allResults.length} PDF report(s) downloaded`);
  }, [allResults, toast]);

  // ── Copy JSON ────────────────────────────────────────────────────────────

  const copyConfig = useCallback(() => {
    if (!results) return;
    navigator.clipboard.writeText(JSON.stringify(results.recommendedConfig, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  }, [results]);

  // ── Section Header ───────────────────────────────────────────────────────

  function CollapsibleSection({ id, title, icon: Icon, count, children }: { id: string; title: string; icon: any; count?: number; children: React.ReactNode }) {
    const expanded = expandedSections[id];
    return (
      <div className="border border-slate-700 rounded-lg overflow-hidden">
        <button
          onClick={() => toggleSection(id)}
          className={`w-full flex items-center justify-between px-4 py-3 bg-slate-800/60 hover:bg-slate-800/80 transition-colors ${expanded ? 'border-b border-slate-700' : ''}`}
        >
          <div className="flex items-center gap-3">
            <Icon className="w-5 h-5 text-blue-400" />
            <span className="text-sm font-semibold text-slate-200">{title}</span>
            {count !== undefined && (
              <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 text-xs font-medium rounded">{count}</span>
            )}
          </div>
          {expanded ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
        </button>
        {expanded && (
          <div className="bg-slate-800/20">
            {children}
          </div>
        )}
      </div>
    );
  }

  // ── Render ───────────────────────────────────────────────────────────────

  if (!isConnected) {
    return (
      <main className="max-w-7xl mx-auto px-6 py-8">
        <ConnectionPanel />
      </main>
    );
  }

  return (
    <main className="max-w-5xl mx-auto px-6 py-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-4">
          <Link to="/" className="p-2 hover:bg-slate-800 rounded-lg transition-colors">
            <ArrowLeft className="w-5 h-5 text-slate-400" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-slate-100">DDoS Settings Advisor</h1>
            <p className="text-sm text-slate-400">Analyze traffic and recommend L7 DDoS protection settings</p>
          </div>
          <Link to="/explainer/ddos-advisor" className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-400 hover:text-blue-400 rounded-lg text-xs transition-colors">
            <HelpCircle className="w-3.5 h-3.5" /> How does this work?
          </Link>
        </div>
        {results && (
          <div className="flex items-center gap-2">
            {allResults.length > 1 && (
              <button onClick={exportAllPdfs} className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg text-sm font-medium transition-colors">
                <Download className="w-4 h-4" />
                Export All ({allResults.length})
              </button>
            )}
            <button onClick={exportPdf} className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition-colors">
              <Download className="w-4 h-4" />
              Export PDF
            </button>
          </div>
        )}
      </div>

      {/* Config Panel */}
      {!results && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 mb-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <SearchableSelect
              label="Namespace"
              options={namespaces.map(ns => ({ value: ns.name, label: ns.name }))}
              value={selectedNs}
              onChange={setSelectedNs}
              placeholder="Select namespace..."
            />
            <MultiSelectLb
              label="HTTP Load Balancer(s)"
              options={loadBalancers.map(lb => { const n = lb.metadata?.name || lb.name; return { value: n, label: n }; })}
              selected={selectedLbs}
              onToggle={toggleLb}
              onSelectAll={selectAllLbs}
              onDeselectAll={deselectAllLbs}
              placeholder="Select load balancer(s)..."
              disabled={!selectedNs}
            />
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Time Period</label>
              <div className="flex gap-1">
                {(['24h', '7d', '14d', '30d', 'custom'] as TimePeriod[]).map(tp => (
                  <button
                    key={tp}
                    onClick={() => setTimePeriod(tp)}
                    className={`flex-1 px-2 py-2 rounded-lg text-sm font-medium transition-colors ${
                      timePeriod === tp
                        ? 'bg-blue-600 text-white'
                        : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                    }`}
                  >
                    {tp === 'custom' ? 'Custom' : tp}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Custom date range inputs */}
          {timePeriod === 'custom' && (
            <div className="grid grid-cols-2 gap-3 mb-4">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">From</label>
                <input
                  type="datetime-local"
                  value={customStart}
                  onChange={(e) => setCustomStart(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-sm text-slate-200 [color-scheme:dark]"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">To</label>
                <input
                  type="datetime-local"
                  value={customEnd}
                  onChange={(e) => setCustomEnd(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-sm text-slate-200 [color-scheme:dark]"
                />
              </div>
            </div>
          )}

          {/* Selected LB chips */}
          {selectedLbs.size > 0 && (
            <div className="flex flex-wrap gap-1.5 mb-4">
              {[...selectedLbs].map(lb => (
                <span key={lb} className="inline-flex items-center gap-1 px-2 py-1 bg-blue-500/15 border border-blue-500/30 rounded text-xs text-blue-400">
                  {lb}
                  <button onClick={() => toggleLb(lb)} className="hover:text-blue-200 ml-0.5">×</button>
                </span>
              ))}
            </div>
          )}

          <button
            onClick={runAnalysis}
            disabled={!selectedNs || selectedLbs.size === 0 || isRunning || (timePeriod === 'custom' && (!customStart || !customEnd))}
            className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-lg font-medium transition-colors"
          >
            {isRunning ? <Loader2 className="w-5 h-5 animate-spin" /> : <Play className="w-5 h-5" />}
            {isRunning
              ? `Analyzing ${currentLbIndex}/${totalLbCount}...`
              : `Analyze ${selectedLbs.size} LB${selectedLbs.size > 1 ? 's' : ''} — ${TIME_PERIOD_LABELS[timePeriod]}`}
          </button>
        </div>
      )}

      {/* Progress */}
      {isRunning && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 mb-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-slate-300">{progress.message}</span>
            <span className="text-sm text-slate-400">{progress.progress}%</span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2 mb-3">
            <div
              className="bg-blue-500 h-2 rounded-full transition-all duration-300"
              style={{ width: `${progress.progress}%` }}
            />
          </div>
          <div className="flex gap-6 text-xs text-slate-500">
            <span>Access logs: {progress.accessLogsCount.toLocaleString()}</span>
            <span>Security events: {progress.securityEventsCount.toLocaleString()}</span>
          </div>
        </div>
      )}

      {/* Error */}
      {progress.phase === 'error' && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 mb-6 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-red-400">Analysis Failed</p>
            <p className="text-sm text-red-300/70 mt-1">{progress.error}</p>
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div className="space-y-4">
          {/* Reset button */}
          <button
            onClick={() => { setAllResults([]); setActiveResultIdx(0); setProgress({ phase: 'idle', message: '', progress: 0, accessLogsCount: 0, securityEventsCount: 0 }); }}
            className="flex items-center gap-2 text-sm text-slate-400 hover:text-slate-200 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            New Analysis
          </button>

          {/* LB tabs — only show when multiple results */}
          {allResults.length > 1 && (
            <div className="flex gap-1 overflow-x-auto pb-1">
              {allResults.map((r, idx) => (
                <button
                  key={r.lbName}
                  onClick={() => setActiveResultIdx(idx)}
                  className={`px-3 py-1.5 rounded-lg text-sm font-medium whitespace-nowrap transition-colors ${
                    idx === activeResultIdx
                      ? 'bg-blue-600 text-white'
                      : 'bg-slate-800 text-slate-400 hover:bg-slate-700 hover:text-slate-200'
                  }`}
                >
                  {r.lbName}
                  <span className="ml-1.5 text-xs opacity-70">{r.findings.length} findings</span>
                </button>
              ))}
            </div>
          )}

          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: 'Est. Requests', value: `~${results.trafficStats.totalRequests.toLocaleString()}`, icon: Activity },
              { label: 'Peak RPS', value: results.trafficStats.peakRps.toLocaleString(), icon: Zap },
              { label: 'Traffic Type', value: results.trafficStats.trafficProfile.type.toUpperCase(), icon: Server },
              { label: 'Findings', value: String(results.findings.length), icon: AlertTriangle },
            ].map(card => (
              <div key={card.label} className="bg-slate-800/50 border border-slate-700 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1">
                  <card.icon className="w-3.5 h-3.5 text-slate-500" />
                  <span className="text-xs text-slate-500">{card.label}</span>
                </div>
                <span className={`text-lg font-bold ${card.label === 'Traffic Type'
                  ? results.trafficStats.trafficProfile.type === 'api' ? 'text-violet-400'
                    : results.trafficStats.trafficProfile.type === 'mixed' ? 'text-amber-400'
                    : 'text-emerald-400'
                  : 'text-slate-100'}`}>{card.value}</span>
              </div>
            ))}
          </div>

          {/* Section: Current DDoS Configuration */}
          <CollapsibleSection id="config" title="Current DDoS Configuration" icon={Shield}>
            <div className="p-4 space-y-4">
              {/* Status badges */}
              <div className="flex flex-wrap gap-2">
                <ConfigStatusBadge enabled={results.currentConfig.hasL7DdosProtection} label="L7 DDoS Protection" />
                <ConfigStatusBadge enabled={results.currentConfig.threatMeshEnabled} label="Threat Mesh" />
                <ConfigStatusBadge enabled={results.currentConfig.ipReputationEnabled} label="IP Reputation" />
                <ConfigStatusBadge enabled={results.currentConfig.maliciousUserDetectionEnabled} label="Malicious User Detection" />
                <ConfigStatusBadge enabled={results.currentConfig.botDefenseEnabled} label="Bot Defense" />
              </div>

              {/* Settings grid */}
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                <div className="bg-slate-900/50 rounded-lg p-3">
                  <div className="text-xs text-slate-500 mb-1">RPS Threshold</div>
                  <div className="text-sm font-semibold text-slate-200">
                    {results.currentConfig.rpsThreshold ? results.currentConfig.rpsThreshold.toLocaleString() : 'Not set'}
                    {results.currentConfig.isDefaultRpsThreshold && <span className="text-xs text-slate-500 ml-1">(default)</span>}
                  </div>
                </div>
                <div className="bg-slate-900/50 rounded-lg p-3">
                  <div className="text-xs text-slate-500 mb-1">Mitigation Action</div>
                  <div className="text-sm font-semibold text-slate-200 capitalize">
                    {results.currentConfig.mitigationAction.replace('_', ' ')}
                  </div>
                </div>
                <div className="bg-slate-900/50 rounded-lg p-3">
                  <div className="text-xs text-slate-500 mb-1">Client-side Action</div>
                  <div className="text-sm font-semibold text-slate-200 capitalize">
                    {results.currentConfig.clientsideAction.replace('_', ' ')}
                  </div>
                </div>
                <div className="bg-slate-900/50 rounded-lg p-3">
                  <div className="text-xs text-slate-500 mb-1">Slow DDoS Timeouts</div>
                  <div className="text-sm font-semibold text-slate-200">
                    {results.currentConfig.hasSlowDdosMitigation
                      ? `Headers: ${(results.currentConfig.slowDdosHeadersTimeout || 0) / 1000}s / Request: ${(results.currentConfig.slowDdosRequestTimeout || 0) / 1000}s`
                      : 'System defaults'}
                  </div>
                </div>
                <div className="bg-slate-900/50 rounded-lg p-3">
                  <div className="text-xs text-slate-500 mb-1">DDoS Policy</div>
                  <div className="text-sm font-semibold text-slate-200">
                    {results.currentConfig.ddosPolicy || 'None'}
                  </div>
                </div>
                <div className="bg-slate-900/50 rounded-lg p-3">
                  <div className="text-xs text-slate-500 mb-1">Mitigation Rules</div>
                  <div className="text-sm font-semibold text-slate-200">
                    {results.currentConfig.mitigationRules.length} rule(s)
                  </div>
                </div>
              </div>

              {/* IP threat categories */}
              {results.currentConfig.ipReputationEnabled && (
                <div>
                  <div className="text-xs text-slate-500 mb-2">IP Threat Categories ({results.currentConfig.ipThreatCategories.length}/12)</div>
                  <div className="flex flex-wrap gap-1">
                    {results.currentConfig.ipThreatCategories.map(cat => (
                      <span key={cat} className="px-2 py-0.5 bg-slate-700 text-slate-300 rounded text-xs">{cat}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </CollapsibleSection>

          {/* Section: Traffic Analysis */}
          <CollapsibleSection id="traffic" title="Traffic Analysis" icon={Activity}>
            <div className="p-4 space-y-4">
              {/* Traffic Profile */}
              <div>
                <h4 className="text-sm font-semibold text-slate-300 mb-2">Traffic Profile</h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {/* Type badge */}
                  <div className={`rounded-lg p-3 border ${
                    results.trafficStats.trafficProfile.type === 'api'
                      ? 'bg-violet-500/10 border-violet-500/30'
                      : results.trafficStats.trafficProfile.type === 'mixed'
                        ? 'bg-amber-500/10 border-amber-500/30'
                        : 'bg-emerald-500/10 border-emerald-500/30'
                  }`}>
                    <div className="text-xs text-slate-500 mb-1">Classification</div>
                    <div className={`text-sm font-bold ${
                      results.trafficStats.trafficProfile.type === 'api' ? 'text-violet-400'
                        : results.trafficStats.trafficProfile.type === 'mixed' ? 'text-amber-400'
                        : 'text-emerald-400'
                    }`}>
                      {results.trafficStats.trafficProfile.type === 'api' ? 'API / Programmatic'
                        : results.trafficStats.trafficProfile.type === 'mixed' ? 'Mixed (Web + API)'
                        : 'Web / Browser-based'}
                    </div>
                    <div className="text-xs text-slate-500 mt-1">
                      {results.trafficStats.trafficProfile.apiTrafficPct}% API / {results.trafficStats.trafficProfile.webTrafficPct}% Web
                    </div>
                  </div>
                  {/* UA Breakdown */}
                  <div className="bg-slate-900/50 rounded-lg p-3">
                    <div className="text-xs text-slate-500 mb-2">User Agent Breakdown</div>
                    <div className="space-y-1">
                      {Object.entries(results.trafficStats.trafficProfile.uaBreakdown)
                        .filter(([, count]) => count > 0)
                        .sort((a, b) => b[1] - a[1])
                        .map(([type, count]) => (
                          <div key={type} className="flex justify-between text-xs">
                            <span className="text-slate-400 capitalize">{type}</span>
                            <span className="text-slate-300 font-mono">{count.toLocaleString()}</span>
                          </div>
                        ))}
                    </div>
                  </div>
                  {/* Mitigation Impact */}
                  <div className="bg-slate-900/50 rounded-lg p-3">
                    <div className="text-xs text-slate-500 mb-2">Mitigation Impact</div>
                    <div className="space-y-1 text-xs">
                      <div className="flex items-center gap-2">
                        <span className={results.trafficStats.trafficProfile.type !== 'api' ? 'text-emerald-400' : 'text-red-400'}>
                          {results.trafficStats.trafficProfile.type !== 'api' ? '✓' : '✗'}
                        </span>
                        <span className="text-slate-400">JS Challenge compatible</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={results.trafficStats.trafficProfile.type === 'web' ? 'text-emerald-400' : 'text-red-400'}>
                          {results.trafficStats.trafficProfile.type === 'web' ? '✓' : '✗'}
                        </span>
                        <span className="text-slate-400">CAPTCHA compatible</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-emerald-400">✓</span>
                        <span className="text-slate-400">Block compatible</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-emerald-400">✓</span>
                        <span className="text-slate-400">IP Reputation compatible</span>
                      </div>
                    </div>
                  </div>
                </div>
                {/* Top Paths */}
                {results.trafficStats.trafficProfile.topPaths.length > 0 && (
                  <div className="mt-3">
                    <div className="text-xs text-slate-500 mb-1">Top Request Paths</div>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-1">
                      {results.trafficStats.trafficProfile.topPaths.slice(0, 9).map(p => (
                        <div key={p.path} className="flex items-center gap-2 text-xs px-2 py-1 bg-slate-900/30 rounded">
                          <span className={`px-1 rounded text-[10px] font-medium ${p.isApi ? 'bg-violet-500/20 text-violet-400' : 'bg-slate-600/30 text-slate-500'}`}>
                            {p.isApi ? 'API' : 'WEB'}
                          </span>
                          <span className="text-slate-400 truncate flex-1 font-mono">{p.path}</span>
                          <span className="text-slate-600 font-mono">{p.count.toLocaleString()}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* RPS Distribution Table */}
              <div>
                <h4 className="text-sm font-semibold text-slate-300 mb-2">Aggregate RPS Distribution</h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-xs text-slate-500 border-b border-slate-700">
                        <th className="text-left py-2 px-3">Metric</th>
                        <th className="text-right py-2 px-3">RPS</th>
                        <th className="text-right py-2 px-3">RPM</th>
                      </tr>
                    </thead>
                    <tbody>
                      {['p50', 'p75', 'p90', 'p95', 'p99', 'max', 'mean'].map(metric => (
                        <tr key={metric} className="border-b border-slate-700/50 hover:bg-slate-800/50">
                          <td className="py-2 px-3 text-slate-400 font-medium">
                            {metric === 'max' ? 'Peak' : metric === 'mean' ? 'Average' : metric.toUpperCase()}
                          </td>
                          <td className="py-2 px-3 text-right font-mono text-slate-200">
                            {typeof (results.trafficStats.aggregateRps as any)[metric] === 'number'
                              ? Math.round((results.trafficStats.aggregateRps as any)[metric]).toLocaleString()
                              : '-'}
                          </td>
                          <td className="py-2 px-3 text-right font-mono text-slate-200">
                            {typeof (results.trafficStats.aggregateRpm as any)[metric] === 'number'
                              ? Math.round((results.trafficStats.aggregateRpm as any)[metric]).toLocaleString()
                              : '-'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Time Series Chart */}
              {results.trafficStats.timeSeries.length > 0 && (
                <div ref={chartRef}>
                  <h4 className="text-sm font-semibold text-slate-300 mb-2">Peak RPS Per Hour (Full Duration)</h4>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={results.trafficStats.timeSeries}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                        <XAxis
                          dataKey="timestamp"
                          tick={{ fontSize: 10, fill: '#94a3b8' }}
                          tickFormatter={(v: string) => {
                            const d = new Date(v);
                            return `${(d.getUTCMonth() + 1).toString().padStart(2, '0')}/${d.getUTCDate().toString().padStart(2, '0')} ${d.getUTCHours().toString().padStart(2, '0')}:${d.getUTCMinutes().toString().padStart(2, '0')}`;
                          }}
                          interval="preserveStartEnd"
                        />
                        <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} />
                        <Tooltip
                          contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #475569', borderRadius: '8px', fontSize: '12px' }}
                          labelFormatter={(v: unknown) => new Date(String(v)).toLocaleString()}
                          formatter={(value: unknown) => [Number(value).toLocaleString(), 'Peak RPS']}
                        />
                        <Area type="monotone" dataKey="peakRps" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.2} />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              )}

              {/* Response Breakdown */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                {[
                  { label: '2xx', value: results.trafficStats.responseBreakdown.origin2xx, color: 'text-emerald-400' },
                  { label: '3xx', value: results.trafficStats.responseBreakdown.origin3xx, color: 'text-blue-400' },
                  { label: '4xx', value: results.trafficStats.responseBreakdown.origin4xx, color: 'text-yellow-400' },
                  { label: '5xx', value: results.trafficStats.responseBreakdown.origin5xx, color: 'text-red-400' },
                  { label: 'F5 Blocked', value: results.trafficStats.responseBreakdown.f5Blocked, color: 'text-orange-400' },
                ].map(item => (
                  <div key={item.label} className="bg-slate-900/50 rounded-lg p-2 text-center">
                    <div className="text-xs text-slate-500">{item.label}</div>
                    <div className={`text-sm font-bold ${item.color}`}>{item.value.toLocaleString()}</div>
                  </div>
                ))}
              </div>

              {/* Top Countries and ASNs */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {results.trafficStats.topCountries.length > 0 && (
                  <div>
                    <h4 className="text-xs font-semibold text-slate-400 mb-2">Top Countries</h4>
                    <div className="space-y-1">
                      {results.trafficStats.topCountries.slice(0, 5).map(c => (
                        <div key={c.country} className="flex justify-between text-xs">
                          <span className="text-slate-300">{c.country || 'Unknown'}</span>
                          <span className="text-slate-500 font-mono">{c.count.toLocaleString()}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {results.trafficStats.topAsns.length > 0 && (
                  <div>
                    <h4 className="text-xs font-semibold text-slate-400 mb-2">Top ASNs</h4>
                    <div className="space-y-1">
                      {results.trafficStats.topAsns.slice(0, 5).map(a => (
                        <div key={a.asn} className="flex justify-between text-xs">
                          <span className="text-slate-300">AS{a.asn}</span>
                          <span className="text-slate-500 font-mono">{a.count.toLocaleString()}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </CollapsibleSection>

          {/* Section: Findings */}
          <CollapsibleSection id="findings" title="Security Findings & Recommendations" icon={AlertTriangle} count={results.findings.length}>
            {results.findings.length === 0 ? (
              <div className="p-8 text-center text-slate-500">
                <CheckCircle className="w-8 h-8 mx-auto mb-2 text-emerald-500" />
                <p>No issues found — DDoS configuration looks good!</p>
              </div>
            ) : (
              <div className="divide-y divide-slate-700/50">
                {results.findings.map((finding, idx) => (
                  <FindingRow key={idx} finding={finding} />
                ))}
              </div>
            )}
          </CollapsibleSection>

          {/* Section: RPS Threshold Recommendation */}
          <CollapsibleSection id="recommendations" title="RPS Threshold Recommendation" icon={Zap}>
            <div className="p-4">
              {results.rpsRecommendations.map(rec => (
                <div
                  key={rec.algorithm}
                  className="rounded-lg p-5 border bg-blue-500/10 border-blue-500/30"
                >
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-sm font-semibold text-slate-200">{rec.label}</span>
                    <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 text-xs font-semibold rounded">Recommended</span>
                  </div>
                  <div className="text-3xl font-bold text-slate-100 mb-1">
                    {rec.rpsThreshold.toLocaleString()} <span className="text-sm font-normal text-slate-500">RPS</span>
                  </div>
                  <div className="text-xs text-slate-500 font-mono mb-3">{rec.formula}</div>
                  <div className="text-sm text-slate-400">{rec.description}</div>
                  {results.currentConfig.rpsThreshold && (
                    <div className="mt-3 text-sm text-slate-500 border-t border-slate-700/50 pt-3">
                      Current threshold: {results.currentConfig.rpsThreshold.toLocaleString()} RPS
                      <span className="ml-2">
                        ({rec.rpsThreshold > results.currentConfig.rpsThreshold ? '\u2191' : '\u2193'} {Math.abs(rec.rpsThreshold - results.currentConfig.rpsThreshold).toLocaleString()})
                      </span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </CollapsibleSection>

          {/* Section: Recommended Configuration */}
          <CollapsibleSection id="generatedConfig" title="Recommended Configuration (JSON)" icon={Server}>
            <div className="p-4">
              <div className="flex items-center justify-between mb-3">
                <p className="text-xs text-slate-500">
                  Apply these settings to your HTTP Load Balancer for optimal DDoS protection.
                </p>
                <button
                  onClick={copyConfig}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded text-xs text-slate-300 transition-colors"
                >
                  {copiedJson ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {copiedJson ? 'Copied!' : 'Copy JSON'}
                </button>
              </div>
              <pre className="bg-slate-950 rounded-lg p-4 overflow-x-auto text-xs font-mono text-emerald-400 leading-relaxed max-h-96 overflow-y-auto">
                {JSON.stringify(results.recommendedConfig, null, 2)}
              </pre>
            </div>
          </CollapsibleSection>
        </div>
      )}
    </main>
  );
}
