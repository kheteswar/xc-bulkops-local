// ═══════════════════════════════════════════════════════════════════════════
// API Shield Advisor — Guided API security assessment tool
// Analyzes F5 XC HTTP LB configurations against OWASP API Security Top 10
// and produces a prioritized implementation guide.
// ═══════════════════════════════════════════════════════════════════════════

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ArrowLeft, Shield, Loader2, Play, Search,
  ChevronDown, ChevronUp, AlertTriangle, CheckCircle,
  XCircle, Download, Zap, Eye, Lock, FileCheck,
  Bot, Gauge, Target, BookOpen, ListChecks, Map,
  Info, Filter, Clock, Activity, GitBranch, HelpCircle,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  PieChart, Pie, Cell,
} from 'recharts';
import { apiClient } from '../services/api';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import { ConnectionPanel } from '../components/ConnectionPanel';
import {
  runAssessment,
  CONTROL_DOMAINS,
  OWASP_API_TOP_10,
} from '../services/api-shield';
import type {
  AssessmentDepth,
  AssessmentConfig,
  AssessmentResult,
  SecurityControl,
  ControlStatusValue,
  ControlPriority,
  ControlPhase,
  Recommendation,
  PhaseProgress,
} from '../services/api-shield';
import type { Namespace, LoadBalancer } from '../types';

// ─── Dropdown Components ─────────────────────────────────────────────────────

function SearchableSelect({ label, options, value, onChange, placeholder, disabled }: {
  label: string; options: Array<{ value: string; label: string }>; value: string;
  onChange: (v: string) => void; placeholder: string; disabled?: boolean;
}) {
  const [isOpen, setIsOpen] = useState(false);
  const [filter, setFilter] = useState('');
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const h = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setIsOpen(false); };
    document.addEventListener('mousedown', h); return () => document.removeEventListener('mousedown', h);
  }, []);
  const filtered = options.filter(o => o.label.toLowerCase().includes(filter.toLowerCase()));
  return (
    <div ref={ref} className="relative">
      <label className="block text-xs font-medium text-slate-400 mb-1">{label}</label>
      <button onClick={() => !disabled && setIsOpen(!isOpen)} disabled={disabled} className="w-full flex items-center justify-between px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-sm text-slate-200 hover:border-slate-500 disabled:opacity-50 disabled:cursor-not-allowed">
        <span className={value ? 'text-slate-200' : 'text-slate-500'}>{value ? options.find(o => o.value === value)?.label || value : placeholder}</span>
        <ChevronDown className="w-4 h-4 text-slate-400" />
      </button>
      {isOpen && (
        <div className="absolute z-50 mt-1 w-full bg-slate-800 border border-slate-600 rounded-lg shadow-xl max-h-60 overflow-hidden">
          <div className="p-2 border-b border-slate-700"><div className="flex items-center gap-2 px-2 py-1 bg-slate-900 rounded"><Search className="w-3 h-3 text-slate-500" /><input type="text" value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter..." className="bg-transparent text-sm text-slate-200 outline-none w-full" autoFocus /></div></div>
          <div className="max-h-48 overflow-y-auto">
            {filtered.map(o => (<button key={o.value} onClick={() => { onChange(o.value); setIsOpen(false); setFilter(''); }} className={`w-full text-left px-3 py-2 text-sm hover:bg-slate-700 ${o.value === value ? 'bg-slate-700 text-blue-400' : 'text-slate-300'}`}>{o.label}</button>))}
            {filtered.length === 0 && <div className="px-3 py-4 text-sm text-slate-500 text-center">No matches</div>}
          </div>
        </div>
      )}
    </div>
  );
}

function MultiSelectLb({ label, options, selected, onToggle, onSelectAll, onDeselectAll, placeholder, disabled }: {
  label: string; options: Array<{ value: string; label: string }>; selected: Set<string>;
  onToggle: (v: string) => void; onSelectAll: () => void; onDeselectAll: () => void; placeholder: string; disabled?: boolean;
}) {
  const [isOpen, setIsOpen] = useState(false);
  const [filter, setFilter] = useState('');
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const h = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setIsOpen(false); };
    document.addEventListener('mousedown', h); return () => document.removeEventListener('mousedown', h);
  }, []);
  const filtered = options.filter(o => o.label.toLowerCase().includes(filter.toLowerCase()));
  return (
    <div ref={ref} className="relative">
      <label className="block text-xs font-medium text-slate-400 mb-1">{label}</label>
      <button onClick={() => !disabled && setIsOpen(!isOpen)} disabled={disabled} className="w-full flex items-center justify-between px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-sm text-slate-200 hover:border-slate-500 disabled:opacity-50 disabled:cursor-not-allowed min-h-[38px]">
        <span className={selected.size > 0 ? 'text-slate-200' : 'text-slate-500'}>{selected.size > 0 ? `${selected.size} LB${selected.size > 1 ? 's' : ''} selected` : placeholder}</span>
        <ChevronDown className="w-4 h-4 text-slate-400" />
      </button>
      {isOpen && (
        <div className="absolute z-50 mt-1 w-full bg-slate-800 border border-slate-600 rounded-lg shadow-xl max-h-72 overflow-hidden">
          <div className="p-2 border-b border-slate-700 space-y-2">
            <div className="flex items-center gap-2 px-2 py-1 bg-slate-900 rounded"><Search className="w-3 h-3 text-slate-500" /><input type="text" value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter..." className="bg-transparent text-sm text-slate-200 outline-none w-full" autoFocus /></div>
            <div className="flex gap-2 px-1"><button onClick={onSelectAll} className="text-xs text-blue-400 hover:text-blue-300">Select All</button><span className="text-slate-600">|</span><button onClick={onDeselectAll} className="text-xs text-slate-400 hover:text-slate-300">Deselect All</button></div>
          </div>
          <div className="max-h-52 overflow-y-auto">
            {filtered.map(o => (<button key={o.value} onClick={() => onToggle(o.value)} className={`w-full flex items-center gap-2 text-left px-3 py-2 text-sm hover:bg-slate-700 ${selected.has(o.value) ? 'bg-slate-700/50' : ''} text-slate-300`}><span className={`w-4 h-4 rounded border flex items-center justify-center text-xs ${selected.has(o.value) ? 'bg-blue-600 border-blue-500 text-white' : 'border-slate-500'}`}>{selected.has(o.value) && <CheckCircle className="w-3 h-3" />}</span><span className="truncate">{o.label}</span></button>))}
            {filtered.length === 0 && <div className="px-3 py-4 text-sm text-slate-500 text-center">No matches</div>}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Badge & Helper Components ───────────────────────────────────────────────

function StatusBadge({ status }: { status: ControlStatusValue }) {
  const m: Record<ControlStatusValue, [string, string]> = { enabled: ['bg-emerald-500/15 text-emerald-400 border-emerald-500/30', 'Enabled'], partial: ['bg-amber-500/15 text-amber-400 border-amber-500/30', 'Partial'], disabled: ['bg-red-500/15 text-red-400 border-red-500/30', 'Disabled'], unknown: ['bg-slate-500/15 text-slate-400 border-slate-500/30', 'Unknown'] };
  return <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${m[status][0]}`}>{m[status][1]}</span>;
}
function PriorityBadge({ priority }: { priority: ControlPriority }) {
  const m: Record<ControlPriority, string> = { critical: 'bg-red-500/20 text-red-400 border-red-500/30', high: 'bg-orange-500/20 text-orange-400 border-orange-500/30', medium: 'bg-amber-500/20 text-amber-400 border-amber-500/30', low: 'bg-blue-500/20 text-blue-400 border-blue-500/30' };
  return <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${m[priority]}`}>{priority.toUpperCase()}</span>;
}
function EffortBadge({ effort }: { effort: string }) {
  const m: Record<string, string> = { low: 'bg-emerald-500/15 text-emerald-400', medium: 'bg-amber-500/15 text-amber-400', high: 'bg-red-500/15 text-red-400' };
  return <span className={`px-2 py-0.5 rounded text-xs font-medium ${m[effort] || 'bg-slate-500/15 text-slate-400'}`}>{effort} effort</span>;
}
function PhaseBadge({ phase }: { phase: ControlPhase }) {
  const c: Record<ControlPhase, string> = { foundation: 'bg-blue-500/15 text-blue-400', visibility: 'bg-cyan-500/15 text-cyan-400', enforcement: 'bg-violet-500/15 text-violet-400', advanced: 'bg-indigo-500/15 text-indigo-400' };
  const l: Record<ControlPhase, string> = { foundation: 'Foundation', visibility: 'Visibility', enforcement: 'Enforcement', advanced: 'Advanced' };
  return <span className={`px-2 py-0.5 rounded text-xs font-medium ${c[phase]}`}>{l[phase]}</span>;
}

const ICON_MAP: Record<string, React.ComponentType<{ className?: string }>> = { Radar: Search, FileCheck, Gauge, Shield, Bot, Zap, Lock, Eye, AlertTriangle, GitBranch, Activity };
function DomainIcon({ iconName, className }: { iconName: string; className?: string }) { const I = ICON_MAP[iconName] || Shield; return <I className={className || 'w-4 h-4'} />; }
function sClr(s: number) { return s >= 70 ? 'text-emerald-400' : s >= 40 ? 'text-amber-400' : 'text-red-400'; }
function sBg(s: number) { return s >= 70 ? 'bg-emerald-500' : s >= 40 ? 'bg-amber-500' : 'bg-red-500'; }
function sRing(s: number) { return s >= 70 ? '#34d399' : s >= 40 ? '#fbbf24' : '#f87171'; }

function ScoreGauge({ score, size = 180 }: { score: number; size?: number }) {
  const r = (size - 20) / 2;
  const circumference = 2 * Math.PI * r;
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="transform -rotate-90"><circle cx={size/2} cy={size/2} r={r} stroke="rgb(51 65 85 / 0.5)" strokeWidth={10} fill="none" /><circle cx={size/2} cy={size/2} r={r} stroke={sRing(score)} strokeWidth={10} fill="none" strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={circumference - (score / 100) * circumference} className="transition-all duration-1000 ease-out" /></svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center"><span className={`text-4xl font-bold ${sClr(score)}`}>{score}</span><span className="text-xs text-slate-400 mt-1">/ 100</span></div>
    </div>
  );
}

function ControlRow({ control }: { control: SecurityControl }) {
  const [exp, setExp] = useState(false);
  return (
    <div className={`border-b border-slate-700/50 last:border-b-0 ${exp ? 'bg-slate-800/30' : ''}`}>
      <button onClick={() => setExp(!exp)} className="w-full flex items-center gap-3 px-4 py-3 hover:bg-slate-800/50 transition-colors text-left">
        <StatusBadge status={control.status} />
        <div className="flex-1 min-w-0"><div className="text-sm font-medium text-slate-200">{control.name}</div><div className="text-xs text-slate-500 mt-0.5 truncate">{control.description}</div></div>
        <PriorityBadge priority={control.priority} />
        <div className="flex items-center gap-1 shrink-0">{control.owaspMapping.slice(0, 3).map(t => <span key={t} className="px-1.5 py-0.5 bg-indigo-500/15 text-indigo-400 text-[10px] rounded font-mono">{t}</span>)}</div>
        {exp ? <ChevronUp className="w-4 h-4 text-slate-500 shrink-0" /> : <ChevronDown className="w-4 h-4 text-slate-500 shrink-0" />}
      </button>
      {exp && (
        <div className="px-4 pb-4 space-y-3">
          <p className="text-sm text-slate-300">{control.description}</p>
          {control.details && <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-3"><div className="flex items-center gap-2 mb-1"><Info className="w-3.5 h-3.5 text-blue-400" /><span className="text-xs font-semibold text-blue-400">Detail</span></div><p className="text-xs text-blue-300">{control.details}</p></div>}
          <div className="flex items-center gap-2 text-xs text-slate-500"><PhaseBadge phase={control.phase} /><span>OWASP: {control.owaspMapping.join(', ')}</span></div>
          {control.status !== 'enabled' && <a href="https://docs.cloud.f5.com/docs" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 rounded-lg text-xs font-medium transition-colors"><BookOpen className="w-3.5 h-3.5" />Enable Guide</a>}
        </div>
      )}
    </div>
  );
}

function TabBtn({ active, onClick, icon: Icon, label, badge }: { active: boolean; onClick: () => void; icon: React.ComponentType<{ className?: string }>; label: string; badge?: number }) {
  return (
    <button onClick={onClick} className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium rounded-lg transition-colors whitespace-nowrap ${active ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'}`}>
      <Icon className="w-4 h-4" />{label}{badge !== undefined && badge > 0 && <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${active ? 'bg-white/20 text-white' : 'bg-slate-700 text-slate-300'}`}>{badge}</span>}
    </button>
  );
}

function RecCard({ rec }: { rec: Recommendation }) {
  const [exp, setExp] = useState(false);
  const dom = CONTROL_DOMAINS.find(d => d.controlIds.includes(rec.controlId));
  return (
    <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
      <button onClick={() => setExp(!exp)} className="w-full flex items-center gap-3 p-4 hover:bg-slate-800/70 transition-colors text-left">
        <PriorityBadge priority={rec.priority} />
        <div className="flex-1 min-w-0"><div className="text-sm font-medium text-slate-200">{rec.title}</div><div className="flex items-center gap-3 mt-1 text-xs text-slate-500">{dom && <span className="flex items-center gap-1"><DomainIcon iconName={dom.icon} className="w-3 h-3" />{dom.name}</span>}<PhaseBadge phase={rec.phase} /><EffortBadge effort={rec.effort} /></div></div>
        {exp ? <ChevronUp className="w-4 h-4 text-slate-500 shrink-0" /> : <ChevronDown className="w-4 h-4 text-slate-500 shrink-0" />}
      </button>
      {exp && (
        <div className="px-4 pb-4 space-y-3 border-t border-slate-700/50 pt-3">
          <p className="text-sm text-slate-300">{rec.description}</p>
          {rec.impact && <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-3"><div className="flex items-center gap-2 mb-1"><Shield className="w-3.5 h-3.5 text-emerald-400" /><span className="text-xs font-semibold text-emerald-400">Impact</span></div><p className="text-xs text-emerald-300">{rec.impact}</p></div>}
          {rec.evidence.length > 0 && <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-3"><div className="flex items-center gap-2 mb-1"><Info className="w-3.5 h-3.5 text-blue-400" /><span className="text-xs font-semibold text-blue-400">Evidence</span></div><ul className="space-y-1">{rec.evidence.map((e, i) => <li key={i} className="text-xs text-blue-300">{e}</li>)}</ul></div>}
          {rec.steps.length > 0 && <div className="bg-slate-900/50 rounded-lg p-3"><div className="text-xs font-semibold text-slate-500 mb-2">Steps</div><ol className="space-y-1.5">{rec.steps.map((s, i) => <li key={i} className="flex items-start gap-2 text-xs text-slate-400"><span className="w-4 h-4 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5">{i+1}</span>{s}</li>)}</ol></div>}
        </div>
      )}
    </div>
  );
}

// ─── Main Component ──────────────────────────────────────────────────────────

export function APIShieldAdvisor() {
  const { isConnected } = useApp();
  const navigate = useNavigate();
  const toast = useToast();
  const [namespaces, setNamespaces] = useState<Namespace[]>([]);
  const [selectedNs, setSelectedNs] = useState('');
  const [loadBalancers, setLoadBalancers] = useState<LoadBalancer[]>([]);
  const [selectedLbs, setSelectedLbs] = useState<Set<string>>(new Set());
  const [depth, setDepth] = useState<AssessmentDepth>('standard');
  const [pMsg, setPMsg] = useState('');
  const [pPct, setPPct] = useState(0);
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<AssessmentResult | null>(null);
  const [tab, setTab] = useState('overview');
  const [domId, setDomId] = useState('');
  const [fPri, setFPri] = useState('all');
  const [fDom, setFDom] = useState('all');
  const [fPh, setFPh] = useState('all');

  useEffect(() => { if (isConnected) apiClient.getNamespaces().then(d => setNamespaces(((d as any).items || []) as Namespace[])).catch(() => toast.error('Failed to load namespaces')); }, [isConnected]);
  useEffect(() => { if (!selectedNs) { setLoadBalancers([]); setSelectedLbs(new Set()); return; } apiClient.getLoadBalancers(selectedNs).then(d => { setLoadBalancers(((d as any).items || []) as LoadBalancer[]); setSelectedLbs(new Set()); }).catch(() => toast.error('Failed to load LBs')); }, [selectedNs]);
  const toggleLb = useCallback((n: string) => setSelectedLbs(p => { const s = new Set(p); s.has(n) ? s.delete(n) : s.add(n); return s; }), []);
  const selAll = useCallback(() => setSelectedLbs(new Set(loadBalancers.map(l => l.metadata?.name || l.name))), [loadBalancers]);
  const deselAll = useCallback(() => setSelectedLbs(new Set()), []);
  useEffect(() => { if (results && CONTROL_DOMAINS.length > 0 && !domId) setDomId(CONTROL_DOMAINS[0].id); }, [results, domId]);

  const start = useCallback(async () => {
    if (!selectedNs || selectedLbs.size === 0) return;
    setRunning(true); setResults(null); setTab('overview'); setDomId('');
    try {
      const r = await runAssessment({ namespace: selectedNs, lbNames: [...selectedLbs], depth } as AssessmentConfig, (m: string, p: number) => { setPMsg(m); setPPct(p); });
      setResults(r); toast.success(`Score ${r.overallScore}/100, ${r.recommendations.length} recommendations`);
    } catch (e) { toast.error(`Failed: ${e instanceof Error ? e.message : String(e)}`); } finally { setRunning(false); }
  }, [selectedNs, selectedLbs, depth, toast]);

  const exportR = useCallback(() => {
    if (!results) return;
    const b = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
    const u = URL.createObjectURL(b); const a = document.createElement('a'); a.href = u;
    a.download = `api-shield-${results.namespace}-${new Date().toISOString().split('T')[0]}.json`;
    a.click(); URL.revokeObjectURL(u); toast.success('Exported');
  }, [results, toast]);

  const dcMap = useMemo(() => {
    const m: Record<string, SecurityControl[]> = {};
    if (!results) return m;
    for (const d of CONTROL_DOMAINS) {
      m[d.id] = results.controls.filter((c) => d.controlIds.includes(c.id));
    }
    return m;
  }, [results]);

  const dScores = useMemo(() => {
    const m: Record<string, { score: number; en: number; tot: number }> = {};
    for (const d of CONTROL_DOMAINS) {
      const cs = dcMap[d.id] || [];
      const en = cs.filter((c) => c.status === 'enabled').length;
      const pa = cs.filter((c) => c.status === 'partial').length;
      const tot = cs.length;
      m[d.id] = { score: tot > 0 ? Math.round(((en + pa * 0.5) / tot) * 100) : 0, en: en + pa, tot };
    }
    return m;
  }, [dcMap]);
  const fRecs = useMemo(() => { if (!results) return []; return results.recommendations.filter(r => { if (fPri !== 'all' && r.priority !== fPri) return false; if (fDom !== 'all') { const d = CONTROL_DOMAINS.find(x => x.id === fDom); if (d && !d.controlIds.includes(r.controlId)) return false; } if (fPh !== 'all' && r.phase !== fPh) return false; return true; }); }, [results, fPri, fDom, fPh]);
  const stats = useMemo(() => { if (!results) return { tot: 0, en: 0, pa: 0, dis: 0, rec: 0 }; return { tot: results.controls.length, en: results.controls.filter(c => c.status === 'enabled').length, pa: results.controls.filter(c => c.status === 'partial').length, dis: results.controls.filter(c => c.status === 'disabled').length, rec: results.recommendations.length }; }, [results]);

  if (!isConnected) return <main className="max-w-7xl mx-auto px-6 py-8"><ConnectionPanel /></main>;

  return (
    <main className="max-w-7xl mx-auto px-6 py-8">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-4">
          <button onClick={() => navigate(-1)} className="p-2 hover:bg-slate-800 rounded-lg transition-colors"><ArrowLeft className="w-5 h-5 text-slate-400" /></button>
          <div><h1 className="text-2xl font-bold text-slate-100">API Shield Advisor</h1><p className="text-sm text-slate-400">Guided API security assessment against OWASP API Top 10</p></div>
          <Link to="/explainer/api-shield" className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-400 hover:text-blue-400 rounded-lg text-xs transition-colors">
            <HelpCircle className="w-3.5 h-3.5" /> How does this work?
          </Link>
        </div>
        {results && <div className="flex items-center gap-2">
          <button onClick={() => { setResults(null); setPMsg(''); setPPct(0); }} className="flex items-center gap-1.5 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg text-sm font-medium transition-colors">
            <ArrowLeft className="w-4 h-4" /> Back to Config
          </button>
          <button onClick={exportR} className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition-colors"><Download className="w-4 h-4" />Export</button>
        </div>}
      </div>

      {/* Setup */}
      {!results && !running && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 mb-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <SearchableSelect label="Namespace" options={namespaces.map(n => ({ value: n.name, label: n.name }))} value={selectedNs} onChange={setSelectedNs} placeholder="Select namespace..." />
            <MultiSelectLb label="HTTP Load Balancer(s)" options={loadBalancers.map(l => { const n = l.metadata?.name || l.name; return { value: n, label: n }; })} selected={selectedLbs} onToggle={toggleLb} onSelectAll={selAll} onDeselectAll={deselAll} placeholder="Select LB(s)..." disabled={!selectedNs} />
          </div>
          <div className="mb-6">
            <label className="block text-xs font-medium text-slate-400 mb-2">Scan Depth</label>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {([{ v: 'quick' as AssessmentDepth, l: 'Quick', t: '~30s', d: 'Config analysis only.' }, { v: 'standard' as AssessmentDepth, l: 'Standard', t: '~2 min', d: 'Config + API discovery.' }, { v: 'deep' as AssessmentDepth, l: 'Deep', t: '~5 min', d: 'Full traffic + security events.' }]).map(o => (
                <button key={o.v} onClick={() => setDepth(o.v)} className={`text-left p-4 rounded-lg border transition-colors ${depth === o.v ? 'bg-blue-600/15 border-blue-500/50 ring-1 ring-blue-500/30' : 'bg-slate-800/50 border-slate-700 hover:border-slate-600'}`}>
                  <div className="flex items-center justify-between mb-1"><span className={`text-sm font-semibold ${depth === o.v ? 'text-blue-400' : 'text-slate-200'}`}>{o.l}</span><span className="text-xs text-slate-500">{o.t}</span></div>
                  <p className="text-xs text-slate-400">{o.d}</p>
                </button>
              ))}
            </div>
          </div>
          <button onClick={start} disabled={!selectedNs || selectedLbs.size === 0} className="flex items-center gap-2 px-6 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-lg font-medium transition-colors disabled:cursor-not-allowed"><Play className="w-4 h-4" />Start Assessment</button>
        </div>
      )}

      {/* Scanning */}
      {running && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-8 mb-6">
          <div className="flex flex-col items-center text-center max-w-lg mx-auto">
            <div className="relative mb-6"><Loader2 className="w-12 h-12 text-blue-400 animate-spin" /><Shield className="w-5 h-5 text-blue-400 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" /></div>
            <h2 className="text-lg font-semibold text-slate-200 mb-2">Running Assessment</h2>
            <p className="text-sm text-slate-400 mb-6">{pMsg || 'Initializing...'}</p>
            <div className="w-full bg-slate-700 rounded-full h-2.5 mb-4"><div className="bg-blue-500 h-2.5 rounded-full transition-all duration-500" style={{ width: `${pPct}%` }} /></div>
            <div className="text-xs text-slate-500">{pPct}%</div>
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div className="space-y-6">
          {/* Report header with namespace and LB details */}
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4 flex items-center justify-between">
            <div className="flex items-center gap-6">
              <div>
                <div className="text-[10px] text-slate-500 uppercase tracking-wider">Namespace</div>
                <div className="text-sm font-semibold text-slate-100 font-mono">{results.namespace}</div>
              </div>
              <div className="w-px h-8 bg-slate-700" />
              <div>
                <div className="text-[10px] text-slate-500 uppercase tracking-wider">Load Balancer{results.lbNames.length > 1 ? 's' : ''}</div>
                <div className="flex items-center gap-1.5 mt-0.5">
                  {results.lbNames.map(lb => (
                    <span key={lb} className="px-2 py-0.5 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded text-xs font-mono">{lb}</span>
                  ))}
                </div>
              </div>
              <div className="w-px h-8 bg-slate-700" />
              <div>
                <div className="text-[10px] text-slate-500 uppercase tracking-wider">Scan Depth</div>
                <div className="text-sm text-slate-300 capitalize">{results.depth}</div>
              </div>
            </div>
            <div className="flex items-center gap-2 bg-slate-900/50 rounded-lg px-3 py-1.5">
              <div className="text-[10px] text-slate-500">Score</div>
              <div className={`text-xl font-bold ${results.overallScore >= 70 ? 'text-emerald-400' : results.overallScore >= 40 ? 'text-amber-400' : 'text-red-400'}`}>{results.overallScore}</div>
            </div>
          </div>

          <div className="flex items-center gap-1 overflow-x-auto pb-1">
            <TabBtn active={tab === 'overview'} onClick={() => setTab('overview')} icon={Eye} label="Overview" />
            <TabBtn active={tab === 'domains'} onClick={() => setTab('domains')} icon={Target} label="Domain Guide" />
            <TabBtn active={tab === 'owasp'} onClick={() => setTab('owasp')} icon={Shield} label="OWASP Coverage" />
            <TabBtn active={tab === 'recs'} onClick={() => setTab('recs')} icon={ListChecks} label="Recommendations" badge={results.recommendations.length} />
            {results.discovery && <TabBtn active={tab === 'disc'} onClick={() => setTab('disc')} icon={Search} label="API Discovery" />}
            {results.traffic && <TabBtn active={tab === 'traffic'} onClick={() => setTab('traffic')} icon={Gauge} label="Traffic Profile" />}
            <TabBtn active={tab === 'plan'} onClick={() => setTab('plan')} icon={Map} label="Action Plan" />
          </div>

          {/* Overview */}
          {tab === 'overview' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 flex flex-col items-center">
                  <h3 className="text-sm font-semibold text-slate-400 mb-4">Overall Security Score</h3>
                  <ScoreGauge score={results.overallScore} />
                  <p className="text-xs text-slate-500 mt-4 text-center">{results.overallScore >= 70 ? 'Good posture' : results.overallScore >= 40 ? 'Moderate' : 'Low - action required'}</p>
                </div>
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                  <h3 className="text-sm font-semibold text-slate-400 mb-4">Quick Stats</h3>
                  <div className="space-y-3">
                    {[['Controls', stats.tot, 'text-slate-200'], ['Enabled', stats.en, 'text-emerald-400'], ['Partial', stats.pa, 'text-amber-400'], ['Disabled', stats.dis, 'text-red-400'], ['Recommendations', stats.rec, 'text-amber-400']].map(([l, v, c]) => (
                      <div key={String(l)} className="flex items-center justify-between"><span className="text-sm text-slate-300">{l}</span><span className={`text-lg font-bold ${c}`}>{v}</span></div>
                    ))}
                  </div>
                  <div className="mt-3 pt-3 border-t border-slate-700 text-xs space-y-1">
                    <div className="flex items-center justify-between"><span className="text-slate-500">Namespace:</span><span className="text-slate-300 font-mono">{results.namespace}</span></div>
                    <div className="text-slate-500">Load Balancer{results.lbNames.length > 1 ? 's' : ''}:
                      {results.lbNames.map(lb => <span key={lb} className="ml-1 inline-block px-1.5 py-0.5 bg-slate-700 text-slate-300 rounded font-mono text-[10px]">{lb}</span>)}
                    </div>
                    <div className="text-slate-500">{(results.assessmentDurationMs / 1000).toFixed(1)}s · {results.depth} scan</div>
                  </div>
                </div>
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                  <h3 className="text-sm font-semibold text-slate-400 mb-4">Phase Progress</h3>
                  <div className="space-y-4">
                    {results.phaseProgress.map(p => (
                      <div key={p.phase}>
                        <div className="flex justify-between mb-1"><span className="text-xs font-medium text-slate-300">{p.phaseName}</span><span className={`text-xs font-bold ${sClr(p.completionPercent)}`}>{p.completionPercent}%</span></div>
                        <div className="w-full bg-slate-700 rounded-full h-1.5"><div className={`h-1.5 rounded-full ${sBg(p.completionPercent)}`} style={{ width: `${p.completionPercent}%` }} /></div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
              <div>
                <h3 className="text-sm font-semibold text-slate-400 mb-3">Security Domains</h3>
                <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
                  {CONTROL_DOMAINS.map(d => { const i = dScores[d.id] || { score: 0, en: 0, tot: 0 }; return (
                    <button key={d.id} onClick={() => { setTab('domains'); setDomId(d.id); }} className="bg-slate-800/50 border border-slate-700 rounded-xl p-4 hover:border-slate-600 transition-colors text-left group">
                      <div className="flex items-center gap-2 mb-2"><DomainIcon iconName={d.icon} className={`w-4 h-4 ${sClr(i.score)}`} /><span className={`text-lg font-bold ${sClr(i.score)}`}>{i.score}</span></div>
                      <div className="text-xs font-medium text-slate-300 mb-1 line-clamp-2 group-hover:text-slate-100">{d.name}</div>
                      <div className="text-[10px] text-slate-500">{i.en}/{i.tot} enabled</div>
                    </button>
                  ); })}
                </div>
              </div>
              {results.security && results.security.totalSecurityEvents > 0 && (
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                  <h3 className="text-sm font-semibold text-slate-400 mb-4">Security Events (24h)</h3>
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                    {[['Total', results.security.totalSecurityEvents, 'text-slate-200'], ['WAF', results.security.wafEvents, 'text-blue-400'], ['Bot', results.security.botEvents, 'text-amber-400'], ['DDoS', results.security.ddosEvents, 'text-red-400'], ['Rate', results.security.rateLimitEvents, 'text-violet-400']].map(([l, v, c]) => (
                      <div key={String(l)} className="bg-slate-900/50 rounded-lg p-3 text-center"><div className="text-xs text-slate-500 mb-1">{l}</div><div className={`text-xl font-bold ${c}`}>{(v as number).toLocaleString()}</div></div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Domain Guide */}
          {tab === 'domains' && (() => {
            const dom = CONTROL_DOMAINS.find(d => d.id === domId);
            const ctrls = dcMap[domId] || [];
            const info = dScores[domId] || { score: 0, en: 0, tot: 0 };
            return (
              <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                <div className="lg:col-span-1 bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
                  <div className="p-3 border-b border-slate-700"><h3 className="text-sm font-semibold text-slate-300">Domains</h3></div>
                  <div className="divide-y divide-slate-700/50">
                    {CONTROL_DOMAINS.map(d => { const i = dScores[d.id] || { score: 0, en: 0, tot: 0 }; return (
                      <button key={d.id} onClick={() => setDomId(d.id)} className={`w-full flex items-center gap-3 px-3 py-3 text-left hover:bg-slate-700/30 ${domId === d.id ? 'bg-slate-700/40 border-l-2 border-l-blue-500' : ''}`}>
                        <DomainIcon iconName={d.icon} className={`w-4 h-4 shrink-0 ${sClr(i.score)}`} />
                        <div className="flex-1 min-w-0"><div className="text-xs font-medium text-slate-200 truncate">{d.name}</div><div className="text-[10px] text-slate-500">{i.en}/{i.tot}</div></div>
                        <span className={`text-xs font-bold ${sClr(i.score)}`}>{i.score}</span>
                      </button>
                    ); })}
                  </div>
                </div>
                <div className="lg:col-span-3">
                  {!dom ? <div className="text-sm text-slate-500 p-6">Select a domain</div> : (
                    <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
                      <div className="p-6 border-b border-slate-700">
                        <div className="flex items-center gap-3 mb-2"><DomainIcon iconName={dom.icon} className={`w-6 h-6 ${sClr(info.score)}`} /><h3 className="text-lg font-semibold text-slate-200">{dom.name}</h3><span className={`text-lg font-bold ${sClr(info.score)}`}>{info.score}/100</span></div>
                        <p className="text-sm text-slate-400">{dom.description}</p>
                        <div className="flex items-center gap-4 mt-3">
                          <div className="flex items-center gap-1.5"><CheckCircle className="w-3.5 h-3.5 text-emerald-400" /><span className="text-xs text-slate-400">{ctrls.filter((c: SecurityControl) => c.status === 'enabled').length} enabled</span></div>
                          <div className="flex items-center gap-1.5"><AlertTriangle className="w-3.5 h-3.5 text-amber-400" /><span className="text-xs text-slate-400">{ctrls.filter((c: SecurityControl) => c.status === 'partial').length} partial</span></div>
                          <div className="flex items-center gap-1.5"><XCircle className="w-3.5 h-3.5 text-red-400" /><span className="text-xs text-slate-400">{ctrls.filter((c: SecurityControl) => c.status === 'disabled' || c.status === 'unknown').length} disabled</span></div>
                        </div>
                      </div>
                      <div className="divide-y divide-slate-700/50">{ctrls.map(c => <ControlRow key={c.id} control={c} />)}{ctrls.length === 0 && <div className="p-6 text-center text-sm text-slate-500">No controls</div>}</div>
                    </div>
                  )}
                </div>
              </div>
            );
          })()}

          {/* OWASP Coverage */}
          {tab === 'owasp' && (
            <div className="space-y-4">
              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4"><p className="text-sm text-slate-400">Coverage against <span className="text-slate-200 font-medium">OWASP API Security Top 10 (2023)</span>.</p></div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {results.owaspCoverage.map(o => {
                  const st = o.coveragePercent >= 80 ? 'fully' : o.coveragePercent > 0 ? 'partially' : 'not';
                  const cls = { fully: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30', partially: 'bg-amber-500/15 text-amber-400 border-amber-500/30', not: 'bg-red-500/15 text-red-400 border-red-500/30' }[st] as string;
                  const lbl = { fully: 'Fully Covered', partially: 'Partially Covered', not: 'Not Covered' }[st] as string;
                  const def = OWASP_API_TOP_10.find(x => x.id === o.id);
                  const allIds = def?.controls || [];
                  const missing = allIds.filter(id => !o.coveredByControls.includes(id));
                  const gn = (id: string) => results.controls.find(c => c.id === id)?.name || id;
                  return (
                    <div key={o.id} className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
                      <div className="flex items-start justify-between mb-3"><div><div className="flex items-center gap-2 mb-1"><span className="px-2 py-0.5 bg-indigo-500/20 text-indigo-400 text-xs font-mono rounded font-bold">{o.id}</span><span className={`px-2 py-0.5 rounded text-xs font-semibold border ${cls}`}>{lbl}</span></div><h4 className="text-sm font-semibold text-slate-200">{o.name}</h4></div><span className={`text-xl font-bold ${sClr(o.coveragePercent)}`}>{o.coveragePercent}%</span></div>
                      <p className="text-xs text-slate-400 mb-3">{o.description}</p>
                      <div className="w-full bg-slate-700 rounded-full h-1.5 mb-3"><div className={`h-1.5 rounded-full ${sBg(o.coveragePercent)}`} style={{ width: `${o.coveragePercent}%` }} /></div>
                      {o.coveredByControls.length > 0 && <div className="mb-2"><div className="text-[10px] font-semibold text-slate-500 mb-1">COVERED</div>{o.coveredByControls.map(id => <div key={id} className="flex items-center gap-1.5 text-xs text-emerald-400"><CheckCircle className="w-3 h-3 shrink-0" />{gn(id)}</div>)}</div>}
                      {missing.length > 0 && <div><div className="text-[10px] font-semibold text-slate-500 mb-1">MISSING</div>{missing.map(id => <div key={id} className="flex items-center gap-1.5 text-xs text-red-400"><XCircle className="w-3 h-3 shrink-0" />{gn(id)}</div>)}</div>}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {tab === 'recs' && (
            <div className="space-y-4">
              <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-3"><Filter className="w-4 h-4 text-slate-400" /><span className="text-sm font-medium text-slate-300">Filters</span><span className="text-xs text-slate-500">({fRecs.length}/{results.recommendations.length})</span></div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div><label className="block text-xs text-slate-500 mb-1">Priority</label><select value={fPri} onChange={e => setFPri(e.target.value)} className="w-full px-3 py-1.5 bg-slate-900 border border-slate-600 rounded-lg text-sm text-slate-200"><option value="all">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
                  <div><label className="block text-xs text-slate-500 mb-1">Domain</label><select value={fDom} onChange={e => setFDom(e.target.value)} className="w-full px-3 py-1.5 bg-slate-900 border border-slate-600 rounded-lg text-sm text-slate-200"><option value="all">All</option>{CONTROL_DOMAINS.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}</select></div>
                  <div><label className="block text-xs text-slate-500 mb-1">Phase</label><select value={fPh} onChange={e => setFPh(e.target.value)} className="w-full px-3 py-1.5 bg-slate-900 border border-slate-600 rounded-lg text-sm text-slate-200"><option value="all">All</option><option value="foundation">Foundation</option><option value="visibility">Visibility</option><option value="enforcement">Enforcement</option><option value="advanced">Advanced</option></select></div>
                </div>
              </div>
              {fRecs.length === 0 && <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-8 text-center"><CheckCircle className="w-8 h-8 text-emerald-400 mx-auto mb-2" /><p className="text-sm text-slate-400">{results.recommendations.length === 0 ? 'All controls enabled!' : 'No matches.'}</p></div>}
              {fRecs.map(r => <RecCard key={r.controlId} rec={r} />)}
            </div>
          )}

          {/* API Discovery */}
          {tab === 'disc' && results.discovery && (() => {
            const data = results.discovery;
            const auth = [{ name: 'Auth', value: data.authenticatedEndpoints, fill: '#34d399' }, { name: 'Unauth', value: data.unauthenticatedEndpoints, fill: '#f87171' }].filter(d => d.value > 0);
            return (
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5"><div className="text-xs text-slate-500 mb-1">Endpoints</div><div className="text-2xl font-bold text-slate-200">{data.totalDiscoveredEndpoints}</div></div>
                  <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5"><div className="text-xs text-slate-500 mb-1">Shadow APIs</div><div className="text-2xl font-bold text-red-400">{data.shadowApiCount}</div></div>
                  <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5"><div className="text-xs text-slate-500 mb-1">PII Types</div><div className="text-2xl font-bold text-amber-400">{data.piiTypesFound.length}</div></div>
                  <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5"><div className="text-xs text-slate-500 mb-1">Auth</div>{auth.length > 0 ? <div className="h-16"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={auth} dataKey="value" cx="50%" cy="50%" innerRadius={15} outerRadius={30}>{auth.map((e, i) => <Cell key={i} fill={e.fill} />)}</Pie><Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #475569', borderRadius: 8, fontSize: 12 }} /></PieChart></ResponsiveContainer></div> : <span className="text-sm text-slate-400">N/A</span>}</div>
                </div>
                {data.lbInsights.length > 0 && <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5"><h3 className="text-sm font-semibold text-slate-300 mb-3">Per-LB Status</h3><div className="space-y-2">{data.lbInsights.map(lb => <div key={lb.lbName} className="flex items-center gap-3 px-3 py-2 bg-slate-900/50 rounded-lg"><span className="text-xs text-slate-300 font-medium flex-1 truncate">{lb.lbName}</span><span className={`text-[10px] px-2 py-0.5 rounded ${lb.discoveryEnabled ? 'bg-emerald-500/15 text-emerald-400' : 'bg-red-500/15 text-red-400'}`}>Discovery: {lb.discoveryEnabled ? 'ON' : 'OFF'}</span><span className="text-xs text-slate-400">{lb.endpointCount} ep</span>{lb.shadowCount > 0 && <span className="text-[10px] px-2 py-0.5 rounded bg-red-500/15 text-red-400">{lb.shadowCount} shadow</span>}</div>)}</div></div>}
                {data.endpoints.length > 0 && <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden"><div className="p-4 border-b border-slate-700"><h3 className="text-sm font-semibold text-slate-300">Endpoints by Risk</h3></div><div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="text-xs text-slate-500 border-b border-slate-700"><th className="text-left px-4 py-2">Method</th><th className="text-left px-4 py-2">Path</th><th className="text-left px-4 py-2">Risk</th><th className="text-left px-4 py-2">Auth</th><th className="text-left px-4 py-2">Status</th><th className="text-right px-4 py-2">Reqs</th></tr></thead><tbody className="divide-y divide-slate-700/50">{[...data.endpoints].sort((a, b) => b.riskScore - a.riskScore).slice(0, 20).map((e, i) => <tr key={i} className="hover:bg-slate-800/50"><td className="px-4 py-2"><span className="px-1.5 py-0.5 bg-blue-500/20 text-blue-400 text-xs rounded font-mono">{e.method}</span></td><td className="px-4 py-2 text-slate-300 font-mono text-xs truncate max-w-[300px]">{e.path}</td><td className="px-4 py-2"><span className={`text-xs font-bold ${e.riskScore >= 7 ? 'text-red-400' : e.riskScore >= 4 ? 'text-amber-400' : 'text-emerald-400'}`}>{e.riskScore}/10</span></td><td className="px-4 py-2"><span className={`text-xs ${e.authenticated ? 'text-emerald-400' : 'text-red-400'}`}>{e.authenticated ? 'Y' : 'N'}</span></td><td className="px-4 py-2">{e.isInDefinition ? <CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> : <span className="px-1.5 py-0.5 bg-red-500/15 text-red-400 text-[10px] rounded font-semibold">SHADOW</span>}</td><td className="px-4 py-2 text-right text-slate-400">{e.requestCount.toLocaleString()}</td></tr>)}</tbody></table></div></div>}
                {data.totalDiscoveredEndpoints === 0 && <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-8 text-center"><Search className="w-8 h-8 text-slate-600 mx-auto mb-3" /><h3 className="text-sm font-semibold text-slate-300 mb-1">No Discovery Data</h3><p className="text-xs text-slate-500">Enable API Discovery on your LBs.</p></div>}
              </div>
            );
          })()}

          {/* Traffic */}
          {tab === 'traffic' && results.traffic && (() => {
            const data = results.traffic;
            const codes = Object.entries(data.responseCodeBreakdown).sort((a, b) => b[1] - a[1]).map(([c, n]) => ({ name: c, count: n, fill: c.startsWith('2') ? '#34d399' : c.startsWith('3') ? '#60a5fa' : c.startsWith('4') ? '#fbbf24' : '#f87171' }));
            return (
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  {[['Avg RPS', data.avgRps, 'text-slate-200'], ['Peak RPS', data.peakRps, 'text-blue-400'], ['Error Rate', `${data.errorRate}%`, 'text-amber-400'], ['Sample', data.sampleSize.toLocaleString(), 'text-slate-200']].map(([l, v, c]) => <div key={String(l)} className="bg-slate-800/50 border border-slate-700 rounded-xl p-5"><div className="text-xs text-slate-500 mb-1">{l}</div><div className={`text-2xl font-bold ${c}`}>{v}</div></div>)}
                </div>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5"><h3 className="text-sm font-semibold text-slate-300 mb-4">Response Codes</h3>{codes.length > 0 ? <div className="h-64"><ResponsiveContainer width="100%" height="100%"><BarChart data={codes}><CartesianGrid strokeDasharray="3 3" stroke="#334155" /><XAxis dataKey="name" stroke="#94a3b8" fontSize={12} /><YAxis stroke="#94a3b8" fontSize={12} /><Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #475569', borderRadius: 8, fontSize: 12 }} /><Bar dataKey="count" radius={[4, 4, 0, 0]}>{codes.map((e, i) => <Cell key={i} fill={e.fill} />)}</Bar></BarChart></ResponsiveContainer></div> : <div className="h-64 flex items-center justify-center text-sm text-slate-500">No data</div>}</div>
                  <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5"><h3 className="text-sm font-semibold text-slate-300 mb-4">Top Countries</h3>{data.topCountries.length > 0 ? <div className="space-y-2">{data.topCountries.slice(0, 10).map((c, i) => { const p = data.sampleSize > 0 ? Math.round(c.count / data.sampleSize * 100) : 0; return <div key={i} className="flex items-center gap-3"><span className="text-xs text-slate-400 w-24 truncate">{c.country}</span><div className="flex-1 bg-slate-700 rounded-full h-2"><div className="bg-blue-500 h-2 rounded-full" style={{ width: `${Math.min(p, 100)}%` }} /></div><span className="text-xs text-slate-400 w-12 text-right">{p}%</span></div>; })}</div> : <div className="h-48 flex items-center justify-center text-sm text-slate-500">No data</div>}</div>
                </div>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5"><h3 className="text-sm font-semibold text-slate-300 mb-4">Bot Traffic</h3><div className="flex items-center gap-6"><div className="relative w-24 h-24"><svg width={96} height={96} className="transform -rotate-90"><circle cx={48} cy={48} r={38} stroke="rgb(51 65 85 / 0.5)" strokeWidth={8} fill="none" /><circle cx={48} cy={48} r={38} stroke={data.botTrafficPercent > 30 ? '#f87171' : data.botTrafficPercent > 10 ? '#fbbf24' : '#34d399'} strokeWidth={8} fill="none" strokeLinecap="round" strokeDasharray={2 * Math.PI * 38} strokeDashoffset={2 * Math.PI * 38 * (1 - data.botTrafficPercent / 100)} /></svg><div className="absolute inset-0 flex items-center justify-center"><span className={`text-lg font-bold ${data.botTrafficPercent > 30 ? 'text-red-400' : data.botTrafficPercent > 10 ? 'text-amber-400' : 'text-emerald-400'}`}>{data.botTrafficPercent}%</span></div></div><p className="text-sm text-slate-300">{data.botTrafficPercent > 30 ? 'High bot traffic' : 'Normal'}</p></div></div>
                  <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5"><h3 className="text-sm font-semibold text-slate-300 mb-4">Latency</h3><div className="bg-slate-900/50 rounded-lg p-4 text-center"><div className="text-xs text-slate-500 mb-1">Average</div><div className={`text-2xl font-bold ${data.avgLatencyMs > 1000 ? 'text-red-400' : data.avgLatencyMs > 500 ? 'text-amber-400' : 'text-emerald-400'}`}>{data.avgLatencyMs.toFixed(1)}ms</div></div></div>
                </div>
                {data.topPaths.length > 0 && <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden"><div className="p-4 border-b border-slate-700"><h3 className="text-sm font-semibold text-slate-300">Top Paths</h3></div><table className="w-full text-sm"><thead><tr className="text-xs text-slate-500 border-b border-slate-700"><th className="text-left px-4 py-2">Path</th><th className="text-right px-4 py-2">Reqs</th><th className="text-right px-4 py-2">Errors</th></tr></thead><tbody className="divide-y divide-slate-700/50">{data.topPaths.map((p, i) => <tr key={i}><td className="px-4 py-2 text-slate-300 font-mono text-xs truncate max-w-[400px]">{p.path}</td><td className="px-4 py-2 text-right text-slate-400">{p.count}</td><td className="px-4 py-2 text-right"><span className={`text-xs ${p.errorRate > 10 ? 'text-red-400' : 'text-slate-400'}`}>{p.errorRate}%</span></td></tr>)}</tbody></table></div>}
              </div>
            );
          })()}

          {/* Action Plan */}
          {tab === 'plan' && (() => {
            const ov = results.phaseProgress.length > 0 ? Math.round(results.phaseProgress.reduce((s, p) => s + p.completionPercent, 0) / results.phaseProgress.length) : 0;
            const descs: Record<ControlPhase, [string, string]> = { foundation: ['Core baseline', 'Week 1'], visibility: ['Detection & monitoring', 'Week 2-3'], enforcement: ['Active blocking', 'Week 3-4'], advanced: ['Optimization', 'Week 4+'] };
            return (
              <div className="space-y-6">
                <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div><h3 className="text-lg font-semibold text-slate-200">Implementation Plan</h3><p className="text-sm text-slate-400">4-phase approach</p></div>
                    <div className="flex items-center gap-4"><div className="text-right"><div className={`text-2xl font-bold ${sClr(ov)}`}>{ov}%</div><div className="text-xs text-slate-500">Overall</div></div><button onClick={exportR} className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium"><Download className="w-4 h-4" />Export</button></div>
                  </div>
                  <div className="w-full bg-slate-700 rounded-full h-3"><div className={`h-3 rounded-full ${sBg(ov)}`} style={{ width: `${ov}%` }} /></div>
                </div>
                {results.phaseProgress.map(ph => {
                  const pCtrls = results.controls.filter(c => c.phase === ph.phase);
                  const [desc, time] = descs[ph.phase] || ['', ''];
                  return <PhaseCard key={ph.phase} phase={ph} pCtrls={pCtrls} desc={desc} time={time} />;
                })}
              </div>
            );
          })()}
        </div>
      )}
    </main>
  );
}

function PhaseCard({ phase, pCtrls, desc, time }: { phase: PhaseProgress; pCtrls: SecurityControl[]; desc: string; time: string }) {
  const [exp, setExp] = useState(phase.completionPercent < 100);
  return (
    <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
      <button onClick={() => setExp(!exp)} className="w-full flex items-center gap-4 p-5 hover:bg-slate-800/70 transition-colors text-left">
        <div className={`w-10 h-10 rounded-full flex items-center justify-center font-bold text-sm shrink-0 ${phase.completionPercent >= 100 ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : phase.completionPercent > 0 ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' : 'bg-slate-700 text-slate-400 border border-slate-600'}`}>
          {phase.completionPercent >= 100 ? <CheckCircle className="w-5 h-5" /> : phase.phaseName.charAt(0)}
        </div>
        <div className="flex-1 min-w-0"><div className="flex items-center gap-3"><h4 className="text-sm font-semibold text-slate-200">{phase.phaseName}</h4><span className="flex items-center gap-1 text-xs text-slate-500"><Clock className="w-3 h-3" />{time}</span></div><p className="text-xs text-slate-400 mt-0.5">{desc}</p></div>
        <div className="flex items-center gap-3 shrink-0"><div className="w-24"><span className={`text-xs font-bold ${sClr(phase.completionPercent)}`}>{phase.completionPercent}%</span><div className="w-full bg-slate-700 rounded-full h-1.5 mt-1"><div className={`h-1.5 rounded-full ${sBg(phase.completionPercent)}`} style={{ width: `${phase.completionPercent}%` }} /></div></div>{exp ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}</div>
      </button>
      {exp && <div className="px-5 pb-5 border-t border-slate-700/50 pt-3"><div className="flex gap-4 mb-3 text-xs text-slate-500"><span>{phase.enabledControls} enabled</span><span>{phase.partialControls} partial</span><span>{phase.disabledControls} disabled</span></div><div className="grid grid-cols-1 md:grid-cols-2 gap-2">{pCtrls.map(c => <div key={c.id} className={`flex items-center gap-2 px-3 py-2 rounded-lg ${c.status === 'enabled' ? 'bg-emerald-500/10 border border-emerald-500/20' : c.status === 'partial' ? 'bg-amber-500/10 border border-amber-500/20' : 'bg-slate-900/50 border border-slate-700'}`}>{c.status === 'enabled' ? <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" /> : c.status === 'partial' ? <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" /> : <XCircle className="w-4 h-4 text-slate-500 shrink-0" />}<span className={`text-xs font-medium flex-1 ${c.status === 'enabled' ? 'text-emerald-400' : c.status === 'partial' ? 'text-amber-400' : 'text-slate-400'}`}>{c.name}</span><PriorityBadge priority={c.priority} /></div>)}</div></div>}
    </div>
  );
}
