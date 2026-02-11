// ═══════════════════════════════════════════════════════════════════════════
// Security Auditor Page Component
// Main UI for running security audits
// ═══════════════════════════════════════════════════════════════════════════

import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  ArrowLeft,
  Play,
  XCircle,
  CheckCircle,
  AlertTriangle,
  AlertCircle,
  Info,
  ChevronDown,
  ChevronRight,
  Download,
  RefreshCw,
  Filter,
  Search,
  ExternalLink,
  FileJson,
  FileText,
  Loader2,
  Clock,
  Database,
  Layers,
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import { apiClient } from '../services/api';
import { AuditEngine } from '../services/security-auditor/audit-engine';
import { allRules, getRuleStats } from '../services/security-auditor/rules';
import {
  CATEGORY_INFO,
  SEVERITY_INFO,
  STATUS_INFO,
} from '../services/security-auditor/types';
import type {
  AuditReport,
  AuditProgress,
  AuditFinding,
  RuleCategory,
  Severity,
  AuditOptions,
} from '../services/security-auditor/types';
import type { Namespace } from '../types';

// ═══════════════════════════════════════════════════════════════════════════
// COMPONENT
// ═══════════════════════════════════════════════════════════════════════════

export function SecurityAuditor() {
  const { isConnected, tenant } = useApp();
  const navigate = useNavigate();
  const toast = useToast();
  const engineRef = useRef<AuditEngine | null>(null);

  // State
  const [step, setStep] = useState<'config' | 'running' | 'results'>('config');
  const [namespaces, setNamespaces] = useState<Namespace[]>([]);
  const [selectedNamespaces, setSelectedNamespaces] = useState<string[]>([]);
  const [isLoadingNamespaces, setIsLoadingNamespaces] = useState(true);
  const [selectAllNamespaces, setSelectAllNamespaces] = useState(false);

  // Categories and severity filter
  const [selectedCategories, setSelectedCategories] = useState<RuleCategory[]>(
    Object.keys(CATEGORY_INFO) as RuleCategory[]
  );
  const [selectedSeverities, setSelectedSeverities] = useState<Severity[]>([
    'CRITICAL',
    'HIGH',
    'MEDIUM',
  ]);
  const [includePassedChecks, setIncludePassedChecks] = useState(false);

  // Progress and results
  const [progress, setProgress] = useState<AuditProgress | null>(null);
  const [report, setReport] = useState<AuditReport | null>(null);

  // Results filtering
  const [filterSeverity, setFilterSeverity] = useState<Severity | 'ALL'>('ALL');
  const [filterCategory, setFilterCategory] = useState<RuleCategory | 'ALL'>('ALL');
  const [filterStatus, setFilterStatus] = useState<string>('FAIL');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());

  // ─────────────────────────────────────────────────────────────────────────
  // EFFECTS
  // ─────────────────────────────────────────────────────────────────────────

  useEffect(() => {
    if (!isConnected) {
      navigate('/');
    }
  }, [isConnected, navigate]);

  useEffect(() => {
    loadNamespaces();
  }, []);

  // ─────────────────────────────────────────────────────────────────────────
  // LOAD NAMESPACES
  // ─────────────────────────────────────────────────────────────────────────

  const loadNamespaces = async () => {
    setIsLoadingNamespaces(true);
    try {
      const resp = await apiClient.getNamespaces();
      const nsList = resp.items || [];
      setNamespaces(nsList);

      // Auto-select 'default' if exists
      const hasDefault = nsList.some((ns) => ns.name === 'default');
      if (hasDefault) {
        setSelectedNamespaces(['default']);
      }
    } catch (err) {
      toast.error('Failed to load namespaces');
    } finally {
      setIsLoadingNamespaces(false);
    }
  };

  // ─────────────────────────────────────────────────────────────────────────
  // RUN AUDIT
  // ─────────────────────────────────────────────────────────────────────────

  const startAudit = async () => {
    if (selectedNamespaces.length === 0) {
      toast.error('Please select at least one namespace');
      return;
    }

    setStep('running');
    setProgress({ phase: 'fetching', message: 'Starting audit...', progress: 0 });
    setReport(null);

    const engine = new AuditEngine((p) => setProgress(p));
    engineRef.current = engine;

    const options: AuditOptions = {
      categories: selectedCategories.length < Object.keys(CATEGORY_INFO).length ? selectedCategories : undefined,
      includePassedChecks,
    };

    try {
      const result = await engine.runAudit(selectedNamespaces, options);
      setReport(result);
      setStep('results');
      toast.success(`Audit complete! Score: ${result.score}/100`);
    } catch (err) {
      if ((err as Error).message === 'Audit aborted') {
        toast.info('Audit cancelled');
        setStep('config');
      } else {
        toast.error(`Audit failed: ${(err as Error).message}`);
        setStep('config');
      }
    } finally {
      engineRef.current = null;
    }
  };

  const cancelAudit = () => {
    if (engineRef.current) {
      engineRef.current.abort();
    }
  };

  // ─────────────────────────────────────────────────────────────────────────
  // NAMESPACE SELECTION HELPERS
  // ─────────────────────────────────────────────────────────────────────────

  const toggleNamespace = (ns: string) => {
    setSelectedNamespaces((prev) =>
      prev.includes(ns) ? prev.filter((n) => n !== ns) : [...prev, ns]
    );
  };

  const toggleSelectAll = () => {
    if (selectAllNamespaces) {
      setSelectedNamespaces([]);
    } else {
      setSelectedNamespaces(namespaces.map((ns) => ns.name));
    }
    setSelectAllNamespaces(!selectAllNamespaces);
  };

  // ─────────────────────────────────────────────────────────────────────────
  // CATEGORY SELECTION HELPERS
  // ─────────────────────────────────────────────────────────────────────────

  const toggleCategory = (cat: RuleCategory) => {
    setSelectedCategories((prev) =>
      prev.includes(cat) ? prev.filter((c) => c !== cat) : [...prev, cat]
    );
  };

  const selectAllCategories = () => {
    setSelectedCategories(Object.keys(CATEGORY_INFO) as RuleCategory[]);
  };

  const deselectAllCategories = () => {
    setSelectedCategories([]);
  };

  // ─────────────────────────────────────────────────────────────────────────
  // FILTER RESULTS
  // ─────────────────────────────────────────────────────────────────────────

  const filteredFindings = report?.findings.filter((f) => {
    if (filterSeverity !== 'ALL' && f.severity !== filterSeverity) return false;
    if (filterCategory !== 'ALL' && f.category !== filterCategory) return false;
    if (filterStatus !== 'ALL' && f.status !== filterStatus) return false;
    if (searchTerm) {
      const search = searchTerm.toLowerCase();
      return (
        f.ruleName.toLowerCase().includes(search) ||
        f.objectName.toLowerCase().includes(search) ||
        f.namespace.toLowerCase().includes(search) ||
        f.ruleId.toLowerCase().includes(search)
      );
    }
    return true;
  }) || [];

  // ─────────────────────────────────────────────────────────────────────────
  // TOGGLE FINDING EXPANDED
  // ─────────────────────────────────────────────────────────────────────────

  const toggleFinding = (key: string) => {
    setExpandedFindings((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  };

  // ─────────────────────────────────────────────────────────────────────────
  // EXPORT FUNCTIONS
  // ─────────────────────────────────────────────────────────────────────────

  const exportJSON = () => {
    if (!report) return;

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-audit-${report.timestamp.slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // ─────────────────────────────────────────────────────────────────────────
  // GET RULE STATS
  // ─────────────────────────────────────────────────────────────────────────

  const ruleStats = getRuleStats();

  // ─────────────────────────────────────────────────────────────────────────
  // RENDER SEVERITY BADGE
  // ─────────────────────────────────────────────────────────────────────────

  const SeverityBadge = ({ severity }: { severity: Severity }) => {
    const info = SEVERITY_INFO[severity];
    return (
      <span className={`px-2 py-0.5 rounded text-xs font-medium ${info.bgColor} ${info.color}`}>
        {info.label}
      </span>
    );
  };

  // ─────────────────────────────────────────────────────────────────────────
  // RENDER STATUS ICON
  // ─────────────────────────────────────────────────────────────────────────

  const StatusIcon = ({ status }: { status: string }) => {
    switch (status) {
      case 'PASS':
        return <CheckCircle className="w-5 h-5 text-green-400" />;
      case 'FAIL':
        return <XCircle className="w-5 h-5 text-red-400" />;
      case 'WARN':
        return <AlertTriangle className="w-5 h-5 text-yellow-400" />;
      case 'ERROR':
        return <AlertCircle className="w-5 h-5 text-purple-400" />;
      default:
        return <Info className="w-5 h-5 text-slate-400" />;
    }
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // RENDER
  // ═══════════════════════════════════════════════════════════════════════════

  return (
    <div className="min-h-screen bg-slate-900">
      {/* Header */}
      <header className="bg-slate-800 border-b border-slate-700 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate('/')}
              className="p-2 hover:bg-slate-700 rounded-lg transition-colors"
            >
              <ArrowLeft className="w-5 h-5 text-slate-400" />
            </button>
            <div className="flex items-center gap-3">
              <div className="p-2 bg-emerald-500/20 rounded-lg">
                <Shield className="w-6 h-6 text-emerald-400" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-slate-100">Security Auditor</h1>
                <p className="text-sm text-slate-400">
                  Validate configurations against security best practices
                </p>
              </div>
            </div>
          </div>

          {report && step === 'results' && (
            <div className="flex items-center gap-3">
              <button
                onClick={() => setStep('config')}
                className="flex items-center gap-2 px-4 py-2 text-slate-300 hover:bg-slate-700 rounded-lg transition-colors"
              >
                <RefreshCw className="w-4 h-4" />
                New Audit
              </button>
              <button
                onClick={exportJSON}
                className="flex items-center gap-2 px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors"
              >
                <FileJson className="w-4 h-4" />
                Export JSON
              </button>
            </div>
          )}
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* ═══════════════════════════════════════════════════════════════════ */}
        {/* CONFIGURATION STEP */}
        {/* ═══════════════════════════════════════════════════════════════════ */}
        {step === 'config' && (
          <div className="space-y-8">
            {/* Rule Stats */}
            <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
              <h2 className="text-lg font-semibold text-slate-100 mb-4">Security Rules Overview</h2>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="text-3xl font-bold text-blue-400">{ruleStats.total}</div>
                  <div className="text-sm text-slate-400">Total Rules</div>
                </div>
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="text-3xl font-bold text-red-400">{ruleStats.bySeverity.CRITICAL || 0}</div>
                  <div className="text-sm text-slate-400">Critical</div>
                </div>
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="text-3xl font-bold text-orange-400">{ruleStats.bySeverity.HIGH || 0}</div>
                  <div className="text-sm text-slate-400">High</div>
                </div>
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="text-3xl font-bold text-yellow-400">{ruleStats.bySeverity.MEDIUM || 0}</div>
                  <div className="text-sm text-slate-400">Medium</div>
                </div>
              </div>
            </div>

            {/* Namespace Selection */}
            <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-slate-100">Select Namespaces</h2>
                <button
                  onClick={toggleSelectAll}
                  className="text-sm text-blue-400 hover:text-blue-300"
                >
                  {selectAllNamespaces ? 'Deselect All' : 'Select All'}
                </button>
              </div>

              {isLoadingNamespaces ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-6 h-6 text-blue-400 animate-spin" />
                </div>
              ) : (
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2">
                  {namespaces.map((ns) => (
                    <label
                      key={ns.name}
                      className={`flex items-center gap-2 p-3 rounded-lg cursor-pointer transition-colors ${
                        selectedNamespaces.includes(ns.name)
                          ? 'bg-blue-500/20 border border-blue-500/50'
                          : 'bg-slate-700/50 border border-transparent hover:bg-slate-700'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={selectedNamespaces.includes(ns.name)}
                        onChange={() => toggleNamespace(ns.name)}
                        className="rounded border-slate-600 text-blue-500 focus:ring-blue-500"
                      />
                      <span className="text-sm text-slate-200 truncate">{ns.name}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>

            {/* Category Selection */}
            <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-slate-100">Rule Categories</h2>
                <div className="flex gap-2">
                  <button
                    onClick={selectAllCategories}
                    className="text-sm text-blue-400 hover:text-blue-300"
                  >
                    Select All
                  </button>
                  <span className="text-slate-600">|</span>
                  <button
                    onClick={deselectAllCategories}
                    className="text-sm text-blue-400 hover:text-blue-300"
                  >
                    Deselect All
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                {(Object.entries(CATEGORY_INFO) as [RuleCategory, typeof CATEGORY_INFO[RuleCategory]][]).map(
                  ([cat, info]) => (
                    <label
                      key={cat}
                      className={`flex items-center gap-3 p-3 rounded-lg cursor-pointer transition-colors ${
                        selectedCategories.includes(cat)
                          ? 'bg-emerald-500/20 border border-emerald-500/50'
                          : 'bg-slate-700/50 border border-transparent hover:bg-slate-700'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={selectedCategories.includes(cat)}
                        onChange={() => toggleCategory(cat)}
                        className="rounded border-slate-600 text-emerald-500 focus:ring-emerald-500"
                      />
                      <span className="text-lg">{info.icon}</span>
                      <span className="text-sm text-slate-200">{info.label}</span>
                    </label>
                  )
                )}
              </div>
            </div>

            {/* Options */}
            <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
              <h2 className="text-lg font-semibold text-slate-100 mb-4">Options</h2>
              <label className="flex items-center gap-3">
                <input
                  type="checkbox"
                  checked={includePassedChecks}
                  onChange={(e) => setIncludePassedChecks(e.target.checked)}
                  className="rounded border-slate-600 text-blue-500 focus:ring-blue-500"
                />
                <span className="text-slate-200">Include passed checks in results</span>
              </label>
            </div>

            {/* Start Button */}
            <div className="flex justify-center">
              <button
                onClick={startAudit}
                disabled={selectedNamespaces.length === 0 || selectedCategories.length === 0}
                className="flex items-center gap-3 px-8 py-4 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-colors text-lg"
              >
                <Play className="w-6 h-6" />
                Start Security Audit
              </button>
            </div>
          </div>
        )}

        {/* ═══════════════════════════════════════════════════════════════════ */}
        {/* RUNNING STEP */}
        {/* ═══════════════════════════════════════════════════════════════════ */}
        {step === 'running' && progress && (
          <div className="max-w-2xl mx-auto">
            <div className="bg-slate-800 rounded-xl p-8 border border-slate-700">
              <div className="text-center mb-8">
                <Loader2 className="w-16 h-16 text-emerald-400 animate-spin mx-auto mb-4" />
                <h2 className="text-2xl font-bold text-slate-100 mb-2">Running Security Audit</h2>
                <p className="text-slate-400">{progress.message}</p>
              </div>

              {/* Progress Bar */}
              <div className="mb-6">
                <div className="flex justify-between text-sm text-slate-400 mb-2">
                  <span>{progress.phase}</span>
                  <span>{progress.progress || 0}%</span>
                </div>
                <div className="h-3 bg-slate-700 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-emerald-500 transition-all duration-300"
                    style={{ width: `${progress.progress || 0}%` }}
                  />
                </div>
              </div>

              {/* Stats */}
              {progress.rulesChecked !== undefined && (
                <div className="grid grid-cols-2 gap-4 mb-6">
                  <div className="bg-slate-700/50 rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-blue-400">
                      {progress.rulesChecked}/{progress.totalRules}
                    </div>
                    <div className="text-sm text-slate-400">Rules Checked</div>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-red-400">{progress.findingsCount || 0}</div>
                    <div className="text-sm text-slate-400">Issues Found</div>
                  </div>
                </div>
              )}

              {/* Cancel Button */}
              <div className="text-center">
                <button
                  onClick={cancelAudit}
                  className="px-6 py-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors"
                >
                  Cancel Audit
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ═══════════════════════════════════════════════════════════════════ */}
        {/* RESULTS STEP */}
        {/* ═══════════════════════════════════════════════════════════════════ */}
        {step === 'results' && report && (
          <div className="space-y-6">
            {/* Summary Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
              {/* Score */}
              <div className="col-span-2 bg-slate-800 rounded-xl p-6 border border-slate-700">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-sm text-slate-400 mb-1">Security Score</div>
                    <div className={`text-4xl font-bold ${
                      report.score >= 80 ? 'text-green-400' :
                      report.score >= 60 ? 'text-yellow-400' :
                      report.score >= 40 ? 'text-orange-400' : 'text-red-400'
                    }`}>
                      {report.score}/100
                    </div>
                  </div>
                  <div className="relative w-20 h-20">
                    <svg className="w-full h-full -rotate-90">
                      <circle
                        cx="40"
                        cy="40"
                        r="35"
                        stroke="currentColor"
                        strokeWidth="8"
                        fill="none"
                        className="text-slate-700"
                      />
                      <circle
                        cx="40"
                        cy="40"
                        r="35"
                        stroke="currentColor"
                        strokeWidth="8"
                        fill="none"
                        strokeDasharray={`${(report.score / 100) * 220} 220`}
                        className={
                          report.score >= 80 ? 'text-green-400' :
                          report.score >= 60 ? 'text-yellow-400' :
                          report.score >= 40 ? 'text-orange-400' : 'text-red-400'
                        }
                      />
                    </svg>
                  </div>
                </div>
              </div>

              {/* Critical */}
              <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                <div className="text-sm text-slate-400 mb-1">Critical</div>
                <div className="text-3xl font-bold text-red-400">{report.summary.critical}</div>
              </div>

              {/* High */}
              <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                <div className="text-sm text-slate-400 mb-1">High</div>
                <div className="text-3xl font-bold text-orange-400">{report.summary.high}</div>
              </div>

              {/* Medium */}
              <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                <div className="text-sm text-slate-400 mb-1">Medium</div>
                <div className="text-3xl font-bold text-yellow-400">{report.summary.medium}</div>
              </div>

              {/* Passed */}
              <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                <div className="text-sm text-slate-400 mb-1">Passed</div>
                <div className="text-3xl font-bold text-green-400">{report.summary.passed}</div>
              </div>
            </div>

            {/* Audit Info */}
            <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
              <div className="flex flex-wrap items-center gap-6 text-sm text-slate-400">
                <div className="flex items-center gap-2">
                  <Clock className="w-4 h-4" />
                  <span>Duration: {(report.durationMs / 1000).toFixed(1)}s</span>
                </div>
                <div className="flex items-center gap-2">
                  <Layers className="w-4 h-4" />
                  <span>Namespaces: {report.namespaces.join(', ')}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Database className="w-4 h-4" />
                  <span>
                    {report.configSnapshot.loadBalancers} LBs, {report.configSnapshot.originPools} Pools,{' '}
                    {report.configSnapshot.wafPolicies} WAFs
                  </span>
                </div>
              </div>
            </div>

            {/* Filters */}
            <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
              <div className="flex flex-wrap items-center gap-4">
                <div className="flex items-center gap-2">
                  <Filter className="w-4 h-4 text-slate-400" />
                  <span className="text-sm text-slate-400">Filters:</span>
                </div>

                <select
                  value={filterStatus}
                  onChange={(e) => setFilterStatus(e.target.value)}
                  className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-slate-200"
                >
                  <option value="ALL">All Status</option>
                  <option value="FAIL">Failed</option>
                  <option value="WARN">Warnings</option>
                  <option value="PASS">Passed</option>
                </select>

                <select
                  value={filterSeverity}
                  onChange={(e) => setFilterSeverity(e.target.value as Severity | 'ALL')}
                  className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-slate-200"
                >
                  <option value="ALL">All Severities</option>
                  {Object.entries(SEVERITY_INFO).map(([sev, info]) => (
                    <option key={sev} value={sev}>
                      {info.label}
                    </option>
                  ))}
                </select>

                <select
                  value={filterCategory}
                  onChange={(e) => setFilterCategory(e.target.value as RuleCategory | 'ALL')}
                  className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-1.5 text-sm text-slate-200"
                >
                  <option value="ALL">All Categories</option>
                  {Object.entries(CATEGORY_INFO).map(([cat, info]) => (
                    <option key={cat} value={cat}>
                      {info.label}
                    </option>
                  ))}
                </select>

                <div className="flex-1 min-w-[200px]">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input
                      type="text"
                      placeholder="Search findings..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="w-full pl-10 pr-4 py-1.5 bg-slate-700 border border-slate-600 rounded-lg text-sm text-slate-200 placeholder-slate-400"
                    />
                  </div>
                </div>

                <div className="text-sm text-slate-400">
                  {filteredFindings.length} finding(s)
                </div>
              </div>
            </div>

            {/* Findings List */}
            <div className="space-y-3">
              {filteredFindings.map((finding, idx) => {
                const key = `${finding.ruleId}-${finding.namespace}-${finding.objectName}-${idx}`;
                const isExpanded = expandedFindings.has(key);

                return (
                  <div
                    key={key}
                    className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden"
                  >
                    {/* Finding Header */}
                    <button
                      onClick={() => toggleFinding(key)}
                      className="w-full px-4 py-3 flex items-center gap-4 hover:bg-slate-700/50 transition-colors"
                    >
                      <StatusIcon status={finding.status} />
                      <SeverityBadge severity={finding.severity} />
                      <div className="flex-1 text-left">
                        <div className="font-medium text-slate-100">
                          {finding.ruleId}: {finding.ruleName}
                        </div>
                        <div className="text-sm text-slate-400">
                          {finding.namespace} / {finding.objectName}
                        </div>
                      </div>
                      <span className="text-xs px-2 py-0.5 rounded bg-slate-700 text-slate-300">
                        {CATEGORY_INFO[finding.category]?.label || finding.category}
                      </span>
                      {isExpanded ? (
                        <ChevronDown className="w-5 h-5 text-slate-400" />
                      ) : (
                        <ChevronRight className="w-5 h-5 text-slate-400" />
                      )}
                    </button>

                    {/* Finding Details */}
                    {isExpanded && (
                      <div className="px-4 pb-4 border-t border-slate-700">
                        <div className="pt-4 space-y-4">
                          {/* Message */}
                          <div>
                            <div className="text-sm font-medium text-slate-400 mb-1">Finding</div>
                            <div className="text-slate-200">{finding.message}</div>
                          </div>

                          {/* Current vs Expected */}
                          {(finding.currentValue !== undefined || finding.expectedValue !== undefined) && (
                            <div className="grid md:grid-cols-2 gap-4">
                              {finding.currentValue !== undefined && (
                                <div>
                                  <div className="text-sm font-medium text-slate-400 mb-1">Current Value</div>
                                  <div className="bg-slate-700/50 rounded-lg p-3 text-sm text-slate-300 font-mono overflow-x-auto">
                                    {typeof finding.currentValue === 'object'
                                      ? JSON.stringify(finding.currentValue, null, 2)
                                      : String(finding.currentValue)}
                                  </div>
                                </div>
                              )}
                              {finding.expectedValue !== undefined && (
                                <div>
                                  <div className="text-sm font-medium text-slate-400 mb-1">Expected Value</div>
                                  <div className="bg-slate-700/50 rounded-lg p-3 text-sm text-slate-300 font-mono overflow-x-auto">
                                    {typeof finding.expectedValue === 'object'
                                      ? JSON.stringify(finding.expectedValue, null, 2)
                                      : String(finding.expectedValue)}
                                  </div>
                                </div>
                              )}
                            </div>
                          )}

                          {/* Remediation */}
                          <div>
                            <div className="text-sm font-medium text-slate-400 mb-1">Remediation</div>
                            <div className="bg-slate-700/50 rounded-lg p-3 text-sm text-slate-300 whitespace-pre-wrap">
                              {finding.remediation}
                            </div>
                          </div>

                          {/* Reference Link */}
                          {finding.referenceUrl && (
                            <a
                              href={finding.referenceUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-2 text-sm text-blue-400 hover:text-blue-300"
                            >
                              <ExternalLink className="w-4 h-4" />
                              View Documentation
                            </a>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}

              {filteredFindings.length === 0 && (
                <div className="bg-slate-800 rounded-xl p-8 border border-slate-700 text-center">
                  <CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-4" />
                  <div className="text-lg font-medium text-slate-200 mb-2">No findings match your filters</div>
                  <div className="text-slate-400">
                    {report.findings.length === 0
                      ? 'All security checks passed!'
                      : 'Try adjusting the filters to see more results.'}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
