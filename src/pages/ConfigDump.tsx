import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import {
  Database, FileJson, FileText, ChevronRight, ChevronDown,
  Search, Loader2, AlertCircle, Check, FolderTree, ArrowLeft, RefreshCw,
  Package, Copy, XCircle, FileSpreadsheet, Filter, Tag, X,
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import { apiClient } from '../services/api';
import {
  OBJECT_TYPES, OBJECT_CATEGORIES,
  listObjects, fetchObjectWithChildren, buildConfigBundle, buildCSV,
  clearCache, sanitizeFilename,
  safeDownloadPDF,
} from '../services/config-dump';
import type { ObjectTypeDefinition, FetchedObject, DumpProgress } from '../services/config-dump';

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function countAllChildren(obj: FetchedObject): number {
  let count = 0;
  for (const g of obj.children) {
    count += g.objects.length;
    for (const c of g.objects) count += countAllChildren(c);
  }
  return count;
}

/** Composite key for object selection across namespaces */
function objKey(namespace: string, name: string): string {
  return `${namespace}/${name}`;
}

function parseObjKey(key: string): { namespace: string; name: string } {
  const idx = key.indexOf('/');
  return { namespace: key.slice(0, idx), name: key.slice(idx + 1) };
}

// ═══════════════════════════════════════════════════════════════════════════
// OBJECT TREE VIEWER
// ═══════════════════════════════════════════════════════════════════════════

function ObjectTreeNode({ obj, depth = 0, onNavigate }: { obj: FetchedObject; depth?: number; onNavigate?: (obj: FetchedObject) => void }) {
  const [expanded, setExpanded] = useState(depth < 2);
  const [showJson, setShowJson] = useState(false);
  const toast = useToast();
  const hasChildren = obj.children.length > 0;
  const indent = depth * 16;

  const copyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(obj.config, null, 2));
    toast.success(`Copied ${obj.name} config to clipboard`);
  };

  return (
    <div style={{ marginLeft: indent }}>
      {/* Node header */}
      <div
        className="flex items-center gap-2 py-2 px-3 hover:bg-slate-700/30 rounded-lg cursor-pointer group transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        {hasChildren ? (
          expanded ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />
        ) : (
          <div className="w-4 h-4" />
        )}
        <Package className="w-4 h-4 text-blue-400 flex-shrink-0" />
        <span className="text-sm font-medium text-slate-200">{obj.name}</span>
        <span className="text-xs text-slate-500 font-mono">{obj.type}</span>
        {obj.namespace && <span className="text-xs text-slate-600">({obj.namespace})</span>}
        <div className="ml-auto flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
          {onNavigate && (
            <button
              onClick={e => { e.stopPropagation(); onNavigate(obj); }}
              className="px-2 py-0.5 text-xs text-violet-400 hover:bg-violet-500/10 rounded transition-colors"
              title="View in graph"
            >
              Graph
            </button>
          )}
          <button
            onClick={e => { e.stopPropagation(); setShowJson(!showJson); }}
            className="px-2 py-0.5 text-xs text-blue-400 hover:bg-blue-500/10 rounded transition-colors"
          >
            {showJson ? 'Hide' : 'JSON'}
          </button>
          <button
            onClick={e => { e.stopPropagation(); copyJson(); }}
            className="p-1 text-slate-400 hover:text-slate-200 hover:bg-slate-600 rounded transition-colors"
            title="Copy JSON"
          >
            <Copy className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* JSON viewer */}
      {showJson && (
        <div className="ml-8 mb-2">
          <pre className="bg-slate-900 border border-slate-700 rounded-lg p-3 text-xs text-slate-300 font-mono overflow-x-auto max-h-96 overflow-y-auto">
            {JSON.stringify(obj.config, null, 2)}
          </pre>
        </div>
      )}

      {/* Children */}
      {expanded && obj.children.map((childGroup, gi) => (
        <div key={gi} style={{ marginLeft: indent + 8 }} className="mb-1">
          <div className="flex items-center gap-2 py-1.5 px-2">
            <FolderTree className="w-3.5 h-3.5 text-amber-400" />
            <span className="text-xs font-semibold text-amber-400 uppercase tracking-wide">
              {childGroup.label} ({childGroup.objects.length})
            </span>
          </div>
          {childGroup.objects.map((child, ci) => (
            <ObjectTreeNode key={ci} obj={child} depth={depth + 1} onNavigate={onNavigate} />
          ))}
        </div>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN COMPONENT
// ═══════════════════════════════════════════════════════════════════════════

export function ConfigDump() {
  const { isConnected } = useApp();
  const toast = useToast();

  // Step management
  const [step, setStep] = useState<'select-type' | 'select-objects' | 'results'>('select-type');

  // Type selection
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [selectedType, setSelectedType] = useState<ObjectTypeDefinition | null>(null);
  const [typeSearch, setTypeSearch] = useState('');

  // Namespace & object selection  —  MULTI-NAMESPACE
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [selectedNamespaces, setSelectedNamespaces] = useState<Set<string>>(new Set());
  const [isLoadingNs, setIsLoadingNs] = useState(false);
  const [nsSearch, setNsSearch] = useState('');
  const [showNsDropdown, setShowNsDropdown] = useState(false);
  const nsDropdownRef = useRef<HTMLDivElement>(null);

  // Object list now carries namespace per item
  const [objectList, setObjectList] = useState<{ name: string; namespace: string; labels?: Record<string, string> }[]>([]);
  const [isLoadingList, setIsLoadingList] = useState(false);
  // selectedObjects keys are "namespace/name"
  const [selectedObjects, setSelectedObjects] = useState<Set<string>>(new Set());
  const [objectSearch, setObjectSearch] = useState('');

  // Label filtering
  const [labelFilter, setLabelFilter] = useState('');
  const [showLabelFilter, setShowLabelFilter] = useState(false);

  // Child type exclusion
  const [excludedChildTypes, setExcludedChildTypes] = useState<Set<string>>(new Set());
  const [showChildFilter, setShowChildFilter] = useState(false);

  // Fetch & results
  const [isFetching, setIsFetching] = useState(false);
  const [progress, setProgress] = useState<DumpProgress | null>(null);
  const [results, setResults] = useState<FetchedObject[]>([]);
  const abortControllerRef = useRef<AbortController | null>(null);


  // ── Close namespace dropdown on outside click ───────────────────
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (nsDropdownRef.current && !nsDropdownRef.current.contains(e.target as Node)) {
        setShowNsDropdown(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  // ── Fetch namespaces ────────────────────────────────────────────
  useEffect(() => {
    if (!isConnected) return;
    setIsLoadingNs(true);
    apiClient.getNamespaces()
      .then(res => {
        const ns = (res.items || []).map((n: any) => n.name || n).sort();
        setNamespaces(ns);
        // Auto-select first namespace if none selected yet
        if (ns.length > 0 && selectedNamespaces.size === 0) {
          setSelectedNamespaces(new Set([ns[0]]));
        }
      })
      .catch(() => toast.error('Failed to load namespaces'))
      .finally(() => setIsLoadingNs(false));
  }, [isConnected]);

  // ── Fetch objects from ALL selected namespaces in parallel ──────
  useEffect(() => {
    if (!selectedType || selectedNamespaces.size === 0) return;
    setIsLoadingList(true);
    setObjectList([]);
    setSelectedObjects(new Set());

    const nsArray = Array.from(selectedNamespaces);
    Promise.all(
      nsArray.map(ns =>
        listObjects(selectedType, ns).then(items =>
          items.map(item => ({ ...item, namespace: ns }))
        )
      )
    )
      .then(results => {
        const merged = results.flat();
        // Sort by namespace then name
        merged.sort((a, b) => a.namespace.localeCompare(b.namespace) || a.name.localeCompare(b.name));
        setObjectList(merged);
      })
      .catch(() => toast.error('Failed to list objects'))
      .finally(() => setIsLoadingList(false));
  }, [selectedType, selectedNamespaces]);

  // ── Filtered namespaces for search ──────────────────────────────
  const filteredNamespaces = useMemo(() => {
    if (!nsSearch) return namespaces;
    const q = nsSearch.toLowerCase();
    return namespaces.filter(ns => ns.toLowerCase().includes(q));
  }, [namespaces, nsSearch]);

  // ── Filtered types ──────────────────────────────────────────────
  const filteredTypes = useMemo(() => {
    let types = OBJECT_TYPES;
    if (selectedCategory) types = types.filter(t => t.category === selectedCategory);
    if (typeSearch) {
      const q = typeSearch.toLowerCase();
      types = types.filter(t => t.label.toLowerCase().includes(q) || t.id.toLowerCase().includes(q));
    }
    return types;
  }, [selectedCategory, typeSearch]);

  // ── Filtered objects (search + label filter) ────────────────────
  const filteredObjects = useMemo(() => {
    let list = objectList;
    if (objectSearch) {
      const q = objectSearch.toLowerCase();
      list = list.filter(o => o.name.toLowerCase().includes(q));
    }
    if (labelFilter) {
      const lf = labelFilter.toLowerCase();
      list = list.filter(o => {
        if (!o.labels) return false;
        return Object.entries(o.labels).some(
          ([k, v]) => k.toLowerCase().includes(lf) || v.toLowerCase().includes(lf)
        );
      });
    }
    return list;
  }, [objectList, objectSearch, labelFilter]);

  // All unique labels across objects
  const allLabels = useMemo(() => {
    const labels = new Map<string, Set<string>>();
    objectList.forEach(obj => {
      if (obj.labels) {
        Object.entries(obj.labels).forEach(([k, v]) => {
          if (!labels.has(k)) labels.set(k, new Set());
          labels.get(k)!.add(v);
        });
      }
    });
    return labels;
  }, [objectList]);

  // ── Namespace toggle ────────────────────────────────────────────
  const toggleNamespace = (ns: string) => {
    setSelectedNamespaces(prev => {
      const next = new Set(prev);
      if (next.has(ns)) next.delete(ns); else next.add(ns);
      return next;
    });
  };

  const selectAllNamespaces = () => setSelectedNamespaces(new Set(filteredNamespaces));
  const clearNamespaces = () => setSelectedNamespaces(new Set());

  // ── Toggle object selection (using ns/name composite key) ───────
  const toggleObject = (namespace: string, name: string) => {
    const key = objKey(namespace, name);
    setSelectedObjects(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  };
  const selectAll = () => setSelectedObjects(new Set(filteredObjects.map(o => objKey(o.namespace, o.name))));
  const selectNone = () => setSelectedObjects(new Set());

  // ── Toggle child type exclusion ─────────────────────────────────
  const toggleChildExclusion = (typeId: string) => {
    setExcludedChildTypes(prev => {
      const next = new Set(prev);
      if (next.has(typeId)) next.delete(typeId); else next.add(typeId);
      return next;
    });
  };

  // ── Cancel fetch ────────────────────────────────────────────────
  const cancelFetch = useCallback(() => {
    abortControllerRef.current?.abort();
    setIsFetching(false);
    setProgress(prev => prev ? { ...prev, phase: 'cancelled', message: 'Cancelled by user' } : null);
    toast.warning('Fetch cancelled');
  }, [toast]);

  // ── Fetch selected objects (multi-namespace aware) ──────────────
  const fetchConfigs = useCallback(async () => {
    if (!selectedType || selectedObjects.size === 0) return;

    clearCache();

    const controller = new AbortController();
    abortControllerRef.current = controller;

    setIsFetching(true);
    setResults([]);
    setStep('results');

    const entries = Array.from(selectedObjects).map(parseObjKey);
    const fetched: FetchedObject[] = [];

    for (let i = 0; i < entries.length; i++) {
      if (controller.signal.aborted) break;

      const { namespace, name } = entries[i];
      setProgress({
        phase: 'fetching',
        message: `Fetching ${name} (${namespace}) — ${i + 1}/${entries.length}`,
        current: i,
        total: entries.length,
      });

      try {
        const obj = await fetchObjectWithChildren(
          selectedType,
          namespace,
          name,
          {
            signal: controller.signal,
            excludeChildTypes: excludedChildTypes.size > 0 ? excludedChildTypes : undefined,
          },
        );
        if (obj) fetched.push(obj);
      } catch (e: any) {
        if (e.name === 'AbortError') break;
        toast.error(`Failed to fetch ${namespace}/${name}: ${e.message}`);
      }
    }

    if (!controller.signal.aborted) {
      setResults(fetched);
      setProgress({ phase: 'done', message: 'Complete', current: entries.length, total: entries.length });
      toast.success(`Fetched ${fetched.length} object(s) with child configs`);
    }

    setIsFetching(false);
  }, [selectedType, selectedObjects, excludedChildTypes, toast]);

  // ── Namespaces summary for display ──────────────────────────────
  const namespaceSummary = useMemo(() => {
    const arr = Array.from(selectedNamespaces);
    if (arr.length === 0) return 'none';
    if (arr.length === 1) return arr[0];
    if (arr.length <= 3) return arr.join(', ');
    return `${arr.slice(0, 2).join(', ')} +${arr.length - 2} more`;
  }, [selectedNamespaces]);

  // ── Download helpers ────────────────────────────────────────────
  const downloadJson = (obj: FetchedObject) => {
    const bundle = buildConfigBundle(obj);
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${sanitizeFilename(obj.type)}_${sanitizeFilename(obj.namespace)}_${sanitizeFilename(obj.name)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`Downloaded ${obj.name}.json`);
  };

  const downloadAllJson = () => {
    const allBundles = results.map(r => buildConfigBundle(r));
    const blob = new Blob([JSON.stringify(allBundles, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `config_dump_${sanitizeFilename(selectedType?.id || 'all')}_${sanitizeFilename(namespaceSummary)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`Downloaded all ${results.length} configs`);
  };

  const downloadPdf = (obj: FetchedObject) => {
    const result = safeDownloadPDF(obj);
    if (result.success) {
      toast.success(`Downloaded ${obj.name}.pdf`);
    } else {
      toast.error(`PDF failed: ${result.error}`);
    }
  };

  const downloadAllPdf = () => {
    let success = 0;
    let failed = 0;
    for (const obj of results) {
      const result = safeDownloadPDF(obj);
      if (result.success) success++;
      else failed++;
    }
    if (failed === 0) {
      toast.success(`Downloaded ${success} PDF(s)`);
    } else {
      toast.warning(`${success} PDFs downloaded, ${failed} failed`);
    }
  };

  const downloadCsv = () => {
    const csv = buildCSV(results);
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `config_dump_${sanitizeFilename(selectedType?.id || 'all')}_${sanitizeFilename(namespaceSummary)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Downloaded CSV summary');
  };

  // ── Not connected ───────────────────────────────────────────────
  if (!isConnected) {
    return (
      <main className="max-w-7xl mx-auto px-6 py-12">
        <div className="text-center py-20">
          <Database className="w-12 h-12 text-slate-600 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-slate-300">Connect to F5 XC first</h2>
          <p className="text-slate-500 mt-2">Go to the home page and connect with your tenant credentials.</p>
        </div>
      </main>
    );
  }

  // ═══════════════════════════════════════════════════════════════
  // STEP 1: SELECT OBJECT TYPE
  // ═══════════════════════════════════════════════════════════════
  if (step === 'select-type') {
    return (
      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <div className="w-12 h-12 bg-violet-500/15 rounded-xl flex items-center justify-center text-violet-400">
            <Database className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-100">Config Dump</h1>
            <p className="text-sm text-slate-400">Export full configuration with all child objects</p>
          </div>
        </div>

        {/* Search */}
        <div className="relative mb-6">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
          <input
            type="text"
            value={typeSearch}
            onChange={e => setTypeSearch(e.target.value)}
            placeholder="Search object types..."
            className="w-full pl-10 pr-4 py-3 bg-slate-800 border border-slate-700 rounded-xl text-slate-200 text-sm focus:outline-none focus:border-blue-500 placeholder:text-slate-500"
          />
        </div>

        {/* Category filter */}
        <div className="flex flex-wrap gap-2 mb-6">
          <button
            onClick={() => setSelectedCategory(null)}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
              !selectedCategory ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700'
            }`}
          >
            All
          </button>
          {OBJECT_CATEGORIES.map(cat => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(selectedCategory === cat ? null : cat)}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                selectedCategory === cat ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        {/* Object type grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {filteredTypes.map(typeDef => (
            <button
              key={typeDef.id}
              onClick={() => { setSelectedType(typeDef); setStep('select-objects'); }}
              className="flex items-start gap-3 p-4 bg-slate-800/50 border border-slate-700 rounded-xl hover:border-blue-500/50 hover:bg-slate-800 text-left transition-all group"
            >
              <Package className="w-5 h-5 text-violet-400 mt-0.5 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-slate-200 group-hover:text-white">{typeDef.label}</p>
                <p className="text-xs text-slate-500 font-mono mt-0.5">{typeDef.apiResource}</p>
                <p className="text-xs text-slate-600 mt-1">{typeDef.category}</p>
                {typeDef.childRefs.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {typeDef.childRefs.map((cr, i) => (
                      <span key={i} className="px-1.5 py-0.5 text-[10px] bg-blue-500/10 text-blue-400 rounded">
                        {cr.label}
                      </span>
                    ))}
                  </div>
                )}
              </div>
              <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-blue-400 mt-0.5" />
            </button>
          ))}
        </div>
      </main>
    );
  }

  // ═══════════════════════════════════════════════════════════════
  // STEP 2: SELECT NAMESPACE(S) & OBJECTS
  // ═══════════════════════════════════════════════════════════════
  if (step === 'select-objects' && selectedType) {
    const childTypes = selectedType.childRefs.map(cr => ({
      id: cr.targetType,
      label: cr.label,
    }));

    return (
      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Header */}
        <div className="flex items-center gap-4 mb-6">
          <button onClick={() => { setStep('select-type'); setSelectedType(null); }} className="p-2 hover:bg-slate-700 rounded-lg transition-colors">
            <ArrowLeft className="w-5 h-5 text-slate-400" />
          </button>
          <div className="w-10 h-10 bg-violet-500/15 rounded-xl flex items-center justify-center text-violet-400">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-100">{selectedType.label}</h1>
            <p className="text-xs text-slate-500 font-mono">{selectedType.apiResource}</p>
          </div>
        </div>

        {/* ── Multi-Namespace Selector ──────────────────────────── */}
        <div className="mb-4 bg-slate-800/50 p-4 rounded-xl border border-slate-700">
          <div className="flex items-center gap-2 mb-2">
            <label className="text-sm font-medium text-slate-300 whitespace-nowrap">Namespaces:</label>
            <span className="text-xs text-slate-500">{selectedNamespaces.size} selected</span>
            <button
              onClick={() => { if (selectedType) { /* re-fetch triggered by selectedNamespaces change */ } }}
              className="ml-auto p-1.5 text-blue-400 hover:bg-blue-500/10 rounded-lg transition-colors"
              title="Refresh objects"
            >
              <RefreshCw className={`w-4 h-4 ${isLoadingList ? 'animate-spin' : ''}`} />
            </button>
          </div>

          {/* Selected namespace chips */}
          {selectedNamespaces.size > 0 && (
            <div className="flex flex-wrap gap-1.5 mb-3">
              {Array.from(selectedNamespaces).sort().map(ns => (
                <span
                  key={ns}
                  className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium bg-blue-500/15 text-blue-400 border border-blue-500/30 rounded-lg"
                >
                  {ns}
                  <button
                    onClick={() => toggleNamespace(ns)}
                    className="ml-0.5 p-0.5 hover:bg-blue-500/20 rounded transition-colors"
                  >
                    <X className="w-3 h-3" />
                  </button>
                </span>
              ))}
            </div>
          )}

          {/* Namespace dropdown */}
          <div className="relative" ref={nsDropdownRef}>
            <div className="flex items-center gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input
                  type="text"
                  value={nsSearch}
                  onChange={e => { setNsSearch(e.target.value); setShowNsDropdown(true); }}
                  onFocus={() => setShowNsDropdown(true)}
                  placeholder={isLoadingNs ? 'Loading namespaces...' : 'Search and select namespaces...'}
                  disabled={isLoadingNs}
                  className="w-full pl-9 pr-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-blue-500 placeholder:text-slate-500 disabled:opacity-50"
                />
              </div>
              <button
                onClick={selectAllNamespaces}
                className="px-2.5 py-2 text-xs font-medium text-slate-400 hover:text-white hover:bg-slate-700 rounded-lg transition-colors whitespace-nowrap"
              >
                All
              </button>
              <button
                onClick={clearNamespaces}
                className="px-2.5 py-2 text-xs font-medium text-slate-400 hover:text-white hover:bg-slate-700 rounded-lg transition-colors whitespace-nowrap"
              >
                Clear
              </button>
            </div>

            {showNsDropdown && filteredNamespaces.length > 0 && (
              <div className="absolute z-20 left-0 right-0 mt-1 max-h-56 overflow-y-auto bg-slate-800 border border-slate-700 rounded-lg shadow-xl">
                {filteredNamespaces.map(ns => {
                  const isSelected = selectedNamespaces.has(ns);
                  return (
                    <div
                      key={ns}
                      onClick={() => toggleNamespace(ns)}
                      className={`flex items-center gap-2.5 px-3 py-2 cursor-pointer transition-colors ${
                        isSelected ? 'bg-blue-500/10' : 'hover:bg-slate-700/50'
                      }`}
                    >
                      <div className={`w-4 h-4 rounded border-2 flex items-center justify-center flex-shrink-0 transition-colors ${
                        isSelected ? 'bg-blue-500 border-blue-500' : 'border-slate-600'
                      }`}>
                        {isSelected && <Check className="w-2.5 h-2.5 text-white" />}
                      </div>
                      <span className="text-sm text-slate-200">{ns}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Child type exclusion filter */}
        {childTypes.length > 0 && (
          <div className="mb-4 bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
            <button
              onClick={() => setShowChildFilter(!showChildFilter)}
              className="flex items-center gap-2 w-full px-4 py-3 text-left hover:bg-slate-700/30 transition-colors"
            >
              <Filter className="w-4 h-4 text-slate-400" />
              <span className="text-sm font-medium text-slate-300">Child Object Filters</span>
              {excludedChildTypes.size > 0 && (
                <span className="px-2 py-0.5 text-xs bg-amber-500/10 text-amber-400 rounded-full">
                  {excludedChildTypes.size} excluded
                </span>
              )}
              <ChevronDown className={`w-4 h-4 text-slate-500 ml-auto transition-transform ${showChildFilter ? 'rotate-180' : ''}`} />
            </button>
            {showChildFilter && (
              <div className="px-4 pb-3 border-t border-slate-700/50">
                <p className="text-xs text-slate-500 mt-2 mb-2">Uncheck child types to exclude from resolution:</p>
                <div className="flex flex-wrap gap-2">
                  {childTypes.map(ct => {
                    const isExcluded = excludedChildTypes.has(ct.id);
                    return (
                      <button
                        key={ct.id}
                        onClick={() => toggleChildExclusion(ct.id)}
                        className={`flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg border transition-colors ${
                          isExcluded
                            ? 'bg-slate-900 border-slate-700 text-slate-500 line-through'
                            : 'bg-blue-500/10 border-blue-500/30 text-blue-400'
                        }`}
                      >
                        <div className={`w-3.5 h-3.5 rounded border flex items-center justify-center flex-shrink-0 ${
                          isExcluded ? 'border-slate-600' : 'bg-blue-500 border-blue-500'
                        }`}>
                          {!isExcluded && <Check className="w-2.5 h-2.5 text-white" />}
                        </div>
                        {ct.label}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Object list */}
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
          {/* Search + actions */}
          <div className="p-4 border-b border-slate-700 flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="text"
                value={objectSearch}
                onChange={e => setObjectSearch(e.target.value)}
                placeholder="Search objects..."
                className="w-full pl-9 pr-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-blue-500 placeholder:text-slate-500"
              />
            </div>

            {/* Label filter toggle */}
            {allLabels.size > 0 && (
              <button
                onClick={() => setShowLabelFilter(!showLabelFilter)}
                className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-lg transition-colors ${
                  showLabelFilter || labelFilter ? 'bg-violet-500/10 text-violet-400 border border-violet-500/30' : 'text-slate-400 hover:text-white hover:bg-slate-700'
                }`}
              >
                <Tag className="w-3.5 h-3.5" />
                Labels
                {labelFilter && <span className="bg-violet-500 text-white px-1 rounded text-[10px]">1</span>}
              </button>
            )}

            <button onClick={selectAll} className="px-3 py-2 text-xs font-medium text-slate-400 hover:text-white hover:bg-slate-700 rounded-lg transition-colors">
              Select All
            </button>
            <button onClick={selectNone} className="px-3 py-2 text-xs font-medium text-slate-400 hover:text-white hover:bg-slate-700 rounded-lg transition-colors">
              Clear
            </button>
            <span className="text-xs text-slate-500">{selectedObjects.size} selected</span>
          </div>

          {/* Label filter input */}
          {showLabelFilter && (
            <div className="px-4 py-3 border-b border-slate-700/50 bg-slate-800/30">
              <div className="flex items-center gap-2">
                <Tag className="w-4 h-4 text-violet-400" />
                <input
                  type="text"
                  value={labelFilter}
                  onChange={e => setLabelFilter(e.target.value)}
                  placeholder="Filter by label key or value..."
                  className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-violet-500 placeholder:text-slate-500"
                />
                {labelFilter && (
                  <button onClick={() => setLabelFilter('')} className="p-1 text-slate-400 hover:text-white">
                    <XCircle className="w-4 h-4" />
                  </button>
                )}
              </div>
              {allLabels.size > 0 && (
                <div className="flex flex-wrap gap-1 mt-2">
                  {Array.from(allLabels.entries()).slice(0, 8).map(([key, values]) => (
                    <button
                      key={key}
                      onClick={() => setLabelFilter(key)}
                      className="px-2 py-0.5 text-[10px] bg-slate-700 text-slate-400 hover:text-white rounded transition-colors"
                    >
                      {key} ({values.size})
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Items */}
          {isLoadingList ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="w-6 h-6 animate-spin text-blue-400" />
              <span className="ml-3 text-sm text-slate-400">Loading objects from {selectedNamespaces.size} namespace{selectedNamespaces.size !== 1 ? 's' : ''}...</span>
            </div>
          ) : selectedNamespaces.size === 0 ? (
            <div className="flex flex-col items-center py-16 text-slate-500">
              <AlertCircle className="w-8 h-8 mb-2 opacity-40" />
              <p className="text-sm">Select at least one namespace above.</p>
            </div>
          ) : filteredObjects.length === 0 ? (
            <div className="flex flex-col items-center py-16 text-slate-500">
              <AlertCircle className="w-8 h-8 mb-2 opacity-40" />
              <p className="text-sm">No {selectedType.label} objects found{labelFilter ? ' matching label filter' : ' in selected namespace(s)'}.</p>
            </div>
          ) : (
            <div className="max-h-[400px] overflow-y-auto divide-y divide-slate-700/50">
              {filteredObjects.map(obj => {
                const key = objKey(obj.namespace, obj.name);
                return (
                  <div
                    key={key}
                    onClick={() => toggleObject(obj.namespace, obj.name)}
                    className={`flex items-center gap-3 px-4 py-3 cursor-pointer transition-colors ${
                      selectedObjects.has(key) ? 'bg-blue-500/10' : 'hover:bg-slate-700/20'
                    }`}
                  >
                    <div className={`w-5 h-5 rounded border-2 flex items-center justify-center flex-shrink-0 transition-colors ${
                      selectedObjects.has(key) ? 'bg-blue-500 border-blue-500' : 'border-slate-600'
                    }`}>
                      {selectedObjects.has(key) && <Check className="w-3 h-3 text-white" />}
                    </div>
                    <span className="text-sm text-slate-200 font-mono">{obj.name}</span>
                    {/* Show namespace badge when multiple namespaces are selected */}
                    {selectedNamespaces.size > 1 && (
                      <span className="px-1.5 py-0.5 text-[10px] bg-slate-700 text-blue-400 rounded font-medium">
                        {obj.namespace}
                      </span>
                    )}
                    {obj.labels && Object.keys(obj.labels).length > 0 && (
                      <div className="flex items-center gap-1 ml-auto">
                        {Object.entries(obj.labels).slice(0, 3).map(([k, v]) => (
                          <span key={k} className="px-1.5 py-0.5 text-[10px] bg-slate-700 text-slate-400 rounded" title={`${k}=${v}`}>
                            {k}={v.length > 12 ? v.slice(0, 10) + '..' : v}
                          </span>
                        ))}
                        {Object.keys(obj.labels).length > 3 && (
                          <span className="text-[10px] text-slate-500">+{Object.keys(obj.labels).length - 3}</span>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Action bar */}
        <div className="flex justify-end mt-6">
          <button
            onClick={fetchConfigs}
            disabled={selectedObjects.size === 0 || isFetching}
            className="flex items-center gap-2 px-6 py-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-colors shadow-lg shadow-blue-900/20"
          >
            {isFetching ? <Loader2 className="w-5 h-5 animate-spin" /> : <Database className="w-5 h-5" />}
            Fetch Config ({selectedObjects.size})
          </button>
        </div>
      </main>
    );
  }

  // ═══════════════════════════════════════════════════════════════
  // STEP 3: RESULTS
  // ═══════════════════════════════════════════════════════════════
  return (
    <main className="max-w-7xl mx-auto px-6 py-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-4">
          <button onClick={() => setStep('select-objects')} className="p-2 hover:bg-slate-700 rounded-lg transition-colors">
            <ArrowLeft className="w-5 h-5 text-slate-400" />
          </button>
          <div>
            <h1 className="text-xl font-bold text-slate-100">
              {selectedType?.label} — {results.length} Object{results.length !== 1 ? 's' : ''}
            </h1>
            <p className="text-xs text-slate-500">
              {selectedNamespaces.size === 1
                ? `Namespace: ${Array.from(selectedNamespaces)[0]}`
                : `${selectedNamespaces.size} namespaces: ${namespaceSummary}`
              }
            </p>
          </div>
        </div>

        {!isFetching && results.length > 0 && (
          <div className="flex items-center gap-2">
            <button onClick={downloadAllJson} className="flex items-center gap-2 px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm transition-colors" title="Download All JSON">
              <FileJson className="w-4 h-4" /> JSON
            </button>
            <button onClick={downloadAllPdf} className="flex items-center gap-2 px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm transition-colors" title="Download All PDF">
              <FileText className="w-4 h-4" /> PDF
            </button>
            <button onClick={downloadCsv} className="flex items-center gap-2 px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm transition-colors" title="Download CSV Summary">
              <FileSpreadsheet className="w-4 h-4" /> CSV
            </button>
          </div>
        )}
      </div>

      {/* Progress */}
      {isFetching && progress && (
        <div className="mb-6 bg-slate-800/50 border border-slate-700 rounded-xl p-6">
          <div className="flex items-center gap-3 mb-3">
            <Loader2 className="w-5 h-5 animate-spin text-blue-400" />
            <span className="text-sm text-slate-300 flex-1">{progress.message}</span>
            <button
              onClick={cancelFetch}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-400 hover:bg-red-500/10 border border-red-500/30 rounded-lg transition-colors"
            >
              <XCircle className="w-3.5 h-3.5" /> Cancel
            </button>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div
              className="bg-blue-500 h-2 rounded-full transition-all"
              style={{ width: `${progress.total > 0 ? (progress.current / progress.total) * 100 : 0}%` }}
            />
          </div>
          <p className="text-xs text-slate-500 mt-2">{progress.current} / {progress.total}</p>
        </div>
      )}

      {/* Tree View */}
      {results.length > 0 && (
        <div className="space-y-4">
          {results.map((obj, idx) => {
            const childCount = countAllChildren(obj);
            return (
              <div key={idx} className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
                {/* Object header */}
                <div className="flex items-center justify-between p-4 border-b border-slate-700/50">
                  <div className="flex items-center gap-3">
                    <Package className="w-5 h-5 text-violet-400" />
                    <div>
                      <span className="text-sm font-semibold text-slate-200">{obj.name}</span>
                      <span className="text-xs text-slate-500 ml-2">{obj.namespace}</span>
                    </div>
                    {childCount > 0 && (
                      <span className="px-2 py-0.5 text-xs bg-blue-500/10 text-blue-400 rounded-full">
                        +{childCount} child object{childCount !== 1 ? 's' : ''}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => downloadJson(obj)}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-emerald-400 hover:bg-emerald-500/10 border border-emerald-500/30 rounded-lg transition-colors"
                    >
                      <FileJson className="w-3.5 h-3.5" /> JSON
                    </button>
                    <button
                      onClick={() => downloadPdf(obj)}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-amber-400 hover:bg-amber-500/10 border border-amber-500/30 rounded-lg transition-colors"
                    >
                      <FileText className="w-3.5 h-3.5" /> PDF
                    </button>
                  </div>
                </div>

                {/* Object tree */}
                <div className="p-3">
                  <ObjectTreeNode obj={obj} />
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Empty state after fetch */}
      {!isFetching && results.length === 0 && progress?.phase === 'done' && (
        <div className="text-center py-16">
          <AlertCircle className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <p className="text-sm text-slate-400">No configs could be fetched. Check permissions and try again.</p>
        </div>
      )}

      {/* Cancelled state */}
      {!isFetching && progress?.phase === 'cancelled' && (
        <div className="text-center py-16">
          <XCircle className="w-10 h-10 text-amber-500/50 mx-auto mb-3" />
          <p className="text-sm text-slate-400">Fetch was cancelled. {results.length} object(s) were fetched before cancellation.</p>
        </div>
      )}
    </main>
  );
}
