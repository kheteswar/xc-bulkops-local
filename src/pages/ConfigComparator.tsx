import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowLeft, ArrowRight, ArrowRightLeft, Check, Search, Server, Shield,
  Globe, AlertTriangle, Loader2, Split, Database, LayoutList, X, Play,
  Key, Layers, Eye, EyeOff, CheckCircle, FolderOpen, Cloud,
  FileJson, Users, Activity, Code, Filter, ChevronDown, ChevronRight, Zap
} from 'lucide-react';
import { apiClient } from '../services/api';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import type { Namespace, LoadBalancer } from '../types';

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

type ScopeMode = 'namespace' | 'tenant';
type Step = 1 | 2 | 3;
type ObjectType = 'http_loadbalancer' | 'cdn_loadbalancer';

interface CompareConfig {
  mode: ScopeMode | null;
  sourceNs: string;
  destNs: string;
  destTenant?: string;
  destToken?: string;
}

interface OverviewItem {
  name: string;
  type: ObjectType;
  sourceObj?: any;
  destObj?: any;
  status: 'match' | 'diff' | 'source_only' | 'dest_only';
  domainsMatch: boolean;
}

interface DeepCompositeObject {
  [section: string]: any;
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPER: SMART FORMATTER
// ═══════════════════════════════════════════════════════════════════════════

const formatValue = (val: any): string => {
  if (val === null || val === undefined) return '';
  if (typeof val === 'boolean') return val ? 'True' : 'False';
  // F5 XC often uses empty objects as flags (e.g. "no_mtls": {})
  if (typeof val === 'object' && Object.keys(val).length === 0) return 'Enabled';
  if (typeof val === 'object') return JSON.stringify(val);
  return String(val);
};

const flattenObject = (obj: any, prefix = ''): Record<string, any> => {
  return Object.keys(obj || {}).reduce((acc: any, k) => {
    const pre = prefix.length ? prefix + '.' : '';
    const val = obj[k];
    const newKey = pre + k;

    if (Array.isArray(val)) {
      if (val.length === 0) {
        // Empty array
        acc[newKey] = '[]';
      } else if (typeof val[0] !== 'object' && val[0] !== null) {
        // Simple array of strings/numbers -> Join them
        acc[newKey] = val.join(', ');
      } else {
        // Array of objects (e.g. routes, trusted_clients) -> Recurse with index
        val.forEach((item, i) => {
          Object.assign(acc, flattenObject(item, `${newKey}[${i}]`));
        });
      }
    } else if (val !== null && typeof val === 'object') {
      // Check for empty object "flags" common in XC
      if (Object.keys(val).length === 0) {
        acc[newKey] = 'Enabled';
      } else {
        // Recurse object
        Object.assign(acc, flattenObject(val, newKey));
      }
    } else {
      // Primitive value
      acc[newKey] = val;
    }
    return acc;
  }, {});
};

// ═══════════════════════════════════════════════════════════════════════════
// COMPONENT
// ═══════════════════════════════════════════════════════════════════════════

export function ConfigComparator() {
  const { isConnected, tenant: currentTenant } = useApp();
  const toast = useToast();

  // State: Setup
  const [step, setStep] = useState<Step>(1);
  const [config, setConfig] = useState<CompareConfig>({
    mode: null,
    sourceNs: '',
    destNs: '',
    destTenant: '',
    destToken: ''
  });

  const [namespaces, setNamespaces] = useState<Namespace[]>([]);
  const [destNamespaces, setDestNamespaces] = useState<Namespace[]>([]);
  const [isLoadingNs, setIsLoadingNs] = useState(false);
  
  // Dest Tenant Validation
  const [showDestToken, setShowDestToken] = useState(false);
  const [isValidatingDest, setIsValidatingDest] = useState(false);
  const [destValidated, setDestValidated] = useState(false);

  // State: Overview
  const [overviewItems, setOverviewItems] = useState<OverviewItem[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [filterType, setFilterType] = useState<'ALL' | ObjectType>('ALL');
  const [filterStatus, setFilterStatus] = useState<'ALL' | 'MATCH' | 'DIFF' | 'ORPHAN'>('ALL');
  const [search, setSearch] = useState('');

  // State: Deep Compare
  const [selectedItem, setSelectedItem] = useState<OverviewItem | null>(null);
  const [deepSource, setDeepSource] = useState<DeepCompositeObject | null>(null);
  const [deepDest, setDeepDest] = useState<DeepCompositeObject | null>(null);
  const [isDeepLoading, setIsDeepLoading] = useState(false);
  const [showDiffOnly, setShowDiffOnly] = useState(false);
  const [jsonModal, setJsonModal] = useState<{ title: string; src: any; dest: any } | null>(null);

  useEffect(() => {
    if (isConnected) loadSourceNamespaces();
  }, [isConnected]);

  const loadSourceNamespaces = async () => {
    setIsLoadingNs(true);
    try {
      const resp = await apiClient.getNamespaces();
      setNamespaces(resp.items.sort((a, b) => a.name.localeCompare(b.name)));
    } catch { toast.error('Failed to load namespaces'); } 
    finally { setIsLoadingNs(false); }
  };

  const validateDestinationTenant = async () => {
    if (!config.destTenant?.trim() || !config.destToken?.trim()) return toast.warning('Missing destination credentials');
    setIsValidatingDest(true);
    try {
      const resp: any = await apiClient.constructor['proxyRequestStatic'](
        config.destTenant.trim(), config.destToken.trim(), '/api/web/namespaces', 'GET'
      );
      setDestNamespaces(resp.items.sort((a: any, b: any) => a.name.localeCompare(b.name)));
      setDestValidated(true);
      toast.success(`Connected to ${config.destTenant}`);
    } catch {
      toast.error('Connection failed. Check credentials.');
      setDestValidated(false);
    } finally { setIsValidatingDest(false); }
  };

  // ═════════════════════════════════════════════════════════════════════════
  // API & LOGIC
  // ═════════════════════════════════════════════════════════════════════════

  const fetchFromSource = async (path: string) => apiClient.get(path);
  const fetchFromDest = async (path: string) => {
    if (config.mode === 'namespace') return apiClient.get(path);
    if (!config.destTenant || !config.destToken) throw new Error('Missing credentials');
    return apiClient.constructor['proxyRequestStatic'](config.destTenant, config.destToken, path);
  };

  const generateOverview = async () => {
    if (!config.sourceNs || !config.destNs) return toast.error('Select namespaces');
    if (config.mode === 'tenant' && !destValidated) return toast.error('Validate destination first');

    setIsLoading(true);
    setOverviewItems([]);

    try {
      const srcHttpPath = `/api/config/namespaces/${config.sourceNs}/http_loadbalancers`;
      const srcCdnPath = `/api/config/namespaces/${config.sourceNs}/cdn_loadbalancers`;
      const destHttpPath = `/api/config/namespaces/${config.destNs}/http_loadbalancers`;
      const destCdnPath = `/api/config/namespaces/${config.destNs}/cdn_loadbalancers`;

      const [srcHttp, srcCdn, destHttp, destCdn] = await Promise.all([
        fetchFromSource(srcHttpPath).catch(() => ({ items: [] })),
        fetchFromSource(srcCdnPath).catch(() => ({ items: [] })),
        fetchFromDest(destHttpPath).catch(() => ({ items: [] })),
        fetchFromDest(destCdnPath).catch(() => ({ items: [] })),
      ]);

      const map = new Map<string, OverviewItem>();

      const processList = (items: any[], type: ObjectType, isSource: boolean) => {
        items.forEach(item => {
          const key = `${type}:${item.name}`;
          if (!map.has(key)) {
            map.set(key, {
              name: item.name,
              type,
              status: isSource ? 'source_only' : 'dest_only',
              domainsMatch: false,
              [isSource ? 'sourceObj' : 'destObj']: item
            });
          } else {
            const entry = map.get(key)!;
            entry[isSource ? 'sourceObj' : 'destObj'] = item;
            if (entry.sourceObj && entry.destObj) {
              const srcD = entry.sourceObj.spec?.domains?.sort().join(',') || '';
              const destD = entry.destObj.spec?.domains?.sort().join(',') || '';
              entry.status = 'match';
              entry.domainsMatch = srcD === destD;
            }
          }
        });
      };

      processList((srcHttp as any).items || [], 'http_loadbalancer', true);
      processList((srcCdn as any).items || [], 'cdn_loadbalancer', true);
      processList((destHttp as any).items || [], 'http_loadbalancer', false);
      processList((destCdn as any).items || [], 'cdn_loadbalancer', false);

      setOverviewItems(Array.from(map.values()).sort((a, b) => a.name.localeCompare(b.name)));
      setStep(2);
    } catch (e: any) { toast.error(e.message); } 
    finally { setIsLoading(false); }
  };

  // ─── DEEP FETCH ENGINE ───────────────────────────────────────────────
  
  const fetchDeepConfig = async (item: OverviewItem, namespace: string, fetcher: (p: string) => Promise<any>): Promise<DeepCompositeObject> => {
    const composite: DeepCompositeObject = {};
    const apiType = item.type === 'http_loadbalancer' ? 'http_loadbalancers' : 'cdn_loadbalancers';
    
    // 1. Fetch Main Object
    let mainObj;
    try {
      mainObj = await fetcher(`/api/config/namespaces/${namespace}/${apiType}/${item.name}`);
      composite['01_Main_Configuration'] = mainObj.spec;
    } catch { return { Error: 'Failed to fetch main object' }; }

    const spec = mainObj.spec;

    // Helper to safely fetch linked objects
    const safeFetch = async (ref: any, type: string, apiPath: string, keyPrefix: string) => {
      if (!ref || !ref.name) return;
      const refNs = ref.namespace || namespace;
      const key = `${keyPrefix} (${ref.name})`;
      try {
        const res = await fetcher(`/api/config/namespaces/${refNs}/${apiPath}/${ref.name}`);
        composite[key] = res.spec;
      } catch { composite[key] = { error: `Failed to fetch ${type}` }; }
    };

    // 2. Security Objects
    await safeFetch(spec.app_firewall, 'WAF', 'app_firewalls', '02_WAF_Policy');
    await safeFetch(spec.bot_defense?.policy, 'Bot Defense', 'bot_defense_policys', '03_Bot_Defense');
    await safeFetch(spec.user_identification, 'User ID', 'user_identifications', '05_User_Identification');

    // 3. Service Policies
    if (spec.active_service_policies?.policies) {
      for (const p of spec.active_service_policies.policies) {
        await safeFetch(p, 'Service Policy', 'service_policys', '04_Service_Policy');
      }
    }

    // 4. Rate Limits
    if (spec.rate_limit?.policies?.policies) {
        for (const p of spec.rate_limit.policies.policies) {
            await safeFetch(p, 'Rate Limit Policy', 'rate_limiter_policys', '08_Rate_Limit');
        }
    }

    // 5. CDN Special Rules
    if (spec.custom_cache_rule?.cdn_cache_rules) {
        for (const r of spec.custom_cache_rule.cdn_cache_rules) {
            await safeFetch(r, 'CDN Cache Rule', 'cdn_cache_rules', '09_CDN_Cache_Rule');
        }
    }

    // 6. Origin Pools (Recursive)
    const pools = [
      ...(spec.default_route_pools || []).map((p: any) => p.pool),
      ...(spec.routes || []).flatMap((r: any) => r.route_destination?.destinations?.map((d: any) => d.pool) || []),
      ...(spec.routes || []).flatMap((r: any) => r.simple_route?.origin_pools?.map((d: any) => d.pool) || []),
      spec.origin_pool // For CDN
    ].filter(Boolean);

    const uniquePools = Array.from(new Set(pools.map((p: any) => p.name))).map(name => pools.find((p: any) => p.name === name));

    for (const poolRef of uniquePools) {
      if (!poolRef) continue;
      const pNs = poolRef.namespace || namespace;
      const poolKey = `06_Origin_Pool (${poolRef.name})`;
      try {
        const poolObj = await fetcher(`/api/config/namespaces/${pNs}/origin_pools/${poolRef.name}`);
        composite[poolKey] = poolObj.spec;

        // 7. Health Checks
        if (poolObj.spec?.healthcheck) {
          for (const hc of poolObj.spec.healthcheck) {
            await safeFetch(hc, 'Health Check', 'healthchecks', `07_Health_Check`);
          }
        }
      } catch { composite[poolKey] = { error: 'Failed to fetch pool' }; }
    }

    return composite;
  };

  const startDeepCompare = async (item: OverviewItem) => {
    setSelectedItem(item);
    setIsDeepLoading(true);
    setDeepSource(null);
    setDeepDest(null);
    setStep(3);

    try {
      const [src, dest] = await Promise.all([
        item.sourceObj ? fetchDeepConfig(item, config.sourceNs, fetchFromSource) : Promise.resolve(null),
        item.destObj ? fetchDeepConfig(item, config.destNs, fetchFromDest) : Promise.resolve(null)
      ]);
      setDeepSource(src);
      setDeepDest(dest);
    } catch (e: any) {
      toast.error('Deep compare error: ' + e.message);
      setStep(2);
    } finally { setIsDeepLoading(false); }
  };

  // ═════════════════════════════════════════════════════════════════════════
  // RENDER HELPERS
  // ═════════════════════════════════════════════════════════════════════════

  const renderDiffTable = () => {
    if (!deepSource && !deepDest) return null;
    const allSections = Array.from(new Set([...Object.keys(deepSource || {}), ...Object.keys(deepDest || {})])).sort();

    return allSections.map(section => {
      const displayTitle = section.replace(/^\d+_/, '').replace(/_/g, ' ');
      const srcRaw = deepSource?.[section];
      const destRaw = deepDest?.[section];
      
      const srcFlat = srcRaw ? flattenObject(srcRaw) : {};
      const destFlat = destRaw ? flattenObject(destRaw) : {};
      const allProps = Array.from(new Set([...Object.keys(srcFlat), ...Object.keys(destFlat)])).sort();

      const hasDifferences = allProps.some(p => formatValue(srcFlat[p]) !== formatValue(destFlat[p]));
      if (showDiffOnly && !hasDifferences) return null;

      return (
        <div key={section} className="mb-6 border border-slate-700 rounded-lg overflow-hidden bg-slate-800/40">
          <div className="bg-slate-800 px-4 py-3 border-b border-slate-700 flex items-center justify-between">
            <div className="flex items-center gap-2">
              {section.includes('WAF') ? <Shield className="w-4 h-4 text-emerald-400"/> :
               section.includes('Pool') ? <Server className="w-4 h-4 text-amber-400"/> :
               section.includes('Health') ? <Activity className="w-4 h-4 text-pink-400"/> :
               section.includes('Policy') ? <FileJson className="w-4 h-4 text-blue-400"/> :
               section.includes('CDN') ? <Cloud className="w-4 h-4 text-cyan-400"/> :
               section.includes('Rate') ? <Zap className="w-4 h-4 text-yellow-400"/> :
               <Database className="w-4 h-4 text-slate-400"/>}
              <h3 className="font-bold text-slate-100 text-sm uppercase tracking-wide">{displayTitle}</h3>
              {hasDifferences && <span className="text-[10px] bg-amber-500/10 text-amber-400 px-2 py-0.5 rounded border border-amber-500/20 ml-2">Diffs Found</span>}
            </div>
            <button 
              onClick={() => setJsonModal({ title: displayTitle, src: srcRaw, dest: destRaw })}
              className="text-xs flex items-center gap-1 text-slate-400 hover:text-white bg-slate-700 hover:bg-slate-600 px-2 py-1 rounded transition-colors"
            >
              <Code className="w-3 h-3"/> View JSON
            </button>
          </div>
          
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-slate-900/50 text-slate-500 uppercase font-semibold">
                  <th className="px-4 py-2 text-left w-1/3">Setting</th>
                  <th className="px-4 py-2 text-left w-1/3 border-l border-slate-700">Source</th>
                  <th className="px-4 py-2 text-left w-1/3 border-l border-slate-700">Destination</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {allProps.map(prop => {
                  const valA = formatValue(srcFlat[prop]);
                  const valB = formatValue(destFlat[prop]);
                  const isDiff = valA !== valB;
                  const isEmptyA = srcFlat[prop] === undefined;
                  const isEmptyB = destFlat[prop] === undefined;

                  if (showDiffOnly && !isDiff) return null;

                  if (!isDiff) {
                    return (
                      <tr key={prop} className="hover:bg-slate-700/20 group">
                        <td className="px-4 py-1.5 font-mono text-slate-500 group-hover:text-slate-300 truncate" title={prop}>{prop}</td>
                        <td className="px-4 py-1.5 text-slate-400 border-l border-slate-700/50 break-all font-mono">{valA}</td>
                        <td className="px-4 py-1.5 text-slate-400 border-l border-slate-700/50 break-all font-mono">{valB}</td>
                      </tr>
                    );
                  }

                  return (
                    <tr key={prop} className="bg-amber-500/10 hover:bg-amber-500/20">
                      <td className="px-4 py-1.5 font-mono text-amber-500/90 font-medium truncate" title={prop}>{prop}</td>
                      <td className={`px-4 py-1.5 border-l border-slate-700/50 break-all font-mono ${isEmptyA ? 'text-slate-600 italic' : 'text-amber-100'}`}>
                        {isEmptyA ? 'MISSING' : valA}
                      </td>
                      <td className={`px-4 py-1.5 border-l border-slate-700/50 break-all font-mono ${isEmptyB ? 'text-slate-600 italic' : 'text-amber-100'}`}>
                        {isEmptyB ? 'MISSING' : valB}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      );
    });
  };

  // ═════════════════════════════════════════════════════════════════════════
  // RENDER UI
  // ═════════════════════════════════════════════════════════════════════════

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100">
      {/* HEADER */}
      <div className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-[95%] mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link to="/" className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg"><ArrowLeft className="w-5 h-5" /></Link>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-indigo-500/15 rounded-xl flex items-center justify-center text-indigo-400"><Split className="w-5 h-5" /></div>
              <div>
                <h1 className="text-lg font-bold">Config Comparator</h1>
                <p className="text-xs text-slate-500">Diff configs across tenants & namespaces</p>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 text-sm bg-slate-800/50 p-1 rounded-full border border-slate-700/50">
            {[1, 2, 3].map(s => (
              <button key={s} disabled={s > step} onClick={() => setStep(s as Step)} 
                className={`px-4 py-1.5 rounded-full flex items-center gap-2 transition-all ${step === s ? 'bg-indigo-600 text-white shadow' : 'text-slate-500'}`}>
                <span className="font-bold">{s}</span> {s === 1 ? 'Setup' : s === 2 ? 'Overview' : 'Diff'}
              </button>
            ))}
          </div>
        </div>
      </div>

      <main className="max-w-[95%] mx-auto px-6 py-8">
        
        {/* STEP 1: SETUP */}
        {step === 1 && (
          <div className="max-w-4xl mx-auto space-y-8">
            <div className="bg-slate-800 border border-slate-700 rounded-2xl p-8 shadow-xl">
              <h2 className="text-xl font-bold mb-6 flex items-center gap-2"><ArrowRightLeft className="w-5 h-5 text-indigo-400" /> Setup Comparison Scope</h2>
              
              {/* Mode Selection */}
              <div className="grid grid-cols-2 gap-4 mb-8">
                <button onClick={() => setConfig({...config, mode: 'namespace'})} className={`p-4 rounded-xl border flex flex-col items-center gap-2 ${config.mode === 'namespace' ? 'bg-indigo-500/20 border-indigo-500 text-indigo-300' : 'bg-slate-900 border-slate-700 text-slate-400'}`}>
                  <LayoutList className="w-6 h-6" /><span className="font-semibold">Across Namespace</span>
                </button>
                <button onClick={() => setConfig({...config, mode: 'tenant'})} className={`p-4 rounded-xl border flex flex-col items-center gap-2 ${config.mode === 'tenant' ? 'bg-indigo-500/20 border-indigo-500 text-indigo-300' : 'bg-slate-900 border-slate-700 text-slate-400'}`}>
                  <Globe className="w-6 h-6" /><span className="font-semibold">Across Tenant</span>
                </button>
              </div>

              {/* Tenant Config */}
              {config.mode === 'tenant' && (
                <div className="bg-slate-900/50 p-6 rounded-xl border border-slate-700 mb-8 animate-in fade-in slide-in-from-top-4">
                  <h3 className="text-sm font-bold text-slate-300 mb-4 flex items-center gap-2"><Key className="w-4 h-4" /> Destination Credentials</h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-xs text-slate-500 block mb-1">Tenant Name</label>
                      <input type="text" placeholder="e.g. f5-sales-public" className="w-full bg-slate-800 border-slate-600 rounded-lg px-3 py-2 text-sm" 
                        value={config.destTenant} onChange={e => setConfig({...config, destTenant: e.target.value})} />
                    </div>
                    <div>
                      <label className="text-xs text-slate-500 block mb-1">API Token</label>
                      <div className="relative">
                        <input type={showDestToken ? 'text' : 'password'} placeholder="••••••" className="w-full bg-slate-800 border-slate-600 rounded-lg px-3 py-2 text-sm" 
                          value={config.destToken} onChange={e => setConfig({...config, destToken: e.target.value})} />
                        <button onClick={() => setShowDestToken(!showDestToken)} className="absolute right-3 top-2 text-slate-500"><Eye className="w-4 h-4"/></button>
                      </div>
                    </div>
                  </div>
                  <button onClick={validateDestinationTenant} disabled={isValidatingDest} className="mt-4 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-bold flex items-center gap-2">
                    {isValidatingDest ? <Loader2 className="w-3 h-3 animate-spin" /> : <Check className="w-3 h-3" />} Validate Connection
                  </button>
                </div>
              )}

              {/* Namespace Selection */}
              <div className="grid grid-cols-[1fr_auto_1fr] gap-6 items-center">
                <div className="p-4 bg-slate-900/50 rounded-xl border border-slate-700">
                   <div className="text-xs font-bold text-blue-400 mb-2 uppercase">Source ({currentTenant})</div>
                   <select className="w-full bg-slate-800 border-slate-600 rounded-lg px-3 py-2 text-sm" value={config.sourceNs} onChange={e => setConfig({...config, sourceNs: e.target.value})}>
                     <option value="">Select Namespace</option>
                     {namespaces.map(n => <option key={n.name} value={n.name}>{n.name}</option>)}
                   </select>
                </div>
                <ArrowRight className="w-6 h-6 text-slate-600" />
                <div className="p-4 bg-slate-900/50 rounded-xl border border-slate-700">
                   <div className="text-xs font-bold text-purple-400 mb-2 uppercase">Destination ({config.mode === 'tenant' ? config.destTenant || 'Remote' : 'Local'})</div>
                   {config.mode === 'namespace' ? (
                     <select className="w-full bg-slate-800 border-slate-600 rounded-lg px-3 py-2 text-sm" value={config.destNs} onChange={e => setConfig({...config, destNs: e.target.value})}>
                       <option value="">Select Namespace</option>
                       {namespaces.map(n => <option key={n.name} value={n.name}>{n.name}</option>)}
                     </select>
                   ) : (
                     <select disabled={!destValidated} className="w-full bg-slate-800 border-slate-600 rounded-lg px-3 py-2 text-sm disabled:opacity-50" value={config.destNs} onChange={e => setConfig({...config, destNs: e.target.value})}>
                       <option value="">Select Remote Namespace</option>
                       {destNamespaces.map(n => <option key={n.name} value={n.name}>{n.name}</option>)}
                     </select>
                   )}
                </div>
              </div>

              <div className="mt-8 flex justify-center">
                <button onClick={generateOverview} disabled={isLoading} className="px-8 py-3 bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-white font-bold rounded-lg flex items-center gap-2 shadow-lg hover:scale-105 transition-all">
                  {isLoading ? <Loader2 className="w-5 h-5 animate-spin"/> : <Play className="w-5 h-5"/>} Compare Configurations
                </button>
              </div>
            </div>
          </div>
        )}

        {/* STEP 2: OVERVIEW */}
        {step === 2 && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
                <div className="text-xs font-bold text-blue-400 uppercase mb-1">Source Tenant</div>
                <div className="text-lg font-mono text-slate-300 mb-2 truncate">{currentTenant}</div>
                <div className="flex items-end gap-2">
                  <span className="text-4xl font-bold text-white">{overviewItems.filter(i => i.sourceObj).length}</span>
                  <span className="text-sm text-slate-500 mb-1">Total Objects</span>
                </div>
              </div>
              <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
                <div className="text-xs font-bold text-purple-400 uppercase mb-1">Destination Tenant</div>
                <div className="text-lg font-mono text-slate-300 mb-2 truncate">{config.mode === 'tenant' ? config.destTenant : currentTenant}</div>
                <div className="flex items-end gap-2">
                  <span className="text-4xl font-bold text-white">{overviewItems.filter(i => i.destObj).length}</span>
                  <span className="text-sm text-slate-500 mb-1">Total Objects</span>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-4 gap-4">
              {[
                { label: 'Total Items', val: overviewItems.length, f: 'ALL', color: 'text-white' },
                { label: 'Exact Match', val: overviewItems.filter(i => i.status === 'match' && i.domainsMatch).length, f: 'MATCH', color: 'text-emerald-400' },
                { label: 'Config Drift', val: overviewItems.filter(i => i.status === 'match' && !i.domainsMatch).length, f: 'DIFF', color: 'text-amber-400' },
                { label: 'Missing / Orphan', val: overviewItems.filter(i => i.status !== 'match').length, f: 'ORPHAN', color: 'text-rose-400' },
              ].map(stat => (
                <button key={stat.label} onClick={() => setFilterStatus(stat.f as any)} 
                  className={`p-4 rounded-xl border transition-all text-left ${filterStatus === stat.f ? 'bg-slate-700 border-slate-500 ring-1 ring-slate-500' : 'bg-slate-800 border-slate-700 hover:bg-slate-700/50'}`}>
                  <div className="text-xs text-slate-400 uppercase font-bold">{stat.label}</div>
                  <div className={`text-2xl font-bold ${stat.color}`}>{stat.val}</div>
                </button>
              ))}
            </div>

            <div className="flex items-center gap-4 bg-slate-800 p-2 rounded-lg border border-slate-700">
               <div className="relative flex-1">
                 <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500"/>
                 <input type="text" placeholder="Search objects..." className="w-full bg-slate-900 rounded-md py-2 pl-9 pr-4 text-sm focus:outline-none" value={search} onChange={e => setSearch(e.target.value)} />
               </div>
               <div className="flex gap-1 bg-slate-900 p-1 rounded-md">
                 {(['ALL', 'http_loadbalancer', 'cdn_loadbalancer'] as const).map(t => (
                   <button key={t} onClick={() => setFilterType(t)} className={`px-3 py-1.5 text-xs font-bold rounded ${filterType === t ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}>
                     {t === 'ALL' ? 'All Types' : t === 'http_loadbalancer' ? 'HTTP LB' : 'CDN LB'}
                   </button>
                 ))}
               </div>
            </div>

            <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
              <table className="w-full text-left text-sm">
                <thead className="bg-slate-900/50 text-slate-400 uppercase text-xs font-bold">
                  <tr>
                    <th className="px-6 py-4">Name</th>
                    <th className="px-6 py-4">Type</th>
                    <th className="px-6 py-4">Status</th>
                    <th className="px-6 py-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700">
                  {overviewItems.filter(item => {
                    if (search && !item.name.toLowerCase().includes(search.toLowerCase())) return false;
                    if (filterType !== 'ALL' && item.type !== filterType) return false;
                    if (filterStatus === 'MATCH' && !(item.status === 'match' && item.domainsMatch)) return false;
                    if (filterStatus === 'DIFF' && !(item.status === 'match' && !item.domainsMatch)) return false;
                    if (filterStatus === 'ORPHAN' && item.status === 'match') return false;
                    return true;
                  }).map(item => (
                    <tr key={`${item.type}-${item.name}`} className="hover:bg-slate-700/30 group">
                      <td className="px-6 py-4 font-medium text-slate-200">{item.name}</td>
                      <td className="px-6 py-4">
                        {item.type === 'http_loadbalancer' ? 
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 text-xs"><LayoutList className="w-3 h-3"/> HTTP</span> :
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 text-xs"><Cloud className="w-3 h-3"/> CDN</span>
                        }
                      </td>
                      <td className="px-6 py-4">
                        {item.status === 'match' ? (
                           item.domainsMatch ? <span className="text-emerald-400 text-xs font-bold px-2 py-1 rounded bg-emerald-500/10">MATCH</span> : <span className="text-amber-400 text-xs font-bold px-2 py-1 rounded bg-amber-500/10">DRIFT</span>
                        ) : (
                           item.status === 'source_only' ? <span className="text-rose-400 text-xs font-bold px-2 py-1 rounded bg-rose-500/10">MISSING IN DEST</span> : <span className="text-rose-400 text-xs font-bold px-2 py-1 rounded bg-rose-500/10">MISSING IN SOURCE</span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-right">
                        <button onClick={() => startDeepCompare(item)} className="text-indigo-400 bg-indigo-500/10 hover:bg-indigo-500/20 px-3 py-1.5 rounded text-xs font-bold opacity-0 group-hover:opacity-100 transition-opacity">Compare</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* STEP 3: DEEP DIFF */}
        {step === 3 && selectedItem && (
          <div className="space-y-6">
            <div className="flex items-center justify-between bg-slate-800 p-4 rounded-xl border border-slate-700">
               <div className="flex items-center gap-4">
                 <div>
                   <h2 className="text-xl font-bold text-white flex items-center gap-2">
                     {selectedItem.type === 'http_loadbalancer' ? <LayoutList className="w-6 h-6 text-blue-400"/> : <Cloud className="w-6 h-6 text-purple-400"/>}
                     {selectedItem.name}
                   </h2>
                   <p className="text-xs text-slate-400 mt-1">Comparing <strong>{config.sourceNs}</strong> vs <strong>{config.destNs}</strong></p>
                 </div>
                 <div className="h-8 w-px bg-slate-700 mx-2"></div>
                 <button onClick={() => setShowDiffOnly(!showDiffOnly)} className={`text-xs px-3 py-1.5 rounded-lg border font-medium transition-colors ${showDiffOnly ? 'bg-amber-500/10 border-amber-500 text-amber-400' : 'bg-slate-700 border-slate-600 text-slate-300'}`}>
                   {showDiffOnly ? 'Showing Differences Only' : 'Show All Properties'}
                 </button>
               </div>
               <button onClick={() => setStep(2)} className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm text-white">Back to List</button>
            </div>

            {isDeepLoading ? (
               <div className="py-20 text-center text-slate-400 bg-slate-800/20 rounded-xl border border-dashed border-slate-700">
                 <Loader2 className="w-10 h-10 animate-spin mx-auto mb-4 text-indigo-500"/>
                 <p>Fetching deep configuration tree...</p>
                 <div className="flex justify-center gap-4 mt-2 text-xs opacity-60">
                   <span>WAF</span><span>•</span><span>Pools</span><span>•</span><span>CDN Rules</span><span>•</span><span>Rate Limits</span>
                 </div>
               </div>
            ) : (
               <div className="space-y-4">{renderDiffTable()}</div>
            )}
          </div>
        )}

      </main>
      
      {/* JSON MODAL */}
      {jsonModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-6" onClick={() => setJsonModal(null)}>
          <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-6xl h-[80vh] flex flex-col" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-4 border-b border-slate-800">
              <h3 className="font-bold text-slate-200">Raw JSON: {jsonModal.title}</h3>
              <button onClick={() => setJsonModal(null)}><X className="w-5 h-5 text-slate-400 hover:text-white"/></button>
            </div>
            <div className="flex-1 grid grid-cols-2 divide-x divide-slate-800 overflow-hidden">
               <div className="p-4 overflow-auto bg-slate-950">
                 <div className="text-xs font-bold text-blue-400 mb-2 uppercase">Source</div>
                 <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap">{JSON.stringify(jsonModal.src || {}, null, 2)}</pre>
               </div>
               <div className="p-4 overflow-auto bg-slate-950">
                 <div className="text-xs font-bold text-purple-400 mb-2 uppercase">Destination</div>
                 <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap">{JSON.stringify(jsonModal.dest || {}, null, 2)}</pre>
               </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}