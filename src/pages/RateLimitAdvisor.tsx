import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Gauge, Play, ChevronDown, ChevronRight, Users, Shield, AlertTriangle,
  Activity, BarChart3, Settings, Copy, Check, Download,
  ArrowRight, TrendingUp, EyeOff, Lock, Bot, UserX, UserCheck,
  FileJson, SlidersHorizontal, Target, Layers, HelpCircle
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RTooltip,
  ResponsiveContainer
} from 'recharts';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import { apiClient } from '../services/api';
import type { LoadBalancer, Namespace } from '../types';
import {
  collectAccessLogs, collectSecurityEvents,
  classifyResponse, getResponseCategory,
  buildUserReputationMap, getReputationFromBotClass,
  analyzeTraffic, buildAllPreGrouped, buildUserMetadata, buildUserProfiles, buildTimeSeries, buildHeatmap, extractUserId,
  analyzeBursts,
  peakBufferRecommendation, p99BurstRecommendation, simulateImpact,
  analyzePaths,
  generateConfig, formatConfigJSON,
} from '../services/rate-limit-advisor';
import type {
  CollectionProgress, AnalysisResults, ClassifiedLogEntry, SecurityEventEntry,
  TimeGranularity, TrafficSegment, ImpactSimulation, AlgorithmResult,
  UserProfile, RateStats, PathAnalysis, UserMetadata, PreGroupedCache
} from '../services/rate-limit-advisor';

// ═══════════════════════════════════════════════════════════════════
// SEARCHABLE SELECT
// ═══════════════════════════════════════════════════════════════════

function SearchableSelect({
  value,
  onChange,
  options,
  placeholder,
  disabled,
}: {
  value: string;
  onChange: (val: string) => void;
  options: { value: string; label: string }[];
  placeholder: string;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = search
    ? options.filter(o => o.label.toLowerCase().includes(search.toLowerCase()))
    : options;

  const selectedLabel = options.find(o => o.value === value)?.label || '';

  // Close on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
        setSearch('');
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const handleSelect = (val: string) => {
    onChange(val);
    setOpen(false);
    setSearch('');
  };

  return (
    <div ref={containerRef} className="relative">
      <input
        ref={inputRef}
        type="text"
        value={open ? search : selectedLabel}
        placeholder={placeholder}
        disabled={disabled}
        className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
        onFocus={() => { setOpen(true); setSearch(''); }}
        onChange={e => setSearch(e.target.value)}
        onKeyDown={e => {
          if (e.key === 'Escape') { setOpen(false); setSearch(''); inputRef.current?.blur(); }
          if (e.key === 'Enter' && filtered.length === 1) { handleSelect(filtered[0].value); inputRef.current?.blur(); }
        }}
      />
      <ChevronDown className={`absolute right-2 top-2.5 w-4 h-4 text-slate-400 pointer-events-none transition-transform ${open ? 'rotate-180' : ''}`} />
      {open && filtered.length > 0 && (
        <div className="absolute z-50 w-full mt-1 bg-slate-800 border border-slate-600 rounded-lg shadow-xl max-h-60 overflow-y-auto">
          {filtered.map(o => (
            <button
              key={o.value}
              onClick={() => handleSelect(o.value)}
              className={`w-full text-left px-3 py-2 text-sm hover:bg-slate-700 transition-colors ${
                o.value === value ? 'text-blue-400 bg-slate-700/50' : 'text-slate-200'
              }`}
            >
              {o.label}
            </button>
          ))}
        </div>
      )}
      {open && filtered.length === 0 && search && (
        <div className="absolute z-50 w-full mt-1 bg-slate-800 border border-slate-600 rounded-lg shadow-xl px-3 py-2 text-sm text-slate-500">
          No matches
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// MAIN COMPONENT
// ═══════════════════════════════════════════════════════════════════

export function RateLimitAdvisor() {
  const { isConnected } = useApp();
  const navigate = useNavigate();
  const toast = useToast();

  // Config state
  const [namespaces, setNamespaces] = useState<Namespace[]>([]);
  const [selectedNamespace, setSelectedNamespace] = useState('');
  const [loadBalancers, setLoadBalancers] = useState<LoadBalancer[]>([]);
  const [selectedLB, setSelectedLB] = useState('');
  const [hoursBack, setHoursBack] = useState(168);

  // Collection state
  const [isCollecting, setIsCollecting] = useState(false);
  const [progress, setProgress] = useState<CollectionProgress>({
    phase: 'idle', message: '', progress: 0, accessLogsCount: 0,
    securityEventsCount: 0, scrollPage: 0,
  });

  // Analysis results
  const [results, setResults] = useState<AnalysisResults | null>(null);

  // Interactive controls
  const [selectedGranularity, setSelectedGranularity] = useState<TimeGranularity>('minute');
  const [selectedSegment, setSelectedSegment] = useState<TrafficSegment>('clean_only');
  const [sliderValue, setSliderValue] = useState<number>(0);
  const [burstMultiplier, setBurstMultiplier] = useState<number>(2);
  const [impactResult, setImpactResult] = useState<ImpactSimulation | null>(null);

  // Algorithm tuning
  const [bufferPercent, setBufferPercent] = useState(0.5);
  const [p99BurstMargin, setP99BurstMargin] = useState(1.1);

  // UI state
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    collection: true, users: false, traffic: false, distribution: true, config: false, paths: false,
  });
  const [copiedField, setCopiedField] = useState('');
  const [showUserDetail, setShowUserDetail] = useState<string | null>(null);
  const [showBurstExplainer, setShowBurstExplainer] = useState(false);

  // Pre-computed compact data — no full log arrays in memory
  const preGroupedCacheRef = useRef<PreGroupedCache | null>(null);
  const userMetaRef = useRef<Map<string, UserMetadata>>(new Map());

  // Chart refs for PDF capture
  const timeSeriesChartRef = useRef<HTMLDivElement>(null);
  const heatmapChartRef = useRef<HTMLDivElement>(null);
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);

  useEffect(() => {
    if (!isConnected) navigate('/');
  }, [isConnected, navigate]);

  // Load namespaces
  useEffect(() => {
    if (isConnected) {
      apiClient.getNamespaces().then(res => {
        const sorted = (res.items || []).sort((a, b) =>
          (a.name || '').localeCompare(b.name || '')
        );
        setNamespaces(sorted);
      }).catch(() => toast.error('Failed to load namespaces'));
    }
  }, [isConnected]);

  // Load LBs when namespace changes
  useEffect(() => {
    if (selectedNamespace) {
      setSelectedLB('');
      setResults(null);
      apiClient.getLoadBalancers(selectedNamespace).then(res => {
        setLoadBalancers(res.items || []);
      }).catch(() => toast.error('Failed to load load balancers'));
    }
  }, [selectedNamespace]);

  const toggleSection = (key: string) => {
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const copyToClipboard = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedField(label);
    setTimeout(() => setCopiedField(''), 2000);
  };

  // ───── PDF DOWNLOAD ─────

  const handleDownloadPdf = async () => {
    if (!results) return;
    setIsGeneratingPdf(true);
    try {
      const [{ default: html2canvas }, { generatePdfReport }] = await Promise.all([
        import('html2canvas'),
        import('../services/rate-limit-advisor/pdf-report-generator'),
      ]);

      let timeSeriesImage: string | undefined;
      let heatmapImage: string | undefined;

      if (timeSeriesChartRef.current) {
        const canvas = await html2canvas(timeSeriesChartRef.current, { backgroundColor: '#0f172a', scale: 2 });
        timeSeriesImage = canvas.toDataURL('image/png');
      }
      if (heatmapChartRef.current) {
        const canvas = await html2canvas(heatmapChartRef.current, { backgroundColor: '#0f172a', scale: 2 });
        heatmapImage = canvas.toDataURL('image/png');
      }

      const unit = selectedGranularity.toUpperCase() as 'SECOND' | 'MINUTE' | 'HOUR';
      const config = generateConfig(results.lbName, results.namespace, sliderValue, unit, burstMultiplier, [], results);

      // Build JSON configs for each algorithm
      const algorithmConfigs = results.algorithms.map(algo => {
        const algoUnit = algo.granularity.toUpperCase() as 'SECOND' | 'MINUTE' | 'HOUR';
        return {
          label: algo.label,
          config: generateConfig(results.lbName, results.namespace, algo.rateLimit, algoUnit, algo.burstMultiplier, [], results),
          rateLimit: algo.rateLimit,
          burstMultiplier: algo.burstMultiplier,
          granularity: algo.granularity,
        };
      });

      await generatePdfReport({
        results,
        config,
        algorithmConfigs,
        sliderValue,
        burstMultiplier,
        selectedGranularity,
        selectedSegment,
        impactResult,
        chartImages: { timeSeries: timeSeriesImage, heatmap: heatmapImage },
      });

      toast.success('PDF report downloaded');
    } catch (err) {
      console.error('PDF generation failed:', err);
      toast.error('Failed to generate PDF report');
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  // ───── ANALYSIS PIPELINE ─────

  const runAnalysis = async () => {
    if (!selectedNamespace || !selectedLB) {
      toast.error('Select a namespace and load balancer');
      return;
    }

    setIsCollecting(true);
    setResults(null);
    setImpactResult(null);

    const endTime = new Date().toISOString();
    const startTime = new Date(Date.now() - hoursBack * 60 * 60 * 1000).toISOString();

    try {
      // Phase 1: Collect access logs
      const accessLogs = await collectAccessLogs(
        selectedNamespace, selectedLB, startTime, endTime, setProgress
      );

      if (accessLogs.length === 0) {
        toast.error('No access logs found for this LB in the selected period');
        setIsCollecting(false);
        setProgress(p => ({ ...p, phase: 'idle', message: '' }));
        return;
      }

      // Phase 2: Collect security events (filtered by vh_name server-side)
      // Gracefully continue with empty array if security events API is rate-limited
      let securityEvents: SecurityEventEntry[] = [];
      try {
        securityEvents = await collectSecurityEvents(
          selectedNamespace, selectedLB, startTime, endTime, setProgress, accessLogs.length
        );
      } catch (secErr) {
        const secMsg = secErr instanceof Error ? secErr.message : String(secErr);
        console.warn(`[RateLimitAdvisor] Security events fetch failed: ${secMsg}`);
        toast.warning(`Security events skipped (rate limited) — analysis continues with access logs only`);
        setProgress(p => ({
          ...p, phase: 'fetching_security',
          message: `Security events skipped (rate limited) — continuing...`,
          progress: 68, securityEventsCount: 0,
        }));
      }

      // ── STEP 1: Join security events to access logs via req_id ──
      // Access logs = master dataset (1 entry per request).
      // Security events = small subset (only requests that triggered a security rule).
      // We join on req_id to create enriched master logs with the SAME count as access logs.
      setProgress({
        phase: 'classifying', message: 'Joining security events to access logs via req_id...',
        progress: 70, accessLogsCount: accessLogs.length,
        securityEventsCount: securityEvents.length, scrollPage: 0,
      });

      // Build req_id → security event lookup (one event per request)
      const secEventByReqId = new Map<string, typeof securityEvents[0]>();
      for (const ev of securityEvents) {
        if (ev.req_id) secEventByReqId.set(ev.req_id, ev);
      }

      // Build user-level reputation from security events (aggregate view)
      const reputationMap = buildUserReputationMap(securityEvents);

      const matchedCount = { matched: 0, unmatched: 0 };

      // ── STEP 2: Create enriched master logs (same count as access logs) ──
      const classified: ClassifiedLogEntry[] = accessLogs.map(log => {
        const responseOrigin = classifyResponse(log);
        const userId = extractUserId(log as unknown as Record<string, unknown>);

        // Join: look up matching security event by req_id
        const secEvent = log.req_id ? secEventByReqId.get(log.req_id) : undefined;
        if (secEvent) matchedCount.matched++;
        else matchedCount.unmatched++;

        // User reputation: from security event join, then user-level aggregation, then bot_class
        let userReputation: 'clean' | 'benign_bot' | 'flagged' | 'malicious' = 'clean';

        if (secEvent) {
          // This specific request has a security event — derive reputation from it
          if (secEvent.action === 'block') {
            userReputation = 'malicious';
          } else if (secEvent['bot_info.classification'] === 'malicious') {
            userReputation = 'malicious';
          } else if (secEvent['bot_info.classification'] === 'benign') {
            userReputation = 'benign_bot';
          } else {
            userReputation = 'flagged';
          }
        } else {
          // No security event for this request — check user-level reputation
          const userRep = reputationMap.get(userId);
          if (userRep) {
            userReputation = userRep.reputation;
          } else if (log.bot_class) {
            const botRep = getReputationFromBotClass(log.bot_class);
            if (botRep) userReputation = botRep;
          }
        }

        return {
          ...log,
          responseOrigin,
          userReputation,
          estimatedWeight: log.sample_rate ? 1 / log.sample_rate : 1,
          // Security event enrichment
          hasSecurityEvent: !!secEvent,
          secEventType: secEvent?.sec_event_type,
          secEventName: secEvent?.sec_event_name,
          secAction: secEvent?.action,
          secBotClassification: secEvent?.['bot_info.classification'] as string | undefined,
          secBotName: secEvent?.['bot_info.name'] as string | undefined,
          secViolationRating: secEvent?.violation_rating,
          secWafMode: secEvent?.waf_mode,
        };
      });

      console.log(`[RateLimitAdvisor] Enrichment: ${accessLogs.length} access logs, ${securityEvents.length} security events, ${matchedCount.matched} joined via req_id, ${matchedCount.unmatched} access logs without security events`);

      // ═══════════════════════════════════════════════════════════════
      // DIAGNOSTIC BLOCK — detailed field inspection for troubleshooting
      // ═══════════════════════════════════════════════════════════════
      if (classified.length > 0) {
        const s = classified[0] as unknown as Record<string, unknown>;

        // 1. Dump ALL top-level keys and their types/values
        console.group('[DIAG] First classified entry — full field dump');
        const fieldSummary: Record<string, { type: string; value: string }> = {};
        for (const [k, v] of Object.entries(s)) {
          const type = v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v;
          const val = type === 'object' || type === 'array'
            ? JSON.stringify(v).slice(0, 200)
            : String(v).slice(0, 200);
          fieldSummary[k] = { type, value: val };
        }
        console.table(fieldSummary);
        console.log('[DIAG] Total fields:', Object.keys(s).length);
        console.log('[DIAG] All keys:', Object.keys(s).sort().join(', '));
        console.groupEnd();

        // 2. Response code fields specifically
        console.group('[DIAG] Response code fields');
        const codeFields = ['rsp_code', 'rsp_code_class', 'rsp_code_details', 'response_code', 'status_code', 'status', 'http_status_code', 'code'];
        for (const f of codeFields) {
          const v = s[f];
          console.log(`  ${f}: value=${JSON.stringify(v)}, type=${typeof v}, parseInt=${typeof v === 'string' || typeof v === 'number' ? parseInt(String(v), 10) : 'N/A'}`);
        }
        console.groupEnd();

        // 3. Timestamp fields
        console.group('[DIAG] Timestamp fields');
        const tsFields = ['@timestamp', 'time', 'timestamp', 'date', 'event_time', '_wrapper_time'];
        for (const f of tsFields) {
          const v = s[f];
          if (v !== undefined) console.log(`  ${f}: value=${JSON.stringify(v)}, type=${typeof v}`);
        }
        console.groupEnd();

        // 4. User identification fields
        console.group('[DIAG] User identification fields');
        const userFields = ['user', 'src_ip', 'user_identifier', 'client_id', 'source_ip', 'client_ip'];
        for (const f of userFields) {
          const v = s[f];
          if (v !== undefined) console.log(`  ${f}: value=${JSON.stringify(v)}, type=${typeof v}`);
        }
        console.groupEnd();

        // 5. Scan for any field containing a value that looks like an HTTP status code
        console.group('[DIAG] Brute-force scan for HTTP-status-like values');
        for (const [k, v] of Object.entries(s)) {
          if (v === null || v === undefined) continue;
          const str = String(v);
          const num = parseInt(str, 10);
          if (isFinite(num) && num >= 100 && num < 600) {
            console.log(`  FOUND: ${k} = ${JSON.stringify(v)} (parsed as ${num})`);
          }
          if (typeof v === 'string' && /^[1-5]xx/i.test(v)) {
            console.log(`  FOUND CLASS: ${k} = ${JSON.stringify(v)}`);
          }
        }
        console.groupEnd();

        // 6. Check for nested objects that might contain rsp_code
        console.group('[DIAG] Nested objects check');
        for (const [k, v] of Object.entries(s)) {
          if (v && typeof v === 'object' && !Array.isArray(v)) {
            const inner = v as Record<string, unknown>;
            const innerKeys = Object.keys(inner);
            console.log(`  ${k}: ${innerKeys.length} keys — ${innerKeys.slice(0, 15).join(', ')}${innerKeys.length > 15 ? '...' : ''}`);
            if (inner['rsp_code'] !== undefined) {
              console.log(`    *** FOUND rsp_code inside '${k}': ${JSON.stringify(inner['rsp_code'])}`);
            }
          }
        }
        console.groupEnd();

        // 7. Print first 3 entries as raw JSON (truncated)
        console.group('[DIAG] First 3 raw classified entries');
        for (let i = 0; i < Math.min(3, classified.length); i++) {
          console.log(`  Entry ${i}:`, JSON.stringify(classified[i]).slice(0, 2000));
        }
        console.groupEnd();
      }

      // Build compact data structures and free raw log arrays
      const userMeta = buildUserMetadata(classified);
      userMetaRef.current = userMeta;

      const allPreGrouped = buildAllPreGrouped(classified);
      preGroupedCacheRef.current = allPreGrouped;

      // Phase 5: Statistical analysis
      setProgress({
        phase: 'analyzing', message: 'Running statistical analysis...',
        progress: 80, accessLogsCount: accessLogs.length,
        securityEventsCount: securityEvents.length, scrollPage: 0,
      });

      // Response breakdown
      const responseBreakdown = {
        origin2xx: 0, origin3xx: 0, origin4xx: 0, origin5xx: 0,
        f5Blocked: 0, f5BlockedReasons: {} as Record<string, number>,
        originOther: 0,
      };
      for (const log of classified) {
        const cat = getResponseCategory(log, log.responseOrigin);
        if (cat === 'origin_2xx') responseBreakdown.origin2xx++;
        else if (cat === 'origin_3xx') responseBreakdown.origin3xx++;
        else if (cat === 'origin_4xx') responseBreakdown.origin4xx++;
        else if (cat === 'origin_5xx') responseBreakdown.origin5xx++;
        else if (cat === 'f5_blocked') {
          responseBreakdown.f5Blocked++;
          const reason = log.rsp_code_details || 'unknown';
          responseBreakdown.f5BlockedReasons[reason] = (responseBreakdown.f5BlockedReasons[reason] || 0) + 1;
        } else {
          responseBreakdown.originOther++;
        }
      }

      // Diagnostic: response breakdown analysis
      console.group('[DIAG] Response Classification Results');
      console.log('Breakdown:', responseBreakdown);
      const total = classified.length;
      const otherPct = total > 0 ? Math.round((responseBreakdown.originOther / total) * 100) : 0;
      console.log(`Summary: 2xx=${responseBreakdown.origin2xx} 3xx=${responseBreakdown.origin3xx} 4xx=${responseBreakdown.origin4xx} 5xx=${responseBreakdown.origin5xx} other=${responseBreakdown.originOther} blocked=${responseBreakdown.f5Blocked}`);
      if (otherPct > 50) {
        console.warn(`[DIAG] WARNING: ${otherPct}% of entries classified as "Other" — likely field parsing issue`);
        // Sample 5 entries from different positions for comparison
        const sampleIndices = [0, Math.floor(total / 4), Math.floor(total / 2), Math.floor(total * 3 / 4), total - 1];
        for (const idx of sampleIndices) {
          if (idx >= 0 && idx < classified.length) {
            const entry = classified[idx] as unknown as Record<string, unknown>;
            console.log(`  Entry[${idx}] rsp_code=${JSON.stringify(entry['rsp_code'])} rsp_code_class=${JSON.stringify(entry['rsp_code_class'])} rsp_code_details=${JSON.stringify(entry['rsp_code_details'])} responseOrigin=${JSON.stringify(entry['responseOrigin'])}`);
          }
        }
      }
      console.groupEnd();

      // User profiles
      const users = buildUserProfiles(classified, reputationMap);
      const userReputationSummary = {
        clean: users.filter(u => u.reputation === 'clean').length,
        benignBot: users.filter(u => u.reputation === 'benign_bot').length,
        flagged: users.filter(u => u.reputation === 'flagged').length,
        malicious: users.filter(u => u.reputation === 'malicious').length,
      };

      // Rate analysis per segment — ALL calculations use access logs only.
      // Security events only contributed user reputation labels (enrichment).
      // The segment filter lets the operator choose which users to include:
      //   clean_only: origin responses from users with no security flags
      //   all_legitimate: origin responses excluding malicious users
      //   total: all access logs (including F5-blocked requests)
      const segments: TrafficSegment[] = ['clean_only', 'all_legitimate', 'total'];
      const rateAnalysis = {} as AnalysisResults['rateAnalysis'];
      for (const seg of segments) {
        const segLogs = seg === 'clean_only'
          ? classified.filter(l => l.responseOrigin === 'origin' && l.userReputation === 'clean')
          : seg === 'all_legitimate'
            ? classified.filter(l => l.responseOrigin === 'origin' && ['clean', 'benign_bot', 'flagged'].includes(l.userReputation))
            : classified;
        const segUsers = new Set(segLogs.map(l => l.user || l.src_ip));

        rateAnalysis[seg] = {
          second: analyzeTraffic(classified, seg, 'second'),
          minute: analyzeTraffic(classified, seg, 'minute'),
          hour: analyzeTraffic(classified, seg, 'hour'),
          userCount: segUsers.size,
          requestCount: segLogs.length,
        };
      }

      // Burst analysis (based on clean P95 minute rate)
      const cleanMinuteP95 = rateAnalysis.clean_only.minute.p95;
      const burstResult = analyzeBursts(classified, cleanMinuteP95, 'minute');

      // Path analysis
      const paths = analyzePaths(classified);

      // Time series + heatmap
      const timeSeries = buildTimeSeries(classified, 'clean_only');
      const heatmap = buildHeatmap(classified, 'clean_only');

      // Current LB config
      let currentConfig: AnalysisResults['currentConfig'] = {
        hasRateLimit: false, trustedClients: [], existingPolicies: [],
      };
      try {
        const lb = await apiClient.getLoadBalancer(selectedNamespace, selectedLB);
        const spec = lb.spec || {};
        const rl = spec.rate_limit;
        // policies can be ObjectRef[] or { policies: ObjectRef[] } depending on API response
        const policiesArr = Array.isArray(rl?.policies)
          ? rl.policies
          : ((rl?.policies as unknown as { policies?: Array<{ name?: string }> })?.policies || []);
        currentConfig = {
          hasRateLimit: !!(rl?.rate_limiter?.total_number),
          currentLimit: rl?.rate_limiter?.total_number,
          currentUnit: rl?.rate_limiter?.unit,
          currentBurstMultiplier: rl?.rate_limiter?.burst_multiplier,
          userIdPolicyName: spec.user_identification?.name,
          trustedClients: ((spec as unknown as { trusted_clients?: Array<{ metadata?: { name?: string } }> }).trusted_clients || [])
            .map((tc) => tc.metadata?.name || 'unnamed'),
          existingPolicies: policiesArr.map((p: { name?: string }) => p.name || ''),
        };
      } catch {
        // Continue without current config
      }

      // Algorithms
      const cleanMinuteStats = rateAnalysis.clean_only.minute;
      const p99BurstRec = p99BurstRecommendation(cleanMinuteStats, 'minute', p99BurstMargin);
      const algorithms: AlgorithmResult[] = [
        p99BurstRec,
        peakBufferRecommendation(cleanMinuteStats, 'minute', bufferPercent),
      ];

      // Sampling rate
      const avgSampleRate = accessLogs.length > 0
        ? accessLogs.reduce((sum, l) => sum + (l.sample_rate || 1), 0) / accessLogs.length
        : 1;
      const estimatedActualRequests = classified.reduce((sum, l) => sum + l.estimatedWeight, 0);

      const analysisResults: AnalysisResults = {
        lbName: selectedLB,
        namespace: selectedNamespace,
        analysisStart: startTime,
        analysisEnd: endTime,
        generatedAt: new Date().toISOString(),
        totalAccessLogs: accessLogs.length,
        totalSecurityEvents: securityEvents.length,
        avgSampleRate: Math.round(avgSampleRate * 1000) / 1000,
        estimatedActualRequests: Math.round(estimatedActualRequests),
        responseBreakdown,
        users,
        userReputationSummary,
        currentConfig,
        rateAnalysis,
        burstEvents: burstResult.events,
        recommendedBurstMultiplier: burstResult.recommendedMultiplier,
        burstRatioP90: burstResult.ratioP90,
        paths,
        algorithms,
        timeSeries,
        heatmap,
      };

      setResults(analysisResults);

      // Set initial slider to P99-Burst recommendation (default algorithm)
      setSliderValue(p99BurstRec.rateLimit);
      setBurstMultiplier(p99BurstRec.burstMultiplier);

      // Initial simulation using P99-Burst values
      {
        const grouped = allPreGrouped.clean_only.minute;
        const sim = simulateImpact(grouped, userMeta, p99BurstRec.rateLimit, 'minute', p99BurstRec.burstMultiplier);
        setImpactResult(sim);
      }

      setProgress({
        phase: 'complete', message: 'Analysis complete!',
        progress: 100, accessLogsCount: accessLogs.length,
        securityEventsCount: securityEvents.length, scrollPage: 0,
      });

      setExpandedSections({ collection: true, users: true, traffic: true, distribution: true, config: true });
      toast.success(`Analysis complete: ${accessLogs.length} logs, ${users.length} users`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Analysis failed';
      toast.error(msg);
      setProgress({
        phase: 'error', message: msg, progress: 0,
        accessLogsCount: 0, securityEventsCount: 0, scrollPage: 0, error: msg,
      });
    } finally {
      setIsCollecting(false);
    }
  };

  // ───── IMPACT SIMULATION (on slider change) ─────

  const getActivePreGrouped = useCallback((): Map<string, Map<string, number>> => {
    return preGroupedCacheRef.current?.[selectedSegment]?.[selectedGranularity] || new Map();
  }, [selectedSegment, selectedGranularity]);

  const recalculateImpact = useCallback((limit: number, burst: number) => {
    const grouped = getActivePreGrouped();
    if (grouped.size === 0 || userMetaRef.current.size === 0) return;
    const sim = simulateImpact(grouped, userMetaRef.current, limit, selectedGranularity, burst);
    setImpactResult(sim);
  }, [selectedGranularity, getActivePreGrouped]);

  const handleSliderChange = (value: number) => {
    setSliderValue(value);
    recalculateImpact(value, burstMultiplier);
  };

  const handleBurstChange = (value: number) => {
    setBurstMultiplier(value);
    recalculateImpact(sliderValue, value);
  };

  // Re-simulate when segment or granularity changes (no re-grouping needed — all 9 combos pre-computed)
  useEffect(() => {
    if (preGroupedCacheRef.current && results && sliderValue > 0) {
      recalculateImpact(sliderValue, burstMultiplier);
    }
  }, [selectedSegment, selectedGranularity]);

  // Current stats for the selected segment + granularity
  const currentStats: RateStats | null = useMemo(() => {
    if (!results) return null;
    return results.rateAnalysis[selectedSegment]?.[selectedGranularity] || null;
  }, [results, selectedSegment, selectedGranularity]);

  const sliderMax = useMemo(() => {
    if (!currentStats) return 100;
    return Math.max(Math.ceil(currentStats.max * 2), 50);
  }, [currentStats]);

  // ═══════════════════════════════════════════════════════════════════
  // RENDER
  // ═══════════════════════════════════════════════════════════════════

  return (
    <main className="max-w-7xl mx-auto px-6 py-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <div className="w-10 h-10 bg-amber-500/15 rounded-xl flex items-center justify-center text-amber-400">
            <Gauge className="w-5 h-5" />
          </div>
          <h1 className="text-2xl font-bold text-slate-100">Rate Limit Advisor</h1>
          <span className="px-2 py-0.5 text-xs font-medium bg-blue-500/20 text-blue-400 rounded-full">Analysis Tool</span>
        </div>
        <p className="text-slate-400 ml-13">
          Analyze traffic patterns to find safe, data-driven rate limits. Every number traces back to real data.
        </p>
      </div>

      {/* Section 1: Configuration + Data Collection */}
      <Section title="Configuration & Data Collection" icon={Settings} defaultOpen>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Namespace</label>
            <SearchableSelect
              value={selectedNamespace}
              onChange={setSelectedNamespace}
              options={namespaces.map(ns => ({ value: ns.name, label: ns.name }))}
              placeholder="Type or select namespace..."
              disabled={isCollecting}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Load Balancer</label>
            <SearchableSelect
              value={selectedLB}
              onChange={setSelectedLB}
              options={loadBalancers.map(lb => {
                const lbName = lb.metadata?.name || lb.name;
                return { value: lbName, label: lbName };
              })}
              placeholder="Type or select load balancer..."
              disabled={isCollecting || !selectedNamespace}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Analysis Period</label>
            <select
              value={hoursBack}
              onChange={e => setHoursBack(Number(e.target.value))}
              className="w-full bg-slate-800 border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200"
              disabled={isCollecting}
            >
              <option value={0.0833}>Last 5 minutes</option>
              <option value={1}>Last 1 hour</option>
              <option value={6}>Last 6 hours</option>
              <option value={24}>Last 24 hours</option>
              <option value={72}>Last 3 days</option>
              <option value={168}>Last 7 days</option>
            </select>
          </div>
          <div className="flex items-end">
            <button
              onClick={runAnalysis}
              disabled={isCollecting || !selectedLB}
              className="w-full flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-lg px-4 py-2 font-medium transition-colors"
            >
              {isCollecting ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  Analyze Traffic
                </>
              )}
            </button>
          </div>
        </div>

        {/* Progress Bar */}
        {progress.phase !== 'idle' && (
          <div className="mt-4">
            <div className="flex items-center justify-between text-sm mb-2">
              <span className="text-slate-300">{progress.message}</span>
              <span className={`font-semibold ${
                progress.phase === 'error' ? 'text-red-400' :
                progress.phase === 'complete' ? 'text-emerald-400' : 'text-blue-400'
              }`}>{progress.progress}%</span>
            </div>
            <div className="w-full bg-slate-700 rounded-full h-2.5">
              <div
                className={`h-2.5 rounded-full transition-all duration-300 ${
                  progress.phase === 'error' ? 'bg-red-500' :
                  progress.phase === 'complete' ? 'bg-emerald-500' : 'bg-blue-500'
                }`}
                style={{ width: `${progress.progress}%` }}
              />
            </div>
            <div className="flex gap-6 mt-2 text-xs text-slate-400">
              {/* Access Logs — fetched count + estimated total */}
              <span>
                Access Logs: <span className="text-slate-200 font-medium">{progress.accessLogsCount.toLocaleString()}</span>
                {progress.phase === 'fetching_logs' && progress.estimatedTotal && progress.estimatedTotal > 0 ? (
                  <span className="text-slate-500"> / ~{progress.estimatedTotal.toLocaleString()}</span>
                ) : null}
                {progress.phase !== 'fetching_logs' && progress.accessLogsCount > 0 ? (
                  <span className="text-emerald-400 ml-1">&#10003;</span>
                ) : null}
              </span>
              {/* Security Events — only show once relevant */}
              {(progress.phase === 'fetching_security' || progress.securityEventsCount > 0 || !['fetching_logs'].includes(progress.phase)) && (
                <span>
                  Security Events: <span className="text-slate-200 font-medium">{progress.securityEventsCount.toLocaleString()}</span>
                  {progress.phase === 'fetching_security' && progress.estimatedTotal && progress.estimatedTotal > 0 ? (
                    <span className="text-slate-500"> / ~{progress.estimatedTotal.toLocaleString()}</span>
                  ) : null}
                  {!['fetching_security', 'fetching_logs'].includes(progress.phase) && progress.securityEventsCount > 0 ? (
                    <span className="text-emerald-400 ml-1">&#10003;</span>
                  ) : null}
                </span>
              )}
              {/* Phase indicator */}
              {progress.phase === 'fetching_logs' && (
                <span className="text-blue-400">Phase 1/4: Collecting access logs</span>
              )}
              {progress.phase === 'fetching_security' && (
                <span className="text-blue-400">Phase 2/4: Collecting security events</span>
              )}
              {progress.phase === 'classifying' && (
                <span className="text-blue-400">Phase 3/4: Classifying &amp; enriching</span>
              )}
              {progress.phase === 'analyzing' && (
                <span className="text-blue-400">Phase 4/4: Statistical analysis</span>
              )}
            </div>
          </div>
        )}
      </Section>

      {/* Results sections - only show after analysis */}
      {results && (
        <>
          {/* Section 2: Data Collection Report */}
          <Section
            title="Data Collection Report"
            icon={BarChart3}
            collapsible
            expanded={expandedSections.collection}
            onToggle={() => toggleSection('collection')}
            badge={`${results.totalAccessLogs.toLocaleString()} logs`}
          >
            <DataCollectionReport results={results} />
          </Section>

          {/* Section 3: User Landscape */}
          <Section
            title="User Landscape"
            icon={Users}
            collapsible
            expanded={expandedSections.users}
            onToggle={() => toggleSection('users')}
            badge={`${results.users.length} users`}
          >
            <UserLandscape
              results={results}
              showDetail={showUserDetail}
              onShowDetail={setShowUserDetail}
            />
          </Section>

          {/* Section 4: Traffic Patterns */}
          <Section
            title="Traffic Patterns"
            icon={Activity}
            collapsible
            expanded={expandedSections.traffic}
            onToggle={() => toggleSection('traffic')}
          >
            <TrafficPatterns results={results} timeSeriesRef={timeSeriesChartRef} heatmapRef={heatmapChartRef} />
          </Section>

          {/* Section 5: Distribution Analysis + Impact Simulator */}
          <Section
            title="Distribution Analysis & Impact Simulator"
            icon={Target}
            collapsible
            expanded={expandedSections.distribution}
            onToggle={() => toggleSection('distribution')}
          >
            {/* Segment + Granularity controls */}
            <div className="flex flex-wrap gap-4 mb-6">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Traffic Segment</label>
                <div className="flex gap-1">
                  {(['clean_only', 'all_legitimate', 'total'] as TrafficSegment[]).map(seg => (
                    <button
                      key={seg}
                      onClick={() => setSelectedSegment(seg)}
                      className={`px-3 py-1.5 text-xs rounded-lg font-medium transition-colors ${
                        selectedSegment === seg
                          ? 'bg-blue-600 text-white'
                          : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                      }`}
                    >
                      {seg === 'clean_only' ? 'Clean Only' : seg === 'all_legitimate' ? 'All Legit' : 'Total'}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Time Granularity</label>
                <div className="flex gap-1">
                  {(['second', 'minute', 'hour'] as TimeGranularity[]).map(g => (
                    <button
                      key={g}
                      onClick={() => setSelectedGranularity(g)}
                      className={`px-3 py-1.5 text-xs rounded-lg font-medium transition-colors ${
                        selectedGranularity === g
                          ? 'bg-blue-600 text-white'
                          : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                      }`}
                    >
                      Per {g.charAt(0).toUpperCase() + g.slice(1)}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Percentile Table */}
            {currentStats && (
              <PercentileTable stats={currentStats} granularity={selectedGranularity} />
            )}

            {/* Algorithm Recommendations */}
            <div className="mt-6 mb-6">
              <h4 className="text-sm font-semibold text-slate-200 mb-3">Algorithm Starting Points</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {currentStats && (
                  <>
                    <AlgorithmCard
                      result={p99BurstRecommendation(currentStats, selectedGranularity, p99BurstMargin)}
                      isSelected={false}
                      recommended
                      onSelect={(val) => {
                        const rec = p99BurstRecommendation(currentStats, selectedGranularity, p99BurstMargin);
                        setSliderValue(val);
                        setBurstMultiplier(rec.burstMultiplier);
                        recalculateImpact(val, rec.burstMultiplier);
                      }}
                      paramLabel="Safety Margin"
                      paramValue={p99BurstMargin}
                      paramMin={1}
                      paramMax={1.5}
                      paramStep={0.05}
                      onParamChange={(v) => setP99BurstMargin(v)}
                    />
                    <AlgorithmCard
                      result={peakBufferRecommendation(currentStats, selectedGranularity, bufferPercent)}
                      isSelected={false}
                      onSelect={(val) => { setSliderValue(val); setBurstMultiplier(1); recalculateImpact(val, 1); }}
                      paramLabel="Buffer %"
                      paramValue={bufferPercent * 100}
                      paramMin={10}
                      paramMax={100}
                      paramStep={5}
                      onParamChange={(v) => setBufferPercent(v / 100)}
                    />
                  </>
                )}
              </div>
            </div>

            {/* Interactive Slider */}
            <div className="bg-slate-800/80 border border-blue-500/30 rounded-xl p-6 mb-6">
              <h4 className="text-sm font-semibold text-blue-400 mb-4 flex items-center gap-2">
                <SlidersHorizontal className="w-4 h-4" />
                Interactive Impact Simulator
              </h4>

              <div className="mb-4">
                <div className="flex items-center justify-between mb-2">
                  <label className="text-sm text-slate-300">
                    Rate Limit: <span className="text-white font-bold text-lg">{sliderValue}</span>
                    <span className="text-slate-400"> req/{selectedGranularity}</span>
                  </label>
                  <input
                    type="number"
                    value={sliderValue}
                    onChange={e => handleSliderChange(Math.max(0, Math.min(8192, Number(e.target.value))))}
                    className="w-24 bg-slate-700 border border-slate-600 rounded px-2 py-1 text-sm text-slate-100 text-right"
                    min={0}
                    max={8192}
                  />
                </div>
                <input
                  type="range"
                  value={sliderValue}
                  onChange={e => handleSliderChange(Number(e.target.value))}
                  min={0}
                  max={sliderMax}
                  step={1}
                  className="w-full h-2 bg-slate-700 rounded-full appearance-none cursor-pointer accent-blue-500"
                />
                <div className="flex justify-between text-xs text-slate-500 mt-1">
                  <span>0</span>
                  <span>{sliderMax}</span>
                </div>
              </div>

              <div className="mb-4">
                <div className="flex items-center justify-between mb-2">
                  <label className="text-sm text-slate-300 flex items-center gap-1.5">
                    Burst Multiplier: <span className="text-white font-bold">{burstMultiplier}x</span>
                    <span className="text-slate-400 text-xs ml-1">(effective limit: {sliderValue * burstMultiplier})</span>
                    <button
                      onClick={() => setShowBurstExplainer(!showBurstExplainer)}
                      className="ml-1 text-blue-400 hover:text-blue-300 transition-colors"
                      title="Learn how burst multiplier works"
                    >
                      <HelpCircle className="w-3.5 h-3.5" />
                    </button>
                  </label>
                </div>
                <input
                  type="range"
                  value={burstMultiplier}
                  onChange={e => handleBurstChange(Number(e.target.value))}
                  min={1}
                  max={10}
                  step={1}
                  className="w-full h-2 bg-slate-700 rounded-full appearance-none cursor-pointer accent-amber-500"
                />
                <div className="flex justify-between text-xs text-slate-500 mt-1">
                  <span>1x</span>
                  <span>10x</span>
                </div>

                {showBurstExplainer && (
                  <div className="mt-3 bg-slate-900/80 border border-slate-700 rounded-lg p-4 text-xs space-y-3">
                    <div className="flex items-start gap-2">
                      <HelpCircle className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
                      <div>
                        <h5 className="text-sm font-semibold text-slate-100 mb-2">Why use Burst Multiplier instead of doubling the Rate Limit?</h5>
                        <p className="text-slate-400 leading-relaxed">
                          F5 XC uses a <span className="text-slate-200 font-medium">token bucket</span> internally. The rate limit (<code className="text-blue-300 bg-slate-800 px-1 rounded">total_number</code>) controls the <span className="text-slate-200">refill rate</span> (tokens added per period), while <code className="text-blue-300 bg-slate-800 px-1 rounded">total_number x burst_multiplier</code> controls the <span className="text-slate-200">bucket capacity</span> (max tokens).
                        </p>
                      </div>
                    </div>

                    <div className="border-t border-slate-700 pt-3">
                      <p className="text-slate-300 font-medium mb-2">These two configs have the same burst capacity but very different security:</p>
                      <div className="grid grid-cols-2 gap-3">
                        <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-3">
                          <div className="text-emerald-400 font-semibold mb-1">40/min x 2 burst</div>
                          <div className="text-slate-400">Bucket: 80 tokens, refills at 40/min</div>
                          <div className="text-slate-400 mt-1">Attacker at 60/min drains 20 tokens/min.</div>
                          <div className="text-emerald-300 font-medium mt-1">Blocked after ~4 min.</div>
                        </div>
                        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3">
                          <div className="text-red-400 font-semibold mb-1">80/min x 1 burst</div>
                          <div className="text-slate-400">Bucket: 80 tokens, refills at 80/min</div>
                          <div className="text-slate-400 mt-1">Attacker at 60/min uses 60, gets 80 back.</div>
                          <div className="text-red-300 font-medium mt-1">Never blocked.</div>
                        </div>
                      </div>
                    </div>

                    <div className="border-t border-slate-700 pt-3">
                      <p className="text-slate-300 font-medium mb-1.5">How it works:</p>
                      <ul className="space-y-1 text-slate-400">
                        <li className="flex items-start gap-1.5">
                          <span className="text-blue-400 mt-px">-</span>
                          <span><span className="text-slate-200">Rate limit</span> = the sustained ceiling an attacker gets throttled down to</span>
                        </li>
                        <li className="flex items-start gap-1.5">
                          <span className="text-blue-400 mt-px">-</span>
                          <span><span className="text-slate-200">Burst multiplier</span> = temporary headroom for legitimate users to spike without being blocked</span>
                        </li>
                        <li className="flex items-start gap-1.5">
                          <span className="text-blue-400 mt-px">-</span>
                          <span>Set the base rate to your P99 traffic + margin. Use burst 2-3x to absorb natural peaks.</span>
                        </li>
                      </ul>
                    </div>

                    <div className="border-t border-slate-700 pt-3 bg-amber-500/5 -mx-4 -mb-4 px-4 pb-3 rounded-b-lg">
                      <p className="text-amber-300 font-medium text-[11px]">
                        Recommendation: Always use burst {'>'}1. A burst multiplier of 2-3x protects legitimate users during traffic spikes while keeping the sustained rate low enough to catch attackers.
                      </p>
                    </div>
                  </div>
                )}
              </div>

              {/* Impact Results */}
              {impactResult && <ImpactDisplay impact={impactResult} hoursBack={hoursBack} />}
            </div>

            {/* Current vs Recommended */}
            {results.currentConfig.hasRateLimit && (
              <CurrentVsRecommended current={results.currentConfig} proposed={sliderValue} granularity={selectedGranularity} burstMultiplier={burstMultiplier} />
            )}
          </Section>

          {/* Section 6: Decision + Config */}
          <Section
            title="Decision & Configuration"
            icon={FileJson}
            collapsible
            expanded={expandedSections.config}
            onToggle={() => toggleSection('config')}
          >
            <ConfigOutput
              results={results}
              rateLimit={sliderValue}
              granularity={selectedGranularity}
              burstMultiplier={burstMultiplier}
              onCopy={copyToClipboard}
              copiedField={copiedField}
              onDownloadPdf={handleDownloadPdf}
              isGeneratingPdf={isGeneratingPdf}
            />
          </Section>

          {/* Section 7: Path Analysis */}
          {results.paths.length > 0 && (
            <Section
              title="Path Analysis"
              icon={Layers}
              collapsible
              expanded={expandedSections.paths}
              onToggle={() => setExpandedSections(s => ({ ...s, paths: !s.paths }))}
              badge={`${results.paths.length} paths`}
            >
              <PathAnalysisSection paths={results.paths} />
            </Section>
          )}
        </>
      )}
    </main>
  );
}

// ═══════════════════════════════════════════════════════════════════
// SUB-COMPONENTS
// ═══════════════════════════════════════════════════════════════════

function Section({ title, icon: Icon, children, collapsible, expanded, onToggle, badge, defaultOpen }: {
  title: string;
  icon: React.ElementType;
  children: React.ReactNode;
  collapsible?: boolean;
  expanded?: boolean;
  onToggle?: () => void;
  badge?: string;
  defaultOpen?: boolean;
}) {
  const [localOpen, setLocalOpen] = useState(defaultOpen ?? true);
  const isOpen = collapsible ? expanded : localOpen;
  const toggle = collapsible ? onToggle : () => setLocalOpen(!localOpen);

  return (
    <div className="mb-6">
      <button
        onClick={toggle}
        className="w-full flex items-center justify-between p-4 bg-slate-800/50 border border-slate-700 rounded-t-xl hover:border-slate-600 transition-colors"
      >
        <div className="flex items-center gap-3">
          <Icon className="w-5 h-5 text-blue-400" />
          <h3 className="text-lg font-semibold text-slate-100">{title}</h3>
          {badge && <span className="px-2 py-0.5 text-xs font-medium bg-slate-700 text-slate-300 rounded-full">{badge}</span>}
        </div>
        {collapsible && (isOpen ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />)}
      </button>
      {isOpen && (
        <div className="p-6 bg-slate-800/30 border border-t-0 border-slate-700 rounded-b-xl">
          {children}
        </div>
      )}
    </div>
  );
}

// ───── DATA COLLECTION REPORT ─────

function DataCollectionReport({ results }: { results: AnalysisResults }) {
  const rb = results.responseBreakdown;
  const totalOrigin = rb.origin2xx + rb.origin3xx + rb.origin4xx + rb.origin5xx + (rb.originOther || 0);
  const total = totalOrigin + rb.f5Blocked;

  const rows = [
    { label: '2xx (Success)', count: rb.origin2xx, color: 'text-emerald-400', included: true },
    { label: '3xx (Redirects)', count: rb.origin3xx, color: 'text-blue-400', included: true },
    { label: '4xx (Origin errors)', count: rb.origin4xx, color: 'text-amber-400', included: true },
    { label: '5xx (Server errors)', count: rb.origin5xx, color: 'text-red-400', included: true },
    ...((rb.originOther || 0) > 0 ? [{ label: 'Other (code unknown)', count: rb.originOther || 0, color: 'text-slate-400', included: true }] : []),
    { label: 'F5 XC Blocked', count: rb.f5Blocked, color: 'text-slate-500', included: false },
  ];

  return (
    <div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatCard label="Total Access Logs" value={results.totalAccessLogs.toLocaleString()} icon={BarChart3} />
        <StatCard label="Security Events" value={results.totalSecurityEvents.toLocaleString()} icon={Shield} />
        <StatCard label="Avg Sample Rate" value={results.avgSampleRate.toFixed(3)} icon={Activity} />
        <StatCard label="Est. Actual Requests" value={results.estimatedActualRequests.toLocaleString()} icon={TrendingUp} />
      </div>

      <h4 className="text-sm font-semibold text-slate-200 mb-3">Response Classification</h4>
      <div className="bg-slate-800/50 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-700">
              <th className="text-left px-4 py-2 text-slate-400 font-medium">Category</th>
              <th className="text-right px-4 py-2 text-slate-400 font-medium">Count</th>
              <th className="text-right px-4 py-2 text-slate-400 font-medium">%</th>
              <th className="text-center px-4 py-2 text-slate-400 font-medium">In Baseline?</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(row => (
              <tr key={row.label} className="border-b border-slate-700/50">
                <td className={`px-4 py-2 ${row.color}`}>{row.label}</td>
                <td className="text-right px-4 py-2 text-slate-100">{row.count.toLocaleString()}</td>
                <td className="text-right px-4 py-2 text-slate-400">{total > 0 ? ((row.count / total) * 100).toFixed(1) : 0}%</td>
                <td className="text-center px-4 py-2">
                  {row.included
                    ? <Check className="w-4 h-4 text-emerald-400 inline" />
                    : <EyeOff className="w-4 h-4 text-slate-500 inline" />
                  }
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {Object.keys(rb.f5BlockedReasons).length > 0 && (
        <div className="mt-4">
          <h5 className="text-xs font-medium text-slate-400 mb-2">F5 Block Reasons</h5>
          <div className="flex flex-wrap gap-2">
            {Object.entries(rb.f5BlockedReasons).sort((a, b) => b[1] - a[1]).map(([reason, count]) => (
              <span key={reason} className="px-2 py-1 text-xs bg-slate-700/50 text-slate-300 rounded">
                {reason}: {count}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, icon: Icon }: { label: string; value: string; icon: React.ElementType }) {
  return (
    <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
      <div className="flex items-center gap-2 mb-1">
        <Icon className="w-4 h-4 text-slate-400" />
        <span className="text-xs text-slate-400">{label}</span>
      </div>
      <span className="text-xl font-bold text-slate-100">{value}</span>
    </div>
  );
}

// ───── USER LANDSCAPE ─────

function UserLandscape({ results, showDetail, onShowDetail }: {
  results: AnalysisResults;
  showDetail: string | null;
  onShowDetail: (id: string | null) => void;
}) {
  const summary = results.userReputationSummary;
  const categories = [
    { label: 'Clean', count: summary.clean, color: 'bg-emerald-500', textColor: 'text-emerald-400', icon: UserCheck },
    { label: 'Benign Bot', count: summary.benignBot, color: 'bg-blue-500', textColor: 'text-blue-400', icon: Bot },
    { label: 'Flagged', count: summary.flagged, color: 'bg-amber-500', textColor: 'text-amber-400', icon: AlertTriangle },
    { label: 'Malicious', count: summary.malicious, color: 'bg-red-500', textColor: 'text-red-400', icon: UserX },
  ];
  const totalUsers = summary.clean + summary.benignBot + summary.flagged + summary.malicious;

  return (
    <div>
      {/* Reputation Breakdown */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        {categories.map(cat => (
          <div key={cat.label} className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <cat.icon className={`w-4 h-4 ${cat.textColor}`} />
              <span className={`text-sm font-medium ${cat.textColor}`}>{cat.label}</span>
            </div>
            <div className="text-2xl font-bold text-slate-100">{cat.count}</div>
            <div className="text-xs text-slate-400">{totalUsers > 0 ? ((cat.count / totalUsers) * 100).toFixed(1) : 0}%</div>
            {/* Mini bar */}
            <div className="w-full bg-slate-700 rounded-full h-1 mt-2">
              <div className={`h-1 rounded-full ${cat.color}`} style={{ width: `${totalUsers > 0 ? (cat.count / totalUsers) * 100 : 0}%` }} />
            </div>
          </div>
        ))}
      </div>

      {/* Top 20 Users Table */}
      <h4 className="text-sm font-semibold text-slate-200 mb-3">Top Users by Request Volume</h4>
      <div className="bg-slate-800/50 rounded-lg overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-700">
              <th className="text-left px-3 py-2 text-slate-400 font-medium">#</th>
              <th className="text-left px-3 py-2 text-slate-400 font-medium">User</th>
              <th className="text-left px-3 py-2 text-slate-400 font-medium">Reputation</th>
              <th className="text-right px-3 py-2 text-slate-400 font-medium">Requests</th>
              <th className="text-right px-3 py-2 text-slate-400 font-medium">Peak/min</th>
              <th className="text-right px-3 py-2 text-slate-400 font-medium">Avg/min</th>
              <th className="text-left px-3 py-2 text-slate-400 font-medium">Top Path</th>
            </tr>
          </thead>
          <tbody>
            {results.users.slice(0, 20).map((user, idx) => (
              <tr
                key={user.identifier}
                className="border-b border-slate-700/50 hover:bg-slate-700/30 cursor-pointer"
                onClick={() => onShowDetail(showDetail === user.identifier ? null : user.identifier)}
              >
                <td className="px-3 py-2 text-slate-500">{idx + 1}</td>
                <td className="px-3 py-2 text-slate-100 font-mono text-xs max-w-[200px] truncate">{user.srcIp || user.identifier.slice(0, 30)}</td>
                <td className="px-3 py-2">
                  <ReputationBadge reputation={user.reputation} />
                </td>
                <td className="text-right px-3 py-2 text-slate-100">{user.totalRequests.toLocaleString()}</td>
                <td className="text-right px-3 py-2 text-amber-400 font-medium">{user.rateStats.minute.max}</td>
                <td className="text-right px-3 py-2 text-slate-300">{user.rateStats.minute.mean.toFixed(1)}</td>
                <td className="px-3 py-2 text-slate-400 text-xs max-w-[150px] truncate">{user.topPaths[0]?.path || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* User Detail Expandable */}
      {showDetail && (
        <UserDetailPanel user={results.users.find(u => u.identifier === showDetail)} />
      )}
    </div>
  );
}

function ReputationBadge({ reputation }: { reputation: string }) {
  const styles: Record<string, string> = {
    clean: 'bg-emerald-500/20 text-emerald-400',
    benign_bot: 'bg-blue-500/20 text-blue-400',
    flagged: 'bg-amber-500/20 text-amber-400',
    malicious: 'bg-red-500/20 text-red-400',
  };
  return (
    <span className={`px-2 py-0.5 text-xs rounded-full font-medium ${styles[reputation] || styles.clean}`}>
      {reputation.replace('_', ' ')}
    </span>
  );
}

function UserDetailPanel({ user }: { user?: UserProfile }) {
  if (!user) return null;
  return (
    <div className="mt-4 p-4 bg-slate-800/80 border border-slate-600 rounded-lg">
      <h5 className="text-sm font-semibold text-slate-200 mb-3">User Detail: {user.srcIp || user.identifier.slice(0, 40)}</h5>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
        <div><span className="text-slate-400">Country:</span> <span className="text-slate-100 ml-1">{user.country || 'N/A'}</span></div>
        <div><span className="text-slate-400">User Agent:</span> <span className="text-slate-100 ml-1 text-xs">{user.userAgent?.slice(0, 40) || 'N/A'}</span></div>
        <div><span className="text-slate-400">Peak Hour:</span> <span className="text-slate-100 ml-1">{user.peakHour || 'N/A'}</span></div>
        <div><span className="text-slate-400">Bot:</span> <span className="text-slate-100 ml-1">{user.botClassification || 'None'} {user.botName ? `(${user.botName})` : ''}</span></div>
        <div><span className="text-slate-400">WAF Blocks:</span> <span className="text-red-400 ml-1">{user.wafBlockCount}</span></div>
        <div><span className="text-slate-400">WAF Reports:</span> <span className="text-amber-400 ml-1">{user.wafReportCount}</span></div>
        <div><span className="text-slate-400">Peak/sec:</span> <span className="text-slate-100 ml-1">{user.rateStats.second.max}</span></div>
        <div><span className="text-slate-400">Peak/hour:</span> <span className="text-slate-100 ml-1">{user.rateStats.hour.max}</span></div>
      </div>
      {user.attackTypes.length > 0 && (
        <div className="mt-2">
          <span className="text-slate-400 text-sm">Attack Types: </span>
          {user.attackTypes.map(at => (
            <span key={at} className="px-2 py-0.5 text-xs bg-red-500/20 text-red-400 rounded mr-1">{at}</span>
          ))}
        </div>
      )}
    </div>
  );
}

// ───── TRAFFIC PATTERNS ─────

function TrafficPatterns({ results, timeSeriesRef, heatmapRef }: {
  results: AnalysisResults;
  timeSeriesRef?: React.Ref<HTMLDivElement>;
  heatmapRef?: React.Ref<HTMLDivElement>;
}) {
  const ts = results.timeSeries;

  return (
    <div>
      {/* Time Series Chart */}
      {ts.length > 0 && (
        <div ref={timeSeriesRef} className="mb-6">
          <h4 className="text-sm font-semibold text-slate-200 mb-3">Requests Over Time (per minute avg)</h4>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={ts}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis
                dataKey="timestamp"
                stroke="#94a3b8"
                tick={{ fontSize: 10 }}
                tickFormatter={(val) => {
                  const d = new Date(val);
                  return `${(d.getUTCMonth()+1)}/${d.getUTCDate()} ${d.getUTCHours()}:${String(d.getUTCMinutes()).padStart(2,'0')}`;
                }}
                interval="preserveStartEnd"
              />
              <YAxis stroke="#94a3b8" tick={{ fontSize: 11 }} />
              <RTooltip
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #475569', borderRadius: '8px' }}
                labelStyle={{ color: '#94a3b8' }}
                labelFormatter={(val) => new Date(val).toLocaleString()}
              />
              <Area type="monotone" dataKey="requestsPerMinute" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.1} name="Req/min" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Heatmap */}
      {results.heatmap.length > 0 && (
        <div ref={heatmapRef}>
          <h4 className="text-sm font-semibold text-slate-200 mb-3">Day x Hour Heatmap (avg req/min)</h4>
          <HeatmapGrid data={results.heatmap} />
        </div>
      )}
    </div>
  );
}

function HeatmapGrid({ data }: { data: AnalysisResults['heatmap'] }) {
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const maxVal = Math.max(...data.map(d => d.avgRequestsPerMinute), 1);

  return (
    <div className="overflow-x-auto">
      <div className="inline-block">
        <div className="flex gap-0.5">
          <div className="w-10" /> {/* spacer */}
          {Array.from({ length: 24 }, (_, i) => (
            <div key={i} className="w-7 text-center text-[10px] text-slate-500">{i}</div>
          ))}
        </div>
        {days.map((day, dayIdx) => (
          <div key={day} className="flex gap-0.5 mb-0.5">
            <div className="w-10 text-xs text-slate-400 flex items-center">{day}</div>
            {Array.from({ length: 24 }, (_, hourIdx) => {
              const entry = data.find(d => d.dayOfWeek === dayIdx && d.hourOfDay === hourIdx);
              const val = entry?.avgRequestsPerMinute || 0;
              const intensity = maxVal > 0 ? val / maxVal : 0;
              const bg = intensity === 0
                ? 'bg-slate-800'
                : intensity < 0.25
                  ? 'bg-blue-900/50'
                  : intensity < 0.5
                    ? 'bg-blue-700/50'
                    : intensity < 0.75
                      ? 'bg-blue-500/50'
                      : 'bg-blue-400/60';
              return (
                <div
                  key={hourIdx}
                  className={`w-7 h-6 rounded-sm ${bg} flex items-center justify-center cursor-pointer`}
                  title={`${day} ${hourIdx}:00 — ${val} req/min`}
                >
                  {val > 0 && <span className="text-[8px] text-slate-300">{val}</span>}
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}

// ───── PERCENTILE TABLE ─────

function PercentileTable({ stats, granularity }: { stats: RateStats; granularity: TimeGranularity }) {
  const rows = [
    { label: 'P50 (Median)', value: stats.p50, desc: '50% of users stay below this' },
    { label: 'P75', value: stats.p75, desc: '75% of users stay below this' },
    { label: 'P90', value: stats.p90, desc: '90% of users stay below this' },
    { label: 'P95', value: stats.p95, desc: '95% of users stay below this', highlight: true },
    { label: 'P99', value: stats.p99, desc: '99% of users stay below this' },
    { label: 'Max', value: stats.max, desc: 'The highest observed per-user rate' },
    { label: 'Mean (avg)', value: stats.mean, desc: 'Average across all users' },
    { label: 'Std Dev (σ)', value: stats.stdDev, desc: `Spread: rates vary by ~${stats.stdDev.toFixed(1)} from the mean` },
  ];

  return (
    <div>
      <h4 className="text-sm font-semibold text-slate-200 mb-3">
        Per-User Peak Rate Distribution (req/{granularity})
        <span className="text-xs text-slate-400 font-normal ml-2">— {stats.sampleCount} users analyzed</span>
      </h4>
      <div className="bg-slate-800/50 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-700">
              <th className="text-left px-4 py-2 text-slate-400 font-medium">Metric</th>
              <th className="text-right px-4 py-2 text-slate-400 font-medium">Value</th>
              <th className="text-left px-4 py-2 text-slate-400 font-medium">Meaning</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(row => (
              <tr key={row.label} className={`border-b border-slate-700/50 ${row.highlight ? 'bg-blue-500/5' : ''}`}>
                <td className={`px-4 py-2 ${row.highlight ? 'text-blue-400 font-semibold' : 'text-slate-200'}`}>{row.label}</td>
                <td className={`text-right px-4 py-2 font-mono ${row.highlight ? 'text-blue-400 font-bold text-base' : 'text-slate-100'}`}>
                  {typeof row.value === 'number' && row.value % 1 !== 0 ? row.value.toFixed(2) : row.value}
                </td>
                <td className="px-4 py-2 text-slate-400 text-xs">{row.desc}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ───── ALGORITHM CARD ─────

function AlgorithmCard({ result, isSelected, recommended, onSelect, paramLabel, paramValue, paramMin, paramMax, paramStep, onParamChange }: {
  result: AlgorithmResult;
  isSelected: boolean;
  recommended?: boolean;
  onSelect: (val: number) => void;
  paramLabel: string;
  paramValue: number;
  paramMin: number;
  paramMax: number;
  paramStep: number;
  onParamChange: (val: number) => void;
}) {
  return (
    <div className={`bg-slate-800/50 border rounded-lg p-4 ${recommended ? 'border-emerald-500/60 ring-1 ring-emerald-500/20' : isSelected ? 'border-blue-500' : 'border-slate-700'}`}>
      <div className="flex items-center gap-2 mb-1">
        <h5 className="text-sm font-semibold text-slate-200">{result.label}</h5>
        {recommended && <span className="px-1.5 py-0.5 text-[10px] font-semibold bg-emerald-500/20 text-emerald-400 rounded">Recommended</span>}
      </div>
      <div className="text-3xl font-bold text-slate-100 mb-1">
        {result.rateLimit}
        <span className="text-sm font-normal text-slate-400 ml-1">req/{result.granularity}</span>
      </div>
      {result.type === 'p99_burst' && result.burstMultiplier > 1 && (
        <div className="mb-2 px-2.5 py-1.5 bg-emerald-500/10 border border-emerald-500/30 rounded-lg">
          <div className="text-xs text-emerald-400 font-medium">Effective Rate (base × burst)</div>
          <div className="text-lg font-bold text-emerald-300">
            {result.rateLimit * result.burstMultiplier}
            <span className="text-xs font-normal text-emerald-400/70 ml-1">req/{result.granularity}</span>
            <span className="text-xs font-normal text-slate-400 ml-2">({result.rateLimit} × {result.burstMultiplier})</span>
          </div>
        </div>
      )}
      <p className="text-xs text-slate-400 mb-3">{result.description}</p>
      <div className="text-xs text-slate-500 font-mono mb-3">{result.formula}</div>

      {/* Parameter tuning */}
      <div className="mb-3">
        <div className="flex items-center justify-between text-xs mb-1">
          <span className="text-slate-400">{paramLabel}</span>
          <span className="text-slate-300 font-medium">{paramValue}</span>
        </div>
        <input
          type="range"
          value={paramValue}
          onChange={e => onParamChange(Number(e.target.value))}
          min={paramMin}
          max={paramMax}
          step={paramStep}
          className="w-full h-1.5 bg-slate-700 rounded-full appearance-none cursor-pointer accent-blue-500"
        />
      </div>

      <button
        onClick={() => onSelect(result.rateLimit)}
        className="w-full px-3 py-1.5 text-xs font-medium bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 rounded-lg transition-colors flex items-center justify-center gap-1"
      >
        <ArrowRight className="w-3 h-3" />
        Use as starting point
      </button>
    </div>
  );
}

// ───── IMPACT DISPLAY ─────

function ImpactDisplay({ impact, hoursBack }: { impact: ImpactSimulation; hoursBack: number }) {
  const durationLabel = hoursBack >= 24
    ? `${Math.round(hoursBack / 24)} day${Math.round(hoursBack / 24) !== 1 ? 's' : ''}`
    : hoursBack < 1
    ? `${Math.round(hoursBack * 60)} minutes`
    : `${hoursBack} hour${hoursBack !== 1 ? 's' : ''}`;
  return (
    <div>
      {/* Summary stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
        <div className="bg-slate-700/50 rounded-lg p-3">
          <div className="text-xs text-slate-400">Users Affected</div>
          <div className={`text-xl font-bold ${impact.usersAffected > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
            {impact.usersAffected}
          </div>
          <div className="text-xs text-slate-400">{impact.usersAffectedPercent}% of {impact.totalUsersAnalyzed}</div>
        </div>
        <div className="bg-slate-700/50 rounded-lg p-3">
          <div className="text-xs text-slate-400">Requests Blocked</div>
          <div className={`text-xl font-bold ${impact.requestsBlocked > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
            {impact.requestsBlocked.toLocaleString()}
          </div>
          <div className="text-xs text-slate-400">{impact.requestsBlockedPercent}% of total</div>
        </div>
        <div className="bg-slate-700/50 rounded-lg p-3">
          <div className="text-xs text-slate-400">Rate Limit</div>
          <div className="text-xl font-bold text-slate-100">{impact.rateLimit}</div>
          <div className="text-xs text-slate-400">per {impact.granularity}</div>
        </div>
        <div className="bg-slate-700/50 rounded-lg p-3">
          <div className="text-xs text-slate-400">Effective Limit</div>
          <div className="text-xl font-bold text-slate-100">{impact.rateLimit * impact.burstMultiplier}</div>
          <div className="text-xs text-slate-400">with {impact.burstMultiplier}x burst</div>
        </div>
      </div>

      {/* Affected Users Table */}
      {impact.affectedUsers.length > 0 && (
        <div className="mb-4">
          <h5 className="text-xs font-semibold text-slate-300 mb-2">Users That Would Have Been Rate-Limited</h5>
          <div className="bg-slate-800/50 rounded-lg overflow-x-auto max-h-48 overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-slate-800">
                <tr className="border-b border-slate-700">
                  <th className="text-left px-3 py-1.5 text-slate-400">User</th>
                  <th className="text-left px-3 py-1.5 text-slate-400">Reputation</th>
                  <th className="text-right px-3 py-1.5 text-slate-400">Times Blocked</th>
                  <th className="text-right px-3 py-1.5 text-slate-400">Peak Rate</th>
                  <th className="text-right px-3 py-1.5 text-slate-400">Avg Rate</th>
                  <th className="text-left px-3 py-1.5 text-slate-400">Top Path</th>
                </tr>
              </thead>
              <tbody>
                {impact.affectedUsers.map(u => (
                  <tr key={u.identifier} className="border-b border-slate-700/30">
                    <td className="px-3 py-1.5 text-slate-200 font-mono truncate max-w-[150px]">{u.identifier.slice(0, 25)}</td>
                    <td className="px-3 py-1.5"><ReputationBadge reputation={u.reputation} /></td>
                    <td className="text-right px-3 py-1.5 text-amber-400">{u.timesBlocked}</td>
                    <td className="text-right px-3 py-1.5 text-slate-100">{u.peakRate}</td>
                    <td className="text-right px-3 py-1.5 text-slate-300">{u.avgRate}</td>
                    <td className="px-3 py-1.5 text-slate-400 truncate max-w-[120px]">{u.topBlockedPaths[0] || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Path Impact */}
      {impact.pathImpact.length > 0 && (
        <div>
          <h5 className="text-xs font-semibold text-slate-300 mb-2">Paths Most Affected by Blocks</h5>
          <div className="flex flex-wrap gap-2">
            {impact.pathImpact.map(p => (
              <span key={p.path} className="px-2 py-1 text-xs bg-slate-700/50 text-slate-300 rounded">
                {p.path} ({p.blockedRequests} blocks, {p.percentOfBlocks}%)
              </span>
            ))}
          </div>
        </div>
      )}

      {impact.usersAffected === 0 && (
        <div className="flex items-center gap-2 p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
          <Check className="w-4 h-4 text-emerald-400" />
          <span className="text-sm text-emerald-400">No legitimate users would have been rate-limited in the past {durationLabel} at this setting.</span>
        </div>
      )}
    </div>
  );
}

// ───── CURRENT VS RECOMMENDED ─────

function CurrentVsRecommended({ current, proposed, granularity, burstMultiplier }: {
  current: AnalysisResults['currentConfig'];
  proposed: number;
  granularity: TimeGranularity;
  burstMultiplier: number;
}) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
      <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
        <h5 className="text-sm font-semibold text-slate-400 mb-3">Current Config</h5>
        <div className="space-y-2 text-sm">
          <div><span className="text-slate-400">Rate Limit:</span> <span className="text-slate-100 font-bold">{current.currentLimit || 'None'}</span> <span className="text-slate-400">req/{current.currentUnit?.toLowerCase() || 'N/A'}</span></div>
          <div><span className="text-slate-400">Burst:</span> <span className="text-slate-100">{current.currentBurstMultiplier || 'N/A'}x</span></div>
          <div><span className="text-slate-400">User ID Policy:</span> <span className="text-slate-100">{current.userIdPolicyName || 'None'}</span></div>
          {current.existingPolicies.length > 0 && (
            <div><span className="text-slate-400">Policies:</span> <span className="text-slate-100">{current.existingPolicies.join(', ')}</span></div>
          )}
        </div>
      </div>
      <div className="bg-slate-800/50 border border-blue-500/30 rounded-lg p-4">
        <h5 className="text-sm font-semibold text-blue-400 mb-3">Your Analysis Says</h5>
        <div className="space-y-2 text-sm">
          <div><span className="text-slate-400">Rate Limit:</span> <span className="text-blue-400 font-bold">{proposed}</span> <span className="text-slate-400">req/{granularity}</span></div>
          <div><span className="text-slate-400">Burst:</span> <span className="text-blue-400">{burstMultiplier}x</span></div>
          <div><span className="text-slate-400">Effective:</span> <span className="text-slate-100">{proposed * burstMultiplier} req/{granularity}</span></div>
          {current.currentLimit && proposed < current.currentLimit && (
            <div className="mt-2 p-2 bg-amber-500/10 border border-amber-500/20 rounded text-xs text-amber-400">
              Tighter than current ({current.currentLimit} → {proposed}). This provides better protection.
            </div>
          )}
          {current.currentLimit && proposed > current.currentLimit && (
            <div className="mt-2 p-2 bg-blue-500/10 border border-blue-500/20 rounded text-xs text-blue-400">
              Higher than current ({current.currentLimit} → {proposed}). Accommodates observed traffic peaks.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ───── CONFIG OUTPUT ─────

function ConfigOutput({ results, rateLimit, granularity, burstMultiplier, onCopy, copiedField, onDownloadPdf, isGeneratingPdf }: {
  results: AnalysisResults;
  rateLimit: number;
  granularity: TimeGranularity;
  burstMultiplier: number;
  onCopy: (text: string, label: string) => void;
  copiedField: string;
  onDownloadPdf: () => void;
  isGeneratingPdf: boolean;
}) {
  const unit = granularity.toUpperCase() as 'SECOND' | 'MINUTE' | 'HOUR';
  const config = generateConfig(results.lbName, results.namespace, rateLimit, unit, burstMultiplier, [], results);

  // Build JSON for each algorithm
  const algorithmConfigs = results.algorithms.map(algo => {
    const algoUnit = algo.granularity.toUpperCase() as 'SECOND' | 'MINUTE' | 'HOUR';
    const algoConfig = generateConfig(results.lbName, results.namespace, algo.rateLimit, algoUnit, algo.burstMultiplier, [], results);
    return {
      label: algo.label,
      type: algo.type,
      rateLimit: algo.rateLimit,
      burstMultiplier: algo.burstMultiplier,
      granularity: algo.granularity,
      effective: algo.rateLimit * algo.burstMultiplier,
      json: formatConfigJSON({
        rate_limit: {
          rate_limiter: algoConfig.rateLimiter,
          no_ip_allowed_list: {},
          policies: { policies: [] },
        },
      }),
    };
  });

  return (
    <div>
      {/* Rationale */}
      <div className="mb-6">
        <h4 className="text-sm font-semibold text-slate-200 mb-2">Analysis Rationale</h4>
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 text-sm text-slate-300 leading-relaxed">
          {config.rationale}
        </div>
      </div>

      {/* JSON Configs for each algorithm */}
      {algorithmConfigs.map((ac, idx) => (
        <div key={ac.type} className={`mb-6 ${idx === 0 ? 'border border-emerald-500/30 rounded-xl p-4 bg-emerald-500/5' : ''}`}>
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <h4 className="text-sm font-semibold text-slate-200">{ac.label}</h4>
              {ac.type === 'p99_burst' && <span className="px-1.5 py-0.5 text-[10px] font-semibold bg-emerald-500/20 text-emerald-400 rounded">Recommended</span>}
              <span className="text-xs text-slate-400">
                Base: {ac.rateLimit} | Burst: {ac.burstMultiplier}x | Effective: {ac.effective} req/{ac.granularity}
              </span>
            </div>
            <button
              onClick={() => onCopy(ac.json, `algo-${ac.type}`)}
              className="flex items-center gap-1 px-3 py-1 text-xs bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg transition-colors"
            >
              {copiedField === `algo-${ac.type}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              {copiedField === `algo-${ac.type}` ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <pre className="bg-slate-950 border border-slate-700 rounded-lg p-4 text-sm text-green-400 overflow-x-auto font-mono">
            {ac.json}
          </pre>
        </div>
      ))}

      {/* Download */}
      <div className="flex gap-3">
        <button
          onClick={() => {
            const allConfigs = algorithmConfigs.reduce((acc, ac) => {
              acc[ac.type] = { label: ac.label, rateLimit: ac.rateLimit, burstMultiplier: ac.burstMultiplier, effective: ac.effective, config: JSON.parse(ac.json) };
              return acc;
            }, {} as Record<string, unknown>);
            const blob = new Blob([JSON.stringify(allConfigs, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `rate-limit-advisor-${results.lbName}-${new Date().toISOString().split('T')[0]}.json`;
            a.click();
            URL.revokeObjectURL(url);
          }}
          className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg transition-colors text-sm"
        >
          <Download className="w-4 h-4" />
          Download All Configs
        </button>
        <button
          onClick={() => {
            const report = {
              analysis: results,
              algorithmConfigs: algorithmConfigs.map(ac => ({ label: ac.label, type: ac.type, rateLimit: ac.rateLimit, burstMultiplier: ac.burstMultiplier, effective: ac.effective, config: JSON.parse(ac.json) })),
              generatedAt: new Date().toISOString(),
            };
            const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `rate-limit-analysis-${results.lbName}-${new Date().toISOString().split('T')[0]}.json`;
            a.click();
            URL.revokeObjectURL(url);
          }}
          className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg transition-colors text-sm"
        >
          <Download className="w-4 h-4" />
          Download Full Analysis Report
        </button>
        <button
          type="button"
          onClick={(e) => { e.preventDefault(); e.stopPropagation(); onDownloadPdf(); }}
          disabled={isGeneratingPdf}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-lg transition-colors text-sm"
        >
          {isGeneratingPdf ? (
            <>
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Generating PDF...
            </>
          ) : (
            <>
              <FileJson className="w-4 h-4" />
              Download Report as PDF
            </>
          )}
        </button>
      </div>
    </div>
  );
}

// ───── PATH ANALYSIS ─────

function PathAnalysisSection({ paths }: { paths: PathAnalysis[] }) {
  return (
    <div>
      <div className="bg-slate-800/50 rounded-lg overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-700">
              <th className="text-left px-4 py-2 text-slate-400 font-medium">Path</th>
              <th className="text-right px-4 py-2 text-slate-400 font-medium">Requests</th>
              <th className="text-right px-4 py-2 text-slate-400 font-medium">Users</th>
              <th className="text-right px-4 py-2 text-slate-400 font-medium">P95/min</th>
              <th className="text-right px-4 py-2 text-slate-400 font-medium">Max/min</th>
              <th className="text-left px-4 py-2 text-slate-400 font-medium">Methods</th>
              <th className="text-center px-4 py-2 text-slate-400 font-medium">Sensitive?</th>
            </tr>
          </thead>
          <tbody>
            {paths.slice(0, 20).map(path => (
              <tr key={path.normalizedPath} className="border-b border-slate-700/50">
                <td className="px-4 py-2 text-slate-100 font-mono text-xs">{path.normalizedPath}</td>
                <td className="text-right px-4 py-2 text-slate-100">{path.totalRequests.toLocaleString()}</td>
                <td className="text-right px-4 py-2 text-slate-300">{path.uniqueUsers}</td>
                <td className="text-right px-4 py-2 text-amber-400">{path.rateStats.minute.p95}</td>
                <td className="text-right px-4 py-2 text-slate-100">{path.rateStats.minute.max}</td>
                <td className="px-4 py-2 text-slate-400 text-xs">{Object.keys(path.methods).join(', ')}</td>
                <td className="text-center px-4 py-2">
                  {path.isSensitive ? (
                    <span className="px-2 py-0.5 text-xs bg-red-500/20 text-red-400 rounded" title={path.sensitiveReason}>
                      <Lock className="w-3 h-3 inline" /> {path.sensitiveReason?.split(' ')[0]}
                    </span>
                  ) : (
                    <span className="text-slate-500">-</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
