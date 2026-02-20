import { useState, useRef, useMemo } from 'react';
import { 
  ArrowLeft, Play, Download, Upload, 
  CheckCircle, XCircle, Activity, ChevronDown, ChevronRight,
  ShieldAlert, Layers, Code, Trash2, Plus, Globe, FileText, X, ClipboardList,
  ExternalLink
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { useToast } from '../context/ToastContext';

// --- Types ---

interface TestRow {
  id: string;
  domain: string;
  targetIps: string[];
  path: string;
}

interface RequestResult {
  status: number | string;
  statusText: string;
  size: number;
  headers: Record<string, string>;
  body: string;
  normalizedBody: string;
  duration: number;
  isBotChallenge: boolean;
  debugInfo?: string;
  error?: string;
  connectedIp?: string;
}

interface SpoofedResult {
  ip: string;
  result: RequestResult;
  score: number;
  statusMatch: boolean;
  passed: boolean;
}

interface ComparisonResult {
  row: TestRow;
  public: RequestResult;
  spoofedResults: SpoofedResult[];
  overallPassed: boolean;
  reasons: string[];
  timestamp: string;
}

interface UrlEntry {
  id: string;
  url: string;
}

// --- Configuration Constants ---

const IGNORED_HEADERS = new Set([
  'date', 'server', 'connection', 'keep-alive', 'age', 
  'transfer-encoding', 'set-cookie', 'content-length', 
  'etag', 'last-modified', 'strict-transport-security',
  'x-akamai-staging', 'x-akamai-transformed'
]);

const BOT_SIGNATURES = [
  '_imp_apg_r_',
  'id="challenge-form"',
  'f5_cspm',
  'challenge-platform'
];

// --- Helper Functions ---

const normalizeHtml = (html: string): string => {
  return html
    .replace(/<script\b[^>]*>([\s\S]*?)<\/script>/gim, "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<style\b[^>]*>([\s\S]*?)<\/style>/gim, "")
    .replace(/\s+/g, " ")
    .trim();
};

const calculateSimilarity = (str1: string, str2: string): number => {
  if (str1 === str2) return 100;
  if (!str1 || !str2) return 0;
  
  const bigrams = (str: string) => {
    const s = str.toLowerCase();
    const v = new Array(Math.max(0, s.length - 1));
    for (let i = 0; i < v.length; i++) v[i] = s.slice(i, i + 2);
    return v;
  };

  const pairs1 = bigrams(str1);
  const pairs2 = bigrams(str2);
  const union = pairs1.length + pairs2.length;
  if (union === 0) return 100;

  let hit = 0;

  for (const x of pairs1) {
    for (let i = 0; i < pairs2.length; i++) {
      if (x === pairs2[i]) {
        hit++;
        pairs2.splice(i, 1);
        break;
      }
    }
  }

  return Math.floor((2.0 * hit) / union * 100);
};

const parseCSV = (text: string): TestRow[] => {
  const lines = text.split('\n').filter(l => l.trim().length > 0);
  const startIdx = lines[0]?.toLowerCase().startsWith('domain') ? 1 : 0;
  
  return lines.slice(startIdx).map((line, idx) => {
    const cols = line.split(',').map(c => c.trim());
    return {
      id: `row-${idx}-${Date.now()}`,
      domain: cols[0] || '',
      targetIps: cols[1] ? cols[1].split(';').map(ip => ip.trim()).filter(Boolean) : [],
      path: cols[2] || '/',
    };
  }).filter(r => r.domain && r.path);
};

const parseUrlEntries = (entries: UrlEntry[], spoofIps: string[]): TestRow[] => {
  const validIps = spoofIps.map(ip => ip.trim()).filter(Boolean);
  return entries
    .filter(e => e.url.trim().length > 0)
    .map((entry, idx) => {
      try {
        const parsed = new URL(
          entry.url.startsWith('http') ? entry.url : `https://${entry.url}`
        );
        return {
          id: `url-${idx}-${Date.now()}`,
          domain: parsed.hostname,
          targetIps: validIps,
          path: parsed.pathname + parsed.search,
        };
      } catch {
        return null;
      }
    })
    .filter(Boolean) as TestRow[];
};

// --- Components ---

// --- Spoof color palette ---
const SPOOF_COLORS = [
  { label: 'text-amber-400',  border: 'border-amber-500/40',  bg: 'bg-amber-500/10',  dot: 'bg-amber-400'  },
  { label: 'text-violet-400', border: 'border-violet-500/40', bg: 'bg-violet-500/10', dot: 'bg-violet-400' },
  { label: 'text-cyan-400',   border: 'border-cyan-500/40',   bg: 'bg-cyan-500/10',   dot: 'bg-cyan-400'   },
  { label: 'text-rose-400',   border: 'border-rose-500/40',   bg: 'bg-rose-500/10',   dot: 'bg-rose-400'   },
];
const getSpoofColor = (idx: number) => SPOOF_COLORS[idx % SPOOF_COLORS.length];

const getSpoofLabel = (idx: number) => {
  const labels = ['Prod', 'Stag'];
  return labels[idx] || `SPOOF ${idx + 1}`;
};

const ComparisonTable = ({ publicRes, spoofedResults }: { publicRes: RequestResult, spoofedResults: SpoofedResult[] }) => {
  const liveColor = { label: 'text-blue-400', dot: 'bg-blue-400' };
  const cols = [
    { label: 'LIVE', color: liveColor, result: publicRes, ip: null as string|null, score: null as number|null },
    ...spoofedResults.map((s, i) => ({ label: getSpoofLabel(i), color: getSpoofColor(i), result: s.result, ip: s.ip, score: s.score }))
  ];

  const metrics: { label: string; render: (r: RequestResult) => string }[] = [
    { label: 'Status',   render: r => r.status.toString() },
    { label: 'Time',     render: r => `${r.duration}ms` },
    { label: 'Size',     render: r => r.size > 0 ? `${(r.size/1024).toFixed(1)} KB` : '—' },
    { label: 'Bot?',     render: r => r.isBotChallenge ? '⚠ Yes' : 'No' },
    { label: 'Conn. IP', render: r => r.connectedIp || '—' },
  ];

  return (
    <div className="overflow-x-auto rounded-lg border border-slate-700">
      <table className="w-full text-xs font-mono">
        <thead>
          <tr className="border-b border-slate-700 bg-slate-900/60">
            <th className="text-left py-2 px-3 text-slate-500 font-normal w-20">Metric</th>
            {cols.map((col, ci) => (
              <th key={ci} className={`py-2 px-3 text-left ${col.color.label}`}>
                <div className="flex items-center gap-1.5">
                  <div className={`w-1.5 h-1.5 rounded-full ${col.color.dot}`} />
                  {col.label}
                </div>
                {col.ip && <div className="text-[10px] text-slate-500 font-normal mt-0.5 truncate max-w-[140px]" title={col.ip}>{col.ip}</div>}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {metrics.map(({ label, render }, ri) => (
            <tr key={ri} className={`border-b border-slate-700/50 ${ri % 2 === 0 ? 'bg-slate-900/20' : ''}`}>
              <td className="py-2 px-3 text-slate-500">{label}</td>
              {cols.map((col, ci) => {
                const val = render(col.result);
                const liveVal = render(cols[0].result);
                const isBot   = label === 'Bot?'   && col.result.isBotChallenge;
                const isErr   = label === 'Status' && col.result.status === 'ERR';
                const isDrift = ci > 0 && val !== liveVal && label !== 'Size' && label !== 'Time' && label !== 'Conn. IP';
                return (
                  <td key={ci} className={`py-2 px-3 ${isBot ? 'text-amber-400 font-bold' : isErr ? 'text-red-400 font-bold' : isDrift ? 'text-amber-300 font-bold' : 'text-slate-200'}`}>
                    {val}
                  </td>
                );
              })}
            </tr>
          ))}
          <tr className="border-b border-slate-700/50 bg-slate-900/20">
            <td className="py-2 px-3 text-slate-500">Similarity</td>
            <td className="py-2 px-3 text-slate-500 text-[10px] italic">baseline</td>
            {cols.slice(1).map((col, ci) => (
              <td key={ci} className={`py-2 px-3 font-bold ${(col.score ?? 0) >= 95 ? 'text-emerald-400' : 'text-red-400'}`}>
                {col.score !== null ? `${col.score}%` : '—'}
              </td>
            ))}
          </tr>
          {cols.some(c => c.result.error) && (
            <tr>
              <td className="py-2 px-3 text-slate-500">Error</td>
              {cols.map((col, ci) => (
                <td key={ci} className="py-2 px-3 text-red-400 text-[10px] max-w-[200px] truncate" title={col.result.error}>
                  {col.result.error || '—'}
                </td>
              ))}
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
};

const DiffView = ({ left, right, title }: { left: string, right: string, title: string }) => (
  <div className="grid grid-cols-2 gap-4 text-xs font-mono">
    <div className="bg-slate-900/50 p-2 rounded border border-slate-700/50 overflow-auto max-h-64">
      <div className="text-slate-500 mb-1 border-b border-slate-700 pb-1">Public {title}</div>
      <pre className="whitespace-pre-wrap break-all text-slate-300">{left || '<empty>'}</pre>
    </div>
    <div className="bg-slate-900/50 p-2 rounded border border-slate-700/50 overflow-auto max-h-64">
      <div className="text-slate-500 mb-1 border-b border-slate-700 pb-1">Spoofed {title}</div>
      <pre className="whitespace-pre-wrap break-all text-slate-300">{right || '<empty>'}</pre>
    </div>
  </div>
);

const HeaderDiff = ({ pubHeaders, spoofHeaders, publicIp, spoofedIp }: { 
  pubHeaders: Record<string, string>, 
  spoofHeaders: Record<string, string>,
  publicIp?: string,
  spoofedIp?: string
}) => {
  const allKeys = new Set([...Object.keys(pubHeaders), ...Object.keys(spoofHeaders)]);
  const sortedKeys = Array.from(allKeys).sort();

  return (
    <div className="text-xs font-mono bg-slate-900/50 rounded border border-slate-700/50 max-h-96 overflow-auto">
      <table className="w-full text-left border-collapse">
        <thead className="bg-slate-800 sticky top-0 z-10">
          <tr>
            <th className="p-2 border-b border-slate-700 w-1/3">Header</th>
            <th className="p-2 border-b border-slate-700 w-1/3">
              <div>Public</div>
              {publicIp && <div className="text-[10px] text-blue-400 font-normal">IP: {publicIp}</div>}
            </th>
            <th className="p-2 border-b border-slate-700 w-1/3">
              <div>Spoofed</div>
              {spoofedIp && <div className="text-[10px] text-emerald-400 font-normal">IP: {spoofedIp}</div>}
            </th>
          </tr>
        </thead>
        <tbody>
          {sortedKeys.map(key => {
            const isIgnored = IGNORED_HEADERS.has(key);
            const valPub = pubHeaders[key];
            const valSpoof = spoofHeaders[key];
            const isDiff = valPub !== valSpoof;
            const isSignificantDiff = isDiff && !isIgnored;
            
            let rowClass = 'border-b border-slate-800 hover:bg-slate-800/50';
            let headerClass = 'p-2 truncate';
            
            if (isSignificantDiff) {
              rowClass += ' bg-amber-900/10';
              headerClass += ' text-amber-400 font-bold';
            } else if (isIgnored) {
              headerClass += ' text-slate-600';
            } else {
              headerClass += ' text-slate-400';
            }

            return (
              <tr key={key} className={rowClass}>
                <td className={headerClass}>
                  {key}
                  {isIgnored && <span className="ml-1 text-slate-700 text-[10px]">(ignored)</span>}
                </td>
                <td className="p-2 truncate max-w-xs text-slate-300" title={valPub}>
                  {valPub || <span className="text-slate-600">-</span>}
                </td>
                <td className={`p-2 truncate max-w-xs ${isSignificantDiff ? 'text-amber-300 font-semibold' : 'text-slate-300'}`} title={valSpoof}>
                  {valSpoof || <span className="text-slate-600">-</span>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

// --- Domain / Environment Group Summary ---

interface EnvGroup {
  envIdx: number;
  label: string;
  results: ComparisonResult[];
  passCount: number;
  failCount: number;
}

interface DomainGroup {
  domain: string;
  results: ComparisonResult[];
  envGroups: EnvGroup[];
  allPassed: boolean;
  passCount: number;
  failCount: number;
}

export function HttpSanityChecker() {
  const toast = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const bulkFileInputRef = useRef<HTMLInputElement>(null);
  
  const [inputMode, setInputMode] = useState<'csv' | 'url'>('csv');
  const [urlEntries, setUrlEntries] = useState<UrlEntry[]>([
    { id: `ue-${Date.now()}`, url: '' }
  ]);
  const [spoofIps, setSpoofIps] = useState<string[]>(['', '']);
  const addSpoofIp    = () => setSpoofIps(prev => [...prev, '']);
  const removeSpoofIp = (i: number) => setSpoofIps(prev => prev.length > 1 ? prev.filter((_, idx) => idx !== i) : prev);
  const updateSpoofIp = (i: number, val: string) => setSpoofIps(prev => prev.map((v, idx) => idx === i ? val : v));
  const [showBulkAdd, setShowBulkAdd] = useState(false);
  const [bulkText, setBulkText] = useState('');
  const [csvText, setCsvText] = useState<string>('example.com, 1.2.3.4, /api/health');
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<ComparisonResult[]>([]);
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [collapsedDomains, setCollapsedDomains] = useState<Set<string>>(new Set());
  const [collapsedEnvGroups, setCollapsedEnvGroups] = useState<Set<string>>(new Set());
  const abortController = useRef<AbortController | null>(null);

  // --- Group results by domain, then by spoof environment ---
  const groupedResults: DomainGroup[] = useMemo(() => {
    const map = new Map<string, ComparisonResult[]>();
    for (const res of results) {
      const domain = res.row.domain;
      if (!map.has(domain)) map.set(domain, []);
      map.get(domain)!.push(res);
    }

    return Array.from(map.entries()).map(([domain, items]) => {
      // Determine how many spoof environments exist across all results in this domain
      const maxEnvs = items.reduce((m, r) => Math.max(m, r.spoofedResults.length), 0);

      const envGroups: EnvGroup[] = Array.from({ length: maxEnvs }, (_, envIdx) => {
        const envResults = items.filter(r => r.spoofedResults[envIdx] !== undefined);
        const passCount = envResults.filter(r => r.spoofedResults[envIdx]?.passed).length;
        const failCount = envResults.length - passCount;
        return {
          envIdx,
          label: getSpoofLabel(envIdx),
          results: envResults,
          passCount,
          failCount,
        };
      });

      const passCount = items.filter(r => r.overallPassed).length;
      const failCount = items.length - passCount;
      return { domain, results: items, envGroups, allPassed: failCount === 0, passCount, failCount };
    });
  }, [results]);

  const toggleDomainCollapse = (domain: string) => {
    setCollapsedDomains(prev => {
      const next = new Set(prev);
      if (next.has(domain)) next.delete(domain); else next.add(domain);
      return next;
    });
  };

  const toggleEnvGroupCollapse = (key: string) => {
    setCollapsedEnvGroups(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  };

  // --- Server-Side Proxy Execution ---
  const executeRequest = async (url: string, isSpoofed: boolean, hostHeader: string, targetIp: string): Promise<RequestResult> => {
    const start = performance.now();
    try {
      const headers: Record<string, string> = {
        'User-Agent': 'XC-BulkOps-Validator/1.0',
      };
      
      if (isSpoofed) {
        headers['Host'] = hostHeader;
        headers['X-F5-Test'] = 'sanity-check';
      } else {
        headers['Pragma'] = 'akamai-x-cache-on, akamai-x-get-cache-key, akamai-x-get-true-cache-key';
      }

      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error('Frontend timeout after 20 seconds')), 20000);
      });

      const fetchPromise = fetch('/api/proxy/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url,
          method: 'GET',
          headers,
          targetIp: isSpoofed ? targetIp : undefined
        }),
        signal: abortController.current?.signal
      });

      const proxyResponse = await Promise.race([fetchPromise, timeoutPromise]);
      const data = await proxyResponse.json();
      const end = performance.now();

      if (!proxyResponse.ok) {
        throw new Error(data.error || `Proxy Error: ${proxyResponse.status}`);
      }

      const resHeaders: Record<string, string> = {};
      if (data.headers) {
        Object.entries(data.headers).forEach(([key, val]) => {
          resHeaders[key.toLowerCase()] = String(val);
        });
      }

      const text = data.body || '';
      const isBotChallenge = BOT_SIGNATURES.some(sig => text.includes(sig));
      const debugInfo = resHeaders['x-cache'] || resHeaders['x-akamai-session-info'] || undefined;

      return {
        status: data.status,
        statusText: data.statusText || '',
        size: text.length,
        headers: resHeaders,
        body: text,
        normalizedBody: normalizeHtml(text),
        duration: Math.round(end - start),
        isBotChallenge,
        debugInfo,
        connectedIp: data.connectedIp
      };
    } catch (err: any) {
      const end = performance.now();
      console.error(`[Frontend] Request failed for ${url}:`, err.message);
      return {
        status: 'ERR',
        statusText: 'Network Error',
        size: 0,
        headers: {},
        body: '',
        normalizedBody: '',
        duration: Math.round(end - start),
        isBotChallenge: false,
        error: err.message
      };
    }
  };

  const addUrlEntry = () => {
    setUrlEntries(prev => [...prev, { id: `ue-${Date.now()}`, url: '' }]);
  };

  const removeUrlEntry = (id: string) => {
    setUrlEntries(prev => prev.length > 1 ? prev.filter(e => e.id !== id) : prev);
  };

  const updateUrlEntry = (id: string, value: string) => {
    setUrlEntries(prev => prev.map(e => e.id === id ? { ...e, url: value } : e));
  };

  const handleBulkAdd = () => {
    const lines = bulkText
      .split('\n')
      .map(l => l.trim())
      .filter(l => l.length > 0);

    if (lines.length === 0) return;

    const newEntries: UrlEntry[] = lines.map(url => ({
      id: `ue-${Date.now()}-${Math.random()}`,
      url,
    }));

    setUrlEntries(prev => {
      const hasOnlyBlank = prev.length === 1 && prev[0].url.trim() === '';
      return hasOnlyBlank ? newEntries : [...prev, ...newEntries];
    });

    setBulkText('');
    setShowBulkAdd(false);
    toast.success(`Added ${newEntries.length} URL${newEntries.length > 1 ? 's' : ''}`);
  };

  const isValidUrl = (raw: string): boolean => {
    const candidate = raw.startsWith('http://') || raw.startsWith('https://') ? raw : `https://${raw}`;
    try {
      const u = new URL(candidate);
      // Must have a real hostname with at least one dot (e.g. "localhost" is excluded)
      return u.hostname.includes('.');
    } catch {
      return false;
    }
  };

  const handleBulkFileImport = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result;
      if (typeof text === 'string') {
        const allLines = text.split('\n').map(l => l.trim()).filter(Boolean);
        const validUrls = allLines.filter(isValidUrl);
        const skipped = allLines.length - validUrls.length;

        if (validUrls.length === 0) {
          toast.error(`No valid URLs found in ${file.name}`);
          return;
        }

        setBulkText(prev => {
          const combined = prev.trim()
            ? `${prev.trim()}\n${validUrls.join('\n')}`
            : validUrls.join('\n');
          return combined;
        });

        const skippedNote = skipped > 0 ? ` (${skipped} invalid line${skipped !== 1 ? 's' : ''} skipped)` : '';
        toast.success(`Imported ${validUrls.length} URL${validUrls.length !== 1 ? 's' : ''} from ${file.name}${skippedNote}`);
      }
    };
    reader.readAsText(file);
    event.target.value = '';
  };

  const handleExportUrlsAsCsv = () => {
    const validEntries = urlEntries.filter(e => e.url.trim().length > 0);
    if (validEntries.length === 0) {
      toast.error("No URLs to export");
      return;
    }

    const validIps = spoofIps.map(ip => ip.trim()).filter(Boolean);
    const rows = validEntries.map(entry => {
      try {
        const parsed = new URL(
          entry.url.startsWith('http') ? entry.url : `https://${entry.url}`
        );
        const domain = parsed.hostname;
        const path = parsed.pathname + parsed.search || '/';
        return [domain, validIps.join(';'), path].join(',');
      } catch {
        return null;
      }
    }).filter(Boolean);

    const content = ['domain, targetIps (;-sep), path', ...rows].join('\n');
    const blob = new Blob([content], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `url-mode-export-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`Exported ${rows.length} URL${rows.length !== 1 ? 's' : ''} as CSV`);
  };

  const runTest = async () => {
    let rows: TestRow[];

    if (inputMode === 'csv') {
      rows = parseCSV(csvText);
      if (rows.length === 0) {
        toast.error("No valid rows found in CSV");
        return;
      }
    } else {
      const validIps = spoofIps.filter(ip => ip.trim() !== '');
      if (validIps.length === 0) {
        toast.error("Please enter at least one Spoof IP address");
        return;
      }
      rows = parseUrlEntries(urlEntries, spoofIps);
      if (rows.length === 0) {
        toast.error("No valid URLs found. Check that URLs are properly formatted.");
        return;
      }
    }

    setIsRunning(true);
    setResults([]);
    setProgress(0);
    setCollapsedDomains(new Set());
    setCollapsedEnvGroups(new Set());
    abortController.current = new AbortController();

    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      const publicUrl = `https://${row.domain}${row.path}`;

      const [publicRes, ...spoofResArray] = await Promise.all([
        executeRequest(publicUrl, false, row.domain, ''),
        ...row.targetIps.map(ip => executeRequest(publicUrl, true, row.domain, ip))
      ]);

      const overallReasons: string[] = [];
      let overallPassed = true;

      const spoofedResults: SpoofedResult[] = spoofResArray.map((spoofedRes, idx) => {
        const ip = row.targetIps[idx];
        const score = calculateSimilarity(publicRes.normalizedBody, spoofedRes.normalizedBody);
        const statusMatch = publicRes.status.toString() === spoofedRes.status.toString();

        const reasons: string[] = [];
        if (!statusMatch)               reasons.push(`Status Drift: Live ${publicRes.status} vs Spoof ${spoofedRes.status}`);
        if (score < 95)                 reasons.push(`Body Content Mismatch (${score}% similarity)`);
        if (spoofedRes.isBotChallenge)  reasons.push(`⚠️ F5 Bot Challenge Detected`);
        if (spoofedRes.status === 'ERR') reasons.push(`Connection Failed: ${spoofedRes.error}`);

        const passed = reasons.length === 0 || (reasons.length === 1 && spoofedRes.isBotChallenge);
        if (!passed) {
          overallPassed = false;
          reasons.forEach(r => overallReasons.push(`[${ip}] ${r}`));
        }

        return { ip, result: spoofedRes, score, statusMatch, passed };
      });

      const result: ComparisonResult = {
        row,
        public: publicRes,
        spoofedResults,
        overallPassed,
        reasons: overallReasons,
        timestamp: new Date().toISOString()
      };

      setResults(prev => [...prev, result]);
      setProgress(Math.round(((i + 1) / rows.length) * 100));
    }

    setIsRunning(false);
    toast.success("Validation Complete");
  };

  const handleExport = () => {
    if (results.length === 0) return;
    const header = [
      "Domain", "Path", "Overall Result",
      "Live Status", "Live ConnIP",
      ...results[0]?.spoofedResults.flatMap((_, i) => [
        `Spoof${i+1} IP`, `Spoof${i+1} Status`, `Spoof${i+1} StatusMatch`, `Spoof${i+1} Similarity`, `Spoof${i+1} Bot`
      ]) ?? [],
      "Drift Reasons"
    ];
    const csvRows = results.map(r => [
      r.row.domain, r.row.path,
      r.overallPassed ? "PASS" : "FAIL",
      r.public.status, r.public.connectedIp || '',
      ...r.spoofedResults.flatMap(s => [
        s.ip, s.result.status, s.statusMatch ? "YES" : "NO", `${s.score}%`, s.result.isBotChallenge ? "YES" : "NO"
      ]),
      r.reasons.join(' | ')
    ]);
    const content = [header.join(','), ...csvRows.map(r => r.join(','))].join('\n');
    const blob = new Blob([content], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `migration-sanity-check-${Date.now()}.csv`;
    a.click();
  };

  const toggleRow = (id: string) => {
    setExpandedRow(expandedRow === id ? null : id);
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result;
      if (typeof text === 'string') {
        setCsvText(text);
        toast.success(`Loaded ${file.name}`);
      }
    };
    reader.readAsText(file);
    event.target.value = '';
  };

  // --- Render a single path row, optionally scoped to one env by envIdx (null = show all spoofs) ---
  const renderPathRow = (res: ComparisonResult, isExpanded: boolean, fullUrl: string, envIdx: number | null) => {
    const displayedSpoofs = envIdx !== null
      ? res.spoofedResults.filter((_, i) => i === envIdx)
      : res.spoofedResults;
    const envPassed = envIdx !== null
      ? (res.spoofedResults[envIdx]?.passed ?? res.overallPassed)
      : res.overallPassed;
    const envIp = envIdx !== null ? res.spoofedResults[envIdx]?.ip : null;
    const displayedReasons = envIdx !== null && envIp
      ? res.reasons.filter(r => r.startsWith(`[${envIp}]`)).map(r => r.replace(`[${envIp}] `, ''))
      : res.reasons;

    return (
      <div key={`${res.row.id}-env${envIdx}`} className="bg-slate-800">
        {/* Row Header */}
        <div
          className="flex items-center gap-3 px-4 py-3 hover:bg-slate-700/50 cursor-pointer transition-colors"
          onClick={() => toggleRow(res.row.id)}
        >
          <div className="shrink-0">
            {isExpanded
              ? <ChevronDown className="w-4 h-4 text-slate-500" />
              : <ChevronRight className="w-4 h-4 text-slate-500" />}
          </div>
          <div className="shrink-0">
            {envPassed
              ? <CheckCircle className="w-5 h-5 text-emerald-500" />
              : <XCircle className="w-5 h-5 text-red-500" />}
          </div>
          <div className="flex-1 min-w-0 mr-2">
            <div className="flex items-center gap-2">
              <span className="font-medium text-sm text-slate-200 truncate" title={res.row.path}>
                {res.row.path}
              </span>
              <a
                href={fullUrl}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="shrink-0 text-slate-500 hover:text-blue-400 transition-colors"
                title={`Open ${fullUrl} in new tab`}
              >
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
            </div>
            {!isExpanded && displayedReasons.length > 0 && (
              <p className="text-[11px] text-amber-400/80 truncate mt-0.5" title={displayedReasons.join(' · ')}>
                {displayedReasons[0]}{displayedReasons.length > 1 ? ` (+${displayedReasons.length - 1} more)` : ''}
              </p>
            )}
          </div>
          <div className="shrink-0 flex items-center gap-2">
            {/* LIVE chip */}
            <div className="flex items-center gap-2 bg-blue-500/10 border border-blue-500/30 rounded-lg px-3 py-1.5">
              <div className="flex items-center gap-1">
                <div className="w-1.5 h-1.5 rounded-full bg-blue-400" />
                <span className="text-[10px] font-bold text-blue-400 uppercase tracking-wider">Live</span>
              </div>
              <span className={`text-sm font-mono font-bold ${res.public.status === 'ERR' ? 'text-red-400' : 'text-blue-300'}`}>
                {res.public.status}
              </span>
              <span className="text-[10px] text-slate-500">{res.public.duration}ms</span>
            </div>
            {/* Env-scoped spoof chip(s) */}
            {displayedSpoofs.map((spoof) => {
              const originalIdx = res.spoofedResults.indexOf(spoof);
              const c = getSpoofColor(originalIdx);
              return (
                <div key={originalIdx} className={`flex items-center gap-2 border rounded-lg px-3 py-1.5 ${c.border} ${c.bg}`}>
                  <div className="flex items-center gap-1">
                    <div className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
                    <span className={`text-[10px] font-bold uppercase tracking-wider ${c.label}`}>{getSpoofLabel(originalIdx)}</span>
                  </div>
                  <span className={`text-sm font-mono font-bold ${
                    spoof.result.status === 'ERR' ? 'text-red-400' : !spoof.statusMatch ? 'text-amber-300' : 'text-slate-200'
                  }`}>
                    {spoof.result.status}
                  </span>
                  <span className={`text-[10px] font-semibold ${spoof.score >= 95 ? 'text-emerald-400' : 'text-red-400'}`}>
                    {spoof.score}%
                  </span>
                  {spoof.result.isBotChallenge && (
                    <span className="text-[10px] text-amber-400 font-bold" title="Bot challenge detected">⚠</span>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Expanded Detail Panel */}
        {isExpanded && (
          <div className="border-t border-slate-700 bg-slate-900/30 p-4 space-y-4">
            <div className="flex items-center gap-2 bg-slate-900/60 border border-slate-700/60 rounded-lg px-3 py-2">
              <Globe className="w-3.5 h-3.5 text-slate-500 shrink-0" />
              <code className="text-xs text-slate-300 truncate flex-1" title={fullUrl}>{fullUrl}</code>
              <a
                href={fullUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="shrink-0 flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
              >
                Open <ExternalLink className="w-3 h-3" />
              </a>
            </div>
            {displayedReasons.length > 0 && (
              <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded text-xs text-amber-200">
                <strong className="block mb-1">Comparison Drift Detected:</strong>
                <ul className="list-disc pl-4 space-y-0.5">
                  {displayedReasons.map((r, i) => <li key={i}>{r}</li>)}
                </ul>
              </div>
            )}
            <div className="space-y-4">
              <div>
                <h4 className="text-xs font-bold text-slate-400 uppercase mb-2 flex items-center gap-2">
                  <Layers className="w-3 h-3" /> Side-by-Side Comparison
                </h4>
                <ComparisonTable
                  publicRes={res.public}
                  spoofedResults={envIdx !== null ? res.spoofedResults.filter((_, i) => i === envIdx) : res.spoofedResults}
                />
              </div>
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-xs font-bold text-slate-400 uppercase flex items-center gap-2">
                    <Layers className="w-3 h-3" /> Header Comparison
                  </h4>
                  <div className="flex items-center gap-3 text-[10px]">
                    <div className="flex items-center gap-1">
                      <div className="w-2 h-2 bg-amber-500 rounded"></div>
                      <span className="text-slate-500">Significant Diff</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <div className="w-2 h-2 bg-slate-700 rounded"></div>
                      <span className="text-slate-500">Ignored</span>
                    </div>
                  </div>
                </div>
                {displayedSpoofs.map((spoof) => {
                  const originalIdx = res.spoofedResults.indexOf(spoof);
                  const c = getSpoofColor(originalIdx);
                  return (
                    <div key={originalIdx} className="mb-3">
                      <div className={`text-[10px] font-bold uppercase mb-1 ${c.label}`}>
                        LIVE vs {getSpoofLabel(originalIdx)} ({spoof.ip})
                      </div>
                      <HeaderDiff
                        pubHeaders={res.public.headers}
                        spoofHeaders={spoof.result.headers}
                        publicIp={res.public.connectedIp}
                        spoofedIp={spoof.result.connectedIp}
                      />
                    </div>
                  );
                })}
              </div>
              {displayedSpoofs.length > 0 && (
                <div>
                  <h4 className="text-xs font-bold text-slate-400 uppercase mb-2 flex items-center gap-2">
                    <Code className="w-3 h-3" /> Body Preview (Live vs {getSpoofLabel(envIdx ?? 0)})
                  </h4>
                  <div className="text-xs font-bold text-slate-500 mb-1">Normalized Body Preview (First 500 chars)</div>
                  <DiffView
                    left={res.public.normalizedBody.slice(0, 500)}
                    right={displayedSpoofs[0].result.normalizedBody.slice(0, 500)}
                    title="Normalized Content"
                  />
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        <div className="flex items-center gap-4 mb-8">
          <Link to="/" className="p-2 hover:bg-slate-800 rounded-lg">
            <ArrowLeft className="w-5 h-5 text-slate-400" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Activity className="w-6 h-6 text-blue-400" />
              Live vs Spoof HTTP Sanity Checker
            </h1>
            <p className="text-slate-400">Smart comparison between Public DNS (Akamai) and Target IP (F5 Origin)</p>
          </div>
        </div>

        <div className="grid lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 space-y-4">
            <div className="bg-slate-800 rounded-xl p-6 border border-slate-700 h-full flex flex-col">
              <h3 className="font-semibold text-lg mb-4">Configuration</h3>

              {/* Mode Toggle */}
              <div className="flex rounded-lg overflow-hidden border border-slate-700 mb-4">
                <button
                  onClick={() => setInputMode('csv')}
                  className={`flex-1 flex items-center justify-center gap-2 py-2 text-sm font-medium transition-colors ${
                    inputMode === 'csv'
                      ? 'bg-blue-600 text-white'
                      : 'bg-slate-900 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <FileText className="w-4 h-4" /> CSV Mode
                </button>
                <button
                  onClick={() => setInputMode('url')}
                  className={`flex-1 flex items-center justify-center gap-2 py-2 text-sm font-medium transition-colors ${
                    inputMode === 'url'
                      ? 'bg-blue-600 text-white'
                      : 'bg-slate-900 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Globe className="w-4 h-4" /> URL Mode
                </button>
              </div>

              <div className="flex-1 flex flex-col">
                {inputMode === 'csv' ? (
                  <>
                    <div className="flex justify-between items-center mb-2">
                      <label className="block text-xs font-mono text-slate-400">
                        CSV Input: Domain, Target IP, Path
                      </label>
                      <div className="flex gap-2">
                        <button 
                          onClick={() => setCsvText('')}
                          className="text-xs flex items-center gap-1 text-slate-400 hover:text-white transition-colors"
                          title="Clear Input"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                        <button 
                          onClick={() => fileInputRef.current?.click()}
                          className="text-xs flex items-center gap-1 text-blue-400 hover:text-blue-300 transition-colors"
                        >
                          <Upload className="w-3 h-3" /> Upload CSV
                        </button>
                        <input 
                          ref={fileInputRef} 
                          type="file" 
                          onChange={handleFileUpload} 
                          accept=".csv,.txt" 
                          className="hidden" 
                        />
                      </div>
                    </div>
                    <textarea
                      value={csvText}
                      onChange={(e) => setCsvText(e.target.value)}
                      className="w-full h-64 bg-slate-900 border border-slate-700 rounded-lg p-3 text-xs font-mono focus:ring-2 focus:ring-blue-500 outline-none resize-none"
                      placeholder="example.com, 1.2.3.4, /api/status"
                    />
                  </>
                ) : (
                  <>
                    {/* Spoof IP fields */}
                    <div className="mb-4 space-y-2">
                      <div className="flex items-center justify-between mb-1">
                        <label className="block text-xs font-mono text-slate-400 uppercase tracking-wider">
                          Spoof IP Addresses <span className="text-red-400">*</span>
                        </label>
                        <button onClick={addSpoofIp} className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors">
                          <Plus className="w-3 h-3"/> Add IP
                        </button>
                      </div>
                      {spoofIps.map((ip, index) => {
                        const c = getSpoofColor(index);
                        return (
                          <div key={index} className={`flex gap-2 items-center p-2 rounded-lg border ${c.border} ${c.bg}`}>
                            <div className={`text-[10px] font-bold uppercase w-14 shrink-0 ${c.label}`}>{getSpoofLabel(index)}</div>
                            <input
                              type="text"
                              value={ip}
                              onChange={(e) => updateSpoofIp(index, e.target.value)}
                              placeholder="e.g. 10.0.0.1"
                              className="flex-1 bg-slate-900/70 border border-slate-700 rounded px-2 py-1.5 text-sm font-mono focus:ring-1 focus:ring-slate-500 outline-none"
                            />
                            <button
                              onClick={() => removeSpoofIp(index)}
                              disabled={spoofIps.length === 1}
                              className="p-1 text-slate-600 hover:text-red-400 disabled:opacity-20 transition-colors"
                            >
                              <X className="w-4 h-4"/>
                            </button>
                          </div>
                        );
                      })}
                      <p className="text-[10px] text-slate-500">Each URL will be tested against all spoof IPs in parallel.</p>
                    </div>

                    {/* URL list */}
                    <div className="flex items-center justify-between mb-2">
                      <label className="text-xs font-mono text-slate-400">URLs to Test</label>
                      <div className="flex items-center gap-3">
                        <button
                          onClick={handleExportUrlsAsCsv}
                          disabled={urlEntries.every(e => e.url.trim() === '')}
                          className="text-xs flex items-center gap-1 text-slate-400 hover:text-slate-200 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                          title="Export URLs as CSV for use in CSV mode"
                        >
                          <Download className="w-3 h-3" /> Export CSV
                        </button>
                        <button
                          onClick={() => { setShowBulkAdd(v => !v); setBulkText(''); }}
                          className="text-xs flex items-center gap-1 text-emerald-400 hover:text-emerald-300 transition-colors"
                        >
                          <ClipboardList className="w-3 h-3" /> Bulk Add
                        </button>
                        <button
                          onClick={addUrlEntry}
                          className="text-xs flex items-center gap-1 text-blue-400 hover:text-blue-300 transition-colors"
                        >
                          <Plus className="w-3 h-3" /> Add URL
                        </button>
                      </div>
                    </div>

                    {/* Bulk Add Panel */}
                    {showBulkAdd && (
                      <div className="mb-3 p-3 bg-slate-900 border border-emerald-500/30 rounded-lg space-y-2">
                        <div className="flex items-center justify-between">
                          <p className="text-xs text-emerald-300 font-medium">Paste URLs — one per line</p>
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => bulkFileInputRef.current?.click()}
                              className="text-xs flex items-center gap-1 text-blue-400 hover:text-blue-300 transition-colors"
                              title="Import URLs from a .txt or .csv file (one URL per line)"
                            >
                              <Upload className="w-3 h-3" /> Import from File
                            </button>
                            <input
                              ref={bulkFileInputRef}
                              type="file"
                              onChange={handleBulkFileImport}
                              accept=".txt,.csv"
                              className="hidden"
                            />
                            <button onClick={() => { setShowBulkAdd(false); setBulkText(''); }} className="text-slate-500 hover:text-slate-300">
                              <X className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </div>
                        <textarea
                          autoFocus
                          value={bulkText}
                          onChange={(e) => setBulkText(e.target.value)}
                          placeholder={`https://example.com/page1\nhttps://example.com/page2\nhttps://example.com/page3`}
                          className="w-full h-32 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-xs font-mono focus:ring-2 focus:ring-emerald-500 outline-none resize-none placeholder-slate-600"
                        />
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] text-slate-500">
                            {bulkText.split('\n').filter(l => l.trim()).length} URL{bulkText.split('\n').filter(l => l.trim()).length !== 1 ? 's' : ''} detected
                          </span>
                          <button
                            onClick={handleBulkAdd}
                            disabled={bulkText.trim().length === 0}
                            className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 disabled:cursor-not-allowed rounded text-xs font-semibold transition-colors"
                          >
                            Add to List
                          </button>
                        </div>
                      </div>
                    )}

                    <div className="overflow-y-auto max-h-64 space-y-2 pr-0.5">
                      {urlEntries.map((entry) => (
                        <div key={entry.id} className="flex gap-2 items-center">
                          <input
                            type="text"
                            value={entry.url}
                            onChange={(e) => updateUrlEntry(entry.id, e.target.value)}
                            placeholder={`https://example.com/path`}
                            className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono focus:ring-2 focus:ring-blue-500 outline-none"
                          />
                          <button
                            onClick={() => removeUrlEntry(entry.id)}
                            disabled={urlEntries.length === 1}
                            className="p-2 text-slate-600 hover:text-red-400 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                            title="Remove URL"
                          >
                            <X className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </>
                )}

                <div className="mt-4 p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg text-xs space-y-2">
                  <div className="flex items-start gap-2">
                    <ShieldAlert className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                    <span className="text-blue-200">
                      <strong>Smart Features Active:</strong>
                      <ul className="list-disc pl-4 mt-1 space-y-0.5 text-blue-300/80">
                        <li>Pass/Fail based on Live vs Spoof status code match</li>
                        <li>Fuzzy HTML Matching (Scripts removed)</li>
                        <li>F5 Bot Defense Detection</li>
                        <li>Complete Header Analysis (All headers shown, noise marked)</li>
                        <li>Akamai Debug Headers Injected</li>
                      </ul>
                    </span>
                  </div>
                </div>
              </div>
              
              <button
                onClick={runTest}
                disabled={isRunning}
                className="mt-4 w-full py-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg font-semibold flex items-center justify-center gap-2 transition-colors"
              >
                {isRunning ? 'Running Analysis...' : 'Start Sanity Check'}
                <Play className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="lg:col-span-2 flex flex-col space-y-4">
            {isRunning && (
              <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-slate-300">Analyzing Requests...</span>
                  <span className="text-blue-400 font-mono">{progress}%</span>
                </div>
                <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
                  <div className="h-full bg-blue-500 transition-all duration-300" style={{ width: `${progress}%` }} />
                </div>
              </div>
            )}

            <div className="bg-slate-800 rounded-xl border border-slate-700 flex-1 flex flex-col overflow-hidden min-h-[500px]">
              <div className="p-4 border-b border-slate-700 flex justify-between items-center bg-slate-800/50">
                <h3 className="font-semibold text-slate-200">Analysis Report</h3>
                <div className="flex items-center gap-3">
                  {groupedResults.length > 0 && (
                    <span className="text-xs text-slate-500">
                      {groupedResults.length} domain{groupedResults.length !== 1 ? 's' : ''} · {results.length} test{results.length !== 1 ? 's' : ''}
                    </span>
                  )}
                  <button 
                    onClick={handleExport}
                    disabled={results.length === 0}
                    className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm flex items-center gap-2 transition-colors"
                  >
                    <Download className="w-4 h-4" /> Export CSV
                  </button>
                </div>
              </div>

              <div className="overflow-y-auto flex-1">
                {results.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center text-slate-500 p-8">
                    <Activity className="w-12 h-12 mb-4 opacity-20" />
                    <p>Ready to analyze. Upload CSV or enter URLs to begin.</p>
                  </div>
                ) : (
                  <div className="divide-y divide-slate-700">
                    {groupedResults.map((group) => {
                      const isDomainCollapsed = collapsedDomains.has(group.domain);
                      return (
                        <div key={group.domain}>
                          {/* Domain Group Header */}
                          <div
                            onClick={() => toggleDomainCollapse(group.domain)}
                            className="flex items-center gap-3 px-4 py-3 bg-slate-900/80 border-b border-slate-700 cursor-pointer hover:bg-slate-900 transition-colors sticky top-0 z-10"
                          >
                            <div className="shrink-0">
                              {isDomainCollapsed ? (
                                <ChevronRight className="w-4 h-4 text-slate-500" />
                              ) : (
                                <ChevronDown className="w-4 h-4 text-slate-500" />
                              )}
                            </div>
                            <Globe className="w-4 h-4 text-blue-400 shrink-0" />
                            <span className="font-semibold text-slate-100 text-sm">{group.domain}</span>
                            <div className="flex items-center gap-2 ml-auto">
                              {group.passCount > 0 && (
                                <span className="flex items-center gap-1 text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 rounded-full px-2.5 py-0.5">
                                  <CheckCircle className="w-3 h-3" /> {group.passCount}
                                </span>
                              )}
                              {group.failCount > 0 && (
                                <span className="flex items-center gap-1 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-full px-2.5 py-0.5">
                                  <XCircle className="w-3 h-3" /> {group.failCount}
                                </span>
                              )}
                              <span className="text-xs text-slate-500">
                                {group.results.length} path{group.results.length !== 1 ? 's' : ''}
                              </span>
                            </div>
                          </div>

                          {/* Domain Group Results — sub-grouped by environment */}
                          {!isDomainCollapsed && (
                            <div>
                              {group.envGroups.length === 0 ? (
                                // No spoof IPs — flat list
                                <div className="divide-y divide-slate-700/50">
                                  {group.results.map((res) => {
                                    const isExpanded = expandedRow === res.row.id;
                                    const fullUrl = `https://${res.row.domain}${res.row.path}`;
                                    return renderPathRow(res, isExpanded, fullUrl, null);
                                  })}
                                </div>
                              ) : (
                                group.envGroups.map((envGroup) => {
                                  const envKey = `${group.domain}::${envGroup.envIdx}`;
                                  const isEnvCollapsed = collapsedEnvGroups.has(envKey);
                                  const c = getSpoofColor(envGroup.envIdx);

                                  return (
                                    <div key={envKey} className="border-b border-slate-700/60 last:border-b-0">
                                      {/* Environment sub-group header */}
                                      <div
                                        onClick={() => toggleEnvGroupCollapse(envKey)}
                                        className={`flex items-center gap-2.5 px-6 py-2.5 cursor-pointer transition-colors border-b ${c.border} bg-slate-900/40 hover:bg-slate-900/70`}
                                      >
                                        <div className="shrink-0">
                                          {isEnvCollapsed
                                            ? <ChevronRight className={`w-3.5 h-3.5 ${c.label}`} />
                                            : <ChevronDown className={`w-3.5 h-3.5 ${c.label}`} />}
                                        </div>
                                        <div className={`w-2 h-2 rounded-full shrink-0 ${c.dot}`} />
                                        <span className={`text-xs font-bold uppercase tracking-widest ${c.label}`}>
                                          {envGroup.label}
                                        </span>
                                        <span className="text-[10px] text-slate-500 ml-1">
                                          {envGroup.results.length} path{envGroup.results.length !== 1 ? 's' : ''}
                                        </span>
                                        <div className="flex items-center gap-1.5 ml-auto">
                                          {envGroup.passCount > 0 && (
                                            <span className="flex items-center gap-1 text-[10px] text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 rounded-full px-2 py-0.5">
                                              <CheckCircle className="w-2.5 h-2.5" /> {envGroup.passCount}
                                            </span>
                                          )}
                                          {envGroup.failCount > 0 && (
                                            <span className="flex items-center gap-1 text-[10px] text-red-400 bg-red-500/10 border border-red-500/20 rounded-full px-2 py-0.5">
                                              <XCircle className="w-2.5 h-2.5" /> {envGroup.failCount}
                                            </span>
                                          )}
                                        </div>
                                      </div>

                                      {/* Paths for this environment */}
                                      {!isEnvCollapsed && (
                                        <div className="divide-y divide-slate-700/40">
                                          {envGroup.results.map((res) => {
                                            const isExpanded = expandedRow === res.row.id;
                                            const fullUrl = `https://${res.row.domain}${res.row.path}`;
                                            return renderPathRow(res, isExpanded, fullUrl, envGroup.envIdx);
                                          })}
                                        </div>
                                      )}
                                    </div>
                                  );
                                })
                              )}
                            </div>
                          )}

                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}