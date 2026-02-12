import { useState, useRef } from 'react';
import { 
  ArrowLeft, Play, Download, Upload, 
  CheckCircle, XCircle, Activity, ChevronDown, ChevronRight,
  ShieldAlert, Layers, Code, Trash2
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { useToast } from '../context/ToastContext';

// --- Types ---

interface TestRow {
  id: string;
  domain: string;
  targetIp: string;
  path: string;
  expectedCode: string;
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

interface ComparisonResult {
  row: TestRow;
  public: RequestResult;
  spoofed: RequestResult;
  score: number; // 0-100 similarity score
  statusMatch: boolean;
  passed: boolean;
  reasons: string[];
  timestamp: string;
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
    .replace(/<script\b[^>]*>([\s\S]*?)<\/script>/gim, "") // Remove scripts
    .replace(/<!--[\s\S]*?-->/g, "") // Remove comments
    .replace(/<style\b[^>]*>([\s\S]*?)<\/style>/gim, "") // Remove styles
    .replace(/\s+/g, " ") // Collapse whitespace
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
      targetIp: cols[1] || '',
      path: cols[2] || '/',
      expectedCode: cols[3] || '200'
    };
  }).filter(r => r.domain && r.path);
};

const matchStatusCode = (actual: number | string, expected: string): boolean => {
  if (actual === 'ERR') return false;
  const actStr = actual.toString();
  if (expected.toLowerCase().includes('x')) {
    return actStr.charAt(0) === expected.charAt(0);
  }
  return actStr === expected;
};

// --- Components ---

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
            
            // Determine row styling
            let rowClass = 'border-b border-slate-800 hover:bg-slate-800/50';
            let headerClass = 'p-2 truncate';
            
            if (isSignificantDiff) {
              // Significant difference - highlight in amber
              rowClass += ' bg-amber-900/10';
              headerClass += ' text-amber-400 font-bold';
            } else if (isIgnored) {
              // Ignored header - dimmed
              headerClass += ' text-slate-600';
            } else {
              // Normal header
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

export function HttpSanityChecker() {
  const toast = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);
  
  const [csvText, setCsvText] = useState<string>('example.com, 1.2.3.4, /api/health, 200');
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<ComparisonResult[]>([]);
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const abortController = useRef<AbortController | null>(null);

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

      // Create a timeout promise
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error('Frontend timeout after 20 seconds')), 20000);
      });

      // We now call our local proxy endpoint instead of fetch() directly
      const fetchPromise = fetch('/api/proxy/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url,
          method: 'GET',
          headers,
          // Only send targetIp if we are spoofing
          targetIp: isSpoofed ? targetIp : undefined
        }),
        signal: abortController.current?.signal
      });

      // Race between fetch and timeout
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

  const runTest = async () => {
    const rows = parseCSV(csvText);
    if (rows.length === 0) {
      toast.error("No valid rows found");
      return;
    }

    setIsRunning(true);
    setResults([]);
    setProgress(0);
    abortController.current = new AbortController();

    const newResults: ComparisonResult[] = [];
    
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      const publicUrl = `https://${row.domain}${row.path}`;
      
      // Parallel Execution for Speed
      const [publicRes, spoofedRes] = await Promise.all([
        executeRequest(publicUrl, false, row.domain, ''), // Empty string for live DNS
        executeRequest(publicUrl, true, row.domain, row.targetIp) // Pass targetIp for spoofing
      ]);
      
      const similarity = calculateSimilarity(publicRes.normalizedBody, spoofedRes.normalizedBody);
      const statusMatch = publicRes.status === spoofedRes.status;
      const expectedMatch = matchStatusCode(spoofedRes.status, row.expectedCode);
      
      const reasons: string[] = [];
      if (!expectedMatch) reasons.push(`Status ${spoofedRes.status} != Expected ${row.expectedCode}`);
      if (!statusMatch) reasons.push(`Public/Spoof Status Drift (${publicRes.status} vs ${spoofedRes.status})`);
      if (similarity < 95) reasons.push(`Body Content Mismatch (${similarity}% similarity)`);
      if (spoofedRes.isBotChallenge) reasons.push(`⚠️ F5 Bot Challenge Detected`);
      if (spoofedRes.status === 'ERR') reasons.push(`Spoofed Connection Failed: ${spoofedRes.error}`);

      const passed = reasons.length === 0 || (reasons.length === 1 && spoofedRes.isBotChallenge);

      const result: ComparisonResult = {
        row,
        public: publicRes,
        spoofed: spoofedRes,
        score: similarity,
        statusMatch,
        passed,
        reasons,
        timestamp: new Date().toISOString()
      };

      newResults.push(result);
      setResults(prev => [...prev, result]);
      setProgress(Math.round(((i + 1) / rows.length) * 100));
    }

    setIsRunning(false);
    toast.success("Validation Complete");
  };

  const handleExport = () => {
    if (results.length === 0) return;
    const header = [
      "Domain", "Path", "Target IP", "Expected", "Result", 
      "Public Status", "Spoofed Status", "Similarity %", 
      "Akamai X-Cache", "Bot Challenge", "Drift Reasons"
    ];
    const csvRows = results.map(r => [
      r.row.domain, r.row.path, r.row.targetIp, r.row.expectedCode,
      r.passed ? "PASS" : "FAIL",
      r.public.status, r.spoofed.status, r.score,
      r.public.debugInfo || '',
      r.spoofed.isBotChallenge ? "YES" : "NO",
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

  const handleUploadClick = () => {
    fileInputRef.current?.click();
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
              <div className="flex-1">
                <div className="flex justify-between items-center mb-2">
                  <label className="block text-xs font-mono text-slate-400">
                    CSV Input: Domain, Target IP, Path, Expected Code
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
                  placeholder="example.com, 1.2.3.4, /api/status, 200"
                />
                
                <div className="mt-4 p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg text-xs space-y-2">
                  <div className="flex items-start gap-2">
                    <ShieldAlert className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                    <span className="text-blue-200">
                      <strong>Smart Features Active:</strong>
                      <ul className="list-disc pl-4 mt-1 space-y-0.5 text-blue-300/80">
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
                <button 
                  onClick={handleExport}
                  disabled={results.length === 0}
                  className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm flex items-center gap-2 transition-colors"
                >
                  <Download className="w-4 h-4" /> Export CSV
                </button>
              </div>

              <div className="overflow-y-auto flex-1">
                {results.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center text-slate-500 p-8">
                    <Activity className="w-12 h-12 mb-4 opacity-20" />
                    <p>Ready to analyze. Upload CSV or enter data to begin.</p>
                  </div>
                ) : (
                  <div className="divide-y divide-slate-700">
                    {results.map((res) => {
                      const isExpanded = expandedRow === res.row.id;
                      return (
                        <div key={res.row.id} className="bg-slate-800">
                          <div 
                            onClick={() => toggleRow(res.row.id)}
                            className="flex items-center p-3 hover:bg-slate-700/50 cursor-pointer transition-colors"
                          >
                            <div className="pr-4">
                              {isExpanded ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                            </div>
                            <div className="w-8">
                              {res.passed ? (
                                <CheckCircle className="w-5 h-5 text-emerald-500" />
                              ) : (
                                <XCircle className="w-5 h-5 text-red-500" />
                              )}
                            </div>
                            <div className="flex-1 min-w-0 grid grid-cols-12 gap-4 items-center">
                              <div className="col-span-4">
                                <div className="font-medium text-slate-200 truncate" title={res.row.domain}>{res.row.domain}</div>
                                <div className="text-xs text-slate-500 truncate" title={res.row.path}>{res.row.path}</div>
                              </div>
                              <div className="col-span-2">
                                <div className="text-xs text-slate-500 uppercase">Target</div>
                                <div className="text-sm font-mono text-slate-300 truncate">{res.row.targetIp}</div>
                              </div>
                              <div className="col-span-2">
                                <div className="text-xs text-slate-500 uppercase">Status</div>
                                <div className="flex items-center gap-1 text-sm font-mono">
                                  <span className={res.public.status === 'ERR' ? 'text-red-400' : 'text-slate-300'}>{res.public.status}</span>
                                  <span className="text-slate-600">→</span>
                                  <span className={!res.statusMatch ? 'text-amber-400 font-bold' : 'text-slate-300'}>{res.spoofed.status}</span>
                                </div>
                              </div>
                              <div className="col-span-2">
                                <div className="text-xs text-slate-500 uppercase">Similarity</div>
                                <div className={`text-sm font-bold ${res.score >= 95 ? 'text-emerald-400' : 'text-red-400'}`}>
                                  {res.score}%
                                </div>
                              </div>
                            </div>
                          </div>

                          {isExpanded && (
                            <div className="border-t border-slate-700 bg-slate-900/30 p-4 space-y-4">
                              {res.reasons.length > 0 && (
                                <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded text-xs text-amber-200">
                                  <strong className="block mb-1">Comparison Drift Detected:</strong>
                                  <ul className="list-disc pl-4 space-y-0.5">
                                    {res.reasons.map((r, i) => <li key={i}>{r}</li>)}
                                  </ul>
                                </div>
                              )}

                              <div className="space-y-4">
                                <div>
                                  <div className="flex items-center justify-between mb-2">
                                    <h4 className="text-xs font-bold text-slate-400 uppercase flex items-center gap-2">
                                      <Layers className="w-3 h-3" /> Complete Header Comparison
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
                                  <HeaderDiff 
                                    pubHeaders={res.public.headers} 
                                    spoofHeaders={res.spoofed.headers}
                                    publicIp={res.public.connectedIp}
                                    spoofedIp={res.spoofed.connectedIp}
                                  />
                                </div>

                                <div>
                                  <h4 className="text-xs font-bold text-slate-400 uppercase mb-2 flex items-center gap-2">
                                    <Code className="w-3 h-3" /> Body Analysis
                                  </h4>
                                  <div className="grid grid-cols-2 gap-4 text-xs mb-2">
                                    <div className="p-2 bg-slate-800 rounded">
                                      <div className="text-slate-500">Public Response</div>
                                      <div className="text-slate-200 font-mono">{res.public.size} bytes</div>
                                      {res.public.connectedIp && (
                                        <div className="mt-1 text-blue-400 font-mono text-[10px]">
                                          IP: {res.public.connectedIp}
                                        </div>
                                      )}
                                      {res.public.debugInfo && (
                                        <div className="mt-1 text-purple-400 font-mono text-[10px]">{res.public.debugInfo}</div>
                                      )}
                                    </div>
                                    <div className="p-2 bg-slate-800 rounded">
                                      <div className="text-slate-500">Spoofed Response</div>
                                      <div className="text-slate-200 font-mono">{res.spoofed.size} bytes</div>
                                      {res.spoofed.connectedIp && (
                                        <div className="mt-1 text-emerald-400 font-mono text-[10px]">
                                          IP: {res.spoofed.connectedIp}
                                        </div>
                                      )}
                                      {res.spoofed.isBotChallenge && (
                                        <div className="mt-1 text-amber-400 font-bold flex items-center gap-1">
                                          <ShieldAlert className="w-3 h-3" /> F5 Challenge Page
                                        </div>
                                      )}
                                    </div>
                                  </div>
                                  <div className="text-xs font-bold text-slate-500 mb-1">Normalized Body Preview (First 500 chars)</div>
                                  <DiffView 
                                    left={res.public.normalizedBody.slice(0, 500)} 
                                    right={res.spoofed.normalizedBody.slice(0, 500)} 
                                    title="Normalized Content" 
                                  />
                                </div>
                              </div>
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