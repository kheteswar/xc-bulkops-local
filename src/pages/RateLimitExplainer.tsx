import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowLeft, Shield, Gauge, Droplets, Check, X, Maximize2, Minimize2, Clock,
  TrendingUp, Users, Zap, ChevronRight, ChevronLeft,
} from 'lucide-react';

// ═══════════════════════════════════════════════════════════════════
// TOKEN BUCKET ANIMATION
// ═══════════════════════════════════════════════════════════════════

function TokenBucketDemo() {
  const [tokens, setTokens] = useState(80);
  const [blocked, setBlocked] = useState(0);
  const [allowed, setAllowed] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  const [mode, setMode] = useState<'idle' | 'normal' | 'burst' | 'attack'>('idle');
  const [incomingDots, setIncomingDots] = useState<Array<{ id: number; blocked: boolean }>>([]);
  const dotIdRef = useRef(0);
  const intervalRef = useRef<ReturnType<typeof setInterval>>();

  const N = 40, B = 2, capacity = N * B;
  const incoming = mode === 'normal' ? 20 : mode === 'burst' ? 70 : mode === 'attack' ? 55 : 0;
  const modeColor = mode === 'normal' ? 'emerald' : mode === 'burst' ? 'amber' : mode === 'attack' ? 'red' : 'slate';
  const modeLabel = mode === 'normal' ? 'Normal User' : mode === 'burst' ? 'Page Load Burst' : mode === 'attack' ? 'Sustained Attacker' : '';

  useEffect(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    if (mode === 'idle') { setTokens(capacity); setBlocked(0); setAllowed(0); setElapsed(0); setIncomingDots([]); return; }
    setBlocked(0); setAllowed(0); setElapsed(0); setIncomingDots([]);

    intervalRef.current = setInterval(() => {
      setElapsed(e => e + 1);
      setTokens(prev => {
        const refilled = Math.min(prev + N / 10, capacity);
        const consumed = incoming / 10;
        const isBlocked = refilled < consumed;

        // Spawn visual dot
        const id = ++dotIdRef.current;
        setIncomingDots(dots => [...dots.slice(-12), { id, blocked: isBlocked }]);

        if (isBlocked) {
          setBlocked(b => b + Math.round(consumed - refilled));
          return Math.max(refilled - consumed, 0);
        }
        setAllowed(a => a + Math.round(consumed));
        return Math.min(refilled - consumed, capacity);
      });
    }, 100);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [mode, capacity, incoming]);

  const fillPct = Math.round((tokens / capacity) * 100);
  const fillColor = fillPct > 50 ? 'bg-emerald-500' : fillPct > 20 ? 'bg-amber-500' : 'bg-red-500';
  const bucketEmpty = tokens <= 2;
  const elapsedSec = (elapsed / 10).toFixed(1);
  const netPerTick = incoming / 10 - N / 10;
  const timeToEmpty = netPerTick > 0 ? Math.ceil(tokens / netPerTick / 10) : Infinity;

  return (
    <div>
      {/* Scenario buttons */}
      <div className="grid grid-cols-3 gap-3 mb-6">
        {([
          ['normal', 'Normal User', '20 req/min', 'emerald', 'User browsing normally'],
          ['burst', 'Page Load Burst', '70 req/min', 'amber', 'SPA loading many resources'],
          ['attack', 'Sustained Attacker', '55 req/min', 'red', 'Scraper hammering your API'],
        ] as const).map(([id, label, rate, color, desc]) => (
          <button key={id} onClick={() => setMode(mode === id ? 'idle' : id)}
            className={`text-left p-4 rounded-xl border-2 transition-all ${
              mode === id
                ? `border-${color}-500 bg-${color}-500/15`
                : 'border-slate-700 bg-slate-800/50 hover:border-slate-600'
            }`}>
            <div className={`text-sm font-bold ${mode === id ? `text-${color}-400` : 'text-slate-200'}`}>{label}</div>
            <div className={`text-lg font-mono font-bold mt-1 ${mode === id ? `text-${color}-400` : 'text-slate-400'}`}>{rate}</div>
            <div className="text-xs text-slate-500 mt-1">{desc}</div>
          </button>
        ))}
      </div>

      {mode !== 'idle' ? (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
          {/* Header with timer */}
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className={`w-3 h-3 rounded-full bg-${modeColor}-500 animate-pulse`} />
              <span className={`text-sm font-semibold text-${modeColor}-400`}>{modeLabel}</span>
              <span className="text-slate-500">·</span>
              <span className="text-sm text-slate-400 font-mono">{incoming} req/min incoming</span>
            </div>
            <div className="flex items-center gap-2 bg-slate-900/50 rounded-lg px-3 py-1.5">
              <Clock className="w-3.5 h-3.5 text-slate-500" />
              <span className="text-sm font-mono text-slate-300">{elapsedSec}s</span>
            </div>
          </div>

          {/* Main visualization: Incoming → Bucket → Output */}
          <div className="flex items-center gap-4 mb-6">
            {/* Incoming traffic stream */}
            <div className="flex-1">
              <div className="text-xs text-slate-500 mb-2 text-center">Incoming Requests</div>
              <div className="h-16 bg-slate-900/50 rounded-lg flex items-center justify-end px-2 gap-1 overflow-hidden">
                {incomingDots.map(dot => (
                  <div key={dot.id}
                    className={`w-3 h-3 rounded-full flex-shrink-0 transition-all duration-300 ${
                      dot.blocked ? 'bg-red-500 opacity-60' : `bg-${modeColor}-500`
                    }`}
                    style={{ animation: 'slideIn 0.3s ease-out' }} />
                ))}
                <div className={`text-lg font-bold text-${modeColor}-400 ml-2`}>→</div>
              </div>
            </div>

            {/* Token Bucket */}
            <div className="flex flex-col items-center flex-shrink-0">
              <div className="text-xs text-emerald-400 font-semibold mb-1 animate-pulse">+{N}/min refill</div>
              <div className={`relative w-24 h-32 border-2 rounded-b-xl overflow-hidden bg-slate-900 ${
                bucketEmpty ? 'border-red-500' : 'border-slate-500'
              }`}>
                <div className={`absolute bottom-0 left-0 right-0 transition-all duration-200 ${fillColor}`}
                  style={{ height: `${fillPct}%` }} />
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-2xl font-bold text-white drop-shadow-lg">{Math.round(tokens)}</span>
                  <span className="text-[9px] text-slate-400">/ {capacity}</span>
                </div>
              </div>
              <div className="text-xs text-slate-500 mt-1">Token Bucket</div>
            </div>

            {/* Output: Allowed vs Blocked */}
            <div className="flex-1">
              <div className="text-xs text-slate-500 mb-2 text-center">Output</div>
              <div className="h-16 grid grid-rows-2 gap-1">
                <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg flex items-center px-3">
                  <Check className="w-3.5 h-3.5 text-emerald-400 mr-2" />
                  <span className="text-xs text-emerald-400 font-medium">Allowed</span>
                  <span className="text-sm font-bold text-emerald-400 ml-auto font-mono">{allowed}</span>
                </div>
                <div className={`border rounded-lg flex items-center px-3 ${
                  blocked > 0 ? 'bg-red-500/10 border-red-500/20' : 'bg-slate-900/30 border-slate-700'
                }`}>
                  <X className={`w-3.5 h-3.5 mr-2 ${blocked > 0 ? 'text-red-400' : 'text-slate-600'}`} />
                  <span className={`text-xs font-medium ${blocked > 0 ? 'text-red-400' : 'text-slate-600'}`}>Blocked</span>
                  <span className={`text-sm font-bold ml-auto font-mono ${blocked > 0 ? 'text-red-400' : 'text-slate-600'}`}>{blocked}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Live stats bar */}
          <div className="grid grid-cols-4 gap-3">
            <div className="bg-slate-900/50 rounded-lg p-3 text-center">
              <div className="text-[10px] text-slate-500 uppercase">Bucket Level</div>
              <div className={`text-lg font-bold font-mono ${fillPct > 50 ? 'text-emerald-400' : fillPct > 20 ? 'text-amber-400' : 'text-red-400'}`}>{fillPct}%</div>
            </div>
            <div className="bg-slate-900/50 rounded-lg p-3 text-center">
              <div className="text-[10px] text-slate-500 uppercase">Net Drain</div>
              <div className={`text-lg font-bold font-mono ${incoming > N ? 'text-red-400' : 'text-emerald-400'}`}>
                {incoming > N ? `-${incoming - N}` : `+${N - incoming}`}/min
              </div>
            </div>
            <div className="bg-slate-900/50 rounded-lg p-3 text-center">
              <div className="text-[10px] text-slate-500 uppercase">Time to Empty</div>
              <div className={`text-lg font-bold font-mono ${timeToEmpty < 10 ? 'text-red-400' : timeToEmpty === Infinity ? 'text-emerald-400' : 'text-amber-400'}`}>
                {timeToEmpty === Infinity ? '∞' : `~${timeToEmpty}s`}
              </div>
            </div>
            <div className="bg-slate-900/50 rounded-lg p-3 text-center">
              <div className="text-[10px] text-slate-500 uppercase">Status</div>
              <div className={`text-lg font-bold ${bucketEmpty ? 'text-red-400 animate-pulse' : 'text-emerald-400'}`}>
                {bucketEmpty ? '🚫 BLOCKED' : '✓ PASSING'}
              </div>
            </div>
          </div>

          {/* Explanation for current scenario */}
          <div className={`mt-4 p-3 bg-${modeColor}-500/5 border border-${modeColor}-500/20 rounded-lg text-sm`}>
            {mode === 'normal' && (
              <p className="text-emerald-300">
                <strong>Normal user at 20 req/min:</strong> Refill is {N}/min, consumption is only 20/min.
                Bucket gains {N - 20} tokens/min — it stays full. This user is <strong>never blocked</strong>.
              </p>
            )}
            {mode === 'burst' && (
              <p className="text-amber-300">
                <strong>Page load burst at 70 req/min:</strong> Consuming {70 - N} more tokens/min than the {N}/min refill.
                The bucket ({capacity} tokens) can absorb ~{Math.round(capacity / ((70 - N) / 60))}s of this burst before emptying.
                {bucketEmpty ? ' Bucket is now empty — requests are being blocked!' : ' Watch the bucket drain...'}
              </p>
            )}
            {mode === 'attack' && (
              <p className="text-red-300">
                <strong>Attacker at 55 req/min:</strong> Draining {55 - N} tokens/min net. Bucket will empty in ~{Math.round(capacity / ((55 - N) / 60))}s.
                {bucketEmpty ? ' BLOCKED — the attacker has been caught by the rate limiter!' : ` ${Math.round(tokens)} tokens remaining, blocking starts soon...`}
              </p>
            )}
          </div>

          {/* Stop button */}
          <button onClick={() => setMode('idle')}
            className="mt-3 text-xs text-slate-500 hover:text-slate-300 transition-colors">
            ■ Stop & Reset
          </button>
        </div>
      ) : (
        <div className="bg-slate-800/30 border border-dashed border-slate-700 rounded-xl p-8 text-center">
          <Droplets className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <p className="text-slate-400 mb-1">Click a scenario above to start the simulation</p>
          <p className="text-xs text-slate-600">Watch how the token bucket handles different traffic patterns in real time</p>
        </div>
      )}

      <style>{`
        @keyframes slideIn {
          from { transform: translateX(20px); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
      `}</style>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// SLIDES
// ═══════════════════════════════════════════════════════════════════

function Slide1() {
  return (
    <div>
      <div className="flex items-center gap-4 mb-6">
        <div className="w-14 h-14 bg-blue-500/15 rounded-2xl flex items-center justify-center flex-shrink-0">
          <Gauge className="w-7 h-7 text-blue-400" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-slate-100">Rate Limit Advisor</h1>
          <p className="text-base text-slate-400">Data-driven rate limit recommendations for F5 XC HTTP Load Balancers</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-5">
          <div className="text-xs text-blue-400 font-semibold uppercase tracking-wider mb-2">What is it?</div>
          <p className="text-sm text-slate-300 leading-relaxed">Analyses real traffic on your HTTP Load Balancers and recommends the optimal Number (N) and Burst Multiplier (B) settings for F5 XC's per-user rate limiter.</p>
        </div>
        <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-5">
          <div className="text-xs text-red-400 font-semibold uppercase tracking-wider mb-2">What problem does it solve?</div>
          <p className="text-sm text-slate-300 leading-relaxed">Setting rate limits by guesswork leads to either blocking legitimate users (too low) or failing to catch attackers (too high). This tool sizes limits from actual per-user traffic data.</p>
        </div>
        <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-5">
          <div className="text-xs text-emerald-400 font-semibold uppercase tracking-wider mb-2">Who should use it?</div>
          <p className="text-sm text-slate-300 leading-relaxed">Security engineers configuring rate limits, operations teams protecting applications, and anyone deploying F5 XC rate limiting for the first time.</p>
        </div>
        <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-5">
          <div className="text-xs text-amber-400 font-semibold uppercase tracking-wider mb-2">When to use it?</div>
          <p className="text-sm text-slate-300 leading-relaxed">Before enabling rate limits on a new LB, after significant traffic changes, and monthly to verify your limits still match your traffic patterns.</p>
        </div>
      </div>
    </div>
  );
}

function Slide2() {
  return (
    <div>
      <SlideTitle icon={Droplets} title="The Token Bucket" subtitle="How rate limiting actually works under the hood" />
      <div className="mt-6 grid grid-cols-3 gap-4 mb-8">
        {[
          { label: 'N (Number)', value: 'Refill rate', desc: 'Tokens added per minute — the sustained ceiling', color: 'text-blue-400 border-blue-500/30' },
          { label: 'B (Burst)', value: 'Bucket size multiplier', desc: 'Capacity = N × B — how much burst is allowed', color: 'text-amber-400 border-amber-500/30' },
          { label: 'N × B', value: 'Effective limit', desc: 'Maximum requests in a burst before blocking', color: 'text-emerald-400 border-emerald-500/30' },
        ].map(c => (
          <div key={c.label} className={`bg-slate-800/50 border rounded-xl p-5 text-center ${c.color}`}>
            <div className={`text-2xl font-bold mb-1`}>{c.label}</div>
            <div className="text-sm text-slate-200 font-medium">{c.value}</div>
            <div className="text-xs text-slate-400 mt-2">{c.desc}</div>
          </div>
        ))}
      </div>
      <TokenBucketDemo />
    </div>
  );
}

function Slide3() {
  return (
    <div>
      <SlideTitle icon={Zap} title="Why Burst Multiplier Matters" subtitle="Same capacity, completely different security" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
        <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4"><Check className="w-6 h-6 text-emerald-400" /><h3 className="text-xl font-bold text-emerald-400">Good Config</h3></div>
          <div className="text-4xl font-bold text-slate-100 mb-3">40/min × 2 burst</div>
          <div className="text-sm text-slate-300 mb-4">Bucket: 80 tokens, refills at 40/min</div>
          <div className="space-y-3 text-sm">
            <div className="flex items-center gap-2 text-emerald-300"><Check className="w-4 h-4" /> Normal user (20/min): never blocked</div>
            <div className="flex items-center gap-2 text-emerald-300"><Check className="w-4 h-4" /> Page burst (70/min): bucket absorbs it</div>
            <div className="flex items-center gap-2 text-red-300"><X className="w-4 h-4" /> Attacker (55/min): <strong>blocked in ~5 min</strong></div>
          </div>
          <div className="mt-4 p-3 bg-emerald-500/10 rounded-lg text-xs text-emerald-300">
            Attacker drains 15 tokens/min (55 − 40 refill). Bucket (80) empty in ~5 min. <strong>Caught.</strong>
          </div>
        </div>
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4"><X className="w-6 h-6 text-red-400" /><h3 className="text-xl font-bold text-red-400">Bad Config</h3></div>
          <div className="text-4xl font-bold text-slate-100 mb-3">80/min × 1 burst</div>
          <div className="text-sm text-slate-300 mb-4">Bucket: 80 tokens, refills at 80/min</div>
          <div className="space-y-3 text-sm">
            <div className="flex items-center gap-2 text-emerald-300"><Check className="w-4 h-4" /> Normal user (20/min): never blocked</div>
            <div className="flex items-center gap-2 text-emerald-300"><Check className="w-4 h-4" /> Page burst (70/min): fine</div>
            <div className="flex items-center gap-2 text-red-400 font-bold"><Check className="w-4 h-4" /> Attacker (55/min): NEVER blocked!</div>
          </div>
          <div className="mt-4 p-3 bg-red-500/10 rounded-lg text-xs text-red-300">
            Refill (80) exceeds consumption (55). Bucket never drains. Same capacity, <strong>zero protection</strong>.
          </div>
        </div>
      </div>
      <div className="mt-6 p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg text-sm text-blue-300 text-center">
        <strong>Rule:</strong> Always use burst ≥ 2 for web apps. B=1 is only for strict API endpoints with predictable traffic.
      </div>
    </div>
  );
}

function Slide4() {
  const steps = [
    { icon: TrendingUp, title: 'Phase 1: Weekly Baseline', desc: '7-day daily probes → traffic shape, trend, seasonality', color: 'bg-blue-500', detail: '~14 API calls' },
    { icon: Zap, title: 'Phase 2: Deep Scan', desc: 'ALL raw logs for your selected window (1h–24h)', color: 'bg-emerald-500', detail: 'Variable calls' },
    { icon: Shield, title: 'Cleaning Filter', desc: 'Remove WAF blocks, malicious bots, policy denials, MUM, high-risk IPs', color: 'bg-red-500', detail: 'Client-side' },
    { icon: Users, title: 'Per-User Analysis', desc: 'Peak RPM and median RPM for every clean user', color: 'bg-violet-500', detail: 'Local' },
    { icon: Gauge, title: 'P95 + Safety Margin', desc: 'N = P95 of per-user peaks × 1.5 (industry standard)', color: 'bg-amber-500', detail: 'Local' },
    { icon: Droplets, title: 'Burst Sizing', desc: 'B = ceil(P99.9 / P95), min 2, max 5', color: 'bg-cyan-500', detail: 'Local' },
  ];

  return (
    <div>
      <SlideTitle icon={Gauge} title="How the Advisor Works" subtitle="Two-phase analysis pipeline" />
      <div className="space-y-4 mt-8">
        {steps.map((step, i) => (
          <div key={i} className="flex items-start gap-4 group">
            <div className="flex flex-col items-center">
              <div className={`w-12 h-12 rounded-full ${step.color} flex items-center justify-center text-white shadow-lg`}>
                <step.icon className="w-6 h-6" />
              </div>
              {i < steps.length - 1 && <div className="w-0.5 h-6 bg-slate-700" />}
            </div>
            <div className="flex-1 bg-slate-800/50 border border-slate-700 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <h4 className="font-semibold text-slate-100">{step.title}</h4>
                <span className="text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded">{step.detail}</span>
              </div>
              <p className="text-sm text-slate-400 mt-1">{step.desc}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function Slide5() {
  return (
    <div>
      <SlideTitle icon={Gauge} title="The Recommendation Formula" subtitle="Based on OWASP, AWS, Google Cloud, and Cloudflare guidance" />
      <div className="mt-8 space-y-6">
        <div className="bg-slate-800/50 border border-blue-500/30 rounded-xl p-6">
          <div className="flex items-start gap-4">
            <div className="w-14 h-14 rounded-xl bg-amber-500/20 flex items-center justify-center text-amber-400 font-bold text-2xl flex-shrink-0">N</div>
            <div>
              <div className="text-lg font-semibold text-slate-100">N = ceil( P95 of per-user peak RPMs × 1.5 )</div>
              <div className="text-sm text-slate-400 mt-2 leading-relaxed">
                <strong className="text-slate-200">P95</strong> is the industry standard baseline. 95% of legitimate users never exceed this, even in their busiest minute. The <strong className="text-slate-200">1.5× safety margin</strong> (50% buffer) absorbs natural variation and organic growth without needing constant retuning.
              </div>
            </div>
          </div>
        </div>
        <div className="bg-slate-800/50 border border-cyan-500/30 rounded-xl p-6">
          <div className="flex items-start gap-4">
            <div className="w-14 h-14 rounded-xl bg-cyan-500/20 flex items-center justify-center text-cyan-400 font-bold text-2xl flex-shrink-0">B</div>
            <div>
              <div className="text-lg font-semibold text-slate-100">B = ceil( P99.9 / P95 ), minimum 2, maximum 5</div>
              <div className="text-sm text-slate-400 mt-2 leading-relaxed">
                Sized by how spiky top users are. If the rare power-user peak (P99.9) is 3× the baseline (P95), then B=3 gives them burst headroom without permanently raising the sustained rate. <strong className="text-slate-200">B=2 is the default</strong> for web applications.
              </div>
            </div>
          </div>
        </div>
        <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-5 text-center">
          <div className="text-sm text-emerald-300 mb-2">Example with real data</div>
          <div className="text-slate-300">P95 peak = 120 req/min → N = ceil(120 × 1.5) = <span className="text-2xl font-bold text-white">180</span> req/min</div>
          <div className="text-slate-300 mt-1">P99.9 = 350, ratio = 350/120 = 2.9 → B = <span className="text-2xl font-bold text-white">3</span>×</div>
          <div className="text-slate-300 mt-1">Effective limit = 180 × 3 = <span className="text-2xl font-bold text-emerald-400">540</span> req/min burst capacity</div>
        </div>
      </div>
    </div>
  );
}

function SlideExample() {
  return (
    <div>
      <SlideTitle icon={Gauge} title="Example Output" subtitle="What the advisor actually produces — and what each number means" />
      <div className="mt-6">
        {/* Mock recommendation card */}
        <div className="bg-gradient-to-b from-blue-500/10 to-slate-800/50 border border-blue-500/40 rounded-xl p-6 mb-6">
          <div className="text-xs text-slate-400 mb-3 uppercase tracking-wider">LB-Wide Recommendation</div>
          <div className="grid grid-cols-3 gap-6 mb-6">
            <div className="text-center">
              <div className="text-5xl font-bold text-slate-100">180</div>
              <div className="text-sm text-slate-400 mt-1">req/min</div>
              <div className="text-xs text-blue-400 mt-2 font-medium">Number (N)</div>
            </div>
            <div className="text-center">
              <div className="text-5xl font-bold text-slate-100">2<span className="text-2xl">×</span></div>
              <div className="text-sm text-slate-400 mt-1">burst</div>
              <div className="text-xs text-amber-400 mt-2 font-medium">Burst Multiplier (B)</div>
            </div>
            <div className="text-center">
              <div className="text-5xl font-bold text-emerald-400">360</div>
              <div className="text-sm text-slate-400 mt-1">req/min peak</div>
              <div className="text-xs text-emerald-400 mt-2 font-medium">Effective Limit (N × B)</div>
            </div>
          </div>

          {/* Definitions */}
          <div className="space-y-4">
            <div className="flex items-start gap-4 bg-slate-800/60 rounded-lg p-4">
              <div className="w-12 h-12 rounded-xl bg-blue-500/20 flex items-center justify-center flex-shrink-0">
                <span className="text-blue-400 font-bold text-lg">N</span>
              </div>
              <div>
                <div className="font-semibold text-slate-100">Number = 180 req/min</div>
                <div className="text-sm text-slate-400 mt-1">
                  The <strong className="text-slate-200">sustained rate limit</strong> per user per minute.
                  This is the token bucket refill rate — how many tokens each user gets back every minute.
                  A user sending ≤180 req/min will never be blocked.
                  An attacker sustaining 200+ req/min will eventually drain their bucket and get blocked.
                </div>
                <div className="text-xs text-blue-400 mt-2">
                  Derived from: P95 of per-user peak RPMs (120) × 1.5 safety margin = 180
                </div>
              </div>
            </div>

            <div className="flex items-start gap-4 bg-slate-800/60 rounded-lg p-4">
              <div className="w-12 h-12 rounded-xl bg-amber-500/20 flex items-center justify-center flex-shrink-0">
                <span className="text-amber-400 font-bold text-lg">B</span>
              </div>
              <div>
                <div className="font-semibold text-slate-100">Burst Multiplier = 2×</div>
                <div className="text-sm text-slate-400 mt-1">
                  The <strong className="text-slate-200">token bucket capacity multiplier</strong>.
                  The bucket can hold N × B = 360 tokens at once.
                  This lets a legitimate user briefly spike to 360 req/min — for example, a single page load
                  that fires 50 API calls simultaneously. The bucket absorbs the burst, then refills at 180/min.
                </div>
                <div className="text-xs text-amber-400 mt-2">
                  Derived from: ceil(P99.9 peak / P95 peak) = ceil(220 / 120) = 2
                </div>
              </div>
            </div>

            <div className="flex items-start gap-4 bg-slate-800/60 rounded-lg p-4">
              <div className="w-12 h-12 rounded-xl bg-emerald-500/20 flex items-center justify-center flex-shrink-0">
                <span className="text-emerald-400 font-bold text-sm">N×B</span>
              </div>
              <div>
                <div className="font-semibold text-slate-100">Effective Limit = 360 req/min</div>
                <div className="text-sm text-slate-400 mt-1">
                  The <strong className="text-slate-200">maximum burst capacity</strong>.
                  A user can send up to 360 requests in a single burst if their bucket is full.
                  But they cannot sustain more than 180/min — the bucket drains faster than it refills
                  at any rate above N, and eventually hits zero.
                </div>
                <div className="text-xs text-emerald-400 mt-2">
                  In F5 XC: Number=180, Per Period=Minutes, Periods=1, Burst Multiplier=2
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* What happens at different rates */}
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
          <h4 className="font-semibold text-slate-200 mb-3">What happens at different request rates with N=180, B=2</h4>
          <div className="space-y-2">
            {[
              { rate: '100 req/min', result: 'Never blocked', reason: 'Well under N — bucket stays full', color: 'text-emerald-400', icon: Check },
              { rate: '180 req/min', result: 'Never blocked', reason: 'Exactly at N — bucket stays stable (refill = consumption)', color: 'text-emerald-400', icon: Check },
              { rate: '250 req/min', result: 'Blocked after ~5 min', reason: 'Drains 70 tokens/min (250-180). Bucket (360) empty in ~5 min', color: 'text-amber-400', icon: Gauge },
              { rate: '360 req/min burst', result: 'First minute OK, then blocked', reason: 'Empties 360-token bucket in ~1 min. Blocked until refill accumulates', color: 'text-amber-400', icon: Gauge },
              { rate: '500 req/min', result: 'Blocked after ~1 min', reason: 'Drains 320 tokens/min. Bucket empty in ~1.1 min', color: 'text-red-400', icon: X },
            ].map((row, i) => (
              <div key={i} className="flex items-center gap-3 bg-slate-900/50 rounded-lg p-3">
                <row.icon className={`w-4 h-4 ${row.color} flex-shrink-0`} />
                <div className="w-28 flex-shrink-0 font-mono text-sm text-slate-200">{row.rate}</div>
                <div className={`w-40 flex-shrink-0 text-sm font-medium ${row.color}`}>{row.result}</div>
                <div className="text-xs text-slate-500">{row.reason}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function Slide6() {
  const excluded = [
    { signal: 'waf_action = block', why: 'WAF engine blocked the request' },
    { signal: 'bot_defense.insight = MALICIOUS', why: 'Shape ML classified as malicious bot' },
    { signal: 'policy_hits.result = deny / default_deny', why: 'Service policy denial' },
    { signal: 'malicious_user_mitigate_action ≠ MUM_NONE', why: 'Behaviour analysis challenged or blocked' },
    { signal: 'ip_risk = HIGH_RISK', why: 'IP on active threat feeds' },
  ];
  const kept = [
    'Auth failures (401, 403) — legitimate users make mistakes',
    'Rate limit rejects (429) — needed to see current impact',
    'MEDIUM_RISK IPs — not confirmed malicious',
    'Suspicious bots — may be legitimate automation',
  ];

  return (
    <div>
      <SlideTitle icon={Shield} title="Cleaning Filter" subtitle="What traffic is excluded from analysis" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
        <div className="bg-red-500/5 border border-red-500/30 rounded-xl p-6">
          <h3 className="font-semibold text-red-400 mb-4 flex items-center gap-2 text-lg"><X className="w-5 h-5" /> Excluded</h3>
          <div className="space-y-3">
            {excluded.map((f, i) => (
              <div key={i} className="flex items-start gap-3">
                <X className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                <div><code className="text-red-300 text-xs bg-red-500/10 px-1.5 py-0.5 rounded">{f.signal}</code>
                  <div className="text-xs text-slate-400 mt-0.5">{f.why}</div></div>
              </div>
            ))}
          </div>
        </div>
        <div className="bg-emerald-500/5 border border-emerald-500/30 rounded-xl p-6">
          <h3 className="font-semibold text-emerald-400 mb-4 flex items-center gap-2 text-lg"><Check className="w-5 h-5" /> Kept</h3>
          <div className="space-y-3">
            {kept.map((k, i) => (
              <div key={i} className="flex items-center gap-3">
                <Check className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                <span className="text-sm text-slate-300">{k}</span>
              </div>
            ))}
          </div>
          <div className="mt-4 p-3 bg-slate-800/50 rounded-lg text-xs text-slate-400">
            These represent legitimate-but-imperfect users whose traffic patterns matter for sizing the rate limit correctly.
          </div>
        </div>
      </div>
    </div>
  );
}

function Slide7() {
  return (
    <div>
      <SlideTitle icon={Gauge} title="F5 XC Console Settings" subtitle="Where to apply the recommendation" />
      <div className="mt-8">
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 mb-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Number', value: 'N', desc: 'Requests per period per user' },
              { label: 'Per Period', value: 'Minutes', desc: 'Always Minutes for this advisor' },
              { label: 'Periods', value: '1', desc: 'Rate per single minute' },
              { label: 'Burst Multiplier', value: 'B', desc: 'Token bucket capacity = N × B' },
            ].map(f => (
              <div key={f.label} className="p-4 bg-slate-900/50 rounded-lg text-center">
                <div className="text-xs text-slate-400 mb-1">{f.label}</div>
                <div className="text-2xl font-bold text-blue-400">{f.value}</div>
                <div className="text-xs text-slate-500 mt-1">{f.desc}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-5">
          <h4 className="text-blue-300 font-semibold mb-3">Console Path</h4>
          <div className="space-y-2 text-sm text-slate-300">
            {[
              'Multi-Cloud App Connect → Load Balancers → HTTP Load Balancers',
              'Select your LB → Manage Configuration → Edit Configuration',
              'Common Security Controls → Rate Limiting',
              'Custom Rate Limiting Parameters → View Configuration',
              'Set Number, Per Period, Periods, and Burst Multiplier',
            ].map((step, i) => (
              <div key={i} className="flex items-center gap-2">
                <div className="w-6 h-6 rounded-full bg-blue-500/20 flex items-center justify-center text-blue-400 text-xs font-bold flex-shrink-0">{i + 1}</div>
                <span>{step}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// SLIDE TITLE
// ═══════════════════════════════════════════════════════════════════

function SlideTitle({ icon: Icon, title, subtitle }: { icon: React.ElementType; title: string; subtitle: string }) {
  return (
    <div className="flex items-center gap-3">
      <div className="w-12 h-12 bg-blue-500/15 rounded-xl flex items-center justify-center"><Icon className="w-6 h-6 text-blue-400" /></div>
      <div>
        <h2 className="text-2xl font-bold text-slate-100">{title}</h2>
        <p className="text-sm text-slate-400">{subtitle}</p>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// MAIN PAGE — SLIDESHOW
// ═══════════════════════════════════════════════════════════════════

const SLIDES = [
  { component: Slide1, title: 'Rate Limit Advisor' },
  { component: Slide2, title: 'The Token Bucket' },
  { component: Slide3, title: 'Why Burst Matters' },
  { component: Slide4, title: 'How the Advisor Works' },
  { component: Slide5, title: 'The Formula' },
  { component: SlideExample, title: 'Example Output' },
  { component: Slide6, title: 'Cleaning Filter' },
  { component: Slide7, title: 'F5 XC Settings' },
];

export function RateLimitExplainer() {
  const navigate = useNavigate();
  const [currentSlide, setCurrentSlide] = useState(0);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [zoomLevel, setZoomLevel] = useState(1);

  useEffect(() => {
    const calcZoom = () => setZoomLevel(Math.max(1, window.innerHeight / 700));
    calcZoom();
    window.addEventListener('resize', calcZoom);
    return () => window.removeEventListener('resize', calcZoom);
  }, []);

  const toggleFullscreen = useCallback(() => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().then(() => setIsFullscreen(true)).catch(() => {});
    } else {
      document.exitFullscreen().then(() => setIsFullscreen(false)).catch(() => {});
    }
  }, []);

  useEffect(() => {
    const onFsChange = () => setIsFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', onFsChange);
    return () => document.removeEventListener('fullscreenchange', onFsChange);
  }, []);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'ArrowRight' || e.key === ' ') { e.preventDefault(); setCurrentSlide(s => Math.min(s + 1, SLIDES.length - 1)); }
      if (e.key === 'ArrowLeft') { e.preventDefault(); setCurrentSlide(s => Math.max(s - 1, 0)); }
      if (e.key === 'f' || e.key === 'F') { e.preventDefault(); toggleFullscreen(); }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [toggleFullscreen]);

  const SlideComponent = SLIDES[currentSlide].component;

  if (isFullscreen) {
    return (
      <div className="fixed inset-0 z-[9999] bg-slate-900 flex flex-col">
        <div className="flex items-center justify-between px-8 py-4">
          <div className="flex items-center gap-1">
            {SLIDES.map((_, i) => (
              <button key={i} onClick={() => setCurrentSlide(i)}
                className={`h-2 rounded-full transition-all ${i === currentSlide ? 'bg-blue-500 w-8' : 'bg-slate-700 hover:bg-slate-600 w-2'}`} />
            ))}
          </div>
          <div className="flex items-center gap-4">
            <span className="text-sm text-slate-500">{currentSlide + 1} / {SLIDES.length}</span>
            <button onClick={toggleFullscreen} className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg"><Minimize2 className="w-5 h-5" /></button>
          </div>
        </div>
        <div className="flex-1 overflow-auto p-6">
          <div className="max-w-5xl mx-auto" style={{ zoom: zoomLevel }}><SlideComponent /></div>
        </div>
        <div className="flex items-center justify-between px-8 py-4">
          <button onClick={() => setCurrentSlide(s => Math.max(s - 1, 0))} disabled={currentSlide === 0}
            className="flex items-center gap-2 px-4 py-2 text-slate-400 hover:text-slate-200 disabled:opacity-20 text-sm"><ChevronLeft className="w-5 h-5" /> Previous</button>
          <span className="text-xs text-slate-600">Press F to exit · Arrow keys to navigate</span>
          <button onClick={() => setCurrentSlide(s => Math.min(s + 1, SLIDES.length - 1))} disabled={currentSlide === SLIDES.length - 1}
            className="flex items-center gap-2 px-4 py-2 text-slate-400 hover:text-slate-200 disabled:opacity-20 text-sm">Next <ChevronRight className="w-5 h-5" /></button>
        </div>
      </div>
    );
  }

  return (
    <main className="max-w-5xl mx-auto px-6 py-6 min-h-screen flex flex-col">
      {/* Top nav */}
      <div className="flex items-center justify-between mb-6">
        <button onClick={() => navigate(-1)} className="flex items-center gap-1 text-sm text-slate-400 hover:text-slate-200">
          <ArrowLeft className="w-4 h-4" /> Back
        </button>
        <div className="flex items-center gap-1">
          {SLIDES.map((_, i) => (
            <button key={i} onClick={() => setCurrentSlide(i)}
              className={`w-2.5 h-2.5 rounded-full transition-all ${i === currentSlide ? 'bg-blue-500 w-6' : 'bg-slate-600 hover:bg-slate-500'}`}
              title={SLIDES[i].title} />
          ))}
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-500">{currentSlide + 1} / {SLIDES.length}</span>
          <button onClick={toggleFullscreen} title="Present fullscreen (F)"
            className="p-1.5 text-slate-500 hover:text-blue-400 hover:bg-blue-500/10 rounded-lg transition-colors">
            <Maximize2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Slide content */}
      <div className="flex-1 bg-slate-800/30 border border-slate-700 rounded-2xl p-8 min-h-[500px]">
        <SlideComponent />
      </div>

      {/* Bottom navigation */}
      <div className="flex items-center justify-between mt-6 pb-4">
        <button onClick={() => setCurrentSlide(s => Math.max(s - 1, 0))} disabled={currentSlide === 0}
          className="flex items-center gap-2 px-5 py-2.5 bg-slate-800 border border-slate-700 hover:border-slate-500 disabled:opacity-30 text-slate-200 rounded-lg text-sm transition-colors">
          <ChevronLeft className="w-4 h-4" /> Previous
        </button>

        <button onClick={() => navigate('/rate-limit-advisor')}
          className="flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors">
          <Gauge className="w-4 h-4" /> Go to Rate Limit Advisor <ChevronRight className="w-4 h-4" />
        </button>

        <button onClick={() => setCurrentSlide(s => Math.min(s + 1, SLIDES.length - 1))} disabled={currentSlide === SLIDES.length - 1}
          className="flex items-center gap-2 px-5 py-2.5 bg-slate-800 border border-slate-700 hover:border-slate-500 disabled:opacity-30 text-slate-200 rounded-lg text-sm transition-colors">
          Next <ChevronRight className="w-4 h-4" />
        </button>
      </div>
    </main>
  );
}
