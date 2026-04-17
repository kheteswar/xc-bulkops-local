/**
 * Explainer slideshow pages for tools 10-18 (Part 2).
 * Each tool has 4-6 richly detailed slides explaining features and workflows.
 * Uses the shared Slideshow component for consistent navigation.
 */

import {
  Shield, Search, ShieldAlert, Activity, Grid3X3, Split, GitBranch,
  Database, BarChart2, Zap, Copy, Layers, Hammer, Globe,
  Users, Target, Check, AlertTriangle, Eye, Lock, FileJson,
  TrendingUp, Filter, Settings, Cpu, Server, Bug, X,
  ChevronRight, Hash, Clock, Gauge,
} from 'lucide-react';
import { Slideshow, SlideTitle, FeatureCard, StepList } from '../components/Slideshow';
import type { SlideDefinition } from '../components/Slideshow';

// ═══════════════════════════════════════════════════════════════════
// TOOL 10: LOAD TESTER
// ═══════════════════════════════════════════════════════════════════

const loadTesterSlides: SlideDefinition[] = [
  /* Slide 1 - Overview */
  { title: 'Overview', component: () => (
    <div>
      <SlideTitle icon={Zap} title="Load Tester" subtitle="Stress test any endpoint with configurable load profiles and real-time analytics" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        <FeatureCard icon={Zap} title="4 Load Profiles" description="Constant, Ramp, Step, and Spike profiles simulate different real-world traffic patterns. Configure duration, concurrency, and target RPS." color="blue" />
        <FeatureCard icon={TrendingUp} title="Real-Time Metrics" description="Live response time charts, throughput graphs, status code distribution, and latency histograms updated every second during the test." color="emerald" />
        <FeatureCard icon={Target} title="Pass/Fail Thresholds" description="Set rules for max response time, error rate, and Apdex score. Get an instant verdict when the test completes." color="amber" />
        <FeatureCard icon={Cpu} title="Standalone Operation" description="Runs entirely from your browser with no F5 XC connection required. Test any publicly reachable URL endpoint independently." color="violet" />
      </div>
      <div className="mt-6 grid grid-cols-4 gap-3">
        {[
          { label: 'HTTP Methods', value: 'GET / POST / PUT / DELETE' },
          { label: 'Max Concurrency', value: 'Up to 50 workers' },
          { label: 'Duration', value: '10s - 10min' },
          { label: 'Export', value: 'JSON results' },
        ].map(s => (
          <div key={s.label} className="bg-slate-800/60 border border-slate-700 rounded-lg p-3 text-center">
            <div className="text-xs text-slate-500 uppercase tracking-wide">{s.label}</div>
            <div className="text-sm font-semibold text-slate-200 mt-1">{s.value}</div>
          </div>
        ))}
      </div>
    </div>
  )},

  /* Slide 2 - Load Profiles */
  { title: 'Load Profiles', component: () => (
    <div>
      <SlideTitle icon={Activity} title="Load Profiles" subtitle="Four distinct traffic patterns to simulate real-world scenarios" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        {[
          {
            name: 'Constant',
            icon: Gauge,
            color: 'blue',
            pattern: '\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588',
            desc: 'Sends requests at a fixed rate for the entire duration. Ideal for baseline performance measurement and sustained throughput testing.',
            params: 'Target RPS, Duration, Concurrency',
          },
          {
            name: 'Ramp',
            icon: TrendingUp,
            color: 'emerald',
            pattern: '\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588\u2588\u2588\u2588\u2588',
            desc: 'Gradually increases load from zero to target RPS. Reveals the point where performance degrades and capacity limits appear.',
            params: 'Start RPS, End RPS, Ramp Duration',
          },
          {
            name: 'Step',
            icon: BarChart2,
            color: 'amber',
            pattern: '\u2581\u2581\u2583\u2583\u2585\u2585\u2587\u2587\u2588\u2588\u2588\u2588',
            desc: 'Incremental jumps in load at regular intervals. Each plateau stabilizes before the next increase, making bottlenecks easier to isolate.',
            params: 'Steps Count, Step Duration, Max RPS',
          },
          {
            name: 'Spike',
            icon: Zap,
            color: 'red',
            pattern: '\u2581\u2581\u2581\u2588\u2581\u2581\u2588\u2581\u2581\u2581\u2588\u2581',
            desc: 'Sudden bursts of high traffic followed by quiet periods. Tests how the system handles flash crowds and recovers under intermittent surges.',
            params: 'Spike RPS, Spike Duration, Interval',
          },
        ].map(p => {
          const colors: Record<string, string> = {
            blue: 'text-blue-400 border-blue-500/30 bg-blue-500/10',
            emerald: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
            amber: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
            red: 'text-red-400 border-red-500/30 bg-red-500/10',
          };
          const c = colors[p.color] || colors.blue;
          const [text, border, bg] = c.split(' ');
          return (
            <div key={p.name} className={`${bg} border ${border} rounded-xl p-5`}>
              <div className="flex items-center gap-2 mb-1">
                <p.icon className={`w-5 h-5 ${text}`} />
                <h3 className={`font-semibold ${text}`}>{p.name}</h3>
              </div>
              <div className={`font-mono text-lg tracking-widest ${text} mb-2`}>{p.pattern}</div>
              <p className="text-sm text-slate-400">{p.desc}</p>
              <div className="mt-2 text-xs text-slate-500">Config: {p.params}</div>
            </div>
          );
        })}
      </div>
    </div>
  )},

  /* Slide 3 - Real-Time Metrics */
  { title: 'Real-Time Metrics', component: () => (
    <div>
      <SlideTitle icon={TrendingUp} title="Real-Time Metrics" subtitle="Live stats updating every second during the test run" />
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-8">
        {[
          { label: 'Total Requests', value: '12,847', sub: 'sent', color: 'text-blue-400' },
          { label: 'Avg Response', value: '142ms', sub: 'p50 latency', color: 'text-emerald-400' },
          { label: 'Error Rate', value: '0.3%', sub: '38 errors', color: 'text-amber-400' },
          { label: 'Throughput', value: '428 RPS', sub: 'current', color: 'text-violet-400' },
        ].map(m => (
          <div key={m.label} className="bg-slate-800/60 border border-slate-700 rounded-xl p-4 text-center">
            <div className="text-xs text-slate-500 uppercase tracking-wide">{m.label}</div>
            <div className={`text-2xl font-bold ${m.color} mt-1`}>{m.value}</div>
            <div className="text-xs text-slate-500 mt-0.5">{m.sub}</div>
          </div>
        ))}
      </div>
      <div className="mt-6 space-y-3">
        <h3 className="text-sm font-semibold text-slate-300">Percentile Breakdown</h3>
        {[
          { pct: 'p50', value: '142ms', width: '28%', color: 'bg-emerald-500' },
          { pct: 'p75', value: '210ms', width: '42%', color: 'bg-blue-500' },
          { pct: 'p90', value: '385ms', width: '64%', color: 'bg-amber-500' },
          { pct: 'p95', value: '520ms', width: '78%', color: 'bg-orange-500' },
          { pct: 'p99', value: '1,240ms', width: '96%', color: 'bg-red-500' },
        ].map(p => (
          <div key={p.pct} className="flex items-center gap-3">
            <div className="w-10 text-xs text-slate-400 font-mono">{p.pct}</div>
            <div className="flex-1 bg-slate-800 rounded-full h-5 overflow-hidden">
              <div className={`${p.color} h-full rounded-full flex items-center justify-end pr-2`} style={{ width: p.width }}>
                <span className="text-[10px] font-bold text-white">{p.value}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
      <div className="mt-6">
        <h3 className="text-sm font-semibold text-slate-300 mb-3">Status Code Distribution</h3>
        <div className="flex gap-2">
          {[
            { code: '2xx', count: '12,547', pct: '97.7%', color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' },
            { code: '3xx', count: '182', pct: '1.4%', color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
            { code: '4xx', count: '80', pct: '0.6%', color: 'bg-amber-500/20 text-amber-400 border-amber-500/30' },
            { code: '5xx', count: '38', pct: '0.3%', color: 'bg-red-500/20 text-red-400 border-red-500/30' },
          ].map(s => (
            <div key={s.code} className={`flex-1 ${s.color} border rounded-lg p-3 text-center`}>
              <div className="text-lg font-bold">{s.code}</div>
              <div className="text-xs opacity-80">{s.count} ({s.pct})</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )},

  /* Slide 4 - Charts & Visualization */
  { title: 'Charts', component: () => (
    <div>
      <SlideTitle icon={BarChart2} title="Charts & Visualization" subtitle="Three chart tabs for deep performance analysis" />
      <div className="space-y-5 mt-8">
        {[
          {
            tab: 'Response Time',
            icon: Clock,
            color: 'blue',
            desc: 'Time-series line chart showing p50, p90, and p99 response times over the test duration. Hover for exact values at any point. Zoom and pan to inspect specific intervals.',
            highlights: ['Min / Avg / Max summary stats', 'Standard deviation overlay', 'Anomaly markers for spikes > 2 sigma'],
          },
          {
            tab: 'Throughput',
            icon: TrendingUp,
            color: 'emerald',
            desc: 'Area chart tracking requests per second (RPS) and successful responses per second. Overlays the target RPS so you can see if the server kept up with the load.',
            highlights: ['Target vs Actual RPS comparison', 'Error rate overlay', 'Apdex score timeline'],
          },
          {
            tab: 'Histogram',
            icon: BarChart2,
            color: 'amber',
            desc: 'Distribution histogram of response times across logarithmic buckets. Quickly spot bimodal distributions indicating cache hits vs. misses or fast vs. slow endpoints.',
            highlights: ['Logarithmic or linear bucket scale', 'Percentile markers on the axis', 'Outlier highlighting beyond p99'],
          },
        ].map(t => {
          const colors: Record<string, string> = {
            blue: 'text-blue-400 border-blue-500/30',
            emerald: 'text-emerald-400 border-emerald-500/30',
            amber: 'text-amber-400 border-amber-500/30',
          };
          const [text, border] = (colors[t.color] || colors.blue).split(' ');
          return (
            <div key={t.tab} className={`bg-slate-800/50 border ${border} rounded-xl p-5`}>
              <div className="flex items-center gap-2 mb-2">
                <t.icon className={`w-5 h-5 ${text}`} />
                <h3 className={`font-semibold ${text} text-base`}>{t.tab} Tab</h3>
              </div>
              <p className="text-sm text-slate-400 mb-3">{t.desc}</p>
              <div className="flex flex-wrap gap-2">
                {t.highlights.map(h => (
                  <span key={h} className="flex items-center gap-1 text-xs bg-slate-700/50 text-slate-300 px-2 py-1 rounded-md">
                    <Check className="w-3 h-3 text-emerald-400" /> {h}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  )},

  /* Slide 5 - Thresholds & F5 XC Integration */
  { title: 'Thresholds', component: () => (
    <div>
      <SlideTitle icon={Target} title="Thresholds & Verdict" subtitle="Automated pass/fail rules with optional F5 XC log analysis" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Pass / Fail Rules</h3>
          <div className="space-y-3">
            {[
              { rule: 'Max Response Time (p95)', example: '< 500ms', icon: Clock, pass: true },
              { rule: 'Error Rate', example: '< 1%', icon: AlertTriangle, pass: true },
              { rule: 'Apdex Score', example: '>= 0.85', icon: Target, pass: false },
              { rule: 'Min Throughput', example: '>= 400 RPS', icon: TrendingUp, pass: true },
            ].map(r => (
              <div key={r.rule} className="flex items-center gap-3 bg-slate-800/50 border border-slate-700 rounded-lg p-3">
                <r.icon className="w-4 h-4 text-slate-400 flex-shrink-0" />
                <div className="flex-1">
                  <div className="text-sm text-slate-200">{r.rule}</div>
                  <div className="text-xs text-slate-500">Threshold: {r.example}</div>
                </div>
                {r.pass ? (
                  <span className="flex items-center gap-1 text-xs font-semibold text-emerald-400 bg-emerald-500/10 px-2 py-1 rounded">
                    <Check className="w-3 h-3" /> PASS
                  </span>
                ) : (
                  <span className="flex items-center gap-1 text-xs font-semibold text-red-400 bg-red-500/10 px-2 py-1 rounded">
                    <X className="w-3 h-3" /> FAIL
                  </span>
                )}
              </div>
            ))}
          </div>
          <div className="mt-4 bg-amber-500/10 border border-amber-500/30 rounded-lg p-3">
            <div className="flex items-center gap-2 text-amber-400 text-sm font-semibold mb-1">
              <AlertTriangle className="w-4 h-4" /> Apdex Score
            </div>
            <p className="text-xs text-slate-400">
              Application Performance Index: satisfied (&lt; T), tolerating (&lt; 4T), frustrated (&gt; 4T).
              Default T = 300ms. Customize the T value for your SLA requirements.
            </p>
          </div>
        </div>
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">F5 XC Log Analysis Integration</h3>
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 space-y-4">
            <p className="text-sm text-slate-400">
              When connected to F5 XC, the Load Tester can correlate your test traffic with F5 XC access logs to provide deeper insight:
            </p>
            {[
              { label: 'WAF Events', desc: 'See if any test requests triggered WAF violations or were blocked', icon: Shield, color: 'text-red-400' },
              { label: 'Bot Detection', desc: 'Check if F5 XC classified your load test traffic as bot activity', icon: Bug, color: 'text-amber-400' },
              { label: 'Origin Timing', desc: 'Compare client-observed latency with F5 XC-reported origin response time', icon: Server, color: 'text-blue-400' },
              { label: 'Geo Distribution', desc: 'Verify which F5 XC PoP handled your requests and regional latency breakdown', icon: Globe, color: 'text-emerald-400' },
            ].map(f => (
              <div key={f.label} className="flex items-start gap-3">
                <f.icon className={`w-4 h-4 ${f.color} mt-0.5 flex-shrink-0`} />
                <div>
                  <div className="text-sm font-medium text-slate-200">{f.label}</div>
                  <div className="text-xs text-slate-500">{f.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )},
];

export function LoadTesterExplainer() {
  return <Slideshow slides={loadTesterSlides} toolName="Load Tester" toolRoute="/load-tester" toolIcon={Zap} />;
}

// ═══════════════════════════════════════════════════════════════════
// TOOL 11: API SHIELD ADVISOR
// ═══════════════════════════════════════════════════════════════════

const apiShieldSlides: SlideDefinition[] = [
  /* Slide 1 - Overview */
  { title: 'Overview', component: () => (
    <div>
      <SlideTitle icon={Shield} title="API Shield Advisor" subtitle="Comprehensive API security assessment against OWASP API Security Top 10" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        <FeatureCard icon={Shield} title="90+ Security Controls" description="Scans your F5 XC configuration against a comprehensive control framework covering authentication, authorization, rate limiting, input validation, and more." color="blue" />
        <FeatureCard icon={Target} title="OWASP API Top 10 Mapping" description="Every control is mapped to OWASP API Security Top 10 (2023) categories. See exactly which threats your current config addresses." color="red" />
        <FeatureCard icon={TrendingUp} title="Traffic-Grounded Profiling" description="Analyses real API traffic to identify endpoints, methods, response patterns, and bot activity so recommendations are grounded in actual usage data." color="emerald" />
        <FeatureCard icon={Layers} title="3 Scan Depths" description="Quick (config-only, 30s), Standard (config + traffic, 2min), or Deep (full analysis + OWASP scoring, 5min). Choose the depth that fits your schedule." color="amber" />
      </div>
      <div className="mt-6 grid grid-cols-3 gap-3">
        {[
          { label: 'Security Controls', value: '90+', color: 'text-blue-400' },
          { label: 'Security Domains', value: '11', color: 'text-emerald-400' },
          { label: 'OWASP Categories', value: '10/10', color: 'text-red-400' },
        ].map(s => (
          <div key={s.label} className="bg-slate-800/60 border border-slate-700 rounded-lg p-3 text-center">
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-xs text-slate-500 mt-1">{s.label}</div>
          </div>
        ))}
      </div>
    </div>
  )},

  /* Slide 2 - Security Domains */
  { title: 'Security Domains', component: () => (
    <div>
      <SlideTitle icon={Layers} title="11 Security Domains" subtitle="Comprehensive coverage across all API security dimensions" />
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mt-8">
        {[
          { domain: 'Authentication', desc: 'API keys, OAuth, JWT validation, mTLS', icon: Lock, color: 'text-blue-400 border-blue-500/30' },
          { domain: 'Authorization', desc: 'RBAC, scope checks, object-level auth', icon: Shield, color: 'text-emerald-400 border-emerald-500/30' },
          { domain: 'Rate Limiting', desc: 'Per-client, per-endpoint, adaptive limits', icon: Gauge, color: 'text-amber-400 border-amber-500/30' },
          { domain: 'Input Validation', desc: 'Schema enforcement, parameter filtering', icon: Filter, color: 'text-red-400 border-red-500/30' },
          { domain: 'Bot Protection', desc: 'Bot defense, JS challenge, captcha', icon: Bug, color: 'text-violet-400 border-violet-500/30' },
          { domain: 'DDoS Mitigation', desc: 'L7 auto-mitigation, slow-rate detection', icon: ShieldAlert, color: 'text-cyan-400 border-cyan-500/30' },
          { domain: 'Data Exposure', desc: 'Response filtering, PII masking, headers', icon: Eye, color: 'text-blue-400 border-blue-500/30' },
          { domain: 'Encryption', desc: 'TLS version, cipher suites, HSTS', icon: Lock, color: 'text-emerald-400 border-emerald-500/30' },
          { domain: 'Logging', desc: 'Access logs, security events, retention', icon: FileJson, color: 'text-amber-400 border-amber-500/30' },
          { domain: 'API Discovery', desc: 'Endpoint inventory, schema learning', icon: Search, color: 'text-red-400 border-red-500/30' },
          { domain: 'WAF Coverage', desc: 'App firewall, signatures, exclusions', icon: Shield, color: 'text-violet-400 border-violet-500/30' },
        ].map(d => {
          const [text, border] = d.color.split(' ');
          return (
            <div key={d.domain} className={`bg-slate-800/50 border ${border} rounded-xl p-4`}>
              <div className="flex items-center gap-2 mb-1">
                <d.icon className={`w-4 h-4 ${text}`} />
                <div className={`font-semibold text-sm ${text}`}>{d.domain}</div>
              </div>
              <p className="text-xs text-slate-400">{d.desc}</p>
            </div>
          );
        })}
      </div>
    </div>
  )},

  /* Slide 3 - OWASP Coverage */
  { title: 'OWASP Coverage', component: () => (
    <div>
      <SlideTitle icon={Target} title="OWASP API Top 10 Coverage" subtitle="How the advisor maps to each OWASP API Security category" />
      <div className="space-y-2.5 mt-8">
        {[
          { id: 'API1', name: 'Broken Object-Level Auth', pct: 85, controls: 8, color: 'bg-blue-500' },
          { id: 'API2', name: 'Broken Authentication', pct: 92, controls: 11, color: 'bg-emerald-500' },
          { id: 'API3', name: 'Broken Object Property Auth', pct: 78, controls: 7, color: 'bg-blue-500' },
          { id: 'API4', name: 'Unrestricted Resource Consumption', pct: 95, controls: 12, color: 'bg-emerald-500' },
          { id: 'API5', name: 'Broken Function-Level Auth', pct: 80, controls: 8, color: 'bg-blue-500' },
          { id: 'API6', name: 'Unrestricted Access to Sensitive Flows', pct: 88, controls: 9, color: 'bg-emerald-500' },
          { id: 'API7', name: 'Server-Side Request Forgery', pct: 72, controls: 6, color: 'bg-amber-500' },
          { id: 'API8', name: 'Security Misconfiguration', pct: 96, controls: 14, color: 'bg-emerald-500' },
          { id: 'API9', name: 'Improper Inventory Management', pct: 90, controls: 10, color: 'bg-emerald-500' },
          { id: 'API10', name: 'Unsafe Consumption of APIs', pct: 68, controls: 5, color: 'bg-amber-500' },
        ].map(o => (
          <div key={o.id} className="flex items-center gap-3">
            <div className="w-12 text-xs font-mono text-slate-400 flex-shrink-0">{o.id}</div>
            <div className="flex-1">
              <div className="flex items-center justify-between mb-0.5">
                <span className="text-xs text-slate-300">{o.name}</span>
                <span className="text-xs text-slate-500">{o.controls} controls</span>
              </div>
              <div className="bg-slate-800 rounded-full h-4 overflow-hidden">
                <div className={`${o.color} h-full rounded-full flex items-center justify-end pr-2`} style={{ width: `${o.pct}%` }}>
                  <span className="text-[10px] font-bold text-white">{o.pct}%</span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )},

  /* Slide 4 - Recommendations & Phases */
  { title: 'Recommendations', component: () => (
    <div>
      <SlideTitle icon={ChevronRight} title="Prioritized Recommendations" subtitle="Actionable security improvements organized into implementation phases" />
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mt-8">
        {[
          {
            phase: 'Phase 1: Quick Wins',
            color: 'border-emerald-500/40 bg-emerald-500/5',
            headerColor: 'text-emerald-400',
            timeline: '1-2 days',
            items: [
              'Enable WAF in blocking mode',
              'Set TLS minimum to v1.2',
              'Enable API Discovery',
              'Configure access logging',
              'Add HSTS headers',
            ],
          },
          {
            phase: 'Phase 2: Core Controls',
            color: 'border-blue-500/40 bg-blue-500/5',
            headerColor: 'text-blue-400',
            timeline: '1-2 weeks',
            items: [
              'Implement rate limiting per-client',
              'Enable bot defense with JS challenge',
              'Configure L7 DDoS auto-mitigation',
              'Add API schema validation',
              'Set up alert policies',
            ],
          },
          {
            phase: 'Phase 3: Advanced',
            color: 'border-violet-500/40 bg-violet-500/5',
            headerColor: 'text-violet-400',
            timeline: '2-4 weeks',
            items: [
              'Malicious User Detection (MUD)',
              'Custom WAF signature tuning',
              'mTLS for service-to-service',
              'Sensitive data masking',
              'Geo-based access policies',
            ],
          },
        ].map(p => (
          <div key={p.phase} className={`border ${p.color} rounded-xl p-5`}>
            <h3 className={`font-semibold ${p.headerColor} mb-1`}>{p.phase}</h3>
            <div className="text-xs text-slate-500 mb-3">Timeline: {p.timeline}</div>
            <ul className="space-y-2">
              {p.items.map(item => (
                <li key={item} className="flex items-start gap-2 text-sm text-slate-300">
                  <Check className={`w-3.5 h-3.5 ${p.headerColor} mt-0.5 flex-shrink-0`} />
                  {item}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  )},

  /* Slide 5 - Results Tabs */
  { title: 'Results Tabs', component: () => (
    <div>
      <SlideTitle icon={Layers} title="Results Dashboard" subtitle="Seven tabs providing complete visibility into your API security posture" />
      <div className="space-y-3 mt-8">
        {[
          { tab: 'Overview', icon: BarChart2, desc: 'Overall security score, domain breakdown radar chart, and executive summary with top findings.', color: 'text-blue-400' },
          { tab: 'Domain Scores', icon: Shield, desc: 'Per-domain scoring (0-100) across all 11 security domains with pass/partial/fail indicators per control.', color: 'text-emerald-400' },
          { tab: 'OWASP Mapping', icon: Target, desc: 'Coverage heatmap showing which OWASP API Top 10 categories your config addresses and where gaps remain.', color: 'text-red-400' },
          { tab: 'Findings', icon: AlertTriangle, desc: 'Detailed list of every finding with severity, affected objects, remediation steps, and OWASP cross-reference.', color: 'text-amber-400' },
          { tab: 'Traffic Profile', icon: TrendingUp, desc: 'Endpoint inventory from live traffic, method distribution, response patterns, and bot vs. human breakdown.', color: 'text-violet-400' },
          { tab: 'Recommendations', icon: ChevronRight, desc: 'Prioritized action items grouped by phase. Each recommendation links to the finding it addresses.', color: 'text-cyan-400' },
          { tab: 'Export', icon: FileJson, desc: 'Download the full report as PDF, Excel, or JSON. Share with stakeholders or import into GRC tools.', color: 'text-blue-400' },
        ].map((t, i) => (
          <div key={t.tab} className="flex items-start gap-4 bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <div className="w-8 h-8 rounded-lg bg-slate-700/50 flex items-center justify-center flex-shrink-0">
              <span className="text-xs font-bold text-slate-400">{i + 1}</span>
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-0.5">
                <t.icon className={`w-4 h-4 ${t.color}`} />
                <h4 className={`font-semibold text-sm ${t.color}`}>{t.tab}</h4>
              </div>
              <p className="text-xs text-slate-400">{t.desc}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )},
];

export function APIShieldExplainer() {
  return <Slideshow slides={apiShieldSlides} toolName="API Shield Advisor" toolRoute="/api-shield" toolIcon={Shield} />;
}

// ═══════════════════════════════════════════════════════════════════
// TOOL 12: API REPORT
// ═══════════════════════════════════════════════════════════════════

const apiReportSlides: SlideDefinition[] = [
  /* Slide 1 - Overview */
  { title: 'Overview', component: () => (
    <div>
      <SlideTitle icon={BarChart2} title="API Report Dashboard" subtitle="API discovery stats, Swagger parsing, and multi-LB endpoint reporting" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        <FeatureCard icon={BarChart2} title="Discovery Statistics" description="View how many API endpoints F5 XC has discovered on each load balancer, with per-method and per-path breakdowns showing API surface area." color="blue" />
        <FeatureCard icon={FileJson} title="Swagger/OpenAPI Parsing" description="Parses learnt API schemas from F5 XC to display endpoint paths, methods, parameters, and request/response types in a structured view." color="emerald" />
        <FeatureCard icon={Layers} title="Multi-LB Consolidation" description="Aggregate API endpoint data across multiple load balancers into a single consolidated report. Identify overlapping APIs and gaps." color="amber" />
        <FeatureCard icon={FileJson} title="Excel Workbook Export" description="Export the complete API inventory as a structured Excel workbook with separate sheets for stats, endpoints, and Swagger definitions." color="violet" />
      </div>
      <div className="mt-6 grid grid-cols-4 gap-3">
        {[
          { label: 'Load Balancers', value: 'Multi-LB', icon: Server },
          { label: 'Schema Format', value: 'OpenAPI 3.x', icon: FileJson },
          { label: 'Export', value: 'Excel / JSON', icon: Layers },
          { label: 'Discovery', value: 'Real traffic', icon: Search },
        ].map(s => (
          <div key={s.label} className="bg-slate-800/60 border border-slate-700 rounded-lg p-3 text-center">
            <s.icon className="w-4 h-4 text-slate-500 mx-auto mb-1" />
            <div className="text-sm font-semibold text-slate-200">{s.value}</div>
            <div className="text-xs text-slate-500">{s.label}</div>
          </div>
        ))}
      </div>
    </div>
  )},

  /* Slide 2 - Results Dashboard Tabs */
  { title: 'Results Dashboard', component: () => (
    <div>
      <SlideTitle icon={Layers} title="Results Dashboard" subtitle="Three tabs providing complete API visibility" />
      <div className="space-y-5 mt-8">
        {[
          {
            tab: 'Stats',
            icon: BarChart2,
            color: 'blue',
            desc: 'High-level discovery metrics for each selected load balancer.',
            details: [
              { label: 'Total Endpoints', value: 'Count of unique path + method combinations discovered' },
              { label: 'Methods', value: 'GET / POST / PUT / DELETE / PATCH distribution' },
              { label: 'Response Codes', value: '2xx / 4xx / 5xx breakdown across all discovered APIs' },
              { label: 'First / Last Seen', value: 'Discovery timeline showing when endpoints were first and last observed' },
            ],
          },
          {
            tab: 'Swagger',
            icon: FileJson,
            color: 'emerald',
            desc: 'Parsed OpenAPI schema view of the learnt API specification.',
            details: [
              { label: 'Endpoints Tree', value: 'Hierarchical path + method listing with parameters' },
              { label: 'Request Body', value: 'Inferred request schema with types and examples' },
              { label: 'Response Schema', value: 'Learnt response structure and content types' },
              { label: 'Parameters', value: 'Path, query, and header parameters with types' },
            ],
          },
          {
            tab: 'Endpoints',
            icon: Search,
            color: 'amber',
            desc: 'Flat searchable table of every discovered endpoint.',
            details: [
              { label: 'Path + Method', value: 'Full endpoint URL pattern with HTTP method' },
              { label: 'Hit Count', value: 'Number of times F5 XC observed traffic to this endpoint' },
              { label: 'Avg Latency', value: 'Average response time across all observations' },
              { label: 'Status Dist', value: 'Response code distribution per endpoint' },
            ],
          },
        ].map(t => {
          const colors: Record<string, string> = {
            blue: 'text-blue-400 border-blue-500/30 bg-blue-500/5',
            emerald: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/5',
            amber: 'text-amber-400 border-amber-500/30 bg-amber-500/5',
          };
          const c = colors[t.color] || colors.blue;
          const [text, border, bg] = c.split(' ');
          return (
            <div key={t.tab} className={`${bg} border ${border} rounded-xl p-5`}>
              <div className="flex items-center gap-2 mb-2">
                <t.icon className={`w-5 h-5 ${text}`} />
                <h3 className={`font-semibold ${text}`}>{t.tab} Tab</h3>
              </div>
              <p className="text-sm text-slate-400 mb-3">{t.desc}</p>
              <div className="grid grid-cols-2 gap-2">
                {t.details.map(d => (
                  <div key={d.label} className="bg-slate-800/50 rounded-lg p-2.5">
                    <div className="text-xs font-semibold text-slate-300">{d.label}</div>
                    <div className="text-xs text-slate-500 mt-0.5">{d.value}</div>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  )},

  /* Slide 3 - Swagger Analysis */
  { title: 'Swagger Analysis', component: () => (
    <div>
      <SlideTitle icon={FileJson} title="Swagger / OpenAPI Analysis" subtitle="Deep parsing of learnt API schemas from F5 XC discovery" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Schema Parsing Engine</h3>
          <StepList steps={[
            { icon: Search, title: 'Fetch Learnt Schema', desc: 'Retrieves the OpenAPI spec that F5 XC has built from observing real traffic to your API endpoints.', color: 'bg-blue-500' },
            { icon: FileJson, title: 'Parse & Normalize', desc: 'Handles OpenAPI 3.0/3.1 specs, resolves $ref references, and normalizes paths for consistent display.', color: 'bg-emerald-500' },
            { icon: Layers, title: 'Endpoint Inventory', desc: 'Builds a complete inventory of all paths, methods, parameters, request bodies, and response schemas.', color: 'bg-amber-500' },
            { icon: BarChart2, title: 'Coverage Report', desc: 'Compares discovered endpoints against any uploaded Swagger file to identify shadow and zombie APIs.', color: 'bg-violet-500' },
          ]} />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">What You Get</h3>
          <div className="space-y-3">
            {[
              { label: 'Endpoint Count', desc: 'Total unique path + method combinations in the spec', icon: Hash, color: 'text-blue-400' },
              { label: 'Path Hierarchy', desc: 'Tree view showing API structure: /api/v1/users, /api/v1/orders, etc.', icon: GitBranch, color: 'text-emerald-400' },
              { label: 'Parameter Types', desc: 'Path params, query strings, headers, and request body schemas with data types', icon: Filter, color: 'text-amber-400' },
              { label: 'Response Models', desc: 'Inferred response schemas with status codes, content types, and field definitions', icon: FileJson, color: 'text-violet-400' },
              { label: 'Shadow APIs', desc: 'Endpoints seen in traffic but missing from your uploaded spec (potential security risk)', icon: AlertTriangle, color: 'text-red-400' },
              { label: 'Zombie APIs', desc: 'Endpoints in your spec but no longer receiving traffic (potential cleanup candidates)', icon: X, color: 'text-slate-400' },
            ].map(f => (
              <div key={f.label} className="flex items-start gap-3 bg-slate-800/50 border border-slate-700 rounded-lg p-3">
                <f.icon className={`w-4 h-4 ${f.color} mt-0.5 flex-shrink-0`} />
                <div>
                  <div className="text-sm font-medium text-slate-200">{f.label}</div>
                  <div className="text-xs text-slate-500">{f.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )},

  /* Slide 4 - Export */
  { title: 'Export', component: () => (
    <div>
      <SlideTitle icon={FileJson} title="Excel Workbook Export" subtitle="Structured multi-sheet workbook for documentation and compliance" />
      <div className="mt-8">
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
          <div className="bg-slate-700/50 px-5 py-3 border-b border-slate-700">
            <h3 className="text-sm font-semibold text-slate-200">Workbook Structure</h3>
          </div>
          <div className="divide-y divide-slate-700">
            {[
              { sheet: 'Summary', cols: 'LB Name, Namespace, Total Endpoints, Methods, Discovery Date', icon: BarChart2, color: 'text-blue-400' },
              { sheet: 'Endpoints', cols: 'Path, Method, Hit Count, Avg Latency, Status Codes, First Seen, Last Seen', icon: Search, color: 'text-emerald-400' },
              { sheet: 'Swagger Paths', cols: 'Path, Method, Parameters, Request Body, Response Schema, Tags', icon: FileJson, color: 'text-amber-400' },
              { sheet: 'Shadow APIs', cols: 'Path, Method, Hit Count, Risk Level, Recommendation', icon: AlertTriangle, color: 'text-red-400' },
            ].map(s => (
              <div key={s.sheet} className="flex items-start gap-4 px-5 py-4">
                <s.icon className={`w-5 h-5 ${s.color} mt-0.5 flex-shrink-0`} />
                <div className="flex-1">
                  <div className={`font-semibold text-sm ${s.color}`}>{s.sheet} Sheet</div>
                  <div className="text-xs text-slate-400 mt-1">Columns: {s.cols}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4 mt-5">
          <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4">
            <div className="flex items-center gap-2 text-blue-400 text-sm font-semibold mb-2">
              <FileJson className="w-4 h-4" /> JSON Export
            </div>
            <p className="text-xs text-slate-400">Raw API inventory as structured JSON for programmatic consumption, CI/CD integration, or import into API management platforms.</p>
          </div>
          <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-4">
            <div className="flex items-center gap-2 text-emerald-400 text-sm font-semibold mb-2">
              <Layers className="w-4 h-4" /> Multi-LB Merge
            </div>
            <p className="text-xs text-slate-400">When multiple LBs are selected, endpoints are deduplicated and the export includes a source column showing which LB(s) serve each API.</p>
          </div>
        </div>
      </div>
    </div>
  )},
];

export function APIReportExplainer() {
  return <Slideshow slides={apiReportSlides} toolName="API Report" toolRoute="/api-report" toolIcon={BarChart2} />;
}

// ═══════════════════════════════════════════════════════════════════
// TOOL 13: SOC LOBBY / SOC ROOM
// ═══════════════════════════════════════════════════════════════════

const socRoomSlides: SlideDefinition[] = [
  /* Slide 1 - Overview */
  { title: 'Overview', component: () => (
    <div>
      <SlideTitle icon={Activity} title="Live SOC Room" subtitle="Multi-room security operations center with continuous monitoring and threat detection" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        <FeatureCard icon={Activity} title="Continuous Monitoring" description="Real-time dashboards showing RPS, error rates, WAF events, and security metrics with 60-second heartbeat polling for always-current data." color="blue" />
        <FeatureCard icon={AlertTriangle} title="23 Anomaly Detectors" description="Built-in anomaly detection identifies unusual patterns in traffic volume, error spikes, geographic shifts, and security event clusters." color="red" />
        <FeatureCard icon={Zap} title="12 Auto-Investigations" description="Automated investigation workflows trigger when anomalies are detected, gathering context, correlating events, and building evidence timelines." color="emerald" />
        <FeatureCard icon={Users} title="Multi-Room Architecture" description="Create separate SOC rooms for different environments, teams, or incidents. Each room has independent monitoring state and persistence." color="amber" />
      </div>
      <div className="mt-6 grid grid-cols-4 gap-3">
        {[
          { label: 'Heartbeat', value: '60s polling' },
          { label: 'Threat Levels', value: '5 severity' },
          { label: 'Persistence', value: 'localStorage' },
          { label: 'Detectors', value: '23 built-in' },
        ].map(s => (
          <div key={s.label} className="bg-slate-800/60 border border-slate-700 rounded-lg p-3 text-center">
            <div className="text-xs text-slate-500 uppercase tracking-wide">{s.label}</div>
            <div className="text-sm font-semibold text-slate-200 mt-1">{s.value}</div>
          </div>
        ))}
      </div>
    </div>
  )},

  /* Slide 2 - Heartbeat System */
  { title: 'Heartbeat System', component: () => (
    <div>
      <SlideTitle icon={Activity} title="Heartbeat System" subtitle="60-second polling cycle keeps dashboards current with minimal API load" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Polling Cycle</h3>
          <StepList steps={[
            { icon: Clock, title: 'Timer Fires (every 60s)', desc: 'The heartbeat timer triggers a new data collection cycle for all monitored load balancers in the room.', color: 'bg-blue-500' },
            { icon: Server, title: 'Fetch Access Logs', desc: 'Pulls the latest 60 seconds of access logs from F5 XC for each LB. Concurrent requests with adaptive rate limiting.', color: 'bg-emerald-500' },
            { icon: BarChart2, title: 'Compute Metrics', desc: 'Calculates RPS, error rates, response time percentiles, geo distribution, and security event counts from the raw logs.', color: 'bg-amber-500' },
            { icon: AlertTriangle, title: 'Run Anomaly Detectors', desc: 'All 23 detectors evaluate the new metrics against baselines and thresholds. Anomalies trigger alerts and investigations.', color: 'bg-red-500' },
          ]} />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">RPS Calculation</h3>
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 space-y-4">
            <div className="bg-slate-900/50 rounded-lg p-3 font-mono text-xs text-slate-300">
              <div className="text-slate-500">// Real-time RPS from log count</div>
              <div className="mt-1">rps = logCount / windowSeconds</div>
              <div className="mt-1">peakRps = max(rps, historicalPeak)</div>
              <div className="mt-1">avgRps = totalLogs / totalSeconds</div>
            </div>
            <div className="space-y-2">
              {[
                { metric: 'Current RPS', desc: 'Requests in the last 60s window divided by 60', color: 'text-blue-400' },
                { metric: 'Peak RPS', desc: 'Highest RPS seen since the room was created', color: 'text-red-400' },
                { metric: 'Average RPS', desc: 'Running average across all heartbeat cycles', color: 'text-emerald-400' },
                { metric: 'Error RPS', desc: 'Only 4xx/5xx responses per second', color: 'text-amber-400' },
              ].map(m => (
                <div key={m.metric} className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${m.color.replace('text-', 'bg-')}`} />
                  <span className={`text-xs font-semibold ${m.color}`}>{m.metric}</span>
                  <span className="text-xs text-slate-500">- {m.desc}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )},

  /* Slide 3 - Room Management */
  { title: 'Room Management', component: () => (
    <div>
      <SlideTitle icon={Users} title="Room Management" subtitle="Create, configure, and manage independent monitoring rooms" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Room CRUD Operations</h3>
          <div className="space-y-3">
            {[
              { op: 'Create Room', desc: 'Name the room, select target LBs, set initial threat level, and choose monitoring frequency.', icon: Zap, color: 'text-emerald-400' },
              { op: 'Edit Room', desc: 'Add or remove LBs, adjust threat level, rename, or change alert thresholds at any time.', icon: Settings, color: 'text-blue-400' },
              { op: 'Archive Room', desc: 'Deactivate a room while preserving its historical data and investigation results.', icon: Database, color: 'text-amber-400' },
              { op: 'Delete Room', desc: 'Permanently remove a room and all its monitoring data from localStorage.', icon: X, color: 'text-red-400' },
            ].map(o => (
              <div key={o.op} className="flex items-start gap-3 bg-slate-800/50 border border-slate-700 rounded-lg p-3">
                <o.icon className={`w-4 h-4 ${o.color} mt-0.5 flex-shrink-0`} />
                <div>
                  <div className={`text-sm font-medium ${o.color}`}>{o.op}</div>
                  <div className="text-xs text-slate-500">{o.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Threat Level Indicators</h3>
          <div className="space-y-2">
            {[
              { level: 'CRITICAL', color: 'bg-red-600', textColor: 'text-red-300', desc: 'Active incident: DDoS attack, mass exploitation, or service outage detected', ring: 'ring-2 ring-red-500/50' },
              { level: 'HIGH', color: 'bg-orange-600', textColor: 'text-orange-300', desc: 'Elevated threat: significant anomalies, unusual traffic spikes, or WAF event clusters', ring: 'ring-2 ring-orange-500/50' },
              { level: 'MEDIUM', color: 'bg-amber-600', textColor: 'text-amber-300', desc: 'Moderate concern: minor anomalies detected, elevated error rates, or scanning activity', ring: '' },
              { level: 'LOW', color: 'bg-blue-600', textColor: 'text-blue-300', desc: 'Normal operations: traffic within expected baselines, no anomalies detected', ring: '' },
              { level: 'INFO', color: 'bg-slate-600', textColor: 'text-slate-300', desc: 'Monitoring only: room is active but no thresholds have been configured yet', ring: '' },
            ].map(t => (
              <div key={t.level} className={`flex items-center gap-3 bg-slate-800/50 border border-slate-700 rounded-lg p-3 ${t.ring}`}>
                <div className={`w-10 h-6 ${t.color} rounded flex items-center justify-center`}>
                  <span className="text-[10px] font-bold text-white">{t.level}</span>
                </div>
                <p className="text-xs text-slate-400 flex-1">{t.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )},

  /* Slide 4 - SOC Room Deep Features */
  { title: 'SOC Room Features', component: () => (
    <div>
      <SlideTitle icon={Zap} title="SOC Room Deep Features" subtitle="Deep monitoring, anomaly detection, and automated investigation inside each room" />
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mt-8">
        <div className="bg-blue-500/5 border border-blue-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <BarChart2 className="w-5 h-5 text-blue-400" />
            <h3 className="font-semibold text-blue-400">Live Dashboard</h3>
          </div>
          <ul className="space-y-2">
            {[
              'RPS timeline chart (last 30min)',
              'Status code distribution pie',
              'Top paths by request count',
              'Geo heatmap of traffic origins',
              'WAF event timeline',
              'Response time percentile bands',
            ].map(item => (
              <li key={item} className="flex items-start gap-2 text-xs text-slate-300">
                <Check className="w-3 h-3 text-blue-400 mt-0.5 flex-shrink-0" /> {item}
              </li>
            ))}
          </ul>
        </div>
        <div className="bg-red-500/5 border border-red-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <h3 className="font-semibold text-red-400">Anomaly Detection</h3>
          </div>
          <ul className="space-y-2">
            {[
              'RPS spike > 3x baseline',
              'Error rate > 5% threshold',
              'New country in top sources',
              'WAF block rate surge',
              'Latency p99 degradation',
              'Bot traffic percentage jump',
            ].map(item => (
              <li key={item} className="flex items-start gap-2 text-xs text-slate-300">
                <AlertTriangle className="w-3 h-3 text-red-400 mt-0.5 flex-shrink-0" /> {item}
              </li>
            ))}
          </ul>
        </div>
        <div className="bg-emerald-500/5 border border-emerald-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <Zap className="w-5 h-5 text-emerald-400" />
            <h3 className="font-semibold text-emerald-400">Auto-Investigation</h3>
          </div>
          <ul className="space-y-2">
            {[
              'Correlate spike with WAF events',
              'Identify top attacking IPs',
              'Map attack geo distribution',
              'Extract attack signatures',
              'Build incident timeline',
              'Generate investigation report',
            ].map(item => (
              <li key={item} className="flex items-start gap-2 text-xs text-slate-300">
                <Zap className="w-3 h-3 text-emerald-400 mt-0.5 flex-shrink-0" /> {item}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )},
];

export function SOCRoomExplainer() {
  return <Slideshow slides={socRoomSlides} toolName="SOC Lobby" toolRoute="/soc-lobby" toolIcon={Activity} />;
}

// ═══════════════════════════════════════════════════════════════════
// TOOL 14: PREFIX BUILDER
// ═══════════════════════════════════════════════════════════════════

const prefixBuilderSlides: SlideDefinition[] = [
  /* Slide 1 - Overview */
  { title: 'Overview', component: () => (
    <div>
      <SlideTitle icon={Grid3X3} title="Prefix Builder" subtitle="Bulk IP prefix set creation with validation, file upload, and policy attachment" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        <FeatureCard icon={Grid3X3} title="Bulk IP Prefix Creation" description="Create IP prefix sets containing hundreds of entries at once. Supports both IPv4 (192.168.0.0/16) and IPv6 (2001:db8::/32) CIDR notation." color="blue" />
        <FeatureCard icon={Layers} title="Single & Multi-Set Modes" description="Create a single prefix set with all IPs, or split entries across multiple named sets. Multi-set mode supports CSV file upload with set assignments." color="emerald" />
        <FeatureCard icon={Check} title="Real-Time Validation" description="Every IP address and CIDR range is validated before submission. Invalid entries are flagged inline with clear error messages and suggested corrections." color="amber" />
        <FeatureCard icon={Shield} title="Policy Attachment" description="Optionally attach created prefix sets to a new or existing service policy with allow/deny rules in one streamlined workflow." color="violet" />
      </div>
      <div className="mt-6 flex gap-4">
        <div className="flex-1 bg-slate-800/60 border border-slate-700 rounded-lg p-4">
          <h4 className="text-xs text-slate-500 uppercase tracking-wide mb-2">Supported Formats</h4>
          <div className="flex flex-wrap gap-2">
            {['10.0.0.0/8', '192.168.1.0/24', '172.16.0.0/12', '2001:db8::/32', 'fd00::/8', '10.0.0.1/32'].map(ip => (
              <span key={ip} className="font-mono text-xs bg-slate-700/50 text-slate-300 px-2 py-1 rounded">{ip}</span>
            ))}
          </div>
        </div>
        <div className="flex-1 bg-slate-800/60 border border-slate-700 rounded-lg p-4">
          <h4 className="text-xs text-slate-500 uppercase tracking-wide mb-2">Input Methods</h4>
          <div className="space-y-1.5">
            {[
              { method: 'Manual Entry', desc: 'Type or paste IPs in the text area' },
              { method: 'CSV Upload', desc: 'Upload a CSV file with IP/CIDR column' },
              { method: 'Bulk Paste', desc: 'Paste from spreadsheet or text file' },
            ].map(m => (
              <div key={m.method} className="flex items-center gap-2 text-xs">
                <Check className="w-3 h-3 text-emerald-400" />
                <span className="text-slate-300 font-medium">{m.method}</span>
                <span className="text-slate-500">- {m.desc}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )},

  /* Slide 2 - Configuration */
  { title: 'Configuration', component: () => (
    <div>
      <SlideTitle icon={Settings} title="Configuration" subtitle="Namespace selection, labels, descriptions, and file upload" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Required Settings</h3>
          <div className="space-y-3">
            {[
              { field: 'Namespace', desc: 'Target namespace where prefix sets will be created. Dropdown populated from your connected tenant.', icon: Database, required: true },
              { field: 'Prefix Set Name', desc: 'Name for the prefix set object. Must be unique within the namespace. Auto-sanitized for F5 XC naming rules.', icon: Hash, required: true },
              { field: 'IP Entries', desc: 'One or more IP addresses or CIDR ranges. Enter manually or upload via CSV file.', icon: Grid3X3, required: true },
            ].map(f => (
              <div key={f.field} className="flex items-start gap-3 bg-slate-800/50 border border-slate-700 rounded-lg p-4">
                <f.icon className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-slate-200">{f.field}</span>
                    {f.required && <span className="text-[10px] font-bold text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded">REQUIRED</span>}
                  </div>
                  <div className="text-xs text-slate-500 mt-0.5">{f.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Optional Settings</h3>
          <div className="space-y-3">
            {[
              { field: 'Description', desc: 'Free-text description for the prefix set. Shows in the F5 XC console.', icon: FileJson },
              { field: 'Labels', desc: 'Key-value labels for organization and filtering (e.g., team=security, env=prod).', icon: Filter },
              { field: 'CSV File Upload', desc: 'Upload a CSV with columns: ip, name (optional), description (optional). Supports multi-set assignments.', icon: Layers },
            ].map(f => (
              <div key={f.field} className="flex items-start gap-3 bg-slate-800/50 border border-slate-700 rounded-lg p-4">
                <f.icon className="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0" />
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-slate-200">{f.field}</span>
                    <span className="text-[10px] font-bold text-slate-500 bg-slate-700/50 px-1.5 py-0.5 rounded">OPTIONAL</span>
                  </div>
                  <div className="text-xs text-slate-500 mt-0.5">{f.desc}</div>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-4 bg-blue-500/10 border border-blue-500/30 rounded-lg p-3">
            <div className="text-xs text-blue-400 font-semibold mb-1">CSV Template</div>
            <div className="font-mono text-[11px] text-slate-400 bg-slate-900/50 rounded p-2">
              ip,set_name,description<br/>
              10.0.0.0/8,internal,RFC1918<br/>
              192.168.0.0/16,internal,Private<br/>
              203.0.113.0/24,external,Test-Net-3
            </div>
          </div>
        </div>
      </div>
    </div>
  )},

  /* Slide 3 - Policy Attachment */
  { title: 'Policy Attachment', component: () => (
    <div>
      <SlideTitle icon={Shield} title="Service Policy Attachment" subtitle="Optionally create or attach to a service policy in the same workflow" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
        <div className="bg-emerald-500/5 border border-emerald-500/30 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <Zap className="w-5 h-5 text-emerald-400" />
            <h3 className="font-semibold text-emerald-400">Create New Policy</h3>
          </div>
          <div className="space-y-3">
            {[
              'Name the new service policy',
              'Select action: Allow or Deny',
              'Prefix set auto-attached as source IP match',
              'Policy created in same namespace',
              'Attach to LBs in a separate step',
            ].map((s, i) => (
              <div key={i} className="flex items-start gap-2 text-sm text-slate-300">
                <div className="w-5 h-5 rounded-full bg-emerald-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-[10px] font-bold text-emerald-400">{i + 1}</span>
                </div>
                {s}
              </div>
            ))}
          </div>
        </div>
        <div className="bg-blue-500/5 border border-blue-500/30 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <Link2Icon className="w-5 h-5 text-blue-400" />
            <h3 className="font-semibold text-blue-400">Attach to Existing Policy</h3>
          </div>
          <div className="space-y-3">
            {[
              'Browse existing service policies in the namespace',
              'Preview current policy rules before modification',
              'Add prefix set as a new rule in the policy',
              'Choose rule position (first, last, or specific index)',
              'Existing rules remain unchanged',
            ].map((s, i) => (
              <div key={i} className="flex items-start gap-2 text-sm text-slate-300">
                <div className="w-5 h-5 rounded-full bg-blue-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-[10px] font-bold text-blue-400">{i + 1}</span>
                </div>
                {s}
              </div>
            ))}
          </div>
        </div>
      </div>
      <div className="mt-5 bg-amber-500/10 border border-amber-500/30 rounded-lg p-4">
        <div className="flex items-center gap-2 text-amber-400 text-sm font-semibold mb-1">
          <AlertTriangle className="w-4 h-4" /> Policy attachment is optional
        </div>
        <p className="text-xs text-slate-400">
          You can skip policy attachment and create only the prefix sets. Attach them to service policies later through the F5 XC console or by running this tool again.
        </p>
      </div>
    </div>
  )},

  /* Slide 4 - Execution */
  { title: 'Execution', component: () => (
    <div>
      <SlideTitle icon={Zap} title="Execution & Results" subtitle="Chunked creation with progress tracking and detailed result reporting" />
      <StepList steps={[
        { icon: Check, title: 'Validation Pass', desc: 'All IP entries are re-validated. Invalid entries are rejected with specific error messages. Valid entries proceed to creation.', color: 'bg-blue-500' },
        { icon: Layers, title: 'Chunked Creation', desc: 'Large prefix sets are split into chunks of 256 entries each (F5 XC API limit). Each chunk is sent as a separate API call with retry logic.', color: 'bg-emerald-500' },
        { icon: Shield, title: 'Policy Attachment', desc: 'If a policy was configured, the prefix set is attached after successful creation. Policy creation/update happens in a separate API call.', color: 'bg-amber-500' },
        { icon: BarChart2, title: 'Results Summary', desc: 'Detailed results showing: total prefix sets created, total IPs added, any failed entries, and policy attachment status.', color: 'bg-violet-500' },
      ]} />
      <div className="mt-6 grid grid-cols-3 gap-4">
        <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-4 text-center">
          <Check className="w-6 h-6 text-emerald-400 mx-auto mb-1" />
          <div className="text-lg font-bold text-emerald-400">Created</div>
          <div className="text-xs text-slate-500">Prefix set exists in F5 XC</div>
        </div>
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4 text-center">
          <AlertTriangle className="w-6 h-6 text-amber-400 mx-auto mb-1" />
          <div className="text-lg font-bold text-amber-400">Partial</div>
          <div className="text-xs text-slate-500">Some entries skipped (invalid)</div>
        </div>
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-center">
          <X className="w-6 h-6 text-red-400 mx-auto mb-1" />
          <div className="text-lg font-bold text-red-400">Failed</div>
          <div className="text-xs text-slate-500">API error with retry details</div>
        </div>
      </div>
    </div>
  )},
];

/* Link2 icon stand-in (using GitBranch since Link2 is not in the available set) */
const Link2Icon = GitBranch;

export function PrefixBuilderExplainer() {
  return <Slideshow slides={prefixBuilderSlides} toolName="Prefix Builder" toolRoute="/prefix-builder" toolIcon={Grid3X3} />;
}

// ═══════════════════════════════════════════════════════════════════
// TOOL 15: COPY CONFIG
// ═══════════════════════════════════════════════════════════════════

const copyConfigSlides: SlideDefinition[] = [
  /* Slide 1 - Overview */
  { title: 'Overview', component: () => (
    <div>
      <SlideTitle icon={Copy} title="Copy Config" subtitle="Copy configuration objects across tenants and namespaces" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        <FeatureCard icon={Copy} title="Cross-Tenant Copy" description="Copy alert receivers, alert policies, and CDN cache rules from one F5 XC tenant to another. Essential for managed service providers and multi-tenant environments." color="blue" />
        <FeatureCard icon={Split} title="Cross-Namespace Copy" description="Clone configuration objects between namespaces within the same tenant. Ideal for environment promotion workflows (dev to staging to production)." color="emerald" />
        <FeatureCard icon={Eye} title="Preview Before Copy" description="View the full JSON payload of each object before it is sent to the destination. Verify exactly what will be created." color="amber" />
        <FeatureCard icon={Check} title="Per-Object Status Tracking" description="Real-time status for each object: success, already exists, conflict, or failure with detailed error messages." color="violet" />
      </div>
      <div className="mt-6">
        <h3 className="text-sm font-semibold text-slate-300 mb-3">Supported Object Types</h3>
        <div className="grid grid-cols-3 gap-3">
          {[
            { type: 'Alert Receivers', desc: 'Slack, PagerDuty, email, webhook alert destinations', icon: Zap, color: 'text-blue-400 border-blue-500/30' },
            { type: 'Alert Policies', desc: 'Alert rules binding conditions to receivers', icon: AlertTriangle, color: 'text-amber-400 border-amber-500/30' },
            { type: 'CDN Cache Rules', desc: 'Cache TTL, bypass, and purge configurations', icon: Globe, color: 'text-emerald-400 border-emerald-500/30' },
          ].map(t => {
            const [text, border] = t.color.split(' ');
            return (
              <div key={t.type} className={`bg-slate-800/50 border ${border} rounded-xl p-4`}>
                <div className="flex items-center gap-2 mb-1">
                  <t.icon className={`w-4 h-4 ${text}`} />
                  <div className={`font-semibold text-sm ${text}`}>{t.type}</div>
                </div>
                <p className="text-xs text-slate-400">{t.desc}</p>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  )},

  /* Slide 2 - Object Selection */
  { title: 'Object Selection', component: () => (
    <div>
      <SlideTitle icon={Search} title="Object Selection" subtitle="Browse, search, preview, and select objects for copying" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Source Selection</h3>
          <StepList steps={[
            { icon: Globe, title: 'Choose Source Tenant', desc: 'Enter source tenant name and API token. The tool validates the connection before proceeding.', color: 'bg-blue-500' },
            { icon: Database, title: 'Select Namespace', desc: 'Pick the source namespace. For shared/system objects, the "shared" namespace is used automatically.', color: 'bg-emerald-500' },
            { icon: Layers, title: 'Pick Object Type', desc: 'Select which type of objects to copy: Alert Receivers, Alert Policies, or CDN Cache Rules.', color: 'bg-amber-500' },
            { icon: Check, title: 'Select Objects', desc: 'Browse the list with search/filter. Toggle individual objects or select all. Preview JSON for any object.', color: 'bg-violet-500' },
          ]} />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Destination Setup</h3>
          <div className="space-y-3">
            {[
              { label: 'Same Tenant', desc: 'Copy between namespaces. Only namespace field changes in the payload.', icon: Split, active: true },
              { label: 'Different Tenant', desc: 'Enter destination tenant + token. Full payload transformation applied.', icon: Globe, active: true },
            ].map(d => (
              <div key={d.label} className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
                <div className="flex items-center gap-2 mb-2">
                  <d.icon className="w-5 h-5 text-blue-400" />
                  <h4 className="font-semibold text-slate-200">{d.label}</h4>
                </div>
                <p className="text-sm text-slate-400">{d.desc}</p>
              </div>
            ))}
          </div>
          <div className="mt-4 bg-slate-800/50 border border-slate-700 rounded-xl p-4">
            <h4 className="text-sm font-semibold text-slate-300 mb-2">Multi-Select</h4>
            <div className="flex flex-wrap gap-2">
              {['Select All', 'Deselect All', 'Invert Selection', 'Filter by Name'].map(a => (
                <span key={a} className="text-xs bg-blue-500/10 text-blue-400 border border-blue-500/30 px-2.5 py-1 rounded-md">{a}</span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )},

  /* Slide 3 - Payload Preparation */
  { title: 'Payload Preparation', component: () => (
    <div>
      <SlideTitle icon={Settings} title="Smart Payload Transformation" subtitle="Automatic namespace and metadata updates for the destination" />
      <div className="mt-8">
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
          <div className="bg-slate-700/50 px-5 py-3 border-b border-slate-700">
            <h3 className="text-sm font-semibold text-slate-200">Transformation Rules</h3>
          </div>
          <div className="divide-y divide-slate-700">
            {[
              { rule: 'Namespace Update', desc: 'The metadata.namespace field is replaced with the destination namespace', from: '"namespace": "source-ns"', to: '"namespace": "dest-ns"', color: 'text-blue-400' },
              { rule: 'Metadata Cleanup', desc: 'System-generated fields (uid, creation_timestamp, modification_timestamp, resource_version) are removed', from: '"uid": "abc-123", "resource_version": "42"', to: '(removed)', color: 'text-emerald-400' },
              { rule: 'Tenant Reference Update', desc: 'Any tenant-specific references in the spec are updated to point to the destination tenant', from: '"tenant": "source-tenant"', to: '"tenant": "dest-tenant"', color: 'text-amber-400' },
              { rule: 'Label Preservation', desc: 'All user-defined labels and annotations are preserved in the copied object', from: '"labels": {"team": "security"}', to: '"labels": {"team": "security"}', color: 'text-violet-400' },
            ].map(r => (
              <div key={r.rule} className="px-5 py-4">
                <div className={`font-semibold text-sm ${r.color} mb-1`}>{r.rule}</div>
                <p className="text-xs text-slate-400 mb-2">{r.desc}</p>
                <div className="flex gap-3">
                  <div className="flex-1 bg-red-500/5 border border-red-500/20 rounded p-2">
                    <div className="text-[10px] text-red-400 font-semibold mb-0.5">Before</div>
                    <code className="text-[11px] text-slate-400 font-mono">{r.from}</code>
                  </div>
                  <div className="flex items-center"><ChevronRight className="w-4 h-4 text-slate-500" /></div>
                  <div className="flex-1 bg-emerald-500/5 border border-emerald-500/20 rounded p-2">
                    <div className="text-[10px] text-emerald-400 font-semibold mb-0.5">After</div>
                    <code className="text-[11px] text-slate-400 font-mono">{r.to}</code>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )},

  /* Slide 4 - Execution */
  { title: 'Execution', component: () => (
    <div>
      <SlideTitle icon={Zap} title="Batch Execution & Results" subtitle="Sequential copy with per-object status tracking" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Execution Flow</h3>
          <StepList steps={[
            { icon: Check, title: 'Pre-Flight Check', desc: 'Validates destination connection, namespace exists, and checks for name conflicts before starting.', color: 'bg-blue-500' },
            { icon: Copy, title: 'Sequential Copy', desc: 'Objects are copied one at a time with a brief delay between calls. Progress bar shows completion percentage.', color: 'bg-emerald-500' },
            { icon: AlertTriangle, title: 'Conflict Handling', desc: 'If an object with the same name exists, it is reported as "already exists" and skipped. No overwrites.', color: 'bg-amber-500' },
            { icon: BarChart2, title: 'Summary Report', desc: 'Final tally: created, skipped (exists), and failed with error details for each object.', color: 'bg-violet-500' },
          ]} />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Per-Object Status</h3>
          <div className="space-y-2.5">
            {[
              { name: 'slack-alerts-receiver', status: 'Created', color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30', icon: Check },
              { name: 'pagerduty-critical', status: 'Created', color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30', icon: Check },
              { name: 'email-ops-team', status: 'Already Exists', color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30', icon: AlertTriangle },
              { name: 'webhook-siem-forward', status: 'Created', color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30', icon: Check },
              { name: 'custom-receiver-v2', status: 'Failed', color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30', icon: X },
            ].map(o => (
              <div key={o.name} className={`flex items-center gap-3 ${o.bg} border rounded-lg p-3`}>
                <o.icon className={`w-4 h-4 ${o.color} flex-shrink-0`} />
                <div className="flex-1">
                  <span className="text-sm font-mono text-slate-300">{o.name}</span>
                </div>
                <span className={`text-xs font-semibold ${o.color}`}>{o.status}</span>
              </div>
            ))}
          </div>
          <div className="mt-4 bg-slate-800/50 border border-slate-700 rounded-lg p-3">
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-400">Total: 5 objects</span>
              <div className="flex gap-3">
                <span className="text-emerald-400">3 created</span>
                <span className="text-amber-400">1 skipped</span>
                <span className="text-red-400">1 failed</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )},
];

export function CopyConfigExplainer() {
  return <Slideshow slides={copyConfigSlides} toolName="Copy Config" toolRoute="/copy-config" toolIcon={Copy} />;
}

// ═══════════════════════════════════════════════════════════════════
// TOOL 16: PROPERTY VIEWER
// ═══════════════════════════════════════════════════════════════════

const propertyViewerSlides: SlideDefinition[] = [
  /* Slide 1 - Overview */
  { title: 'Overview', component: () => (
    <div>
      <SlideTitle icon={Layers} title="Property Viewer" subtitle="View any property across all config objects at a glance" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        <FeatureCard icon={Layers} title="5 Object Types" description="Inspect properties across HTTP Load Balancers, TCP LBs, Origin Pools, WAF Policies, and Service Policies. Select one or more types per scan." color="blue" />
        <FeatureCard icon={Eye} title="45+ Properties" description="Deep property extraction covering WAF mode, TLS version, timeouts, health checks, cert expiry, bot settings, rate limits, and many more." color="emerald" />
        <FeatureCard icon={BarChart2} title="Value Distribution" description="Instantly see how many objects have each value. For example: 12 LBs on TLSv1.3, 3 on TLSv1.2, 1 with no TLS configured." color="amber" />
        <FeatureCard icon={FileJson} title="Multi-Format Export" description="Export results as CSV, Excel, or JSON for compliance reporting, change management, or configuration audits." color="violet" />
      </div>
      <div className="mt-6 grid grid-cols-5 gap-2">
        {[
          { type: 'HTTP LB', count: '~20 props', color: 'text-blue-400 border-blue-500/30' },
          { type: 'TCP LB', count: '~10 props', color: 'text-emerald-400 border-emerald-500/30' },
          { type: 'Origin Pool', count: '~8 props', color: 'text-amber-400 border-amber-500/30' },
          { type: 'WAF Policy', count: '~5 props', color: 'text-red-400 border-red-500/30' },
          { type: 'Service Policy', count: '~5 props', color: 'text-violet-400 border-violet-500/30' },
        ].map(t => {
          const [text, border] = t.color.split(' ');
          return (
            <div key={t.type} className={`bg-slate-800/50 border ${border} rounded-lg p-3 text-center`}>
              <div className={`text-sm font-semibold ${text}`}>{t.type}</div>
              <div className="text-xs text-slate-500 mt-0.5">{t.count}</div>
            </div>
          );
        })}
      </div>
    </div>
  )},

  /* Slide 2 - Property Extraction */
  { title: 'Property Extraction', component: () => (
    <div>
      <SlideTitle icon={Search} title="Deep Property Extraction" subtitle="How properties are extracted from deeply nested F5 XC configuration specs" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Extraction Pipeline</h3>
          <StepList steps={[
            { icon: Server, title: 'Fetch Objects', desc: 'Retrieves all objects of the selected type(s) from the chosen namespace(s) via the F5 XC API.', color: 'bg-blue-500' },
            { icon: Search, title: 'Navigate Spec Tree', desc: 'Traverses the deeply nested JSON spec to locate each property. Handles union types and optional fields gracefully.', color: 'bg-emerald-500' },
            { icon: Filter, title: 'Normalize Values', desc: 'Converts raw API values to human-readable labels: enum codes to names, timestamps to dates, booleans to Yes/No.', color: 'bg-amber-500' },
            { icon: BarChart2, title: 'Aggregate & Display', desc: 'Groups results by value and computes distribution statistics. Renders in table or card view.', color: 'bg-violet-500' },
          ]} />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Sample Properties (HTTP LB)</h3>
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
            <div className="divide-y divide-slate-700">
              {[
                { prop: 'WAF Mode', path: 'spec.app_firewall.mode', example: 'BLOCKING' },
                { prop: 'TLS Minimum Version', path: 'spec.https.tls_parameters.minimum_version', example: 'TLSv1.2' },
                { prop: 'Idle Timeout', path: 'spec.idle_timeout', example: '120000ms' },
                { prop: 'Bot Defense', path: 'spec.bot_defense.policy', example: 'Enabled' },
                { prop: 'API Discovery', path: 'spec.api_discovery.enable', example: 'true' },
                { prop: 'DDoS Mitigation', path: 'spec.ddos_mitigation.auto_mitigation', example: 'Enabled' },
                { prop: 'Malicious User Detection', path: 'spec.malicious_user_detection', example: 'Disabled' },
                { prop: 'CORS Policy', path: 'spec.cors_policy', example: 'Configured' },
              ].map(p => (
                <div key={p.prop} className="px-4 py-2.5 flex items-center justify-between">
                  <div>
                    <div className="text-sm text-slate-200">{p.prop}</div>
                    <div className="text-[10px] font-mono text-slate-600">{p.path}</div>
                  </div>
                  <span className="text-xs font-mono bg-slate-700/50 text-slate-300 px-2 py-0.5 rounded">{p.example}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )},

  /* Slide 3 - Views & Filtering */
  { title: 'Views', component: () => (
    <div>
      <SlideTitle icon={Grid3X3} title="Table & Card Views" subtitle="Switch between views and filter by value distribution" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Table View</h3>
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
            <div className="bg-slate-700/30 px-4 py-2 border-b border-slate-700 flex gap-8 text-xs font-semibold text-slate-400">
              <span className="w-32">Object Name</span>
              <span className="w-24">Namespace</span>
              <span className="flex-1">WAF Mode</span>
            </div>
            {[
              { name: 'web-frontend', ns: 'production', value: 'BLOCKING', color: 'text-emerald-400' },
              { name: 'api-gateway', ns: 'production', value: 'BLOCKING', color: 'text-emerald-400' },
              { name: 'staging-app', ns: 'staging', value: 'MONITORING', color: 'text-amber-400' },
              { name: 'dev-test-lb', ns: 'development', value: 'No WAF', color: 'text-red-400' },
              { name: 'internal-api', ns: 'production', value: 'BLOCKING', color: 'text-emerald-400' },
            ].map(r => (
              <div key={r.name} className="px-4 py-2.5 border-b border-slate-700/50 flex gap-8 text-xs">
                <span className="w-32 font-mono text-slate-300">{r.name}</span>
                <span className="w-24 text-slate-500">{r.ns}</span>
                <span className={`flex-1 font-semibold ${r.color}`}>{r.value}</span>
              </div>
            ))}
          </div>
        </div>
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Distribution Filter</h3>
          <div className="space-y-3">
            {[
              { value: 'BLOCKING', count: 3, total: 5, color: 'bg-emerald-500', text: 'text-emerald-400' },
              { value: 'MONITORING', count: 1, total: 5, color: 'bg-amber-500', text: 'text-amber-400' },
              { value: 'No WAF', count: 1, total: 5, color: 'bg-red-500', text: 'text-red-400' },
            ].map(d => (
              <div key={d.value} className="bg-slate-800/50 border border-slate-700 rounded-lg p-3">
                <div className="flex items-center justify-between mb-2">
                  <span className={`text-sm font-semibold ${d.text}`}>{d.value}</span>
                  <span className="text-xs text-slate-500">{d.count} / {d.total} ({Math.round(d.count / d.total * 100)}%)</span>
                </div>
                <div className="bg-slate-700 rounded-full h-2.5 overflow-hidden">
                  <div className={`${d.color} h-full rounded-full`} style={{ width: `${(d.count / d.total) * 100}%` }} />
                </div>
              </div>
            ))}
          </div>
          <div className="mt-4 bg-blue-500/10 border border-blue-500/30 rounded-lg p-3">
            <p className="text-xs text-slate-400">
              <span className="text-blue-400 font-semibold">Click any value</span> in the distribution to filter the table to only objects with that value. Click again to clear the filter.
            </p>
          </div>
        </div>
      </div>
    </div>
  )},

  /* Slide 4 - Export */
  { title: 'Export', component: () => (
    <div>
      <SlideTitle icon={FileJson} title="Multi-Format Export" subtitle="Download property data as CSV, Excel, or JSON" />
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mt-8">
        {[
          {
            format: 'CSV',
            icon: FileJson,
            color: 'blue',
            desc: 'Comma-separated values file. One row per object with columns for name, namespace, and every selected property value.',
            useCase: 'Import into spreadsheets, databases, or scripts for further analysis.',
          },
          {
            format: 'Excel (.xlsx)',
            icon: Layers,
            color: 'emerald',
            desc: 'Formatted Excel workbook with header row, column widths auto-fitted, and conditional formatting for key values.',
            useCase: 'Share with stakeholders, attach to compliance reports, or use for change management.',
          },
          {
            format: 'JSON',
            icon: FileJson,
            color: 'amber',
            desc: 'Structured JSON array of objects. Each entry includes metadata (name, namespace) and all extracted property values.',
            useCase: 'Programmatic consumption, CI/CD pipeline integration, or config-as-code workflows.',
          },
        ].map(f => {
          const colors: Record<string, string> = {
            blue: 'text-blue-400 border-blue-500/30 bg-blue-500/5',
            emerald: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/5',
            amber: 'text-amber-400 border-amber-500/30 bg-amber-500/5',
          };
          const c = colors[f.color] || colors.blue;
          const [text, border, bg] = c.split(' ');
          return (
            <div key={f.format} className={`${bg} border ${border} rounded-xl p-5`}>
              <div className="flex items-center gap-2 mb-3">
                <f.icon className={`w-5 h-5 ${text}`} />
                <h3 className={`font-semibold ${text}`}>{f.format}</h3>
              </div>
              <p className="text-sm text-slate-400 mb-3">{f.desc}</p>
              <div className="bg-slate-800/50 rounded-lg p-2.5">
                <div className="text-xs text-slate-500 font-semibold mb-0.5">Best For</div>
                <div className="text-xs text-slate-300">{f.useCase}</div>
              </div>
            </div>
          );
        })}
      </div>
      <div className="mt-6 bg-slate-800/50 border border-slate-700 rounded-xl p-5">
        <h3 className="text-sm font-semibold text-slate-300 mb-3">Export Includes</h3>
        <div className="flex flex-wrap gap-3">
          {['Object Name', 'Namespace', 'All Selected Properties', 'Value Distribution Summary', 'Scan Timestamp', 'Object Count'].map(item => (
            <span key={item} className="flex items-center gap-1 text-xs bg-slate-700/50 text-slate-300 px-2.5 py-1.5 rounded-md">
              <Check className="w-3 h-3 text-emerald-400" /> {item}
            </span>
          ))}
        </div>
      </div>
    </div>
  )},
];

export function PropertyViewerExplainer() {
  return <Slideshow slides={propertyViewerSlides} toolName="Property Viewer" toolRoute="/property-viewer" toolIcon={Layers} />;
}

// ═══════════════════════════════════════════════════════════════════
// TOOL 17: HTTP LB FORGE
// ═══════════════════════════════════════════════════════════════════

const httpLbForgeSlides: SlideDefinition[] = [
  /* Slide 1 - Overview */
  { title: 'Overview', component: () => (
    <div>
      <SlideTitle icon={Hammer} title="HTTP LB Forge" subtitle="Create multiple HTTP Load Balancers at scale from a CSV template" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        <FeatureCard icon={Hammer} title="CSV-Driven Bulk Creation" description="Define multiple load balancers in a CSV file with domain, origin, type, and WAF settings. Create them all in one operation with no console clicks." color="blue" />
        <FeatureCard icon={Lock} title="Auto Certificate Discovery" description="Automatically matches existing TLS certificates to domains. Falls back to creating new certs if no match is found. Handles HTTP and HTTPS types." color="emerald" />
        <FeatureCard icon={Server} title="Origin Pool Generation" description="Creates origin pools alongside each LB. Specify origin servers, ports, and health check settings in your CSV." color="amber" />
        <FeatureCard icon={Shield} title="WAF Auto-Assignment" description="Optionally assigns an existing WAF policy to all created LBs, ensuring security protection from day one." color="red" />
      </div>
      <div className="mt-6">
        <h3 className="text-sm font-semibold text-slate-300 mb-3">3 Load Balancer Types</h3>
        <div className="grid grid-cols-3 gap-3">
          {[
            { type: 'HTTPS (Auto-Cert)', desc: 'F5 XC provisions and manages the TLS certificate automatically via Let\'s Encrypt', icon: Lock, color: 'text-emerald-400 border-emerald-500/30' },
            { type: 'HTTPS (Custom Cert)', desc: 'Uses an existing certificate from your tenant\'s certificate store, matched by domain', icon: Shield, color: 'text-blue-400 border-blue-500/30' },
            { type: 'HTTP Only', desc: 'No TLS termination. Plain HTTP with optional redirect-to-HTTPS rule', icon: Globe, color: 'text-amber-400 border-amber-500/30' },
          ].map(t => {
            const [text, border] = t.color.split(' ');
            return (
              <div key={t.type} className={`bg-slate-800/50 border ${border} rounded-xl p-4`}>
                <div className="flex items-center gap-2 mb-1">
                  <t.icon className={`w-4 h-4 ${text}`} />
                  <div className={`font-semibold text-sm ${text}`}>{t.type}</div>
                </div>
                <p className="text-xs text-slate-400">{t.desc}</p>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  )},

  /* Slide 2 - Validation */
  { title: 'Validation', component: () => (
    <div>
      <SlideTitle icon={Check} title="Pre-Flight Validation" subtitle="Every row is checked before any API calls are made" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Per-Row Validation Checks</h3>
          <div className="space-y-2.5">
            {[
              { check: 'Domain Format', desc: 'Valid hostname with proper TLD. No wildcards unless explicitly supported.', pass: true },
              { check: 'Origin Server', desc: 'Valid IP address or resolvable hostname for the origin server.', pass: true },
              { check: 'Port Number', desc: 'Valid port (1-65535). Defaults to 443 for HTTPS, 80 for HTTP.', pass: true },
              { check: 'LB Type', desc: 'Must be one of: https-auto, https-custom, http. Case insensitive.', pass: true },
              { check: 'Certificate Match', desc: 'For https-custom type, verifies a matching cert exists in the tenant.', pass: false },
              { check: 'WAF Policy', desc: 'If specified, verifies the WAF policy exists in the target namespace.', pass: true },
              { check: 'Name Uniqueness', desc: 'Generated LB name must not conflict with an existing LB in the namespace.', pass: true },
            ].map(c => (
              <div key={c.check} className="flex items-center gap-3 bg-slate-800/50 border border-slate-700 rounded-lg p-3">
                {c.pass ? (
                  <Check className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                ) : (
                  <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />
                )}
                <div className="flex-1">
                  <div className="text-sm text-slate-200">{c.check}</div>
                  <div className="text-xs text-slate-500">{c.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Certificate Discovery</h3>
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 space-y-4">
            <p className="text-sm text-slate-400">
              For <span className="text-blue-400 font-semibold">https-custom</span> type LBs, the Forge searches your tenant for a matching certificate:
            </p>
            <StepList steps={[
              { icon: Search, title: 'List All Certificates', desc: 'Fetches every certificate in the target namespace from the F5 XC cert store.', color: 'bg-blue-500' },
              { icon: Globe, title: 'Match by Domain', desc: 'Compares each cert\'s SAN (Subject Alternative Names) against the LB domain. Supports exact match and wildcard.', color: 'bg-emerald-500' },
              { icon: Check, title: 'Verify Validity', desc: 'Checks that the matched certificate is not expired and has at least 30 days remaining.', color: 'bg-amber-500' },
            ]} />
          </div>
          <div className="mt-4 bg-slate-800/50 border border-slate-700 rounded-xl p-4">
            <h4 className="text-xs text-slate-400 font-semibold mb-2">Domain Parsing Examples</h4>
            <div className="space-y-1">
              {[
                { domain: 'www.example.com', matches: '*.example.com, www.example.com' },
                { domain: 'api.v2.example.com', matches: '*.v2.example.com, api.v2.example.com' },
                { domain: 'example.com', matches: 'example.com, *.example.com' },
              ].map(d => (
                <div key={d.domain} className="flex items-center gap-2 text-xs">
                  <span className="font-mono text-blue-400 w-40">{d.domain}</span>
                  <ChevronRight className="w-3 h-3 text-slate-600" />
                  <span className="text-slate-400">{d.matches}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )},

  /* Slide 3 - Execution Pipeline */
  { title: 'Execution', component: () => (
    <div>
      <SlideTitle icon={Zap} title="3-Phase Execution Pipeline" subtitle="Origin Pools, then WAF attachment, then Load Balancers" />
      <div className="mt-8">
        <div className="grid grid-cols-3 gap-4">
          {[
            {
              phase: 'Phase 1: Origin Pools',
              icon: Server,
              color: 'blue',
              items: [
                'Create origin pool per CSV row',
                'Set origin server IP/hostname',
                'Configure port and protocol',
                'Attach health checks if specified',
                'Pool name derived from domain',
              ],
            },
            {
              phase: 'Phase 2: WAF Policy',
              icon: Shield,
              color: 'amber',
              items: [
                'Look up specified WAF policy',
                'Validate policy exists and is active',
                'Prepare WAF reference for LB spec',
                'Skip if no WAF specified in CSV',
                'Same policy shared across all LBs',
              ],
            },
            {
              phase: 'Phase 3: Load Balancers',
              icon: Hammer,
              color: 'emerald',
              items: [
                'Create HTTP LB with domain config',
                'Attach origin pool from Phase 1',
                'Configure TLS / cert from validation',
                'Attach WAF reference from Phase 2',
                'Set advertise policy and routing',
              ],
            },
          ].map((p, idx) => {
            const colors: Record<string, string> = {
              blue: 'text-blue-400 border-blue-500/30 bg-blue-500/5',
              amber: 'text-amber-400 border-amber-500/30 bg-amber-500/5',
              emerald: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/5',
            };
            const c = colors[p.color] || colors.blue;
            const [text, border, bg] = c.split(' ');
            return (
              <div key={p.phase} className={`${bg} border ${border} rounded-xl p-5`}>
                <div className="flex items-center gap-2 mb-1">
                  <div className={`w-6 h-6 rounded-full bg-slate-700 flex items-center justify-center`}>
                    <span className="text-xs font-bold text-slate-300">{idx + 1}</span>
                  </div>
                  <p.icon className={`w-5 h-5 ${text}`} />
                </div>
                <h3 className={`font-semibold ${text} mb-3`}>{p.phase}</h3>
                <ul className="space-y-2">
                  {p.items.map(item => (
                    <li key={item} className="flex items-start gap-2 text-xs text-slate-300">
                      <Check className={`w-3 h-3 ${text} mt-0.5 flex-shrink-0`} /> {item}
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>
        <div className="mt-5 bg-slate-800/50 border border-slate-700 rounded-lg p-4">
          <div className="flex items-center gap-2 text-sm text-slate-300 mb-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <span className="font-semibold">Rollback Behavior</span>
          </div>
          <p className="text-xs text-slate-400">
            If an LB creation fails in Phase 3, the origin pool from Phase 1 is NOT rolled back (it may be useful independently).
            Failed rows are reported with full error details so you can fix the CSV and re-run for just the failed entries.
          </p>
        </div>
      </div>
    </div>
  )},

  /* Slide 4 - Results */
  { title: 'Results', component: () => (
    <div>
      <SlideTitle icon={BarChart2} title="Results & Diagnostics" subtitle="VIP/CNAME details, step indicators, and error reporting for each LB" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Per-Row Results</h3>
          <div className="space-y-3">
            {[
              {
                domain: 'www.example.com',
                vip: '5.6.7.8',
                cname: 'ves-io-abcdef.ac.vh.ves.io',
                steps: [true, true, true],
                status: 'success',
              },
              {
                domain: 'api.example.com',
                vip: '5.6.7.9',
                cname: 'ves-io-ghijkl.ac.vh.ves.io',
                steps: [true, true, true],
                status: 'success',
              },
              {
                domain: 'staging.example.com',
                vip: '-',
                cname: '-',
                steps: [true, false, false],
                status: 'failed',
              },
            ].map(r => (
              <div key={r.domain} className={`bg-slate-800/50 border rounded-xl p-4 ${r.status === 'success' ? 'border-emerald-500/20' : 'border-red-500/20'}`}>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-sm text-slate-200">{r.domain}</span>
                  <span className={`text-xs font-semibold ${r.status === 'success' ? 'text-emerald-400' : 'text-red-400'}`}>
                    {r.status.toUpperCase()}
                  </span>
                </div>
                <div className="flex items-center gap-3 mb-2">
                  <div className="flex items-center gap-1">
                    <span className="text-[10px] text-slate-500">Steps:</span>
                    {['Pool', 'WAF', 'LB'].map((step, i) => (
                      <span key={step} className={`text-[10px] px-1.5 py-0.5 rounded ${r.steps[i] ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}`}>
                        {step} {r.steps[i] ? '\u2713' : '\u2717'}
                      </span>
                    ))}
                  </div>
                </div>
                {r.status === 'success' && (
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="bg-slate-900/50 rounded p-2">
                      <div className="text-slate-500">VIP</div>
                      <div className="font-mono text-slate-300">{r.vip}</div>
                    </div>
                    <div className="bg-slate-900/50 rounded p-2">
                      <div className="text-slate-500">CNAME</div>
                      <div className="font-mono text-slate-300 text-[10px]">{r.cname}</div>
                    </div>
                  </div>
                )}
                {r.status === 'failed' && (
                  <div className="bg-red-500/5 border border-red-500/20 rounded p-2 text-xs text-red-400">
                    Error: No matching certificate found for staging.example.com. Upload a cert or switch to https-auto type.
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Summary Stats</h3>
          <div className="grid grid-cols-2 gap-3 mb-5">
            {[
              { label: 'LBs Created', value: '2 / 3', color: 'text-emerald-400' },
              { label: 'Pools Created', value: '3 / 3', color: 'text-blue-400' },
              { label: 'WAF Attached', value: '2 / 3', color: 'text-amber-400' },
              { label: 'Certs Matched', value: '2 / 3', color: 'text-violet-400' },
            ].map(s => (
              <div key={s.label} className="bg-slate-800/60 border border-slate-700 rounded-lg p-3 text-center">
                <div className={`text-xl font-bold ${s.color}`}>{s.value}</div>
                <div className="text-xs text-slate-500 mt-0.5">{s.label}</div>
              </div>
            ))}
          </div>
          <h3 className="text-sm font-semibold text-slate-300 mb-3">Error Details</h3>
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4 space-y-3">
            <div className="flex items-start gap-3">
              <X className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
              <div>
                <div className="text-sm font-medium text-red-400">staging.example.com</div>
                <div className="text-xs text-slate-500 mt-0.5">Phase 2 failed: WAF policy "default-waf" not found in namespace "production"</div>
                <div className="text-xs text-slate-500 mt-1">
                  <span className="text-slate-400 font-semibold">Fix:</span> Verify the WAF policy name in your CSV matches an existing policy in the target namespace.
                </div>
              </div>
            </div>
          </div>
          <div className="mt-4 bg-blue-500/10 border border-blue-500/30 rounded-lg p-3">
            <div className="flex items-center gap-2 text-blue-400 text-sm font-semibold mb-1">
              <Hammer className="w-4 h-4" /> Re-Run Failed Rows
            </div>
            <p className="text-xs text-slate-400">
              Fix the issues in your CSV and re-upload. The Forge detects already-created objects and skips them, processing only the previously failed rows.
            </p>
          </div>
        </div>
      </div>
    </div>
  )},
];

export function HttpLbForgeExplainer() {
  return <Slideshow slides={httpLbForgeSlides} toolName="HTTP LB Forge" toolRoute="/http-lb-forge" toolIcon={Hammer} />;
}

// ═══════════════════════════════════════════════════════════════════
// TOOL 18: CONFIG DUMP
// ═══════════════════════════════════════════════════════════════════

const configDumpSlides: SlideDefinition[] = [
  /* Slide 1 - Overview */
  { title: 'Overview', component: () => (
    <div>
      <SlideTitle icon={Database} title="Config Dump" subtitle="Recursive configuration export with child resolution and multi-format output" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        <FeatureCard icon={Database} title="Recursive Export" description="Exports the complete configuration tree for any object type. Follows references to child objects (pools, WAFs, certs) and includes them in the dump." color="blue" />
        <FeatureCard icon={Layers} title="8 Object Categories" description="Supports HTTP LBs, TCP LBs, CDN distributions, origin pools, WAF policies, service policies, health checks, and certificates." color="emerald" />
        <FeatureCard icon={Globe} title="Multi-Namespace" description="Dump configurations across multiple namespaces in one operation. Useful for cross-environment documentation and backup." color="amber" />
        <FeatureCard icon={FileJson} title="4 Export Formats" description="Download as structured JSON (for automation), CSV (for spreadsheets), Excel (for reports), or PDF (for documentation and audits)." color="violet" />
      </div>
      <div className="mt-6 grid grid-cols-4 gap-3">
        {[
          { label: 'Object Categories', value: '8', color: 'text-blue-400' },
          { label: 'Child Resolution', value: 'Recursive', color: 'text-emerald-400' },
          { label: 'Export Formats', value: '4', color: 'text-amber-400' },
          { label: 'Namespaces', value: 'Multi', color: 'text-violet-400' },
        ].map(s => (
          <div key={s.label} className="bg-slate-800/60 border border-slate-700 rounded-lg p-3 text-center">
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-xs text-slate-500 mt-0.5">{s.label}</div>
          </div>
        ))}
      </div>
    </div>
  )},

  /* Slide 2 - Object Selection */
  { title: 'Object Selection', component: () => (
    <div>
      <SlideTitle icon={Layers} title="Object Selection" subtitle="Browse categories, filter by labels, and select objects for export" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Object Categories</h3>
          <div className="space-y-2">
            {[
              { cat: 'HTTP Load Balancers', count: 'Most common', icon: Globe, color: 'text-blue-400' },
              { cat: 'TCP Load Balancers', count: 'L4 objects', icon: Server, color: 'text-emerald-400' },
              { cat: 'CDN Distributions', count: 'Edge caching', icon: Globe, color: 'text-amber-400' },
              { cat: 'Origin Pools', count: 'Backend servers', icon: Server, color: 'text-violet-400' },
              { cat: 'WAF Policies', count: 'App firewalls', icon: Shield, color: 'text-red-400' },
              { cat: 'Service Policies', count: 'Access rules', icon: Lock, color: 'text-cyan-400' },
              { cat: 'Health Checks', count: 'Monitors', icon: Activity, color: 'text-blue-400' },
              { cat: 'Certificates', count: 'TLS certs', icon: Lock, color: 'text-emerald-400' },
            ].map(c => (
              <div key={c.cat} className="flex items-center gap-3 bg-slate-800/50 border border-slate-700 rounded-lg p-3">
                <c.icon className={`w-4 h-4 ${c.color} flex-shrink-0`} />
                <div className="flex-1">
                  <span className={`text-sm font-medium ${c.color}`}>{c.cat}</span>
                </div>
                <span className="text-xs text-slate-500">{c.count}</span>
              </div>
            ))}
          </div>
        </div>
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Filtering Options</h3>
          <div className="space-y-4">
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
              <div className="flex items-center gap-2 mb-3">
                <Filter className="w-4 h-4 text-blue-400" />
                <h4 className="font-semibold text-sm text-blue-400">Label Filter</h4>
              </div>
              <p className="text-sm text-slate-400 mb-3">
                Filter objects by F5 XC labels. Only objects matching all specified label key-value pairs are included in the dump.
              </p>
              <div className="space-y-1.5">
                {[
                  { label: 'env=production', desc: 'Only production objects' },
                  { label: 'team=platform', desc: 'Team-owned objects' },
                  { label: 'managed-by=terraform', desc: 'IaC-managed objects' },
                ].map(l => (
                  <div key={l.label} className="flex items-center gap-2 text-xs">
                    <span className="font-mono text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded">{l.label}</span>
                    <span className="text-slate-500">{l.desc}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
              <div className="flex items-center gap-2 mb-3">
                <Search className="w-4 h-4 text-emerald-400" />
                <h4 className="font-semibold text-sm text-emerald-400">Name Search</h4>
              </div>
              <p className="text-sm text-slate-400">
                Type-ahead search to quickly find specific objects by name. Supports partial matching and regex patterns.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )},

  /* Slide 3 - Recursive Fetch */
  { title: 'Recursive Fetch', component: () => (
    <div>
      <SlideTitle icon={GitBranch} title="Recursive Child Resolution" subtitle="How the dump follows references to build the complete configuration tree" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Resolution Pipeline</h3>
          <StepList steps={[
            { icon: Database, title: 'Fetch Parent Objects', desc: 'Retrieves all selected objects of the chosen category from the namespace. Respects label and name filters.', color: 'bg-blue-500' },
            { icon: Search, title: 'Scan for References', desc: 'Parses each object\'s spec to find references to child objects: origin pools, WAF policies, health checks, certificates.', color: 'bg-emerald-500' },
            { icon: Server, title: 'Fetch Children', desc: 'Recursively fetches each referenced child object. Handles cross-namespace references and avoids circular dependencies.', color: 'bg-amber-500' },
            { icon: GitBranch, title: 'Build Tree', desc: 'Assembles the complete dependency tree. Each parent node contains its children, forming a hierarchical export.', color: 'bg-violet-500' },
          ]} />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Example Dependency Tree</h3>
          <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 font-mono text-xs">
            <div className="space-y-1">
              {[
                { indent: 0, icon: Globe, text: 'web-frontend (HTTP LB)', color: 'text-blue-400' },
                { indent: 1, icon: Server, text: 'web-frontend-pool (Origin Pool)', color: 'text-emerald-400' },
                { indent: 2, icon: Activity, text: 'http-health-check (Health Check)', color: 'text-cyan-400' },
                { indent: 1, icon: Shield, text: 'default-waf (WAF Policy)', color: 'text-red-400' },
                { indent: 1, icon: Lock, text: '*.example.com (Certificate)', color: 'text-amber-400' },
                { indent: 1, icon: Lock, text: 'ip-allowlist (Service Policy)', color: 'text-violet-400' },
                { indent: 0, icon: Globe, text: 'api-gateway (HTTP LB)', color: 'text-blue-400' },
                { indent: 1, icon: Server, text: 'api-pool (Origin Pool)', color: 'text-emerald-400' },
                { indent: 2, icon: Activity, text: 'tcp-health-check (Health Check)', color: 'text-cyan-400' },
                { indent: 1, icon: Shield, text: 'default-waf (WAF Policy)', color: 'text-red-400' },
                { indent: 1, icon: Lock, text: 'api.example.com (Certificate)', color: 'text-amber-400' },
              ].map((n, i) => {
                const NodeIcon = n.icon;
                return (
                  <div key={i} className="flex items-center gap-1.5" style={{ paddingLeft: `${n.indent * 20}px` }}>
                    {n.indent > 0 && <span className="text-slate-600">{n.indent === 1 ? '\u251c\u2500' : '\u2502 \u251c\u2500'}</span>}
                    <NodeIcon className={`w-3 h-3 ${n.color}`} />
                    <span className={`${n.color}`}>{n.text}</span>
                  </div>
                );
              })}
            </div>
          </div>
          <div className="mt-3 bg-amber-500/10 border border-amber-500/30 rounded-lg p-3">
            <div className="flex items-center gap-2 text-amber-400 text-xs font-semibold mb-1">
              <AlertTriangle className="w-3 h-3" /> Shared Children
            </div>
            <p className="text-[11px] text-slate-400">
              When multiple parents reference the same child (e.g., shared WAF policy), it is included once and referenced by all parents to avoid duplicate data.
            </p>
          </div>
        </div>
      </div>
    </div>
  )},

  /* Slide 4 - Export Formats */
  { title: 'Export', component: () => (
    <div>
      <SlideTitle icon={FileJson} title="Export Formats" subtitle="Download the configuration dump in 4 formats" />
      <div className="grid grid-cols-2 gap-5 mt-8">
        {[
          {
            format: 'JSON Bundle',
            icon: FileJson,
            color: 'blue',
            desc: 'Complete hierarchical JSON with parent-child relationships preserved. Ideal for backup, automation, and programmatic access.',
            features: ['Full spec included', 'Child objects nested', 'Metadata preserved', 'Single file output'],
          },
          {
            format: 'CSV',
            icon: Layers,
            color: 'emerald',
            desc: 'Flattened tabular format with one row per object. Key properties extracted into columns for spreadsheet analysis.',
            features: ['One row per object', 'Key props as columns', 'Parent reference column', 'Quick filtering'],
          },
          {
            format: 'Excel Workbook',
            icon: BarChart2,
            color: 'amber',
            desc: 'Multi-sheet workbook with separate sheets per object type. Formatted headers, auto-width columns, and summary sheet.',
            features: ['Sheet per type', 'Formatted headers', 'Summary sheet', 'Column auto-fit'],
          },
          {
            format: 'PDF Report',
            icon: FileJson,
            color: 'violet',
            desc: 'Formatted documentation PDF with table of contents, object details, and dependency diagrams. Ready for compliance audits.',
            features: ['Table of contents', 'Object detail pages', 'Dependency graph', 'Branded layout'],
          },
        ].map(f => {
          const colors: Record<string, string> = {
            blue: 'text-blue-400 border-blue-500/30 bg-blue-500/5',
            emerald: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/5',
            amber: 'text-amber-400 border-amber-500/30 bg-amber-500/5',
            violet: 'text-violet-400 border-violet-500/30 bg-violet-500/5',
          };
          const c = colors[f.color] || colors.blue;
          const [text, border, bg] = c.split(' ');
          return (
            <div key={f.format} className={`${bg} border ${border} rounded-xl p-5`}>
              <div className="flex items-center gap-2 mb-2">
                <f.icon className={`w-5 h-5 ${text}`} />
                <h3 className={`font-semibold ${text}`}>{f.format}</h3>
              </div>
              <p className="text-sm text-slate-400 mb-3">{f.desc}</p>
              <div className="flex flex-wrap gap-1.5">
                {f.features.map(feat => (
                  <span key={feat} className="flex items-center gap-1 text-[11px] bg-slate-800/50 text-slate-300 px-2 py-1 rounded">
                    <Check className="w-2.5 h-2.5 text-emerald-400" /> {feat}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>
      <div className="mt-5 bg-slate-800/50 border border-slate-700 rounded-lg p-4">
        <div className="flex items-center gap-2 text-sm text-slate-300 mb-1">
          <Copy className="w-4 h-4 text-blue-400" />
          <span className="font-semibold">Clipboard Support</span>
        </div>
        <p className="text-xs text-slate-400">
          Copy any individual object's full JSON to clipboard with one click. Useful for quick pasting into Terraform, Postman, or other tools.
        </p>
      </div>
    </div>
  )},
];

export function ConfigDumpExplainer() {
  return <Slideshow slides={configDumpSlides} toolName="Config Dump" toolRoute="/config-dump" toolIcon={Database} />;
}
