/**
 * Explainer slideshow pages for all XC App Store tools (Part 1: Tools 1-9).
 * Uses the shared Slideshow component for consistent navigation.
 * Each tool has 4-6 slides explaining what it does, how it works, and key concepts.
 */

import {
  Shield, Search, ShieldAlert, Activity, Grid3X3, Split, GitBranch,
  Database, BarChart2, Zap, Copy, Layers, Hammer, Globe,
  Users, Target, Check, AlertTriangle, Eye, Lock, FileJson,
  TrendingUp, Filter, Settings, Cpu, Server, Bug, X, ChevronRight,
  Hash, Clock, Gauge,
} from 'lucide-react';
import { Slideshow, SlideTitle, FeatureCard, StepList } from '../components/Slideshow';
import type { SlideDefinition } from '../components/Slideshow';

// ═══════════════════════════════════════════════════════════════════
// TOOL 1: WAF SCANNER  (4 slides)
// ═══════════════════════════════════════════════════════════════════

const wafScannerSlides: SlideDefinition[] = [
  /* ── Slide 1: Overview ── */
  { title: 'WAF Status Scanner', component: () => (
    <div>
      <SlideTitle icon={Search} title="WAF Status Scanner" subtitle="Audit WAF protection across all your load balancers in seconds" />
      <p className="text-sm text-slate-400 mt-4 mb-6">
        Scans every HTTP load balancer in your selected namespaces to check WAF policy assignment, enforcement mode, and route-level overrides.
        Designed for security teams running periodic compliance checks or engineers validating post-deployment WAF coverage.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <FeatureCard icon={Search} title="Multi-Namespace Scan" description="Scans all HTTP load balancers across one or more namespaces in parallel. Automatic concurrency management handles rate limits." color="blue" />
        <FeatureCard icon={Shield} title="Mode Detection" description="Identifies Blocking (active protection), Monitoring (logging only), or No WAF for each LB. Includes shared WAF namespace resolution." color="emerald" />
        <FeatureCard icon={AlertTriangle} title="Gap Detection" description="Highlights load balancers missing WAF protection entirely -- the most critical security gaps in your deployment." color="red" />
        <FeatureCard icon={FileJson} title="Excel & JSON Export" description="Download full results as filtered Excel or JSON. Share with stakeholders or import into your compliance workflow." color="amber" />
      </div>
    </div>
  )},

  /* ── Slide 2: Workflow ── */
  { title: 'How to Use', component: () => (
    <div>
      <SlideTitle icon={Settings} title="Three-Step Workflow" subtitle="From namespace selection to actionable results" />
      <div className="mt-6">
        <StepList steps={[
          {
            icon: Filter,
            title: 'Select Namespaces',
            desc: 'Choose one or more namespaces from the dropdown. The scanner discovers all HTTP load balancers within each namespace automatically. A real-time ETA shows expected scan duration based on LB count.',
            color: 'bg-blue-500',
          },
          {
            icon: Search,
            title: 'Scan with Live Progress',
            desc: 'The scanner checks each LB\'s top-level WAF assignment, then inspects every route for overrides and shared-namespace references. Progress bar updates per-LB with adaptive concurrency (automatic retry on 429).',
            color: 'bg-emerald-500',
          },
          {
            icon: BarChart2,
            title: 'Filter & Review Results',
            desc: 'Results appear in a sortable table with mode badges (Blocking / Monitoring / None). Click filter chips to isolate unprotected LBs. Expand any row to see route-level WAF assignments and exclusion rule counts.',
            color: 'bg-amber-500',
          },
        ]} />
      </div>
    </div>
  )},

  /* ── Slide 3: Route-Level Analysis ── */
  { title: 'Route-Level Analysis', component: () => (
    <div>
      <SlideTitle icon={GitBranch} title="Route-Level WAF Analysis" subtitle="Understanding WAF inheritance, overrides, and shared namespaces" />
      <div className="space-y-4 mt-6">
        {/* Concept 1: Inheritance */}
        <div className="bg-slate-800/50 border border-blue-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-8 h-8 rounded-full bg-blue-500/20 flex items-center justify-center"><Layers className="w-4 h-4 text-blue-400" /></div>
            <h3 className="font-semibold text-blue-400">WAF Inheritance</h3>
          </div>
          <p className="text-sm text-slate-400">
            When a WAF policy is assigned at the LB level, all routes inherit it by default. The scanner checks whether each route
            actually uses the inherited policy or has its own override. A route with no WAF and no LB-level WAF is flagged as unprotected.
          </p>
        </div>
        {/* Concept 2: Route Override */}
        <div className="bg-slate-800/50 border border-amber-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-8 h-8 rounded-full bg-amber-500/20 flex items-center justify-center"><AlertTriangle className="w-4 h-4 text-amber-400" /></div>
            <h3 className="font-semibold text-amber-400">Route Override</h3>
          </div>
          <p className="text-sm text-slate-400">
            Individual routes can override the LB-level WAF with a different policy or disable WAF entirely. The scanner detects these
            overrides and reports the effective WAF mode per route -- not just the LB-level setting.
          </p>
        </div>
        {/* Concept 3: Shared Namespace */}
        <div className="bg-slate-800/50 border border-emerald-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-8 h-8 rounded-full bg-emerald-500/20 flex items-center justify-center"><Globe className="w-4 h-4 text-emerald-400" /></div>
            <h3 className="font-semibold text-emerald-400">Shared Namespace Lookup</h3>
          </div>
          <p className="text-sm text-slate-400">
            WAF policies can reside in the "shared" namespace and be referenced by LBs in other namespaces. The scanner automatically
            resolves cross-namespace references to report the actual WAF policy name and mode, not just the reference.
          </p>
        </div>
      </div>
    </div>
  )},

  /* ── Slide 4: Output ── */
  { title: 'Output & Export', component: () => (
    <div>
      <SlideTitle icon={BarChart2} title="Results Dashboard & Export" subtitle="Stat cards, filter badges, and multi-format export" />
      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 mb-6">
        {[
          { label: 'Total LBs', value: '42', color: 'text-slate-100', bg: 'bg-slate-700/50' },
          { label: 'Blocking', value: '28', color: 'text-emerald-400', bg: 'bg-emerald-500/10' },
          { label: 'Monitoring', value: '9', color: 'text-amber-400', bg: 'bg-amber-500/10' },
          { label: 'No WAF', value: '5', color: 'text-red-400', bg: 'bg-red-500/10' },
        ].map(s => (
          <div key={s.label} className={`${s.bg} border border-slate-700 rounded-xl p-4 text-center`}>
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-xs text-slate-400 mt-1">{s.label}</div>
          </div>
        ))}
      </div>
      {/* Filter Badges */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mb-5">
        <h4 className="font-semibold text-slate-200 text-sm mb-3">Filter Badges</h4>
        <div className="flex flex-wrap gap-2">
          {['All', 'Blocking', 'Monitoring', 'No WAF', 'Has Exclusions', 'Route Override'].map(b => (
            <span key={b} className="px-3 py-1.5 bg-slate-700/60 border border-slate-600 rounded-full text-xs text-slate-300">{b}</span>
          ))}
        </div>
        <p className="text-xs text-slate-500 mt-3">Click any badge to filter the results table instantly. Combine multiple filters for precise queries.</p>
      </div>
      {/* Export Formats */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
        <h4 className="font-semibold text-slate-200 text-sm mb-3">Export Formats</h4>
        <div className="grid grid-cols-2 gap-3">
          {[
            { fmt: 'Excel (.xlsx)', desc: 'Formatted workbook with color-coded WAF modes and route details per sheet' },
            { fmt: 'JSON', desc: 'Machine-readable output for automation pipelines and SIEM integration' },
          ].map(e => (
            <div key={e.fmt} className="flex items-start gap-2">
              <Check className="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0" />
              <div><span className="text-sm text-slate-200 font-medium">{e.fmt}</span><p className="text-xs text-slate-500">{e.desc}</p></div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )},
];
export function WAFScannerExplainer() { return <Slideshow slides={wafScannerSlides} toolName="WAF Scanner" toolRoute="/waf-scanner" toolIcon={Search} />; }


// ═══════════════════════════════════════════════════════════════════
// TOOL 2: SECURITY AUDITOR  (5 slides)
// ═══════════════════════════════════════════════════════════════════

const securityAuditorSlides: SlideDefinition[] = [
  /* ── Slide 1: Overview ── */
  { title: 'Security Auditor', component: () => (
    <div>
      <SlideTitle icon={Shield} title="Security Auditor" subtitle="Comprehensive security posture assessment against 50+ best-practice rules" />
      <p className="text-sm text-slate-400 mt-4 mb-6">
        Automatically audits your F5 XC configuration against a curated ruleset covering TLS, WAF, bot defence, DDoS, access control,
        API security, origin hardening, and operational readiness. Produces a scored report with prioritised findings and actionable remediation.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <FeatureCard icon={Shield} title="50+ Security Rules" description="Rules span 12 categories: TLS/SSL, WAF, Bot Defence, API Security, DDoS, Origin, Access Control, Logging, Alerting, User Identification, Rate Limiting, Client Security." color="blue" />
        <FeatureCard icon={Target} title="Scored Assessment" description="Each namespace receives a 0-100 security score calculated from finding severity weights. Track improvement over time." color="emerald" />
        <FeatureCard icon={AlertTriangle} title="Severity Classification" description="Findings are classified as Critical, High, Medium, Low, or Info. Critical and High findings lower the score significantly." color="red" />
        <FeatureCard icon={Settings} title="Actionable Remediation" description="Every finding includes specific remediation steps, the exact setting to change, and a reference URL to F5 XC documentation." color="amber" />
      </div>
    </div>
  )},

  /* ── Slide 2: 12 Rule Categories ── */
  { title: 'Rule Categories', component: () => (
    <div>
      <SlideTitle icon={Layers} title="12 Rule Categories" subtitle="What the auditor checks across your entire configuration" />
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mt-6">
        {[
          { cat: 'TLS/SSL', desc: 'HTTPS redirect, TLS version, cipher suites, certificate expiry, HSTS', color: 'border-blue-500/30 text-blue-400', rules: 'SEC-001 to SEC-005' },
          { cat: 'WAF', desc: 'Blocking mode enforcement, signature coverage, exclusion hygiene', color: 'border-emerald-500/30 text-emerald-400', rules: 'SEC-008 to SEC-010' },
          { cat: 'Bot Defence', desc: 'Bot protection enabled, challenge actions, JS insertion', color: 'border-amber-500/30 text-amber-400', rules: 'SEC-011' },
          { cat: 'DDoS Protection', desc: 'L7 DDoS auto-mitigation, threshold tuning, slow DDoS', color: 'border-red-500/30 text-red-400', rules: 'SEC-013' },
          { cat: 'API Security', desc: 'API discovery, schema validation, endpoint rate limiting', color: 'border-violet-500/30 text-violet-400', rules: 'SEC-012' },
          { cat: 'Origin Security', desc: 'Origin TLS, health checks, timeout configuration', color: 'border-cyan-500/30 text-cyan-400', rules: 'SEC-006 to SEC-007' },
          { cat: 'Access Control', desc: 'Service policies, IP allowlists, geo restrictions', color: 'border-blue-500/30 text-blue-400', rules: 'SEC-014 to SEC-016' },
          { cat: 'Rate Limiting', desc: 'Rate limit configuration, thresholds, response actions', color: 'border-emerald-500/30 text-emerald-400', rules: 'SEC-018' },
          { cat: 'Logging', desc: 'Access log streaming, global log receivers, SIEM integration', color: 'border-amber-500/30 text-amber-400', rules: 'SEC-022+' },
          { cat: 'Alerting', desc: 'Alert policies, notification receivers, escalation paths', color: 'border-red-500/30 text-red-400', rules: 'SEC-023+' },
          { cat: 'User Identification', desc: 'User tracking, session identification, MUD input', color: 'border-violet-500/30 text-violet-400', rules: 'SEC-019' },
          { cat: 'Client Security', desc: 'Client-side defence, JavaScript security, cookie settings', color: 'border-cyan-500/30 text-cyan-400', rules: 'SEC-020 to SEC-021' },
        ].map(c => (
          <div key={c.cat} className={`border ${c.color.split(' ')[0]} bg-slate-800/50 rounded-xl p-3.5`}>
            <div className={`font-semibold text-sm ${c.color.split(' ')[1]} mb-1`}>{c.cat}</div>
            <p className="text-xs text-slate-400 leading-relaxed">{c.desc}</p>
            <p className="text-[10px] text-slate-600 mt-2 font-mono">{c.rules}</p>
          </div>
        ))}
      </div>
    </div>
  )},

  /* ── Slide 3: Audit Configuration ── */
  { title: 'Audit Configuration', component: () => (
    <div>
      <SlideTitle icon={Filter} title="Configuring an Audit" subtitle="Namespace selection, category toggles, and severity filters" />
      <div className="mt-6 space-y-5">
        {/* Namespace Selection */}
        <div className="bg-slate-800/50 border border-blue-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <Globe className="w-5 h-5 text-blue-400" />
            <h3 className="font-semibold text-blue-400">Namespace Selection</h3>
          </div>
          <p className="text-sm text-slate-400">
            Choose one or more namespaces to audit. The engine fetches all relevant config objects (LBs, origin pools, WAF policies,
            certificates, service policies, health checks, alert policies, log receivers) from each namespace before running rules.
          </p>
        </div>
        {/* Category Toggles */}
        <div className="bg-slate-800/50 border border-emerald-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <Layers className="w-5 h-5 text-emerald-400" />
            <h3 className="font-semibold text-emerald-400">Category Toggles</h3>
          </div>
          <p className="text-sm text-slate-400 mb-3">
            Enable or disable entire rule categories. For example, disable "Alerting" if you manage alerts externally, or focus only on "WAF" and "TLS/SSL" for a targeted check.
          </p>
          <div className="flex flex-wrap gap-2">
            {['TLS/SSL', 'WAF', 'Bot Defence', 'DDoS', 'API Security', 'Origin', 'Access Control', 'Logging'].map(c => (
              <span key={c} className="px-2.5 py-1 bg-emerald-500/10 border border-emerald-500/30 rounded-full text-xs text-emerald-400">{c}</span>
            ))}
          </div>
        </div>
        {/* Severity Filter */}
        <div className="bg-slate-800/50 border border-amber-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
            <h3 className="font-semibold text-amber-400">Minimum Severity</h3>
          </div>
          <p className="text-sm text-slate-400">
            Set a minimum severity threshold (e.g., "High") to suppress lower-priority findings. Useful for executive summaries where only critical gaps matter.
          </p>
          <div className="flex gap-2 mt-3">
            {[
              { s: 'Critical', c: 'bg-red-500/20 text-red-400 border-red-500/30' },
              { s: 'High', c: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
              { s: 'Medium', c: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
              { s: 'Low', c: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
              { s: 'Info', c: 'bg-slate-500/20 text-slate-400 border-slate-500/30' },
            ].map(sv => (
              <span key={sv.s} className={`px-2.5 py-1 border rounded-full text-xs ${sv.c}`}>{sv.s}</span>
            ))}
          </div>
        </div>
      </div>
    </div>
  )},

  /* ── Slide 4: Results Dashboard ── */
  { title: 'Results Dashboard', component: () => (
    <div>
      <SlideTitle icon={BarChart2} title="Results Dashboard" subtitle="Score, findings table, severity breakdown, and export" />
      {/* Score + summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mt-6 mb-5">
        <div className="md:col-span-1 bg-slate-800/50 border border-blue-500/30 rounded-xl p-4 text-center flex flex-col justify-center">
          <div className="text-3xl font-bold text-blue-400">78</div>
          <div className="text-xs text-slate-400 mt-1">Security Score</div>
          <div className="text-[10px] text-slate-600">out of 100</div>
        </div>
        {[
          { label: 'Critical', val: '2', color: 'text-red-400', bg: 'bg-red-500/10' },
          { label: 'High', val: '5', color: 'text-orange-400', bg: 'bg-orange-500/10' },
          { label: 'Medium', val: '8', color: 'text-yellow-400', bg: 'bg-yellow-500/10' },
          { label: 'Passed', val: '35', color: 'text-emerald-400', bg: 'bg-emerald-500/10' },
        ].map(s => (
          <div key={s.label} className={`${s.bg} border border-slate-700 rounded-xl p-4 text-center`}>
            <div className={`text-2xl font-bold ${s.color}`}>{s.val}</div>
            <div className="text-xs text-slate-400 mt-1">{s.label}</div>
          </div>
        ))}
      </div>
      {/* Findings table preview */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden mb-5">
        <div className="grid grid-cols-12 gap-2 px-4 py-2.5 bg-slate-700/50 text-xs font-medium text-slate-400">
          <div className="col-span-1">Sev</div>
          <div className="col-span-2">Rule</div>
          <div className="col-span-3">Object</div>
          <div className="col-span-2">Status</div>
          <div className="col-span-4">Message</div>
        </div>
        {[
          { sev: 'CRITICAL', sevColor: 'text-red-400', rule: 'SEC-008', obj: 'prod-api-lb', status: 'FAIL', msg: 'WAF in Monitoring mode, should be Blocking' },
          { sev: 'HIGH', sevColor: 'text-orange-400', rule: 'SEC-001', obj: 'staging-web-lb', status: 'FAIL', msg: 'No HTTP-to-HTTPS redirect configured' },
          { sev: 'MEDIUM', sevColor: 'text-yellow-400', rule: 'SEC-012', obj: 'api-gateway-lb', status: 'WARN', msg: 'API Protection not enabled on API endpoint' },
        ].map((f, i) => (
          <div key={i} className="grid grid-cols-12 gap-2 px-4 py-2.5 border-t border-slate-700/50 text-xs">
            <div className={`col-span-1 font-bold ${f.sevColor}`}>{f.sev.charAt(0)}</div>
            <div className="col-span-2 text-slate-300 font-mono">{f.rule}</div>
            <div className="col-span-3 text-slate-300">{f.obj}</div>
            <div className="col-span-2"><span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded text-[10px]">{f.status}</span></div>
            <div className="col-span-4 text-slate-400">{f.msg}</div>
          </div>
        ))}
      </div>
      <p className="text-xs text-slate-500">Click any finding row to expand remediation steps, current vs. expected values, and a direct link to F5 XC documentation.</p>
    </div>
  )},

  /* ── Slide 5: Rule Structure ── */
  { title: 'Rule Structure', component: () => (
    <div>
      <SlideTitle icon={Settings} title="How Rules Work" subtitle="Anatomy of a security rule: ID, check function, remediation, and reference" />
      <div className="mt-6 bg-slate-900/60 border border-slate-700 rounded-xl p-5 font-mono text-xs leading-relaxed">
        <div className="text-slate-500">{'// Example: SEC-008 WAF Blocking Mode'}</div>
        <div className="mt-2">
          <span className="text-violet-400">{'{'}</span>
        </div>
        <div className="ml-4 space-y-1">
          <div><span className="text-blue-400">id</span>: <span className="text-emerald-400">'SEC-008'</span>,</div>
          <div><span className="text-blue-400">name</span>: <span className="text-emerald-400">'WAF Blocking Mode'</span>,</div>
          <div><span className="text-blue-400">category</span>: <span className="text-emerald-400">'WAF'</span>,</div>
          <div><span className="text-blue-400">severity</span>: <span className="text-red-400">'CRITICAL'</span>,</div>
          <div><span className="text-blue-400">appliesTo</span>: [<span className="text-emerald-400">'app_firewall'</span>],</div>
          <div><span className="text-blue-400">check</span>: <span className="text-amber-400">(obj, context)</span> <span className="text-slate-500">=&gt;</span> <span className="text-slate-500">{'{ ... }'}</span>,</div>
          <div><span className="text-blue-400">remediation</span>: <span className="text-emerald-400">'Set WAF to Blocking mode...'</span>,</div>
          <div><span className="text-blue-400">referenceUrl</span>: <span className="text-emerald-400">'https://docs.cloud.f5.com/...'</span>,</div>
        </div>
        <div><span className="text-violet-400">{'}'}</span></div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-5">
        <div className="bg-slate-800/50 border border-blue-500/30 rounded-xl p-4">
          <h4 className="font-semibold text-blue-400 text-sm mb-2">check(obj, context)</h4>
          <p className="text-xs text-slate-400">
            Receives the config object being audited and an AuditContext with cross-references to all other objects (LBs, origin pools, WAFs, certs).
            Returns a CheckResult: PASS, FAIL, WARN, or SKIP with a message and current/expected values.
          </p>
        </div>
        <div className="bg-slate-800/50 border border-emerald-500/30 rounded-xl p-4">
          <h4 className="font-semibold text-emerald-400 text-sm mb-2">AuditContext</h4>
          <p className="text-xs text-slate-400">
            Provides helper methods like getOriginPool(), getAppFirewall(), getCertificate() for cross-object lookups.
            Rules can check whether an LB's WAF is in blocking mode, its origin pool has TLS, or its cert is about to expire.
          </p>
        </div>
        <div className="bg-slate-800/50 border border-amber-500/30 rounded-xl p-4">
          <h4 className="font-semibold text-amber-400 text-sm mb-2">remediation</h4>
          <p className="text-xs text-slate-400">
            Plain-text instructions for fixing the issue. Tells the user exactly which console page to visit and which setting to change, e.g., "Navigate to WAF Policy &gt; Enforcement Mode &gt; Set to Blocking."
          </p>
        </div>
        <div className="bg-slate-800/50 border border-violet-500/30 rounded-xl p-4">
          <h4 className="font-semibold text-violet-400 text-sm mb-2">appliesTo</h4>
          <p className="text-xs text-slate-400">
            Each rule declares which config object types it applies to: http_loadbalancer, app_firewall, origin_pool, service_policy, certificate, etc.
            The engine only runs the rule against matching objects.
          </p>
        </div>
      </div>
    </div>
  )},
];
export function SecurityAuditorExplainer() { return <Slideshow slides={securityAuditorSlides} toolName="Security Auditor" toolRoute="/security-auditor" toolIcon={Shield} />; }


// ═══════════════════════════════════════════════════════════════════
// TOOL 3: FP ANALYZER  (6 slides)
// ═══════════════════════════════════════════════════════════════════

const fpAnalyzerSlides: SlideDefinition[] = [
  /* ── Slide 1: Overview ── */
  { title: 'FP Analyzer', component: () => (
    <div>
      <SlideTitle icon={ShieldAlert} title="False Positive Analyzer" subtitle="Detect and fix WAF false positives with 7-signal scoring" />
      <p className="text-sm text-slate-400 mt-4 mb-6">
        WAF false positives block legitimate users and erode trust in security controls. The FP Analyzer ingests security events,
        scores each one across 7 signals, and classifies them from "Highly Likely FP" to "Confirmed True Positive" -- so you know
        exactly which exclusions are safe to apply.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <FeatureCard icon={Bug} title="False Positive Detection" description="Analyses WAF security events to determine which blocked requests were legitimate users -- preventing real customers from being denied access." color="red" />
        <FeatureCard icon={BarChart2} title="7-Signal Scoring" description="Each event is scored across 7 independent signals: signature risk, violation context, request pattern, source distribution, WAF action, history, and content analysis." color="blue" />
        <FeatureCard icon={Shield} title="Exclusion Generation" description="Automatically generates WAF exclusion rules for confirmed false positives -- ready to paste into the F5 XC console or apply via API." color="emerald" />
        <FeatureCard icon={Target} title="Per-Path Analysis" description="Groups events by request path to show per-URL FP/TP classification. Identifies which pages trigger the most false positives." color="amber" />
      </div>
    </div>
  )},

  /* ── Slide 2: 7-Signal Scoring ── */
  { title: '7-Signal Scoring', component: () => (
    <div>
      <SlideTitle icon={BarChart2} title="The 7-Signal Scoring System" subtitle="Each signal contributes a weighted score to the overall FP probability" />
      <div className="space-y-2.5 mt-6">
        {[
          { signal: 'Signature Risk Level', weight: '20%', desc: 'Low-risk signatures (informational, cookie/header parsing) have higher FP rates than SQL injection or command injection signatures.', color: 'bg-blue-500' },
          { signal: 'Violation Type', weight: '15%', desc: 'Violation types like "Illegal meta character" or "Failed to convert parameter" are more likely benign than "Attack signature detected."', color: 'bg-emerald-500' },
          { signal: 'Request Context', weight: '15%', desc: 'Normal browsing patterns (GET to known paths, standard Content-Type) vs. suspicious patterns (POST to /admin, encoded payloads).', color: 'bg-amber-500' },
          { signal: 'Source Distribution', weight: '15%', desc: 'Events from many different IPs, countries, and ASNs suggest a real pattern affecting multiple users -- not a single attacker.', color: 'bg-violet-500' },
          { signal: 'WAF Action Taken', weight: '10%', desc: 'Events that were blocked vs. only logged. Blocked events need more confidence before adding exclusions since they affect live traffic.', color: 'bg-red-500' },
          { signal: 'Historical Pattern', weight: '15%', desc: 'Recurring events on the same signature across multiple users and time windows suggest a systemic FP that persists over time.', color: 'bg-cyan-500' },
          { signal: 'Content Analysis', weight: '10%', desc: 'Inspects the actual matched value for genuine attack payloads (SQL keywords, script tags) vs. benign data (product names, search terms).', color: 'bg-blue-500' },
        ].map((s, i) => (
          <div key={i} className="flex items-center gap-3 bg-slate-800/50 border border-slate-700 rounded-lg p-3.5">
            <div className={`w-9 h-9 rounded-lg ${s.color} flex items-center justify-center text-white font-bold text-xs flex-shrink-0`}>{i + 1}</div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-medium text-slate-200 text-sm">{s.signal}</span>
                <span className="px-2 py-0.5 bg-slate-700 rounded text-[10px] text-slate-400 font-mono">{s.weight}</span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">{s.desc}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )},

  /* ── Slide 3: Verdict Classification ── */
  { title: 'Verdict Classification', component: () => (
    <div>
      <SlideTitle icon={Target} title="Verdict Classification" subtitle="From highly likely false positive to confirmed true positive" />
      <p className="text-sm text-slate-400 mt-4 mb-6">
        The combined score from all 7 signals produces a verdict. Each verdict has clear guidance on whether to create an exclusion, investigate further, or leave the block in place.
      </p>
      <div className="space-y-3">
        {[
          { verdict: 'Highly Likely FP', range: '85-100', color: 'bg-emerald-500', textColor: 'text-emerald-400', borderColor: 'border-emerald-500/30', desc: 'Very high confidence this is a false positive. Safe to create a WAF exclusion immediately.', action: 'Auto-generate exclusion rule', actionIcon: Check },
          { verdict: 'Likely FP', range: '65-84', color: 'bg-blue-500', textColor: 'text-blue-400', borderColor: 'border-blue-500/30', desc: 'High probability of false positive. Review the matched value briefly, then create exclusion.', action: 'Review + create exclusion', actionIcon: Eye },
          { verdict: 'Uncertain', range: '40-64', color: 'bg-amber-500', textColor: 'text-amber-400', borderColor: 'border-amber-500/30', desc: 'Could be either FP or TP. Manual investigation of the request content and source is needed.', action: 'Manual investigation required', actionIcon: Search },
          { verdict: 'Likely TP', range: '15-39', color: 'bg-orange-500', textColor: 'text-orange-400', borderColor: 'border-orange-500/30', desc: 'Probably a real attack. The request content and pattern are suspicious. Keep the block.', action: 'Keep block, monitor source', actionIcon: AlertTriangle },
          { verdict: 'Confirmed TP', range: '0-14', color: 'bg-red-500', textColor: 'text-red-400', borderColor: 'border-red-500/30', desc: 'Definitely malicious. Attack payload confirmed in request content. Do NOT create an exclusion.', action: 'Block confirmed, no action', actionIcon: X },
        ].map(v => (
          <div key={v.verdict} className={`flex items-center gap-4 bg-slate-800/50 border ${v.borderColor} rounded-xl p-4`}>
            <div className={`w-12 h-12 ${v.color} rounded-full flex items-center justify-center text-white flex-shrink-0`}>
              <v.actionIcon className="w-5 h-5" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className={`font-semibold text-sm ${v.textColor}`}>{v.verdict}</span>
                <span className="px-2 py-0.5 bg-slate-700/80 rounded text-[10px] text-slate-400 font-mono">Score {v.range}</span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">{v.desc}</p>
            </div>
            <div className="text-[10px] text-slate-500 text-right flex-shrink-0 hidden md:block">{v.action}</div>
          </div>
        ))}
      </div>
    </div>
  )},

  /* ── Slide 4: Per-Path Analysis ── */
  { title: 'Per-Path Analysis', component: () => (
    <div>
      <SlideTitle icon={GitBranch} title="Per-Path FP Analysis" subtitle="Path-level grouping with exclusion generation per URL" />
      <p className="text-sm text-slate-400 mt-4 mb-6">
        Events are grouped by request path so you can see which URLs trigger the most WAF events. Each path gets its own FP/TP breakdown and targeted exclusion rules.
      </p>
      {/* Mock path table */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden mb-5">
        <div className="grid grid-cols-12 gap-2 px-4 py-2.5 bg-slate-700/50 text-xs font-medium text-slate-400">
          <div className="col-span-4">Path</div>
          <div className="col-span-2 text-center">Events</div>
          <div className="col-span-2 text-center">Likely FP</div>
          <div className="col-span-2 text-center">Likely TP</div>
          <div className="col-span-2 text-center">Exclusion</div>
        </div>
        {[
          { path: '/api/v1/search', events: 142, fp: 138, tp: 4, hasExcl: true },
          { path: '/checkout/payment', events: 87, fp: 12, tp: 75, hasExcl: false },
          { path: '/login', events: 56, fp: 3, tp: 53, hasExcl: false },
          { path: '/products/catalog', events: 34, fp: 31, tp: 3, hasExcl: true },
        ].map((p, i) => (
          <div key={i} className="grid grid-cols-12 gap-2 px-4 py-2.5 border-t border-slate-700/50 text-xs">
            <div className="col-span-4 text-slate-300 font-mono truncate">{p.path}</div>
            <div className="col-span-2 text-center text-slate-300">{p.events}</div>
            <div className="col-span-2 text-center text-emerald-400">{p.fp}</div>
            <div className="col-span-2 text-center text-red-400">{p.tp}</div>
            <div className="col-span-2 text-center">
              {p.hasExcl
                ? <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-400 rounded text-[10px]">Ready</span>
                : <span className="px-2 py-0.5 bg-slate-700/50 text-slate-500 rounded text-[10px]">N/A</span>}
            </div>
          </div>
        ))}
      </div>
      <div className="bg-slate-800/50 border border-emerald-500/30 rounded-xl p-4">
        <h4 className="font-semibold text-emerald-400 text-sm mb-2">Exclusion Generation</h4>
        <p className="text-xs text-slate-400">
          For paths with high FP counts, the analyzer generates path-scoped WAF exclusion rules targeting the specific signature IDs that trigger
          false positives on that path. Exclusions are scoped to the exact path + signature combination so they do not weaken protection elsewhere.
        </p>
      </div>
    </div>
  )},

  /* ── Slide 5: Client Intelligence ── */
  { title: 'Client Intelligence', component: () => (
    <div>
      <SlideTitle icon={Users} title="Client Intelligence" subtitle="IP details, bot classification, and source correlation" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-6">
        <div className="bg-slate-800/50 border border-blue-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <Globe className="w-5 h-5 text-blue-400" />
            <h4 className="font-semibold text-blue-400 text-sm">IP & Geo Details</h4>
          </div>
          <ul className="space-y-2">
            {['Source IP address and ASN organisation', 'Country and region of origin', 'Number of unique IPs triggering same signature', 'IP reputation score from threat intelligence'].map(item => (
              <li key={item} className="flex items-start gap-2 text-xs text-slate-400">
                <Check className="w-3.5 h-3.5 text-blue-400 mt-0.5 flex-shrink-0" />
                {item}
              </li>
            ))}
          </ul>
        </div>
        <div className="bg-slate-800/50 border border-amber-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <Cpu className="w-5 h-5 text-amber-400" />
            <h4 className="font-semibold text-amber-400 text-sm">Bot Classification</h4>
          </div>
          <ul className="space-y-2">
            {['Bot type: good bot, bad bot, or human', 'Known bot name (Googlebot, Bingbot, etc.)', 'User-agent family and device type', 'Automated tool detection (curl, python-requests)'].map(item => (
              <li key={item} className="flex items-start gap-2 text-xs text-slate-400">
                <Check className="w-3.5 h-3.5 text-amber-400 mt-0.5 flex-shrink-0" />
                {item}
              </li>
            ))}
          </ul>
        </div>
        <div className="bg-slate-800/50 border border-emerald-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <Hash className="w-5 h-5 text-emerald-400" />
            <h4 className="font-semibold text-emerald-400 text-sm">Signature Matching</h4>
          </div>
          <ul className="space-y-2">
            {['Signature ID and name', 'Attack type classification', 'Matched value in the request', 'Accuracy rating (high/medium/low)'].map(item => (
              <li key={item} className="flex items-start gap-2 text-xs text-slate-400">
                <Check className="w-3.5 h-3.5 text-emerald-400 mt-0.5 flex-shrink-0" />
                {item}
              </li>
            ))}
          </ul>
        </div>
        <div className="bg-slate-800/50 border border-violet-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <TrendingUp className="w-5 h-5 text-violet-400" />
            <h4 className="font-semibold text-violet-400 text-sm">Correlation</h4>
          </div>
          <ul className="space-y-2">
            {['Same signature across multiple paths', 'Same client hitting multiple signatures', 'Time-of-day patterns for the source', 'Cross-LB event correlation'].map(item => (
              <li key={item} className="flex items-start gap-2 text-xs text-slate-400">
                <Check className="w-3.5 h-3.5 text-violet-400 mt-0.5 flex-shrink-0" />
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )},

  /* ── Slide 6: Output ── */
  { title: 'Output & Export', component: () => (
    <div>
      <SlideTitle icon={FileJson} title="Output Formats" subtitle="PDF report, Excel workbook, and WAF exclusion policy JSON" />
      <div className="space-y-4 mt-6">
        {/* PDF */}
        <div className="bg-slate-800/50 border border-red-500/30 rounded-xl p-5">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-lg bg-red-500/20 flex items-center justify-center"><FileJson className="w-5 h-5 text-red-400" /></div>
            <div>
              <h4 className="font-semibold text-red-400 text-sm">PDF Report</h4>
              <p className="text-[10px] text-slate-500">For stakeholders and audit trails</p>
            </div>
          </div>
          <p className="text-xs text-slate-400">
            Formatted PDF with executive summary, per-signature analysis, verdict breakdown charts, and recommended exclusion rules.
            Suitable for sharing with security management or attaching to change requests.
          </p>
        </div>
        {/* Excel */}
        <div className="bg-slate-800/50 border border-emerald-500/30 rounded-xl p-5">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-lg bg-emerald-500/20 flex items-center justify-center"><Database className="w-5 h-5 text-emerald-400" /></div>
            <div>
              <h4 className="font-semibold text-emerald-400 text-sm">Excel Workbook</h4>
              <p className="text-[10px] text-slate-500">For detailed analysis and filtering</p>
            </div>
          </div>
          <p className="text-xs text-slate-400">
            Multi-sheet Excel file with events, signatures, verdicts, per-path breakdown, and client details.
            Auto-filtered columns and conditional formatting for easy sorting.
          </p>
        </div>
        {/* WAF Exclusion JSON */}
        <div className="bg-slate-800/50 border border-blue-500/30 rounded-xl p-5">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-lg bg-blue-500/20 flex items-center justify-center"><Shield className="w-5 h-5 text-blue-400" /></div>
            <div>
              <h4 className="font-semibold text-blue-400 text-sm">WAF Exclusion Policy JSON</h4>
              <p className="text-[10px] text-slate-500">For direct import into F5 XC</p>
            </div>
          </div>
          <p className="text-xs text-slate-400">
            Ready-to-apply JSON containing WAF exclusion rules scoped to specific paths and signature IDs.
            Copy and paste into the F5 XC console or apply via API for immediate FP resolution.
          </p>
        </div>
      </div>
    </div>
  )},
];
export function FPAnalyzerExplainer() { return <Slideshow slides={fpAnalyzerSlides} toolName="FP Analyzer" toolRoute="/fp-analyzer" toolIcon={ShieldAlert} />; }


// ═══════════════════════════════════════════════════════════════════
// TOOL 4: DDOS ADVISOR  (5 slides)
// ═══════════════════════════════════════════════════════════════════

const ddosAdvisorSlides: SlideDefinition[] = [
  /* ── Slide 1: Overview ── */
  { title: 'DDoS Advisor', component: () => (
    <div>
      <SlideTitle icon={Shield} title="DDoS Settings Advisor" subtitle="Analyse traffic patterns and recommend tuned L7 DDoS protection" />
      <p className="text-sm text-slate-400 mt-4 mb-6">
        Analyses your actual access logs and security events to recommend DDoS auto-mitigation settings tailored to your traffic profile.
        Supports multiple load balancers, configurable time windows (24h to 30d), and produces a detailed PDF report with ready-to-apply configuration.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <FeatureCard icon={TrendingUp} title="Traffic Analysis" description="Scans access logs to find peak RPS, traffic distribution by country/ASN, response code patterns, and user reputation breakdown." color="blue" />
        <FeatureCard icon={Shield} title="Traffic-Aware Tuning" description="Recommends mitigation action (Block, JS Challenge, or Captcha) based on whether your traffic is Web, API, or Mixed." color="emerald" />
        <FeatureCard icon={Gauge} title="RPS Threshold Calculation" description="Calculates optimal DDoS trigger threshold using Peak RPS x 3 algorithm with a minimum floor of 100 RPS to prevent false positives." color="amber" />
        <FeatureCard icon={FileJson} title="PDF Report + JSON Config" description="Generates a formatted PDF report for stakeholders and a ready-to-apply JSON configuration blob for the F5 XC API." color="violet" />
      </div>
    </div>
  )},

  /* ── Slide 2: Analysis Pipeline ── */
  { title: 'Analysis Pipeline', component: () => (
    <div>
      <SlideTitle icon={Activity} title="5-Phase Analysis Pipeline" subtitle="From config fetch to recommendations in under a minute" />
      <div className="mt-6">
        <StepList steps={[
          {
            icon: Settings,
            title: 'Phase 1: Fetch Current Config',
            desc: 'Reads the load balancer\'s existing DDoS settings including L7 protection mode, RPS threshold, mitigation action, slow DDoS timeouts, threat mesh, IP reputation, and bot defence status.',
            color: 'bg-blue-500',
          },
          {
            icon: Database,
            title: 'Phase 2: Collect Access Logs',
            desc: 'Downloads access logs for the selected time window (24h to 30d). Computes aggregate RPS/RPM per second, identifies peak hours, and builds the traffic profile (Web vs. API vs. Mixed).',
            color: 'bg-emerald-500',
          },
          {
            icon: ShieldAlert,
            title: 'Phase 3: Collect Security Events',
            desc: 'Fetches security events to count DDoS events, WAF blocks, and bot detections. These inform whether existing protection is catching attacks or needs tuning.',
            color: 'bg-amber-500',
          },
          {
            icon: Cpu,
            title: 'Phase 4: Analyse & Score',
            desc: 'Runs the recommendation engine: calculates RPS thresholds, determines optimal mitigation action based on traffic profile, evaluates slow DDoS risk, and checks supplementary features (Threat Mesh, IP Reputation, MUD).',
            color: 'bg-violet-500',
          },
          {
            icon: FileJson,
            title: 'Phase 5: Generate Report',
            desc: 'Produces findings with severity levels (Critical to Info), a recommended config JSON, and RPS recommendation options. All packaged into a downloadable PDF report.',
            color: 'bg-red-500',
          },
        ]} />
      </div>
    </div>
  )},

  /* ── Slide 3: RPS Threshold Algorithm ── */
  { title: 'RPS Threshold', component: () => (
    <div>
      <SlideTitle icon={Gauge} title="RPS Threshold Algorithm" subtitle="How the optimal DDoS trigger point is calculated" />
      {/* Formula card */}
      <div className="bg-slate-900/60 border border-blue-500/30 rounded-xl p-6 mt-6 text-center">
        <div className="font-mono text-lg text-blue-400 mb-2">
          threshold = max( peak_rps <span className="text-slate-500">x</span> 3 , 100 )
        </div>
        <p className="text-xs text-slate-500">Peak observed RPS multiplied by 3, with a minimum floor of 100 RPS</p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-5">
        <div className="bg-slate-800/50 border border-blue-500/30 rounded-xl p-4">
          <div className="text-center mb-2">
            <TrendingUp className="w-6 h-6 text-blue-400 mx-auto" />
            <h4 className="font-semibold text-blue-400 text-sm mt-1">Peak RPS</h4>
          </div>
          <p className="text-xs text-slate-400 text-center">
            The highest per-second request count observed during the analysis window. Calculated from sampled access logs with sample-rate correction.
          </p>
        </div>
        <div className="bg-slate-800/50 border border-emerald-500/30 rounded-xl p-4">
          <div className="text-center mb-2">
            <Hash className="w-6 h-6 text-emerald-400 mx-auto" />
            <h4 className="font-semibold text-emerald-400 text-sm mt-1">3x Multiplier</h4>
          </div>
          <p className="text-xs text-slate-400 text-center">
            Provides headroom for legitimate traffic spikes (flash sales, marketing campaigns) while still catching volumetric DDoS attacks that dwarf normal traffic.
          </p>
        </div>
        <div className="bg-slate-800/50 border border-amber-500/30 rounded-xl p-4">
          <div className="text-center mb-2">
            <Shield className="w-6 h-6 text-amber-400 mx-auto" />
            <h4 className="font-semibold text-amber-400 text-sm mt-1">Minimum 100 RPS</h4>
          </div>
          <p className="text-xs text-slate-400 text-center">
            Low-traffic sites would get unreasonably low thresholds. The 100 RPS floor prevents false-positive DDoS triggers from normal traffic bursts.
          </p>
        </div>
      </div>
      {/* Traffic Profiles */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mt-5">
        <h4 className="font-semibold text-slate-200 text-sm mb-3">Mitigation Action by Traffic Profile</h4>
        <div className="grid grid-cols-3 gap-3">
          {[
            { profile: 'Web Traffic', action: 'JS Challenge', desc: 'Transparent to browsers, blocks bots', color: 'text-blue-400' },
            { profile: 'API Traffic', action: 'Block', desc: 'APIs cannot solve JS challenges', color: 'text-emerald-400' },
            { profile: 'Mixed Traffic', action: 'JS Challenge', desc: 'Favours browser UX, API clients add headers', color: 'text-amber-400' },
          ].map(p => (
            <div key={p.profile} className="text-center">
              <div className={`font-semibold text-sm ${p.color}`}>{p.profile}</div>
              <div className="text-xs text-slate-300 mt-1">{p.action}</div>
              <div className="text-[10px] text-slate-500 mt-0.5">{p.desc}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )},

  /* ── Slide 4: Findings ── */
  { title: 'Findings', component: () => (
    <div>
      <SlideTitle icon={AlertTriangle} title="Findings & Recommendations" subtitle="Severity-graded findings with current vs. recommended values" />
      <p className="text-sm text-slate-400 mt-4 mb-5">
        Each finding compares your current DDoS configuration against the traffic-derived recommendation. Findings span 10 categories covering every aspect of L7 DDoS protection.
      </p>
      {/* Finding categories grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2 mb-5">
        {[
          'RPS Threshold', 'Mitigation Action', 'Client-Side Action', 'Slow DDoS',
          'Threat Mesh', 'IP Reputation', 'MUD', 'Bot Defence', 'DDoS Policy', 'Mitigation Rules',
        ].map(cat => (
          <div key={cat} className="bg-slate-800/50 border border-slate-700 rounded-lg px-3 py-2 text-center">
            <span className="text-xs text-slate-300">{cat}</span>
          </div>
        ))}
      </div>
      {/* Example findings */}
      <div className="space-y-3">
        {[
          { sev: 'Critical', sevColor: 'bg-red-500', title: 'DDoS Auto-Mitigation Not Enabled', current: 'Disabled', recommended: 'Enable with JS Challenge + 450 RPS threshold', desc: 'No L7 DDoS protection is configured. Volumetric application-layer attacks can exhaust origin capacity.' },
          { sev: 'High', sevColor: 'bg-orange-500', title: 'RPS Threshold Too High', current: '10,000 (default)', recommended: '450 (Peak 150 x 3)', desc: 'Default threshold is 22x higher than peak traffic. Attacks below 10K RPS would go undetected.' },
          { sev: 'Medium', sevColor: 'bg-yellow-500', title: 'IP Reputation Not Enabled', current: 'Disabled', recommended: 'Enable with all 12 threat categories', desc: 'Known bad IPs (botnets, scanners, proxies) are not being pre-filtered before reaching the application.' },
        ].map((f, i) => (
          <div key={i} className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <div className={`w-2.5 h-2.5 rounded-full ${f.sevColor}`} />
              <span className="font-semibold text-sm text-slate-200">{f.title}</span>
              <span className="text-[10px] text-slate-500 ml-auto">{f.sev}</span>
            </div>
            <p className="text-xs text-slate-400 mb-2">{f.desc}</p>
            <div className="flex gap-4">
              <div className="flex items-center gap-1.5 text-xs">
                <X className="w-3.5 h-3.5 text-red-400" />
                <span className="text-slate-500">Current:</span>
                <span className="text-red-400">{f.current}</span>
              </div>
              <div className="flex items-center gap-1.5 text-xs">
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-slate-500">Recommended:</span>
                <span className="text-emerald-400">{f.recommended}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )},

  /* ── Slide 5: Output ── */
  { title: 'Output & Export', component: () => (
    <div>
      <SlideTitle icon={FileJson} title="Report & Config Export" subtitle="PDF report, JSON configuration, and config status badges" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-6">
        {/* PDF Report */}
        <div className="bg-slate-800/50 border border-red-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-8 h-8 rounded-lg bg-red-500/20 flex items-center justify-center"><FileJson className="w-4 h-4 text-red-400" /></div>
            <h4 className="font-semibold text-red-400 text-sm">PDF Report</h4>
          </div>
          <ul className="space-y-1.5">
            {['Executive summary with severity counts', 'Traffic statistics table (RPS percentiles, peaks)', 'Current vs. recommended comparison', 'Traffic profile analysis (Web/API/Mixed)', 'Finding details with rationale', 'Response code and geo distribution'].map(item => (
              <li key={item} className="flex items-start gap-2 text-xs text-slate-400">
                <Check className="w-3.5 h-3.5 text-red-400 mt-0.5 flex-shrink-0" />
                {item}
              </li>
            ))}
          </ul>
        </div>
        {/* JSON Config */}
        <div className="bg-slate-800/50 border border-blue-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-8 h-8 rounded-lg bg-blue-500/20 flex items-center justify-center"><Settings className="w-4 h-4 text-blue-400" /></div>
            <h4 className="font-semibold text-blue-400 text-sm">JSON Config Blob</h4>
          </div>
          <ul className="space-y-1.5">
            {['l7_ddos_protection section (threshold + action)', 'slow_ddos_mitigation timeouts', 'enable_threat_mesh toggle', 'enable_ip_reputation with 12 threat categories', 'enable_malicious_user_detection toggle', 'Copy to clipboard for F5 XC API'].map(item => (
              <li key={item} className="flex items-start gap-2 text-xs text-slate-400">
                <Check className="w-3.5 h-3.5 text-blue-400 mt-0.5 flex-shrink-0" />
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>
      {/* Config Status Badges */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5 mt-5">
        <h4 className="font-semibold text-slate-200 text-sm mb-3">Config Status Badges</h4>
        <p className="text-xs text-slate-400 mb-3">
          Each DDoS feature is shown with a status badge reflecting whether it is currently enabled, disabled, or using defaults.
        </p>
        <div className="flex flex-wrap gap-2">
          {[
            { label: 'L7 DDoS', status: 'Enabled', color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' },
            { label: 'Slow DDoS', status: 'Disabled', color: 'bg-red-500/20 text-red-400 border-red-500/30' },
            { label: 'Threat Mesh', status: 'Enabled', color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' },
            { label: 'IP Reputation', status: 'Partial', color: 'bg-amber-500/20 text-amber-400 border-amber-500/30' },
            { label: 'MUD', status: 'Disabled', color: 'bg-red-500/20 text-red-400 border-red-500/30' },
            { label: 'Bot Defence', status: 'Enabled', color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' },
          ].map(b => (
            <span key={b.label} className={`px-3 py-1.5 border rounded-full text-xs ${b.color}`}>
              {b.label}: {b.status}
            </span>
          ))}
        </div>
      </div>
    </div>
  )},
];
export function DDoSAdvisorExplainer() { return <Slideshow slides={ddosAdvisorSlides} toolName="DDoS Advisor" toolRoute="/ddos-advisor" toolIcon={Shield} />; }


// ═══════════════════════════════════════════════════════════════════
// TOOL 5: CONFIG VIEWER  (4 slides)
// ═══════════════════════════════════════════════════════════════════

const configViewerSlides: SlideDefinition[] = [
  /* ── Slide 1: Overview ── */
  { title: 'Config Viewer', component: () => (
    <div>
      <SlideTitle icon={Grid3X3} title="Config Viewer" subtitle="Interactive map of Load Balancer dependencies and settings" />
      <p className="text-sm text-slate-400 mt-4 mb-6">
        Visualises the complete dependency tree for any HTTP or CDN load balancer: routes, origin pools, health checks, WAF policies,
        service policies, and certificates. Supports multi-LB selection for side-by-side comparison.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <FeatureCard icon={Grid3X3} title="Full Configuration Tree" description="Renders the complete hierarchy: LB -> Routes -> Origin Pools -> Endpoints -> Health Checks, plus all security policies in one interactive view." color="blue" />
        <FeatureCard icon={Eye} title="Feature Status Matrix" description="At-a-glance matrix showing which security features are enabled: WAF mode, Bot Defence, DDoS, API Discovery, MUD, Service Policies." color="emerald" />
        <FeatureCard icon={Server} title="HTTP & CDN Support" description="Works with both HTTP Load Balancers and CDN distributions. Toggle between them using a type selector. CDN shows cache rules and edge logic." color="amber" />
        <FeatureCard icon={Lock} title="Certificate Inspector" description="View TLS certificate details: subject, issuer, SAN list, expiry date, and cipher suite configuration for each load balancer." color="red" />
      </div>
    </div>
  )},

  /* ── Slide 2: Route Parsing ── */
  { title: 'Route Parsing', component: () => (
    <div>
      <SlideTitle icon={GitBranch} title="Route Parsing" subtitle="Path types, advanced options, and origin pool references" />
      <div className="mt-6 space-y-4">
        {/* Path Types Table */}
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
          <div className="px-4 py-3 bg-slate-700/50">
            <h4 className="font-semibold text-slate-200 text-sm">Supported Route Path Types</h4>
          </div>
          <div className="divide-y divide-slate-700/50">
            {[
              { type: 'Prefix', example: '/api/', desc: 'Matches any path starting with the prefix. Most common type.' },
              { type: 'Exact', example: '/login', desc: 'Matches the exact path only. Strictest matching.' },
              { type: 'Regex', example: '/v[0-9]+/.*', desc: 'Matches paths using regular expressions. Most flexible.' },
              { type: 'Default', example: '/ (catch-all)', desc: 'Fallback route when no other route matches. Usually the last route.' },
            ].map(r => (
              <div key={r.type} className="grid grid-cols-12 gap-2 px-4 py-3 text-xs">
                <div className="col-span-2 font-semibold text-blue-400">{r.type}</div>
                <div className="col-span-3 text-slate-300 font-mono">{r.example}</div>
                <div className="col-span-7 text-slate-400">{r.desc}</div>
              </div>
            ))}
          </div>
        </div>
        {/* Advanced Options */}
        <div className="bg-slate-800/50 border border-emerald-500/30 rounded-xl p-5">
          <h4 className="font-semibold text-emerald-400 text-sm mb-3">Advanced Route Options Parsed</h4>
          <div className="grid grid-cols-2 gap-3">
            {[
              'WAF override per route', 'Bot defence per route', 'Route-level rate limits',
              'Request/response header manipulation', 'Origin pool weighting', 'Retry and timeout policies',
              'CORS configuration', 'Buffer settings',
            ].map(opt => (
              <div key={opt} className="flex items-center gap-2 text-xs text-slate-400">
                <Check className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                {opt}
              </div>
            ))}
          </div>
        </div>
        {/* Origin Pool References */}
        <div className="bg-slate-800/50 border border-amber-500/30 rounded-xl p-5">
          <h4 className="font-semibold text-amber-400 text-sm mb-2">Origin Pool Resolution</h4>
          <p className="text-xs text-slate-400">
            Each route references one or more origin pools (with weights for traffic splitting). The viewer resolves every origin pool reference,
            fetches its endpoints (public IPs, DNS names, or k8s services), and displays health check configuration -- even across namespaces.
          </p>
        </div>
      </div>
    </div>
  )},

  /* ── Slide 3: Security Layer ── */
  { title: 'Security Layer', component: () => (
    <div>
      <SlideTitle icon={Shield} title="Security Features View" subtitle="WAF, Bot Defence, DDoS, service policies, and certificates" />
      <div className="mt-6">
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
          <div className="divide-y divide-slate-700/50">
            {[
              { feature: 'WAF Policy', icon: Shield, color: 'text-blue-400', fields: 'Policy name, enforcement mode (Blocking/Monitoring), exclusion rule count, detection settings' },
              { feature: 'Bot Defence', icon: Cpu, color: 'text-emerald-400', fields: 'Enabled/disabled, protected endpoints, JS insertion method, bot categories' },
              { feature: 'DDoS Auto-Mitigation', icon: Zap, color: 'text-amber-400', fields: 'L7 DDoS enabled, RPS threshold, mitigation action, slow DDoS timeouts' },
              { feature: 'Service Policies', icon: Lock, color: 'text-red-400', fields: 'Policy name, rule count, allowed/denied prefixes, geo restrictions' },
              { feature: 'API Discovery', icon: Search, color: 'text-violet-400', fields: 'Enabled/disabled, learnt endpoints count, schema validation status' },
              { feature: 'Malicious User Detection', icon: Users, color: 'text-cyan-400', fields: 'MUD enabled, threat mesh, IP reputation categories' },
              { feature: 'TLS Certificates', icon: Lock, color: 'text-blue-400', fields: 'Certificate name, type (auto/custom), domains, expiry date' },
            ].map(f => (
              <div key={f.feature} className="flex items-start gap-3 px-5 py-3.5">
                <f.icon className={`w-5 h-5 ${f.color} flex-shrink-0 mt-0.5`} />
                <div>
                  <div className={`font-semibold text-sm ${f.color}`}>{f.feature}</div>
                  <p className="text-xs text-slate-400 mt-0.5">{f.fields}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )},

  /* ── Slide 4: Feature Mapping ── */
  { title: 'Feature Mapping', component: () => (
    <div>
      <SlideTitle icon={Eye} title="Human-Readable Feature Names" subtitle="Config Viewer translates F5 XC API field names into plain English" />
      <p className="text-sm text-slate-400 mt-4 mb-5">
        The F5 XC API uses verbose internal names. Config Viewer maps these to readable labels so you do not need to memorise API field names.
      </p>
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
        <div className="grid grid-cols-2 gap-0">
          <div className="px-4 py-2.5 bg-slate-700/50 text-xs font-medium text-slate-400">API Field Name</div>
          <div className="px-4 py-2.5 bg-slate-700/50 text-xs font-medium text-slate-400">Display Name</div>
          {[
            { api: 'disable_waf', display: 'WAF: Disabled' },
            { api: 'app_firewall.enforcement_mode', display: 'WAF Mode (Blocking/Monitoring)' },
            { api: 'enable_ddos_detection', display: 'L7 DDoS Auto-Mitigation' },
            { api: 'bot_defense.enable', display: 'Bot Defence: Enabled' },
            { api: 'enable_malicious_user_detection', display: 'Malicious User Detection' },
            { api: 'enable_api_discovery', display: 'API Discovery' },
            { api: 'enable_threat_mesh', display: 'Threat Mesh (IP sharing)' },
            { api: 'enable_ip_reputation', display: 'IP Reputation Filtering' },
            { api: 'no_challenge', display: 'JS Challenge: Disabled' },
            { api: 'policy_based_challenge', display: 'Policy-Based Challenge' },
            { api: 'slow_ddos_mitigation', display: 'Slow DDoS Protection' },
            { api: 'cors_policy', display: 'CORS Policy' },
          ].map((m, i) => (
            <div key={m.api} className={`contents ${i % 2 === 0 ? '' : ''}`}>
              <div className={`px-4 py-2 text-xs font-mono text-slate-400 ${i % 2 === 1 ? 'bg-slate-800/30' : ''} border-t border-slate-700/50`}>{m.api}</div>
              <div className={`px-4 py-2 text-xs text-slate-300 ${i % 2 === 1 ? 'bg-slate-800/30' : ''} border-t border-slate-700/50`}>{m.display}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )},
];
export function ConfigViewerExplainer() { return <Slideshow slides={configViewerSlides} toolName="Config Viewer" toolRoute="/config-visualizer" toolIcon={Grid3X3} />; }


// ═══════════════════════════════════════════════════════════════════
// TOOL 6: CONFIG COMPARATOR  (4 slides)
// ═══════════════════════════════════════════════════════════════════

const configComparatorSlides: SlideDefinition[] = [
  /* ── Slide 1: Overview ── */
  { title: 'Config Comparator', component: () => (
    <div>
      <SlideTitle icon={Split} title="Config Comparator" subtitle="Detect configuration drift across namespaces and tenants" />
      <p className="text-sm text-slate-400 mt-4 mb-6">
        Compare HTTP LB configurations between namespaces within the same tenant, or across completely different tenants.
        Ideal for validating environment promotions (dev -&gt; staging -&gt; prod) or auditing managed service provider configurations.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <FeatureCard icon={Split} title="Namespace vs. Tenant Mode" description="Two comparison modes: same-tenant namespace diff (e.g., staging vs. prod) or cross-tenant diff for managed service providers." color="blue" />
        <FeatureCard icon={Eye} title="3-Step Wizard" description="Step 1: Select source. Step 2: Select destination. Step 3: Review overview with match/diff/source-only/dest-only classification." color="emerald" />
        <FeatureCard icon={FileJson} title="Deep Object Diff" description="Click any LB to see a flattened property-by-property diff using dot-notation paths. Changed values are highlighted in red/green." color="amber" />
        <FeatureCard icon={Check} title="Status Classification" description="Every LB is classified: Match (identical), Diff (exists in both but different), Source Only, or Destination Only." color="violet" />
      </div>
    </div>
  )},

  /* ── Slide 2: Overview Generation ── */
  { title: 'Overview Generation', component: () => (
    <div>
      <SlideTitle icon={BarChart2} title="Comparison Overview" subtitle="Four status categories for every load balancer" />
      <div className="mt-6 grid grid-cols-2 gap-4 mb-6">
        {[
          { status: 'Match', color: 'bg-emerald-500', textColor: 'text-emerald-400', borderColor: 'border-emerald-500/30', icon: Check, desc: 'LB exists in both source and destination with identical configuration. No drift detected.' },
          { status: 'Diff', color: 'bg-amber-500', textColor: 'text-amber-400', borderColor: 'border-amber-500/30', icon: AlertTriangle, desc: 'LB exists in both but has configuration differences. Click to see the detailed property diff.' },
          { status: 'Source Only', color: 'bg-blue-500', textColor: 'text-blue-400', borderColor: 'border-blue-500/30', icon: ChevronRight, desc: 'LB exists in the source namespace/tenant but not in the destination. May need to be created.' },
          { status: 'Dest Only', color: 'bg-violet-500', textColor: 'text-violet-400', borderColor: 'border-violet-500/30', icon: ChevronRight, desc: 'LB exists in the destination but not in the source. May be orphaned or environment-specific.' },
        ].map(s => (
          <div key={s.status} className={`bg-slate-800/50 border ${s.borderColor} rounded-xl p-5`}>
            <div className="flex items-center gap-2 mb-2">
              <div className={`w-8 h-8 ${s.color} rounded-full flex items-center justify-center text-white`}>
                <s.icon className="w-4 h-4" />
              </div>
              <span className={`font-semibold text-sm ${s.textColor}`}>{s.status}</span>
            </div>
            <p className="text-xs text-slate-400">{s.desc}</p>
          </div>
        ))}
      </div>
      {/* Example stat row */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-5">
        <h4 className="font-semibold text-slate-200 text-sm mb-3">Example Overview</h4>
        <div className="grid grid-cols-4 gap-3">
          {[
            { stat: '12', label: 'Match', color: 'text-emerald-400' },
            { stat: '5', label: 'Diff', color: 'text-amber-400' },
            { stat: '3', label: 'Source Only', color: 'text-blue-400' },
            { stat: '1', label: 'Dest Only', color: 'text-violet-400' },
          ].map(s => (
            <div key={s.label} className="text-center">
              <div className={`text-2xl font-bold ${s.color}`}>{s.stat}</div>
              <div className="text-xs text-slate-400">{s.label}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )},

  /* ── Slide 3: Deep Comparison ── */
  { title: 'Deep Comparison', component: () => (
    <div>
      <SlideTitle icon={Search} title="Deep Object Comparison" subtitle="Flattened property diff with dot-notation paths" />
      <p className="text-sm text-slate-400 mt-4 mb-5">
        When an LB has status "Diff", click it to see exactly which properties differ. The comparator flattens both JSON objects
        and compares every leaf value using dot-notation paths.
      </p>
      {/* Mock diff table */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
        <div className="grid grid-cols-12 gap-2 px-4 py-2.5 bg-slate-700/50 text-xs font-medium text-slate-400">
          <div className="col-span-5">Property Path</div>
          <div className="col-span-3">Source Value</div>
          <div className="col-span-3">Dest Value</div>
          <div className="col-span-1">Status</div>
        </div>
        {[
          { path: 'spec.waf_type.mode', src: 'blocking', dst: 'monitoring', status: 'diff' },
          { path: 'spec.routes[0].timeout', src: '30s', dst: '60s', status: 'diff' },
          { path: 'spec.enable_ddos_detection', src: 'true', dst: 'false', status: 'diff' },
          { path: 'spec.cors_policy.max_age', src: '86400', dst: '--', status: 'src_only' },
          { path: 'spec.routes[2].path.prefix', src: '--', dst: '/api/v3', status: 'dst_only' },
        ].map((r, i) => (
          <div key={i} className="grid grid-cols-12 gap-2 px-4 py-2.5 border-t border-slate-700/50 text-xs">
            <div className="col-span-5 font-mono text-slate-300 truncate">{r.path}</div>
            <div className={`col-span-3 ${r.status === 'diff' || r.status === 'src_only' ? 'text-red-400' : 'text-slate-500'}`}>{r.src}</div>
            <div className={`col-span-3 ${r.status === 'diff' || r.status === 'dst_only' ? 'text-emerald-400' : 'text-slate-500'}`}>{r.dst}</div>
            <div className="col-span-1">
              {r.status === 'diff' && <span className="px-1.5 py-0.5 bg-amber-500/20 text-amber-400 rounded text-[10px]">Diff</span>}
              {r.status === 'src_only' && <span className="px-1.5 py-0.5 bg-blue-500/20 text-blue-400 rounded text-[10px]">Src</span>}
              {r.status === 'dst_only' && <span className="px-1.5 py-0.5 bg-violet-500/20 text-violet-400 rounded text-[10px]">Dst</span>}
            </div>
          </div>
        ))}
      </div>
      <p className="text-xs text-slate-500 mt-3">
        The diff uses flattened dot-notation so nested differences like <span className="font-mono text-slate-400">spec.routes[0].waf_type.mode</span> are visible at a glance
        without expanding JSON trees.
      </p>
    </div>
  )},

  /* ── Slide 4: Cross-Compare ── */
  { title: 'Cross-Compare', component: () => (
    <div>
      <SlideTitle icon={Globe} title="Cross-Tenant & Custom Compare" subtitle="Saved credentials, custom LB selections, and JSON modal" />
      <div className="mt-6 space-y-4">
        <div className="bg-slate-800/50 border border-blue-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <Globe className="w-5 h-5 text-blue-400" />
            <h4 className="font-semibold text-blue-400 text-sm">Cross-Tenant Mode</h4>
          </div>
          <p className="text-xs text-slate-400">
            Enter a second tenant's URL and API token to compare configurations across completely separate F5 XC tenants.
            Useful for managed service providers ensuring consistent security posture across customer deployments.
            Destination credentials are stored in session only (not persisted to localStorage).
          </p>
        </div>
        <div className="bg-slate-800/50 border border-emerald-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <Filter className="w-5 h-5 text-emerald-400" />
            <h4 className="font-semibold text-emerald-400 text-sm">Custom LB Selection</h4>
          </div>
          <p className="text-xs text-slate-400">
            Instead of comparing all LBs, you can select specific load balancers from source and destination to compare.
            Pick one from each side to do a focused 1:1 comparison, or select multiple for a filtered overview.
          </p>
        </div>
        <div className="bg-slate-800/50 border border-amber-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <FileJson className="w-5 h-5 text-amber-400" />
            <h4 className="font-semibold text-amber-400 text-sm">JSON Modal</h4>
          </div>
          <p className="text-xs text-slate-400">
            Click "View JSON" on any LB to see its full raw configuration in a syntax-highlighted modal.
            Compare source and destination JSON side-by-side. Copy to clipboard for external diff tools.
          </p>
        </div>
      </div>
    </div>
  )},
];
export function ConfigComparatorExplainer() { return <Slideshow slides={configComparatorSlides} toolName="Config Comparator" toolRoute="/config-comparator" toolIcon={Split} />; }


// ═══════════════════════════════════════════════════════════════════
// TOOL 7: CONFIG EXPLORER (Dependency Map)  (4 slides)
// ═══════════════════════════════════════════════════════════════════

const dependencyMapSlides: SlideDefinition[] = [
  /* ── Slide 1: Overview ── */
  { title: 'Config Explorer', component: () => (
    <div>
      <SlideTitle icon={GitBranch} title="Config Explorer" subtitle="3 view modes for visualising object relationships and dependencies" />
      <p className="text-sm text-slate-400 mt-4 mb-6">
        Recursively fetches all configuration objects referenced by your load balancers and presents them in three interactive views:
        a sortable dependency table, an expandable hierarchy tree, and a force-directed relationship graph.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <FeatureCard icon={Database} title="Recursive Object Catalog" description="Starting from your selected LBs, recursively discovers every referenced object: origin pools, WAFs, health checks, service policies, certs, and more." color="blue" />
        <FeatureCard icon={Layers} title="3 View Modes" description="Table view (sortable, searchable), Tree view (expandable hierarchy), and Graph view (force-directed network visualisation)." color="emerald" />
        <FeatureCard icon={Search} title="Search & Filter" description="Filter by object name, type, or namespace. Instantly find any object across your entire configuration tree." color="amber" />
        <FeatureCard icon={FileJson} title="CSV Export" description="Export the complete dependency data as CSV for external analysis, documentation, or import into CMDB tools." color="violet" />
      </div>
    </div>
  )},

  /* ── Slide 2: Dependency Table ── */
  { title: 'Dependency Table', component: () => (
    <div>
      <SlideTitle icon={Database} title="Dependency Table View" subtitle="Sortable, searchable, with object type filtering" />
      <p className="text-sm text-slate-400 mt-4 mb-5">
        The table view lists every discovered object as a flat row with columns for name, type, namespace, parent, and depth in the dependency tree.
      </p>
      {/* Mock table */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden mb-5">
        <div className="grid grid-cols-12 gap-2 px-4 py-2.5 bg-slate-700/50 text-xs font-medium text-slate-400">
          <div className="col-span-3">Object Name</div>
          <div className="col-span-2">Type</div>
          <div className="col-span-2">Namespace</div>
          <div className="col-span-3">Parent</div>
          <div className="col-span-1">Depth</div>
          <div className="col-span-1">Refs</div>
        </div>
        {[
          { name: 'prod-api-lb', type: 'HTTP LB', ns: 'production', parent: '--', depth: 0, refs: 8 },
          { name: 'api-origin-pool', type: 'Origin Pool', ns: 'production', parent: 'prod-api-lb', depth: 1, refs: 3 },
          { name: 'api-health-tcp', type: 'Health Check', ns: 'production', parent: 'api-origin-pool', depth: 2, refs: 0 },
          { name: 'global-waf-blocking', type: 'WAF Policy', ns: 'shared', parent: 'prod-api-lb', depth: 1, refs: 0 },
          { name: 'prod-cert-auto', type: 'Certificate', ns: 'production', parent: 'prod-api-lb', depth: 1, refs: 0 },
        ].map((r, i) => (
          <div key={i} className="grid grid-cols-12 gap-2 px-4 py-2 border-t border-slate-700/50 text-xs">
            <div className="col-span-3 text-slate-300 font-medium">{r.name}</div>
            <div className="col-span-2"><span className="px-1.5 py-0.5 bg-blue-500/10 text-blue-400 rounded text-[10px]">{r.type}</span></div>
            <div className="col-span-2 text-slate-400">{r.ns}</div>
            <div className="col-span-3 text-slate-400 font-mono text-[11px]">{r.parent}</div>
            <div className="col-span-1 text-slate-400 text-center">{r.depth}</div>
            <div className="col-span-1 text-slate-400 text-center">{r.refs}</div>
          </div>
        ))}
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div className="flex items-center gap-2 text-xs text-slate-400"><Check className="w-3.5 h-3.5 text-emerald-400" />Sortable by any column (click header)</div>
        <div className="flex items-center gap-2 text-xs text-slate-400"><Check className="w-3.5 h-3.5 text-emerald-400" />Full-text search across all columns</div>
        <div className="flex items-center gap-2 text-xs text-slate-400"><Check className="w-3.5 h-3.5 text-emerald-400" />Filter by object type (dropdown)</div>
        <div className="flex items-center gap-2 text-xs text-slate-400"><Check className="w-3.5 h-3.5 text-emerald-400" />Export to CSV with one click</div>
      </div>
    </div>
  )},

  /* ── Slide 3: Hierarchy Tree ── */
  { title: 'Hierarchy Tree', component: () => (
    <div>
      <SlideTitle icon={Layers} title="Hierarchy Tree View" subtitle="Expandable tree with type-based colour coding" />
      <p className="text-sm text-slate-400 mt-4 mb-5">
        The tree view renders the dependency graph as an expandable tree, colour-coded by object type. Expand any node to see its children.
      </p>
      {/* Mock tree */}
      <div className="bg-slate-900/60 border border-slate-700 rounded-xl p-5 font-mono text-xs space-y-1">
        <div className="text-blue-400">
          <span className="text-slate-600 mr-2">{'>'}</span>
          <span className="bg-blue-500/10 px-1.5 py-0.5 rounded">HTTP LB</span> prod-api-lb
        </div>
        <div className="ml-6 text-emerald-400">
          <span className="text-slate-600 mr-2">{'>'}</span>
          <span className="bg-emerald-500/10 px-1.5 py-0.5 rounded">Route</span> /api/v1/* (prefix)
        </div>
        <div className="ml-12 text-amber-400">
          <span className="text-slate-600 mr-2">{' '}</span>
          <span className="bg-amber-500/10 px-1.5 py-0.5 rounded">Origin Pool</span> api-origin-pool
        </div>
        <div className="ml-[4.5rem] text-cyan-400">
          <span className="text-slate-600 mr-2">{' '}</span>
          <span className="bg-cyan-500/10 px-1.5 py-0.5 rounded">Health Check</span> api-health-tcp
        </div>
        <div className="ml-[4.5rem] text-cyan-400">
          <span className="text-slate-600 mr-2">{' '}</span>
          <span className="bg-cyan-500/10 px-1.5 py-0.5 rounded">Endpoint</span> 10.0.1.50:8080
        </div>
        <div className="ml-6 text-red-400">
          <span className="text-slate-600 mr-2">{' '}</span>
          <span className="bg-red-500/10 px-1.5 py-0.5 rounded">WAF Policy</span> global-waf-blocking <span className="text-slate-600">(shared)</span>
        </div>
        <div className="ml-6 text-violet-400">
          <span className="text-slate-600 mr-2">{' '}</span>
          <span className="bg-violet-500/10 px-1.5 py-0.5 rounded">Certificate</span> prod-cert-auto
        </div>
        <div className="ml-6 text-emerald-400">
          <span className="text-slate-600 mr-2">{'>'}</span>
          <span className="bg-emerald-500/10 px-1.5 py-0.5 rounded">Route</span> /static/* (prefix)
        </div>
        <div className="ml-12 text-amber-400">
          <span className="text-slate-600 mr-2">{' '}</span>
          <span className="bg-amber-500/10 px-1.5 py-0.5 rounded">Origin Pool</span> cdn-origin-pool
        </div>
      </div>
      {/* Color legend */}
      <div className="mt-4 flex flex-wrap gap-3">
        {[
          { type: 'HTTP LB', color: 'bg-blue-500' },
          { type: 'Route', color: 'bg-emerald-500' },
          { type: 'Origin Pool', color: 'bg-amber-500' },
          { type: 'Health Check', color: 'bg-cyan-500' },
          { type: 'WAF Policy', color: 'bg-red-500' },
          { type: 'Certificate', color: 'bg-violet-500' },
          { type: 'Service Policy', color: 'bg-rose-500' },
        ].map(l => (
          <div key={l.type} className="flex items-center gap-1.5 text-xs text-slate-400">
            <div className={`w-3 h-3 rounded-sm ${l.color}`} />
            {l.type}
          </div>
        ))}
      </div>
    </div>
  )},

  /* ── Slide 4: Relationship Graph ── */
  { title: 'Relationship Graph', component: () => (
    <div>
      <SlideTitle icon={GitBranch} title="Force-Directed Relationship Graph" subtitle="Interactive network visualisation of all object connections" />
      <p className="text-sm text-slate-400 mt-4 mb-5">
        The graph view renders objects as nodes and their relationships as edges in a force-directed layout.
        Drag nodes to rearrange, zoom in/out, and click any node to highlight its connections.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="bg-slate-800/50 border border-blue-500/30 rounded-xl p-5">
          <h4 className="font-semibold text-blue-400 text-sm mb-3">Interaction</h4>
          <ul className="space-y-2">
            {[
              'Drag nodes to reposition them',
              'Scroll to zoom in/out',
              'Click a node to highlight its edges',
              'Double-click to view full JSON config',
              'Hover for object name and type tooltip',
            ].map(item => (
              <li key={item} className="flex items-start gap-2 text-xs text-slate-400">
                <Check className="w-3.5 h-3.5 text-blue-400 mt-0.5 flex-shrink-0" />
                {item}
              </li>
            ))}
          </ul>
        </div>
        <div className="bg-slate-800/50 border border-emerald-500/30 rounded-xl p-5">
          <h4 className="font-semibold text-emerald-400 text-sm mb-3">Visual Encoding</h4>
          <ul className="space-y-2">
            {[
              'Node colour = object type (same as tree view)',
              'Node size = number of connections',
              'Edge thickness = relationship weight',
              'Dashed edges = cross-namespace references',
              'Labels show object name (toggleable)',
            ].map(item => (
              <li key={item} className="flex items-start gap-2 text-xs text-slate-400">
                <Check className="w-3.5 h-3.5 text-emerald-400 mt-0.5 flex-shrink-0" />
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>
      <div className="bg-slate-800/50 border border-amber-500/30 rounded-xl p-4 mt-4">
        <p className="text-xs text-slate-400">
          <span className="text-amber-400 font-semibold">Tip:</span> The graph is especially useful for identifying shared objects -- objects referenced by multiple LBs appear as
          highly-connected nodes in the center. This helps you understand the blast radius of changing a shared WAF policy or origin pool.
        </p>
      </div>
    </div>
  )},
];
export function DependencyMapExplainer() { return <Slideshow slides={dependencyMapSlides} toolName="Config Explorer" toolRoute="/config-explorer" toolIcon={GitBranch} />; }


// ═══════════════════════════════════════════════════════════════════
// TOOL 8: HTTP SANITY CHECKER  (5 slides)
// ═══════════════════════════════════════════════════════════════════

const httpSanitySlides: SlideDefinition[] = [
  /* ── Slide 1: Overview ── */
  { title: 'HTTP Sanity Checker', component: () => (
    <div>
      <SlideTitle icon={Activity} title="HTTP Sanity Checker" subtitle="Compare live vs. spoofed responses to validate your F5 XC deployment" />
      <p className="text-sm text-slate-400 mt-4 mb-6">
        Before cutting DNS to F5 XC, validate that the platform returns the same response as your current provider. The Sanity Checker
        sends requests through both the real DNS path (Live) and directly to the F5 XC VIP (Spoof), then compares status, headers, body, and TLS certs.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <FeatureCard icon={Globe} title="Live vs. Spoof Comparison" description="Sends parallel requests through real DNS (current provider) and spoofed DNS (pointing to F5 XC IP). Compares responses side by side." color="blue" />
        <FeatureCard icon={Lock} title="TLS Certificate Validation" description="Compares TLS certificates from both paths: subject, issuer, SAN list, and expiry. Ensures F5 XC has the correct cert before DNS cutover." color="emerald" />
        <FeatureCard icon={Activity} title="Body Similarity Scoring" description="Computes a fuzzy similarity percentage between Live and Spoof response bodies. Highlights differences in content length and structure." color="amber" />
        <FeatureCard icon={AlertTriangle} title="Bot Challenge Detection" description="Detects if F5 XC is serving a JavaScript challenge or CAPTCHA page instead of the real content -- a common migration issue." color="red" />
      </div>
    </div>
  )},

  /* ── Slide 2: Response Analysis ── */
  { title: 'Response Analysis', component: () => (
    <div>
      <SlideTitle icon={BarChart2} title="Response Comparison Metrics" subtitle="What gets compared between Live and Spoof responses" />
      <div className="mt-6 bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden">
        <div className="divide-y divide-slate-700/50">
          {[
            { metric: 'Status Code', desc: 'HTTP response code (200, 301, 403, etc.) must match between Live and Spoof.', match: 'Exact match required', icon: Hash },
            { metric: 'Response Headers', desc: 'Headers compared excluding transient ones (Date, X-Request-Id, Age, etc.). Differences shown in amber.', match: 'Filtered comparison', icon: Layers },
            { metric: 'Body Content', desc: 'Response body compared with fuzzy matching. Similarity score (0-100%) accounts for dynamic elements.', match: 'Fuzzy similarity %', icon: FileJson },
            { metric: 'Content Length', desc: 'Total body size in bytes. Large size differences suggest different content being served.', match: 'Within tolerance', icon: Database },
            { metric: 'Response Time', desc: 'Latency comparison between paths. Significant differences may indicate routing or origin issues.', match: 'Informational', icon: Clock },
            { metric: 'Bot Challenge', desc: 'Detects challenge pages (JS Challenge, CAPTCHA) served by F5 XC that would block real users.', match: 'Absent = pass', icon: AlertTriangle },
          ].map(m => (
            <div key={m.metric} className="flex items-start gap-3 px-5 py-3.5">
              <m.icon className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-sm text-slate-200">{m.metric}</span>
                  <span className="px-2 py-0.5 bg-slate-700/80 rounded text-[10px] text-slate-400">{m.match}</span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">{m.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )},

  /* ── Slide 3: TLS Certificate Comparison ── */
  { title: 'TLS Certificate', component: () => (
    <div>
      <SlideTitle icon={Lock} title="TLS Certificate Comparison" subtitle="Subject, issuer, SAN, and expiry checked between Live and Spoof" />
      <p className="text-sm text-slate-400 mt-4 mb-5">
        A mismatched TLS certificate on the F5 XC side will cause browser warnings after DNS cutover. The checker validates certificate fields from both paths.
      </p>
      {/* Mock cert comparison table */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden mb-5">
        <div className="grid grid-cols-12 gap-2 px-4 py-2.5 bg-slate-700/50 text-xs font-medium text-slate-400">
          <div className="col-span-3">Field</div>
          <div className="col-span-4">Live (Current Provider)</div>
          <div className="col-span-4">Spoof (F5 XC)</div>
          <div className="col-span-1">Match</div>
        </div>
        {[
          { field: 'Subject CN', live: 'www.example.com', spoof: 'www.example.com', match: true },
          { field: 'Issuer', live: 'DigiCert SHA2 CA', spoof: "Let's Encrypt R3", match: false },
          { field: 'SAN', live: '*.example.com', spoof: '*.example.com', match: true },
          { field: 'Valid Until', live: '2026-12-15', spoof: '2026-09-22', match: false },
          { field: 'Serial Number', live: '0A:1B:2C:3D...', spoof: '7E:8F:9A:0B...', match: false },
        ].map((r, i) => (
          <div key={i} className="grid grid-cols-12 gap-2 px-4 py-2.5 border-t border-slate-700/50 text-xs">
            <div className="col-span-3 text-slate-300 font-medium">{r.field}</div>
            <div className="col-span-4 text-slate-400 font-mono">{r.live}</div>
            <div className="col-span-4 text-slate-400 font-mono">{r.spoof}</div>
            <div className="col-span-1 text-center">
              {r.match
                ? <Check className="w-4 h-4 text-emerald-400 inline" />
                : <X className="w-4 h-4 text-amber-400 inline" />}
            </div>
          </div>
        ))}
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-slate-800/50 border border-emerald-500/30 rounded-xl p-4">
          <h4 className="font-semibold text-emerald-400 text-sm mb-1">Match = Safe to cutover</h4>
          <p className="text-xs text-slate-400">Subject CN and SAN match means the domain is covered by the F5 XC certificate.</p>
        </div>
        <div className="bg-slate-800/50 border border-amber-500/30 rounded-xl p-4">
          <h4 className="font-semibold text-amber-400 text-sm mb-1">Issuer differs = Expected</h4>
          <p className="text-xs text-slate-400">Different issuers are normal when migrating (e.g., DigiCert to Let's Encrypt). As long as the domain coverage matches, this is fine.</p>
        </div>
      </div>
    </div>
  )},

  /* ── Slide 4: Header & Body Diff ── */
  { title: 'Header & Body Diff', component: () => (
    <div>
      <SlideTitle icon={Eye} title="Header & Body Diff" subtitle="Filtered header comparison and body similarity analysis" />
      <div className="mt-6 space-y-5">
        {/* Ignored headers */}
        <div className="bg-slate-800/50 border border-blue-500/30 rounded-xl p-5">
          <h4 className="font-semibold text-blue-400 text-sm mb-3">Ignored Headers (Transient)</h4>
          <p className="text-xs text-slate-400 mb-3">
            These headers are expected to differ between Live and Spoof and are excluded from comparison:
          </p>
          <div className="flex flex-wrap gap-2">
            {['date', 'age', 'x-request-id', 'x-envoy-upstream-service-time', 'server', 'via', 'x-cache', 'x-served-by', 'cf-ray', 'x-amz-request-id'].map(h => (
              <span key={h} className="px-2 py-1 bg-slate-700/60 rounded text-[10px] font-mono text-slate-400">{h}</span>
            ))}
          </div>
        </div>
        {/* Amber highlights */}
        <div className="bg-slate-800/50 border border-amber-500/30 rounded-xl p-5">
          <h4 className="font-semibold text-amber-400 text-sm mb-3">Amber Highlight = Different</h4>
          <p className="text-xs text-slate-400 mb-3">
            Non-transient headers that differ between Live and Spoof are highlighted in amber. These may indicate:
          </p>
          <div className="grid grid-cols-2 gap-2">
            {[
              'Missing security headers on F5 XC side',
              'Different caching behaviour',
              'CORS headers not replicated',
              'Custom headers not forwarded',
            ].map(item => (
              <div key={item} className="flex items-start gap-2 text-xs text-slate-400">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400 mt-0.5 flex-shrink-0" />
                {item}
              </div>
            ))}
          </div>
        </div>
        {/* Body similarity */}
        <div className="bg-slate-800/50 border border-emerald-500/30 rounded-xl p-5">
          <h4 className="font-semibold text-emerald-400 text-sm mb-2">Body Similarity Scoring</h4>
          <div className="flex items-center gap-4 mt-3">
            {[
              { score: '95-100%', label: 'Identical', color: 'text-emerald-400', desc: 'Minor dynamic element differences' },
              { score: '70-94%', label: 'Similar', color: 'text-amber-400', desc: 'Check for missing assets or JS' },
              { score: '< 70%', label: 'Different', color: 'text-red-400', desc: 'Likely wrong content or challenge page' },
            ].map(s => (
              <div key={s.score} className="flex-1 text-center">
                <div className={`text-lg font-bold ${s.color}`}>{s.score}</div>
                <div className="text-xs text-slate-300">{s.label}</div>
                <div className="text-[10px] text-slate-500">{s.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )},

  /* ── Slide 5: Input & Export ── */
  { title: 'Input & Export', component: () => (
    <div>
      <SlideTitle icon={Settings} title="Input Modes & Export" subtitle="CSV import, URL entry, bulk add, and PDF export" />
      <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* URL Mode */}
        <div className="bg-slate-800/50 border border-blue-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <Globe className="w-5 h-5 text-blue-400" />
            <h4 className="font-semibold text-blue-400 text-sm">URL Entry Mode</h4>
          </div>
          <p className="text-xs text-slate-400 mb-2">Enter individual URLs with their spoof IP addresses:</p>
          <div className="bg-slate-900/60 border border-slate-700 rounded p-2 font-mono text-[10px] text-slate-400 space-y-1">
            <div>URL: https://www.example.com/page</div>
            <div>Spoof IP: 185.94.x.x (F5 XC VIP)</div>
            <div className="text-slate-600">Optionally add multiple spoof IPs</div>
          </div>
        </div>
        {/* CSV Mode */}
        <div className="bg-slate-800/50 border border-emerald-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <Database className="w-5 h-5 text-emerald-400" />
            <h4 className="font-semibold text-emerald-400 text-sm">CSV Import Mode</h4>
          </div>
          <p className="text-xs text-slate-400 mb-2">Upload a CSV file for bulk checking:</p>
          <div className="bg-slate-900/60 border border-slate-700 rounded p-2 font-mono text-[10px] text-slate-400 space-y-1">
            <div className="text-slate-600">url, spoof_ip</div>
            <div>https://api.example.com, 185.94.x.x</div>
            <div>https://www.example.com, 185.94.x.x</div>
            <div>https://cdn.example.com, 185.94.y.y</div>
          </div>
        </div>
        {/* Multi-Spoof */}
        <div className="bg-slate-800/50 border border-amber-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <Server className="w-5 h-5 text-amber-400" />
            <h4 className="font-semibold text-amber-400 text-sm">Multi-Spoof IPs</h4>
          </div>
          <p className="text-xs text-slate-400">
            Each URL can be tested against multiple spoof IPs. This is useful when F5 XC has multiple Regional Edge (RE) VIPs
            and you want to verify all of them return the same response.
          </p>
        </div>
        {/* PDF Export */}
        <div className="bg-slate-800/50 border border-red-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <FileJson className="w-5 h-5 text-red-400" />
            <h4 className="font-semibold text-red-400 text-sm">PDF Export</h4>
          </div>
          <p className="text-xs text-slate-400">
            Generate a formatted PDF report with all comparison results, TLS cert details, header diffs, and body similarity scores.
            Paginated results with color-coded pass/fail indicators. Attach to migration change requests.
          </p>
        </div>
      </div>
    </div>
  )},
];
export function HttpSanityExplainer() { return <Slideshow slides={httpSanitySlides} toolName="HTTP Sanity Checker" toolRoute="/http-sanity-checker" toolIcon={Activity} />; }


// ═══════════════════════════════════════════════════════════════════
// TOOL 9: LOG ANALYZER  (5 slides)
// ═══════════════════════════════════════════════════════════════════

const logAnalyzerSlides: SlideDefinition[] = [
  /* ── Slide 1: Overview ── */
  { title: 'Log Analyzer', component: () => (
    <div>
      <SlideTitle icon={BarChart2} title="Log Analyzer" subtitle="Flexible access and security log analytics with custom filters and breakdowns" />
      <p className="text-sm text-slate-400 mt-4 mb-6">
        Analyses F5 XC access logs and security events with server-side aggregation for fast results even on large datasets.
        Choose from 7 time windows (5 min to 14 days), apply multi-field filters, and explore data across 6 analytics tabs.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <FeatureCard icon={BarChart2} title="Field Analytics" description="Analyse any of 70+ log fields -- response codes, countries, paths, user agents, WAF actions -- with automatic distribution charts and top-value tables." color="blue" />
        <FeatureCard icon={Filter} title="Custom Filters" description="Build complex queries with multiple field filters. Combine equals, contains, not-equals, and regex operators. Click any chart value to add as filter." color="emerald" />
        <FeatureCard icon={TrendingUp} title="Dual Log Sources" description="Toggle between Access Logs (request/response data) and Security Events (WAF blocks, bot detections, DDoS triggers) or analyse both simultaneously." color="amber" />
        <FeatureCard icon={FileJson} title="Multi-Format Export" description="Export results as JSON, CSV, Excel, or PDF. Each format optimised for its use case: CSV for spreadsheets, JSON for automation, PDF for reports." color="violet" />
      </div>
    </div>
  )},

  /* ── Slide 2: Analytics Tabs ── */
  { title: 'Analytics Tabs', component: () => (
    <div>
      <SlideTitle icon={Layers} title="6 Analytics Tabs" subtitle="Each tab provides a different perspective on your log data" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
        {[
          {
            tab: 'Overview',
            icon: BarChart2,
            color: 'blue',
            desc: 'Summary cards (total requests, unique IPs, error rate, avg latency), time series chart, and response code distribution. Your starting point for any investigation.',
          },
          {
            tab: 'Distributions',
            icon: Grid3X3,
            color: 'emerald',
            desc: 'Field-by-field breakdown cards. Click any field (country, path, status code, user agent) to see its value distribution with counts and percentages.',
          },
          {
            tab: 'Performance',
            icon: Gauge,
            color: 'amber',
            desc: 'Latency percentiles (p50/p90/p95/p99), slowest requests table, performance by path and by country. Identify slow endpoints and geographic latency patterns.',
          },
          {
            tab: 'Errors',
            icon: AlertTriangle,
            color: 'red',
            desc: 'Error rate analysis by status code class (4xx/5xx), by path, by source IP. Response code detail breakdown (e.g., "upstream_reset_before_response_started").',
          },
          {
            tab: 'Security',
            icon: Shield,
            color: 'violet',
            desc: 'WAF action breakdown, bot classification, top blocked IPs, policy hit results, and suspicious paths with high block rates.',
          },
          {
            tab: 'Top Talkers',
            icon: Users,
            color: 'cyan',
            desc: 'Busiest source IPs ranked by request count, error rate, bandwidth, and WAF blocks. Includes country, ASN, bot class, and top path per IP.',
          },
        ].map(t => {
          const colorMap: Record<string, string> = {
            blue: 'border-blue-500/30 text-blue-400',
            emerald: 'border-emerald-500/30 text-emerald-400',
            amber: 'border-amber-500/30 text-amber-400',
            red: 'border-red-500/30 text-red-400',
            violet: 'border-violet-500/30 text-violet-400',
            cyan: 'border-cyan-500/30 text-cyan-400',
          };
          const c = colorMap[t.color] || colorMap.blue;
          return (
            <div key={t.tab} className={`bg-slate-800/50 border ${c.split(' ')[0]} rounded-xl p-4`}>
              <div className="flex items-center gap-2 mb-2">
                <t.icon className={`w-5 h-5 ${c.split(' ')[1]}`} />
                <h4 className={`font-semibold text-sm ${c.split(' ')[1]}`}>{t.tab}</h4>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">{t.desc}</p>
            </div>
          );
        })}
      </div>
    </div>
  )},

  /* ── Slide 3: Distribution Sections ── */
  { title: 'Distributions', component: () => (
    <div>
      <SlideTitle icon={Grid3X3} title="Field Distribution Cards" subtitle="Click-to-filter drill-down across all log fields" />
      <p className="text-sm text-slate-400 mt-4 mb-5">
        The Distributions tab renders a card for each field group. Each card shows the top values with counts and percentage bars.
        Click any value to add it as a filter and instantly re-query.
      </p>
      {/* Field groups */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
        {[
          { group: 'Request', fields: 'Method, Path, Host, Protocol, User Agent, Browser, Device', color: 'text-blue-400 border-blue-500/30' },
          { group: 'Response', fields: 'Status Code, Code Class, Response Size, Flags', color: 'text-emerald-400 border-emerald-500/30' },
          { group: 'Geo', fields: 'Country, City, ASN, Region, Latitude/Longitude', color: 'text-amber-400 border-amber-500/30' },
          { group: 'Timing', fields: 'Duration, TTFB, RTT Upstream, RTT Downstream', color: 'text-violet-400 border-violet-500/30' },
          { group: 'Routing', fields: 'Virtual Host, Site, Source Site, Instance', color: 'text-cyan-400 border-cyan-500/30' },
          { group: 'Security', fields: 'WAF Action, Bot Class, Policy Result, Threat Type', color: 'text-red-400 border-red-500/30' },
          { group: 'TLS', fields: 'TLS Version, Cipher Suite, Certificate', color: 'text-blue-400 border-blue-500/30' },
          { group: 'Meta', fields: 'Namespace, Tenant, Log Source, Sample Rate', color: 'text-slate-400 border-slate-500/30' },
        ].map(g => (
          <div key={g.group} className={`border ${g.color.split(' ')[1]} bg-slate-800/50 rounded-xl p-3`}>
            <div className={`font-semibold text-xs ${g.color.split(' ')[0]} mb-1`}>{g.group}</div>
            <p className="text-[10px] text-slate-500 leading-relaxed">{g.fields}</p>
          </div>
        ))}
      </div>
      {/* Example distribution card */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4">
        <h4 className="font-semibold text-slate-200 text-sm mb-3">Example: Response Code Distribution</h4>
        <div className="space-y-2">
          {[
            { value: '200', count: 12450, pct: 78, color: 'bg-emerald-500' },
            { value: '301', count: 1840, pct: 12, color: 'bg-blue-500' },
            { value: '404', count: 952, pct: 6, color: 'bg-amber-500' },
            { value: '403', count: 480, pct: 3, color: 'bg-red-500' },
            { value: '500', count: 160, pct: 1, color: 'bg-red-500' },
          ].map(v => (
            <div key={v.value} className="flex items-center gap-3">
              <span className="w-8 text-xs text-slate-300 font-mono text-right">{v.value}</span>
              <div className="flex-1 h-5 bg-slate-700/50 rounded-full overflow-hidden">
                <div className={`h-full ${v.color} rounded-full`} style={{ width: `${v.pct}%` }} />
              </div>
              <span className="text-xs text-slate-400 w-16 text-right">{v.count.toLocaleString()}</span>
              <span className="text-xs text-slate-500 w-10 text-right">{v.pct}%</span>
            </div>
          ))}
        </div>
        <p className="text-[10px] text-slate-600 mt-2">Click any bar to filter log results by that status code</p>
      </div>
    </div>
  )},

  /* ── Slide 4: Field Analysis / Cross-Tabulation ── */
  { title: 'Cross-Tabulation', component: () => (
    <div>
      <SlideTitle icon={Filter} title="Field Breakdown (Cross-Tabulation)" subtitle="Multi-field analysis: break down one field by another" />
      <p className="text-sm text-slate-400 mt-4 mb-5">
        Select a primary field and one or more breakdown fields to see cross-tabulated results.
        For example: "Show top request paths, broken down by response code and country."
      </p>
      {/* Mock cross-tabulation */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl overflow-hidden mb-5">
        <div className="px-4 py-2.5 bg-slate-700/50">
          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400">Primary:</span>
            <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded font-medium">Request Path</span>
            <span className="text-slate-600 mx-1">broken down by</span>
            <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-400 rounded font-medium">Response Code</span>
            <span className="px-2 py-0.5 bg-amber-500/20 text-amber-400 rounded font-medium">Country</span>
          </div>
        </div>
        <div className="divide-y divide-slate-700/50">
          {[
            { path: '/api/v1/users', total: 4500, codes: [{ c: '200', n: 4200 }, { c: '401', n: 250 }, { c: '500', n: 50 }], countries: [{ c: 'US', n: 2100 }, { c: 'UK', n: 1200 }, { c: 'DE', n: 800 }] },
            { path: '/login', total: 2100, codes: [{ c: '200', n: 1800 }, { c: '403', n: 280 }, { c: '429', n: 20 }], countries: [{ c: 'US', n: 900 }, { c: 'CN', n: 600 }, { c: 'RU', n: 350 }] },
          ].map((row, i) => (
            <div key={i} className="px-4 py-3">
              <div className="flex items-center gap-2 mb-2">
                <span className="font-mono text-sm text-slate-200">{row.path}</span>
                <span className="text-xs text-slate-500">({row.total.toLocaleString()} requests)</span>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <span className="text-[10px] text-emerald-400 font-medium">Response Codes:</span>
                  <div className="flex gap-2 mt-1">
                    {row.codes.map(c => (
                      <span key={c.c} className="px-2 py-0.5 bg-slate-700/60 rounded text-[10px] text-slate-300">
                        {c.c}: <span className="text-slate-400">{c.n.toLocaleString()}</span>
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <span className="text-[10px] text-amber-400 font-medium">Countries:</span>
                  <div className="flex gap-2 mt-1">
                    {row.countries.map(c => (
                      <span key={c.c} className="px-2 py-0.5 bg-slate-700/60 rounded text-[10px] text-slate-300">
                        {c.c}: <span className="text-slate-400">{c.n.toLocaleString()}</span>
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="bg-slate-800/50 border border-blue-500/30 rounded-xl p-4">
        <p className="text-xs text-slate-400">
          <span className="text-blue-400 font-semibold">Use cases:</span> "Which paths have the highest 5xx rate?", "Which countries generate the most 403s?",
          "What user agents hit /admin?", "Break down WAF blocks by request path and source country."
        </p>
      </div>
    </div>
  )},

  /* ── Slide 5: Export ── */
  { title: 'Export', component: () => (
    <div>
      <SlideTitle icon={FileJson} title="Multi-Format Export" subtitle="JSON, CSV, Excel, and PDF export for every view" />
      <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* JSON */}
        <div className="bg-slate-800/50 border border-blue-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-8 h-8 rounded-lg bg-blue-500/20 flex items-center justify-center"><FileJson className="w-4 h-4 text-blue-400" /></div>
            <div>
              <h4 className="font-semibold text-blue-400 text-sm">JSON</h4>
              <p className="text-[10px] text-slate-500">For automation and API integration</p>
            </div>
          </div>
          <ul className="space-y-1.5">
            {['Full aggregation data with all fields', 'Preserves numeric types and nested objects', 'Import into Elasticsearch, Splunk, or custom tools', 'Includes query filters and time window metadata'].map(item => (
              <li key={item} className="flex items-start gap-2 text-xs text-slate-400">
                <Check className="w-3.5 h-3.5 text-blue-400 mt-0.5 flex-shrink-0" />
                {item}
              </li>
            ))}
          </ul>
        </div>
        {/* CSV */}
        <div className="bg-slate-800/50 border border-emerald-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/20 flex items-center justify-center"><Database className="w-4 h-4 text-emerald-400" /></div>
            <div>
              <h4 className="font-semibold text-emerald-400 text-sm">CSV</h4>
              <p className="text-[10px] text-slate-500">For spreadsheet analysis</p>
            </div>
          </div>
          <ul className="space-y-1.5">
            {['Flat table format for Excel / Google Sheets', 'One row per log entry or aggregation bucket', 'UTF-8 encoded with proper escaping', 'Quick import into any data analysis tool'].map(item => (
              <li key={item} className="flex items-start gap-2 text-xs text-slate-400">
                <Check className="w-3.5 h-3.5 text-emerald-400 mt-0.5 flex-shrink-0" />
                {item}
              </li>
            ))}
          </ul>
        </div>
        {/* Excel */}
        <div className="bg-slate-800/50 border border-amber-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-8 h-8 rounded-lg bg-amber-500/20 flex items-center justify-center"><Layers className="w-4 h-4 text-amber-400" /></div>
            <div>
              <h4 className="font-semibold text-amber-400 text-sm">Excel (.xlsx)</h4>
              <p className="text-[10px] text-slate-500">For formatted reports</p>
            </div>
          </div>
          <ul className="space-y-1.5">
            {['Multi-sheet workbook (Overview, Distributions, Errors)', 'Auto-filtered columns and freeze panes', 'Conditional formatting for error rates', 'Charts embedded in the workbook'].map(item => (
              <li key={item} className="flex items-start gap-2 text-xs text-slate-400">
                <Check className="w-3.5 h-3.5 text-amber-400 mt-0.5 flex-shrink-0" />
                {item}
              </li>
            ))}
          </ul>
        </div>
        {/* PDF */}
        <div className="bg-slate-800/50 border border-red-500/30 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-8 h-8 rounded-lg bg-red-500/20 flex items-center justify-center"><FileJson className="w-4 h-4 text-red-400" /></div>
            <div>
              <h4 className="font-semibold text-red-400 text-sm">PDF</h4>
              <p className="text-[10px] text-slate-500">For stakeholder reports</p>
            </div>
          </div>
          <ul className="space-y-1.5">
            {['Formatted report with summary statistics', 'Distribution charts as embedded images', 'Top talkers and error analysis tables', 'Branded header with tenant and time window'].map(item => (
              <li key={item} className="flex items-start gap-2 text-xs text-slate-400">
                <Check className="w-3.5 h-3.5 text-red-400 mt-0.5 flex-shrink-0" />
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )},
];
export function LogAnalyzerExplainer() { return <Slideshow slides={logAnalyzerSlides} toolName="Log Analyzer" toolRoute="/log-analyzer" toolIcon={BarChart2} />; }


// ═══════════════════════════════════════════════════════════════════
// REMAINING TOOL STUBS (Part 2 - kept for compilation)
// These retain single-slide overviews and will be expanded later.
// ═══════════════════════════════════════════════════════════════════

// ── CONFIG DUMP ──
const configDumpSlides: SlideDefinition[] = [
  { title: 'Config Dump', component: () => (
    <div>
      <SlideTitle icon={Database} title="Config Dump" subtitle="Export full configuration for any object type with all child objects" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        <FeatureCard icon={Database} title="Complete Export" description="Exports the full configuration tree for any object type -- including all nested child objects and their dependencies." color="blue" />
        <FeatureCard icon={Layers} title="Multiple Object Types" description="Supports HTTP LBs, CDN distributions, origin pools, WAF policies, service policies, and more." color="emerald" />
        <FeatureCard icon={FileJson} title="JSON & PDF" description="Download as structured JSON (for automation/backup) or formatted PDF (for documentation and audits)." color="amber" />
        <FeatureCard icon={Copy} title="Clipboard Support" description="Copy any object's configuration to clipboard with one click for quick pasting into other tools." color="violet" />
      </div>
    </div>
  )},
];
export function ConfigDumpExplainer() { return <Slideshow slides={configDumpSlides} toolName="Config Dump" toolRoute="/config-dump" toolIcon={Database} />; }

// ── LOAD TESTER ──
const loadTesterSlides: SlideDefinition[] = [
  { title: 'Load Tester', component: () => (
    <div>
      <SlideTitle icon={Zap} title="Load Tester" subtitle="Stress test any endpoint with configurable load profiles" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        <FeatureCard icon={Zap} title="4 Load Profiles" description="Constant (steady RPS), Ramp (gradual increase), Step (incremental jumps), and Spike (sudden bursts) -- each simulating different real-world patterns." color="blue" />
        <FeatureCard icon={TrendingUp} title="Real-Time Metrics" description="Live response time charts, throughput graphs, status code distribution, and latency histograms updated in real time during the test." color="emerald" />
        <FeatureCard icon={Target} title="Threshold Rules" description="Set pass/fail criteria: max response time, error rate limits, and Apdex score thresholds. Get an instant pass/fail verdict." color="amber" />
        <FeatureCard icon={Cpu} title="Standalone" description="Runs directly from your browser -- no connection to F5 XC needed. Test any public URL endpoint independently." color="violet" />
      </div>
    </div>
  )},
];
export function LoadTesterExplainer() { return <Slideshow slides={loadTesterSlides} toolName="Load Tester" toolRoute="/load-tester" toolIcon={Zap} />; }

// ── API SHIELD ADVISOR ──
const apiShieldSlides: SlideDefinition[] = [
  { title: 'API Shield Advisor', component: () => (
    <div>
      <SlideTitle icon={Shield} title="API Shield Advisor" subtitle="Guided API security assessment against OWASP API Security Top 10" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        <FeatureCard icon={Shield} title="90+ Security Controls" description="Scans your F5 XC configuration against a comprehensive control framework covering authentication, authorization, rate limiting, input validation, and more." color="blue" />
        <FeatureCard icon={Target} title="OWASP API Top 10" description="Controls are mapped to the OWASP API Security Top 10 (2023) categories -- the definitive standard for API threat modelling." color="red" />
        <FeatureCard icon={TrendingUp} title="Traffic Profiling" description="Analyses real API traffic to identify endpoints, methods, response patterns, and bot activity -- grounding recommendations in actual usage data." color="emerald" />
        <FeatureCard icon={Layers} title="Phased Roadmap" description="Recommendations are organized into implementation phases (Quick Wins -> Core -> Advanced) so you can adopt controls incrementally." color="amber" />
      </div>
    </div>
  )},
];
export function APIShieldExplainer() { return <Slideshow slides={apiShieldSlides} toolName="API Shield Advisor" toolRoute="/api-shield" toolIcon={Shield} />; }

// ── API REPORT ──
const apiReportSlides: SlideDefinition[] = [
  { title: 'API Report', component: () => (
    <div>
      <SlideTitle icon={BarChart2} title="API Report Dashboard" subtitle="API discovery stats, schema parsing, and endpoint reporting" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        <FeatureCard icon={BarChart2} title="Discovery Stats" description="View how many API endpoints F5 XC has discovered on each load balancer, with method and path breakdowns." color="blue" />
        <FeatureCard icon={FileJson} title="Schema Parsing" description="Parse and display learnt API schemas showing endpoint paths, methods, parameters, and request/response types." color="emerald" />
        <FeatureCard icon={Layers} title="Multi-LB Consolidation" description="Aggregate API endpoint data across multiple load balancers into a single consolidated report." color="amber" />
        <FeatureCard icon={FileJson} title="Excel Export" description="Export the complete API inventory as an Excel workbook for documentation, compliance, or sharing with development teams." color="violet" />
      </div>
    </div>
  )},
];
export function APIReportExplainer() { return <Slideshow slides={apiReportSlides} toolName="API Report" toolRoute="/api-report" toolIcon={BarChart2} />; }

// ── LIVE SOC ROOM ──
const socRoomSlides: SlideDefinition[] = [
  { title: 'Live SOC Room', component: () => (
    <div>
      <SlideTitle icon={Activity} title="Live SOC Room" subtitle="Real-time security operations center with continuous monitoring" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        <FeatureCard icon={Activity} title="Continuous Monitoring" description="Monitors your F5 XC deployment in real time with live dashboards showing RPS, error rates, and security events as they happen." color="blue" />
        <FeatureCard icon={AlertTriangle} title="Anomaly Detection" description="23 built-in anomaly detectors identify unusual patterns in traffic, errors, geography, and security events." color="red" />
        <FeatureCard icon={Zap} title="Auto-Investigation" description="12 automated investigation workflows trigger when anomalies are detected -- gathering context and evidence automatically." color="emerald" />
        <FeatureCard icon={Users} title="Multi-Room" description="Create separate SOC rooms for different environments, teams, or incidents. Each room has independent monitoring and alert state." color="amber" />
      </div>
    </div>
  )},
];
export function SOCRoomExplainer() { return <Slideshow slides={socRoomSlides} toolName="SOC Lobby" toolRoute="/soc-lobby" toolIcon={Activity} />; }

// ── PREFIX BUILDER ──
const prefixBuilderSlides: SlideDefinition[] = [
  { title: 'Prefix Builder', component: () => (
    <div>
      <SlideTitle icon={Grid3X3} title="Prefix Builder" subtitle="Build IP prefix sets in bulk for firewall and routing rules" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        <FeatureCard icon={Grid3X3} title="Bulk Creation" description="Create IP prefix sets with hundreds of entries at once -- via manual input or CSV import. Supports both IPv4 and IPv6." color="blue" />
        <FeatureCard icon={Layers} title="Multi-Set Mode" description="Create multiple prefix sets in one operation. Each set can have its own name, description, and IP list." color="emerald" />
        <FeatureCard icon={Shield} title="Policy Attachment" description="Optionally attach the created prefix set to a new or existing service policy -- configuring allow/deny rules in one step." color="amber" />
        <FeatureCard icon={Check} title="Validation" description="All IP addresses and CIDR ranges are validated before submission. Invalid entries are flagged with clear error messages." color="violet" />
      </div>
    </div>
  )},
];
export function PrefixBuilderExplainer() { return <Slideshow slides={prefixBuilderSlides} toolName="Prefix Builder" toolRoute="/prefix-builder" toolIcon={Grid3X3} />; }

// ── COPY CONFIG ──
const copyConfigSlides: SlideDefinition[] = [
  { title: 'Copy Config', component: () => (
    <div>
      <SlideTitle icon={Copy} title="Copy Config" subtitle="Copy configuration objects across tenants or namespaces" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        <FeatureCard icon={Copy} title="Cross-Tenant Copy" description="Copy alert receivers, policies, and CDN cache rules from one F5 XC tenant to another. Useful for managed service providers." color="blue" />
        <FeatureCard icon={Split} title="Cross-Namespace" description="Clone configuration objects between namespaces within the same tenant -- for environment promotion (dev -> staging -> prod)." color="emerald" />
        <FeatureCard icon={Eye} title="Preview Before Copy" description="View the full JSON of each object before copying. Verify what will be created in the destination." color="amber" />
        <FeatureCard icon={Check} title="Result Tracking" description="See the status of each copied object -- success, failure, or already exists -- with detailed error messages for any failures." color="violet" />
      </div>
    </div>
  )},
];
export function CopyConfigExplainer() { return <Slideshow slides={copyConfigSlides} toolName="Copy Config" toolRoute="/copy-config" toolIcon={Copy} />; }

// ── PROPERTY VIEWER ──
const propertyViewerSlides: SlideDefinition[] = [
  { title: 'Property Viewer', component: () => (
    <div>
      <SlideTitle icon={Layers} title="Property Viewer" subtitle="View any property across all config objects at a glance" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        <FeatureCard icon={Layers} title="Cross-Object View" description="Select a property (e.g., WAF mode, TLS version, timeout) and see its value across ALL load balancers or origin pools at once." color="blue" />
        <FeatureCard icon={BarChart2} title="Value Distribution" description="Instantly see how many objects have each value -- e.g., '12 LBs on TLSv1.3, 3 on TLSv1.2, 1 with no TLS'." color="emerald" />
        <FeatureCard icon={Grid3X3} title="Card & Table Views" description="Switch between card view (visual overview) and table view (detailed comparison) depending on your needs." color="amber" />
        <FeatureCard icon={FileJson} title="Multi-Format Export" description="Export as CSV, Excel, or JSON. Use for compliance reporting, change management, or configuration audits." color="violet" />
      </div>
    </div>
  )},
];
export function PropertyViewerExplainer() { return <Slideshow slides={propertyViewerSlides} toolName="Property Viewer" toolRoute="/property-viewer" toolIcon={Layers} />; }

// ── HTTP LB FORGE ──
const httpLbForgeSlides: SlideDefinition[] = [
  { title: 'HTTP LB Forge', component: () => (
    <div>
      <SlideTitle icon={Hammer} title="HTTP LB Forge" subtitle="Create multiple HTTP Load Balancers at scale from CSV input" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mt-8">
        <FeatureCard icon={Hammer} title="Bulk Creation" description="Define multiple load balancers in a CSV file -- domain, origin, type -- and create them all at once. No clicking through the console for each one." color="blue" />
        <FeatureCard icon={Lock} title="Auto Certificate" description="Automatically matches existing TLS certificates to domains, or creates new ones. Handles both HTTP and HTTPS types." color="emerald" />
        <FeatureCard icon={Server} title="Origin Pool Generation" description="Creates origin pools alongside LBs. Specify origin servers, ports, and health check settings in the CSV." color="amber" />
        <FeatureCard icon={Shield} title="WAF Auto-Assign" description="Optionally assigns an existing WAF policy to all created LBs -- ensuring security from day one." color="red" />
      </div>
    </div>
  )},
];
export function HttpLbForgeExplainer() { return <Slideshow slides={httpLbForgeSlides} toolName="HTTP LB Forge" toolRoute="/http-lb-forge" toolIcon={Hammer} />; }
