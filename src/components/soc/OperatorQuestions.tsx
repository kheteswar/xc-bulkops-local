import React, { useState, useMemo } from 'react';
import {
  Heart, Shield, Gauge, HardDrive, Lock, Bot, Server, Settings,
  TrendingUp, TrendingDown, Minus, HelpCircle,
} from 'lucide-react';
import type { SOCRoomState, OperatorAnswer, OperatorTab } from '../../services/live-soc/types';

interface OperatorQuestionsProps {
  state: SOCRoomState;
}

interface QuestionDef {
  question: string;
  compute: (state: SOCRoomState) => OperatorAnswer;
}

const TAB_CONFIG: Array<{ id: OperatorTab; label: string; icon: React.ReactNode }> = [
  { id: 'health', label: 'Health', icon: <Heart className="w-3.5 h-3.5" /> },
  { id: 'security', label: 'Security', icon: <Shield className="w-3.5 h-3.5" /> },
  { id: 'performance', label: 'Performance', icon: <Gauge className="w-3.5 h-3.5" /> },
  { id: 'cdn', label: 'CDN', icon: <HardDrive className="w-3.5 h-3.5" /> },
  { id: 'api_security', label: 'API Security', icon: <Lock className="w-3.5 h-3.5" /> },
  { id: 'bot_defense', label: 'Bot Defense', icon: <Bot className="w-3.5 h-3.5" /> },
  { id: 'infrastructure', label: 'Infrastructure', icon: <Server className="w-3.5 h-3.5" /> },
  { id: 'operations', label: 'Operations', icon: <Settings className="w-3.5 h-3.5" /> },
];

function statusDotColor(status: OperatorAnswer['status']): string {
  switch (status) {
    case 'good': return '#00ff88';
    case 'warning': return '#ffbe0b';
    case 'critical': return '#ff0040';
    case 'info': return '#00d4ff';
    case 'unknown': return '#6b7280';
  }
}

function statusBorderClass(status: OperatorAnswer['status']): string {
  switch (status) {
    case 'good': return 'border-[#00ff88]/20';
    case 'warning': return 'border-[#ffbe0b]/20';
    case 'critical': return 'border-[#ff0040]/20';
    case 'info': return 'border-[#00d4ff]/20';
    case 'unknown': return 'border-gray-600/20';
  }
}

function TrendArrow({ trend }: { trend?: 'up' | 'down' | 'stable' }) {
  if (!trend || trend === 'stable') return <Minus className="w-3 h-3 text-gray-500" />;
  if (trend === 'up') return <TrendingUp className="w-3 h-3 text-[#00ff88]" />;
  return <TrendingDown className="w-3 h-3 text-[#ff0040]" />;
}

// ---------------------------------------------------------------------------
// Question definitions per tab
// ---------------------------------------------------------------------------

const HEALTH_QUESTIONS: QuestionDef[] = [
  {
    question: 'Is the application up?',
    compute: (s) => {
      const { totalRequests, errorRate } = s.metrics;
      const has2xx = s.metrics.responseCodeDist.some((d) => d.code.startsWith('2') && d.count > 0);
      if (totalRequests === 0) return { status: 'unknown', summary: 'No traffic observed' };
      const critical = s.alerts.some((a) => a.severity === 'critical');
      if (critical) return { status: 'critical', summary: 'Critical alerts active', value: `${errorRate.toFixed(2)}% errors` };
      if (has2xx && errorRate < 5) return { status: 'good', summary: 'Serving 2xx responses normally', value: `${(100 - errorRate).toFixed(1)}% success` };
      if (errorRate >= 5) return { status: 'warning', summary: `Elevated error rate: ${errorRate.toFixed(2)}%`, value: `${errorRate.toFixed(2)}%` };
      return { status: 'good', summary: 'Application responding', value: `${totalRequests} reqs` };
    },
  },
  {
    question: 'Are all origins healthy?',
    compute: (s) => {
      const origins = s.metrics.originHealth;
      if (origins.length === 0) return { status: 'unknown', summary: 'No origin data available' };
      const unhealthy = origins.filter((o) => o.errorRate > 5);
      if (unhealthy.length === 0) return { status: 'good', summary: `All ${origins.length} origins healthy`, value: `${origins.length} origins` };
      if (unhealthy.length === origins.length) return { status: 'critical', summary: 'All origins reporting errors', value: `${unhealthy.length}/${origins.length} failing` };
      return { status: 'warning', summary: `${unhealthy.length} origin(s) with elevated errors`, value: `${unhealthy.length} degraded` };
    },
  },
  {
    question: "What's the error rate?",
    compute: (s) => {
      const { errorRate, prevErrorRate } = s.metrics;
      const trend = errorRate > prevErrorRate + 0.5 ? 'up' as const : errorRate < prevErrorRate - 0.5 ? 'down' as const : 'stable' as const;
      if (errorRate < 1) return { status: 'good', summary: 'Error rate nominal', value: `${errorRate.toFixed(2)}%`, trend };
      if (errorRate < 5) return { status: 'warning', summary: 'Elevated error rate', value: `${errorRate.toFixed(2)}%`, trend };
      return { status: 'critical', summary: 'High error rate', value: `${errorRate.toFixed(2)}%`, trend };
    },
  },
  {
    question: "What's causing 5xx errors?",
    compute: (s) => {
      const diag = s.metrics.errorDiagnosis.filter((d) => d.rspCode.startsWith('5'));
      if (diag.length === 0) return { status: 'good', summary: 'No 5xx errors detected' };
      const top = diag.sort((a, b) => b.count - a.count)[0];
      return {
        status: diag.some((d) => d.severity === 'CRITICAL') ? 'critical' : 'warning',
        summary: `Top: ${top.rspCodeDetails} (${top.rootCause})`,
        value: `${diag.reduce((a, d) => a + d.count, 0)} errors`,
        details: diag.map((d) => `${d.rspCodeDetails}: ${d.count} — ${d.rootCause}`).join('; '),
      };
    },
  },
  {
    question: 'Are there active alerts?',
    compute: (s) => {
      const alerts = s.alerts;
      if (alerts.length === 0) return { status: 'good', summary: 'No active alerts' };
      const critical = alerts.filter((a) => a.severity === 'critical').length;
      const major = alerts.filter((a) => a.severity === 'major').length;
      if (critical > 0) return { status: 'critical', summary: `${critical} critical, ${major} major alerts`, value: `${alerts.length} total` };
      if (major > 0) return { status: 'warning', summary: `${major} major alerts active`, value: `${alerts.length} total` };
      return { status: 'info', summary: `${alerts.length} minor alert(s)`, value: `${alerts.length}` };
    },
  },
  {
    question: 'Any config changes recently?',
    compute: (s) => {
      const count = s.auditEntries.length;
      if (count === 0) return { status: 'good', summary: 'No recent config changes' };
      const latest = s.auditEntries[0];
      return {
        status: count > 5 ? 'warning' : 'info',
        summary: `${count} change(s) — last by ${latest?.user || 'unknown'}`,
        value: `${count} changes`,
        details: latest ? `${latest.operation} on ${latest.objectType}/${latest.objectName}` : undefined,
      };
    },
  },
];

const SECURITY_QUESTIONS: QuestionDef[] = [
  {
    question: 'Are we under attack?',
    compute: (s) => {
      const lvl = s.threatLevel;
      if (lvl === 'NOMINAL') return { status: 'good', summary: 'Threat level nominal — no active attacks detected' };
      if (lvl === 'ELEVATED') return { status: 'warning', summary: 'Elevated threat level — anomalies detected', value: `${s.activeAnomalies.length} anomalies` };
      if (lvl === 'HIGH') return { status: 'warning', summary: 'High threat level — investigate immediately', value: `${s.incidents.filter((i) => i.status === 'active').length} incidents` };
      return { status: 'critical', summary: 'CRITICAL — active attack in progress', value: `${s.incidents.filter((i) => i.status === 'active').length} incidents` };
    },
  },
  {
    question: 'Top WAF signatures?',
    compute: (s) => {
      const sigs = s.metrics.topSignatures;
      if (sigs.length === 0) return { status: 'good', summary: 'No WAF signatures firing' };
      const top = sigs[0];
      return {
        status: sigs.length > 5 ? 'warning' : 'info',
        summary: `Top: ${top.id} (${top.count} hits)`,
        value: `${sigs.length} signatures`,
        details: sigs.slice(0, 5).map((s) => `${s.id}: ${s.count}`).join(', '),
      };
    },
  },
  {
    question: 'Who is attacking?',
    compute: (s) => {
      const ips = s.metrics.topAttackingIps;
      if (ips.length === 0) return { status: 'good', summary: 'No attacking sources identified' };
      const top = ips[0];
      const ja4Insight = s.ja4Clusters.length > 0
        ? ` (${s.ja4Clusters.length} JA4 clusters)`
        : '';
      return {
        status: ips.length > 10 ? 'warning' : 'info',
        summary: `Top: ${top.ip}${top.country ? ` (${top.country})` : ''} — ${top.count} events${ja4Insight}`,
        value: `${ips.length} sources`,
      };
    },
  },
  {
    question: 'Any false positives?',
    compute: (s) => {
      const sigs = s.metrics.topSignatures;
      if (sigs.length === 0) return { status: 'good', summary: 'No signatures to evaluate' };
      return { status: 'info', summary: 'Use FP Analyzer for detailed assessment', value: `${sigs.length} signatures to review` };
    },
  },
  {
    question: 'Bot traffic normal?',
    compute: (s) => {
      if (!s.botOverview) return { status: 'unknown', summary: 'Bot Defense not enabled' };
      const { maliciousBotPct } = s.botOverview;
      const trend = s.baseline.avgBotRatio > 0 && maliciousBotPct > s.baseline.avgBotRatio * 1.5
        ? 'up' as const : 'stable' as const;
      if (maliciousBotPct < 5) return { status: 'good', summary: `${maliciousBotPct.toFixed(1)}% malicious bots — normal`, value: `${maliciousBotPct.toFixed(1)}%`, trend };
      if (maliciousBotPct < 20) return { status: 'warning', summary: `${maliciousBotPct.toFixed(1)}% malicious bots — elevated`, value: `${maliciousBotPct.toFixed(1)}%`, trend };
      return { status: 'critical', summary: `${maliciousBotPct.toFixed(1)}% malicious bots — high`, value: `${maliciousBotPct.toFixed(1)}%`, trend };
    },
  },
  {
    question: 'Rate limits being hit?',
    compute: (s) => {
      const rlActions = s.metrics.wafActions.filter((a) => a.action.toLowerCase().includes('rate'));
      if (rlActions.length === 0) return { status: 'good', summary: 'No rate limiting actions observed' };
      const total = rlActions.reduce((a, r) => a + r.count, 0);
      return { status: total > 100 ? 'warning' : 'info', summary: `${total} requests rate-limited`, value: `${total}` };
    },
  },
];

const PERFORMANCE_QUESTIONS: QuestionDef[] = [
  {
    question: 'How fast is the app?',
    compute: (s) => {
      const p95 = s.latencyStats.p95;
      if (p95 === 0) return { status: 'unknown', summary: 'No latency data available' };
      const trend = s.baseline.avgLatencyP95 > 0 && p95 > s.baseline.avgLatencyP95 * 1.5
        ? 'up' as const : 'stable' as const;
      if (p95 < 200) return { status: 'good', summary: `P95 latency: ${p95.toFixed(0)}ms`, value: `${p95.toFixed(0)}ms`, trend };
      if (p95 < 1000) return { status: 'warning', summary: `P95 latency elevated: ${p95.toFixed(0)}ms`, value: `${p95.toFixed(0)}ms`, trend };
      return { status: 'critical', summary: `P95 latency high: ${(p95 / 1000).toFixed(2)}s`, value: `${(p95 / 1000).toFixed(2)}s`, trend };
    },
  },
  {
    question: 'Origin slow?',
    compute: (s) => {
      const ttfb = s.latencyStats.originTTFB_p95;
      if (ttfb === 0) return { status: 'unknown', summary: 'No origin TTFB data' };
      if (ttfb < 200) return { status: 'good', summary: `Origin TTFB P95: ${ttfb.toFixed(0)}ms`, value: `${ttfb.toFixed(0)}ms` };
      if (ttfb < 1000) return { status: 'warning', summary: `Origin TTFB elevated: ${ttfb.toFixed(0)}ms`, value: `${ttfb.toFixed(0)}ms` };
      return { status: 'critical', summary: `Origin TTFB high: ${(ttfb / 1000).toFixed(2)}s`, value: `${(ttfb / 1000).toFixed(2)}s` };
    },
  },
  {
    question: 'Slowest paths?',
    compute: (s) => {
      const paths = s.metrics.hotPaths.filter((p) => p.count > 0).sort((a, b) => b.errorRate - a.errorRate);
      if (paths.length === 0) return { status: 'unknown', summary: 'No path data available' };
      const worst = paths[0];
      return {
        status: worst.errorRate > 5 ? 'warning' : 'info',
        summary: `Highest error path: ${worst.path} (${worst.errorRate.toFixed(1)}%)`,
        value: `${paths.length} paths`,
      };
    },
  },
  {
    question: 'Traffic volume?',
    compute: (s) => {
      const { rps, prevRps } = s.metrics;
      const trend = rps > prevRps * 1.2 ? 'up' as const : rps < prevRps * 0.8 ? 'down' as const : 'stable' as const;
      const formatted = rps >= 1000 ? `${(rps / 1000).toFixed(1)}K` : rps.toFixed(1);
      return { status: 'info', summary: `${formatted} requests/sec`, value: `${formatted} rps`, trend };
    },
  },
  {
    question: 'Traffic by country?',
    compute: (s) => {
      const geo = s.metrics.geoDistribution;
      if (geo.length === 0) return { status: 'unknown', summary: 'No geo data available' };
      const newCountries = geo.filter((g) => g.isNew);
      if (newCountries.length > 0) {
        return {
          status: 'warning',
          summary: `New traffic from: ${newCountries.map((c) => c.country).join(', ')}`,
          value: `${geo.length} countries`,
        };
      }
      return { status: 'info', summary: `Top: ${geo[0].country} (${geo[0].pct.toFixed(1)}%)`, value: `${geo.length} countries` };
    },
  },
  {
    question: 'Cross-site routing?',
    compute: (_s) => {
      return { status: 'info', summary: 'Requires raw log analysis for cross-site detection', details: 'Check if src_site differs from dst_site in access logs' };
    },
  },
];

const CDN_QUESTIONS: QuestionDef[] = [
  {
    question: 'Cache hit ratio?',
    compute: (s) => {
      const ratio = s.metrics.cacheHitRatio;
      if (ratio === null) return { status: 'unknown', summary: 'CDN not configured' };
      if (ratio >= 90) return { status: 'good', summary: `${ratio.toFixed(1)}% cache hit ratio`, value: `${ratio.toFixed(1)}%` };
      if (ratio >= 70) return { status: 'warning', summary: `${ratio.toFixed(1)}% — room for improvement`, value: `${ratio.toFixed(1)}%` };
      return { status: 'critical', summary: `${ratio.toFixed(1)}% — most requests missing cache`, value: `${ratio.toFixed(1)}%` };
    },
  },
  {
    question: 'Why are requests missing cache?',
    compute: (s) => {
      if (s.metrics.cacheHitRatio === null) return { status: 'unknown', summary: 'CDN not configured' };
      return { status: 'info', summary: 'Review CDN Monitor panel for miss reason breakdown', details: 'Common causes: no cache-control, set-cookie, non-GET methods' };
    },
  },
  {
    question: 'WAF set-cookie causing misses?',
    compute: (_s) => {
      return { status: 'info', summary: 'Check CDN Monitor panel for TS cookie detection', details: 'If detected: configure Ignore-Response-Cookie in CDN distribution' };
    },
  },
  {
    question: 'Origin pull rate?',
    compute: (s) => {
      const ratio = s.metrics.cacheHitRatio;
      if (ratio === null) return { status: 'unknown', summary: 'CDN not configured' };
      const pullRate = 100 - ratio;
      if (pullRate < 20) return { status: 'good', summary: `${pullRate.toFixed(1)}% origin pull rate`, value: `${pullRate.toFixed(1)}%` };
      if (pullRate < 40) return { status: 'warning', summary: `${pullRate.toFixed(1)}% — moderate origin load`, value: `${pullRate.toFixed(1)}%` };
      return { status: 'critical', summary: `${pullRate.toFixed(1)}% — heavy origin load`, value: `${pullRate.toFixed(1)}%` };
    },
  },
  {
    question: 'TTFB hit vs miss?',
    compute: (s) => {
      if (s.metrics.cacheHitRatio === null) return { status: 'unknown', summary: 'CDN not configured' };
      return { status: 'info', summary: 'Requires raw log analysis to split TTFB by cache status', details: 'Compare time_to_first_downstream_tx_byte for HIT vs MISS' };
    },
  },
];

const API_SECURITY_QUESTIONS: QuestionDef[] = [
  {
    question: 'How many API endpoints?',
    compute: (s) => {
      if (!s.apiSecurity) return { status: 'unknown', summary: 'API Security not enabled' };
      return {
        status: s.apiSecurity.shadowEndpoints > 0 ? 'warning' : 'info',
        summary: `${s.apiSecurity.totalEndpoints} discovered, ${s.apiSecurity.shadowEndpoints} shadow`,
        value: `${s.apiSecurity.totalEndpoints} endpoints`,
      };
    },
  },
  {
    question: 'New/unknown APIs?',
    compute: (s) => {
      if (!s.apiSecurity) return { status: 'unknown', summary: 'API Security not enabled' };
      const shadow = s.apiSecurity.shadowEndpoints;
      if (shadow === 0) return { status: 'good', summary: 'No shadow/unknown endpoints detected' };
      return { status: 'warning', summary: `${shadow} shadow endpoint(s) discovered`, value: `${shadow}` };
    },
  },
  {
    question: 'Sensitive data exposed?',
    compute: (s) => {
      if (!s.apiSecurity) return { status: 'unknown', summary: 'API Security not enabled' };
      const sensitive = s.apiSecurity.sensitiveData;
      if (sensitive.length === 0) return { status: 'good', summary: 'No sensitive data exposure detected' };
      const high = sensitive.filter((d) => d.riskLevel === 'high');
      return {
        status: high.length > 0 ? 'critical' : 'warning',
        summary: `${sensitive.length} data exposure(s) found`,
        value: `${sensitive.length} exposures`,
      };
    },
  },
  {
    question: 'Authentication issues?',
    compute: (s) => {
      if (!s.apiSecurity) return { status: 'unknown', summary: 'API Security not enabled' };
      const unauth = s.apiSecurity.unauthenticatedEndpoints;
      if (unauth === 0) return { status: 'good', summary: 'All endpoints properly authenticated' };
      return { status: 'warning', summary: `${unauth} unauthenticated endpoint(s)`, value: `${unauth}` };
    },
  },
  {
    question: 'Known vulnerabilities?',
    compute: (s) => {
      if (!s.apiSecurity) return { status: 'unknown', summary: 'API Security not enabled' };
      const vulns = s.apiSecurity.vulnerabilities;
      if (vulns.length === 0) return { status: 'good', summary: 'No known vulnerabilities' };
      const critical = vulns.filter((v) => v.severity.toLowerCase() === 'critical');
      return {
        status: critical.length > 0 ? 'critical' : 'warning',
        summary: `${vulns.length} vulnerability(ies) — ${critical.length} critical`,
        value: `${vulns.length} vulns`,
      };
    },
  },
];

const BOT_DEFENSE_QUESTIONS: QuestionDef[] = [
  {
    question: "% of traffic that's bots?",
    compute: (s) => {
      if (!s.botOverview) return { status: 'unknown', summary: 'Bot Defense not enabled' };
      const botPct = s.botOverview.goodBotPct + s.botOverview.maliciousBotPct;
      return {
        status: s.botOverview.maliciousBotPct > 20 ? 'critical' : botPct > 30 ? 'warning' : 'info',
        summary: `${s.botOverview.humanPct.toFixed(1)}% human, ${s.botOverview.goodBotPct.toFixed(1)}% good bot, ${s.botOverview.maliciousBotPct.toFixed(1)}% malicious`,
        value: `${botPct.toFixed(1)}% bot`,
      };
    },
  },
  {
    question: 'Credential stuffing?',
    compute: (s) => {
      if (!s.botOverview) return { status: 'unknown', summary: 'Bot Defense not enabled' };
      if (s.botOverview.credentialStuffingDetected) {
        return { status: 'critical', summary: 'Credential stuffing attack DETECTED', value: 'Active' };
      }
      return { status: 'good', summary: 'No credential stuffing detected', value: 'None' };
    },
  },
  {
    question: 'What are bots doing?',
    compute: (s) => {
      if (!s.botOverview) return { status: 'unknown', summary: 'Bot Defense not enabled' };
      const intents = s.botOverview.attackIntent;
      if (intents.length === 0) return { status: 'good', summary: 'No malicious bot intent detected' };
      const top = intents[0];
      return {
        status: 'info',
        summary: `Top intent: ${top.intent} (${top.pct.toFixed(1)}%)`,
        value: `${intents.length} intents`,
        details: intents.map((i) => `${i.intent}: ${i.pct.toFixed(1)}%`).join(', '),
      };
    },
  },
  {
    question: 'Bot defense effective?',
    compute: (s) => {
      if (!s.botOverview) return { status: 'unknown', summary: 'Bot Defense not enabled' };
      const actions = s.botOverview.mitigationActions;
      if (actions.length === 0) return { status: 'info', summary: 'No mitigation data available' };
      const blocked = actions.find((a) => a.action.toLowerCase().includes('block'));
      const challenged = actions.find((a) => a.action.toLowerCase().includes('challenge'));
      return {
        status: 'info',
        summary: `Block: ${blocked?.pct.toFixed(1) ?? 0}%, Challenge: ${challenged?.pct.toFixed(1) ?? 0}%`,
        value: `${(blocked?.pct ?? 0) + (challenged?.pct ?? 0)}% mitigated`,
      };
    },
  },
  {
    question: 'Top bot attackers?',
    compute: (s) => {
      if (!s.botOverview) return { status: 'unknown', summary: 'Bot Defense not enabled' };
      const ips = s.botOverview.topMaliciousIps;
      if (ips.length === 0) return { status: 'good', summary: 'No malicious bot IPs identified' };
      return {
        status: ips.length > 5 ? 'warning' : 'info',
        summary: `Top: ${ips[0].ip} (${ips[0].count} events)`,
        value: `${ips.length} IPs`,
      };
    },
  },
];

const INFRASTRUCTURE_QUESTIONS: QuestionDef[] = [
  {
    question: 'L3/L4 DDoS attacks?',
    compute: (s) => {
      if (!s.infraProtect) return { status: 'unknown', summary: 'InfraProtect not enabled' };
      const alerts = s.infraProtect.alerts;
      if (alerts.length === 0) return { status: 'good', summary: 'No L3/L4 DDoS alerts' };
      return {
        status: alerts.some((a) => a.severity.toLowerCase() === 'critical') ? 'critical' : 'warning',
        summary: `${alerts.length} DDoS alert(s) active`,
        value: `${alerts.length} alerts`,
      };
    },
  },
  {
    question: 'Active mitigations?',
    compute: (s) => {
      if (!s.infraProtect) return { status: 'unknown', summary: 'InfraProtect not enabled' };
      const mits = s.infraProtect.activeMitigations;
      if (mits.length === 0) return { status: 'good', summary: 'No active mitigations' };
      const totalIps = mits.reduce((a, m) => a + m.mitigatedIps, 0);
      return { status: 'info', summary: `${mits.length} mitigation(s) active, ${totalIps} IPs blocked`, value: `${totalIps} IPs` };
    },
  },
  {
    question: 'Synthetic monitors passing?',
    compute: (s) => {
      if (!s.syntheticHealth) return { status: 'unknown', summary: 'Synthetic monitors not configured' };
      const monitors = s.syntheticHealth.monitors;
      const unhealthy = monitors.filter((m) => m.status === 'unhealthy');
      if (unhealthy.length === 0) return { status: 'good', summary: `All ${monitors.length} monitors passing`, value: `${s.syntheticHealth.globalAvailabilityPct.toFixed(1)}%` };
      return {
        status: 'critical',
        summary: `${unhealthy.length}/${monitors.length} monitors failing`,
        value: `${s.syntheticHealth.globalAvailabilityPct.toFixed(1)}%`,
      };
    },
  },
  {
    question: 'DNS resolution working?',
    compute: (s) => {
      if (!s.dnsHealth) return { status: 'unknown', summary: 'DNS monitoring not configured' };
      const lbs = s.dnsHealth.loadBalancers;
      const degraded = lbs.filter((lb) => lb.status !== 'healthy');
      if (degraded.length === 0) return { status: 'good', summary: `All ${lbs.length} DNS LBs healthy` };
      return {
        status: degraded.some((d) => d.status === 'down') ? 'critical' : 'warning',
        summary: `${degraded.length} DNS LB(s) degraded/down`,
        value: `${degraded.length} issues`,
      };
    },
  },
  {
    question: 'Top volumetric talkers?',
    compute: (s) => {
      if (!s.infraProtect) return { status: 'unknown', summary: 'InfraProtect not enabled' };
      const talkers = s.infraProtect.topTalkers;
      if (talkers.length === 0) return { status: 'good', summary: 'No volumetric anomalies' };
      const top = talkers[0];
      const bps = top.bps >= 1e9 ? `${(top.bps / 1e9).toFixed(1)} Gbps` : `${(top.bps / 1e6).toFixed(1)} Mbps`;
      return { status: 'warning', summary: `Top talker: ${top.ip} at ${bps}`, value: `${talkers.length} talkers` };
    },
  },
];

const OPERATIONS_QUESTIONS: QuestionDef[] = [
  {
    question: 'WAF policy config?',
    compute: (s) => {
      const wafActions = s.metrics.wafActions;
      if (wafActions.length === 0) return { status: 'info', summary: 'No WAF action data — check LB config for WAF mode' };
      const blocking = wafActions.some((a) => a.action.toLowerCase().includes('block') && a.count > 0);
      return {
        status: 'info',
        summary: blocking ? 'WAF in blocking mode — actively enforcing' : 'WAF may be in monitoring mode',
        value: blocking ? 'Blocking' : 'Monitor',
      };
    },
  },
  {
    question: 'Certificates expiring?',
    compute: (s) => {
      if (!s.syntheticHealth) return { status: 'unknown', summary: 'Synthetic monitors not configured for TLS checks' };
      const certs = s.syntheticHealth.tlsCerts;
      if (certs.length === 0) return { status: 'info', summary: 'No TLS certificate data available' };
      const critical = certs.filter((c) => c.status === 'critical');
      const warning = certs.filter((c) => c.status === 'warning');
      if (critical.length > 0) {
        return {
          status: 'critical',
          summary: `${critical[0].domain} expires in ${critical[0].daysUntilExpiry} days!`,
          value: `${critical.length} critical`,
        };
      }
      if (warning.length > 0) {
        return {
          status: 'warning',
          summary: `${warning[0].domain} expires in ${warning[0].daysUntilExpiry} days`,
          value: `${warning.length} expiring`,
        };
      }
      return { status: 'good', summary: 'All certificates valid', value: `${certs.length} certs` };
    },
  },
  {
    question: 'Config changes today?',
    compute: (s) => {
      const entries = s.auditEntries;
      if (entries.length === 0) return { status: 'good', summary: 'No config changes recorded' };
      return { status: entries.length > 10 ? 'warning' : 'info', summary: `${entries.length} change(s) in audit window`, value: `${entries.length}` };
    },
  },
  {
    question: 'Baseline learning status?',
    compute: (s) => {
      const samples = s.baseline.sampleCount;
      if (samples === 0) return { status: 'info', summary: 'Baseline not yet established — collecting data' };
      if (samples < 12) return { status: 'warning', summary: `Baseline learning: ${samples}/12 samples`, value: `${samples} samples` };
      return { status: 'good', summary: `Baseline stable with ${samples} samples`, value: `${samples} samples` };
    },
  },
  {
    question: 'Active investigations?',
    compute: (s) => {
      const active = s.activeInvestigations.length;
      const completed = s.completedInvestigations.length;
      if (active === 0 && completed === 0) return { status: 'good', summary: 'No investigations' };
      if (active === 0) return { status: 'info', summary: `${completed} completed investigation(s)`, value: `${completed} done` };
      return { status: 'info', summary: `${active} active, ${completed} completed`, value: `${active} running` };
    },
  },
];

const QUESTIONS_BY_TAB: Record<OperatorTab, QuestionDef[]> = {
  health: HEALTH_QUESTIONS,
  security: SECURITY_QUESTIONS,
  performance: PERFORMANCE_QUESTIONS,
  cdn: CDN_QUESTIONS,
  api_security: API_SECURITY_QUESTIONS,
  bot_defense: BOT_DEFENSE_QUESTIONS,
  infrastructure: INFRASTRUCTURE_QUESTIONS,
  operations: OPERATIONS_QUESTIONS,
};

function QuestionCard({ question, answer }: { question: string; answer: OperatorAnswer }) {
  const [showDetails, setShowDetails] = useState(false);
  const dotColor = statusDotColor(answer.status);

  return (
    <div
      className={`bg-[#0a0e1a]/60 border rounded-lg p-3 transition-colors hover:bg-[#0a0e1a]/80 ${statusBorderClass(answer.status)}`}
    >
      <div className="flex items-start gap-2.5">
        {/* Status dot */}
        <span
          className="inline-block w-2.5 h-2.5 rounded-full flex-shrink-0 mt-1"
          style={{
            backgroundColor: dotColor,
            boxShadow: answer.status !== 'unknown' ? `0 0 8px ${dotColor}40` : undefined,
          }}
        />

        <div className="flex-1 min-w-0">
          {/* Question */}
          <p className="text-xs font-medium text-gray-300 mb-1">{question}</p>

          {/* Answer summary */}
          <p className="text-[11px] text-gray-400">{answer.summary}</p>

          {/* Value + Trend */}
          {(answer.value || answer.trend) && (
            <div className="flex items-center gap-2 mt-1.5">
              {answer.value && (
                <span
                  className="text-xs font-mono font-semibold"
                  style={{ color: dotColor }}
                >
                  {answer.value}
                </span>
              )}
              {answer.trend && <TrendArrow trend={answer.trend} />}
            </div>
          )}

          {/* Details toggle */}
          {answer.details && (
            <button
              onClick={() => setShowDetails(!showDetails)}
              className="text-[10px] text-[#00d4ff] hover:text-[#00d4ff]/80 mt-1 transition-colors"
            >
              {showDetails ? 'Hide details' : 'Show details'}
            </button>
          )}
          {showDetails && answer.details && (
            <p className="text-[10px] text-gray-500 mt-1 bg-[#1a2332]/50 rounded px-2 py-1 font-mono">
              {answer.details}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

export default function OperatorQuestions({ state }: OperatorQuestionsProps) {
  const [activeTab, setActiveTab] = useState<OperatorTab>('health');

  const questions = QUESTIONS_BY_TAB[activeTab];

  const answers = useMemo(
    () => questions.map((q) => ({ question: q.question, answer: q.compute(state) })),
    [questions, state]
  );

  // Count statuses per tab for indicators
  const tabStatuses = useMemo(() => {
    const statuses: Record<OperatorTab, { critical: number; warning: number }> = {
      health: { critical: 0, warning: 0 },
      security: { critical: 0, warning: 0 },
      performance: { critical: 0, warning: 0 },
      cdn: { critical: 0, warning: 0 },
      api_security: { critical: 0, warning: 0 },
      bot_defense: { critical: 0, warning: 0 },
      infrastructure: { critical: 0, warning: 0 },
      operations: { critical: 0, warning: 0 },
    };

    for (const [tab, qs] of Object.entries(QUESTIONS_BY_TAB) as [OperatorTab, QuestionDef[]][]) {
      for (const q of qs) {
        const answer = q.compute(state);
        if (answer.status === 'critical') statuses[tab].critical++;
        else if (answer.status === 'warning') statuses[tab].warning++;
      }
    }

    return statuses;
  }, [state]);

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      {/* Header */}
      <div className="flex items-center gap-2 mb-4">
        <HelpCircle className="w-4 h-4 text-[#00d4ff]" />
        <h3 className="text-sm font-semibold text-gray-200">Operator Questions</h3>
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap gap-1 mb-4 -mx-1">
        {TAB_CONFIG.map((tab) => {
          const isActive = activeTab === tab.id;
          const status = tabStatuses[tab.id];
          const hasCritical = status.critical > 0;
          const hasWarning = status.warning > 0;

          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                isActive
                  ? 'bg-[#00d4ff]/15 text-[#00d4ff] border border-[#00d4ff]/30'
                  : 'bg-[#1a2332]/50 text-gray-400 border border-transparent hover:text-gray-200 hover:bg-[#1a2332]'
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
              {hasCritical && (
                <span className="w-1.5 h-1.5 rounded-full bg-[#ff0040] flex-shrink-0" />
              )}
              {!hasCritical && hasWarning && (
                <span className="w-1.5 h-1.5 rounded-full bg-[#ffbe0b] flex-shrink-0" />
              )}
            </button>
          );
        })}
      </div>

      {/* Question Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
        {answers.map(({ question, answer }) => (
          <QuestionCard key={question} question={question} answer={answer} />
        ))}
      </div>
    </div>
  );
}
